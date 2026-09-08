/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Recipient, SpamFilterContext, SpamFilterInput, SpamFilterOutput, SpamFilterResult, TextPart,
};
use common::{Server, config::mailstore::spamfilter::Location};
use mail_parser::{Header, parsers::MessageStream};
use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
};

pub mod classifier;
pub mod date;
pub mod dmarc;
pub mod domain;
pub mod ehlo;
pub mod from;
pub mod headers;
pub mod html;
pub mod init;
pub mod ip;
pub mod messageid;
pub mod mime;
mod mime_types;
pub mod pyzor;
pub mod received;
pub mod recipient;
pub mod replyto;
pub mod rules;
pub mod score;
pub mod subject;
pub mod url;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod llm;
// SPDX-SnippetEnd

impl SpamFilterInput<'_> {
    pub fn header_as_address(&self, header: &Header<'_>) -> Option<Cow<'_, str>> {
        self.message
            .raw_message()
            .get(header.offset_start as usize..header.offset_end as usize)
            .map(|bytes| MessageStream::new(bytes).parse_address())
            .and_then(|addr| addr.into_address())
            .and_then(|addr| addr.into_list().into_iter().next())
            .and_then(|addr| addr.address)
    }
}

impl SpamFilterOutput<'_> {
    pub fn all_recipients(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients_to
            .iter()
            .chain(self.recipients_cc.iter())
            .chain(self.recipients_bcc.iter())
    }
}

impl SpamFilterContext<'_> {
    pub fn text_body(&self) -> Option<&str> {
        self.input
            .message
            .text_body
            .first()
            .or_else(|| self.input.message.html_body.first())
            .and_then(|idx| self.output.text_parts.get(*idx as usize))
            .and_then(|part| match part {
                TextPart::Plain { text_body, .. } => Some(*text_body),
                TextPart::Html { text_body, .. } => Some(text_body.as_str()),
                TextPart::None => None,
            })
    }
}

impl SpamFilterResult {
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.insert(tag.into());
    }

    pub fn has_tag(&self, tag: impl AsRef<str>) -> bool {
        self.tags.contains(tag.as_ref())
    }
}

#[derive(Debug)]
pub struct ElementLocation<T> {
    pub element: T,
    pub location: Location,
}

impl<T: Hash> Hash for ElementLocation<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.element.hash(state);
    }
}

impl<T: PartialEq> PartialEq for ElementLocation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.element.eq(&other.element)
    }
}

impl<T: Eq> Eq for ElementLocation<T> {}

impl std::borrow::Borrow<crate::Email> for ElementLocation<Recipient> {
    fn borrow(&self) -> &crate::Email {
        &self.element.email
    }
}

impl std::borrow::Borrow<str> for ElementLocation<crate::analysis::url::UrlParts<'_>> {
    fn borrow(&self) -> &str {
        self.element.url.as_str()
    }
}

impl<T> ElementLocation<T> {
    pub fn new(element: T, location: impl Into<Location>) -> Self {
        Self {
            element,
            location: location.into(),
        }
    }
}

pub(crate) async fn is_trusted_domain(server: &Server, domain: &str, span_id: u64) -> bool {
    if let Some(store) = server.get_lookup_store("trusted-domains") {
        match store.key_exists(domain).await {
            Ok(true) => return true,
            Ok(false) => (),
            Err(err) => {
                trc::error!(err.span_id(span_id).caused_by(trc::location!()));
            }
        }
    }

    match server.domain(domain).await {
        Ok(result) => result.is_some(),
        Err(err) => {
            trc::error!(err.span_id(span_id).caused_by(trc::location!()));
            false
        }
    }
}

pub(crate) async fn is_url_redirector(server: &Server, url: &str, span_id: u64) -> bool {
    if let Some(store) = server.get_lookup_store("url-redirectors") {
        match store.key_exists(url).await {
            Ok(result) => result,
            Err(err) => {
                trc::error!(err.span_id(span_id).caused_by(trc::location!()));
                false
            }
        }
    } else {
        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ExcessEncoding {
    None,
    QuotedPrintable,
    Base64,
    Other,
}

#[inline]
pub(crate) fn excess_encoding(text: &str) -> ExcessEncoding {
    if !text.contains("=?") || !text.contains("?=") {
        return ExcessEncoding::None;
    }

    let bytes = text.as_bytes();
    let mut has_qp = false;
    let mut has_base64 = false;

    for (pos, _) in text.match_indices('?') {
        if bytes.get(pos + 2) == Some(&b'?') {
            match bytes.get(pos + 1) {
                Some(b'q' | b'Q') => has_qp = true,
                Some(b'b' | b'B') => has_base64 = true,
                _ => {}
            }
        }
    }

    if has_qp {
        ExcessEncoding::QuotedPrintable
    } else if has_base64 {
        ExcessEncoding::Base64
    } else {
        ExcessEncoding::Other
    }
}

pub(crate) fn eq_lowercase_str(left: &str, right: &str) -> bool {
    if left.is_ascii() && right.is_ascii() {
        left.eq_ignore_ascii_case(right)
    } else {
        left.to_lowercase() == right.to_lowercase()
    }
}

pub(crate) fn to_lowercase_cow(text: &str) -> Cow<'_, str> {
    if text.is_ascii() {
        if text.as_bytes().iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(text.to_ascii_lowercase())
        } else {
            Cow::Borrowed(text)
        }
    } else {
        Cow::Owned(text.to_lowercase())
    }
}

pub(crate) fn eq_lowercase(text: &str, lowercase_literal: &str) -> bool {
    debug_assert!(
        lowercase_literal
            .bytes()
            .all(|b| b.is_ascii() && !b.is_ascii_uppercase())
    );
    text.chars()
        .flat_map(char::to_lowercase)
        .eq(lowercase_literal.chars())
}

pub(crate) fn starts_with_ignore_ascii_case(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix.as_bytes()))
}

pub(crate) fn contains_ignore_ascii_case(text: &str, needle: &str) -> bool {
    let bytes = text.as_bytes();
    let needle_bytes = needle.as_bytes();

    if needle_bytes.is_empty() {
        true
    } else if bytes.len() > 512 {
        text.to_ascii_lowercase()
            .contains(needle.to_ascii_lowercase().as_str())
    } else {
        bytes.len() >= needle_bytes.len()
            && bytes
                .windows(needle_bytes.len())
                .any(|window| window.eq_ignore_ascii_case(needle_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ExcessEncoding, contains_ignore_ascii_case, eq_lowercase, eq_lowercase_str,
        excess_encoding, starts_with_ignore_ascii_case, to_lowercase_cow,
    };
    use std::borrow::Cow;

    #[test]
    fn excess_encoding_markers() {
        for (text, expected) in [
            ("plain subject", ExcessEncoding::None),
            ("=?utf-8?Q?a?=", ExcessEncoding::QuotedPrintable),
            ("x =?utf-8?q?a?= y", ExcessEncoding::QuotedPrintable),
            ("=?utf-8?B?YQ==?=", ExcessEncoding::Base64),
            ("=?utf-8?b?YQ==?=", ExcessEncoding::Base64),
            (
                "=?utf-8?B?YQ==?= =?utf-8?Q?a?=",
                ExcessEncoding::QuotedPrintable,
            ),
            ("=?utf-8?X?a?=", ExcessEncoding::Other),
            ("?= =?", ExcessEncoding::Other),
            ("=?utf-8?Q?a", ExcessEncoding::None),
            ("?q? ?b? without markers", ExcessEncoding::None),
            ("", ExcessEncoding::None),
        ] {
            assert_eq!(excess_encoding(text), expected, "{text:?}");
        }
    }

    #[test]
    fn lowercase_comparisons() {
        assert!(eq_lowercase("BULK", "bulk"));
        assert!(eq_lowercase("bulk", "bulk"));
        assert!(eq_lowercase("BUL\u{212a}", "bulk"));
        assert!(!eq_lowercase("bulk ", "bulk"));
        assert!(!eq_lowercase("bul", "bulk"));
        assert!(eq_lowercase("", ""));
        assert!(eq_lowercase_str("ABC", "abc"));
        assert!(eq_lowercase_str("\u{130}", "i\u{307}"));
        assert!(eq_lowercase_str("\u{391}\u{3a3}", "\u{3b1}\u{3c2}"));
        assert!(!eq_lowercase_str("\u{391}\u{3a3}", "\u{3b1}\u{3c3}"));
        assert!(!eq_lowercase_str("abc", "abd"));
    }

    #[test]
    fn lowercase_cow_borrows_when_unchanged() {
        assert!(matches!(to_lowercase_cow("abc"), Cow::Borrowed("abc")));
        assert!(matches!(to_lowercase_cow(""), Cow::Borrowed("")));
        assert!(matches!(to_lowercase_cow("Abc"), Cow::Owned(ref s) if s == "abc"));
        assert!(matches!(to_lowercase_cow("\u{e9}"), Cow::Owned(ref s) if s == "\u{e9}"));
        assert!(matches!(to_lowercase_cow("\u{c9}COLE"), Cow::Owned(ref s) if s == "\u{e9}cole"));
    }

    #[test]
    fn ascii_case_insensitive_search() {
        assert!(contains_ignore_ascii_case("Stylesheet", "stylesheet"));
        assert!(contains_ignore_ascii_case("x.CSS", ".css"));
        assert!(!contains_ignore_ascii_case("abc", "abcd"));
        assert!(contains_ignore_ascii_case("", ""));
        let long_upper = format!("{}ABC", "x".repeat(600));
        let long_lower = format!("{}abc", "x".repeat(600));
        assert!(contains_ignore_ascii_case(&long_upper, "abc"));
        assert!(contains_ignore_ascii_case(&long_lower, "ABC"));
        assert!(contains_ignore_ascii_case("ABC", "abc"));
        assert!(contains_ignore_ascii_case("abc", "ABC"));
        assert!(starts_with_ignore_ascii_case("DATA:x", "data:"));
        assert!(!starts_with_ignore_ascii_case("dat", "data:"));
        assert!(starts_with_ignore_ascii_case("anything", ""));
    }
}
