/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use bytes::Bytes;
use mail_parser::{MessagePart, MessageRef};

use crate::{
    common::{
        base64::{Base64Mode, base64_decode_into, base64_encode_into, base64_encoded_len},
        time::FileTime,
    },
    convert::{
        mime::{ends_with_ignore_case, starts_with_ignore_case},
        model::PropBag,
        tags,
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey},
};

pub(super) const MULTIPART_REPORT: &str = "multipart/report";
pub(super) const REPORT_TYPE: &str = "report-type";
pub(super) const DISPOSITION_NOTIFICATION: &str = "disposition-notification";
pub(super) const DISPOSITION_NOTIFICATION_TYPE: &str = "message/disposition-notification";
const REPORT_PREFIX: &str = "REPORT.";
const SUFFIX_READ: &str = ".IPNRN";
const SUFFIX_NOT_READ: &str = ".IPNNRN";
const CLASS_READ: &str = "REPORT.IPM.Note.IPNRN";
const CLASS_NOT_READ: &str = "REPORT.IPM.Note.IPNNRN";
const MAX_CORRELATION_KEY: usize = 4096;
const FINAL_RECIPIENT: &str = "Final-Recipient";
const ORIGINAL_RECIPIENT: &str = "Original-Recipient";
const DISPOSITION: &str = "Disposition";
const CORRELATION_KEY: &str = "X-MSExch-Correlation-Key";
const ORIGINAL_MESSAGE_ID: &str = "Original-Message-ID";
const DISPLAY_NAME: &str = "X-Display-Name";
const DISPOSITION_MODE: &str = "automatic-action/MDN-sent-automatically; ";
const ADDRESS_TYPE: &str = "rfc822;";
const ENCODED_WORD_START: &str = " =?utf-8?B?";
const ENCODED_WORD_END: &str = "?=";
const MAX_ENCODED_WORD_BYTES: usize = 36;
const MAX_LINE: usize = 998;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Disposition {
    Read,
    NotRead,
}

impl Disposition {
    pub fn from_class(class: &str) -> Option<Self> {
        if !starts_with_ignore_case(class, REPORT_PREFIX) {
            return None;
        }
        if ends_with_ignore_case(class, SUFFIX_NOT_READ) {
            Some(Disposition::NotRead)
        } else if ends_with_ignore_case(class, SUFFIX_READ) {
            Some(Disposition::Read)
        } else {
            None
        }
    }

    pub fn class(self) -> &'static str {
        match self {
            Disposition::Read => CLASS_READ,
            Disposition::NotRead => CLASS_NOT_READ,
        }
    }

    fn action(self) -> &'static str {
        match self {
            Disposition::Read => "displayed",
            Disposition::NotRead => "deleted",
        }
    }
}

pub(super) struct Mdn<'m> {
    body: Cow<'m, [u8]>,
}

impl<'m> Mdn<'m> {
    pub fn find(msg: MessageRef<'m>) -> Option<Self> {
        if !is_report(msg) {
            return None;
        }
        let body = msg
            .parts()
            .find(|part| is_notification(*part))
            .map(|part| part.decoded())
            .unwrap_or_default();
        Some(Mdn { body })
    }

    pub fn disposition(&self) -> Disposition {
        self.field(DISPOSITION)
            .and_then(|value| {
                let value = strip_comments(&value);
                let (_, kind) = value.split_once(';')?;
                let kind = kind
                    .split(|c: char| c == '/' || c == ';' || c.is_ascii_whitespace())
                    .find(|token| !token.is_empty())?;
                hashify::map_ignore_case!(kind.as_bytes(), Disposition,
                    "displayed" => Disposition::Read,
                    "dispatched" => Disposition::Read,
                    "processed" => Disposition::Read,
                    "deleted" => Disposition::NotRead,
                    "denied" => Disposition::NotRead,
                    "failed" => Disposition::NotRead,
                )
                .copied()
            })
            .unwrap_or(Disposition::Read)
    }

    pub fn set_props(&self, bag: &mut PropBag, sent: Option<FileTime>) {
        if let Some(recipient) = self
            .recipient(ORIGINAL_RECIPIENT)
            .or_else(|| self.recipient(FINAL_RECIPIENT))
        {
            set_string(bag, tags::ORIGINAL_DISPLAY_TO, &recipient);
        }
        if let Some(sent) = sent {
            for id in [
                tags::ORIGINAL_DELIVERY_TIME,
                tags::RECEIPT_TIME,
                tags::REPORT_TIME,
            ] {
                bag.set(PropKey::tag(id), OwnedPropValue::Time(sent));
            }
        }
        if let Some(disposition) = self.field(DISPOSITION) {
            set_string(bag, tags::REPORT_TEXT, &disposition);
        }
        if let Some(key) = self.field(CORRELATION_KEY) {
            let mut decoded = Vec::new();
            if base64_decode_into(
                key.as_bytes(),
                &mut decoded,
                MAX_CORRELATION_KEY,
                Base64Mode::Lenient,
            )
            .is_ok()
                && !decoded.is_empty()
            {
                bag.set(
                    PropKey::tag(tags::PARENT_KEY),
                    OwnedPropValue::Binary(Bytes::from(decoded)),
                );
            }
        }
        if let Some(id) = self.field(ORIGINAL_MESSAGE_ID) {
            let id = strip_comments(&id);
            let id = id.trim();
            if !id.is_empty() {
                set_string(bag, tags::ORIGINAL_MESSAGE_ID, id);
                set_string(bag, tags::INTERNET_REFERENCES, id);
            }
        }
    }

    fn recipient(&self, name: &str) -> Option<String> {
        self.field(name)
            .map(|value| recipient_address(&value).to_string())
            .filter(|address| !address.is_empty())
    }

    fn field(&self, name: &str) -> Option<Cow<'_, str>> {
        let mut lines = self.body.split(|byte| *byte == b'\n');
        let first = lines.by_ref().find_map(|line| {
            if is_continuation(line) {
                return None;
            }
            let mut fields = line.splitn(2, |byte| *byte == b':');
            let field = fields.next()?;
            let value = fields.next()?;
            field
                .trim_ascii_end()
                .eq_ignore_ascii_case(name.as_bytes())
                .then_some(value)
        })?;
        let mut value = Cow::Borrowed(first.trim_ascii());
        for line in lines.take_while(|line| is_continuation(line)) {
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            let unfolded = value.to_mut();
            if !unfolded.is_empty() {
                unfolded.push(b' ');
            }
            unfolded.extend_from_slice(line);
        }
        let value = match value {
            Cow::Borrowed(bytes) => Cow::Borrowed(std::str::from_utf8(bytes).ok()?),
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8(bytes).ok()?),
        };
        (!value.is_empty()).then_some(value)
    }
}

pub(super) fn is_report(msg: MessageRef<'_>) -> bool {
    msg.root_part().content_type().is_some_and(|ctype| {
        ctype.ctype().eq_ignore_ascii_case("multipart")
            && ctype
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("report"))
            && ctype
                .attribute(REPORT_TYPE)
                .is_some_and(|kind| kind.eq_ignore_ascii_case(DISPOSITION_NOTIFICATION))
    })
}

pub(super) fn is_notification(part: MessagePart<'_>) -> bool {
    part.is_content_type("message", DISPOSITION_NOTIFICATION)
}

pub(super) struct NotificationFields<'a> {
    pub recipient: Option<(Option<&'a str>, &'a str)>,
    pub disposition: Disposition,
    pub parent_key: Option<&'a [u8]>,
    pub original_message_id: Option<&'a str>,
}

impl NotificationFields<'_> {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(FINAL_RECIPIENT.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(ADDRESS_TYPE.as_bytes());
        if let Some((_, email)) = self.recipient.filter(|(_, email)| {
            email.is_ascii()
                && fits(
                    FINAL_RECIPIENT,
                    ADDRESS_TYPE.len().saturating_add(email.len()),
                )
        }) {
            push_value(out, email);
        }
        out.extend_from_slice(b"\r\n");
        push_field(
            out,
            DISPOSITION,
            &[DISPOSITION_MODE, self.disposition.action()],
        );
        if let Some(key) = self
            .parent_key
            .filter(|key| !key.is_empty() && fits(CORRELATION_KEY, base64_encoded_len(key.len())))
        {
            out.extend_from_slice(CORRELATION_KEY.as_bytes());
            out.extend_from_slice(b": ");
            base64_encode_into(key, out);
            out.extend_from_slice(b"\r\n");
        }
        if let Some(id) = self
            .original_message_id
            .filter(|id| !id.is_empty() && id.is_ascii() && fits(ORIGINAL_MESSAGE_ID, id.len()))
        {
            push_field(out, ORIGINAL_MESSAGE_ID, &[id]);
        }
        if let Some((Some(name), email)) = self.recipient
            && !name.is_empty()
            && !name.eq_ignore_ascii_case(email)
        {
            if name.is_ascii() && fits(DISPLAY_NAME, name.len()) {
                push_field(out, DISPLAY_NAME, &[name]);
            } else {
                out.extend_from_slice(DISPLAY_NAME.as_bytes());
                out.extend_from_slice(b":");
                push_encoded_words(out, name);
                out.extend_from_slice(b"\r\n");
            }
        }
    }
}

fn push_field(out: &mut Vec<u8>, name: &str, values: &[&str]) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    for value in values {
        push_value(out, value);
    }
    out.extend_from_slice(b"\r\n");
}

fn push_value(out: &mut Vec<u8>, value: &str) {
    out.extend(value.bytes().map(|byte| match byte {
        b'\0' | b'\r' | b'\n' => b' ',
        byte => byte,
    }));
}

fn push_encoded_words(out: &mut Vec<u8>, text: &str) {
    let mut rest = text;
    while !rest.is_empty() {
        let end = rest
            .char_indices()
            .map(|(start, ch)| start.saturating_add(ch.len_utf8()))
            .take_while(|end| *end <= MAX_ENCODED_WORD_BYTES)
            .last()
            .unwrap_or(rest.len());
        let Some((chunk, tail)) = rest.split_at_checked(end) else {
            return;
        };
        if !out.ends_with(b":") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(ENCODED_WORD_START.as_bytes());
        base64_encode_into(chunk.as_bytes(), out);
        out.extend_from_slice(ENCODED_WORD_END.as_bytes());
        rest = tail;
    }
}

fn fits(name: &str, value_len: usize) -> bool {
    name.len().saturating_add(2).saturating_add(value_len) <= MAX_LINE
}

fn strip_comments(value: &str) -> Cow<'_, str> {
    if !value.contains('(') {
        return Cow::Borrowed(value);
    }
    let mut out = String::with_capacity(value.len());
    let mut depth = 0usize;
    let mut escaped = false;
    for ch in value.chars() {
        if depth == 0 {
            if ch == '(' {
                depth = 1;
                out.push(' ');
            } else {
                out.push(ch);
            }
        } else if escaped {
            escaped = false;
        } else {
            match ch {
                '\\' => escaped = true,
                '(' => depth = depth.saturating_add(1),
                ')' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Cow::Owned(out)
}

fn is_continuation(line: &[u8]) -> bool {
    matches!(line.first(), Some(b' ' | b'\t'))
}

fn recipient_address(value: &str) -> &str {
    value
        .split_once(';')
        .map_or(value, |(_, address)| address)
        .trim()
}

fn set_string(bag: &mut PropBag, id: PropId, value: &str) {
    bag.set(PropKey::tag(id), OwnedPropValue::Unicode(value.into()));
}
