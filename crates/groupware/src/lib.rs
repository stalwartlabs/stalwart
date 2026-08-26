/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use calcard::common::timezone::Tz;
use common::DavResources;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::borrow::Cow;
use types::collection::{Collection, SyncCollection};

pub mod cache;
pub mod calendar;
pub mod contact;
pub mod file;
pub mod scheduling;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavResourceName {
    Card,
    Cal,
    File,
    Principal,
    Scheduling,
}

pub const RFC_3986: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn is_pchar(byte: u8) -> bool {
    matches!(byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
            | b':'
            | b'@')
}

pub fn is_uri_segment(name: &str) -> bool {
    let mut bytes = name.as_bytes().iter();

    while let Some(&byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(u8::is_ascii_hexdigit)
                || !bytes.next().is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
        } else if !is_pchar(byte) {
            return false;
        }
    }

    true
}

pub fn encode_path_segment(name: &str) -> Cow<'_, str> {
    if is_uri_segment(name) {
        Cow::Borrowed(name)
    } else {
        utf8_percent_encode(name, RFC_3986).into()
    }
}

pub struct DestroyArchive<T>(pub T);

impl DavResourceName {
    pub fn parse(service: &str) -> Option<Self> {
        hashify::tiny_map!(service.as_bytes(),
            "card" => DavResourceName::Card,
            "cal" => DavResourceName::Cal,
            "file" => DavResourceName::File,
            "pal" => DavResourceName::Principal,
            "itip" => DavResourceName::Scheduling,
        )
    }

    pub fn base_path(&self) -> &'static str {
        match self {
            DavResourceName::Card => "/dav/card",
            DavResourceName::Cal => "/dav/cal",
            DavResourceName::File => "/dav/file",
            DavResourceName::Principal => "/dav/pal",
            DavResourceName::Scheduling => "/dav/itip",
        }
    }

    pub fn collection_path(&self) -> &'static str {
        match self {
            DavResourceName::Card => "/dav/card/",
            DavResourceName::Cal => "/dav/cal/",
            DavResourceName::File => "/dav/file/",
            DavResourceName::Principal => "/dav/pal/",
            DavResourceName::Scheduling => "/dav/itip/",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DavResourceName::Card => "CardDAV",
            DavResourceName::Cal => "CalDAV",
            DavResourceName::File => "WebDAV",
            DavResourceName::Principal => "Principal",
            DavResourceName::Scheduling => "Scheduling",
        }
    }
}

impl From<DavResourceName> for Collection {
    fn from(value: DavResourceName) -> Self {
        match value {
            DavResourceName::Card => Collection::AddressBook,
            DavResourceName::Cal => Collection::Calendar,
            DavResourceName::File => Collection::FileNode,
            DavResourceName::Principal => Collection::Principal,
            DavResourceName::Scheduling => Collection::CalendarEventNotification,
        }
    }
}

impl From<Collection> for DavResourceName {
    fn from(value: Collection) -> Self {
        match value {
            Collection::AddressBook => DavResourceName::Card,
            Collection::Calendar => DavResourceName::Cal,
            Collection::FileNode => DavResourceName::File,
            Collection::Principal => DavResourceName::Principal,
            Collection::CalendarEventNotification => DavResourceName::Scheduling,
            _ => unreachable!(),
        }
    }
}

impl From<SyncCollection> for DavResourceName {
    fn from(value: SyncCollection) -> Self {
        match value {
            SyncCollection::AddressBook => DavResourceName::Card,
            SyncCollection::Calendar => DavResourceName::Cal,
            SyncCollection::FileNode => DavResourceName::File,
            SyncCollection::CalendarEventNotification => DavResourceName::Scheduling,
            _ => unreachable!(),
        }
    }
}

pub trait DavCalendarResource {
    fn calendar_default_tz(&self, calendar_id: u32, account_id: u32) -> Option<Tz>;
}

impl DavCalendarResource for DavResources {
    fn calendar_default_tz(&self, calendar_id: u32, account_id: u32) -> Option<Tz> {
        self.container_resource_by_id(calendar_id)
            .and_then(|c| c.calendar_preferences(account_id))
            .map(|p| p.tz)
    }
}

pub fn strip_mailto_scheme(value: &str) -> &str {
    value
        .split_once(':')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("mailto"))
        .map_or(value, |(_, address)| address.trim())
}

pub fn decode_mailto_address(value: &str) -> Cow<'_, str> {
    match value.split_once(':') {
        Some((scheme, address)) if scheme.eq_ignore_ascii_case("mailto") => {
            let address = address.trim();
            let address = address.split_once('?').map_or(address, |(to, _)| to);
            percent_decode_str(address).decode_utf8_lossy()
        }
        _ => Cow::Borrowed(value),
    }
}

pub fn extract_addr_spec(value: &str) -> Option<&str> {
    value
        .rsplit_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(addr, _)| addr.trim())
        .filter(|addr| !addr.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_from_uris_are_preserved() {
        for name in [
            "readme.txt",
            "My%20Folder",
            "%C3%9Cnterlagen.txt",
            "file(1).txt",
            "a+b.txt",
            "Q&A.txt",
            "it's.txt",
            "mail@host.txt",
            "a:b.txt",
            "notes;v=2,rev=3!$*=.txt",
            "~backup_1-2.txt",
        ] {
            assert!(is_uri_segment(name), "{name:?}");
            assert_eq!(encode_path_segment(name), name);
        }
    }

    #[test]
    fn path_segments_from_names_are_encoded() {
        for (name, expected) in [
            ("My Folder", "My%20Folder"),
            ("Ünterlagen.txt", "%C3%9Cnterlagen.txt"),
            ("Ünterlagen 2026.txt", "%C3%9Cnterlagen%202026.txt"),
            ("100%", "100%25"),
            ("100%2", "100%252"),
            ("100%zz", "100%25zz"),
            ("a/b.txt", "a%2Fb.txt"),
            ("a<b>c.txt", "a%3Cb%3Ec.txt"),
            ("a\"b#c?d.txt", "a%22b%23c%3Fd.txt"),
            ("a\tb.txt", "a%09b.txt"),
        ] {
            assert!(!is_uri_segment(name), "{name:?}");
            assert_eq!(encode_path_segment(name), expected, "{name:?}");
        }
    }

    #[test]
    fn encoded_path_segments_are_stable() {
        for name in [
            "My Folder",
            "Ünterlagen 2026.txt",
            "100%",
            "a/b.txt",
            "file(1).txt",
        ] {
            let encoded = encode_path_segment(name).into_owned();
            assert!(is_uri_segment(&encoded), "{encoded:?}");
            assert_eq!(encode_path_segment(&encoded), encoded, "{name:?}");
        }
    }
}
