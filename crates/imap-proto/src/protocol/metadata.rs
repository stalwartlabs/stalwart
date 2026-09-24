/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{literal_string, push_int, quoted_string};
use crate::utf7::quoted_mailbox_name;
use compact_str::CompactString;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetArguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub max_size: Option<u32>,
    pub depth: Depth,
    pub entries: Vec<Entry<'static>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetArguments {
    pub tag: CompactString,
    pub mailbox_name: CompactString,
    pub entries: Vec<EntryValue<'static>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Depth {
    #[default]
    Zero,
    One,
    Infinity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Shared,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry<'x> {
    pub scope: Scope,
    pub path: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryValue<'x> {
    pub entry: Entry<'x>,
    pub value: Option<Cow<'x, [u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<'x> {
    pub mailbox_name: &'x str,
    pub entries: Vec<EntryValue<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsolicitedResponse<'x> {
    pub mailbox_name: &'x str,
    pub entries: Vec<Entry<'x>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataCode {
    LongEntries(u32),
    MaxSize(u32),
    TooMany,
    NoPrivate,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Shared => "/shared",
            Scope::Private => "/private",
        }
    }
}

impl Entry<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        let scope = self.scope.as_str();
        if self.path.bytes().all(is_astring_char) {
            buf.extend_from_slice(scope.as_bytes());
            buf.extend_from_slice(self.path.as_bytes());
        } else {
            quoted_string(buf, &[scope, &self.path].concat());
        }
    }
}

impl EntryValue<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        self.entry.serialize(buf);
        buf.push(b' ');
        match self.value.as_deref() {
            Some(value) if value.iter().all(|ch| (0x20..0x7f).contains(ch)) => {
                quoted_string(buf, std::str::from_utf8(value).unwrap_or_default())
            }
            Some(value) if value.contains(&0) => {
                buf.push(b'~');
                literal_string(buf, value);
            }
            Some(value) => literal_string(buf, value),
            None => buf.extend_from_slice(b"NIL"),
        }
    }
}

impl Response<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.extend_from_slice(b"* METADATA ");
        quoted_mailbox_name(buf, self.mailbox_name, is_utf8);
        buf.extend_from_slice(b" (");
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }
            entry.serialize(buf);
        }
        buf.extend_from_slice(b")\r\n");
    }
}

impl UnsolicitedResponse<'_> {
    pub fn serialize(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.extend_from_slice(b"* METADATA ");
        quoted_mailbox_name(buf, self.mailbox_name, is_utf8);
        for entry in &self.entries {
            buf.push(b' ');
            entry.serialize(buf);
        }
        buf.extend_from_slice(b"\r\n");
    }
}

impl MetadataCode {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
        if let MetadataCode::LongEntries(size) | MetadataCode::MaxSize(size) = self {
            buf.push(b' ');
            push_int(buf, *size);
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetadataCode::LongEntries(_) => "METADATA LONGENTRIES",
            MetadataCode::MaxSize(_) => "METADATA MAXSIZE",
            MetadataCode::TooMany => "METADATA TOOMANY",
            MetadataCode::NoPrivate => "METADATA NOPRIVATE",
        }
    }
}

fn is_astring_char(ch: u8) -> bool {
    ch > 0x20 && ch < 0x7f && !matches!(ch, b'(' | b')' | b'{' | b'"' | b'\\' | b'%' | b'*')
}

#[cfg(test)]
mod tests {
    use super::{Entry, EntryValue, MetadataCode, Response, Scope, UnsolicitedResponse};
    use crate::{ResponseCode, StatusResponse};
    use std::borrow::Cow;

    fn entry(scope: Scope, path: &str) -> Entry<'_> {
        Entry {
            scope,
            path: Cow::Borrowed(path),
        }
    }

    #[test]
    fn serialize_metadata_response() {
        for (response, is_utf8, expected) in [
            (
                Response {
                    mailbox_name: "",
                    entries: vec![EntryValue {
                        entry: entry(Scope::Shared, "/comment"),
                        value: Some(Cow::Borrowed(b"Shared comment")),
                    }],
                },
                false,
                "* METADATA \"\" (/shared/comment \"Shared comment\")\r\n",
            ),
            (
                Response {
                    mailbox_name: "INBOX",
                    entries: vec![
                        EntryValue {
                            entry: entry(Scope::Private, "/comment"),
                            value: Some(Cow::Borrowed(b"My \"own\" comment")),
                        },
                        EntryValue {
                            entry: entry(Scope::Shared, "/comment"),
                            value: None,
                        },
                        EntryValue {
                            entry: entry(Scope::Shared, "/vendor/x/lines"),
                            value: Some(Cow::Borrowed(b"a\r\nb")),
                        },
                        EntryValue {
                            entry: entry(Scope::Shared, "/vendor/x/binary"),
                            value: Some(Cow::Borrowed(b"a\0b")),
                        },
                        EntryValue {
                            entry: entry(Scope::Shared, "/vendor/x/empty"),
                            value: Some(Cow::Borrowed(b"")),
                        },
                        EntryValue {
                            entry: entry(Scope::Shared, "/vendor/x/with space"),
                            value: Some(Cow::Borrowed("caf\u{e9}".as_bytes())),
                        },
                    ],
                },
                false,
                concat!(
                    "* METADATA \"INBOX\" (/private/comment \"My \\\"own\\\" comment\" ",
                    "/shared/comment NIL /shared/vendor/x/lines {4}\r\na\r\nb ",
                    "/shared/vendor/x/binary ~{3}\r\na\0b /shared/vendor/x/empty \"\" ",
                    "\"/shared/vendor/x/with space\" {5}\r\ncaf\u{e9})\r\n"
                ),
            ),
            (
                Response {
                    mailbox_name: "Caf\u{e9}",
                    entries: vec![EntryValue {
                        entry: entry(Scope::Shared, "/comment"),
                        value: Some(Cow::Borrowed(b"x")),
                    }],
                },
                true,
                "* METADATA \"Caf\u{e9}\" (/shared/comment \"x\")\r\n",
            ),
            (
                Response {
                    mailbox_name: "Caf\u{e9}",
                    entries: vec![EntryValue {
                        entry: entry(Scope::Shared, "/comment"),
                        value: Some(Cow::Borrowed(b"x")),
                    }],
                },
                false,
                "* METADATA \"Caf&AOk-\" (/shared/comment \"x\")\r\n",
            ),
        ] {
            let mut buf = Vec::new();
            response.serialize(&mut buf, is_utf8);
            assert_eq!(String::from_utf8(buf).unwrap(), expected);
        }
    }

    #[test]
    fn serialize_unsolicited_metadata_response() {
        let mut buf = Vec::new();
        UnsolicitedResponse {
            mailbox_name: "INBOX",
            entries: vec![
                entry(Scope::Shared, "/comment"),
                entry(Scope::Private, "/comment"),
            ],
        }
        .serialize(&mut buf, false);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "* METADATA \"INBOX\" /shared/comment /private/comment\r\n"
        );
    }

    #[test]
    fn serialize_metadata_codes() {
        for (code, expected) in [
            (
                MetadataCode::LongEntries(2199),
                "a OK [METADATA LONGENTRIES 2199] GETMETADATA completed\r\n",
            ),
            (
                MetadataCode::MaxSize(1024),
                "a OK [METADATA MAXSIZE 1024] GETMETADATA completed\r\n",
            ),
            (
                MetadataCode::TooMany,
                "a OK [METADATA TOOMANY] GETMETADATA completed\r\n",
            ),
            (
                MetadataCode::NoPrivate,
                "a OK [METADATA NOPRIVATE] GETMETADATA completed\r\n",
            ),
        ] {
            assert_eq!(
                String::from_utf8(
                    StatusResponse::completed(crate::Command::GetMetadata)
                        .with_tag("a")
                        .with_code(ResponseCode::Metadata(code))
                        .into_bytes()
                )
                .unwrap(),
                expected
            );
        }
    }
}
