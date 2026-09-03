/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod hierarchy;
pub mod paths;
pub mod resource;
pub mod store;

pub use store::ResourceChunkBuilder;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use std::borrow::Cow;

pub(crate) const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;
pub const CONTAINER_FLAG: u32 = 1 << 31;

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
