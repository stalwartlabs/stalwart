/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod file;
pub mod hierarchy;
pub mod paths;
pub mod resource;
pub mod store;

pub use file::{
    FILE_DEFAULT_MEDIA_TYPE, FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_KIND_SYMLINK,
    MAX_FILE_EXTRA_LEN,
};
pub use store::ResourceChunkBuilder;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use std::borrow::Cow;

pub(crate) const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;
pub const CONTAINER_FLAG: u32 = 1 << 31;
pub const MAX_FILE_NODE_DEPTH: usize = 64;

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

pub const FILE_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub const MAX_DAV_FILE_NAME_LEN: usize = 255;
pub const FORBIDDEN_FILE_NAME_CHARS: &str = "/<>:\"\\|?*";
pub const FORBIDDEN_FILE_NODE_NAMES: &[&str] = &[
    ".", "..", "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
    "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavFileNameError {
    Empty,
    TooLong,
    InvalidCharacter,
    ReservedName,
}

pub fn canonical_path_segment(name: &str) -> Cow<'_, str> {
    utf8_percent_encode(name, FILE_SEGMENT).into()
}

pub fn canonical_uri_path(path: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    if !path
        .bytes()
        .any(|byte| byte == b'%' || !is_pchar(byte) && byte != b'/')
    {
        return Ok(Cow::Borrowed(path));
    }
    let mut canonical = String::with_capacity(path.len() + 8);
    for (idx, segment) in path.split('/').enumerate() {
        if idx > 0 {
            canonical.push('/');
        }
        canonical.push_str(&canonical_path_segment(&decode_segment(segment)?));
    }
    Ok(Cow::Owned(canonical))
}

pub fn canonical_dav_resource_uri(uri: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    let Some((base, (collection, (account, resource)))) =
        uri.split_once("/dav/").and_then(|(base, path)| {
            path.split_once('/').and_then(|(collection, rest)| {
                rest.split_once('/')
                    .map(|account| (base, (collection, account)))
            })
        })
    else {
        return Ok(Cow::Borrowed(uri));
    };
    Ok(match canonical_uri_path(resource)? {
        Cow::Borrowed(_) => Cow::Borrowed(uri),
        Cow::Owned(resource) => Cow::Owned(format!("{base}/dav/{collection}/{account}/{resource}")),
    })
}

pub fn dav_file_name(segment: &str) -> Result<String, DavFileNameError> {
    let name = decode_segment(segment)?;
    if name.is_empty() {
        Err(DavFileNameError::Empty)
    } else if name.len() > MAX_DAV_FILE_NAME_LEN {
        Err(DavFileNameError::TooLong)
    } else if matches!(name.as_ref(), "." | "..") {
        Err(DavFileNameError::ReservedName)
    } else if name.contains(char::is_control)
        || percent_decode_str(segment).any(|byte| byte.is_ascii_control())
    {
        Err(DavFileNameError::InvalidCharacter)
    } else {
        Ok(name.into_owned())
    }
}

fn decode_segment(segment: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    let decoded: Cow<'_, [u8]> = percent_decode_str(segment).into();
    if decoded.iter().any(|byte| matches!(byte, b'/' | b'\0')) {
        return Err(DavFileNameError::InvalidCharacter);
    }
    Ok(match decoded {
        Cow::Borrowed(_) => Cow::Borrowed(segment),
        Cow::Owned(bytes) => match String::from_utf8(bytes) {
            Ok(decoded) => Cow::Owned(decoded),
            Err(err) => Cow::Owned(escape_invalid_utf8(err.as_bytes())),
        },
    })
}

fn escape_invalid_utf8(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut name = String::with_capacity(bytes.len() * 3);
    for chunk in bytes.utf8_chunks() {
        name.push_str(chunk.valid());
        for byte in chunk.invalid() {
            let _ = write!(name, "%{byte:02X}");
        }
    }
    name
}

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
    fn dav_names_decode_from_any_spelling() {
        for (segment, name) in [
            ("readme.txt", "readme.txt"),
            ("My%20Folder", "My Folder"),
            ("file(1).txt", "file(1).txt"),
            ("file%281%29.txt", "file(1).txt"),
            ("%c3%9cbersicht.pdf", "\u{dc}bersicht.pdf"),
            ("%C3%9Cbersicht.pdf", "\u{dc}bersicht.pdf"),
            ("%E9t%E9.txt", "%E9t%E9.txt"),
            ("%e9t%e9.txt", "%E9t%E9.txt"),
            ("%E9t%e9%2a.txt", "%E9t%E9*.txt"),
            ("%E9%41.txt", "%E9A.txt"),
            ("%e9A.txt", "%E9A.txt"),
            ("%E9%C3%BC", "%E9\u{fc}"),
            ("%e9%zz%4", "%E9%zz%4"),
            ("100%25", "100%"),
            ("..a", "..a"),
            ("b c", "b c"),
        ] {
            let decoded = dav_file_name(segment).expect(segment);
            assert_eq!(decoded, name, "{segment}");
            let canonical = canonical_uri_path(segment).expect(segment);
            assert_eq!(canonical, canonical_path_segment(&decoded), "{segment}");
            assert_eq!(dav_file_name(&canonical).as_deref(), Ok(name), "{segment}");
        }
        assert_eq!(
            canonical_uri_path("%E9t%E9.txt"),
            canonical_uri_path("%e9t%e9.txt")
        );
        for (segment, error) in [
            ("a%2Fb", DavFileNameError::InvalidCharacter),
            ("a%2fb", DavFileNameError::InvalidCharacter),
            ("a%00b", DavFileNameError::InvalidCharacter),
            ("%E9%2F", DavFileNameError::InvalidCharacter),
            ("a%01b", DavFileNameError::InvalidCharacter),
            ("a%7Fb", DavFileNameError::InvalidCharacter),
            ("a%C2%85b", DavFileNameError::InvalidCharacter),
            ("%E9%0A", DavFileNameError::InvalidCharacter),
            (".", DavFileNameError::ReservedName),
            ("..", DavFileNameError::ReservedName),
            ("%2E", DavFileNameError::ReservedName),
            ("%2e%2E", DavFileNameError::ReservedName),
            ("", DavFileNameError::Empty),
        ] {
            assert_eq!(dav_file_name(segment), Err(error), "{segment}");
        }
        assert_eq!(
            dav_file_name(&"%41".repeat(256)),
            Err(DavFileNameError::TooLong)
        );
        assert!(matches!(
            canonical_uri_path("/dav/file/john/docs/a.txt"),
            Ok(Cow::Borrowed(_))
        ));
        assert_eq!(
            canonical_uri_path("/dav/file/john%40example.com/My%20Docs/file%281%29.txt").as_deref(),
            Ok("/dav/file/john@example.com/My%20Docs/file(1).txt")
        );
        for path in ["a%2Fb/c.txt", "docs/a%00/c.txt", "a%2f/b"] {
            assert_eq!(
                canonical_uri_path(path),
                Err(DavFileNameError::InvalidCharacter),
                "{path}"
            );
        }
        assert_eq!(
            canonical_dav_resource_uri("/dav/file/john%40example.com/My%20Docs/file%281%29.txt")
                .as_deref(),
            Ok("/dav/file/john%40example.com/My%20Docs/file(1).txt")
        );
        assert_eq!(
            canonical_dav_resource_uri(
                "https://host:8080/dav/file/john%40example.com/%c3%9c/a%28b"
            )
            .as_deref(),
            Ok("https://host:8080/dav/file/john%40example.com/%C3%9C/a(b")
        );
        assert_eq!(
            canonical_dav_resource_uri("/dav/file/john%40example.com/a%2Fb/c.txt"),
            Err(DavFileNameError::InvalidCharacter)
        );
        assert!(matches!(
            canonical_dav_resource_uri("/dav/file/john%40example.com"),
            Ok(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn canonical_segments_are_injective() {
        for (name, expected) in [
            ("readme.txt", "readme.txt"),
            ("file(1)+a:b@c!$&'*,;=.txt", "file(1)+a:b@c!$&'*,;=.txt"),
            ("My Folder", "My%20Folder"),
            ("My%20Folder", "My%2520Folder"),
            ("Ünterlagen.txt", "%C3%9Cnterlagen.txt"),
            ("a/b", "a%2Fb"),
            ("a\u{7f}b", "a%7Fb"),
            (
                "q?#[]^`{|}<>\"\\",
                "q%3F%23%5B%5D%5E%60%7B%7C%7D%3C%3E%22%5C",
            ),
        ] {
            assert_eq!(canonical_path_segment(name), expected, "{name:?}");
            assert!(is_uri_segment(&canonical_path_segment(name)), "{name:?}");
        }
        assert!(matches!(
            canonical_path_segment("plain-name.txt"),
            Cow::Borrowed(_)
        ));
    }

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
