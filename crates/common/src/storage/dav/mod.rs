/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod file;
pub mod hierarchy;
pub mod paths;
pub mod presence;
pub mod resource;
pub mod store;

pub use file::{
    FILE_DEFAULT_MEDIA_TYPE, FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_KIND_SYMLINK,
    MAX_FILE_EXTRA_LEN,
};
pub use presence::{DISPLAY_NAME_PROPERTY, FilePresence, PresenceBits};
pub use store::ResourceChunkBuilder;

use percent_encoding::{
    AsciiSet, CONTROLS, percent_decode_str, percent_encode, utf8_percent_encode,
};
use std::{borrow::Cow, convert::Infallible};

pub(crate) const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;
pub const CONTAINER_FLAG: u32 = 1 << 31;
pub const MAX_CACHED_UID_LEN: usize = 255;

pub trait CachedUid {
    fn cached_uid(&self) -> &str;
}

impl CachedUid for str {
    fn cached_uid(&self) -> &str {
        if self.len() <= MAX_CACHED_UID_LEN {
            self
        } else {
            self.get(..self.ceil_char_boundary(MAX_CACHED_UID_LEN))
                .unwrap_or(self)
        }
    }
}
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
    canonicalize_path(path, push_file_segment)
}

pub fn canonical_dav_resource_uri(uri: &str) -> Result<Cow<'_, str>, DavFileNameError> {
    canonicalize_resource_uri(uri, push_file_segment)
}

pub fn canonical_calcard_segment(segment: &str) -> Cow<'_, str> {
    if segment.bytes().all(is_pchar) {
        return Cow::Borrowed(segment);
    }
    let mut canonical = String::with_capacity(segment.len() + 8);
    let Ok(()) = push_calcard_segment(&mut canonical, segment);
    Cow::Owned(canonical)
}

pub fn canonical_calcard_uri(uri: &str) -> Cow<'_, str> {
    let Ok(uri) = canonicalize_resource_uri(uri, push_calcard_segment);
    uri
}

fn canonicalize_path<E>(
    path: &str,
    push_segment: impl Fn(&mut String, &str) -> Result<(), E>,
) -> Result<Cow<'_, str>, E> {
    if path.bytes().all(|byte| is_pchar(byte) || byte == b'/') {
        return Ok(Cow::Borrowed(path));
    }
    let mut canonical = String::with_capacity(path.len() + 8);
    for (idx, segment) in path.split('/').enumerate() {
        if idx > 0 {
            canonical.push('/');
        }
        push_segment(&mut canonical, segment)?;
    }
    Ok(Cow::Owned(canonical))
}

fn canonicalize_resource_uri<E>(
    uri: &str,
    push_segment: impl Fn(&mut String, &str) -> Result<(), E>,
) -> Result<Cow<'_, str>, E> {
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
    Ok(match canonicalize_path(resource, push_segment)? {
        Cow::Borrowed(_) => Cow::Borrowed(uri),
        Cow::Owned(resource) => Cow::Owned(format!("{base}/dav/{collection}/{account}/{resource}")),
    })
}

fn push_file_segment(canonical: &mut String, segment: &str) -> Result<(), DavFileNameError> {
    canonical.extend(utf8_percent_encode(&decode_segment(segment)?, FILE_SEGMENT));
    Ok(())
}

fn push_calcard_segment(canonical: &mut String, segment: &str) -> Result<(), Infallible> {
    let decoded: Cow<'_, [u8]> = percent_decode_str(segment).into();
    canonical.extend(percent_encode(&decoded, FILE_SEGMENT));
    Ok(())
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
            assert_eq!(canonical_calcard_segment(expected), expected, "{name:?}");
        }
        assert!(matches!(
            canonical_path_segment("plain-name.txt"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn calcard_names_canonicalize_from_any_spelling() {
        for (segment, expected) in [
            ("event.ics", "event.ics"),
            ("abc@example.org.ics", "abc@example.org.ics"),
            ("abc%40example.org.ics", "abc@example.org.ics"),
            ("file(1)+a:b!$&'*,;=.ics", "file(1)+a:b!$&'*,;=.ics"),
            ("file%281%29%2B.ics", "file(1)+.ics"),
            ("My Event.ics", "My%20Event.ics"),
            ("My%20Event.ics", "My%20Event.ics"),
            ("%c3%9cbersicht.vcf", "%C3%9Cbersicht.vcf"),
            ("\u{dc}bersicht.vcf", "%C3%9Cbersicht.vcf"),
            ("a/b.ics", "a%2Fb.ics"),
            ("a%2Fb.ics", "a%2Fb.ics"),
            ("a%2fb.ics", "a%2Fb.ics"),
            ("a%00b.ics", "a%00b.ics"),
            ("100%", "100%25"),
            ("100%25", "100%25"),
            ("100%zz", "100%25zz"),
            ("%2540", "%2540"),
            ("%e9t%e9.ics", "%E9t%E9.ics"),
            ("caf%E9.ics", "caf%E9.ics"),
            ("caf%25E9.ics", "caf%25E9.ics"),
            ("%E9%c3%bc", "%E9%C3%BC"),
            ("a\"b#c?d.ics", "a%22b%23c%3Fd.ics"),
            ("@", "@"),
            ("%40", "@"),
            ("%00", "%00"),
            (" ", "%20"),
            ("%20", "%20"),
            ("%", "%25"),
            ("%25", "%25"),
            ("/", "%2F"),
            ("%2F", "%2F"),
            ("{", "%7B"),
            ("%7b", "%7B"),
            ("|", "%7C"),
            ("\"", "%22"),
        ] {
            let canonical = canonical_calcard_segment(segment);
            assert_eq!(canonical, expected, "{segment:?}");
            assert_eq!(
                canonical_calcard_segment(&canonical),
                expected,
                "{segment:?}"
            );
        }
        assert!(matches!(
            canonical_calcard_segment("abc@example.org.ics"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn calcard_uris_canonicalize_resource_path() {
        for (uri, expected) in [
            (
                "/dav/cal/john%40example.com/home/abc%40example.org.ics",
                "/dav/cal/john%40example.com/home/abc@example.org.ics",
            ),
            (
                "https://host:8080/dav/card/john/My%20Book/a%2fb%c3%bc.vcf",
                "https://host:8080/dav/card/john/My%20Book/a%2Fb%C3%BC.vcf",
            ),
            ("/dav/cal/john/work%40home/", "/dav/cal/john/work@home/"),
            ("/dav/cal/john/a%2Fb/c.ics", "/dav/cal/john/a%2Fb/c.ics"),
            ("/dav/cal/john/home/%7b", "/dav/cal/john/home/%7B"),
            ("/dav/cal/john/home/%00", "/dav/cal/john/home/%00"),
            (
                "/dav/card/john/book/caf%e9.vcf",
                "/dav/card/john/book/caf%E9.vcf",
            ),
        ] {
            assert_eq!(canonical_calcard_uri(uri), expected, "{uri}");
        }
        for uri in [
            "/dav/cal/john/home/abc@example.org.ics",
            "/dav/cal/john%40example.com",
            "/dav/cal/john/",
            "/dav/cal",
        ] {
            assert!(
                matches!(canonical_calcard_uri(uri), Cow::Borrowed(_)),
                "{uri}"
            );
        }
    }
}
