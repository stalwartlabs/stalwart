/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{ByteRange, Condition, Depth, If, RequestHeaders, ResourceState, Return, Timeout};
use calcard::vcard::VCardVersion;
use std::ops::Range;

impl<'x> RequestHeaders<'x> {
    pub fn new(uri: &'x str) -> Self {
        RequestHeaders {
            uri,
            ..Default::default()
        }
    }

    pub fn parse(&mut self, key: &str, value: &'x str) -> bool {
        hashify::fnc_map_ignore_case!(key.as_bytes(),
            "Depth" => {
                if let Some(depth) = Depth::parse(value.as_bytes()) {
                    self.depth = depth;
                    return true;
                }
            },
            "Destination" => {
                self.destination = Some(value);
                return true;
            },
            "Lock-Token" => {
                self.lock_token = Some(try_unwrap_coded_url(value));
                return true;
            },
            "If" => {
                let num = self.if_.len();
                self.parse_if(value);
                return self.if_.len() != num;
            },
            "If-Match" => {
                let num = self.if_.len();
                self.parse_if_match(value, false);
                return self.if_.len() != num;
            },
            "If-None-Match" => {
                let num = self.if_.len();
                self.parse_if_match(value, true);
                return self.if_.len() != num;
            },
            "Timeout" => {
                let value = value.split_once(',').map(|(first, _)| first).unwrap_or(value).trim();
                if let Some(seconds) = value.strip_prefix("Second-") {
                    if let Ok(seconds) = seconds.parse() {
                        self.timeout = Timeout::Second(seconds);
                        return true;
                    }
                } else if value == "Infinite" {
                    self.timeout = Timeout::Infinite;
                    return true;
                }
            },
            "Overwrite" => {
                self.overwrite_fail = value == "F";
                return true;
            },
            "CalDAV-Timezones" => {
                self.no_timezones = value == "F";
                return true;
            },
            "Prefer" => {
                for value in value.split(&[',', ';']) {
                    match value.trim() {
                        "return=minimal" => self.ret = Return::Minimal,
                        "return=representation" => self.ret = Return::Representation,
                        "depth-noroot" => self.depth_no_root = true,
                        _ => {}
                    }
                }
            },
            "Content-Type" => {
                let value = value.trim();
                if (2..=127).contains(&value.len()) {
                    self.content_type = Some(value);
                }
                return true;
            },
            "Accept" => {
                let mut preferred: Option<(f32, VCardVersion)> = None;

                for entry in value.split(',') {
                    let mut parts = entry.split(';');
                    if !parts.next().is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/vcard")) {
                        continue;
                    }

                    let mut version = None;
                    let mut quality = 1.0;

                    for param in parts {
                        let Some((name, param_value)) = param.split_once('=') else {
                            continue;
                        };
                        let param_value = param_value.trim().trim_matches('"');

                        if name.trim().eq_ignore_ascii_case("version") {
                            version = VCardVersion::try_parse(param_value);
                        } else if name.trim().eq_ignore_ascii_case("q") {
                            quality = param_value.parse().unwrap_or(1.0);
                        }
                    }

                    if let Some(version) = version
                        && quality > 0.0
                        && preferred.is_none_or(|(preferred_quality, _)| quality > preferred_quality) {
                        preferred = Some((quality, version));
                    }
                }

                if let Some((_, version)) = preferred {
                    self.vcard_version = Some(version);
                }
                return true;
            },
            "If-Schedule-Tag-Match" => {
                self.if_schedule_tag = value.trim().trim_matches('"').parse().ok();
                return true;
            },
            "Schedule-Reply" => {
                self.no_schedule_reply = value == "F";
                return true;
            },
            "Range" => {
                self.range = ByteRange::parse(value);
                return self.range.is_some();
            },
            "If-Range" => {
                self.if_range = Some(value.trim());
                return true;
            },
            _ => {}
        );

        false
    }

    pub fn has_if(&self) -> bool {
        !self.if_.is_empty()
    }

    pub fn eval_if_resources(&self) -> impl Iterator<Item = &str> {
        self.if_.iter().filter_map(|if_| if_.resource)
    }

    pub fn eval_if<T>(&self, resources: &[ResourceState<T>]) -> bool
    where
        T: AsRef<str>,
    {
        if self.if_.is_empty() {
            return true;
        }

        'outer: for if_ in &self.if_ {
            if if_.list.is_empty() {
                continue;
            }

            let (current_token, current_etag) = resources
                .iter()
                .find_map(|r| {
                    if if_.resource == r.resource.as_ref().map(|v| v.as_ref()) {
                        Some((r.state_token.as_ref(), r.etag.as_ref()))
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            for cond in if_.list.iter() {
                match cond {
                    Condition::StateToken { is_not, token } => {
                        if !((current_token == *token) ^ is_not) {
                            continue 'outer;
                        }
                    }
                    Condition::ETag { is_not, tag } => {
                        if !((current_etag == *tag) ^ is_not) {
                            continue 'outer;
                        }
                    }
                    Condition::Exists { is_not } => {
                        if !((current_etag.is_empty()) ^ is_not) {
                            continue 'outer;
                        }
                    }
                }
            }

            return true;
        }

        false
    }

    fn parse_if(&mut self, value: &'x str) {
        let value = value.as_bytes();
        let mut iter = value.iter().enumerate();
        let mut resource = None;

        while let Some((idx, ch)) = iter.next() {
            match ch {
                b'<' if resource.is_none() => {
                    for (to_idx, ch) in iter.by_ref() {
                        if *ch == b'>' {
                            resource = Some(std::str::from_utf8(&value[idx + 1..to_idx]).unwrap());
                            break;
                        }
                    }
                }
                b'(' => {
                    let mut is_not = false;
                    let mut conditions = Vec::new();
                    while let Some((idx, ch)) = iter.next() {
                        match ch {
                            b'N' => {
                                if matches!(iter.next(), Some((_, b'o')))
                                    && matches!(iter.next(), Some((_, b't')))
                                {
                                    is_not = true;
                                } else {
                                    return;
                                }
                            }
                            b'<' | b'[' => {
                                let (stop_char, is_etag) = match ch {
                                    b'<' => (b'>', false),
                                    b'[' => (b']', true),
                                    _ => unreachable!(),
                                };

                                for (to_idx, ch) in iter.by_ref() {
                                    if *ch == stop_char {
                                        let value =
                                            std::str::from_utf8(&value[idx + 1..to_idx]).unwrap();
                                        let condition = if is_etag {
                                            Condition::ETag { is_not, tag: value }
                                        } else {
                                            Condition::StateToken {
                                                is_not,
                                                token: value,
                                            }
                                        };
                                        conditions.push(condition);
                                        is_not = false;
                                        break;
                                    }
                                }
                            }
                            b')' => {
                                self.if_.push(If {
                                    resource: resource.take(),
                                    list: conditions,
                                });
                                break;
                            }
                            _ => {
                                if !ch.is_ascii_whitespace() {
                                    return;
                                }
                            }
                        }
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return;
                    }
                }
            }
        }
    }

    pub fn parse_if_match(&mut self, value: &'x str, is_not: bool) {
        if value == "*" {
            self.if_.push(If {
                resource: None,
                list: vec![Condition::Exists { is_not }],
            });
        } else if !is_not {
            for etag in value.split(',') {
                self.if_.push(If {
                    resource: None,
                    list: vec![Condition::ETag {
                        is_not,
                        tag: etag.trim(),
                    }],
                });
            }
        } else {
            let mut etags = Vec::new();
            for etag in value.split(',') {
                etags.push(Condition::ETag {
                    is_not,
                    tag: etag.trim(),
                });
            }
            self.if_.push(If {
                resource: None,
                list: etags,
            });
        }
    }

    pub fn eval_if_range(&self, etag: &str, last_modified: Option<&str>) -> bool {
        match self.if_range {
            Some(validator) => {
                !validator.starts_with("W/")
                    && (validator == etag
                        || last_modified.is_some_and(|last_modified| validator == last_modified))
            }
            None => true,
        }
    }

    pub fn base_uri(&self) -> Option<&str> {
        dav_base_uri(self.uri)
    }
}

impl ByteRange {
    pub fn parse(value: &str) -> Option<Self> {
        let (unit, spec) = value.split_once('=')?;
        if !unit.trim().eq_ignore_ascii_case("bytes") || spec.contains(',') {
            return None;
        }

        let (start, end) = spec.split_once('-')?;
        let (start, end) = (start.trim(), end.trim());

        if !start.is_empty() {
            let start = start.parse::<u64>().ok()?;
            let end = if !end.is_empty() {
                let end = end.parse::<u64>().ok()?;
                if end < start {
                    return None;
                }
                Some(end)
            } else {
                None
            };

            Some(ByteRange::Offset { start, end })
        } else {
            end.parse::<u64>().ok().map(ByteRange::Suffix)
        }
    }

    pub fn resolve(&self, size: u64) -> Option<Range<u64>> {
        match self {
            ByteRange::Offset { start, end } if *start < size => {
                Some(*start..end.map_or(size, |end| std::cmp::min(end.saturating_add(1), size)))
            }
            ByteRange::Suffix(length) if *length > 0 && size > 0 => {
                Some(size.saturating_sub(*length)..size)
            }
            _ => None,
        }
    }
}

pub fn dav_base_uri(uri: &str) -> Option<&str> {
    // From a path ../dav/collection/account/..
    // returns ../dav/collection/account without the trailing slash

    let uri = uri.as_bytes();
    let mut found_dav = false;
    let mut last_idx = 0;
    let mut sep_count = 0;

    for (idx, ch) in uri.iter().enumerate() {
        if *ch == b'/' {
            if !found_dav {
                found_dav = uri.get(idx + 1..idx + 5).is_some_and(|s| s == b"dav/");
            } else if found_dav {
                if sep_count == 2 {
                    break;
                }
                sep_count += 1;
            }
        }
        last_idx = idx;
    }

    if sep_count == 2 {
        uri.get(..last_idx + 1)
            .map(|uri| std::str::from_utf8(uri).unwrap())
    } else {
        None
    }
}

impl Depth {
    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::tiny_map!(value,
            "0" => Depth::Zero,
            "1" => Depth::One,
            "infinity" => Depth::Infinity,
            "infinite" => Depth::Infinity,
        )
    }
}

fn try_unwrap_coded_url(url: &str) -> &str {
    url.strip_prefix("<")
        .and_then(|url| url.strip_suffix(">"))
        .unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accept_vcard_version() {
        for (header, expected) in [
            ("text/vcard", None),
            ("application/json", None),
            ("text/vcard; version=3.0", Some(VCardVersion::V3_0)),
            ("text/vcard;version=\"3.0\"", Some(VCardVersion::V3_0)),
            ("text/vcard; VERSION=3.0", Some(VCardVersion::V3_0)),
            ("text/vcard; version=3.0; q=1.0", Some(VCardVersion::V3_0)),
            (
                "text/vcard; version=3.0; charset=utf-8",
                Some(VCardVersion::V3_0),
            ),
            (
                "text/vcard; charset=utf-8; version=3.0",
                Some(VCardVersion::V3_0),
            ),
            (
                "text/vcard; version=4.0, text/vcard; version=3.0",
                Some(VCardVersion::V4_0),
            ),
            (
                "text/vcard; version=4.0; q=0.5, text/vcard; version=3.0",
                Some(VCardVersion::V3_0),
            ),
            (
                "text/vcard; q=0.5; version=4.0, text/vcard; q=1.0; version=3.0",
                Some(VCardVersion::V3_0),
            ),
            (
                "text/vcard; version=4.0; q=0, text/vcard; version=3.0; q=0.1",
                Some(VCardVersion::V3_0),
            ),
            ("*/*, text/vcard; version=3.0", Some(VCardVersion::V3_0)),
            ("text/vcard-custom; version=3.0", None),
        ] {
            let mut headers = RequestHeaders::new("/dav/card/test/default/");
            assert!(headers.parse("Accept", header));
            assert_eq!(headers.vcard_version, expected, "failed for {header:?}");
        }
    }

    #[test]
    fn parse_range() {
        for (header, expected) in [
            (
                "bytes=0-499",
                Some(ByteRange::Offset {
                    start: 0,
                    end: Some(499),
                }),
            ),
            (
                "bytes=500-",
                Some(ByteRange::Offset {
                    start: 500,
                    end: None,
                }),
            ),
            (
                "bytes = 500 - 999 ",
                Some(ByteRange::Offset {
                    start: 500,
                    end: Some(999),
                }),
            ),
            (
                "BYTES=0-0",
                Some(ByteRange::Offset {
                    start: 0,
                    end: Some(0),
                }),
            ),
            ("bytes=-500", Some(ByteRange::Suffix(500))),
            ("bytes=-0", Some(ByteRange::Suffix(0))),
            ("bytes=0-499,600-999", None),
            ("bytes=499-100", None),
            ("bytes=abc-def", None),
            ("bytes=-", None),
            ("bytes=0", None),
            ("items=0-499", None),
            ("0-499", None),
        ] {
            let mut headers = RequestHeaders::new("/dav/file/test/file.txt");
            assert_eq!(headers.parse("Range", header), expected.is_some());
            assert_eq!(headers.range, expected, "failed for {header:?}");
        }

        for (range, size, expected) in [
            (
                ByteRange::Offset {
                    start: 0,
                    end: Some(499),
                },
                1000,
                Some(0..500),
            ),
            (
                ByteRange::Offset {
                    start: 0,
                    end: Some(499),
                },
                100,
                Some(0..100),
            ),
            (
                ByteRange::Offset {
                    start: 500,
                    end: None,
                },
                1000,
                Some(500..1000),
            ),
            (
                ByteRange::Offset {
                    start: 999,
                    end: Some(u64::MAX),
                },
                1000,
                Some(999..1000),
            ),
            (
                ByteRange::Offset {
                    start: 1000,
                    end: None,
                },
                1000,
                None,
            ),
            (
                ByteRange::Offset {
                    start: 0,
                    end: None,
                },
                0,
                None,
            ),
            (ByteRange::Suffix(500), 1000, Some(500..1000)),
            (ByteRange::Suffix(5000), 1000, Some(0..1000)),
            (ByteRange::Suffix(0), 1000, None),
            (ByteRange::Suffix(500), 0, None),
        ] {
            assert_eq!(
                range.resolve(size),
                expected,
                "failed for {range:?} of {size}"
            );
        }
    }

    #[test]
    fn eval_if_range_header() {
        const LAST_MODIFIED: &str = "Mon, 10 Aug 2026 12:00:00 GMT";

        let mut headers = RequestHeaders::new("/dav/file/test/file.txt");
        assert!(headers.eval_if_range("\"etag\"", Some(LAST_MODIFIED)));

        for (validator, expected) in [
            ("\"etag\"", true),
            (LAST_MODIFIED, true),
            ("W/\"etag\"", false),
            ("\"other\"", false),
            ("Sun, 09 Aug 2026 12:00:00 GMT", false),
        ] {
            assert!(headers.parse("If-Range", validator));
            assert_eq!(
                headers.eval_if_range("\"etag\"", Some(LAST_MODIFIED)),
                expected,
                "failed for {validator:?}"
            );
        }

        for (validator, expected) in [("\"etag\"", true), (LAST_MODIFIED, false)] {
            assert!(headers.parse("If-Range", validator));
            assert_eq!(
                headers.eval_if_range("\"etag\"", None),
                expected,
                "failed for {validator:?}"
            );
        }
    }

    #[test]
    fn base_uri() {
        for (uri, expected_base) in [
            (
                "http://host/dav/collection/account/test/",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dav/collection/account/test",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dav/collection/account/",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dav/collection/account",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account/test/",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account/test",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account/",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "/dav/collection/account/test/",
                Some("/dav/collection/account"),
            ),
            (
                "/dav/collection/account/test",
                Some("/dav/collection/account"),
            ),
            ("/dav/collection/account/", Some("/dav/collection/account")),
            ("/dav/collection/account", Some("/dav/collection/account")),
        ] {
            assert_eq!(RequestHeaders::new(uri).base_uri(), expected_base);
        }
    }

    #[test]
    fn eval_if_header() {
        let mut headers = RequestHeaders::default();
        assert!(headers.parse(
            "If",
            r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
   ["I am an ETag"])
   (["I am another ETag"])"#,
        ));

        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: "\"I am an ETag\""
        }]));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "",
            etag: "\"I am another ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "",
            etag: "\"Unknown ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: ""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: "\"Other ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "",
            etag: "\"I am an ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:blah",
            etag: "\"I am an ETag\""
        }]));

        assert!(headers.parse(
            "If",
            r#"(Not <urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
     <urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092>)"#,
        ));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092",
            etag: ""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: ""
        }]));

        assert!(headers.parse(
            "If",
            r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)
       (Not <DAV:no-lock>)"#
        ));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: ""
        }]));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:other-token",
            etag: ""
        }]));
    }

    #[test]
    fn parse_headers() {
        let mut headers = RequestHeaders::default();
        assert!(headers.parse("Depth", "0"));
        assert_eq!(headers.depth, Depth::Zero);

        assert!(headers.parse("Destination", "/path/to/destination"));
        assert_eq!(headers.destination, Some("/path/to/destination"));

        assert!(headers.parse("Lock-Token", "<urn:uuid:1234>"));
        assert_eq!(headers.lock_token, Some("urn:uuid:1234"));

        for (input, expected) in [
            (
                "<urn:uuid:1234>(<urn:uuid:1234>)",
                vec![If {
                    resource: "urn:uuid:1234".into(),
                    list: vec![Condition::StateToken {
                        is_not: false,
                        token: "urn:uuid:1234",
                    }],
                }],
            ),
            (
                "<>(<>)",
                vec![If {
                    resource: "".into(),
                    list: vec![Condition::StateToken {
                        is_not: false,
                        token: "",
                    }],
                }],
            ),
            (
                r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
       ["I am an ETag"])
       (["I am another ETag"])"#,
                vec![
                    If {
                        resource: None,
                        list: vec![
                            Condition::StateToken {
                                is_not: false,
                                token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                            },
                            Condition::ETag {
                                is_not: false,
                                tag: "\"I am an ETag\"",
                            },
                        ],
                    },
                    If {
                        resource: None,
                        list: vec![Condition::ETag {
                            is_not: false,
                            tag: "\"I am another ETag\"",
                        }],
                    },
                ],
            ),
            (
                r#"(Not <urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
     <urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092>)"#,
                vec![If {
                    resource: None,
                    list: vec![
                        Condition::StateToken {
                            is_not: true,
                            token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                        },
                        Condition::StateToken {
                            is_not: false,
                            token: "urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092",
                        },
                    ],
                }],
            ),
            (
                r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)
       (Not <DAV:no-lock>)"#,
                vec![
                    If {
                        resource: None,
                        list: vec![Condition::StateToken {
                            is_not: false,
                            token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                        }],
                    },
                    If {
                        resource: None,
                        list: vec![Condition::StateToken {
                            is_not: true,
                            token: "DAV:no-lock",
                        }],
                    },
                ],
            ),
            (
                r#"</resource1>
                 (<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
                 [W/"A weak ETag"]) (["strong ETag"])"#,
                vec![
                    If {
                        resource: "/resource1".into(),
                        list: vec![
                            Condition::StateToken {
                                is_not: false,
                                token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                            },
                            Condition::ETag {
                                is_not: false,
                                tag: "W/\"A weak ETag\"",
                            },
                        ],
                    },
                    If {
                        resource: None,
                        list: vec![Condition::ETag {
                            is_not: false,
                            tag: "\"strong ETag\"",
                        }],
                    },
                ],
            ),
            (
                r#"<http://www.example.com/specs/>
            (<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)"#,
                vec![If {
                    resource: "http://www.example.com/specs/".into(),
                    list: vec![Condition::StateToken {
                        is_not: false,
                        token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                    }],
                }],
            ),
            (
                r#"</specs/rfc2518.doc> (["4217"])"#,
                vec![If {
                    resource: "/specs/rfc2518.doc".into(),
                    list: vec![Condition::ETag {
                        is_not: false,
                        tag: "\"4217\"",
                    }],
                }],
            ),
            (
                r#"</specs/rfc2518.doc> (Not ["4217"])"#,
                vec![If {
                    resource: "/specs/rfc2518.doc".into(),
                    list: vec![Condition::ETag {
                        is_not: true,
                        tag: "\"4217\"",
                    }],
                }],
            ),
            (
                r#"</test/file.txt> (["1234"]) </specs/rfc2518.doc> (Not ["4217"])"#,
                vec![
                    If {
                        resource: "/test/file.txt".into(),
                        list: vec![Condition::ETag {
                            is_not: false,
                            tag: "\"1234\"",
                        }],
                    },
                    If {
                        resource: "/specs/rfc2518.doc".into(),
                        list: vec![Condition::ETag {
                            is_not: true,
                            tag: "\"4217\"",
                        }],
                    },
                ],
            ),
        ] {
            assert!(headers.parse("If", input));
            assert_eq!(headers.if_, expected, "Failed for input: {}", input);
            headers.if_.clear();
        }

        assert!(headers.parse("If-Match", "*"));
        assert_eq!(
            headers.if_,
            vec![If {
                resource: None,
                list: vec![Condition::Exists { is_not: false }],
            }]
        );
        headers.if_.clear();

        assert!(headers.parse("If-None-Match", "etag1, etag2"));
        assert_eq!(
            headers.if_,
            vec![If {
                resource: None,
                list: vec![
                    Condition::ETag {
                        is_not: true,
                        tag: "etag1",
                    },
                    Condition::ETag {
                        is_not: true,
                        tag: "etag2",
                    }
                ],
            },]
        );

        assert!(headers.parse("Timeout", "Second-10"));
        assert_eq!(headers.timeout, Timeout::Second(10));

        assert!(headers.parse("Timeout", "Infinite, Second-4100000000"));
        assert_eq!(headers.timeout, Timeout::Infinite);

        assert!(headers.parse("Overwrite", "F"));
        assert!(headers.overwrite_fail);
    }
}
