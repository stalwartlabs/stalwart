/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Write;

use smallvec::SmallVec;

use super::{
    error::BodyError,
    http::{ResponseCode, header},
};
use crate::common::UtcSeconds;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaTag {
    Processing,
    Pending,
    Done,
}

impl MetaTag {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            MetaTag::Processing => b"PROCESSING\r\n",
            MetaTag::Pending => b"PENDING\r\n",
            MetaTag::Done => b"DONE\r\n",
        }
    }

    fn parse(line: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(line, MetaTag,
            "PROCESSING" => MetaTag::Processing,
            "PENDING" => MetaTag::Pending,
            "DONE" => MetaTag::Done,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoneTrailer {
    pub start: UtcSeconds,
    pub elapsed_ms: u32,
    pub response_code: Option<ResponseCode>,
}

pub fn write_meta(out: &mut Vec<u8>, tag: MetaTag) {
    out.extend_from_slice(tag.as_bytes());
}

pub fn write_done(out: &mut Vec<u8>, trailer: &DoneTrailer) {
    out.extend_from_slice(MetaTag::Done.as_bytes());
    out.extend_from_slice(header::START_TIME.as_bytes());
    out.extend_from_slice(b": ");
    trailer.start.write_http_date(out);
    let _ = write!(
        out,
        "\r\n{}: {}\r\n",
        header::ELAPSED_TIME,
        trailer.elapsed_ms
    );
    if let Some(code) = trailer.response_code {
        let _ = write!(out, "{}: {}\r\n", header::RESPONSE_CODE, code.code());
    }
    out.extend_from_slice(b"\r\n");
}

pub fn write_bounded_response(out: &mut Vec<u8>, trailer: &DoneTrailer, body: &[u8]) {
    out.reserve(body.len().saturating_add(96));
    write_meta(out, MetaTag::Processing);
    write_done(out, trailer);
    out.extend_from_slice(body);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedStream<'a> {
    pub tags: SmallVec<[MetaTag; 4]>,
    pub headers: SmallVec<[(&'a str, &'a str); 4]>,
    pub body: &'a [u8],
}

impl<'a> ParsedStream<'a> {
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    pub fn response_code(&self) -> Option<u32> {
        self.header(header::RESPONSE_CODE)?.trim().parse().ok()
    }
}

fn split_line(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = memchr::memmem::find(input, b"\r\n")?;
    let (line, rest) = input.split_at_checked(pos)?;
    Some((line, rest.get(2..)?))
}

pub fn parse_response_stream(stream: &[u8]) -> Result<ParsedStream<'_>, BodyError> {
    let mut tags = SmallVec::new();
    let mut rest = stream;
    loop {
        let Some((line, after)) = split_line(rest) else {
            if tags.is_empty() {
                return Ok(ParsedStream {
                    tags,
                    headers: SmallVec::new(),
                    body: stream,
                });
            }
            return Err(BodyError::BadMetaStream);
        };
        match MetaTag::parse(line) {
            Some(tag) => {
                tags.push(tag);
                rest = after;
                if tag == MetaTag::Done {
                    break;
                }
            }
            None if tags.is_empty() => {
                return Ok(ParsedStream {
                    tags,
                    headers: SmallVec::new(),
                    body: stream,
                });
            }
            None => return Err(BodyError::BadMetaStream),
        }
    }
    let mut headers = SmallVec::new();
    loop {
        let (line, after) = split_line(rest).ok_or(BodyError::BadMetaStream)?;
        rest = after;
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(line).map_err(|_| BodyError::BadMetaStream)?;
        let (name, value) = line.split_once(':').ok_or(BodyError::BadMetaStream)?;
        headers.push((name.trim(), value.trim()));
    }
    Ok(ParsedStream {
        tags,
        headers,
        body: rest,
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/stream/tests.rs"]
mod tests;
