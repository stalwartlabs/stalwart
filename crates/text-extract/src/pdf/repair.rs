/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    lexer::{Lexer, Token, is_regular, is_whitespace},
    object::{
        Dict, Indirect, ObjRef, Object, keyword_after, keyword_at, skip_container,
        stream_data_start,
    },
    seek::Seek,
    source::Source,
};
use memchr::{memchr2, memmem::Finder};

const TRAILER: &[u8] = b"trailer";
const STREAM: &[u8] = b"stream";
const OBJ: &[u8] = b"obj";
const TRAILER_LEN: u32 = TRAILER.len() as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Plain,
    XRef,
    ObjStm,
    Catalog,
    PageTree,
    Page,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Found {
    pub(crate) id: ObjRef,
    pub(crate) offset: u32,
    pub(crate) kind: Kind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Trailer {
    pub(crate) offset: u32,
    pub(crate) end: u32,
}

#[derive(Default)]
pub(crate) struct Scan {
    pub(crate) objects: Vec<Found>,
    pub(crate) trailers: Vec<Trailer>,
}

struct Headers<'a> {
    data: &'a [u8],
    finder: Finder<'static>,
    seek: Seek,
}

impl Kind {
    pub(crate) fn of(dict: Dict<'_>) -> Self {
        let Some(kind) = dict.get(b"Type").and_then(|kind| kind.as_name()) else {
            return if dict.contains(b"Parent") && dict.contains(b"Contents") {
                Kind::Page
            } else {
                Kind::Plain
            };
        };
        hashify::fnc_map!(kind.decoded(),
            b"XRef" => Kind::XRef,
            b"ObjStm" => Kind::ObjStm,
            b"Catalog" => Kind::Catalog,
            b"Pages" => {
                if dict.contains(b"Parent") {
                    Kind::Plain
                } else {
                    Kind::PageTree
                }
            },
            b"Page" => Kind::Page,
            _ => Kind::Plain
        )
    }
}

impl Scan {
    pub(crate) fn run(source: &Source<'_>) -> Self {
        let data = source.data;
        let mut headers = Headers::new(data);
        let mut scan = Scan::default();
        let mut pos = 0usize;
        while let Some(&byte) = data.get(pos) {
            if is_whitespace(byte) {
                pos += 1;
            } else if byte == b'%' {
                pos = memchr2(b'\r', b'\n', data.get(pos..).unwrap_or_default())
                    .map_or(data.len(), |offset| pos + offset);
            } else if byte.is_ascii_digit()
                && pos
                    .checked_sub(1)
                    .and_then(|before| data.get(before))
                    .is_none_or(|&before| !is_regular(before))
            {
                pos = match Indirect::header(data, pos) {
                    Some((id, lexer)) => {
                        let body = lexer.pos();
                        let limit = headers.next(body);
                        let Some(end) = scan.object(source, pos, id, body, limit) else {
                            break;
                        };
                        end
                    }
                    None => run_end(data, pos),
                };
            } else if is_regular(byte) {
                if keyword_at(data, pos, TRAILER) {
                    scan.trailer(pos, headers.next(pos + TRAILER.len()));
                }
                pos = run_end(data, pos);
            } else {
                pos += 1;
            }
        }
        scan.bound_trailers();
        scan
    }

    fn object(
        &mut self,
        source: &Source<'_>,
        start: usize,
        id: ObjRef,
        body: usize,
        limit: usize,
    ) -> Option<usize> {
        let bounded = source.data.get(..limit.max(body)).unwrap_or(source.data);
        let (kind, end, lexed) = body_end(source, bounded, body);
        if !source.charge_scan(lexed.saturating_sub(body)) {
            return None;
        }
        if let Ok(offset) = u32::try_from(start) {
            self.objects.push(Found { id, offset, kind });
        }
        Some(end.max(body).max(start + 1))
    }

    fn trailer(&mut self, keyword: usize, limit: usize) {
        if let (Ok(offset), Ok(end)) =
            (u32::try_from(keyword + TRAILER.len()), u32::try_from(limit))
        {
            self.trailers.push(Trailer { offset, end });
        }
    }

    fn bound_trailers(&mut self) {
        let mut next_start = u32::MAX;
        for trailer in self.trailers.iter_mut().rev() {
            trailer.end = trailer.end.min(next_start);
            next_start = trailer.offset.saturating_sub(TRAILER_LEN);
        }
    }
}

impl Trailer {
    pub(crate) fn dict<'a>(&self, data: &'a [u8]) -> Option<Dict<'a>> {
        let bounded = data.get(..self.end as usize).unwrap_or(data);
        Object::read(&mut Lexer::at(bounded, self.offset as usize), None)?.as_dict()
    }
}

impl<'a> Headers<'a> {
    fn new(data: &'a [u8]) -> Self {
        Headers {
            data,
            finder: Finder::new(OBJ),
            seek: Seek::default(),
        }
    }

    fn next(&mut self, from: usize) -> usize {
        let Headers { data, finder, seek } = self;
        seek.find(from, |from| {
            finder.find_iter(data.get(from..)?).find_map(|offset| {
                Indirect::header_before(data, from + offset).filter(|&start| start >= from)
            })
        })
        .unwrap_or(data.len())
    }
}

fn run_end(data: &[u8], pos: usize) -> usize {
    data.get(pos..)
        .unwrap_or_default()
        .iter()
        .position(|&byte| !is_regular(byte))
        .map_or(data.len(), |offset| pos + offset)
        .max(pos + 1)
}

fn body_end(source: &Source<'_>, bounded: &[u8], body: usize) -> (Kind, usize, usize) {
    let mut lexer = Lexer::at(bounded, body);
    lexer.skip_whitespace();
    let dict_start = lexer.pos();
    if lexer.next() != Some(Token::DictOpen) {
        return (Kind::Plain, dict_start, lexer.pos());
    }
    let (span, closed) = skip_container(&mut lexer);
    if !closed {
        return (Kind::Plain, dict_start + 2, lexer.pos());
    }
    let dict = Dict::new(span, None);
    let kind = Kind::of(dict);
    let after_dict = lexer.pos();
    let Some(after_keyword) = keyword_after(lexer, STREAM) else {
        return (kind, after_dict, after_dict);
    };
    let start = stream_data_start(source.data, after_keyword);
    let length = dict.get(b"Length").and_then(|length| match length {
        Object::Int(value) => Some(value),
        _ => None,
    });
    (
        kind,
        source.stream_end(start, length).unwrap_or(start),
        after_keyword,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pdf::source::Codec, xml::stream::Budget};

    fn budget() -> Budget {
        Budget {
            part_bytes: 1 << 20,
            total_bytes: 1 << 20,
            parts: usize::MAX,
            used_bytes: 0,
            used_parts: 0,
            truncated: false,
        }
    }

    #[test]
    fn scan_finds_objects_and_skips_stream_bodies() {
        let data = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n\
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj 3 0 obj <</Type /Page /Parent 2 0 R>>\n\
4 0 obj << /Length 18 >>\nstream\n9 0 obj fake endobj\nendstream endobj\n\
5 0 obj << /Length 99 >> stream\nabc 8 0 obj\nendstream\nendobj\n\
trailer << /Root 1 0 R >>\n1 0 obj << /Type /Catalog /Pages 2 0 R /V 2 >>";
        let mut codec = Codec::default();
        let source = Source::new(data, &mut codec, budget());
        let scan = Scan::run(&source);
        let found: Vec<(u32, Kind)> = scan
            .objects
            .iter()
            .map(|found| (found.id.num, found.kind))
            .collect();
        assert_eq!(
            found,
            vec![
                (1, Kind::Catalog),
                (2, Kind::PageTree),
                (3, Kind::Page),
                (4, Kind::Plain),
                (5, Kind::Plain),
                (1, Kind::Catalog),
            ]
        );
        assert_eq!(scan.trailers.len(), 1);
    }
}
