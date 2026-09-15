/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Handler, Tag, scan::Scanner};
use crate::{output::Output, zip::MemberData};
use encoding_rs::{CoderResult, Decoder, Encoding, UTF_8, UTF_16BE, UTF_16LE};
use flate2::{Decompress, FlushDecompress, Status};
use memchr::memmem;

pub(crate) const WINDOW: usize = 1 << 16;
const SNIFF_LEN: usize = 1024;

pub(crate) struct Budget {
    pub(crate) part_bytes: u64,
    pub(crate) total_bytes: u64,
    pub(crate) parts: usize,
    pub(crate) used_bytes: u64,
    pub(crate) used_parts: usize,
    pub(crate) truncated: bool,
}

impl Budget {
    fn part_cap(&self) -> u64 {
        self.part_bytes
            .min(self.total_bytes.saturating_sub(self.used_bytes))
    }

    fn charge(&mut self, bytes: usize) {
        self.used_bytes = self.used_bytes.saturating_add(bytes as u64);
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.used_parts >= self.parts || self.used_bytes >= self.total_bytes
    }
}

#[derive(Default)]
pub(crate) struct Buffers {
    window: Vec<u8>,
    raw: Vec<u8>,
    inflater: Option<Decompress>,
}

enum Sniff {
    Utf8 {
        skip: usize,
    },
    Encoded {
        encoding: &'static Encoding,
        skip: usize,
    },
    NotXml,
}

enum Source<'a> {
    Stored {
        data: &'a [u8],
    },
    Inflate {
        data: &'a [u8],
        inflater: &'a mut Decompress,
        done: bool,
    },
}

impl Source<'_> {
    fn fill(&mut self, dst: &mut [u8]) -> usize {
        match self {
            Source::Stored { data } => {
                let len = data.len().min(dst.len());
                let (head, tail) = data.split_at(len);
                if let Some(slot) = dst.get_mut(..len) {
                    slot.copy_from_slice(head);
                }
                *data = tail;
                len
            }
            Source::Inflate {
                data,
                inflater,
                done,
            } => {
                if *done || dst.is_empty() {
                    return 0;
                }
                let before_in = inflater.total_in();
                let before_out = inflater.total_out();
                let status = inflater.decompress(data, dst, FlushDecompress::None);
                let consumed = usize::try_from(inflater.total_in().saturating_sub(before_in))
                    .unwrap_or(usize::MAX);
                let produced = usize::try_from(inflater.total_out().saturating_sub(before_out))
                    .unwrap_or(usize::MAX);
                *data = data.get(consumed..).unwrap_or_default();
                if !matches!(status, Ok(Status::Ok | Status::BufError))
                    || (produced == 0 && (consumed == 0 || data.is_empty()))
                {
                    *done = true;
                }
                produced.min(dst.len())
            }
        }
    }

    fn finished(&self) -> bool {
        match self {
            Source::Stored { data } => data.is_empty(),
            Source::Inflate { done, .. } => *done,
        }
    }
}

impl Buffers {
    pub(crate) fn scan<H: Handler>(
        &mut self,
        member: MemberData<'_>,
        budget: &mut Budget,
        handler: &mut H,
        out: &mut Output<'_>,
    ) {
        if budget.exhausted() {
            budget.truncated = true;
            return;
        }
        budget.used_parts += 1;
        let cap = usize::try_from(budget.part_cap()).unwrap_or(usize::MAX);
        match member {
            MemberData::Stored(data) => {
                let bounded = data.get(..cap).unwrap_or(data);
                if bounded.len() < data.len() {
                    budget.truncated = true;
                }
                match sniff(bounded) {
                    Sniff::Utf8 { skip } => {
                        budget.charge(bounded.len());
                        Scanner::default().feed(
                            bounded.get(skip..).unwrap_or_default(),
                            true,
                            handler,
                            out,
                        );
                    }
                    Sniff::Encoded { encoding, skip } => {
                        let source = Source::Stored {
                            data: bounded.get(skip..).unwrap_or_default(),
                        };
                        self.decode(source, encoding, cap, budget, handler, out);
                    }
                    Sniff::NotXml => (),
                }
            }
            MemberData::Deflated(data) => {
                let inflater = match &mut self.inflater {
                    Some(inflater) => {
                        inflater.reset(false);
                        inflater
                    }
                    None => self.inflater.insert(Decompress::new(false)),
                };
                let source = Source::Inflate {
                    data,
                    inflater,
                    done: false,
                };
                Self::stream(
                    &mut self.window,
                    &mut self.raw,
                    source,
                    cap,
                    budget,
                    handler,
                    out,
                );
            }
        }
    }

    fn decode<H: Handler>(
        &mut self,
        source: Source<'_>,
        encoding: &'static Encoding,
        cap: usize,
        budget: &mut Budget,
        handler: &mut H,
        out: &mut Output<'_>,
    ) {
        let mut decoder = encoding.new_decoder_without_bom_handling();
        prepare(&mut self.raw);
        prepare(&mut self.window);
        transcode(
            &mut self.window,
            &mut self.raw,
            0,
            source,
            &mut decoder,
            cap,
            budget,
            handler,
            out,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn stream<H: Handler>(
        window: &mut Vec<u8>,
        raw: &mut Vec<u8>,
        mut source: Source<'_>,
        cap: usize,
        budget: &mut Budget,
        handler: &mut H,
        out: &mut Output<'_>,
    ) {
        prepare(window);
        let mut filled = 0;
        let mut remaining = cap;
        while filled < SNIFF_LEN && !source.finished() && remaining > 0 {
            let room = window.len().min(filled.saturating_add(remaining));
            let produced = source.fill(window.get_mut(filled..room).unwrap_or_default());
            filled += produced;
            remaining -= produced.min(remaining);
        }
        budget.charge(filled);
        match sniff(window.get(..filled).unwrap_or_default()) {
            Sniff::NotXml => {}
            Sniff::Utf8 { skip } => {
                let mut scanner = Scanner::default();
                let mut start = skip.min(filled);
                loop {
                    let exhausted = source.finished() || remaining == 0;
                    let consumed = scanner.feed(
                        window.get(start..filled).unwrap_or_default(),
                        exhausted,
                        handler,
                        out,
                    );
                    if exhausted || out.is_full() || handler.aborted() {
                        if remaining == 0 && !source.finished() {
                            budget.truncated = true;
                        }
                        return;
                    }
                    let begin = start.saturating_add(consumed).min(filled);
                    window.copy_within(begin..filled, 0);
                    filled -= begin;
                    start = 0;
                    let room = window.len().min(filled.saturating_add(remaining));
                    let produced = source.fill(window.get_mut(filled..room).unwrap_or_default());
                    filled += produced;
                    remaining -= produced.min(remaining);
                    budget.charge(produced);
                }
            }
            Sniff::Encoded { encoding, skip } => {
                let mut decoder = encoding.new_decoder_without_bom_handling();
                prepare(raw);
                std::mem::swap(window, raw);
                let start = skip.min(filled);
                raw.copy_within(start..filled, 0);
                transcode(
                    window,
                    raw,
                    filled - start,
                    source,
                    &mut decoder,
                    remaining,
                    budget,
                    handler,
                    out,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn transcode<H: Handler>(
    window: &mut [u8],
    raw: &mut [u8],
    mut raw_filled: usize,
    mut source: Source<'_>,
    decoder: &mut Decoder,
    mut remaining: usize,
    budget: &mut Budget,
    handler: &mut H,
    out: &mut Output<'_>,
) {
    let mut scanner = Scanner::default();
    let mut filled = 0;
    loop {
        let room = raw.len().min(raw_filled.saturating_add(remaining));
        let produced = source.fill(raw.get_mut(raw_filled..room).unwrap_or_default());
        raw_filled += produced;
        remaining -= produced.min(remaining);
        budget.charge(produced);
        let source_done = source.finished() || remaining == 0;
        let (result, read, written, _) = decoder.decode_to_utf8(
            raw.get(..raw_filled).unwrap_or_default(),
            window.get_mut(filled..).unwrap_or_default(),
            source_done,
        );
        raw.copy_within(read.min(raw_filled)..raw_filled, 0);
        raw_filled -= read.min(raw_filled);
        filled += written;
        let exhausted = source_done && raw_filled == 0 && result == CoderResult::InputEmpty;
        let consumed = scanner.feed(
            window.get(..filled).unwrap_or_default(),
            exhausted,
            handler,
            out,
        );
        if exhausted || out.is_full() || handler.aborted() {
            if remaining == 0 && !source.finished() {
                budget.truncated = true;
            }
            return;
        }
        let consumed = consumed.min(filled);
        window.copy_within(consumed..filled, 0);
        filled -= consumed;
        if produced == 0 && read == 0 && written == 0 && consumed == 0 {
            return;
        }
    }
}

fn prepare(buffer: &mut Vec<u8>) {
    if buffer.len() != WINDOW {
        buffer.resize(WINDOW, 0);
    }
}

fn sniff(prefix: &[u8]) -> Sniff {
    match prefix {
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8_or_declared(rest, 3),
        [0xFF, 0xFE, ..] => Sniff::Encoded {
            encoding: UTF_16LE,
            skip: 2,
        },
        [0xFE, 0xFF, ..] => Sniff::Encoded {
            encoding: UTF_16BE,
            skip: 2,
        },
        [b'<', 0, ..] => Sniff::Encoded {
            encoding: UTF_16LE,
            skip: 0,
        },
        [0, b'<', ..] => Sniff::Encoded {
            encoding: UTF_16BE,
            skip: 0,
        },
        _ => utf8_or_declared(prefix, 0),
    }
}

fn utf8_or_declared(rest: &[u8], skip: usize) -> Sniff {
    let trimmed = rest.trim_ascii_start();
    if trimmed.first() != Some(&b'<') {
        return Sniff::NotXml;
    }
    let Some(declaration) = trimmed.strip_prefix(b"<?xml") else {
        return Sniff::Utf8 { skip };
    };
    let declaration = declaration
        .get(..memmem::find(declaration, b"?>").unwrap_or(declaration.len()))
        .unwrap_or_default();
    let declaration = Tag {
        name: b"",
        attrs: Some(declaration),
    };
    let Some(label) = declaration
        .attributes()
        .find_map(|(name, value)| hashify::tiny_set!(name, b"encoding").then_some(value))
    else {
        return Sniff::Utf8 { skip };
    };
    match Encoding::for_label(label) {
        Some(encoding) if encoding != UTF_8 && encoding.is_ascii_compatible() => {
            Sniff::Encoded { encoding, skip }
        }
        _ => Sniff::Utf8 { skip },
    }
}
