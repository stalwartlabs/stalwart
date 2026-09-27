/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    crypt::{Decryptor, Target},
    decode::{Chain, DecodeOutcome},
    filter::Decoder,
    lexer::is_whitespace,
    object::{ObjRef, keyword_at},
};
use crate::xml::stream::Budget;
use memchr::memmem;
use std::cell::{Cell, OnceCell, RefCell};

const ENDSTREAM: &[u8] = b"endstream";
const ENDOBJ: &[u8] = b"endobj";
const MAX_END_MARKERS: usize = 4 << 20;
const MAX_ENDSTREAM_GAP: usize = 256;
const SCAN_FACTOR: u64 = 16;
const SCAN_BASE: u64 = 64 << 20;

#[derive(Default)]
pub(crate) struct Codec {
    decoder: Option<Decoder>,
    stages: [Vec<u8>; 2],
    decrypted: Vec<u8>,
}

#[derive(Default)]
struct Ends {
    endstream: Vec<u32>,
    endobj: Vec<u32>,
}

pub(crate) struct Source<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) header: usize,
    ends: OnceCell<Ends>,
    budget: RefCell<Budget>,
    scan_left: Cell<u64>,
    codec: RefCell<&'a mut Codec>,
}

impl Codec {
    pub(crate) fn shrink(&mut self, max: usize) {
        for buffer in self
            .stages
            .iter_mut()
            .chain(std::iter::once(&mut self.decrypted))
        {
            buffer.clear();
            buffer.shrink_to(max);
        }
    }
}

impl Ends {
    fn build(data: &[u8]) -> Self {
        let collect = |needle: &[u8]| -> Vec<u32> {
            memmem::find_iter(data, needle)
                .map_while(|pos| u32::try_from(pos).ok())
                .take(MAX_END_MARKERS)
                .collect()
        };
        Ends {
            endstream: collect(ENDSTREAM),
            endobj: collect(ENDOBJ),
        }
    }

    fn first_after(positions: &[u32], start: usize) -> Option<usize> {
        let index = positions.partition_point(|&pos| (pos as usize) < start);
        positions.get(index).map(|&pos| pos as usize)
    }
}

impl<'a> Source<'a> {
    pub(crate) fn new(data: &'a [u8], codec: &'a mut Codec, budget: Budget) -> Self {
        let header = memmem::find(data.get(..1024).unwrap_or(data), b"%PDF-").unwrap_or(0);
        let scan = SCAN_FACTOR
            .saturating_mul(data.len() as u64)
            .saturating_add(SCAN_BASE);
        Source {
            data,
            header,
            ends: OnceCell::new(),
            budget: RefCell::new(budget),
            scan_left: Cell::new(scan),
            codec: RefCell::new(codec),
        }
    }

    pub(crate) fn charge_scan(&self, bytes: usize) -> bool {
        let left = self.scan_left.get();
        match left.checked_sub(bytes as u64) {
            Some(rest) => {
                self.scan_left.set(rest);
                true
            }
            None => {
                self.scan_left.set(0);
                self.mark_truncated();
                false
            }
        }
    }

    pub(crate) fn scan_exhausted(&self) -> bool {
        self.scan_left.get() == 0
    }

    pub(crate) fn mark_truncated(&self) {
        self.budget.borrow_mut().truncated = true;
    }

    pub(crate) fn budget_exhausted(&self) -> bool {
        self.budget.borrow().exhausted()
    }

    pub(crate) fn used_bytes(&self) -> u64 {
        self.budget.borrow().used_bytes
    }

    #[cfg(test)]
    pub(crate) fn truncated(&self) -> bool {
        self.budget.borrow().truncated
    }

    pub(crate) fn into_budget(self) -> Budget {
        self.budget.into_inner()
    }

    pub(crate) fn stream_data(&self, start: usize, length: Option<i64>) -> &'a [u8] {
        let end = self.stream_end(start, length).unwrap_or(self.data.len());
        self.data.get(start..end).unwrap_or_default()
    }

    pub(crate) fn stream_end(&self, start: usize, length: Option<i64>) -> Option<usize> {
        let data = self.data;
        if let Some(end) = length
            .and_then(|length| usize::try_from(length).ok())
            .and_then(|length| start.checked_add(length))
            .filter(|&end| end <= data.len())
            && self.endstream_follows(end)
        {
            return Some(end);
        }
        let end = self.find_end(start)?;
        let body = data.get(start..end).unwrap_or_default();
        let trimmed = body
            .strip_suffix(b"\r\n")
            .or_else(|| body.strip_suffix(b"\n"))
            .or_else(|| body.strip_suffix(b"\r"))
            .unwrap_or(body);
        Some(start + trimmed.len())
    }

    fn endstream_follows(&self, end: usize) -> bool {
        let skip = self
            .data
            .get(end..)
            .unwrap_or_default()
            .iter()
            .take(MAX_ENDSTREAM_GAP + 1)
            .take_while(|&&byte| is_whitespace(byte))
            .count();
        if skip > MAX_ENDSTREAM_GAP {
            return false;
        }
        let pos = end + skip;
        self.data
            .get(pos..)
            .is_some_and(|rest| rest.starts_with(ENDSTREAM))
            || keyword_at(self.data, pos, ENDOBJ)
    }

    fn find_end(&self, start: usize) -> Option<usize> {
        let ends = self.ends.get_or_init(|| Ends::build(self.data));
        let endstream = Ends::first_after(&ends.endstream, start);
        let endobj = Ends::first_after(&ends.endobj, start);
        match (endstream, endobj) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (found, None) | (None, found) => found,
        }
    }

    pub(crate) fn decode(
        &self,
        chain: &Chain,
        raw: &[u8],
        decrypt: Option<(&Decryptor, ObjRef)>,
        out: &mut Vec<u8>,
    ) -> DecodeOutcome {
        if let Some(outcome) = chain.early_outcome() {
            return outcome;
        }
        let Ok(mut codec) = self.codec.try_borrow_mut() else {
            let mut fallback = Codec::default();
            return self.run(&mut fallback, chain, raw, decrypt, out);
        };
        self.run(&mut codec, chain, raw, decrypt, out)
    }

    pub(crate) fn borrow<'s>(&self, data: &'s [u8]) -> (&'s [u8], DecodeOutcome) {
        let taken = data.len().min(self.part_cap());
        self.charge(taken);
        if taken < data.len() {
            self.mark_truncated();
            return (
                data.get(..taken).unwrap_or_default(),
                DecodeOutcome::Truncated,
            );
        }
        (data, DecodeOutcome::Complete)
    }

    fn run(
        &self,
        codec: &mut Codec,
        chain: &Chain,
        raw: &[u8],
        decrypt: Option<(&Decryptor, ObjRef)>,
        out: &mut Vec<u8>,
    ) -> DecodeOutcome {
        let Codec {
            decoder,
            stages,
            decrypted,
        } = codec;
        let input: &[u8] = match decrypt {
            Some((decryptor, id)) => {
                decrypted.clear();
                decryptor.decrypt(Target::Stream, id.num, id.generation, raw, decrypted);
                decrypted
            }
            None => raw,
        };
        let count = chain.codecs().count();
        if count == 0 {
            let (taken, outcome) = self.borrow(input);
            out.extend_from_slice(taken);
            return outcome;
        }
        let decoder = decoder.get_or_insert_with(Decoder::new);
        let [first, second] = stages;
        let mut current: Option<bool> = None;
        let mut outcome = DecodeOutcome::Complete;
        for (index, (filter, params)) in chain.codecs().enumerate() {
            let cap = self.part_cap();
            if cap == 0 {
                self.mark_truncated();
                return DecodeOutcome::Truncated;
            }
            let last = index + 1 == count;
            let (source, target): (&[u8], &mut Vec<u8>) = match current {
                None => (input, if last { &mut *out } else { &mut *first }),
                Some(true) => (first, if last { &mut *out } else { &mut *second }),
                Some(false) => (second, if last { &mut *out } else { &mut *first }),
            };
            let before = if last {
                target.len()
            } else {
                target.clear();
                0
            };
            if source.is_empty() {
                break;
            }
            let result = decoder.decode(filter, &params, source, target, cap);
            self.charge(target.len().saturating_sub(before));
            if result.truncated {
                self.mark_truncated();
                outcome = DecodeOutcome::Truncated;
            } else if result.corrupt && outcome == DecodeOutcome::Complete {
                outcome = DecodeOutcome::Corrupt;
            }
            current = Some(!matches!(current, Some(true)));
        }
        outcome
    }

    fn part_cap(&self) -> usize {
        usize::try_from(self.budget.borrow().part_cap()).unwrap_or(usize::MAX)
    }

    fn charge(&self, bytes: usize) {
        self.budget.borrow_mut().charge(bytes);
    }
}
