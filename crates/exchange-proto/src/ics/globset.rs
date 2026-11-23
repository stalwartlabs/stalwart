/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{common::LeReader, ids::Globcnt};

const CMD_END: u8 = 0x00;
const CMD_BITMASK: u8 = 0x42;
const CMD_POP: u8 = 0x50;
const CMD_RANGE: u8 = 0x52;
const GLOBCNT_LEN: usize = 6;
const BITMASK_DEPTH: usize = 5;
const MIN_PUSH_GAIN: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobsetError {
    Truncated,
    PopEmpty,
    BadDepth,
    BitmaskDepth,
    RangeOrder,
    TooManyRanges,
    UnknownCommand(u8),
    NotEmptyAtEnd,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobSet {
    ranges: Vec<(u64, u64)>,
}

impl GlobSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_range(lo: Globcnt, hi: Globcnt) -> Self {
        let (lo, hi) = ordered(lo.get(), hi.get());
        GlobSet {
            ranges: vec![(lo, hi)],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    pub fn max(&self) -> Option<Globcnt> {
        self.ranges.last().and_then(|&(_, hi)| Globcnt::new(hi))
    }

    pub fn min(&self) -> Option<Globcnt> {
        self.ranges.first().and_then(|&(lo, _)| Globcnt::new(lo))
    }

    pub fn ranges(&self) -> impl Iterator<Item = (Globcnt, Globcnt)> + '_ {
        self.ranges
            .iter()
            .filter_map(|&(lo, hi)| Some((Globcnt::new(lo)?, Globcnt::new(hi)?)))
    }

    pub fn contains(&self, v: Globcnt) -> bool {
        let v = v.get();
        let index = self.ranges.partition_point(|&(_, hi)| hi < v);
        self.ranges.get(index).is_some_and(|&(lo, _)| lo <= v)
    }

    pub fn run_end(&self, start: Globcnt) -> Option<Globcnt> {
        let start = start.get();
        let index = self.ranges.partition_point(|&(_, hi)| hi < start);
        self.ranges
            .get(index)
            .filter(|&&(lo, _)| lo <= start)
            .and_then(|&(_, hi)| Globcnt::new(hi))
    }

    pub fn push_ascending(&mut self, lo: Globcnt, hi: Globcnt) -> bool {
        let (lo, hi) = ordered(lo.get(), hi.get());
        match self.ranges.last_mut() {
            Some(last) if lo <= last.1 => false,
            Some(last) if lo == last.1.saturating_add(1) => {
                last.1 = hi;
                true
            }
            _ => {
                self.ranges.push((lo, hi));
                true
            }
        }
    }

    pub fn insert(&mut self, v: Globcnt) {
        self.insert_range(v, v);
    }

    pub fn insert_range(&mut self, lo: Globcnt, hi: Globcnt) {
        let (lo, hi) = ordered(lo.get(), hi.get());
        if self.push_raw_ascending(lo, hi) {
            return;
        }
        let start = self
            .ranges
            .partition_point(|&(_, r_hi)| r_hi.saturating_add(1) < lo);
        let end = self
            .ranges
            .partition_point(|&(r_lo, _)| r_lo <= hi.saturating_add(1));
        match self.ranges.get(start..end) {
            Some([]) | None => self.ranges.insert(start, (lo, hi)),
            Some([first, .., last]) | Some([first @ last]) => {
                let merged = (lo.min(first.0), hi.max(last.1));
                self.ranges.drain(start.saturating_add(1)..end);
                if let Some(slot) = self.ranges.get_mut(start) {
                    *slot = merged;
                }
            }
        }
    }

    fn push_raw_ascending(&mut self, lo: u64, hi: u64) -> bool {
        match self.ranges.last_mut() {
            None => {
                self.ranges.push((lo, hi));
                true
            }
            Some(last) if lo > last.1.saturating_add(1) => {
                self.ranges.push((lo, hi));
                true
            }
            Some(last) if lo >= last.0 => {
                last.1 = last.1.max(hi);
                true
            }
            Some(_) => false,
        }
    }

    pub fn remove(&mut self, v: Globcnt) {
        let v = v.get();
        let index = self.ranges.partition_point(|&(_, hi)| hi < v);
        let Some(&(lo, hi)) = self.ranges.get(index) else {
            return;
        };
        if v < lo {
            return;
        }
        match (v == lo, v == hi) {
            (true, true) => {
                self.ranges.remove(index);
            }
            (true, false) => {
                if let Some(slot) = self.ranges.get_mut(index) {
                    slot.0 = v.saturating_add(1);
                }
            }
            (false, true) => {
                if let Some(slot) = self.ranges.get_mut(index) {
                    slot.1 = v.saturating_sub(1);
                }
            }
            (false, false) => {
                if let Some(slot) = self.ranges.get_mut(index) {
                    slot.1 = v.saturating_sub(1);
                }
                self.ranges
                    .insert(index.saturating_add(1), (v.saturating_add(1), hi));
            }
        }
    }

    pub fn union_with(&mut self, other: &GlobSet) {
        if other.ranges.is_empty() {
            return;
        }
        if self.ranges.is_empty() {
            self.ranges.clone_from(&other.ranges);
            return;
        }
        let mut merged = Vec::with_capacity(self.ranges.len().saturating_add(other.ranges.len()));
        let mut left = self.ranges.iter().copied().peekable();
        let mut right = other.ranges.iter().copied().peekable();
        loop {
            let next = match (left.peek(), right.peek()) {
                (Some(a), Some(b)) if a.0 <= b.0 => left.next(),
                (Some(_), Some(_)) => right.next(),
                (Some(_), None) => left.next(),
                (None, Some(_)) => right.next(),
                (None, None) => None,
            };
            let Some((lo, hi)) = next else { break };
            push_coalesced(&mut merged, lo, hi);
        }
        self.ranges = merged;
    }

    pub fn difference_with(&mut self, other: &GlobSet) {
        if self.ranges.is_empty() || other.ranges.is_empty() {
            return;
        }
        let mut result = Vec::with_capacity(self.ranges.len());
        let mut cut = other.ranges.iter().copied().peekable();
        for &(lo, hi) in &self.ranges {
            let mut lo = Some(lo);
            while let Some(current) = lo {
                while cut.peek().is_some_and(|&(_, c_hi)| c_hi < current) {
                    cut.next();
                }
                match cut.peek() {
                    Some(&(c_lo, c_hi)) if c_lo <= hi => {
                        if c_lo > current {
                            result.push((current, c_lo.saturating_sub(1)));
                        }
                        lo = (c_hi < hi).then(|| c_hi.saturating_add(1));
                    }
                    _ => {
                        result.push((current, hi));
                        lo = None;
                    }
                }
            }
        }
        self.ranges = result;
    }

    pub fn is_subset_of(&self, other: &GlobSet) -> bool {
        let mut outer = other.ranges.iter().peekable();
        self.ranges.iter().all(|&(lo, hi)| {
            while outer.peek().is_some_and(|&&(_, o_hi)| o_hi < lo) {
                outer.next();
            }
            outer
                .peek()
                .is_some_and(|&&(o_lo, o_hi)| o_lo <= lo && hi <= o_hi)
        })
    }

    pub fn intersects(&self, other: &GlobSet) -> bool {
        let mut a = self.ranges.iter().peekable();
        let mut b = other.ranges.iter().peekable();
        while let (Some(&&(a_lo, a_hi)), Some(&&(b_lo, b_hi))) = (a.peek(), b.peek()) {
            if a_hi < b_lo {
                a.next();
            } else if b_hi < a_lo {
                b.next();
            } else {
                return true;
            }
        }
        false
    }

    pub(super) fn append_unsorted(&mut self, other: GlobSet) {
        self.ranges.extend(other.ranges);
    }

    pub(super) fn normalize(&mut self) {
        self.ranges.sort_unstable();
        self.ranges.dedup_by(|next, prev| {
            let adjacent = next.0 <= prev.1.saturating_add(1);
            if adjacent {
                prev.1 = prev.1.max(next.1);
            }
            adjacent
        });
    }

    pub fn decode(r: &mut LeReader<'_>, max_ranges: usize) -> Result<Self, GlobsetError> {
        let mut decoder = Decoder::new(max_ranges);
        loop {
            let command = r.u8().map_err(|_| GlobsetError::Truncated)?;
            match command {
                CMD_END => {
                    if decoder.depth != 0 {
                        return Err(GlobsetError::NotEmptyAtEnd);
                    }
                    return Ok(decoder.finish());
                }
                1..=6 => {
                    let len = usize::from(command);
                    let bytes = r.bytes(len).map_err(|_| GlobsetError::Truncated)?;
                    decoder.push(bytes)?;
                }
                CMD_POP => decoder.pop()?,
                CMD_BITMASK => {
                    let [start, mask] = r.array::<2>().map_err(|_| GlobsetError::Truncated)?;
                    decoder.bitmask(start, mask)?;
                }
                CMD_RANGE => {
                    let tail = GLOBCNT_LEN
                        .checked_sub(decoder.depth)
                        .ok_or(GlobsetError::BadDepth)?;
                    let low = r.bytes(tail).map_err(|_| GlobsetError::Truncated)?;
                    let high = r.bytes(tail).map_err(|_| GlobsetError::Truncated)?;
                    decoder.range(low, high)?;
                }
                other => return Err(GlobsetError::UnknownCommand(other)),
            }
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let (Some(&(first, _)), Some(&(_, last))) = (self.ranges.first(), self.ranges.last())
        else {
            out.push(CMD_END);
            return;
        };
        let first = to_wire(first);
        let last = to_wire(last);
        let shared = common_prefix(&first, &last);
        let outer = if shared == GLOBCNT_LEN {
            out.push(6);
            out.extend_from_slice(&first);
            out.push(CMD_END);
            return;
        } else if shared >= MIN_PUSH_GAIN || (shared > 0 && self.ranges.len() > 1) {
            out.push(prefix_command(shared));
            out.extend_from_slice(first.get(..shared).unwrap_or_default());
            shared
        } else {
            0
        };
        for &(lo, hi) in &self.ranges {
            let lo = to_wire(lo);
            let hi = to_wire(hi);
            if lo == hi {
                let tail = lo.get(outer..).unwrap_or_default();
                out.push(prefix_command(tail.len()));
                out.extend_from_slice(tail);
                continue;
            }
            let inner = common_prefix(&lo, &hi);
            let depth = if inner.saturating_sub(outer) >= MIN_PUSH_GAIN {
                let extra = lo.get(outer..inner).unwrap_or_default();
                out.push(prefix_command(extra.len()));
                out.extend_from_slice(extra);
                inner
            } else {
                outer
            };
            out.push(CMD_RANGE);
            out.extend_from_slice(lo.get(depth..).unwrap_or_default());
            out.extend_from_slice(hi.get(depth..).unwrap_or_default());
            if depth != outer {
                out.push(CMD_POP);
            }
        }
        if outer != 0 {
            out.push(CMD_POP);
        }
        out.push(CMD_END);
    }
}

fn ordered(a: u64, b: u64) -> (u64, u64) {
    if a <= b { (a, b) } else { (b, a) }
}

fn to_wire(v: u64) -> [u8; GLOBCNT_LEN] {
    let [_, _, b0, b1, b2, b3, b4, b5] = v.to_be_bytes();
    [b0, b1, b2, b3, b4, b5]
}

fn common_prefix(a: &[u8; GLOBCNT_LEN], b: &[u8; GLOBCNT_LEN]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn prefix_command(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(0)
}

fn push_coalesced(ranges: &mut Vec<(u64, u64)>, lo: u64, hi: u64) {
    match ranges.last_mut() {
        Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
        _ => ranges.push((lo, hi)),
    }
}

struct Decoder {
    stack: [u8; GLOBCNT_LEN],
    depth: usize,
    frames: [u8; GLOBCNT_LEN],
    frame_count: usize,
    ranges: Vec<(u64, u64)>,
    sorted: bool,
    max_ranges: usize,
}

impl Decoder {
    fn new(max_ranges: usize) -> Self {
        Decoder {
            stack: [0; GLOBCNT_LEN],
            depth: 0,
            frames: [0; GLOBCNT_LEN],
            frame_count: 0,
            ranges: Vec::new(),
            sorted: true,
            max_ranges,
        }
    }

    fn value(&self, tail: &[u8]) -> Result<u64, GlobsetError> {
        let mut wire = [0u8; 8];
        let (_, counter) = wire.split_at_mut(2);
        let prefix = self.stack.get(..self.depth).ok_or(GlobsetError::BadDepth)?;
        let (head, rest) = counter.split_at_mut(self.depth);
        head.copy_from_slice(prefix);
        rest.get_mut(..tail.len())
            .ok_or(GlobsetError::BadDepth)?
            .copy_from_slice(tail);
        Ok(u64::from_be_bytes(wire))
    }

    fn add(&mut self, lo: u64, hi: u64) -> Result<(), GlobsetError> {
        if lo > hi {
            return Err(GlobsetError::RangeOrder);
        }
        if let Some(last) = self.ranges.last_mut() {
            if lo > last.1 && lo == last.1.saturating_add(1) {
                last.1 = hi;
                return Ok(());
            }
            if lo <= last.1 {
                self.sorted = false;
            }
        }
        if self.ranges.len() >= self.max_ranges {
            return Err(GlobsetError::TooManyRanges);
        }
        self.ranges.push((lo, hi));
        Ok(())
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), GlobsetError> {
        let new_depth = self
            .depth
            .checked_add(bytes.len())
            .filter(|&d| d <= GLOBCNT_LEN)
            .ok_or(GlobsetError::BadDepth)?;
        if new_depth == GLOBCNT_LEN {
            let value = self.value(bytes)?;
            return self.add(value, value);
        }
        self.stack
            .get_mut(self.depth..new_depth)
            .ok_or(GlobsetError::BadDepth)?
            .copy_from_slice(bytes);
        let frame = self
            .frames
            .get_mut(self.frame_count)
            .ok_or(GlobsetError::BadDepth)?;
        *frame = u8::try_from(bytes.len()).map_err(|_| GlobsetError::BadDepth)?;
        self.frame_count = self.frame_count.saturating_add(1);
        self.depth = new_depth;
        Ok(())
    }

    fn pop(&mut self) -> Result<(), GlobsetError> {
        let top = self
            .frame_count
            .checked_sub(1)
            .ok_or(GlobsetError::PopEmpty)?;
        let len = self
            .frames
            .get(top)
            .copied()
            .ok_or(GlobsetError::PopEmpty)?;
        self.depth = self.depth.saturating_sub(usize::from(len));
        self.frame_count = top;
        Ok(())
    }

    fn bitmask(&mut self, start: u8, mask: u8) -> Result<(), GlobsetError> {
        if self.depth != BITMASK_DEPTH {
            return Err(GlobsetError::BitmaskDepth);
        }
        let base = self.value(&[0])?;
        let mut run_start = u64::from(start);
        let mut run_end = run_start;
        for bit in 0..8u8 {
            let low = u64::from(start)
                .saturating_add(1)
                .saturating_add(u64::from(bit));
            if mask & (1 << bit) == 0 {
                continue;
            }
            if low > 0xFF {
                return Err(GlobsetError::RangeOrder);
            }
            if low == run_end.saturating_add(1) {
                run_end = low;
            } else {
                self.add(base | run_start, base | run_end)?;
                run_start = low;
                run_end = low;
            }
        }
        self.add(base | run_start, base | run_end)
    }

    fn range(&mut self, low: &[u8], high: &[u8]) -> Result<(), GlobsetError> {
        if self.depth >= GLOBCNT_LEN {
            return Err(GlobsetError::BadDepth);
        }
        let lo = self.value(low)?;
        let hi = self.value(high)?;
        self.add(lo, hi)
    }

    fn finish(self) -> GlobSet {
        let mut set = GlobSet {
            ranges: self.ranges,
        };
        if !self.sorted {
            set.normalize();
        }
        set
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ics/globset/tests.rs"]
mod tests;
