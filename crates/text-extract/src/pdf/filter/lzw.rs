/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use super::stage::{Source, Step};

const TABLE_SIZE: usize = 4096;
const INDEX_MASK: usize = TABLE_SIZE - 1;
const CLEAR: u16 = 256;
const END: u16 = 257;
const FIRST_FREE: u16 = 258;
const MIN_WIDTH: u32 = 9;
const EXPANSION_GUESS: usize = 3;
const MIN_STEP: usize = 4096;

pub(crate) struct LzwTable {
    prefix: [u16; TABLE_SIZE],
    suffix: [u8; TABLE_SIZE],
    length: [u16; TABLE_SIZE],
    sequence: [u8; TABLE_SIZE],
}

impl LzwTable {
    pub(super) fn boxed() -> Box<Self> {
        let mut table = Box::new(Self {
            prefix: [0; TABLE_SIZE],
            suffix: [0; TABLE_SIZE],
            length: [1; TABLE_SIZE],
            sequence: [0; TABLE_SIZE],
        });
        for (code, suffix) in (0..=u8::MAX).zip(table.suffix.iter_mut()) {
            *suffix = code;
        }
        table
    }

    fn expand(&mut self, code: u16) -> usize {
        let length = usize::from(self.length[usize::from(code) & INDEX_MASK]);
        let Some(slots) = self.sequence.get_mut(..length) else {
            return 0;
        };
        let mut code = usize::from(code);
        for slot in slots.iter_mut().rev() {
            *slot = self.suffix[code & INDEX_MASK];
            code = usize::from(self.prefix[code & INDEX_MASK]);
        }
        length
    }

    fn add(&mut self, next: u16, prefix: u16, first: u8) {
        let next = usize::from(next) & INDEX_MASK;
        self.prefix[next] = prefix;
        self.suffix[next] = first;
        self.length[next] = self.length[usize::from(prefix) & INDEX_MASK].saturating_add(1);
    }
}

pub(super) struct LzwSource<'a> {
    table: &'a mut LzwTable,
    input: &'a [u8],
    buffer: u32,
    buffered: u32,
    width: u32,
    next: u16,
    early: u16,
    previous: Option<u16>,
    pending: Range<usize>,
    finished: Option<bool>,
    hint: usize,
}

impl<'a> LzwSource<'a> {
    pub(super) fn new(table: &'a mut LzwTable, input: &'a [u8], early_change: bool) -> Self {
        Self {
            table,
            input,
            buffer: 0,
            buffered: 0,
            width: MIN_WIDTH,
            next: FIRST_FREE,
            early: u16::from(early_change),
            previous: None,
            pending: 0..0,
            finished: None,
            hint: input.len().saturating_mul(EXPANSION_GUESS).max(MIN_STEP),
        }
    }

    fn read(&mut self) -> Option<u16> {
        while self.buffered < self.width {
            let (byte, rest) = self.input.split_first()?;
            self.input = rest;
            self.buffer = (self.buffer << 8) | u32::from(*byte);
            self.buffered += 8;
        }
        self.buffered -= self.width;
        let code = (self.buffer >> self.buffered) & ((1 << self.width) - 1);
        self.buffer &= (1 << self.buffered) - 1;
        u16::try_from(code).ok()
    }

    fn emit(&mut self, out: &mut Vec<u8>, cap: usize) -> bool {
        let room = cap.saturating_sub(out.len());
        let take = self.pending.len().min(room);
        let from = self.pending.start;
        if let Some(chunk) = self.table.sequence.get(from..from + take) {
            out.extend_from_slice(chunk);
        }
        self.pending.start += take;
        self.pending.is_empty()
    }

    fn step(&mut self, code: u16) -> Result<(), bool> {
        match code {
            CLEAR => {
                self.width = MIN_WIDTH;
                self.next = FIRST_FREE;
                self.previous = None;
                return Ok(());
            }
            END => return Err(false),
            _ => {}
        }
        let length = if code < self.next {
            self.table.expand(code)
        } else if let Some(previous) = self.previous.filter(|_| code == self.next) {
            let length = self.table.expand(previous);
            let first = self.table.sequence.first().copied().unwrap_or_default();
            match self.table.sequence.get_mut(length) {
                Some(slot) => *slot = first,
                None => return Err(true),
            }
            length + 1
        } else {
            return Err(true);
        };
        if let Some(previous) = self.previous
            && usize::from(self.next) < TABLE_SIZE
        {
            let first = self.table.sequence.first().copied().unwrap_or_default();
            self.table.add(self.next, previous, first);
            self.next += 1;
            self.width = match self.next + self.early {
                2048.. => 12,
                1024.. => 11,
                512.. => 10,
                _ => MIN_WIDTH,
            };
        }
        self.previous = Some(code);
        self.pending = 0..length;
        Ok(())
    }
}

impl Source for LzwSource<'_> {
    fn produce(&mut self, out: &mut Vec<u8>, cap: usize) -> Step {
        loop {
            if !self.emit(out, cap) {
                return Step::More;
            }
            if let Some(corrupt) = self.finished {
                return Step::Done { corrupt };
            }
            if out.len() >= cap {
                return Step::More;
            }
            let Some(code) = self.read() else {
                self.finished = Some(false);
                continue;
            };
            if let Err(corrupt) = self.step(code) {
                self.finished = Some(corrupt);
            }
        }
    }

    fn size_hint(&self) -> usize {
        self.hint
    }
}
