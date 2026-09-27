/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Outcome;

pub(super) struct Output<'a> {
    out: &'a mut Vec<u8>,
    start: usize,
    end: usize,
    truncated: bool,
}

impl<'a> Output<'a> {
    pub(super) fn run(
        out: &'a mut Vec<u8>,
        limit: usize,
        decode: impl FnOnce(&mut Self) -> bool,
    ) -> Outcome {
        let start = out.len();
        let end = start.saturating_add(limit);
        let mut output = Self {
            out,
            start,
            end,
            truncated: false,
        };
        let corrupt = decode(&mut output);
        Outcome {
            truncated: output.truncated,
            corrupt,
        }
    }

    fn room(&self) -> usize {
        self.end.saturating_sub(self.out.len())
    }

    pub(super) fn reserve(&mut self, hint: usize) {
        self.out.reserve_exact(hint.min(self.room()));
    }

    fn grow(&mut self, additional: usize) {
        if self.out.capacity() - self.out.len() < additional {
            let produced = self.out.len() - self.start;
            self.out
                .reserve_exact(additional.max(produced).min(self.room()));
        }
    }

    pub(super) fn push(&mut self, data: &[u8]) -> bool {
        match data.get(..self.room()) {
            Some(fitting) if fitting.len() < data.len() => {
                self.grow(fitting.len());
                self.out.extend_from_slice(fitting);
                self.truncated = true;
                false
            }
            _ => {
                self.grow(data.len());
                self.out.extend_from_slice(data);
                true
            }
        }
    }

    pub(super) fn push_byte(&mut self, byte: u8) -> bool {
        if self.room() > 0 {
            self.grow(1);
            self.out.push(byte);
            true
        } else {
            self.truncated = true;
            false
        }
    }

    pub(super) fn push_repeat(&mut self, byte: u8, count: usize) -> bool {
        let room = self.room();
        if count <= room {
            self.grow(count);
            self.out.resize(self.out.len() + count, byte);
            true
        } else {
            self.grow(room);
            self.out.resize(self.end, byte);
            self.truncated = true;
            false
        }
    }
}
