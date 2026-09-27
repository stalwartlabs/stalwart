/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::{
    content::ops::Op,
    lexer::{Lexer, Token, is_whitespace},
    seek::Seek,
};
use memchr::{memchr, memmem};
use std::collections::VecDeque;

pub(super) const END_MARKER: &[u8] = b"EI";
pub(super) const DATA_MARKER: &[u8] = b"ID";
pub(super) const ASCII85_END: &[u8] = b"~>";
const VALIDATION_WINDOW: usize = 96;
const MAX_VALIDATED_CANDIDATES: usize = 256;
const MAX_NULS: usize = 1;

#[derive(Debug, Clone, Copy)]
struct Candidate {
    marker: usize,
    plausible: bool,
}

#[derive(Debug, Default)]
struct Candidates {
    origin: usize,
    frontier: usize,
    queue: VecDeque<Candidate>,
}

#[derive(Debug, Default)]
pub(crate) struct Markers {
    hex_end: Seek,
    ascii85_end: Seek,
    end: Seek,
    data: Seek,
    candidates: Candidates,
}

impl Markers {
    pub(super) fn hex_end(&mut self, data: &[u8], pos: usize) -> Option<usize> {
        self.hex_end.find(pos, |from| {
            memchr(b'>', data.get(from..)?).map(|offset| from + offset)
        })
    }

    pub(super) fn ascii85_end(&mut self, data: &[u8], pos: usize) -> Option<usize> {
        self.ascii85_end
            .find(pos, |from| find(data, from, ASCII85_END))
    }

    pub(super) fn end(&mut self, data: &[u8], pos: usize) -> Option<usize> {
        self.end.find(pos, |from| find(data, from, END_MARKER))
    }

    pub(super) fn data(&mut self, data: &[u8], pos: usize) -> Option<usize> {
        self.data.find(pos, |from| find(data, from, DATA_MARKER))
    }

    pub(super) fn scan(&mut self, data: &[u8], start: usize) -> Option<usize> {
        let candidates = &mut self.candidates;
        candidates.restart(start);
        let head = data
            .get(start..)
            .filter(|rest| rest.starts_with(END_MARKER))
            .filter(|_| !preceded(data, start) && delimited_after(data, start))
            .map(|_| Candidate {
                marker: start,
                plausible: plausible_tail(data, start + END_MARKER.len()),
            });
        let mut fallback = None;
        let mut queued = 0usize;
        for index in 0..=MAX_VALIDATED_CANDIDATES {
            let candidate = match (head, index) {
                (Some(head), 0) => head,
                _ => {
                    let Some(candidate) = candidates.get(data, queued) else {
                        break;
                    };
                    queued += 1;
                    candidate
                }
            };
            let end = candidate.marker + END_MARKER.len();
            if index == MAX_VALIDATED_CANDIDATES || candidate.plausible {
                return Some(end);
            }
            fallback = fallback.or(Some(end));
        }
        fallback
    }
}

impl Candidates {
    fn restart(&mut self, start: usize) {
        if start < self.origin || self.frontier < start {
            self.queue.clear();
            self.frontier = start;
        }
        self.origin = start;
        while self
            .queue
            .front()
            .is_some_and(|candidate| candidate.marker < start)
        {
            self.queue.pop_front();
        }
    }

    fn get(&mut self, data: &[u8], index: usize) -> Option<Candidate> {
        if let Some(candidate) = self.queue.get(index) {
            return Some(*candidate);
        }
        let from = self.frontier;
        let marker = memmem::find_iter(data.get(from..)?, END_MARKER)
            .map(|offset| from + offset)
            .find(|&marker| preceded(data, marker) && delimited_after(data, marker));
        self.frontier = marker.map_or(data.len(), |marker| marker + 1);
        let candidate = Candidate {
            marker: marker?,
            plausible: plausible_tail(data, marker? + END_MARKER.len()),
        };
        self.queue.push_back(candidate);
        Some(candidate)
    }
}

fn find(data: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    memmem::find(data.get(from..)?, needle).map(|offset| from + offset)
}

fn preceded(data: &[u8], marker: usize) -> bool {
    marker
        .checked_sub(1)
        .and_then(|before| data.get(before))
        .is_none_or(|&byte| is_whitespace(byte))
}

pub(super) fn delimited_after(data: &[u8], marker: usize) -> bool {
    data.get(marker + END_MARKER.len())
        .is_none_or(|&byte| is_whitespace(byte) || byte == b'<' || byte == b'/')
}

fn plausible_tail(data: &[u8], end: usize) -> bool {
    let window = data
        .get(end..)
        .map(|rest| rest.get(..VALIDATION_WINDOW).unwrap_or(rest))
        .unwrap_or_default();
    let nuls = window.iter().filter(|&&byte| byte == 0).count();
    if nuls > MAX_NULS
        || window
            .iter()
            .any(|&byte| byte != 0 && !is_whitespace(byte) && !(0x20..0x7F).contains(&byte))
    {
        return false;
    }
    let mut lexer = Lexer::new(window);
    while let Some(token) = lexer.next() {
        match token {
            Token::Keyword(keyword) => {
                return Op::is_known(keyword) || lexer.at_end();
            }
            Token::Error => return false,
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(data: &[u8], start: usize) -> Option<usize> {
        let mut fallback = None;
        let mut validated = 0usize;
        for offset in memmem::find_iter(data.get(start..)?, END_MARKER) {
            let marker = start + offset;
            if !(offset == 0 || preceded(data, marker)) || !delimited_after(data, marker) {
                continue;
            }
            let end = marker + END_MARKER.len();
            if validated >= MAX_VALIDATED_CANDIDATES {
                return Some(end);
            }
            validated += 1;
            fallback = fallback.or(Some(end));
            if plausible_tail(data, end) {
                return Some(end);
            }
        }
        fallback
    }

    #[test]
    fn scan_matches_the_unmemoized_search() {
        let pieces: [&[u8]; 9] = [
            b" EI ",
            b"EI",
            b"xEI",
            b" EI\x01\x02",
            b" Q ",
            b"EI/",
            b"\nEI<",
            b" BT ",
            b"\x00",
        ];
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        for round in 0..40 {
            let mut data = Vec::new();
            let pieces_count = if round % 2 == 0 { 60 } else { 700 };
            for _ in 0..pieces_count {
                data.extend_from_slice(pieces[next(pieces.len())]);
            }
            let mut markers = Markers::default();
            let mut start = 0;
            while start <= data.len() {
                assert_eq!(
                    markers.scan(&data, start),
                    naive(&data, start),
                    "round {round} start {start}"
                );
                start += 1 + next(12);
            }
        }
    }
}
