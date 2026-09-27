/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use flate2::{Decompress, FlushDecompress, Status};
use memchr::memchr;

use super::stage::{Source, Step};

const MIN_STEP: usize = 4096;
const EXPANSION_GUESS: usize = 4;
const ZLIB_HEADER: usize = 2;
const DICTIONARY_ID: usize = 4;

pub(super) struct FlateSource<'a> {
    inflate: &'a mut Decompress,
    data: &'a [u8],
    fallback: Option<&'a [u8]>,
    hint: usize,
}

impl<'a> FlateSource<'a> {
    pub(super) fn new(inflate: &'a mut Decompress, input: &'a [u8]) -> Self {
        let (data, fallback) = plan(input);
        inflate.reset(false);
        Self {
            inflate,
            data,
            fallback,
            hint: input.len().saturating_mul(EXPANSION_GUESS).max(MIN_STEP),
        }
    }

    fn retry(&mut self) -> bool {
        match self.fallback.take() {
            Some(data) if self.inflate.total_out() == 0 => {
                self.inflate.reset(false);
                self.data = data;
                true
            }
            _ => false,
        }
    }
}

impl Source for FlateSource<'_> {
    fn produce(&mut self, out: &mut Vec<u8>, cap: usize) -> Step {
        loop {
            let len = out.len();
            if len >= cap {
                return Step::More;
            }
            out.resize(cap, 0);
            let (in_before, out_before) = (self.inflate.total_in(), self.inflate.total_out());
            let result = self.inflate.decompress(
                self.data,
                out.get_mut(len..).unwrap_or_default(),
                FlushDecompress::None,
            );
            let consumed = delta(self.inflate.total_in(), in_before);
            let produced = delta(self.inflate.total_out(), out_before);
            out.truncate(len + produced);
            self.data = self.data.get(consumed..).unwrap_or_default();
            let stalled = match result {
                Ok(Status::StreamEnd) => {
                    self.data = &[];
                    self.fallback = None;
                    return Step::Done { corrupt: false };
                }
                Ok(_) => consumed == 0 && produced == 0,
                Err(_) => true,
            };
            if stalled && !self.retry() {
                self.data = &[];
                return Step::Done { corrupt: true };
            }
        }
    }

    fn size_hint(&self) -> usize {
        self.hint
    }
}

fn delta(after: u64, before: u64) -> usize {
    usize::try_from(after.saturating_sub(before)).unwrap_or(usize::MAX)
}

fn plan(input: &[u8]) -> (&[u8], Option<&[u8]>) {
    if let Some(body) = zlib_body(input).or_else(|| zlib_body(input.trim_ascii_start())) {
        return (body, None);
    }
    if let Some(body) = gzip_body(input) {
        return (body, None);
    }
    (input, input.get(ZLIB_HEADER..))
}

fn zlib_body(data: &[u8]) -> Option<&[u8]> {
    const DEFLATE: u8 = 8;
    const MAX_WINDOW: u8 = 7;
    const PRESET_DICTIONARY: u8 = 0x20;
    const CHECK_MODULUS: u16 = 31;
    let [cmf, flg, body @ ..] = data else {
        return None;
    };
    let valid = cmf & 0x0f == DEFLATE
        && cmf >> 4 <= MAX_WINDOW
        && (u16::from(*cmf) << 8 | u16::from(*flg)) % CHECK_MODULUS == 0;
    match (valid, flg & PRESET_DICTIONARY != 0) {
        (false, _) => None,
        (true, false) => Some(body),
        (true, true) => body.get(DICTIONARY_ID..),
    }
}

fn gzip_body(data: &[u8]) -> Option<&[u8]> {
    const HEADER_CRC: u8 = 0x02;
    const EXTRA: u8 = 0x04;
    const NAME: u8 = 0x08;
    const COMMENT: u8 = 0x10;
    let [0x1f, 0x8b, 8, flags, _, _, _, _, _, _, rest @ ..] = data else {
        return None;
    };
    let mut rest = rest;
    if flags & EXTRA != 0 {
        let [low, high, extra @ ..] = rest else {
            return None;
        };
        rest = extra.get(usize::from(u16::from_le_bytes([*low, *high]))..)?;
    }
    for flag in [NAME, COMMENT] {
        if flags & flag != 0 {
            rest = rest.get(memchr(0, rest)? + 1..)?;
        }
    }
    if flags & HEADER_CRC != 0 {
        rest = rest.get(2..)?;
    }
    Some(rest)
}
