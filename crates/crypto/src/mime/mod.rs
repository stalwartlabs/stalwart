/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod entity;
pub(crate) mod legacy;
pub mod protection;
pub(crate) mod signed;

use legacy::LegacyPart;

pub(crate) trait Sink {
    fn put(&mut self, data: &[u8]);

    fn put_reencoded(&mut self, part: &LegacyPart<'_>)
    where
        Self: Sized,
    {
        part.write_base64(self);
    }
}

impl Sink for Vec<u8> {
    #[inline]
    fn put(&mut self, data: &[u8]) {
        self.extend_from_slice(data);
    }
}

#[derive(Default)]
pub(crate) struct Counter(pub usize);

impl Sink for Counter {
    #[inline]
    fn put(&mut self, data: &[u8]) {
        self.0 += data.len();
    }

    fn put_reencoded(&mut self, part: &LegacyPart<'_>) {
        self.0 += part.base64_len();
    }
}

pub(crate) const CRLF: &[u8] = b"\r\n";
pub(crate) const BOUNDARY_LEN: usize = 34;
const BOUNDARY_PREFIX: &[u8; 2] = b"=_";
const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn boundary(random: &[u8; 16]) -> [u8; BOUNDARY_LEN] {
    let mut out = [0u8; BOUNDARY_LEN];
    let (prefix, hex) = out.split_at_mut(BOUNDARY_PREFIX.len());
    prefix.copy_from_slice(BOUNDARY_PREFIX);
    let (pairs, _) = hex.as_chunks_mut::<2>();
    for (pair, byte) in pairs.iter_mut().zip(random) {
        *pair = [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0F)]];
    }
    out
}

const SCAN_BLOCK: usize = 4096;

pub(crate) fn has_bare_lf(data: &[u8], prev_cr: bool) -> bool {
    let Some((first, rest)) = data.split_first() else {
        return false;
    };
    if *first == b'\n' && !prev_cr {
        return true;
    }
    let previous = data.get(..rest.len()).unwrap_or_default();
    rest.chunks(SCAN_BLOCK)
        .zip(previous.chunks(SCAN_BLOCK))
        .any(|(current, previous)| {
            current.iter().zip(previous).fold(0u8, |acc, (byte, prev)| {
                acc | (u8::from(*byte == b'\n') & u8::from(*prev != b'\r'))
            }) != 0
        })
}

pub(crate) struct Canonical<'s, S: Sink> {
    sink: &'s mut S,
    prev_cr: bool,
}

impl<'s, S: Sink> Canonical<'s, S> {
    pub(crate) fn new(sink: &'s mut S) -> Self {
        Canonical {
            sink,
            prev_cr: false,
        }
    }

    pub(crate) fn put_canonical(&mut self, data: &[u8]) {
        self.sink.put(data);
        if let Some(last) = data.last() {
            self.prev_cr = *last == b'\r';
        }
    }
}

impl<S: Sink> Sink for Canonical<'_, S> {
    fn put(&mut self, data: &[u8]) {
        if !has_bare_lf(data, self.prev_cr) {
            self.put_canonical(data);
            return;
        }
        let mut start = 0;
        for pos in memchr::memchr_iter(b'\n', data) {
            let has_cr = match pos.checked_sub(1) {
                Some(prev) => data.get(prev) == Some(&b'\r'),
                None => self.prev_cr,
            };
            if !has_cr {
                self.sink.put(data.get(start..pos).unwrap_or_default());
                self.sink.put(CRLF);
                start = pos + 1;
            }
        }
        self.sink.put(data.get(start..).unwrap_or_default());
        if let Some(last) = data.last() {
            self.prev_cr = *last == b'\r';
        }
    }

    fn put_reencoded(&mut self, part: &LegacyPart<'_>) {
        self.sink.put_reencoded(part);
        self.prev_cr = false;
    }
}
