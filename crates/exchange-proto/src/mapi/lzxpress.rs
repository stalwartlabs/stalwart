/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::slice::Iter;

use super::error::BodyError;

pub const XOR_KEY: u8 = 0xA5;
const MIN_MATCH: usize = 3;
const NIBBLE_FULL: u8 = 0x0F;
const BYTE_FULL: u8 = 0xFF;
const INLINE_FULL: u16 = 7;
const SHARED_BASE: usize = 7 + MIN_MATCH;
const BYTE_BASE: usize = 15 + SHARED_BASE;

struct Input<'a> {
    bytes: Iter<'a, u8>,
    key: u8,
}

impl Input<'_> {
    fn is_empty(&self) -> bool {
        self.bytes.as_slice().is_empty()
    }

    fn u8(&mut self) -> Result<u8, BodyError> {
        self.bytes
            .next()
            .map(|b| b ^ self.key)
            .ok_or(BodyError::Lz77Corrupt)
    }

    fn u16(&mut self) -> Result<u16, BodyError> {
        Ok(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }

    fn u32(&mut self) -> Result<u32, BodyError> {
        Ok(u32::from_le_bytes([
            self.u8()?,
            self.u8()?,
            self.u8()?,
            self.u8()?,
        ]))
    }
}

pub fn lz77_decompress(input: &[u8], out: &mut Vec<u8>, expected: usize) -> Result<(), BodyError> {
    decompress(input, 0, out, expected)
}

pub(crate) fn decompress(
    input: &[u8],
    key: u8,
    out: &mut Vec<u8>,
    expected: usize,
) -> Result<(), BodyError> {
    let base = out.len();
    let end = base
        .checked_add(expected)
        .ok_or(BodyError::DecompressedTooLarge)?;
    out.reserve(expected);
    let mut input = Input {
        bytes: input.iter(),
        key,
    };
    let mut flags = 0u32;
    let mut flags_left = 0u8;
    let mut shared_nibble: Option<u8> = None;
    loop {
        if flags_left == 0 {
            if input.is_empty() {
                break;
            }
            flags = input.u32()?;
            flags_left = 32;
        }
        flags_left = flags_left.saturating_sub(1);
        let is_match = flags & 0x8000_0000 != 0;
        flags = flags.wrapping_shl(1);
        if !is_match {
            if input.is_empty() {
                break;
            }
            if out.len() >= end {
                return Err(BodyError::DecompressedTooLarge);
            }
            out.push(input.u8()?);
            continue;
        }
        if input.is_empty() {
            break;
        }
        let meta = input.u16()?;
        let offset = usize::from(meta.wrapping_shr(3)).saturating_add(1);
        let length = match meta & INLINE_FULL {
            INLINE_FULL => {
                let nibble = match shared_nibble.take() {
                    Some(high) => high,
                    None => {
                        let byte = input.u8()?;
                        shared_nibble = Some(byte.wrapping_shr(4));
                        byte & NIBBLE_FULL
                    }
                };
                if nibble == NIBBLE_FULL {
                    match input.u8()? {
                        BYTE_FULL => usize::from(input.u16()?).saturating_add(MIN_MATCH),
                        byte => usize::from(byte).saturating_add(BYTE_BASE),
                    }
                } else {
                    usize::from(nibble).saturating_add(usize::from(INLINE_FULL) + MIN_MATCH)
                }
            }
            inline => usize::from(inline).saturating_add(MIN_MATCH),
        };
        copy_match(out, base, end, offset, length)?;
    }
    if out.len() == end {
        Ok(())
    } else {
        Err(BodyError::SizeMismatch)
    }
}

fn copy_match(
    out: &mut Vec<u8>,
    base: usize,
    end: usize,
    offset: usize,
    length: usize,
) -> Result<(), BodyError> {
    let produced = out.len().saturating_sub(base);
    if offset > produced {
        return Err(BodyError::Lz77Corrupt);
    }
    if length > end.saturating_sub(out.len()) {
        return Err(BodyError::DecompressedTooLarge);
    }
    let start = out.len().saturating_sub(offset);
    let mut remaining = length;
    while remaining > 0 {
        let chunk = remaining.min(out.len().saturating_sub(start));
        out.extend_from_within(start..start.saturating_add(chunk));
        remaining = remaining.saturating_sub(chunk);
    }
    Ok(())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/lzxpress/tests.rs"]
mod tests;
