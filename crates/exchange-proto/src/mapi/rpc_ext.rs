/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{error::BodyError, lzxpress};
use crate::common::{LeReader, LeWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcHeaderExt {
    pub version: u16,
    pub flags: u16,
    pub size: u16,
    pub size_actual: u16,
}

impl RpcHeaderExt {
    pub const LEN: usize = 8;
    pub const COMPRESSED: u16 = 0x0001;
    pub const XOR_MAGIC: u16 = 0x0002;
    pub const LAST: u16 = 0x0004;

    pub fn decode(r: &mut LeReader<'_>) -> Result<Self, BodyError> {
        let bytes: [u8; Self::LEN] = r.array().map_err(|_| BodyError::BadExtHeader)?;
        let [v0, v1, f0, f1, s0, s1, a0, a1] = bytes;
        Ok(RpcHeaderExt {
            version: u16::from_le_bytes([v0, v1]),
            flags: u16::from_le_bytes([f0, f1]),
            size: u16::from_le_bytes([s0, s1]),
            size_actual: u16::from_le_bytes([a0, a1]),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(self.version);
        out.put_u16(self.flags);
        out.put_u16(self.size);
        out.put_u16(self.size_actual);
    }

    pub fn has(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }
}

pub fn decode_single_buffer<'a, 's>(
    input: &'a [u8],
    scratch: &'s mut Vec<u8>,
    max_actual: u16,
) -> Result<&'s [u8], BodyError>
where
    'a: 's,
{
    let mut r = LeReader::new(input);
    let header = RpcHeaderExt::decode(&mut r)?;
    if header.version != 0 {
        return Err(BodyError::BadExtHeader);
    }
    if !header.has(RpcHeaderExt::LAST) {
        return Err(BodyError::NotLastBuffer);
    }
    let payload = r.rest();
    if payload.len() != usize::from(header.size) {
        return Err(BodyError::SizeMismatch);
    }
    if header.size_actual > max_actual {
        return Err(BodyError::DecompressedTooLarge);
    }
    let key = if header.has(RpcHeaderExt::XOR_MAGIC) {
        lzxpress::XOR_KEY
    } else {
        0
    };
    if header.has(RpcHeaderExt::COMPRESSED) {
        scratch.clear();
        lzxpress::decompress(payload, key, scratch, usize::from(header.size_actual))?;
        Ok(scratch.as_slice())
    } else if header.size_actual != header.size {
        Err(BodyError::SizeMismatch)
    } else if key != 0 {
        scratch.clear();
        scratch.extend(payload.iter().map(|b| b ^ key));
        Ok(scratch.as_slice())
    } else {
        Ok(payload)
    }
}

pub fn write_buffer_header(out: &mut Vec<u8>) -> usize {
    let at = out.len();
    RpcHeaderExt {
        version: 0,
        flags: 0,
        size: 0,
        size_actual: 0,
    }
    .encode(out);
    at
}

pub fn patch_buffer_header(out: &mut Vec<u8>, at: usize, last: bool) -> bool {
    let Some(size) = out
        .len()
        .checked_sub(at)
        .and_then(|len| len.checked_sub(RpcHeaderExt::LEN))
        .and_then(|len| u16::try_from(len).ok())
    else {
        return false;
    };
    let flags = if last { RpcHeaderExt::LAST } else { 0 };
    at.checked_add(2).is_some_and(|pos| {
        out.patch_u16(pos, flags)
            && out.patch_u16(pos.saturating_add(2), size)
            && out.patch_u16(pos.saturating_add(4), size)
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rpc_ext/tests.rs"]
mod tests;
