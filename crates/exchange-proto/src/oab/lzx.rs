/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{OabError, crc};

pub const CHUNK_LEN: usize = 32 * 1024;
pub const BLOCK_MAX: u32 = 0x0004_0000;
pub const VERSION_HI: u32 = 3;
pub const VERSION_LO: u32 = 1;
pub const FLAG_LZXD: u32 = 1;
pub const HEADER_LEN: usize = 16;
pub const BLOCK_HEADER_LEN: usize = 16;
pub const LZXD_PREFIX_LEN: usize = 2;
pub const LZXD_HEADER_LEN: usize = 16;
pub const REPEATED_OFFSET: u32 = 1;

const UNCOMPRESSED_BLOCK: u16 = 3 << 12;
const BLOCK_SIZE_HIGH_MASK: u32 = 0x0FFF;
const BLOCK_SIZE_LOW_SHIFT: u32 = 4;

pub fn wrapped_len(total: usize) -> usize {
    if total == 0 {
        return HEADER_LEN + BLOCK_HEADER_LEN;
    }
    let blocks = total.div_ceil(CHUNK_LEN);
    let padding = usize::from(total % CHUNK_LEN % 2 == 1);
    HEADER_LEN + total + padding + blocks * (BLOCK_HEADER_LEN + LZXD_PREFIX_LEN + LZXD_HEADER_LEN)
}

pub fn wrap(parts: &[&[u8]], out: &mut Vec<u8>) -> Result<(), OabError> {
    let total: usize = parts.iter().map(|part| part.len()).sum();
    let target = u32::try_from(total).map_err(|_| OabError::TooLarge)?;
    out.reserve(wrapped_len(total));
    for value in [VERSION_HI, VERSION_LO, BLOCK_MAX, target] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    if total == 0 {
        write_block(out, &[]);
        return Ok(());
    }
    let mut scratch = Vec::new();
    let mut rest = parts;
    let mut current: &[u8] = &[];
    loop {
        while current.is_empty() {
            let Some((first, tail)) = rest.split_first() else {
                return Ok(());
            };
            current = first;
            rest = tail;
        }
        if current.len() >= CHUNK_LEN || rest.iter().all(|part| part.is_empty()) {
            let (chunk, tail) = current.split_at(current.len().min(CHUNK_LEN));
            current = tail;
            write_block(out, chunk);
        } else {
            scratch.clear();
            scratch.reserve(CHUNK_LEN);
            while scratch.len() < CHUNK_LEN {
                let (taken, tail) = current.split_at(current.len().min(CHUNK_LEN - scratch.len()));
                scratch.extend_from_slice(taken);
                current = tail;
                if current.is_empty() {
                    let Some((first, tail)) = rest.split_first() else {
                        break;
                    };
                    current = first;
                    rest = tail;
                }
            }
            write_block(out, &scratch);
        }
    }
}

fn write_block(out: &mut Vec<u8>, chunk: &[u8]) {
    if chunk.is_empty() {
        for value in [0, 0, 0, crc(&[])] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        return;
    }
    let len = chunk.len() as u32;
    let padding = chunk.len() % 2;
    let chunk_size = (LZXD_HEADER_LEN + chunk.len() + padding) as u16;
    let compressed = (LZXD_PREFIX_LEN + usize::from(chunk_size)) as u32;
    for value in [FLAG_LZXD, compressed, len, crc(&[chunk])] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&chunk_size.to_le_bytes());
    let high = UNCOMPRESSED_BLOCK | ((len >> 12) & BLOCK_SIZE_HIGH_MASK) as u16;
    let low = ((len & BLOCK_SIZE_HIGH_MASK) << BLOCK_SIZE_LOW_SHIFT) as u16;
    out.extend_from_slice(&high.to_le_bytes());
    out.extend_from_slice(&low.to_le_bytes());
    for _ in 0..3 {
        out.extend_from_slice(&REPEATED_OFFSET.to_le_bytes());
    }
    out.extend_from_slice(chunk);
    if padding == 1 {
        out.push(0);
    }
}
