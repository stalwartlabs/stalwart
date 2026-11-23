/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::convert::{BlobKind, ConvertError};

const HEADER_LEN: usize = 16;
pub(super) const HEADER_TAIL_LEN: u32 = 12;
const COMP_TYPE_LZFU: u32 = 0x7546_5A4C;
pub(super) const COMP_TYPE_MELA: u32 = 0x414C_454D;
const DICT_LEN: usize = 4096;
const DICT_MASK: usize = 0x0FFF;
const MIN_MATCH: usize = 2;
const RESERVE_CAP: usize = 64 * 1024;
const DICT_PRELOAD: &[u8; 207] = b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx";

const CRC_TABLE: [u32; 256] = crc_table();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtfKind {
    Lzfu,
    Mela,
}

pub fn rtf_decompress(
    input: &[u8],
    out: &mut Vec<u8>,
    max_out: u32,
) -> Result<RtfKind, ConvertError> {
    let (header, body) = input.split_first_chunk::<HEADER_LEN>().ok_or(bad_blob(0))?;
    let [
        c0,
        c1,
        c2,
        c3,
        r0,
        r1,
        r2,
        r3,
        t0,
        t1,
        t2,
        t3,
        k0,
        k1,
        k2,
        k3,
    ] = *header;
    let comp_size = u32::from_le_bytes([c0, c1, c2, c3]);
    let raw_size = u32::from_le_bytes([r0, r1, r2, r3]);
    let comp_type = u32::from_le_bytes([t0, t1, t2, t3]);
    let crc = u32::from_le_bytes([k0, k1, k2, k3]);
    let max_out = usize::try_from(max_out).unwrap_or(usize::MAX);
    match comp_type {
        COMP_TYPE_MELA => {
            if body.len() > max_out {
                return Err(ConvertError::TooLarge);
            }
            out.extend_from_slice(body);
            Ok(RtfKind::Mela)
        }
        COMP_TYPE_LZFU => {
            let contents_len = comp_size
                .checked_sub(HEADER_TAIL_LEN)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(bad_blob(0))?;
            let contents = body.get(..contents_len).ok_or(bad_blob(0))?;
            if crc32(contents) != crc {
                return Err(ConvertError::Crc);
            }
            let reserve = usize::try_from(raw_size)
                .unwrap_or(usize::MAX)
                .min(max_out)
                .min(RESERVE_CAP);
            out.reserve(reserve);
            decompress_lzfu(contents, out, max_out)?;
            Ok(RtfKind::Lzfu)
        }
        _ => Err(bad_blob(8)),
    }
}

struct Dictionary {
    bytes: [u8; DICT_LEN],
    write: usize,
}

impl Dictionary {
    fn new() -> Self {
        let mut bytes = [0u8; DICT_LEN];
        if let Some(head) = bytes.first_chunk_mut::<{ DICT_PRELOAD.len() }>() {
            *head = *DICT_PRELOAD;
        }
        Dictionary {
            bytes,
            write: DICT_PRELOAD.len(),
        }
    }

    fn push(&mut self, byte: u8, out: &mut Vec<u8>, limit: usize) -> Result<(), ConvertError> {
        if out.len() >= limit {
            return Err(ConvertError::TooLarge);
        }
        out.push(byte);
        if let Some(slot) = self.bytes.get_mut(self.write) {
            *slot = byte;
        }
        self.write = self.write.wrapping_add(1) & DICT_MASK;
        Ok(())
    }

    fn get(&self, offset: usize) -> u8 {
        self.bytes.get(offset & DICT_MASK).copied().unwrap_or(0)
    }
}

fn decompress_lzfu(contents: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<(), ConvertError> {
    let limit = out.len().saturating_add(max_out);
    let mut dict = Dictionary::new();
    let mut rest = contents;
    let offset = |rest: &[u8]| {
        let consumed = contents.len().saturating_sub(rest.len());
        u32::try_from(consumed.saturating_add(HEADER_LEN)).unwrap_or(u32::MAX)
    };
    loop {
        let (&control, tail) = rest.split_first().ok_or_else(|| bad_blob(offset(rest)))?;
        rest = tail;
        for bit in 0..8u8 {
            if control & (1 << bit) == 0 {
                let (&literal, tail) = rest.split_first().ok_or_else(|| bad_blob(offset(rest)))?;
                rest = tail;
                dict.push(literal, out, limit)?;
                continue;
            }
            let (&reference, tail) = rest
                .split_first_chunk::<2>()
                .ok_or_else(|| bad_blob(offset(rest)))?;
            rest = tail;
            let reference = u16::from_be_bytes(reference);
            let mut read = usize::from(reference >> 4);
            if read == dict.write {
                return Ok(());
            }
            let len = usize::from(reference & 0x0F).saturating_add(MIN_MATCH);
            for _ in 0..len {
                let byte = dict.get(read);
                dict.push(byte, out, limit)?;
                read = read.wrapping_add(1) & DICT_MASK;
            }
        }
    }
}

fn bad_blob(offset: u32) -> ConvertError {
    ConvertError::BadBlob {
        what: BlobKind::Rtf,
        offset,
    }
}

pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    crc32_update(0, bytes)
}

pub(crate) fn crc32_update(crc: u32, bytes: &[u8]) -> u32 {
    bytes.iter().fold(crc, |crc, &byte| {
        let [low, ..] = crc.to_le_bytes();
        let index = usize::from(low ^ byte);
        (crc >> 8) ^ CRC_TABLE.get(index).copied().unwrap_or(0)
    })
}

#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0u32;
    while n < 256 {
        let mut c = n;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n as usize] = c;
        n += 1;
    }
    table
}
