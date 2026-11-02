/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const GENERATOR: u32 = 0x186_4CFB;
const POLY: u32 = 0x86_4CFB << 8;
const INIT: u32 = 0xB7_04CE << 8;
const DEGREE: u32 = 24;
const LANES: usize = 4;
const MIN_LANE_LEN: usize = 256;

static TABLES: [[u32; 256]; 8] = {
    let mut tables = [[0u32; 256]; 8];
    let mut byte = 0;
    while byte < 256 {
        let mut crc = (byte as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ POLY
            } else {
                crc << 1
            };
            bit += 1;
        }
        tables[0][byte] = crc;
        byte += 1;
    }
    let mut slice = 1;
    while slice < 8 {
        let mut byte = 0;
        while byte < 256 {
            let previous = tables[slice - 1][byte];
            tables[slice][byte] = (previous << 8) ^ tables[0][(previous >> 24) as usize];
            byte += 1;
        }
        slice += 1;
    }
    tables
};

#[inline(always)]
fn step(crc: u32, block: &[u8; 8]) -> u32 {
    let [t0, t1, t2, t3, t4, t5, t6, t7] = &TABLES;
    let [a0, a1, a2, a3, a4, a5, a6, a7] = *block;
    let x = crc ^ u32::from_be_bytes([a0, a1, a2, a3]);
    t7[(x >> 24) as usize]
        ^ t6[((x >> 16) & 0xFF) as usize]
        ^ t5[((x >> 8) & 0xFF) as usize]
        ^ t4[(x & 0xFF) as usize]
        ^ t3[usize::from(a4)]
        ^ t2[usize::from(a5)]
        ^ t1[usize::from(a6)]
        ^ t0[usize::from(a7)]
}

fn update(mut crc: u32, data: &[u8]) -> u32 {
    let (blocks, tail) = data.as_chunks::<8>();
    for block in blocks {
        crc = step(crc, block);
    }
    for byte in tail {
        crc = (crc << 8) ^ TABLES[0][((crc >> 24) ^ u32::from(*byte)) as usize];
    }
    crc
}

fn multiply_mod(mut a: u32, b: u32) -> u32 {
    let mut product = 0;
    for bit in 0..DEGREE {
        if b & (1 << bit) != 0 {
            product ^= a;
        }
        a <<= 1;
        if a & (1 << DEGREE) != 0 {
            a ^= GENERATOR;
        }
    }
    product
}

fn zero_bytes_factor(mut len: usize) -> u32 {
    let mut factor = 1;
    let mut base = 1 << 8;
    while len > 0 {
        if len & 1 != 0 {
            factor = multiply_mod(factor, base);
        }
        base = multiply_mod(base, base);
        len >>= 1;
    }
    factor
}

pub(crate) fn crc24(data: &[u8]) -> u32 {
    let lane_len = data.len() / LANES / 8 * 8;
    if lane_len < MIN_LANE_LEN {
        return update(INIT, data) >> 8;
    }
    let (striped, rest) = data.split_at(lane_len * LANES);
    let (lane0, striped) = striped.split_at(lane_len);
    let (lane1, striped) = striped.split_at(lane_len);
    let (lane2, lane3) = striped.split_at(lane_len);
    let mut crcs = [INIT, 0, 0, 0];
    for (((b0, b1), b2), b3) in lane0
        .as_chunks::<8>()
        .0
        .iter()
        .zip(lane1.as_chunks::<8>().0)
        .zip(lane2.as_chunks::<8>().0)
        .zip(lane3.as_chunks::<8>().0)
    {
        let [c0, c1, c2, c3] = crcs;
        crcs = [step(c0, b0), step(c1, b1), step(c2, b2), step(c3, b3)];
    }
    let factor = zero_bytes_factor(lane_len);
    let [c0, c1, c2, c3] = crcs;
    let combined = [c1, c2, c3]
        .into_iter()
        .fold(c0, |crc, lane| (multiply_mod(crc >> 8, factor) << 8) ^ lane);
    update(combined, rest) >> 8
}
