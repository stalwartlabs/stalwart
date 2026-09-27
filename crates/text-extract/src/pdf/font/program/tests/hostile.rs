/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use super::super::{BuiltinEncoding, Cff, TrueType};
use super::fixtures::FIXTURES;

const MUTATION_ROUNDS: usize = 30_000;
const MAX_MUTATIONS: u64 = 8;
pub(super) const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const INTERESTING: [u16; 6] = [0, 1, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF];
pub(super) const PER_INPUT_BUDGET: Duration = Duration::from_millis(200);

pub(super) struct XorShift(pub(super) u64);

impl XorShift {
    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub(super) fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

pub(super) fn exercise(data: &[u8]) -> usize {
    let mut total = 0usize;
    if let Some(BuiltinEncoding::Custom(names)) = BuiltinEncoding::from_type1(data) {
        total += names.iter().count();
    }
    if let Some(cff) = Cff::parse(data) {
        total += cff.ros().map_or(0, |ros| ros.registry.len());
        for glyph in 0..=cff.num_glyphs() {
            total += cff.glyph_name(glyph).map_or(0, <[u8]>::len);
            total += cff.glyph_cid(glyph).map_or(0, usize::from);
        }
        if let Some(BuiltinEncoding::Custom(names)) = cff.builtin_encoding() {
            total += names.iter().count();
        }
    }
    if let Some(font) = TrueType::parse(data) {
        let map = font.unicode_map();
        total += map.len();
        for glyph in 0..=font.num_glyphs().unwrap_or(0) {
            total += font.glyph_name(glyph).map_or(0, <[u8]>::len);
            total += map.get(glyph).map_or(0, char::len_utf8);
        }
        for code in 0..=u8::MAX {
            total += font.symbolic_glyph(code).map_or(0, usize::from);
        }
        if let Some(cmap) = font.cmap() {
            for (_, _, subtable) in cmap.subtables() {
                total += [0x20, 0x41, 0xA440, 0xF041, 0x1_F600]
                    .into_iter()
                    .filter_map(|code| subtable.glyph(code))
                    .count();
                subtable.for_each_mapping(0x1_0000, |_, glyph| total += usize::from(glyph & 1));
            }
        }
    }
    total
}

#[test]
fn truncated_at_every_offset() {
    for (file, data, _) in FIXTURES {
        let full = exercise(data);
        assert!(full > 0, "{file}");
        for len in 0..data.len() {
            let started = Instant::now();
            exercise(data.get(..len).unwrap_or_default());
            assert!(started.elapsed() < PER_INPUT_BUDGET, "{file} at {len}");
        }
    }
}

#[test]
fn random_mutations() {
    let mut rng = XorShift(SEED);
    let mut buffer = Vec::new();
    let mut slowest = Duration::ZERO;
    for _ in 0..MUTATION_ROUNDS {
        let (_, data, _) = FIXTURES.get(rng.below(FIXTURES.len())).expect("in range");
        buffer.clear();
        buffer.extend_from_slice(data);
        mutate(&mut rng, &mut buffer);
        let started = Instant::now();
        exercise(&buffer);
        slowest = slowest.max(started.elapsed());
    }
    println!("slowest mutated input: {slowest:?}");
    assert!(slowest < PER_INPUT_BUDGET);
}

pub(super) fn mutate(rng: &mut XorShift, buffer: &mut Vec<u8>) {
    for _ in 0..=rng.next() % MAX_MUTATIONS {
        let at = rng.below(buffer.len());
        let value = rng.next();
        match value % 4 {
            0 => {
                if let Some(byte) = buffer.get_mut(at) {
                    *byte = value.to_le_bytes()[1];
                }
            }
            1 => {
                if let Some(byte) = buffer.get_mut(at) {
                    *byte ^= 1 << (value >> 8 & 7);
                }
            }
            2 => {
                let word = INTERESTING
                    .get(rng.below(INTERESTING.len()))
                    .expect("in range")
                    .to_be_bytes();
                if let Some(slot) = buffer.get_mut(at..at + 2) {
                    slot.copy_from_slice(&word);
                }
            }
            _ => {
                if value >> 8 & 7 == 0 {
                    buffer.truncate(at);
                }
            }
        }
    }
}
