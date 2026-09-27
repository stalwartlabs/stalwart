/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const CAPACITY: usize = 8192;
const MAX_LOAD: usize = CAPACITY * 3 / 8;
const MAX_PROBES: usize = 32;
const MIN_TOLERANCE: f64 = 0.05;
const WIDTH_TOLERANCE: f64 = 1.0 / 3.0;
const MIN_EXPONENT: i64 = -16;
const MAX_EXPONENT: i64 = 32;
const EXPONENT_BIAS: i64 = 1023;
const MANTISSA_BITS: u32 = 52;
const EXPONENT_MASK: u64 = 0x7FF;
const HALF: f64 = 0.5;
const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01B3;
const MIX: u64 = 0x9E37_79B9_7F4A_7C15;
const MIX_SHIFT: u32 = 29;
const KEY_SHIFT: u32 = 32;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    key: u32,
    generation: u32,
    x: f64,
    y: f64,
}

#[derive(Debug)]
pub(crate) struct Dedupe {
    slots: Vec<Slot>,
    generation: u32,
    count: usize,
}

impl Default for Dedupe {
    fn default() -> Self {
        Dedupe {
            slots: Vec::new(),
            generation: 1,
            count: 0,
        }
    }
}

fn neighbours(value: f64, cell: f64, tolerance: f64) -> (f64, Option<f64>) {
    let base = (value / cell).floor();
    let offset = value - base * cell;
    let neighbour = if offset < tolerance {
        Some(base - 1.0)
    } else if cell - offset < tolerance {
        Some(base + 1.0)
    } else {
        None
    };
    (base, neighbour)
}

impl Dedupe {
    pub(crate) fn clear(&mut self) {
        self.count = 0;
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.slots
                .iter_mut()
                .for_each(|slot| *slot = Slot::default());
            self.generation = 1;
        }
    }

    pub(crate) fn is_duplicate(
        &mut self,
        text: &str,
        origin: (f64, f64),
        width: f64,
        em: f64,
    ) -> bool {
        if !(em.is_finite() && em > 0.0 && origin.0.is_finite() && origin.1.is_finite()) {
            return false;
        }
        if self.slots.len() != CAPACITY {
            self.slots = vec![Slot::default(); CAPACITY];
        }
        let exponent = ((em.to_bits() >> MANTISSA_BITS & EXPONENT_MASK) as i64 - EXPONENT_BIAS)
            .clamp(MIN_EXPONENT, MAX_EXPONENT);
        let cell = f64::from_bits(((exponent + 1 + EXPONENT_BIAS) as u64) << MANTISSA_BITS);
        let tolerance = (width.abs() * WIDTH_TOLERANCE)
            .max(MIN_TOLERANCE * em)
            .min(cell * HALF);
        let (column, next_column) = neighbours(origin.0, cell, tolerance);
        let (row, next_row) = neighbours(origin.1, cell, tolerance);
        let text_hash = mix(fnv(text.as_bytes()), exponent as u64);
        let home = bucket(text_hash, column, row);
        let found = self.matches(home, origin, tolerance)
            || next_column
                .is_some_and(|next| self.matches(bucket(text_hash, next, row), origin, tolerance))
            || next_row.is_some_and(|next| {
                self.matches(bucket(text_hash, column, next), origin, tolerance)
            })
            || next_column
                .zip(next_row)
                .is_some_and(|(x, y)| self.matches(bucket(text_hash, x, y), origin, tolerance));
        if found {
            return true;
        }
        if self.count >= MAX_LOAD {
            self.clear();
        }
        self.insert(home, origin);
        false
    }

    fn matches(&self, hash: u64, origin: (f64, f64), tolerance: f64) -> bool {
        let start = hash as usize % CAPACITY;
        let key = (hash >> KEY_SHIFT) as u32;
        for probe in 0..MAX_PROBES {
            let Some(slot) = self.slots.get((start + probe) % CAPACITY) else {
                return false;
            };
            if slot.generation != self.generation {
                return false;
            }
            if slot.key == key
                && (slot.x - origin.0).abs() < tolerance
                && (slot.y - origin.1).abs() < tolerance
            {
                return true;
            }
        }
        false
    }

    fn insert(&mut self, hash: u64, origin: (f64, f64)) {
        let start = hash as usize % CAPACITY;
        let key = (hash >> KEY_SHIFT) as u32;
        let generation = self.generation;
        for probe in 0..MAX_PROBES {
            if let Some(slot) = self.slots.get_mut((start + probe) % CAPACITY)
                && slot.generation != generation
            {
                *slot = Slot {
                    key,
                    generation,
                    x: origin.0,
                    y: origin.1,
                };
                self.count += 1;
                return;
            }
        }
    }
}

pub(crate) fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(FNV_OFFSET, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    })
}

fn mix(hash: u64, value: u64) -> u64 {
    let mixed = (hash ^ value).wrapping_mul(MIX);
    mixed ^ (mixed >> MIX_SHIFT)
}

fn bucket(text_hash: u64, x: f64, y: f64) -> u64 {
    mix(mix(text_hash, x as i64 as u64), y as i64 as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overprinted_glyphs_are_duplicates() {
        let mut dedupe = Dedupe::default();
        assert!(!dedupe.is_duplicate("H", (100.0, 700.0), 7.2, 10.0));
        assert!(dedupe.is_duplicate("H", (100.3, 700.1), 7.2, 10.0));
        assert!(dedupe.is_duplicate("H", (99.6, 699.9), 7.2, 10.0));
        assert!(!dedupe.is_duplicate("e", (100.3, 700.1), 5.6, 10.0));
        assert!(!dedupe.is_duplicate("H", (107.2, 700.0), 7.2, 10.0));
        assert!(!dedupe.is_duplicate("l", (0.0, 0.0), 2.2, 10.0));
        assert!(!dedupe.is_duplicate("l", (2.2, 0.0), 2.2, 10.0));
        assert!(dedupe.is_duplicate("l", (2.25, 0.0), 2.2, 10.0));
        dedupe.clear();
        assert!(!dedupe.is_duplicate("H", (100.0, 700.0), 7.2, 10.0));
    }

    #[test]
    fn table_stays_bounded() {
        let mut dedupe = Dedupe::default();
        for index in 0..100_000 {
            let x = f64::from(index) * 10.0;
            assert!(!dedupe.is_duplicate("x", (x, 0.0), 5.0, 10.0));
        }
        assert!(dedupe.count <= MAX_LOAD);
        assert!(!dedupe.is_duplicate("x", (f64::NAN, 0.0), 5.0, 10.0));
    }
}
