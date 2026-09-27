/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cell::Cell;

use super::Params;

const MAX_COLORS: i64 = 32;
const DEFAULT_BITS: i64 = 8;
const TIFF: i64 = 2;
const PNG_FIRST: i64 = 10;
const PNG_LAST: i64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layout {
    None,
    Tiff(Tiff),
    Png(Png),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Tiff {
    row_bytes: usize,
    colors: usize,
    bits: u32,
    samples: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Png {
    row_bytes: usize,
    pixel_bytes: usize,
}

struct Geometry {
    row_bytes: usize,
    colors: usize,
    bits: u32,
    samples: usize,
}

impl Layout {
    pub(super) fn from_params(params: &Params) -> (Self, bool) {
        let png = match params.predictor {
            ..=1 => return (Self::None, false),
            TIFF => false,
            PNG_FIRST..=PNG_LAST => true,
            _ => return (Self::None, true),
        };
        let Some(geometry) = Geometry::from_params(params) else {
            return (Self::None, true);
        };
        let layout = if png {
            Self::Png(Png {
                row_bytes: geometry.row_bytes,
                pixel_bytes: (geometry.colors * geometry.bits as usize)
                    .div_ceil(8)
                    .max(1),
            })
        } else {
            Self::Tiff(Tiff {
                row_bytes: geometry.row_bytes,
                colors: geometry.colors,
                bits: geometry.bits,
                samples: geometry.samples,
            })
        };
        (layout, false)
    }
}

impl Geometry {
    fn from_params(params: &Params) -> Option<Self> {
        let colors = params.colors.clamp(1, MAX_COLORS);
        let bits = match params.bits_per_component {
            ..=0 => DEFAULT_BITS,
            bits @ (1 | 2 | 4 | 8 | 16) => bits,
            _ => return None,
        };
        if params.columns < 1 {
            return None;
        }
        let samples = u64::try_from(params.columns)
            .ok()?
            .checked_mul(colors.unsigned_abs())?;
        let row_bytes = samples.checked_mul(bits.unsigned_abs())?.div_ceil(8);
        let row_bytes = usize::try_from(row_bytes).ok()?;
        row_bytes.checked_add(1)?;
        Some(Self {
            row_bytes,
            colors: usize::try_from(colors).ok()?,
            bits: u32::try_from(bits).ok()?,
            samples: usize::try_from(samples).ok()?,
        })
    }
}

impl Tiff {
    pub(super) fn apply(&self, data: &mut [u8]) {
        let rows = data.chunks_mut(self.row_bytes);
        match self.bits {
            8 => rows.for_each(|row| self.row8(row)),
            16 => rows.for_each(|row| self.row16(row)),
            _ => rows.for_each(|row| self.row_packed(row)),
        }
    }

    fn row8(&self, row: &mut [u8]) {
        let cells = Cell::from_mut(row).as_slice_of_cells();
        for (current, left) in cells.iter().skip(self.colors).zip(cells) {
            current.set(current.get().wrapping_add(left.get()));
        }
    }

    fn row16(&self, row: &mut [u8]) {
        let cells = Cell::from_mut(row).as_slice_of_cells();
        let samples = cells.chunks(2);
        for (current, left) in samples.clone().skip(self.colors).zip(samples) {
            match (current, left) {
                ([high, low], [left_high, left_low]) => {
                    let sum = u16::from_be_bytes([high.get(), low.get()])
                        .wrapping_add(u16::from_be_bytes([left_high.get(), left_low.get()]));
                    let [sum_high, sum_low] = sum.to_be_bytes();
                    high.set(sum_high);
                    low.set(sum_low);
                }
                ([high], [left_high, _]) => high.set(high.get().wrapping_add(left_high.get())),
                _ => {}
            }
        }
    }

    fn row_packed(&self, row: &mut [u8]) {
        let bits = self.bits as usize;
        let mask = (1u8 << self.bits) - 1;
        let samples = self.samples.min(row.len() * 8 / bits);
        let mut previous = [0u8; MAX_COLORS as usize];
        let offsets = (0..samples).map(|sample| sample * bits);
        for (offset, color) in offsets.zip((0..self.colors).cycle()) {
            let shift = 8 - bits - offset % 8;
            if let (Some(byte), Some(previous)) = (row.get_mut(offset / 8), previous.get_mut(color))
            {
                let value = (((*byte >> shift) & mask).wrapping_add(*previous)) & mask;
                *previous = value;
                *byte = (*byte & !(mask << shift)) | (value << shift);
            }
        }
    }
}

impl Png {
    pub(super) fn rows(&self, out: &mut Vec<u8>, start: usize, decoded: &mut usize) -> bool {
        let stride = self.row_bytes + 1;
        let first = *decoded - start < self.row_bytes;
        let cells = Cell::from_mut(out.as_mut_slice()).as_slice_of_cells();
        let mut sources = cells
            .get(*decoded..)
            .unwrap_or_default()
            .chunks_exact(stride);
        let mut targets = cells
            .get(*decoded..)
            .unwrap_or_default()
            .chunks_exact(self.row_bytes);
        let mut unknown = false;
        let mut count = 0;
        if first && let (Some(source), Some(row)) = (sources.next(), targets.next()) {
            unknown |= self.decode(row, source, None);
            count += 1;
        }
        let above = (*decoded + count * self.row_bytes).saturating_sub(self.row_bytes);
        let ups = cells
            .get(above..)
            .unwrap_or_default()
            .chunks_exact(self.row_bytes);
        for ((source, row), up) in sources.zip(targets).zip(ups) {
            unknown |= self.decode(row, source, Some(up));
            count += 1;
        }
        let raw = *decoded + count * stride;
        *decoded += count * self.row_bytes;
        if raw > *decoded {
            let len = out.len();
            out.copy_within(raw..len, *decoded);
            out.truncate(len - (raw - *decoded));
        }
        unknown
    }

    pub(super) fn partial(
        &self,
        out: &mut Vec<u8>,
        start: usize,
        decoded: usize,
        end: usize,
    ) -> bool {
        let width = out
            .len()
            .saturating_sub(decoded + 1)
            .min(end.saturating_sub(decoded));
        let cells = Cell::from_mut(out.as_mut_slice()).as_slice_of_cells();
        let source = cells.get(decoded..).and_then(|rest| rest.get(..=width));
        let row = cells.get(decoded..).and_then(|rest| rest.get(..width));
        let up = if decoded - start >= self.row_bytes {
            cells.get(decoded - self.row_bytes..decoded)
        } else {
            None
        };
        let unknown = match (source, row) {
            (Some(source), Some(row)) if width > 0 => self.decode(row, source, up),
            _ => false,
        };
        out.truncate(decoded + width);
        unknown
    }

    fn decode(&self, row: Row<'_>, source: Row<'_>, up: Option<Row<'_>>) -> bool {
        match source.split_first() {
            Some((kind, source)) => !decode_png_row(kind.get(), row, source, up, self.pixel_bytes),
            None => false,
        }
    }
}

const NONE: u8 = 0;
const SUB: u8 = 1;
const UP: u8 = 2;
const AVERAGE: u8 = 3;
const PAETH: u8 = 4;

type Row<'a> = &'a [Cell<u8>];

fn decode_png_row(
    kind: u8,
    row: Row<'_>,
    source: Row<'_>,
    up: Option<Row<'_>>,
    pixel_bytes: usize,
) -> bool {
    match (kind, up) {
        (NONE, _) | (UP, None) => {
            for (current, raw) in row.iter().zip(source) {
                current.set(raw.get());
            }
        }
        (SUB, _) | (PAETH, None) => sub(row, source, pixel_bytes),
        (UP, Some(up)) => {
            for ((current, raw), above) in row.iter().zip(source).zip(up) {
                current.set(raw.get().wrapping_add(above.get()));
            }
        }
        (AVERAGE, None) => {
            let pixels = row.iter().zip(source);
            for (current, raw) in pixels.clone().take(pixel_bytes) {
                current.set(raw.get());
            }
            for ((current, raw), left) in pixels.skip(pixel_bytes).zip(row) {
                current.set(raw.get().wrapping_add(left.get() >> 1));
            }
        }
        (AVERAGE, Some(up)) => average(row, source, up, pixel_bytes),
        (PAETH, Some(up)) => paeth(row, source, up, pixel_bytes),
        _ => {
            for (current, raw) in row.iter().zip(source) {
                current.set(raw.get());
            }
            return false;
        }
    }
    true
}

fn sub(row: Row<'_>, source: Row<'_>, pixel_bytes: usize) {
    let pixels = row.iter().zip(source);
    for (current, raw) in pixels.clone().take(pixel_bytes) {
        current.set(raw.get());
    }
    for ((current, raw), left) in pixels.skip(pixel_bytes).zip(row) {
        current.set(raw.get().wrapping_add(left.get()));
    }
}

fn average(row: Row<'_>, source: Row<'_>, up: Row<'_>, pixel_bytes: usize) {
    let pixels = row.iter().zip(source).zip(up);
    for ((current, raw), above) in pixels.clone().take(pixel_bytes) {
        current.set(raw.get().wrapping_add(above.get() >> 1));
    }
    for (((current, raw), above), left) in pixels.skip(pixel_bytes).zip(row) {
        let mean = (u16::from(left.get()) + u16::from(above.get())) >> 1;
        current.set(raw.get().wrapping_add(mean as u8));
    }
}

fn paeth(row: Row<'_>, source: Row<'_>, up: Row<'_>, pixel_bytes: usize) {
    let pixels = row.iter().zip(source).zip(up);
    for ((current, raw), above) in pixels.clone().take(pixel_bytes) {
        current.set(raw.get().wrapping_add(above.get()));
    }
    for ((((current, raw), above), left), above_left) in pixels.skip(pixel_bytes).zip(row).zip(up) {
        let predicted = paeth_predict(left.get(), above.get(), above_left.get());
        current.set(raw.get().wrapping_add(predicted));
    }
}

fn paeth_predict(left: u8, above: u8, above_left: u8) -> u8 {
    let (a, b, c) = (i16::from(left), i16::from(above), i16::from(above_left));
    let pa = (b - c).abs();
    let pb = (a - c).abs();
    let pc = (a + b - 2 * c).abs();
    if pa <= pb && pa <= pc {
        left
    } else if pb <= pc {
        above
    } else {
        above_left
    }
}
