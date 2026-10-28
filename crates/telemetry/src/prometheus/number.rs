/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_992.0;

#[inline(always)]
pub fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(itoa::Buffer::new().format(value).as_bytes());
}

#[inline(always)]
pub fn write_f64(out: &mut Vec<u8>, value: f64) {
    write_float(out, value, false);
}

#[inline(always)]
pub fn write_canonical_f64(out: &mut Vec<u8>, value: f64) {
    write_float(out, value, true);
}

fn write_float(out: &mut Vec<u8>, value: f64, canonical: bool) {
    if value.is_nan() {
        out.extend_from_slice(b"NaN");
    } else if value.is_infinite() {
        out.extend_from_slice(if value > 0.0 { b"+Inf" } else { b"-Inf" });
    } else if value.fract() == 0.0 && value.abs() < MAX_EXACT_INTEGER {
        out.extend_from_slice(itoa::Buffer::new().format(value as i64).as_bytes());
        if canonical {
            out.extend_from_slice(b".0");
        }
    } else {
        out.extend_from_slice(zmij::Buffer::new().format_finite(value).as_bytes());
    }
}
