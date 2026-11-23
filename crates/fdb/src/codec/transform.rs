/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DecodeError;

pub const CLEAR_RANGE: u8 = 1;

const EMPTY: &[u8] = &[];

fn is_key_after(key: &[u8], candidate: &[u8]) -> bool {
    candidate
        .split_last()
        .is_some_and(|(last, prefix)| *last == 0 && prefix == key)
}

pub fn single_key_range<'a>(begin: &'a [u8], end: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if is_key_after(begin, end) {
        (end, EMPTY)
    } else {
        (begin, end)
    }
}

pub fn single_key_range_decode<'a>(
    begin: &'a [u8],
    end: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), DecodeError> {
    let (begin, end) = match (begin.split_last(), end.is_empty()) {
        (Some((0, key)), true) => (key, begin),
        (Some(_), true) => return Err(DecodeError::KeyRange),
        _ => (begin, end),
    };
    if begin <= end {
        Ok((begin, end))
    } else {
        Err(DecodeError::KeyRange)
    }
}

pub fn single_key_clear<'a>(kind: u8, param1: &'a [u8], param2: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if kind == CLEAR_RANGE {
        single_key_range(param1, param2)
    } else {
        (param1, param2)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/codec/transform/tests.rs"]
mod tests;
