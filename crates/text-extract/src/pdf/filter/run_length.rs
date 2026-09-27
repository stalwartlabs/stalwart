/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::output::Output;

const END: u8 = 128;
const REPEAT_BASE: usize = 257;

pub(super) fn decode(input: &[u8], output: &mut Output<'_>) -> bool {
    output.reserve(input.len());
    let mut data = input;
    loop {
        match data {
            [] | [END, ..] => return false,
            [length @ 0..END, rest @ ..] => {
                let count = usize::from(*length) + 1;
                let Some((literal, rest)) = rest.split_at_checked(count) else {
                    output.push(rest);
                    return true;
                };
                if !output.push(literal) {
                    return false;
                }
                data = rest;
            }
            [length, byte, rest @ ..] => {
                if !output.push_repeat(*byte, REPEAT_BASE - usize::from(*length)) {
                    return false;
                }
                data = rest;
            }
            [_] => return true,
        }
    }
}
