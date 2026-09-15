/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use text_extract::{Hints, Limits};

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_output_bytes: 1 << 20,
        max_total_bytes: 32 << 20,
        ..Limits::default()
    };
    let mut out = String::new();
    if let Ok(extraction) = text_extract::extract(data, Hints::new(), &limits, &mut out) {
        assert_eq!(extraction.bytes_written, out.len());
    }
    assert!(out.len() <= limits.max_output_bytes);
});
