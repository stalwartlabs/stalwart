/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use text_extract::{Extractor, Hints, Limits};

const REUSE_EVERY: usize = 4;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_output_bytes: 1 << 20,
        max_total_bytes: 32 << 20,
        ..Limits::default()
    };
    let mut extractor = Extractor::new(limits.clone());
    let mut out = String::new();
    let result = extractor.extract(data, Hints::new(), &mut out);
    match &result {
        Ok(extraction) => {
            assert_eq!(extraction.bytes_written, out.len());
            assert!(extraction.bytes_decompressed <= limits.max_total_bytes);
        }
        Err(_) => assert!(out.is_empty()),
    }
    assert!(out.len() <= limits.max_output_bytes);
    if data.len() % REUSE_EVERY == 0 {
        let mut again = String::new();
        assert_eq!(extractor.extract(data, Hints::new(), &mut again), result);
        assert_eq!(again, out);
    }
});
