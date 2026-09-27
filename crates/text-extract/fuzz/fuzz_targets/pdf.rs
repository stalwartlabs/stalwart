/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use text_extract::{Error, Extractor, Format, Hints, Limits};

const HEADER: &[u8] = b"%PDF-1.7\n";
const REUSE_EVERY: usize = 4;

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_output_bytes: 1 << 20,
        max_part_bytes: 8 << 20,
        max_total_bytes: 32 << 20,
        max_pdf_objects: 1 << 16,
        ..Limits::default()
    };
    let mut input = Vec::with_capacity(HEADER.len() + data.len());
    if !data.starts_with(b"%PDF-") {
        input.extend_from_slice(HEADER);
    }
    input.extend_from_slice(data);
    let mut extractor = Extractor::new(limits.clone());
    let mut out = String::new();
    let result = extractor.extract(&input, Hints::new(), &mut out);
    match &result {
        Ok(extraction) => {
            assert_eq!(extraction.format, Format::Pdf);
            assert_eq!(extraction.bytes_written, out.len());
            assert!(extraction.bytes_decompressed <= limits.max_total_bytes);
        }
        Err(failure) => {
            assert!(out.is_empty());
            assert_ne!(failure.error, Error::TooLarge);
        }
    }
    assert!(out.len() <= limits.max_output_bytes);
    if data.len() % REUSE_EVERY == 0 {
        let mut again = String::new();
        assert_eq!(extractor.extract(&input, Hints::new(), &mut again), result);
        assert_eq!(again, out);
    }
});
