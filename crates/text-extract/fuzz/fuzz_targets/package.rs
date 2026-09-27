/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

#[path = "../../tests/common/mod.rs"]
mod common;

use common::ZipBuilder;
use libfuzzer_sys::fuzz_target;
use text_extract::{Extractor, Hints, Limits};

const REUSE_EVERY: usize = 4;

const LAYOUTS: [&[&str]; 6] = [
    &["_rels/.rels", "word/document.xml", "word/_rels/document.xml.rels", "word/header1.xml", "word/footnotes.xml"],
    &["_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"],
    &["_rels/.rels", "ppt/presentation.xml", "ppt/_rels/presentation.xml.rels", "ppt/slides/slide1.xml", "ppt/slides/_rels/slide1.xml.rels"],
    &["mimetype", "content.xml", "styles.xml", "META-INF/manifest.xml"],
    &["mimetype", "META-INF/container.xml", "OEBPS/content.opf", "OEBPS/chapter1.xhtml", "OEBPS/chapter2.xhtml"],
    &["mimetype", "content.xml", "META-INF/container.xml", "a.xhtml"],
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let layout = LAYOUTS[usize::from(selector) % LAYOUTS.len()];
    let mut builder = ZipBuilder::new();
    let mut members = rest.split(|&byte| byte == 0xFF);
    for (index, name) in layout.iter().enumerate() {
        let contents = members.next().unwrap_or_default();
        builder = if selector >> (index % 8) & 1 == 0 {
            builder.file(name, contents)
        } else {
            builder.stored(name, contents)
        };
    }
    let limits = Limits {
        max_output_bytes: 1 << 20,
        max_total_bytes: 32 << 20,
        ..Limits::default()
    };
    let input = builder.build();
    let mut extractor = Extractor::new(limits.clone());
    let mut out = String::new();
    let result = extractor.extract(&input, Hints::new(), &mut out);
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
        assert_eq!(extractor.extract(&input, Hints::new(), &mut again), result);
        assert_eq!(again, out);
    }
});
