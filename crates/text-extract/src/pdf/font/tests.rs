/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    widths::{CidWidths, DEFAULT_CID_WIDTH, MAX_WIDTH_ENTRIES, VerticalAdvances},
    *,
};
use crate::{
    pdf::{document::DocScratch, object::ObjRef, tests::builder::Pdf},
    xml::stream::Budget,
};
use std::time::{Duration, Instant};

const MAX_OBJECTS: usize = 1 << 20;
const TIME_LIMIT: Duration = Duration::from_secs(2);

fn with_document(objects: &[(u32, String)], check: impl FnOnce(&Document<'_>)) {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [] /Count 0 >>");
    for (num, body) in objects {
        pdf.object(*num, body);
    }
    pdf.xref_table("/Root 1 0 R");
    let data = pdf.build();
    let mut scratch = DocScratch::default();
    let budget = Budget {
        part_bytes: 64 << 20,
        total_bytes: 256 << 20,
        parts: usize::MAX,
        used_bytes: 0,
        used_parts: 0,
        truncated: false,
    };
    let document = Document::open(&data, &mut scratch, budget, MAX_OBJECTS)
        .unwrap_or_else(|failure| panic!("open: {failure:?}"));
    check(&document);
}

fn dict<'d>(document: &'d Document<'_>, num: u32) -> Dict<'d> {
    document
        .get(ObjRef { num, generation: 0 })
        .as_dict()
        .unwrap_or_else(|| panic!("object {num} is not a dictionary"))
}

fn rounded(widths: Vec<f32>) -> Vec<f32> {
    widths
        .into_iter()
        .map(|width| (width * 1000.0).round() / 1000.0)
        .collect()
}

fn decode(font: &Font, bytes: &[u8]) -> (String, Vec<f32>) {
    let mut scratch = String::new();
    let mut text = String::new();
    let mut widths = Vec::new();
    let mut rest = bytes;
    while let Some((glyph, glyph_text)) = font.glyph(rest, &mut scratch) {
        text.push_str(glyph_text);
        widths.push(glyph.width);
        rest = rest.get(glyph.len..).unwrap_or_default();
    }
    (text, rounded(widths))
}

#[test]
fn standard_font_decodes_win_ansi() {
    let font = Font::standard();
    let (text, widths) = decode(&font, b"A\x80 ");
    assert_eq!(text, "A\u{20ac} ");
    assert_eq!(widths, vec![0.667, 0.556, 0.278]);
    assert_eq!(font.metrics().space_width, Some(0.278));
}

#[test]
fn cid_widths_ranges_and_lists() {
    with_document(
        &[(
            10,
            "<< /DW 300 /W [1 [500 600] 10 20 700 30 [800 (junk) 900] 15 15 650] >>".into(),
        )],
        |document| {
            let widths = CidWidths::load(document, dict(document, 10));
            let sample: Vec<f32> = [0, 1, 2, 3, 10, 15, 20, 21, 30, 31, 32]
                .iter()
                .map(|&cid| widths.width(cid))
                .collect();
            assert_eq!(
                sample,
                vec![
                    300.0, 500.0, 600.0, 300.0, 700.0, 650.0, 700.0, 300.0, 800.0, 300.0, 900.0
                ]
            );
        },
    );
}

#[test]
fn per_code_width_lists_are_compact() {
    let list: String = (0..1000)
        .map(|index| format!("{} ", 400 + index % 7))
        .collect();
    with_document(
        &[(
            10,
            format!("<< /W [5 [{list}] 2000 2100 250 2101 [250 250 300]] >>"),
        )],
        |document| {
            let widths = CidWidths::load(document, dict(document, 10));
            assert_eq!(widths.width(5), 400.0);
            assert_eq!(widths.width(1004), 405.0);
            assert_eq!(widths.width(2102), 250.0);
            assert_eq!(widths.width(2103), 300.0);
            assert_eq!(widths.width(2104), DEFAULT_CID_WIDTH);
            assert!(widths.heap_size() <= 1002 * 4 + 3 * 16);
        },
    );
}

#[test]
fn hostile_width_arrays_stay_bounded() {
    let mut list = String::from("<< /W [0 4294967295 500 -5 7 100 1e30 2 3 0 [");
    for _ in 0..(MAX_WIDTH_ENTRIES + 5_000) {
        list.push_str("1 ");
    }
    list.push_str("] 200000 [7]] /DW2 [880 -900] /W2 [0 4294967295 -1000 1 1 5 5 -500 250 880] >>");
    with_document(&[(10, list)], |document| {
        let started = Instant::now();
        let widths = CidWidths::load(document, dict(document, 10));
        let vertical = VerticalAdvances::load(document, dict(document, 10));
        assert!(started.elapsed() < TIME_LIMIT);
        assert_eq!(widths.width(4_000_000_000), 500.0);
        assert_eq!(widths.width(3), 1.0);
        assert_eq!(widths.width(200_000), 500.0);
        assert!(widths.heap_size() < 2 << 20);
        assert_eq!(vertical.advance(5), -500.0);
        assert_eq!(vertical.advance(6), -1000.0);
        assert_eq!(VerticalAdvances::empty().advance(6), -1000.0);
    });
}

#[test]
fn simple_widths_follow_first_char_and_fallbacks() {
    with_document(
        &[(
            10,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /FirstChar 65 /Widths [700 (x) 800] /FontDescriptor << /MissingWidth 333 >> >>".into(),
        ), (
            11,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /FirstChar 300 /Widths [100] >>".into(),
        ), (
            12,
            "<< /Type /Font /Subtype /TrueType /BaseFont /UnknownSans /FirstChar -7 /Widths [100] >>".into(),
        )],
        |document| {
            let mut buf = Vec::new();
            let font = Font::load(document, dict(document, 10), &mut buf);
            assert_eq!(decode(&font, b"ABCD").1, vec![0.7, 0.333, 0.8, 0.333]);
            let font = Font::load(document, dict(document, 11), &mut buf);
            assert_eq!(decode(&font, b"A").1, vec![0.722]);
            let font = Font::load(document, dict(document, 12), &mut buf);
            assert_eq!(decode(&font, b"\x00A").1, vec![0.1, 0.667]);
        },
    );
}

#[test]
fn composite_fonts_split_codes_and_measure_cids() {
    with_document(
        &[(
            10,
            "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [11 0 R] >>".into(),
        ), (
            11,
            "<< /Type /Font /Subtype /CIDFontType2 /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) >> /DW 1000 /W [65 [500]] >>".into(),
        ), (
            12,
            "<< /Type /Font /Subtype /Type0 /Encoding /Identity-V /DescendantFonts [<< /Subtype /CIDFontType0 /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) >> /W2 [65 [-800 250 880]] >>] >>".into(),
        ), (
            13,
            "<< /Type /Font /Subtype /Type0 /Encoding /UniJIS-UCS2-H /DescendantFonts [<< /Subtype /CIDFontType0 /DW 1000 >>] >>".into(),
        )],
        |document| {
            let mut buf = Vec::new();
            let font = Font::load(document, dict(document, 10), &mut buf);
            assert_eq!(decode(&font, b"\x00A\x00B\x07"), ("AB".into(), vec![0.5, 1.0, 1.0]));
            assert!(!font.is_vertical());
            let font = Font::load(document, dict(document, 12), &mut buf);
            assert!(font.is_vertical());
            assert_eq!(decode(&font, b"\x00A\x00B").1, vec![-0.8, -1.0]);
            let font = Font::load(document, dict(document, 13), &mut buf);
            assert_eq!(decode(&font, b"\x65\xE5\x00A"), ("\u{65e5}A".into(), vec![1.0, 0.5]));
        },
    );
}

#[test]
fn font_cache_reuses_and_bounds_fonts() {
    let mut objects: Vec<(u32, String)> = vec![(
        10,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
    )];
    objects.push((11, "(not a font)".into()));
    with_document(&objects, |document| {
        let mut cache = FontCache::default();
        let mut buf = Vec::new();
        let reference = Object::Ref(ObjRef {
            num: 10,
            generation: 0,
        });
        let first = cache.load(document, reference, &mut buf);
        assert!(first.is_some());
        assert_eq!(cache.load(document, reference, &mut buf), first);
        let other = Object::Ref(ObjRef {
            num: 11,
            generation: 0,
        });
        assert_eq!(cache.load(document, other, &mut buf), None);
        assert_eq!(cache.load(document, Object::Int(3), &mut buf), None);
        let font = cache.font(first.unwrap_or(FontId::STANDARD));
        assert_eq!(decode(font, b"A").0, "A");
        assert_eq!(decode(cache.font(FontId::STANDARD), b"B").0, "B");
        cache.end_page();
        cache.clear();
        assert_eq!(cache.load(document, reference, &mut buf), first);
    });
}

#[test]
fn usecmap_chains_are_bounded_and_cycles_stop() {
    let chain = 40u32;
    let mut objects = vec![(
        10,
        "<< /Type /Font /Subtype /Type0 /Encoding 100 0 R /DescendantFonts [<< /Subtype /CIDFontType0 /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) >> >>] >>".to_string(),
    )];
    for index in 0..chain {
        let body = format!(
            "begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange 1 begincidchar <{:04X}> {} endcidchar endcmap",
            index,
            0x41 + index
        );
        let parent = if index + 1 == chain { 100 } else { 101 + index };
        objects.push((
            100 + index,
            format!(
                "<< /Type /CMap /UseCMap {parent} 0 R /Length {} >>\nstream\n{body}\nendstream",
                body.len()
            ),
        ));
    }
    with_document(&objects, |document| {
        let mut buf = Vec::new();
        let started = Instant::now();
        let font = Font::load(document, dict(document, 10), &mut buf);
        assert!(started.elapsed() < TIME_LIMIT);
        let (text, _) = decode(&font, b"\x00\x00\x00\x0F\x00\x10\x00\x27");
        assert_eq!(text, "AP");
    });
}
