/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Extra, page};

const CMR10_TYPE1: &[u8] = include_bytes!("../../font/program/tests/data/cmr10-type1.t1");
const CMR10_CFF: &[u8] = include_bytes!("../../font/program/tests/data/cmr10-type1c.cff");
const DEJAVU_LATIN: &[u8] = include_bytes!("../../font/program/tests/data/dejavu-latin.ttf");
const NOTO_CJK: &[u8] = include_bytes!("../../font/program/tests/data/noto-cjk-cid.otf");

fn simple(font: &str, content: &str) -> String {
    page(
        &format!("/Font << /F1 << /Type /Font {font} >> >>"),
        format!("BT /F1 12 Tf 72 700 Td {content} ET").as_bytes(),
        &[],
    )
}

fn with_objects(font: &str, content: &str, objects: &[Extra<'_>]) -> String {
    page(
        &format!("/Font << /F1 {font} >>"),
        format!("BT /F1 12 Tf 72 700 Td {content} ET").as_bytes(),
        objects,
    )
}

fn composite(encoding: &str, descendant: &str, content: &str, objects: &[Extra<'_>]) -> String {
    with_objects(
        &format!(
            "<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding {encoding} /DescendantFonts [<< /Type /Font {descendant} >>] >>"
        ),
        content,
        objects,
    )
}

#[test]
fn to_unicode_wins_but_implausible_targets_fall_back() {
    let to_unicode = b"beginbfchar <41> <0058> <42> <0000> <43> <0009> <44> <E000> <45> <0001> <46> <00660069> endbfchar";
    assert_eq!(
        with_objects(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding /ToUnicode 10 0 R >>",
            "(ABCDEF) Tj",
            &[Extra::Stream("", to_unicode)],
        ),
        "XB DEfi"
    );
    assert_eq!(
        with_objects(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode /Identity-H >>",
            "(caf\\351) Tj",
            &[],
        ),
        "caf\u{e9}"
    );
}

#[test]
fn differences_override_the_base_encoding() {
    assert_eq!(
        simple(
            "/Subtype /Type1 /BaseFont /Helvetica /Encoding << /BaseEncoding /MacRomanEncoding /Differences [65 /Aring /.notdef /uni0041 /f_f_i] >>",
            "(ABCD\\212) Tj"
        ),
        "\u{c5}BAffi\u{e4}"
    );
    assert_eq!(
        simple("/Subtype /TrueType /BaseFont /Arial", "(\\200\\223) Tj"),
        "\u{20ac}\u{201c}"
    );
    assert_eq!(
        simple("/Subtype /Type1 /BaseFont /Helvetica", "(\\341\\047) Tj"),
        "\u{c6}\u{2019}"
    );
}

#[test]
fn numeric_glyph_names_need_a_numeric_encoding() {
    assert_eq!(
        simple(
            "/Subtype /Type1 /BaseFont /Custom /Encoding << /Differences [100 /C65 /C66] >>",
            "(de) Tj"
        ),
        "AB"
    );
    assert_eq!(
        simple(
            "/Subtype /Type1 /BaseFont /Custom /Encoding << /Differences [100 /C65 /g3] >>",
            "(de) Tj"
        ),
        "de"
    );
    assert_eq!(
        simple(
            "/Subtype /Type1 /BaseFont /Custom /Encoding << /Differences [1 /gibberish] >>",
            "(\\001AB) Tj"
        ),
        "AB"
    );
}

#[test]
fn type3_fonts_use_encoding_and_font_matrix() {
    assert_eq!(
        simple(
            "/Subtype /Type3 /FontMatrix [0.001 0 0 0.001 0 0] /FontBBox [0 0 1000 1000] /CharProcs << >> \
             /Encoding << /Differences [65 /a65 233 /a233] >> /FirstChar 65 /LastChar 65 /Widths [600]",
            "(A\\351) Tj"
        ),
        "A\u{e9}"
    );
    assert_eq!(
        simple(
            "/Subtype /Type3 /FontMatrix [1 0 0 1 0 0] /FontBBox [0 0 1 1] /CharProcs << >> \
             /Encoding << /Differences [97 /a /b] >> /FirstChar 97 /LastChar 98 /Widths [0.5 0.5]",
            "(ab) Tj 15 0 Td (ba) Tj"
        ),
        "ab ba"
    );
}

#[test]
fn embedded_programs_supply_builtin_encodings() {
    assert_eq!(
        with_objects(
            "<< /Type /Font /Subtype /Type1 /BaseFont /CMR10 /FirstChar 0 /LastChar 127 /FontDescriptor 10 0 R >>",
            "(\\013\\014A) Tj",
            &[
                Extra::Object(
                    "<< /Type /FontDescriptor /FontName /CMR10 /Flags 4 /FontFile 11 0 R >>"
                ),
                Extra::Stream("/Length1 2587 /Length2 0 /Length3 0", CMR10_TYPE1),
            ],
        ),
        "fffiA"
    );
    assert_eq!(
        with_objects(
            "<< /Type /Font /Subtype /Type1 /BaseFont /CMR10 /FontDescriptor 10 0 R >>",
            "(\\000\\002) Tj",
            &[
                Extra::Object(
                    "<< /Type /FontDescriptor /FontName /CMR10 /Flags 4 /FontFile3 11 0 R >>"
                ),
                Extra::Stream("/Subtype /Type1C", CMR10_CFF),
            ],
        ),
        "\u{393}\u{398}"
    );
    assert_eq!(
        with_objects(
            "<< /Type /Font /Subtype /TrueType /BaseFont /DejaVu /FontDescriptor 10 0 R >>",
            "(Hello World) Tj",
            &[
                Extra::Object(
                    "<< /Type /FontDescriptor /FontName /DejaVu /Flags 4 /FontFile2 11 0 R >>"
                ),
                Extra::Stream("", DEJAVU_LATIN),
            ],
        ),
        "Hello World"
    );
}

#[test]
fn composite_fonts_follow_the_cid_chain() {
    let cid_to_gid: Vec<u8> = [0u16, 4, 10, 13, 14]
        .iter()
        .flat_map(|gid| gid.to_be_bytes())
        .collect();
    assert_eq!(
        composite(
            "/Identity-H",
            "/Subtype /CIDFontType2 /BaseFont /DejaVu /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 10 0 R /CIDToGIDMap 12 0 R /W [1 [750 600 280 610]]",
            "<00010002000300030004> Tj",
            &[
                Extra::Object(
                    "<< /Type /FontDescriptor /FontName /DejaVu /Flags 4 /FontFile2 11 0 R >>"
                ),
                Extra::Stream("", DEJAVU_LATIN),
                Extra::Stream("", &cid_to_gid),
            ],
        ),
        "Hello"
    );
    assert_eq!(
        composite(
            "/Identity-H",
            "/Subtype /CIDFontType0 /BaseFont /Noto /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 10 0 R",
            "<05BE3C04> Tj",
            &[
                Extra::Object(
                    "<< /Type /FontDescriptor /FontName /Noto /Flags 4 /FontFile3 11 0 R >>"
                ),
                Extra::Stream("/Subtype /OpenType", NOTO_CJK),
            ],
        ),
        "\u{304b}\u{5b57}"
    );
    assert_eq!(
        composite(
            "/Identity-H",
            "/Subtype /CIDFontType0 /BaseFont /Ryumin /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >>",
            "<00220023> Tj",
            &[],
        ),
        "AB"
    );
    assert_eq!(
        composite(
            "/Identity-H",
            "/Subtype /CIDFontType2 /BaseFont /Ucs /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >>",
            "<00410042> Tj",
            &[],
        ),
        "AB"
    );
    assert_eq!(
        composite(
            "/Identity-H",
            "/Subtype /CIDFontType2 /BaseFont /Subset /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>",
            "<00410042> Tj",
            &[],
        ),
        ""
    );
}

#[test]
fn predefined_cmaps_decode_codes() {
    let japanese = "/Subtype /CIDFontType0 /BaseFont /HeiseiMin-W3 /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >>";
    assert_eq!(
        composite("/UniJIS-UCS2-H", japanese, "<65E5672C> Tj", &[]),
        "\u{65e5}\u{672c}"
    );
    assert_eq!(
        composite("/90ms-RKSJ-H", japanese, "<93FA967B> Tj (AB) Tj", &[]),
        "\u{65e5}\u{672c}AB"
    );
    assert_eq!(
        composite(
            "/KSCms-UHC-H",
            "/Subtype /CIDFontType0 /BaseFont /Batang /CIDSystemInfo << /Registry (Adobe) /Ordering (Korea1) /Supplement 1 >>",
            "<C7D1B1DB> Tj",
            &[]
        ),
        "\u{d55c}\u{ae00}"
    );
    assert_eq!(
        simple(
            "/Subtype /TrueType /BaseFont /#CB#CE#CC#E5 /Encoding /WinAnsiEncoding",
            "<D6D0CEC4> Tj"
        ),
        "\u{4e2d}\u{6587}"
    );
}

#[test]
fn embedded_encoding_cmaps_map_codes_to_cids() {
    let cmap = b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap \
        2 begincodespacerange <00> <7F> <8140> <9FFC> endcodespacerange \
        1 begincidrange <20> <7E> 1 endcidrange 1 begincidchar <8140> 633 endcidchar \
        endcmap CMapName currentdict /CMap defineresource pop end end";
    assert_eq!(
        composite(
            "10 0 R",
            "/Subtype /CIDFontType0 /BaseFont /Ryumin /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /W [34 [500]]",
            "<41428140> Tj",
            &[Extra::Stream("/Type /CMap /CMapName /Test", cmap)],
        ),
        "AB"
    );
    let parent = b"begincmap 1 begincidrange <0000> <FFFF> 0 endcidrange endcmap";
    let child = b"begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange 1 begincidchar <0001> 34 endcidchar endcmap";
    assert_eq!(
        composite(
            "10 0 R",
            "/Subtype /CIDFontType0 /BaseFont /Ryumin /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >>",
            "<00010023> Tj",
            &[
                Extra::Stream("/Type /CMap /UseCMap 11 0 R", child),
                Extra::Stream("/Type /CMap", parent),
            ],
        ),
        "AB"
    );
}
