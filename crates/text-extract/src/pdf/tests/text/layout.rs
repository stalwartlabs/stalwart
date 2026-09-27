/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Extra, HELVETICA, Page, document, page, text};

const IDENTITY_TO_UNICODE: &[u8] =
    b"begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange \
      1 beginbfrange <0000> <FFFF> <0000> endbfrange endcmap";

fn helvetica(content: &str) -> String {
    page(HELVETICA, content.as_bytes(), &[])
}

fn composite(content: &str, encoding: &str) -> String {
    page(
        "/Font << /F1 10 0 R >>",
        content.as_bytes(),
        &[
            Extra::Object(&format!(
                "<< /Type /Font /Subtype /Type0 /BaseFont /Test /Encoding /{encoding} \
                 /DescendantFonts [11 0 R] /ToUnicode 12 0 R >>"
            )),
            Extra::Object(
                "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Test \
                 /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 1000 >>",
            ),
            Extra::Stream("", IDENTITY_TO_UNICODE),
        ],
    )
}

#[test]
fn tj_kerning_and_word_gaps() {
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td [(W) 80 (ord) -40 (s) -300 (apart)] TJ ET"),
        "Words apart"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td [(A) 120 (V) -90 (A)] TJ ET"),
        "AVA"
    );
}

#[test]
fn letter_spacing_with_tc() {
    assert_eq!(
        helvetica("BT /F1 12 Tf 3 Tc 72 700 Td (Tracked) Tj 0 Tc ( heading) Tj ET"),
        "Tracked heading"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td 3 Tc (Tracked) Tj 0 Tc 70 0 Td (x) Tj ET"),
        "Tracked x"
    );
}

#[test]
fn words_positioned_without_space_glyphs() {
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (Each) Tj 30 0 Td (word) Tj 32 0 Td (placed) Tj \
             1 0 0 1 175 700 Tm (by) Tj 1 0 0 1 191 700 Tm (Tm) Tj ET"
        ),
        "Each word placed by Tm"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td (Hel) Tj 18.672 0 Td (lo) Tj ET"),
        "Hello"
    );
}

#[test]
fn columns_and_lines() {
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (left) Tj 300 0 Td (right) Tj -300 -14 Td (next) Tj \
             0 -14 Td (line) Tj ET"
        ),
        "left\nright\nnext\nline"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 14 TL 72 700 Td (one) Tj T* (two) Tj (three) ' 2 1 (four) \" ET"),
        "one\ntwo\nthree\nfour"
    );
}

#[test]
fn rotated_and_mirrored_text() {
    assert_eq!(
        helvetica("BT /F1 12 Tf 0 1 -1 0 300 100 Tm (rotated text) Tj ET"),
        "rotated text"
    );
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (flat) Tj ET BT /F1 12 Tf 0 1 -1 0 300 100 Tm (up) Tj ET"
        ),
        "flat\nup"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf -1 0 0 1 400 700 Tm (mirror) Tj ET"),
        "mirror"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 0.7 0.7 -0.7 0.7 100 100 Tm (diagonal words) Tj ET"),
        "diagonal words"
    );
}

#[test]
fn vertical_cjk_has_no_synthetic_spaces() {
    assert_eq!(
        composite(
            "BT /F1 12 Tf 1 0 0 1 300 700 Tm <65E5672C8A9E> Tj 1 0 0 1 280 700 Tm <30C630B930C8> Tj ET",
            "Identity-V"
        ),
        "\u{65e5}\u{672c}\u{8a9e}\n\u{30c6}\u{30b9}\u{30c8}"
    );
    assert_eq!(
        composite(
            "BT /F1 12 Tf 72 700 Td [<65E5> -300 <672C>] TJ 30 0 Td <D55CAE00> Tj 30 0 Td <C5B8C5B4> Tj ET",
            "Identity-H"
        ),
        "\u{65e5}\u{672c}\u{d55c}\u{ae00} \u{c5b8}\u{c5b4}"
    );
}

#[test]
fn superscripts_and_baseline_changes() {
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td (E=mc) Tj 5 Ts (2) Tj 0 Ts ( ok) Tj ET"),
        "E=mc2 ok"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td (base) Tj 0 -10 Td (low) Tj ET"),
        "base\nlow"
    );
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (result) Tj /F1 8 Tf 5 Ts (1) Tj /F1 12 Tf 0 Ts (next) Tj ET"
        ),
        "result 1 next"
    );
    assert_eq!(
        helvetica("BT /F1 8 Tf 72 705 Td (1) Tj /F1 12 Tf 4.448 -5 Td (Department) Tj ET"),
        "1 Department"
    );
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 1 0 0 1 72 700 Tm (H) Tj /F1 8 Tf 1 0 0 1 80.67 697 Tm (2) Tj /F1 12 Tf 1 0 0 1 85.12 700 Tm (O) Tj ET"
        ),
        "H2O"
    );
}

#[test]
fn fake_bold_and_shadows_are_deduplicated() {
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (Bold) Tj ET BT /F1 12 Tf 72.3 700.2 Td (Bold) Tj ET \
             BT /F1 12 Tf 72 680 Td (Plain) Tj ET"
        ),
        "Bold\nPlain"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td (aa) Tj 20 0 Td (aa) Tj ET"),
        "aa aa"
    );
}

#[test]
fn actual_text_replaces_glyphs() {
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (Hyphen) Tj /Span << /ActualText (ation) >> BDC (-ation) Tj EMC ET"
        ),
        "Hyphenation"
    );
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td /Span << /ActualText <FEFF00440061007300680020> >> BDC \
             /Span << /ActualText (inner) >> BDC (xx) Tj EMC EMC (end) Tj ET"
        ),
        "Dash end"
    );
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (logo) Tj ET /Figure << /ActualText (Acme) >> BDC 0 0 1 1 re f EMC"
        ),
        "logo Acme"
    );
    assert_eq!(
        page(
            &format!("{HELVETICA} /Properties << /P1 << /ActualText (named) >> >>"),
            b"BT /F1 12 Tf 72 700 Td /Span /P1 BDC (xyz) Tj EMC ET",
            &[]
        ),
        "named"
    );
}

#[test]
fn right_to_left_runs() {
    let hebrew = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Hebrew /Encoding << /Differences [65 /alef /bet /gimel /dalet] >> /Widths [500 500 500 500] /FirstChar 65 >> /F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >>";
    assert_eq!(
        page(hebrew, b"BT /F1 12 Tf 72 700 Td (DCBA) Tj ET", &[]),
        "\u{5d0}\u{5d1}\u{5d2}\u{5d3}"
    );
    assert_eq!(
        page(
            hebrew,
            b"BT /F1 12 Tf 1 0 0 1 90 700 Tm (A) Tj 1 0 0 1 84 700 Tm (B) Tj 1 0 0 1 78 700 Tm (C) Tj ET",
            &[]
        ),
        "\u{5d0}\u{5d1}\u{5d2}"
    );
    assert_eq!(
        page(
            hebrew,
            b"BT /F2 12 Tf 72 700 Td (2024) Tj /F1 12 Tf ( ) Tj (BA) Tj ET",
            &[]
        ),
        "\u{5d0}\u{5d1} 2024"
    );
}

#[test]
fn soft_hyphens_join_lines() {
    let soft = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [173 /uni00AD] >> >> >>";
    assert_eq!(
        page(
            soft,
            b"BT /F1 12 Tf 72 700 Td (exam\xAD) Tj 0 -14 Td (ple) Tj 0 -14 Td (co\xADop) Tj ET",
            &[]
        ),
        "example\ncoop"
    );
    assert_eq!(
        helvetica("BT /F1 12 Tf 72 700 Td (well-) Tj 0 -14 Td (known) Tj ET"),
        "well-\nknown"
    );
}

#[test]
fn spacing_accents_merge_with_their_base() {
    let tex = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /CMR10 /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [18 /grave 19 /acute] >> /FirstChar 18 /LastChar 122 /Widths [500 500] /FontDescriptor << /MissingWidth 500 >> >> >>";
    assert_eq!(
        page(
            tex,
            b"BT /F1 10 Tf 72 700 Td [(o) (\x12) 500 (u)] TJ ET BT /F1 10 Tf 72 680 Td [(\x13) 500 (e) (t) (\xe9)] TJ ET",
            &[]
        ),
        "ou\u{300}\ne\u{301}t\u{e9}"
    );
}

#[test]
fn glyphs_outside_the_page_are_dropped() {
    assert_eq!(
        helvetica(
            "BT /F1 12 Tf 72 700 Td (inside) Tj 2000 0 Td (slug) Tj ET BT /F1 12 Tf -500 -500 Td (far) Tj ET"
        ),
        "inside"
    );
}

#[test]
fn pages_are_separated() {
    let data = document(
        &[
            Page {
                resources: HELVETICA,
                content: b"BT /F1 12 Tf 72 700 Td (first) Tj ET",
                extra: "",
            },
            Page {
                resources: HELVETICA,
                content: b"BT /F1 12 Tf 72 700 Td (second) Tj ET",
                extra: "",
            },
        ],
        &[],
    );
    assert_eq!(text(&data), "first\nsecond");
}

#[test]
fn ligatures_and_presentation_forms_are_normalised() {
    let ligatures = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [1 /fi /ffl /uniFEF5] >> >> >>";
    assert_eq!(
        page(
            ligatures,
            b"BT /F1 12 Tf 72 700 Td (\x01ne ba\x02e) Tj ET",
            &[]
        ),
        "fine baffle"
    );
}

#[test]
fn empty_actual_text_hides_a_line_end_hyphen() {
    assert_eq!(
        helvetica(
            "BT /F1 13 Tf 72 600 Td (The word extraordi) Tj /Span <</ActualText ()>> BDC (-) Tj EMC \
             0 -16 Td (nary is soft-hyphenated.) Tj ET"
        ),
        "The word extraordinary is soft-hyphenated."
    );
}
