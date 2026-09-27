/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Extra, HELVETICA, Page, document, page, text};

const FONT: &str = "<< /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >>";

#[test]
fn form_xobjects_are_interpreted_with_matrix_and_resources() {
    assert_eq!(
        page(
            "/XObject << /Fm1 10 0 R >>",
            b"q 1 0 0 1 72 700 cm /Fm1 Do Q BT /F1 12 Tf 72 600 Td (after) Tj ET",
            &[Extra::Stream(
                &format!(
                    "/Type /XObject /Subtype /Form /BBox [0 0 500 100] /Matrix [1 0 0 1 0 0] /Resources {FONT}"
                ),
                b"BT /F1 12 Tf 0 0 Td (inside form) Tj ET",
            )],
        ),
        "inside form\nafter"
    );
    assert_eq!(
        page(
            &format!("{HELVETICA} /XObject << /Fm1 10 0 R >>"),
            b"BT /F1 12 Tf 72 700 Td (before) Tj ET /Fm1 Do",
            &[Extra::Stream(
                "/Type /XObject /Subtype /Form /BBox [0 0 500 100] /Matrix [1 0 0 1 72 680]",
                b"BT /F1 12 Tf (inherits resources) Tj ET",
            )],
        ),
        "before\ninherits resources"
    );
}

#[test]
fn forms_that_draw_themselves_stop() {
    assert_eq!(
        page(
            &format!("{HELVETICA} /XObject << /Fm1 10 0 R >>"),
            b"/Fm1 Do /Fm1 Do",
            &[Extra::Stream(
                "/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> /XObject << /Fm1 10 0 R >> >>",
                b"BT /F1 12 Tf 72 700 Td (loop) Tj ET /Fm1 Do",
            )],
        ),
        "loop"
    );
    assert_eq!(
        page(
            "/XObject << /Img 10 0 R /Blank 11 0 R >>",
            b"/Img Do /Blank Do /Blank Do /Missing Do",
            &[
                Extra::Stream(
                    "/Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray",
                    b"\x00"
                ),
                Extra::Stream(
                    "/Type /XObject /Subtype /Form /BBox [0 0 1 1]",
                    b"0 0 m 1 1 l S"
                ),
            ],
        ),
        ""
    );
}

#[test]
fn forms_deduplicated_on_one_page_still_draw_on_the_next() {
    let resources = format!("{HELVETICA} /XObject << /Fm 10 0 R >>");
    let watermark = [Extra::Stream(
        &format!("/Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources {FONT}"),
        b"BT /F1 12 Tf 72 700 Td (WMARK) Tj ET",
    )];
    for (first, expected) in [
        (
            &b"BT /F1 12 Tf 72 700 Td (WMARK) Tj ET /Fm Do"[..],
            "WMARK\nWMARK",
        ),
        (b"q 1 0 0 1 0 5000 cm /Fm Do Q /Fm Do", "WMARK\nWMARK"),
        (b"/Fm Do /Fm Do", "WMARK\nWMARK"),
    ] {
        let pages = [
            Page {
                resources: &resources,
                content: first,
                extra: "",
            },
            Page {
                resources: &resources,
                content: b"/Fm Do",
                extra: "",
            },
        ];
        assert_eq!(text(&document(&pages, &watermark)), expected);
    }
}

#[test]
fn graphics_state_stack_tolerates_imbalance() {
    assert_eq!(
        page(
            HELVETICA,
            b"Q Q q q q 2 0 0 2 0 0 cm Q BT /F1 12 Tf 72 700 Td (balanced) Tj ET Q Q Q Q",
            &[]
        ),
        "balanced"
    );
    assert_eq!(
        page(
            HELVETICA,
            b"BT /F1 12 Tf 72 700 Td (no end) Tj BT (twice) Tj ET ET ET ( outside) Tj",
            &[]
        ),
        "no end\ntwice outside"
    );
}

#[test]
fn inline_images_are_skipped() {
    assert_eq!(
        page(
            HELVETICA,
            b"BT /F1 12 Tf 72 700 Td (before) Tj ET BI /W 4 /H 1 /BPC 8 /CS /G ID \x00EI(\xff EI BT /F1 12 Tf 72 680 Td (after) Tj ET",
            &[]
        ),
        "before\nafter"
    );
    assert_eq!(
        page(
            HELVETICA,
            b"BT /F1 12 Tf 72 700 Td (kept) Tj ET BI /W 4 /H 4 /F /Fl ID \x78\x9c no end marker at all",
            &[]
        ),
        "kept"
    );
}

#[test]
fn extgstate_fonts_and_show_operators() {
    assert_eq!(
        page(
            "/ExtGState << /GS1 << /Font [10 0 R 12] >> >>",
            b"BT /GS1 gs 72 700 Td (from gs) Tj ET",
            &[Extra::Object(
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
            )],
        ),
        "from gs"
    );
    assert_eq!(
        page(HELVETICA, b"BT 72 700 Td (no font selected) Tj ET", &[]),
        "no font selected"
    );
    assert_eq!(
        page(
            HELVETICA,
            b"BT /F1 12 Tf 72 700 Td 1 2 3 4 5 6 7 (junk operands) Tj /Unknown 12 Tf ( still) Tj ET",
            &[]
        ),
        "junk operands still"
    );
}

#[test]
fn garbage_does_not_abandon_the_stream_early() {
    let mut content = b"BT /F1 12 Tf 72 700 Td (start) Tj ".to_vec();
    content.extend_from_slice(&b"] >> } { ) xx yy ".repeat(100));
    content.extend_from_slice(b"( end) Tj ET");
    assert_eq!(page(HELVETICA, &content, &[]), "start end");
    let mut binary = b"BT /F1 12 Tf 72 700 Td (start) Tj ".to_vec();
    binary.extend_from_slice(&b"\x01\x02]".repeat(5000));
    binary.extend_from_slice(b"(lost) Tj ET");
    assert_eq!(page(HELVETICA, &binary, &[]), "start");
}

#[test]
fn content_arrays_join_streams() {
    let data = super::super::builder::Pdf::new()
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(
            3,
            &format!("<< /Type /Page /Parent 2 0 R /Resources << {HELVETICA} >> /Contents [4 0 R 5 0 R] >>"),
        )
        .stream(4, "", b"BT /F1 12 Tf 72 700 Td (split")
        .stream(5, "", b"operands) Tj ET")
        .xref_table("/Root 1 0 R")
        .build();
    assert_eq!(super::text(&data), "split operands");
}
