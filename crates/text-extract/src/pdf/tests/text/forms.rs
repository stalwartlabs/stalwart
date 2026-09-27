/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Extra, HELVETICA, Page, document, text};
use crate::pdf::tests::builder::Pdf;

#[test]
fn annotation_comments_follow_the_page() {
    let data = document(
        &[Page {
            resources: HELVETICA,
            content: b"BT /F1 12 Tf 72 700 Td (Page body) Tj ET",
            extra: "/Annots [10 0 R 11 0 R 12 0 R 13 0 R 14 0 R 15 0 R 16 0 R]",
        }],
        &[
            Extra::Object(
                "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (Sticky note) /T (Author) >>",
            ),
            Extra::Object(
                "<< /Type /Annot /Subtype /Popup /Rect [0 0 10 10] /Contents (Sticky note popup) >>",
            ),
            Extra::Object(
                "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /Contents (link tooltip) >>",
            ),
            Extra::Object(
                "<< /Type /Annot /Subtype /FreeText /Rect [0 0 10 10] /Contents <FEFF0046007200650065> >>",
            ),
            Extra::Object(
                "<< /Type /Annot /Subtype /Highlight /Rect [0 0 10 10] /Contents () /RC (<body><p>Rich &amp; bold</p></body>) >>",
            ),
            Extra::Object(
                "<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents (Sticky note) >>",
            ),
            Extra::Object(
                "<< /Type /Annot /Subtype /Widget /Rect [0 0 10 10] /Contents (widget) /V (value) >>",
            ),
        ],
    );
    assert_eq!(text(&data), "Page body\nSticky note\nFree\nRich & bold");
}

#[test]
fn acroform_values_are_emitted_once() {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [10 0 R 11 0 R 12 0 R 13 0 R 14 0 R 15 0 R 10 0 R] >> >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(
            3,
            &format!("<< /Type /Page /Parent 2 0 R /Resources << {HELVETICA} >> /Contents 4 0 R >>"),
        )
        .stream(4, "", b"BT /F1 12 Tf 72 700 Td (Form page) Tj ET")
        .object(10, "<< /FT /Tx /T (name) /V (Jane Doe) >>")
        .object(11, "<< /FT /Tx /T (secret) /Ff 8192 /V (hunter2) >>")
        .object(12, "<< /FT /Ch /T (country) /Opt [[(fr) (France)] [(de) (Germany)]] /V (de) >>")
        .object(13, "<< /FT /Btn /T (agree) /V /Yes >>")
        .object(14, "<< /FT /Tx /T (parent) /Kids [16 0 R 17 0 R] >>")
        .object(15, "<< /FT /Ch /T (multi) /Opt [(Red) (Blue)] /V [(Red) (Blue)] >>")
        .object(16, "<< /T (child) /V <FEFF004B00690064002000760061006C00750065> /Parent 14 0 R >>")
        .object(17, "<< /T (stream) /V 18 0 R /Parent 14 0 R >>")
        .stream(18, "", b"Long text from a stream")
        .xref_table("/Root 1 0 R");
    assert_eq!(
        text(&pdf.build()),
        "Form page\nJane Doe\nGermany\nKid value\nLong text from a stream\nRed Blue"
    );
}

#[test]
fn deep_and_cyclic_field_trees_are_bounded() {
    let mut pdf = Pdf::new();
    pdf.object(
        1,
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [10 0 R] >> >>",
    )
    .object(2, "<< /Type /Pages /Kids [] /Count 0 >>");
    for level in 10..1_010 {
        pdf.object(
            level,
            &format!(
                "<< /T (f{level}) /FT /Tx /V (v{level}) /Kids [{} 0 R 10 0 R] >>",
                level + 1
            ),
        );
    }
    pdf.xref_table("/Root 1 0 R");
    let output = text(&pdf.build());
    assert!(output.starts_with("v10\nv11\n"));
    assert_eq!(output.lines().count(), 64);
}
