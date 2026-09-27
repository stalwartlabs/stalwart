/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod content;
mod fonts;
mod forms;
mod layout;

use super::builder::Pdf;
use crate::{Extractor, Hints, Limits};
use std::fmt::Write as _;

const FIRST_EXTRA: u32 = 10;

pub(super) enum Extra<'a> {
    Object(&'a str),
    Stream(&'a str, &'a [u8]),
}

pub(super) struct Page<'a> {
    pub(super) resources: &'a str,
    pub(super) content: &'a [u8],
    pub(super) extra: &'a str,
}

pub(super) fn document(pages: &[Page<'_>], objects: &[Extra<'_>]) -> Vec<u8> {
    let mut pdf = Pdf::new();
    let first_page = FIRST_EXTRA + objects.len() as u32;
    let kids: String = (0..pages.len() as u32).fold(String::new(), |mut kids, index| {
        let _ = write!(kids, "{} 0 R ", first_page + index * 2);
        kids
    });
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>").object(
        2,
        &format!("<< /Type /Pages /Kids [{kids}] /Count {} >>", pages.len()),
    );
    for (index, object) in objects.iter().enumerate() {
        let num = FIRST_EXTRA + index as u32;
        match object {
            Extra::Object(body) => pdf.object(num, body),
            Extra::Stream(dict, data) => pdf.stream(num, dict, data),
        };
    }
    for (index, page) in pages.iter().enumerate() {
        let num = first_page + index as u32 * 2;
        pdf.object(
            num,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << {} >> /Contents {} 0 R {} >>",
                page.resources,
                num + 1,
                page.extra
            ),
        )
        .stream(num + 1, "", page.content);
    }
    pdf.xref_table("/Root 1 0 R");
    pdf.build()
}

pub(super) fn page(resources: &str, content: &[u8], objects: &[Extra<'_>]) -> String {
    text(&document(
        &[Page {
            resources,
            content,
            extra: "",
        }],
        objects,
    ))
}

pub(super) fn text(data: &[u8]) -> String {
    let mut out = String::new();
    Extractor::new(Limits::default())
        .extract(data, Hints::new(), &mut out)
        .unwrap_or_else(|error| panic!("extraction failed: {error:?}"));
    out
}

pub(super) const HELVETICA: &str = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >> >>";
