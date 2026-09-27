/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[path = "../../../tests/common/pdf.rs"]
pub(super) mod builder;
mod corpus;
mod structure;
mod text;

use super::{
    document::{DocScratch, Document, OpenError},
    pages::{Pages, Visited},
};
use crate::{Limits, xml::stream::Budget};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Walk {
    pages: usize,
    repaired: bool,
    streams: usize,
    failures: usize,
    decoded: u64,
    contents: Vec<Vec<u8>>,
}

fn budget(limits: &Limits) -> Budget {
    Budget {
        part_bytes: limits.max_part_bytes,
        total_bytes: limits.max_total_bytes,
        parts: usize::MAX,
        used_bytes: 0,
        used_parts: 0,
        truncated: false,
    }
}

fn walk_with(data: &[u8], limits: &Limits) -> Result<Walk, OpenError> {
    let mut scratch = DocScratch::default();
    let mut visited = Visited::default();
    let document = Document::open(data, &mut scratch, budget(limits), limits.max_pdf_objects)
        .map_err(|failure| failure.error)?;
    let mut walk = Walk::default();
    let mut contents = Vec::new();
    for page in Pages::new(&document, &mut visited) {
        let (data, outcome) = page.contents(&document, &mut contents);
        walk.pages += 1;
        walk.streams += outcome.streams;
        walk.failures += outcome.failures;
        walk.contents.push(data.to_vec());
    }
    walk.repaired = document.repaired();
    walk.decoded = document.used_bytes();
    Ok(walk)
}

fn walk(data: &[u8]) -> Walk {
    walk_with(data, &Limits::default()).unwrap_or_else(|error| panic!("open failed: {error:?}"))
}

fn pages() -> [&'static [u8]; 3] {
    [
        b"BT (first page) Tj ET",
        b"BT (second) Tj ET",
        b"BT (third page text) Tj ET",
    ]
}
