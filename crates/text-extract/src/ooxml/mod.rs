/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod chart;
mod comments;
mod layout;
mod number;
mod pptx;
mod rels;
mod sheet;
mod styles;
mod text;
mod xlsx;

use crate::{
    Format,
    output::{Output, Separator},
    package::{Arena, Package, Span},
    xml::stream::Part,
};
use chart::{ChartText, ChartValues};
use comments::CommentsText;
use rels::{Rel, RelKind, RelsHandler};
use styles::Styles;
use text::{MainPart, RunText};

const ROOT_RELS: &[u8] = b"_rels/.rels";
const MAIN_PART_FALLBACKS: [&[u8]; 3] = [
    b"word/document.xml",
    b"xl/workbook.xml",
    b"ppt/presentation.xml",
];

#[derive(Default)]
pub(crate) struct Scratch {
    arena: Arena,
    rels: Vec<Rel>,
    child_rels: Vec<Rel>,
    nested_rels: Vec<Rel>,
    ids: Vec<Span>,
    styles: Styles,
}

pub(crate) struct Relations<'s> {
    arena: &'s mut Arena,
    child_rels: &'s mut Vec<Rel>,
    nested_rels: &'s mut Vec<Rel>,
    limit: usize,
}

pub(crate) fn is_package(package: &Package<'_, '_>) -> bool {
    package.archive.contains(ROOT_RELS)
        || MAIN_PART_FALLBACKS
            .iter()
            .any(|name| package.archive.contains(name))
}

pub(crate) fn extract(
    package: &mut Package<'_, '_>,
    scratch: &mut Scratch,
    out: &mut Output<'_>,
) -> Option<Format> {
    let Scratch {
        arena,
        rels,
        child_rels,
        nested_rels,
        ids,
        styles,
    } = scratch;
    arena.clear();
    rels.clear();
    child_rels.clear();
    nested_rels.clear();
    ids.clear();
    styles.clear();
    let limit = package.budget.parts;

    let root = arena.push(b"")?;
    let root_rels = arena.push(ROOT_RELS)?;
    load_rels(package, arena, rels, root_rels, root, limit, out);
    let main = rels
        .iter()
        .find(|rel| rel.kind == RelKind::OfficeDocument)
        .map(|rel| rel.target)
        .filter(|target| package.archive.contains(arena.get(*target)))
        .or_else(|| {
            let fallback = MAIN_PART_FALLBACKS
                .iter()
                .find(|name| package.archive.contains(name))?;
            arena.push(fallback)
        })?;

    let member = package.archive.find(arena.get(main))?;
    let mut main_part = MainPart::new(arena, ids, limit);
    package.scan_member_as(&member, Part::Content, &mut main_part, out);
    let format = main_part.format()?;
    let dates = main_part.dates();
    package.budget.truncated |= main_part.capped();
    out.separator(Separator::Newline);

    rels.clear();
    let main_rels = arena.push_rels_path(main)?;
    load_rels(package, arena, rels, main_rels, main, limit, out);

    let mut relations = Relations {
        arena,
        child_rels,
        nested_rels,
        limit,
    };
    match format {
        Format::Docx => {
            let Relations {
                arena, nested_rels, ..
            } = relations;
            scan_related(
                package,
                arena,
                rels,
                nested_rels,
                limit,
                ChartValues::All,
                out,
            );
        }
        Format::Xlsx => xlsx::extract(package, &mut relations, rels, ids, styles, dates, out),
        _ => pptx::extract(package, &mut relations, rels, ids, out),
    }
    Some(format)
}

fn load_rels(
    package: &mut Package<'_, '_>,
    arena: &mut Arena,
    rels: &mut Vec<Rel>,
    path: Span,
    source: Span,
    limit: usize,
    out: &mut Output<'_>,
) -> bool {
    let Some(member) = package.archive.find(arena.get(path)) else {
        return false;
    };
    let mut handler = RelsHandler {
        arena,
        rels,
        source,
        limit,
    };
    package.scan_member_as(&member, Part::Plumbing, &mut handler, out)
}

impl Relations<'_> {
    fn load_children(
        &mut self,
        package: &mut Package<'_, '_>,
        part: Span,
        out: &mut Output<'_>,
    ) -> bool {
        self.child_rels.clear();
        match self.arena.push_rels_path(part) {
            Some(path) => load_rels(
                package,
                self.arena,
                self.child_rels,
                path,
                part,
                self.limit,
                out,
            ),
            None => false,
        }
    }

    fn scan_children(
        &mut self,
        package: &mut Package<'_, '_>,
        values: ChartValues,
        out: &mut Output<'_>,
    ) {
        let Relations {
            arena,
            child_rels,
            nested_rels,
            limit,
        } = self;
        scan_related(package, arena, child_rels, nested_rels, *limit, values, out);
    }
}

fn scan_related(
    package: &mut Package<'_, '_>,
    arena: &mut Arena,
    rels: &[Rel],
    nested_rels: &mut Vec<Rel>,
    limit: usize,
    values: ChartValues,
    out: &mut Output<'_>,
) {
    for rel in rels {
        if package.stopped(out) {
            return;
        }
        match rel.kind {
            RelKind::Comments | RelKind::ThreadedComments => {
                package.scan(arena.get(rel.target), &mut CommentsText::default(), out);
            }
            RelKind::Footnotes
            | RelKind::Endnotes
            | RelKind::DiagramData
            | RelKind::Header
            | RelKind::Footer
            | RelKind::NotesSlide => {
                package.scan(arena.get(rel.target), &mut RunText::default(), out);
            }
            RelKind::Chart => {
                package.scan(arena.get(rel.target), &mut ChartText::new(values), out);
            }
            RelKind::Drawing => {
                if package.scan(arena.get(rel.target), &mut RunText::default(), out) {
                    out.separator(Separator::Newline);
                    scan_drawing(package, arena, rel.target, nested_rels, limit, values, out);
                }
            }
            _ => continue,
        }
        out.separator(Separator::Newline);
    }
}

fn scan_drawing(
    package: &mut Package<'_, '_>,
    arena: &mut Arena,
    drawing: Span,
    nested_rels: &mut Vec<Rel>,
    limit: usize,
    values: ChartValues,
    out: &mut Output<'_>,
) {
    let mark = arena.mark();
    nested_rels.clear();
    if let Some(path) = arena.push_rels_path(drawing) {
        load_rels(package, arena, nested_rels, path, drawing, limit, out);
    }
    for rel in nested_rels.iter() {
        if package.stopped(out) {
            break;
        }
        match rel.kind {
            RelKind::Chart => {
                package.scan(arena.get(rel.target), &mut ChartText::new(values), out);
            }
            RelKind::DiagramData => {
                package.scan(arena.get(rel.target), &mut RunText::default(), out);
            }
            _ => continue,
        }
        out.separator(Separator::Newline);
    }
    arena.rewind(mark);
}
