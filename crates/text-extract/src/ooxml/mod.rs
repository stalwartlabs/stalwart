/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod rels;
mod text;

use crate::{
    Format,
    output::{Output, Separator},
    package::{Arena, Package, Span},
};
use rels::{Rel, RelKind, RelsHandler, find_target};
use text::{MainPart, RunText, SheetText};

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
    ids: Vec<Span>,
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
        ids,
    } = scratch;
    arena.clear();
    rels.clear();
    child_rels.clear();
    ids.clear();
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
    let data = package.archive.read(&member, package.claimed)?;
    let mut main_part = MainPart::new(arena, ids, limit);
    package
        .buffers
        .scan(data, &mut package.budget, &mut main_part, out);
    let format = main_part.format()?;
    out.separator(Separator::Newline);

    rels.clear();
    let main_rels = arena.push_rels_path(main)?;
    load_rels(package, arena, rels, main_rels, main, limit, out);

    match format {
        Format::Docx => extract_docx(package, arena, rels, out),
        Format::Xlsx => extract_xlsx(package, arena, rels, ids, out),
        _ => extract_pptx(package, arena, rels, child_rels, ids, limit, out),
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
) {
    let Some(member) = package.archive.find(arena.get(path)) else {
        return;
    };
    let Some(data) = package.archive.read(&member, package.claimed) else {
        return;
    };
    let mut handler = RelsHandler {
        arena,
        rels,
        source,
        limit,
    };
    package
        .buffers
        .scan(data, &mut package.budget, &mut handler, out);
}

fn extract_docx(package: &mut Package<'_, '_>, arena: &Arena, rels: &[Rel], out: &mut Output<'_>) {
    for rel in rels.iter().filter(|rel| {
        matches!(
            rel.kind,
            RelKind::Footnotes
                | RelKind::Endnotes
                | RelKind::Comments
                | RelKind::DiagramData
                | RelKind::Header
                | RelKind::Footer
        )
    }) {
        if package.stopped(out) {
            return;
        }
        package.scan(arena.get(rel.target), &mut RunText::default(), out);
        out.separator(Separator::Newline);
    }
}

fn extract_xlsx(
    package: &mut Package<'_, '_>,
    arena: &Arena,
    rels: &[Rel],
    sheets: &[Span],
    out: &mut Output<'_>,
) {
    if let Some(shared) = rels.iter().find(|rel| rel.kind == RelKind::SharedStrings) {
        package.scan(arena.get(shared.target), &mut RunText::default(), out);
        out.separator(Separator::Newline);
    }
    for &sheet in sheets {
        if package.stopped(out) {
            return;
        }
        if let Some(target) = find_target(arena, rels, RelKind::Worksheet, sheet) {
            package.scan(arena.get(target), &mut SheetText::default(), out);
            out.separator(Separator::Newline);
        }
    }
}

fn extract_pptx(
    package: &mut Package<'_, '_>,
    arena: &mut Arena,
    rels: &[Rel],
    child_rels: &mut Vec<Rel>,
    slides: &[Span],
    limit: usize,
    out: &mut Output<'_>,
) {
    for &slide in slides {
        if package.stopped(out) {
            return;
        }
        let Some(target) = find_target(arena, rels, RelKind::Slide, slide) else {
            continue;
        };
        if !package.scan(arena.get(target), &mut RunText::default(), out) {
            continue;
        }
        out.separator(Separator::Newline);
        let mark = arena.mark();
        child_rels.clear();
        if let Some(path) = arena.push_rels_path(target) {
            load_rels(package, arena, child_rels, path, target, limit, out);
        }
        for rel in child_rels.iter().filter(|rel| {
            matches!(
                rel.kind,
                RelKind::NotesSlide | RelKind::Comments | RelKind::DiagramData
            )
        }) {
            if package.stopped(out) {
                break;
            }
            package.scan(arena.get(rel.target), &mut RunText::default(), out);
            out.separator(Separator::Newline);
        }
        arena.rewind(mark);
    }
}
