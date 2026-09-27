/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Relations,
    chart::ChartValues,
    layout::LayoutText,
    load_rels,
    rels::{Rel, RelKind, find_kind, find_sorted, sort_by_id},
    text::RunText,
};
use crate::{
    output::{Output, Separator},
    package::{Package, Span},
};

pub(super) fn extract(
    package: &mut Package<'_, '_>,
    relations: &mut Relations<'_>,
    rels: &mut Vec<Rel>,
    slides: &[Span],
    out: &mut Output<'_>,
) {
    sort_by_id(relations.arena, rels);
    for &slide in slides {
        if package.stopped(out) {
            return;
        }
        let Some(rel) = find_sorted(relations.arena, rels, slide, |kind| kind == RelKind::Slide)
        else {
            continue;
        };
        if !package.scan(
            relations.arena.get(rel.target),
            &mut RunText::default(),
            out,
        ) {
            continue;
        }
        out.separator(Separator::Newline);
        let mark = relations.arena.mark();
        if relations.load_children(package, rel.target, out) {
            relations.scan_children(package, ChartValues::All, out);
            scan_layout(package, relations, out);
        }
        relations.arena.rewind(mark);
    }
}

fn scan_layout(package: &mut Package<'_, '_>, relations: &mut Relations<'_>, out: &mut Output<'_>) {
    let Some(layout) = find_kind(relations.child_rels, RelKind::SlideLayout) else {
        return;
    };
    if package.stopped(out)
        || !package.scan(relations.arena.get(layout), &mut LayoutText::default(), out)
    {
        return;
    }
    out.separator(Separator::Newline);
    relations.nested_rels.clear();
    let Some(path) = relations.arena.push_rels_path(layout) else {
        return;
    };
    load_rels(
        package,
        relations.arena,
        relations.nested_rels,
        path,
        layout,
        relations.limit,
        out,
    );
    if let Some(master) = find_kind(relations.nested_rels, RelKind::SlideMaster)
        && !package.stopped(out)
        && package.scan(relations.arena.get(master), &mut LayoutText::default(), out)
    {
        out.separator(Separator::Newline);
    }
}
