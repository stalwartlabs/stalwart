/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Relations,
    chart::ChartValues,
    number::DateSystem,
    rels::{Rel, RelKind, find_kind, find_sorted, sort_by_id},
    sheet::SheetText,
    styles::Styles,
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
    sheets: &[Span],
    styles: &mut Styles,
    dates: DateSystem,
    out: &mut Output<'_>,
) {
    if let Some(target) = find_kind(rels, RelKind::Styles) {
        package.scan_plumbing(relations.arena.get(target), &mut styles.handler(), out);
    }
    if let Some(shared) = find_kind(rels, RelKind::SharedStrings) {
        package.scan(relations.arena.get(shared), &mut RunText::default(), out);
        out.separator(Separator::Newline);
    }
    sort_by_id(relations.arena, rels);
    for &sheet in sheets {
        if package.stopped(out) {
            return;
        }
        let Some(rel) = find_sorted(relations.arena, rels, sheet, |kind| {
            matches!(kind, RelKind::Worksheet | RelKind::Chartsheet)
        }) else {
            continue;
        };
        if rel.kind == RelKind::Worksheet {
            let mut handler = SheetText::new(styles.cell_formats(), dates);
            if !package.scan(relations.arena.get(rel.target), &mut handler, out) {
                continue;
            }
            out.separator(Separator::Newline);
        }
        let mark = relations.arena.mark();
        if relations.load_children(package, rel.target, out) {
            relations.scan_children(package, ChartValues::Strings, out);
        }
        relations.arena.rewind(mark);
    }
}
