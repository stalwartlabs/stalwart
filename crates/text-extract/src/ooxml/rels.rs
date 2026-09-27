/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    output::Output,
    package::{Arena, Span},
    xml::{Handler, Tag, Text},
};
use memchr::memrchr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelKind {
    OfficeDocument,
    Header,
    Footer,
    Footnotes,
    Endnotes,
    Comments,
    ThreadedComments,
    DiagramData,
    SharedStrings,
    Styles,
    Worksheet,
    Chartsheet,
    Drawing,
    Chart,
    Slide,
    SlideLayout,
    SlideMaster,
    NotesSlide,
}

impl RelKind {
    fn parse(relationship_type: &[u8]) -> Option<Self> {
        let suffix = memrchr(b'/', relationship_type)
            .and_then(|slash| relationship_type.get(slash + 1..))
            .unwrap_or(relationship_type);
        hashify::map!(suffix, RelKind,
            b"officeDocument" => RelKind::OfficeDocument,
            b"header" => RelKind::Header,
            b"footer" => RelKind::Footer,
            b"footnotes" => RelKind::Footnotes,
            b"endnotes" => RelKind::Endnotes,
            b"comments" => RelKind::Comments,
            b"threadedComment" => RelKind::ThreadedComments,
            b"diagramData" => RelKind::DiagramData,
            b"sharedStrings" => RelKind::SharedStrings,
            b"styles" => RelKind::Styles,
            b"worksheet" => RelKind::Worksheet,
            b"chartsheet" => RelKind::Chartsheet,
            b"drawing" => RelKind::Drawing,
            b"chart" => RelKind::Chart,
            b"chartEx" => RelKind::Chart,
            b"slide" => RelKind::Slide,
            b"slideLayout" => RelKind::SlideLayout,
            b"slideMaster" => RelKind::SlideMaster,
            b"notesSlide" => RelKind::NotesSlide,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Rel {
    pub(crate) id: Span,
    pub(crate) kind: RelKind,
    pub(crate) target: Span,
}

pub(crate) struct RelsHandler<'x> {
    pub(crate) arena: &'x mut Arena,
    pub(crate) rels: &'x mut Vec<Rel>,
    pub(crate) source: Span,
    pub(crate) limit: usize,
}

impl Handler for RelsHandler<'_> {
    fn start(&mut self, tag: &Tag<'_>, _out: &mut Output<'_>) {
        if !hashify::set!(tag.local(), b"Relationship") || self.rels.len() >= self.limit {
            return;
        }
        let (mut id, mut kind, mut target, mut external) = (None, None, None, false);
        for (name, value) in tag.attributes() {
            hashify::fnc_map!(name,
                b"Id" => { id = Some(value); },
                b"Type" => { kind = RelKind::parse(value); },
                b"Target" => { target = Some(value); },
                b"TargetMode" => { external = hashify::set_ignore_case!(value, b"External"); },
                _ => {}
            );
        }
        let (Some(id), Some(kind), Some(target), false) = (id, kind, target, external) else {
            return;
        };
        let mark = self.arena.mark();
        match (
            self.arena.push_decoded(id),
            self.arena.push_resolved(self.source, target),
        ) {
            (Some(id), Some(target)) => self.rels.push(Rel { id, kind, target }),
            _ => self.arena.rewind(mark),
        }
    }

    fn end(&mut self, _name: &[u8], _out: &mut Output<'_>) {}

    fn text(&mut self, _text: Text<'_>, _out: &mut Output<'_>) {}
}

pub(crate) fn sort_by_id(arena: &Arena, rels: &mut Vec<Rel>) {
    rels.sort_unstable_by(|left, right| {
        arena
            .get(left.id)
            .cmp(arena.get(right.id))
            .then(left.id.start().cmp(&right.id.start()))
    });
    rels.dedup_by(|later, earlier| arena.get(later.id) == arena.get(earlier.id));
}

pub(crate) fn find_sorted(
    arena: &Arena,
    sorted: &[Rel],
    id: Span,
    accept: impl Fn(RelKind) -> bool,
) -> Option<Rel> {
    let id = arena.get(id);
    let index = sorted
        .binary_search_by(|rel| arena.get(rel.id).cmp(id))
        .ok()?;
    sorted.get(index).filter(|rel| accept(rel.kind)).copied()
}

pub(crate) fn find_kind(rels: &[Rel], kind: RelKind) -> Option<Span> {
    rels.iter()
        .find(|rel| rel.kind == kind)
        .map(|rel| rel.target)
}
