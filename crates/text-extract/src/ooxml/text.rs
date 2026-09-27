/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::number::DateSystem;
use crate::{
    Format,
    output::{Output, Separator},
    package::{Arena, Span},
    xml::{
        Handler, Skip, Tag, Text,
        attr::{push_decoded, split_prefix},
        local_name,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Run {
    Text,
    DeletedText,
    FieldInstruction,
    DeletedFieldInstruction,
    Fallback,
    Phonetic,
    MoveFrom,
    TabStops,
    Tab,
    Cell,
    Break,
    Paragraph,
    Block,
    Boundary,
    NoBreakHyphen,
}

impl Run {
    fn parse(local: &[u8]) -> Option<Run> {
        hashify::map!(local, Run,
            b"t" => Run::Text,
            b"text" => Run::Text,
            b"delText" => Run::DeletedText,
            b"instrText" => Run::FieldInstruction,
            b"delInstrText" => Run::DeletedFieldInstruction,
            b"Fallback" => Run::Fallback,
            b"rPh" => Run::Phonetic,
            b"moveFrom" => Run::MoveFrom,
            b"tabs" => Run::TabStops,
            b"tab" => Run::Tab,
            b"ptab" => Run::Tab,
            b"tc" => Run::Cell,
            b"br" => Run::Break,
            b"cr" => Run::Break,
            b"p" => Run::Paragraph,
            b"tr" => Run::Block,
            b"si" => Run::Block,
            b"txbxContent" => Run::Block,
            b"comment" => Run::Block,
            b"footnote" => Run::Block,
            b"endnote" => Run::Block,
            b"noBreakHyphen" => Run::NoBreakHyphen,
            b"rt" => Run::Boundary,
            b"sym" => Run::Boundary,
            b"num" => Run::Boundary,
            b"den" => Run::Boundary,
        )
        .copied()
    }
}

#[derive(Default)]
pub(crate) struct RunText {
    skip: Skip<Run>,
    in_text: bool,
}

impl Handler for RunText {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        let element = Run::parse(tag.local());
        if self.skip.on_start(element) {
            return;
        }
        match element {
            Some(Run::Text) => self.in_text = true,
            Some(
                skipped @ (Run::DeletedText
                | Run::FieldInstruction
                | Run::DeletedFieldInstruction
                | Run::Fallback
                | Run::Phonetic
                | Run::MoveFrom
                | Run::TabStops),
            ) => self.skip.begin(skipped),
            Some(Run::Tab | Run::Cell | Run::Boundary) => out.separator(Separator::Space),
            Some(Run::Break | Run::Paragraph) => out.separator(Separator::Newline),
            Some(Run::NoBreakHyphen) => out.push_str("-"),
            Some(Run::Block) | None => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        let element = Run::parse(local_name(name));
        if self.skip.on_end(element) {
            return;
        }
        match element {
            Some(Run::Text) => self.in_text = false,
            Some(Run::Paragraph | Run::Block) => out.separator(Separator::Newline),
            Some(Run::Cell | Run::Boundary) => out.separator(Separator::Space),
            _ => {}
        }
    }

    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        if self.in_text {
            text.push(out);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootElement {
    Document,
    Workbook,
    Presentation,
    Sheet,
    SlideId,
    WorkbookProperties,
}

impl RootElement {
    fn parse(local: &[u8]) -> Option<RootElement> {
        hashify::map!(local, RootElement,
            b"document" => RootElement::Document,
            b"workbook" => RootElement::Workbook,
            b"presentation" => RootElement::Presentation,
            b"sheet" => RootElement::Sheet,
            b"sldId" => RootElement::SlideId,
            b"workbookPr" => RootElement::WorkbookProperties,
        )
        .copied()
    }
}

enum Root {
    Pending,
    Document(RunText),
    Workbook,
    Presentation,
    Unknown,
}

pub(crate) struct MainPart<'x> {
    root: Root,
    arena: &'x mut Arena,
    ids: &'x mut Vec<Span>,
    limit: usize,
    dates: DateSystem,
    capped: bool,
}

impl<'x> MainPart<'x> {
    pub(crate) fn new(arena: &'x mut Arena, ids: &'x mut Vec<Span>, limit: usize) -> Self {
        MainPart {
            root: Root::Pending,
            arena,
            ids,
            limit,
            dates: DateSystem::Epoch1900,
            capped: false,
        }
    }

    pub(crate) fn capped(&self) -> bool {
        self.capped
    }

    pub(crate) fn dates(&self) -> DateSystem {
        self.dates
    }

    pub(crate) fn format(&self) -> Option<Format> {
        match self.root {
            Root::Document(_) => Some(Format::Docx),
            Root::Workbook => Some(Format::Xlsx),
            Root::Presentation => Some(Format::Pptx),
            Root::Pending | Root::Unknown => None,
        }
    }

    fn collect_reference(&mut self, tag: &Tag<'_>, out: Option<&mut Output<'_>>) {
        let mut reference = None;
        let mut sheet_name = None;
        for (name, value) in tag.attributes() {
            match split_prefix(name) {
                (true, local) if hashify::set!(local, b"id") => reference = Some(value),
                (false, local) if hashify::set!(local, b"name") => sheet_name = Some(value),
                _ => {}
            }
        }
        if let (Some(out), Some(sheet_name)) = (out, sheet_name) {
            push_decoded(sheet_name, out);
            out.separator(Separator::Newline);
        }
        if self.ids.len() >= self.limit {
            self.capped = true;
        } else if let Some(id) = reference.and_then(|id| self.arena.push_decoded(id)) {
            self.ids.push(id);
        }
    }
}

impl Handler for MainPart<'_> {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        if let Root::Document(text) = &mut self.root {
            text.start(tag, out);
            return;
        }
        let element = RootElement::parse(tag.local());
        match (&self.root, element) {
            (Root::Pending, Some(RootElement::Document)) => {
                self.root = Root::Document(RunText::default())
            }
            (Root::Pending, Some(RootElement::Workbook)) => self.root = Root::Workbook,
            (Root::Pending, Some(RootElement::Presentation)) => self.root = Root::Presentation,
            (Root::Pending, _) => self.root = Root::Unknown,
            (Root::Workbook, Some(RootElement::Sheet)) => self.collect_reference(tag, Some(out)),
            (Root::Presentation, Some(RootElement::SlideId)) => self.collect_reference(tag, None),
            (Root::Workbook, Some(RootElement::WorkbookProperties)) => {
                self.dates = DateSystem::from_properties(tag);
            }
            _ => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        if let Root::Document(text) = &mut self.root {
            text.end(name, out);
        }
    }

    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        if let Root::Document(handler) = &mut self.root {
            handler.text(text, out);
        }
    }

    fn aborted(&self) -> bool {
        matches!(self.root, Root::Unknown)
    }
}
