/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Format,
    output::{Output, Separator},
    package::{Arena, Span},
    xml::{
        Handler, Skip, Tag,
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
    NoBreakHyphen,
}

impl Run {
    fn parse(local: &[u8]) -> Option<Run> {
        hashify::tiny_map!(local,
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
        )
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
            Some(Run::Tab | Run::Cell) => out.separator(Separator::Space),
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
            Some(Run::Cell) => out.separator(Separator::Space),
            _ => {}
        }
    }

    fn text(&mut self, text: &[u8], out: &mut Output<'_>) {
        if self.in_text {
            out.push_utf8(text);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SheetElement {
    Cell,
    Value,
    InlineText,
    Phonetic,
    Extension,
    Row,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Cell {
    #[default]
    None,
    Value,
    Inline,
    Ignored,
}

#[derive(Default)]
pub(crate) struct SheetText {
    skip: Skip<SheetElement>,
    cell: Cell,
    collect: bool,
}

impl SheetElement {
    fn parse(local: &[u8]) -> Option<SheetElement> {
        hashify::tiny_map!(local,
            b"c" => SheetElement::Cell,
            b"v" => SheetElement::Value,
            b"t" => SheetElement::InlineText,
            b"rPh" => SheetElement::Phonetic,
            b"extLst" => SheetElement::Extension,
            b"row" => SheetElement::Row,
        )
    }
}

fn cell_kind(tag: &Tag<'_>) -> Cell {
    if tag.attrs.is_none() {
        return Cell::Ignored;
    }
    let mut kind = Cell::Value;
    for (name, value) in tag.attributes() {
        if hashify::tiny_set!(name, b"t") {
            kind = hashify::tiny_map!(value,
                b"n" => Cell::Value,
                b"str" => Cell::Value,
                b"d" => Cell::Value,
                b"inlineStr" => Cell::Inline,
            )
            .unwrap_or(Cell::Ignored);
        }
    }
    kind
}

impl Handler for SheetText {
    fn start(&mut self, tag: &Tag<'_>, _out: &mut Output<'_>) {
        let element = SheetElement::parse(tag.local());
        if self.skip.on_start(element) {
            return;
        }
        match element {
            Some(SheetElement::Cell) => self.cell = cell_kind(tag),
            Some(SheetElement::Value) => self.collect = self.cell == Cell::Value,
            Some(SheetElement::InlineText) => self.collect = self.cell == Cell::Inline,
            Some(skipped @ (SheetElement::Phonetic | SheetElement::Extension)) => {
                self.skip.begin(skipped)
            }
            Some(SheetElement::Row) | None => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        let element = SheetElement::parse(local_name(name));
        if self.skip.on_end(element) {
            return;
        }
        match element {
            Some(SheetElement::Value | SheetElement::InlineText) => self.collect = false,
            Some(SheetElement::Cell) => {
                self.cell = Cell::None;
                out.separator(Separator::Space);
            }
            Some(SheetElement::Row) => out.separator(Separator::Newline),
            _ => {}
        }
    }

    fn text(&mut self, text: &[u8], out: &mut Output<'_>) {
        if self.collect {
            out.push_utf8(text);
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
}

impl RootElement {
    fn parse(local: &[u8]) -> Option<RootElement> {
        hashify::tiny_map!(local,
            b"document" => RootElement::Document,
            b"workbook" => RootElement::Workbook,
            b"presentation" => RootElement::Presentation,
            b"sheet" => RootElement::Sheet,
            b"sldId" => RootElement::SlideId,
        )
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
}

impl<'x> MainPart<'x> {
    pub(crate) fn new(arena: &'x mut Arena, ids: &'x mut Vec<Span>, limit: usize) -> Self {
        MainPart {
            root: Root::Pending,
            arena,
            ids,
            limit,
        }
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
                (true, local) if hashify::tiny_set!(local, b"id") => reference = Some(value),
                (false, local) if hashify::tiny_set!(local, b"name") => sheet_name = Some(value),
                _ => {}
            }
        }
        if let (Some(out), Some(sheet_name)) = (out, sheet_name) {
            push_decoded(sheet_name, out);
            out.separator(Separator::Newline);
        }
        if self.ids.len() < self.limit
            && let Some(id) = reference.and_then(|id| self.arena.push_decoded(id))
        {
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
            _ => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        if let Root::Document(text) = &mut self.root {
            text.end(name, out);
        }
    }

    fn text(&mut self, text: &[u8], out: &mut Output<'_>) {
        if let Root::Document(handler) = &mut self.root {
            handler.text(text, out);
        }
    }

    fn aborted(&self) -> bool {
        matches!(self.root, Root::Unknown)
    }
}
