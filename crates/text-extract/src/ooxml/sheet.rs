/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    number::{
        DateSystem, NumberFormat, ValueBuffer, push_boolean, push_exact, push_integer, push_number,
    },
    styles::parse_index,
};
use crate::{
    output::{Output, Separator},
    xml::{Handler, Skip, Tag, Text, local_name},
};
use memchr::memchr;

const COLOR_CODE_LEN: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SheetElement {
    Cell,
    Value,
    InlineText,
    Phonetic,
    Extension,
    Row,
    HeaderFooter,
}

impl SheetElement {
    #[inline]
    fn parse(local: &[u8]) -> Option<SheetElement> {
        hashify::map!(local, SheetElement,
            b"c" => SheetElement::Cell,
            b"v" => SheetElement::Value,
            b"t" => SheetElement::InlineText,
            b"rPh" => SheetElement::Phonetic,
            b"extLst" => SheetElement::Extension,
            b"row" => SheetElement::Row,
            b"headerFooter" => SheetElement::HeaderFooter,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Cell {
    #[default]
    None,
    Raw,
    Number(NumberFormat),
    Boolean,
    Inline,
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Collect {
    #[default]
    Nothing,
    Raw,
    Buffered,
    HeaderFooter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Code {
    #[default]
    Text,
    Ampersand,
    FontName,
    FontSize,
    Color(u8),
}

pub(crate) struct SheetText<'x> {
    formats: &'x [NumberFormat],
    dates: DateSystem,
    skip: Skip<SheetElement>,
    cell: Cell,
    collect: Collect,
    value: ValueBuffer,
    code: Code,
    header_footer: bool,
}

impl<'x> SheetText<'x> {
    pub(crate) fn new(formats: &'x [NumberFormat], dates: DateSystem) -> Self {
        let styled = formats
            .iter()
            .any(|&format| format != NumberFormat::General);
        SheetText {
            formats: if styled { formats } else { &[] },
            dates,
            skip: Skip::default(),
            cell: Cell::None,
            collect: Collect::Nothing,
            value: ValueBuffer::default(),
            code: Code::Text,
            header_footer: false,
        }
    }

    fn cell_kind(&self, tag: &Tag<'_>) -> Cell {
        if tag.attrs.is_none() {
            return Cell::Ignored;
        }
        let mut kind = Cell::Number(NumberFormat::General);
        let mut style = None;
        for (name, value) in tag.attributes() {
            match name {
                [b't'] => {
                    kind = hashify::map!(value, Cell,
                        b"n" => Cell::Number(NumberFormat::General),
                        b"str" => Cell::Raw,
                        b"d" => Cell::Raw,
                        b"b" => Cell::Boolean,
                        b"inlineStr" => Cell::Inline,
                    )
                    .copied()
                    .unwrap_or(Cell::Ignored);
                }
                [b's'] => style = Some(value),
                _ => {}
            }
        }
        match (kind, style) {
            (Cell::Number(_), Some(style)) if !self.formats.is_empty() => {
                Cell::Number(self.format_of(style))
            }
            (other, _) => other,
        }
    }

    fn format_of(&self, style: &[u8]) -> NumberFormat {
        let index = match style {
            [digit @ b'0'..=b'9'] => Some(u32::from(digit - b'0')),
            _ => parse_index(style),
        };
        index
            .and_then(|index| self.formats.get(usize::try_from(index).ok()?))
            .copied()
            .unwrap_or_default()
    }

    fn flush_value(&mut self, out: &mut Output<'_>) {
        let raw = self.value.value();
        match self.cell {
            Cell::Number(format) => push_number(raw, format, self.dates, out),
            Cell::Boolean => push_boolean(raw, out),
            _ => out.push_utf8(raw),
        }
        self.value.clear();
    }

    fn header_footer(&mut self, mut text: &[u8], out: &mut Output<'_>) {
        while !text.is_empty() {
            match self.code {
                Code::Text => {
                    let end = memchr(b'&', text).unwrap_or(text.len());
                    let (plain, rest) = text.split_at(end);
                    out.push_utf8(plain);
                    if !rest.is_empty() {
                        self.code = Code::Ampersand;
                    }
                    text = rest.get(1..).unwrap_or_default();
                }
                Code::Ampersand => {
                    let Some((&byte, rest)) = text.split_first() else {
                        return;
                    };
                    self.code = match byte {
                        b'&' => {
                            out.push_str("&");
                            Code::Text
                        }
                        b'"' => Code::FontName,
                        b'0'..=b'9' => Code::FontSize,
                        b'K' => Code::Color(COLOR_CODE_LEN),
                        b'L' | b'C' | b'R' | b'P' | b'N' | b'D' | b'T' | b'A' | b'F' | b'Z'
                        | b'G' => {
                            out.separator(Separator::Space);
                            Code::Text
                        }
                        _ => Code::Text,
                    };
                    text = rest;
                }
                Code::FontName => match memchr(b'"', text) {
                    Some(end) => {
                        self.code = Code::Text;
                        text = text.get(end + 1..).unwrap_or_default();
                    }
                    None => return,
                },
                Code::FontSize => {
                    let digits = text
                        .iter()
                        .position(|byte| !byte.is_ascii_digit())
                        .unwrap_or(text.len());
                    if digits < text.len() {
                        self.code = Code::Text;
                    }
                    text = text.get(digits..).unwrap_or_default();
                }
                Code::Color(remaining) => {
                    let skipped = usize::from(remaining).min(text.len());
                    let left = remaining.saturating_sub(u8::try_from(skipped).unwrap_or(u8::MAX));
                    self.code = if left == 0 {
                        Code::Text
                    } else {
                        Code::Color(left)
                    };
                    text = text.get(skipped..).unwrap_or_default();
                }
            }
        }
    }
}

impl Handler for SheetText<'_> {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        let element = SheetElement::parse(tag.local());
        if self.skip.on_start(element) {
            return;
        }
        if self.header_footer {
            out.separator(Separator::Newline);
            self.code = Code::Text;
            self.collect = Collect::HeaderFooter;
            return;
        }
        match element {
            Some(SheetElement::Cell) => self.cell = self.cell_kind(tag),
            Some(SheetElement::Value) => {
                self.collect = match self.cell {
                    Cell::Raw => Collect::Raw,
                    Cell::Number(_) | Cell::Boolean => {
                        self.value.clear();
                        Collect::Buffered
                    }
                    _ => Collect::Nothing,
                }
            }
            Some(SheetElement::InlineText) => {
                self.collect = if self.cell == Cell::Inline {
                    Collect::Raw
                } else {
                    Collect::Nothing
                }
            }
            Some(SheetElement::HeaderFooter) => self.header_footer = true,
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
        if self.header_footer {
            self.header_footer = element != Some(SheetElement::HeaderFooter);
            self.collect = Collect::Nothing;
            out.separator(Separator::Newline);
            return;
        }
        match element {
            Some(SheetElement::Value) => {
                if self.collect == Collect::Buffered {
                    self.flush_value(out);
                }
                self.collect = Collect::Nothing;
            }
            Some(SheetElement::InlineText) => self.collect = Collect::Nothing,
            Some(SheetElement::Cell) => {
                self.cell = Cell::None;
                out.separator(Separator::Space);
            }
            Some(SheetElement::Row) => {
                self.collect = Collect::Nothing;
                out.separator(Separator::Newline);
            }
            _ => {}
        }
    }

    #[inline]
    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        match self.collect {
            Collect::Nothing => {}
            Collect::Raw => text.push(out),
            Collect::Buffered => {
                if let Cell::Number(format) = self.cell
                    && text.is_closed_by_tag()
                    && self.value.is_empty()
                    && (push_integer(text, format, out) || push_exact(text, format, out))
                {
                    self.collect = Collect::Raw;
                } else if !self.value.push(text.as_bytes(), out) {
                    self.collect = Collect::Raw;
                }
            }
            Collect::HeaderFooter => self.header_footer(text.as_bytes(), out),
        }
    }
}
