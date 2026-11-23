/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mapi::{
    ec::ErrorCode,
    prop::{
        CodePage, OwnedPropValue, PropTag, PropType, PropValue,
        codec::{ValueMode, encode_owned_in, encode_value_in, write_count, write_str_utf16},
        value::CountWidth,
    },
};

const HAS: u8 = 0xFF;
const HAS_NOT: u8 = 0x00;
const ROW_STANDARD: u8 = 0x00;
const ROW_FLAGGED: u8 = 0x01;
const CELL_VALUE: u8 = 0x00;
const CELL_MISSING: u8 = 0x01;
const CELL_ERROR: u8 = 0x0A;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AbkCell<'v> {
    Value(PropValue<'v>),
    Owned(&'v OwnedPropValue),
    Missing,
    Error(ErrorCode),
    Text(&'v str),
    Texts(&'v [Box<str>]),
}

impl AbkCell<'_> {
    fn ptype(&self, column: PropTag) -> PropType {
        match self {
            AbkCell::Value(value) => value.ptype(),
            AbkCell::Owned(value) => value.ptype(),
            AbkCell::Missing => PropType::Null,
            AbkCell::Error(_) => PropType::Error,
            AbkCell::Text(_) => text_type(column),
            AbkCell::Texts(_) => multi_text_type(column),
        }
    }

    fn write_value(&self, out: &mut Vec<u8>, column: PropTag, code_page: CodePage) {
        match self {
            AbkCell::Value(value) => encode_value_in(out, value, ValueMode::AddressBook),
            AbkCell::Owned(value) => encode_owned_in(out, value, ValueMode::AddressBook),
            AbkCell::Missing => {}
            AbkCell::Error(code) => out.extend_from_slice(&code.0.to_le_bytes()),
            AbkCell::Text(text) => {
                out.push(HAS);
                write_text(out, text, text_type(column), code_page);
            }
            AbkCell::Texts(texts) => {
                out.push(HAS);
                write_texts(out, texts, text_type(column), code_page);
            }
        }
    }
}

fn text_type(column: PropTag) -> PropType {
    match column.ptype().base() {
        PropType::String8 => PropType::String8,
        _ => PropType::Unicode,
    }
}

fn multi_text_type(column: PropTag) -> PropType {
    match text_type(column) {
        PropType::String8 => PropType::MvString8,
        _ => PropType::MvUnicode,
    }
}

fn write_text(out: &mut Vec<u8>, text: &str, ptype: PropType, code_page: CodePage) {
    if ptype == PropType::String8 {
        code_page.narrow_str(text, usize::MAX, out);
        out.push(0);
    } else {
        write_str_utf16(out, text);
    }
}

fn write_texts(out: &mut Vec<u8>, texts: &[Box<str>], ptype: PropType, code_page: CodePage) {
    write_count(out, texts.len(), CountWidth::Wide);
    for text in texts {
        out.push(HAS);
        write_text(out, text, ptype, code_page);
    }
}

pub(crate) fn write_tags(out: &mut Vec<u8>, tags: &[PropTag]) {
    out.reserve(tags.len().saturating_mul(4).saturating_add(4));
    out.extend_from_slice(&u32::try_from(tags.len()).unwrap_or(u32::MAX).to_le_bytes());
    for tag in tags {
        out.extend_from_slice(&tag.0.to_le_bytes());
    }
}

fn patch_u32(out: &mut [u8], at: usize, value: u32) {
    if let Some(slot) = out.get_mut(at..).and_then(|s| s.first_chunk_mut::<4>()) {
        *slot = value.to_le_bytes();
    }
}

pub struct AbkRowWriter<'o, 'c> {
    out: &'o mut Vec<u8>,
    columns: &'c [PropTag],
    count_at: usize,
    rows: u32,
    max_rows: u32,
    code_page: CodePage,
}

impl<'o, 'c> AbkRowWriter<'o, 'c> {
    pub fn begin(out: &'o mut Vec<u8>, columns: &'c [PropTag], max_rows: u32) -> Self {
        out.push(HAS);
        write_tags(out, columns);
        let count_at = out.len();
        out.extend_from_slice(&[0; 4]);
        AbkRowWriter {
            out,
            columns,
            count_at,
            rows: 0,
            max_rows,
            code_page: CodePage::WINDOWS_1252,
        }
    }

    pub fn with_code_page(mut self, code_page: CodePage) -> Self {
        self.code_page = code_page;
        self
    }

    pub fn absent(out: &mut Vec<u8>) {
        out.push(HAS_NOT);
    }

    pub fn row(&mut self, cells: &[AbkCell<'_>]) -> bool {
        if self.rows >= self.max_rows || cells.len() != self.columns.len() {
            return false;
        }
        let flagged = cells
            .iter()
            .any(|cell| matches!(cell, AbkCell::Missing | AbkCell::Error(_)));
        self.out
            .push(if flagged { ROW_FLAGGED } else { ROW_STANDARD });
        for (column, cell) in self.columns.iter().zip(cells) {
            if column.ptype() == PropType::Unspecified {
                self.out
                    .extend_from_slice(&cell.ptype(*column).code().to_le_bytes());
            }
            if flagged {
                self.out.push(match cell {
                    AbkCell::Missing => CELL_MISSING,
                    AbkCell::Error(_) => CELL_ERROR,
                    AbkCell::Value(_)
                    | AbkCell::Owned(_)
                    | AbkCell::Text(_)
                    | AbkCell::Texts(_) => CELL_VALUE,
                });
            }
            cell.write_value(self.out, *column, self.code_page);
        }
        self.rows = self.rows.saturating_add(1);
        true
    }

    pub fn rows(&self) -> u32 {
        self.rows
    }

    pub fn output_len(&self) -> usize {
        self.out.len()
    }

    pub fn finish(self) -> u32 {
        patch_u32(self.out, self.count_at, self.rows);
        self.rows
    }
}

pub struct AbkListWriter<'o> {
    out: &'o mut Vec<u8>,
    count_at: usize,
    count: u32,
}

impl<'o> AbkListWriter<'o> {
    pub fn begin(out: &'o mut Vec<u8>) -> Self {
        let count_at = out.len();
        out.extend_from_slice(&[0; 4]);
        AbkListWriter {
            out,
            count_at,
            count: 0,
        }
    }

    pub fn value(&mut self, tag: PropTag, value: &PropValue<'_>) {
        self.out.extend_from_slice(&tag.0.to_le_bytes());
        encode_value_in(self.out, value, ValueMode::AddressBook);
        self.count = self.count.saturating_add(1);
    }

    pub fn owned(&mut self, tag: PropTag, value: &OwnedPropValue) {
        self.out.extend_from_slice(&tag.0.to_le_bytes());
        encode_owned_in(self.out, value, ValueMode::AddressBook);
        self.count = self.count.saturating_add(1);
    }

    pub fn text(&mut self, tag: PropTag, text: &str, code_page: CodePage) {
        let ptype = text_type(tag);
        self.out
            .extend_from_slice(&tag.with_type(ptype).0.to_le_bytes());
        self.out.push(HAS);
        write_text(self.out, text, ptype, code_page);
        self.count = self.count.saturating_add(1);
    }

    pub fn texts(&mut self, tag: PropTag, texts: &[Box<str>], code_page: CodePage) {
        let ptype = text_type(tag);
        self.out
            .extend_from_slice(&tag.with_type(multi_text_type(tag)).0.to_le_bytes());
        self.out.push(HAS);
        write_texts(self.out, texts, ptype, code_page);
        self.count = self.count.saturating_add(1);
    }

    pub fn finish(self) -> u32 {
        patch_u32(self.out, self.count_at, self.count);
        self.count
    }
}
