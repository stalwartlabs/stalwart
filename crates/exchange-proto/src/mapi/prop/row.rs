/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::num::NonZeroU16;

use smallvec::SmallVec;

use super::{
    code_page::CodePage,
    codec::{ValueMode, decode_value_in, encode_value, wire_type, write_counted},
    tag::{PropTag, PropType},
    value::{CountWidth, PropValue},
};
use crate::{
    common::{FileTime, Guid, LeReader, LeWriter},
    mapi::{
        ec::ErrorCode,
        emsmdb::MapiLimits,
        rop::{
            RopDecodeError,
            writer::{Overflow, RopWriter},
        },
    },
};

const STANDARD_ROW: u8 = 0x00;
const FLAGGED_ROW: u8 = 0x01;
const CELL_VALUE: u8 = 0x00;
const CELL_ERROR: u8 = 0x0A;
const TABLE_CELL_MAX: usize = 510;
const BOOKMARK_CURRENT: u8 = 0x01;
const TYPE_WORD_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowSetLayout {
    QueryRows { origin: u8 },
    ExpandRow { expanded_count: u32 },
    ReceiveFolderTable,
    FindRow { no_longer_visible: bool },
    Single,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowOptions {
    pub strings: RowStrings,
    pub cell_limit: CellLimit,
    pub code_page: CodePage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStrings {
    Unicode,
    String8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellLimit {
    Table,
    Property { size_limit: Option<NonZeroU16> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Patch {
    None,
    Count16(usize),
    Count32(usize),
    QueryRows { origin_at: usize, count_at: usize },
    HasRowData(usize),
}

pub struct RowSetWriter<'w, 'o> {
    writer: &'w mut RopWriter<'o>,
    patch: Patch,
    options: RowOptions,
    open: Option<usize>,
    kept: u32,
    dropped: bool,
}

impl<'w, 'o> RowSetWriter<'w, 'o> {
    pub(crate) fn begin(
        writer: &'w mut RopWriter<'o>,
        mark: usize,
        layout: RowSetLayout,
        options: RowOptions,
    ) -> Result<Self, Overflow> {
        let out = &mut *writer.out;
        let patch = match layout {
            RowSetLayout::QueryRows { origin } => {
                let origin_at = out.len();
                out.put_u8(origin);
                let count_at = out.len();
                out.put_u16(0);
                Patch::QueryRows {
                    origin_at,
                    count_at,
                }
            }
            RowSetLayout::ExpandRow { expanded_count } => {
                out.put_u32(expanded_count);
                let count_at = out.len();
                out.put_u16(0);
                Patch::Count16(count_at)
            }
            RowSetLayout::ReceiveFolderTable => {
                let count_at = out.len();
                out.put_u32(0);
                Patch::Count32(count_at)
            }
            RowSetLayout::FindRow { no_longer_visible } => {
                out.put_u8(u8::from(no_longer_visible));
                let at = out.len();
                out.put_u8(0);
                Patch::HasRowData(at)
            }
            RowSetLayout::Single => Patch::None,
        };
        if out.len() > writer.limit {
            out.truncate(mark);
            return Err(Overflow);
        }
        Ok(RowSetWriter {
            writer,
            patch,
            options,
            open: None,
            kept: 0,
            dropped: false,
        })
    }

    fn close_open(&mut self) -> Result<(), Overflow> {
        if let Some(start) = self.open.take() {
            if self.writer.out.len() > self.writer.limit {
                self.writer.out.truncate(start);
                self.dropped = true;
                return Err(Overflow);
            }
            self.kept = self.kept.saturating_add(1);
        }
        Ok(())
    }

    pub fn row<'r>(
        &'r mut self,
        columns: &'r [PropTag],
        all_present: bool,
    ) -> Result<RowWriter<'r>, Overflow> {
        if self.dropped {
            return Err(Overflow);
        }
        self.close_open()?;
        let start = self.writer.out.len();
        self.open = Some(start);
        let out = &mut *self.writer.out;
        out.put_u8(if all_present {
            STANDARD_ROW
        } else {
            FLAGGED_ROW
        });
        Ok(RowWriter {
            out,
            limit: self.writer.limit,
            columns,
            next: 0,
            flagged: !all_present,
            row_start: start,
            cells: SmallVec::new(),
            options: self.options,
        })
    }

    pub fn finish(mut self) -> Result<u32, Overflow> {
        let _ = self.close_open();
        let out = &mut *self.writer.out;
        let kept = self.kept;
        match self.patch {
            Patch::None => {}
            Patch::Count16(at) => {
                out.patch_u16(at, u16::try_from(kept).unwrap_or(u16::MAX));
            }
            Patch::Count32(at) => {
                out.patch_u32(at, kept);
            }
            Patch::QueryRows {
                origin_at,
                count_at,
            } => {
                out.patch_u16(count_at, u16::try_from(kept).unwrap_or(u16::MAX));
                if self.dropped
                    && let Some(origin) = out.get_mut(origin_at)
                {
                    *origin = BOOKMARK_CURRENT;
                }
            }
            Patch::HasRowData(at) => {
                if let Some(flag) = out.get_mut(at) {
                    *flag = u8::from(kept > 0);
                }
            }
        }
        if self.dropped && kept == 0 {
            Err(Overflow)
        } else {
            Ok(kept)
        }
    }
}

enum Text<'t> {
    Utf8(&'t str),
    Utf16(&'t [u8]),
    Bytes(&'t [u8]),
}

pub struct RowWriter<'r> {
    out: &'r mut Vec<u8>,
    limit: usize,
    columns: &'r [PropTag],
    next: usize,
    flagged: bool,
    row_start: usize,
    cells: SmallVec<[usize; 32]>,
    options: RowOptions,
}

impl<'r> RowWriter<'r> {
    pub fn standalone(
        out: &'r mut Vec<u8>,
        columns: &'r [PropTag],
        all_present: bool,
        options: RowOptions,
    ) -> Self {
        let row_start = out.len();
        out.put_u8(if all_present {
            STANDARD_ROW
        } else {
            FLAGGED_ROW
        });
        RowWriter {
            out,
            limit: usize::MAX,
            columns,
            next: 0,
            flagged: !all_present,
            row_start,
            cells: SmallVec::new(),
            options,
        }
    }

    fn column(&self) -> PropType {
        self.columns
            .get(self.next)
            .map_or(PropType::Unspecified, |tag| tag.ptype())
    }

    fn open_cell(&mut self, actual: PropType) -> usize {
        let unspecified = self.column() == PropType::Unspecified;
        self.next = self.next.saturating_add(1);
        self.cells.push(self.out.len());
        if unspecified {
            self.out.put_u16(actual.code());
        }
        if self.flagged {
            self.out.put_u8(CELL_VALUE);
        }
        self.out.len()
    }

    fn close_cell(&mut self, value_start: usize) {
        let ErrorCellCheck::Error(code) = self.check(value_start) else {
            return;
        };
        if let Some(cell_start) = self.cells.pop() {
            self.out.truncate(cell_start);
        }
        self.next = self.next.saturating_sub(1);
        self.error(code);
    }

    fn check(&self, value_start: usize) -> ErrorCellCheck {
        match self.options.cell_limit {
            CellLimit::Table => ErrorCellCheck::Fits,
            CellLimit::Property { size_limit } => {
                let size = self.out.len().saturating_sub(value_start);
                let over_limit = size_limit.is_some_and(|limit| size > usize::from(limit.get()));
                if over_limit || self.out.len() > self.limit {
                    ErrorCellCheck::Error(ErrorCode::NOT_ENOUGH_MEMORY)
                } else {
                    ErrorCellCheck::Fits
                }
            }
        }
    }

    fn fixed(&mut self, ptype: PropType, bytes: &[u8]) {
        let start = self.open_cell(ptype);
        self.out.extend_from_slice(bytes);
        self.close_cell(start);
    }

    pub fn i16(&mut self, v: i16) {
        self.fixed(PropType::I16, &v.to_le_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.fixed(PropType::I32, &v.to_le_bytes());
    }

    pub fn i64(&mut self, v: i64) {
        self.fixed(PropType::I64, &v.to_le_bytes());
    }

    pub fn bool(&mut self, v: bool) {
        self.fixed(PropType::Bool, &[u8::from(v)]);
    }

    pub fn f64(&mut self, v: f64) {
        self.fixed(PropType::F64, &v.to_le_bytes());
    }

    pub fn time(&mut self, v: FileTime) {
        self.fixed(PropType::Time, &v.0.to_le_bytes());
    }

    pub fn guid(&mut self, v: &Guid) {
        self.fixed(PropType::Guid, v.as_bytes());
    }

    pub fn binary(&mut self, v: &[u8]) {
        let v = match self.options.cell_limit {
            CellLimit::Table => v.get(..TABLE_CELL_MAX).unwrap_or(v),
            CellLimit::Property { .. } => v,
        };
        let start = self.open_cell(PropType::Binary);
        write_counted(self.out, v, CountWidth::Rop);
        self.close_cell(start);
    }

    pub fn unicode(&mut self, v: &str) {
        self.text(Text::Utf8(v));
    }

    pub fn string8(&mut self, v: &[u8]) {
        self.text(Text::Bytes(v));
    }

    pub fn value(&mut self, v: &PropValue<'_>) {
        match v {
            PropValue::Unicode(s) => self.text(Text::Utf16(s.as_bytes())),
            PropValue::String8(s) => self.text(Text::Bytes(s)),
            PropValue::Binary(b) => self.binary(b),
            PropValue::Error(code) => self.error(*code),
            PropValue::Null => self.missing(),
            other => {
                let start = self.open_cell(other.ptype());
                encode_value(self.out, other, CountWidth::Rop);
                self.close_cell(start);
            }
        }
    }

    pub fn missing(&mut self) {
        self.error(ErrorCode::NOT_FOUND);
    }

    pub fn error(&mut self, code: ErrorCode) {
        if !self.flagged {
            self.restart_flagged();
        }
        let unspecified = self.column() == PropType::Unspecified;
        self.next = self.next.saturating_add(1);
        self.cells.push(self.out.len());
        if unspecified {
            self.out.put_u16(PropType::Error.code());
        }
        self.out.put_u8(CELL_ERROR);
        self.out.put_u32(code.0);
    }

    fn text_target(&self) -> RowStrings {
        match self.column() {
            PropType::String8 => RowStrings::String8,
            PropType::Unicode => RowStrings::Unicode,
            _ => self.options.strings,
        }
    }

    fn text(&mut self, text: Text<'_>) {
        let target = self.text_target();
        let max = match self.options.cell_limit {
            CellLimit::Table => TABLE_CELL_MAX,
            CellLimit::Property { .. } => usize::MAX,
        };
        let start = match target {
            RowStrings::Unicode => self.open_cell(PropType::Unicode),
            RowStrings::String8 => self.open_cell(PropType::String8),
        };
        let code_page = self.options.code_page;
        match target {
            RowStrings::Unicode => write_unicode(self.out, &text, max, code_page),
            RowStrings::String8 => write_string8(self.out, &text, max, code_page),
        }
        self.close_cell(start);
    }

    #[cold]
    #[inline(never)]
    fn restart_flagged(&mut self) {
        let mut end = self.out.len();
        self.out.resize(end.saturating_add(self.cells.len()), 0);
        for (shift, cell_start) in self.cells.iter_mut().enumerate().rev() {
            let start = *cell_start;
            let type_len = if self
                .columns
                .get(shift)
                .is_none_or(|tag| tag.ptype() == PropType::Unspecified)
            {
                TYPE_WORD_LEN.min(end.saturating_sub(start))
            } else {
                0
            };
            let value_start = start.saturating_add(type_len);
            let marker = value_start.saturating_add(shift);
            self.out
                .copy_within(value_start..end, marker.saturating_add(1));
            if let Some(byte) = self.out.get_mut(marker) {
                *byte = CELL_VALUE;
            }
            self.out
                .copy_within(start..value_start, start.saturating_add(shift));
            *cell_start = start.saturating_add(shift);
            end = start;
        }
        if let Some(flag) = self.out.get_mut(self.row_start) {
            *flag = FLAGGED_ROW;
        }
        self.flagged = true;
    }
}

enum ErrorCellCheck {
    Fits,
    Error(ErrorCode),
}

fn write_unicode(out: &mut Vec<u8>, text: &Text<'_>, max: usize, code_page: CodePage) {
    let max_units = max / 2;
    match text {
        Text::Utf8(s) => {
            out.reserve(s.len().min(max_units).saturating_mul(2).saturating_add(2));
            let mut units = 0usize;
            for ch in s.chars() {
                let width = ch.len_utf16();
                if ch == '\0' || units.saturating_add(width) > max_units {
                    break;
                }
                units = units.saturating_add(width);
                let mut buf = [0u16; 2];
                for unit in ch.encode_utf16(&mut buf) {
                    out.put_u16(*unit);
                }
            }
        }
        Text::Utf16(bytes) => {
            let mut taken = 0usize;
            for unit in bytes.as_chunks::<2>().0.iter().take(max_units) {
                let unit = u16::from_le_bytes(*unit);
                if unit == 0 {
                    break;
                }
                taken = taken.saturating_add(1);
                out.put_u16(unit);
            }
            if taken == max_units
                && bytes.len() > max_units.saturating_mul(2)
                && let Some(last) = out.last_chunk::<2>()
                && (0xD800..0xDC00).contains(&u16::from_le_bytes(*last))
            {
                out.truncate(out.len().saturating_sub(2));
            }
        }
        Text::Bytes(bytes) => code_page.widen(bytes, max_units, out),
    }
    out.put_u16(0);
}

fn write_string8(out: &mut Vec<u8>, text: &Text<'_>, max: usize, code_page: CodePage) {
    match text {
        Text::Utf8(s) => code_page.narrow_str(s, max, out),
        Text::Utf16(bytes) => code_page.narrow_utf16(bytes, max, out),
        Text::Bytes(bytes) => {
            out.extend(bytes.iter().take_while(|b| **b != 0).take(max));
        }
    }
    out.put_u8(0);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RowCell<'a> {
    Value(PropValue<'a>),
    Missing,
    Error(ErrorCode),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowValues<'a> {
    bytes: &'a [u8],
    columns: u16,
}

const VALIDATED: MapiLimits = MapiLimits {
    mv_count_max: u32::MAX,
    restriction_depth: u8::MAX,
    ..MapiLimits::DEFAULT
};

impl<'a> RowValues<'a> {
    pub fn decode(
        r: &mut LeReader<'a>,
        columns: &[PropTag],
        limits: &MapiLimits,
    ) -> Result<Self, RopDecodeError> {
        let start = r.remaining();
        let before = r.offset();
        let mut cells = RowCells {
            reader: r.clone(),
            columns: columns.iter(),
            flagged: None,
            limits,
        };
        for cell in &mut cells {
            cell?;
        }
        if cells.flagged.is_none() {
            let offset = cells.reader.offset();
            if !matches!(cells.reader.u8()?, STANDARD_ROW | FLAGGED_ROW) {
                return Err(RopDecodeError::BadValue {
                    offset: RopDecodeError::at(offset),
                });
            }
        }
        *r = cells.reader;
        let len = r.offset().saturating_sub(before);
        Ok(RowValues {
            bytes: start.get(..len).unwrap_or_default(),
            columns: u16::try_from(columns.len()).unwrap_or(u16::MAX),
        })
    }

    pub fn from_encoded(bytes: &'a [u8], columns: u16) -> Self {
        RowValues { bytes, columns }
    }

    pub const fn empty() -> RowValues<'static> {
        RowValues {
            bytes: &[STANDARD_ROW],
            columns: 0,
        }
    }

    pub fn columns(&self) -> u16 {
        self.columns
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn is_flagged(&self) -> bool {
        self.bytes.first() == Some(&FLAGGED_ROW)
    }

    pub fn iter<'c>(
        &self,
        columns: &'c [PropTag],
    ) -> impl Iterator<Item = (PropTag, RowCell<'a>)> + use<'a, 'c> {
        let columns = columns.get(..usize::from(self.columns)).unwrap_or(columns);
        let cells = RowCells {
            reader: LeReader::new(self.bytes),
            columns: columns.iter(),
            flagged: None,
            limits: &VALIDATED,
        };
        columns.iter().copied().zip(cells.map_while(Result::ok))
    }
}

struct RowCells<'a, 'c, 'l> {
    reader: LeReader<'a>,
    columns: std::slice::Iter<'c, PropTag>,
    flagged: Option<bool>,
    limits: &'l MapiLimits,
}

impl<'a> RowCells<'a, '_, '_> {
    fn cell(&mut self, column: PropTag) -> Result<RowCell<'a>, RopDecodeError> {
        let r = &mut self.reader;
        let flagged = match self.flagged {
            Some(flagged) => flagged,
            None => {
                let offset = r.offset();
                let flagged = match r.u8()? {
                    STANDARD_ROW => false,
                    FLAGGED_ROW => true,
                    _ => {
                        return Err(RopDecodeError::BadValue {
                            offset: RopDecodeError::at(offset),
                        });
                    }
                };
                self.flagged = Some(flagged);
                flagged
            }
        };
        let ptype = match column.ptype() {
            PropType::Unspecified => wire_type(r.u16()?),
            _ => wire_type(column.type_code()),
        };
        if flagged {
            let offset = r.offset();
            match r.u8()? {
                CELL_VALUE => {}
                0x01 => return Ok(RowCell::Missing),
                CELL_ERROR => return Ok(RowCell::Error(ErrorCode(r.u32()?))),
                _ => {
                    return Err(RopDecodeError::BadValue {
                        offset: RopDecodeError::at(offset),
                    });
                }
            }
        }
        let depth = self.limits.restriction_depth;
        decode_value_in(r, ptype, ValueMode::Rop, self.limits, depth).map(RowCell::Value)
    }
}

impl<'a> Iterator for RowCells<'a, '_, '_> {
    type Item = Result<RowCell<'a>, RopDecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        let column = *self.columns.next()?;
        Some(self.cell(column))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/row/tests.rs"]
mod tests;
