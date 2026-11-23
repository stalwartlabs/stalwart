/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::VecDeque;

use super::{
    Marker,
    marker::{meta, tags},
};
use crate::{
    common::{FileTime, LeWriter, Utf16Le},
    ics::{FxError, IcsState, IdSet, SyncKind},
    ids::{Cn, Eid, Mid},
    mapi::prop::{
        CodePage, MvView, NamedPropMap, OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag,
        PropType, PropValue,
    },
};

const MERGE_ATOM_LIMIT: usize = 64;
const CODE_PAGE_UTF16: u16 = 1200;
const NAME_KIND_LID: u8 = 0x00;
const NAME_KIND_STRING: u8 = 0x01;
const PROGRESS_INFO_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringMode {
    Unicode,
    String8 { code_page: u16 },
    CodePageTagged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropOutcome {
    Written,
    SkippedUnnamed,
    SkippedType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProgressInformation {
    pub fai_count: u32,
    pub fai_size: u64,
    pub normal_count: u32,
    pub normal_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageChangeHeader<'x> {
    pub source_key: &'x [u8],
    pub last_modified: FileTime,
    pub change_key: &'x [u8],
    pub pcl: &'x [u8],
    pub associated: bool,
    pub mid: Option<Mid>,
    pub size: Option<u32>,
    pub cn: Option<Cn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FxCheckpoint {
    len: usize,
    atoms: usize,
    open: u32,
}

#[derive(Debug, Clone)]
pub struct FxEncoder {
    buf: Vec<u8>,
    base: usize,
    consumed: usize,
    atoms: VecDeque<(usize, usize)>,
    mode: StringMode,
    open: u32,
}

pub struct FxValueSink<'e> {
    encoder: &'e mut FxEncoder,
}

enum StrValue<'v> {
    Utf16(Utf16Le<'v>),
    Utf8(&'v str),
}

impl FxEncoder {
    pub fn new(mode: StringMode) -> Self {
        FxEncoder {
            buf: Vec::new(),
            base: 0,
            consumed: 0,
            atoms: VecDeque::new(),
            mode,
            open: 0,
        }
    }

    pub fn string_mode(&self) -> StringMode {
        self.mode
    }

    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.consumed)
    }

    pub fn is_value_open(&self) -> bool {
        self.open != 0
    }

    pub fn total_written(&self) -> usize {
        self.base.saturating_add(self.buf.len())
    }

    pub fn take(&mut self, budget: usize) -> (&[u8], usize) {
        let start = self.base.saturating_add(self.consumed);
        let end = self.base.saturating_add(self.buf.len());
        let limit = start.saturating_add(budget);
        let cut = if limit >= end {
            end
        } else {
            let index = self
                .atoms
                .partition_point(|&(_, atom_end)| atom_end <= limit);
            match self.atoms.get(index) {
                Some(&(atom_start, _)) if atom_start < limit => atom_start.max(start),
                _ => limit,
            }
        };
        let from = self.consumed;
        let to = cut.saturating_sub(self.base);
        self.consumed = to;
        let taken = to.saturating_sub(from);
        (self.buf.get(from..to).unwrap_or_default(), taken)
    }

    pub fn min_progress(&self) -> usize {
        let start = self.base.saturating_add(self.consumed);
        let index = self
            .atoms
            .partition_point(|&(_, atom_end)| atom_end <= start);
        match self.atoms.get(index) {
            Some(&(atom_start, atom_end)) if atom_start <= start => atom_end.saturating_sub(start),
            _ => self.buffered().min(1),
        }
    }

    pub fn compact(&mut self) {
        if self.consumed == 0 || self.consumed < self.buffered() {
            return;
        }
        self.buf.drain(..self.consumed);
        self.base = self.base.saturating_add(self.consumed);
        self.consumed = 0;
        while self
            .atoms
            .front()
            .is_some_and(|&(_, atom_end)| atom_end <= self.base)
        {
            self.atoms.pop_front();
        }
    }

    pub fn checkpoint(&self) -> FxCheckpoint {
        FxCheckpoint {
            len: self.buf.len(),
            atoms: self.atoms.len(),
            open: self.open,
        }
    }

    pub fn rollback(&mut self, checkpoint: FxCheckpoint) -> bool {
        if checkpoint.len < self.consumed || checkpoint.len > self.buf.len() {
            return false;
        }
        self.buf.truncate(checkpoint.len);
        self.atoms.truncate(checkpoint.atoms);
        let end = self.position();
        if let Some(last) = self.atoms.back_mut() {
            last.1 = last.1.min(end);
        }
        self.open = checkpoint.open;
        true
    }

    fn position(&self) -> usize {
        self.base.saturating_add(self.buf.len())
    }

    fn atom_from(&mut self, start: usize) {
        let end = self.position();
        if end <= start {
            return;
        }
        let consumed_abs = self.base.saturating_add(self.consumed);
        if let Some(last) = self.atoms.back_mut()
            && last.1 == start
            && last.0 >= consumed_abs
            && end.saturating_sub(last.0) <= MERGE_ATOM_LIMIT
        {
            last.1 = end;
            return;
        }
        self.atoms.push_back((start, end));
    }

    fn check_closed(&self) -> Result<(), FxError> {
        if self.open != 0 {
            Err(FxError::ValueOpen)
        } else {
            Ok(())
        }
    }

    pub fn marker(&mut self, m: Marker) -> Result<(), FxError> {
        self.check_closed()?;
        let start = self.position();
        self.buf.put_u32(m.to_wire());
        self.atom_from(start);
        Ok(())
    }

    fn propdef(&mut self, id: PropId, ptype: PropType, key: PropKeyRef<'_>) {
        self.buf.put_u16(ptype.code());
        self.buf.put_u16(id.0);
        if id.is_named() {
            match key {
                PropKeyRef::Lid { set, lid } => {
                    self.buf.put_guid(&set);
                    self.buf.put_u8(NAME_KIND_LID);
                    self.buf.put_u32(lid);
                }
                PropKeyRef::Name { set, name } => {
                    self.buf.put_guid(&set);
                    self.buf.put_u8(NAME_KIND_STRING);
                    self.buf.put_utf16_z(name);
                }
                PropKeyRef::Tag(_) => {}
            }
        }
    }

    fn resolve_tag<'n>(
        tag: PropTag,
        names: &'n dyn NamedPropMap,
    ) -> Option<(PropId, PropKeyRef<'n>)> {
        let id = tag.id();
        if id.is_named() {
            names.key(id).map(|key| (id, key))
        } else {
            Some((id, PropKeyRef::Tag(id)))
        }
    }

    fn resolve_key<'k>(
        key: PropKeyRef<'k>,
        names: &dyn NamedPropMap,
    ) -> Option<(PropId, PropKeyRef<'k>)> {
        match key {
            PropKeyRef::Tag(id) if !id.is_named() => Some((id, key)),
            PropKeyRef::Tag(_) => None,
            named => names.id(named).map(|id| (id, named)),
        }
    }

    pub fn prop(
        &mut self,
        tag: PropTag,
        value: &PropValue<'_>,
        names: &dyn NamedPropMap,
    ) -> Result<PropOutcome, FxError> {
        self.check_closed()?;
        let Some((id, key)) = Self::resolve_tag(tag, names) else {
            return Ok(PropOutcome::SkippedUnnamed);
        };
        if id == meta::IDSET_GIVEN.id()
            && let PropValue::Binary(bytes) = value
        {
            self.var_bytes(id, PropType::I32, key, bytes);
            return Ok(PropOutcome::Written);
        }
        Ok(self.write_borrowed(id, key, value))
    }

    pub fn prop_text(
        &mut self,
        tag: PropTag,
        text: &str,
        names: &dyn NamedPropMap,
    ) -> Result<PropOutcome, FxError> {
        self.check_closed()?;
        let Some((id, key)) = Self::resolve_tag(tag, names) else {
            return Ok(PropOutcome::SkippedUnnamed);
        };
        self.var_unicode(id, key, StrValue::Utf8(text));
        Ok(PropOutcome::Written)
    }

    pub fn prop_owned(
        &mut self,
        key: PropKeyRef<'_>,
        value: &OwnedPropValue,
        names: &dyn NamedPropMap,
    ) -> Result<PropOutcome, FxError> {
        self.check_closed()?;
        let Some((id, key)) = Self::resolve_key(key, names) else {
            return Ok(PropOutcome::SkippedUnnamed);
        };
        Ok(self.write_owned(id, key, value))
    }

    pub fn prop_stream(
        &mut self,
        key: PropKeyRef<'_>,
        ptype: PropType,
        total_len: u32,
        names: &dyn NamedPropMap,
    ) -> Result<FxValueSink<'_>, FxError> {
        self.check_closed()?;
        if !matches!(
            ptype,
            PropType::Binary
                | PropType::Object
                | PropType::String8
                | PropType::Unicode
                | PropType::CodePageString(_)
        ) {
            return Err(FxError::UnsupportedType { offset: 0 });
        }
        let (id, key) = Self::resolve_key(key, names).ok_or(FxError::BadName { offset: 0 })?;
        let start = self.position();
        self.propdef(id, ptype, key);
        self.buf.put_u32(total_len);
        self.atom_from(start);
        self.open = total_len;
        Ok(FxValueSink { encoder: self })
    }

    pub fn resume_value(&mut self) -> Option<FxValueSink<'_>> {
        (self.open != 0).then_some(FxValueSink { encoder: self })
    }

    pub fn idset_prop(&mut self, tag: PropTag, set: &IdSet) -> Result<(), FxError> {
        self.check_closed()?;
        let start = self.position();
        self.buf.put_u16(tag.type_code());
        self.buf.put_u16(tag.id().0);
        let len_at = self.buf.len();
        self.buf.put_u32(0);
        self.atom_from(start);
        let data_start = self.buf.len();
        set.encode(&mut self.buf);
        let len = u32::try_from(self.buf.len().saturating_sub(data_start))
            .map_err(|_| FxError::TooLarge { offset: 0 })?;
        self.buf.patch_u32(len_at, len);
        Ok(())
    }

    fn fixed(&mut self, id: PropId, ptype: PropType, key: PropKeyRef<'_>, bytes: &[u8]) {
        let start = self.position();
        self.propdef(id, ptype, key);
        self.buf.extend_from_slice(bytes);
        self.atom_from(start);
    }

    fn var_bytes(&mut self, id: PropId, ptype: PropType, key: PropKeyRef<'_>, bytes: &[u8]) {
        let start = self.position();
        self.propdef(id, ptype, key);
        self.buf
            .put_u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        self.atom_from(start);
        self.buf.extend_from_slice(bytes);
    }

    fn var_string8(&mut self, id: PropId, ptype: PropType, key: PropKeyRef<'_>, bytes: &[u8]) {
        let start = self.position();
        self.propdef(id, ptype, key);
        self.buf
            .put_u32(u32::try_from(bytes.len().saturating_add(1)).unwrap_or(u32::MAX));
        self.atom_from(start);
        self.buf.extend_from_slice(bytes);
        self.buf.push(0);
    }

    fn string_type(&self) -> PropType {
        match self.mode {
            StringMode::Unicode => PropType::Unicode,
            StringMode::String8 { .. } => PropType::String8,
            StringMode::CodePageTagged => PropType::CodePageString(CODE_PAGE_UTF16),
        }
    }

    fn var_unicode(&mut self, id: PropId, key: PropKeyRef<'_>, value: StrValue<'_>) {
        let ptype = self.string_type();
        let start = self.position();
        self.propdef(id, ptype, key);
        let len_at = self.buf.len();
        self.buf.put_u32(0);
        self.atom_from(start);
        let data_start = self.buf.len();
        self.put_string_body(value);
        let len = u32::try_from(self.buf.len().saturating_sub(data_start)).unwrap_or(u32::MAX);
        self.buf.patch_u32(len_at, len);
    }

    fn put_string_body(&mut self, value: StrValue<'_>) {
        match (self.mode, value) {
            (StringMode::String8 { code_page }, value) => {
                let code_page = CodePage(code_page);
                match value {
                    StrValue::Utf8(text) => code_page.narrow_str(text, usize::MAX, &mut self.buf),
                    StrValue::Utf16(text) => {
                        code_page.narrow_utf16(text.as_bytes(), usize::MAX, &mut self.buf)
                    }
                }
                self.buf.push(0);
            }
            (_, StrValue::Utf16(text)) => {
                self.buf.extend_from_slice(text.as_bytes());
                self.buf.extend_from_slice(&[0, 0]);
            }
            (_, StrValue::Utf8(text)) => self.buf.put_utf16_z(text),
        }
    }

    fn mv_header(&mut self, id: PropId, ptype: PropType, key: PropKeyRef<'_>, count: usize) {
        let start = self.position();
        self.propdef(id, ptype, key);
        self.buf.put_u32(u32::try_from(count).unwrap_or(u32::MAX));
        self.atom_from(start);
    }

    fn mv_fixed<const N: usize>(&mut self, values: impl Iterator<Item = [u8; N]>) {
        for value in values {
            self.mv_fixed_element(&value);
        }
    }

    fn mv_fixed_element(&mut self, bytes: &[u8]) {
        let start = self.position();
        self.buf.extend_from_slice(bytes);
        self.atom_from(start);
    }

    fn mv_binary_element(&mut self, bytes: &[u8]) {
        let start = self.position();
        self.buf
            .put_u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        self.atom_from(start);
        self.buf.extend_from_slice(bytes);
    }

    fn mv_string8_element(&mut self, bytes: &[u8]) {
        let start = self.position();
        self.buf
            .put_u32(u32::try_from(bytes.len().saturating_add(1)).unwrap_or(u32::MAX));
        self.atom_from(start);
        self.buf.extend_from_slice(bytes);
        self.buf.push(0);
    }

    fn mv_string_element(&mut self, value: StrValue<'_>) {
        let start = self.position();
        let len_at = self.buf.len();
        self.buf.put_u32(0);
        self.atom_from(start);
        let data_start = self.buf.len();
        self.put_string_body(value);
        let len = u32::try_from(self.buf.len().saturating_sub(data_start)).unwrap_or(u32::MAX);
        self.buf.patch_u32(len_at, len);
    }

    fn mv_string_type(&self) -> PropType {
        match self.mode {
            StringMode::String8 { .. } => PropType::MvString8,
            StringMode::Unicode | StringMode::CodePageTagged => PropType::MvUnicode,
        }
    }

    fn write_borrowed(
        &mut self,
        id: PropId,
        key: PropKeyRef<'_>,
        value: &PropValue<'_>,
    ) -> PropOutcome {
        match *value {
            PropValue::I16(v) => self.fixed(id, PropType::I16, key, &v.to_le_bytes()),
            PropValue::I32(v) => self.fixed(id, PropType::I32, key, &v.to_le_bytes()),
            PropValue::F32(v) => self.fixed(id, PropType::F32, key, &v.to_le_bytes()),
            PropValue::F64(v) => self.fixed(id, PropType::F64, key, &v.to_le_bytes()),
            PropValue::Currency(v) => self.fixed(id, PropType::Currency, key, &v.to_le_bytes()),
            PropValue::AppTime(v) => self.fixed(id, PropType::AppTime, key, &v.to_le_bytes()),
            PropValue::Bool(v) => self.fixed(id, PropType::Bool, key, &u16::from(v).to_le_bytes()),
            PropValue::I64(v) => self.fixed(id, PropType::I64, key, &v.to_le_bytes()),
            PropValue::Time(v) => self.fixed(id, PropType::Time, key, &v.0.to_le_bytes()),
            PropValue::Guid(v) => self.fixed(id, PropType::Guid, key, v),
            PropValue::String8(v) => self.var_string8(id, PropType::String8, key, v),
            PropValue::Unicode(v) => self.var_unicode(id, key, StrValue::Utf16(v)),
            PropValue::Binary(v) => self.var_bytes(id, PropType::Binary, key, v),
            PropValue::Mv(view) => self.write_mv_view(id, key, view),
            PropValue::Null
            | PropValue::Error(_)
            | PropValue::ServerId(_)
            | PropValue::Restriction(_)
            | PropValue::RuleAction(_)
            | PropValue::Object => return PropOutcome::SkippedType,
        }
        PropOutcome::Written
    }

    fn write_mv_view(&mut self, id: PropId, key: PropKeyRef<'_>, view: MvView<'_>) {
        let ptype = match view.mv_type().prop_type() {
            PropType::MvUnicode => self.mv_string_type(),
            other => other,
        };
        let count = usize::try_from(view.count()).unwrap_or(0);
        self.mv_header(id, ptype, key, count);
        for element in view.iter() {
            match element {
                PropValue::I16(v) => self.mv_fixed_element(&v.to_le_bytes()),
                PropValue::I32(v) => self.mv_fixed_element(&v.to_le_bytes()),
                PropValue::F32(v) => self.mv_fixed_element(&v.to_le_bytes()),
                PropValue::F64(v) | PropValue::AppTime(v) => {
                    self.mv_fixed_element(&v.to_le_bytes())
                }
                PropValue::Currency(v) | PropValue::I64(v) => {
                    self.mv_fixed_element(&v.to_le_bytes())
                }
                PropValue::Time(v) => self.mv_fixed_element(&v.0.to_le_bytes()),
                PropValue::Guid(v) => self.mv_fixed_element(v),
                PropValue::String8(v) => self.mv_string8_element(v),
                PropValue::Unicode(v) => self.mv_string_element(StrValue::Utf16(v)),
                PropValue::Binary(v) => self.mv_binary_element(v),
                _ => self.mv_binary_element(&[]),
            }
        }
    }

    fn write_owned(
        &mut self,
        id: PropId,
        key: PropKeyRef<'_>,
        value: &OwnedPropValue,
    ) -> PropOutcome {
        match value {
            OwnedPropValue::I16(v) => self.fixed(id, PropType::I16, key, &v.to_le_bytes()),
            OwnedPropValue::I32(v) => self.fixed(id, PropType::I32, key, &v.to_le_bytes()),
            OwnedPropValue::F32(v) => self.fixed(id, PropType::F32, key, &v.to_le_bytes()),
            OwnedPropValue::F64(v) => self.fixed(id, PropType::F64, key, &v.to_le_bytes()),
            OwnedPropValue::Currency(v) => {
                self.fixed(id, PropType::Currency, key, &v.to_le_bytes())
            }
            OwnedPropValue::AppTime(v) => self.fixed(id, PropType::AppTime, key, &v.to_le_bytes()),
            OwnedPropValue::Bool(v) => {
                self.fixed(id, PropType::Bool, key, &u16::from(*v).to_le_bytes())
            }
            OwnedPropValue::I64(v) => self.fixed(id, PropType::I64, key, &v.to_le_bytes()),
            OwnedPropValue::Time(v) => self.fixed(id, PropType::Time, key, &v.0.to_le_bytes()),
            OwnedPropValue::Guid(v) => self.fixed(id, PropType::Guid, key, &v.0),
            OwnedPropValue::String8(v) => self.var_string8(id, PropType::String8, key, v),
            OwnedPropValue::Unicode(v) => self.var_unicode(id, key, StrValue::Utf8(v)),
            OwnedPropValue::Binary(v) => self.var_bytes(id, PropType::Binary, key, v),
            OwnedPropValue::MvI16(v) => {
                self.mv_header(id, PropType::MvI16, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvI32(v) => {
                self.mv_header(id, PropType::MvI32, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvF32(v) => {
                self.mv_header(id, PropType::MvF32, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvF64(v) => {
                self.mv_header(id, PropType::MvF64, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvCurrency(v) => {
                self.mv_header(id, PropType::MvCurrency, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvAppTime(v) => {
                self.mv_header(id, PropType::MvAppTime, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvI64(v) => {
                self.mv_header(id, PropType::MvI64, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.to_le_bytes()));
            }
            OwnedPropValue::MvTime(v) => {
                self.mv_header(id, PropType::MvTime, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.0.to_le_bytes()));
            }
            OwnedPropValue::MvGuid(v) => {
                self.mv_header(id, PropType::MvGuid, key, v.len());
                self.mv_fixed(v.iter().map(|x| x.0));
            }
            OwnedPropValue::MvString8(v) => {
                self.mv_header(id, PropType::MvString8, key, v.len());
                for item in v.iter() {
                    self.mv_string8_element(item);
                }
            }
            OwnedPropValue::MvUnicode(v) => {
                let ptype = self.mv_string_type();
                self.mv_header(id, ptype, key, v.len());
                for item in v.iter() {
                    self.mv_string_element(StrValue::Utf8(item));
                }
            }
            OwnedPropValue::MvBinary(v) => {
                self.mv_header(id, PropType::MvBinary, key, v.len());
                for item in v.iter() {
                    self.mv_binary_element(item);
                }
            }
            OwnedPropValue::Null
            | OwnedPropValue::Error(_)
            | OwnedPropValue::ServerId(_)
            | OwnedPropValue::Restriction(_)
            | OwnedPropValue::RuleAction(_)
            | OwnedPropValue::Object => return PropOutcome::SkippedType,
        }
        PropOutcome::Written
    }

    fn tag_prop(&mut self, tag: PropTag, value: &PropValue<'_>) {
        let id = tag.id();
        self.write_borrowed(id, PropKeyRef::Tag(id), value);
    }

    pub fn progress_total(&mut self, info: &ProgressInformation) -> Result<(), FxError> {
        self.marker(Marker::IncrSyncProgressMode)?;
        let mut bytes = Vec::with_capacity(PROGRESS_INFO_LEN);
        bytes.put_u16(0);
        bytes.put_u16(0);
        bytes.put_u32(info.fai_count);
        bytes.put_u64(info.fai_size);
        bytes.put_u32(info.normal_count);
        bytes.put_u32(0);
        bytes.put_u64(info.normal_size);
        self.tag_prop(meta::PROGRESS_INFORMATION, &PropValue::Binary(&bytes));
        Ok(())
    }

    pub fn progress_per_message(&mut self, size: u32, associated: bool) -> Result<(), FxError> {
        self.marker(Marker::IncrSyncProgressPerMsg)?;
        self.tag_prop(
            meta::PROGRESS_MESSAGE_SIZE,
            &PropValue::I32(i32::from_le_bytes(size.to_le_bytes())),
        );
        self.tag_prop(meta::PROGRESS_MESSAGE_FAI, &PropValue::Bool(associated));
        Ok(())
    }

    pub fn message_change_begin(&mut self, h: &MessageChangeHeader<'_>) -> Result<(), FxError> {
        self.marker(Marker::IncrSyncChg)?;
        self.tag_prop(tags::SOURCE_KEY, &PropValue::Binary(h.source_key));
        self.tag_prop(
            tags::LAST_MODIFICATION_TIME,
            &PropValue::Time(h.last_modified),
        );
        self.tag_prop(tags::CHANGE_KEY, &PropValue::Binary(h.change_key));
        self.tag_prop(tags::PREDECESSOR_CHANGE_LIST, &PropValue::Binary(h.pcl));
        self.tag_prop(tags::ASSOCIATED, &PropValue::Bool(h.associated));
        if let Some(mid) = h.mid {
            self.tag_prop(tags::MID, &PropValue::I64(eid_value(mid)));
        }
        if let Some(size) = h.size {
            self.tag_prop(
                tags::MESSAGE_SIZE,
                &PropValue::I32(i32::from_le_bytes(size.to_le_bytes())),
            );
        }
        if let Some(cn) = h.cn {
            self.tag_prop(tags::CHANGE_NUMBER, &PropValue::I64(eid_value(cn)));
        }
        self.marker(Marker::IncrSyncMessage)
    }

    pub fn fx_del_prop(&mut self, subobject: PropTag) -> Result<(), FxError> {
        self.check_closed()?;
        self.tag_prop(
            meta::FX_DEL_PROP,
            &PropValue::I32(i32::from_le_bytes(subobject.0.to_le_bytes())),
        );
        Ok(())
    }

    pub fn folder_change(
        &mut self,
        props: &[(PropKey, OwnedPropValue)],
        names: &dyn NamedPropMap,
    ) -> Result<(), FxError> {
        self.marker(Marker::IncrSyncChg)?;
        for (key, value) in props {
            self.prop_owned(key.as_ref(), value, names)?;
        }
        Ok(())
    }

    pub fn deletions(
        &mut self,
        deleted: &IdSet,
        no_longer_in_scope: Option<&IdSet>,
    ) -> Result<(), FxError> {
        let nlis = no_longer_in_scope.filter(|set| !set.is_empty());
        if deleted.is_empty() && nlis.is_none() {
            return self.check_closed();
        }
        self.marker(Marker::IncrSyncDel)?;
        if !deleted.is_empty() {
            self.idset_prop(meta::IDSET_DELETED, deleted)?;
        }
        if let Some(nlis) = nlis {
            self.idset_prop(meta::IDSET_NO_LONGER_IN_SCOPE, nlis)?;
        }
        Ok(())
    }

    pub fn read_state_changes(&mut self, read: &IdSet, unread: &IdSet) -> Result<(), FxError> {
        if read.is_empty() && unread.is_empty() {
            return self.check_closed();
        }
        self.marker(Marker::IncrSyncRead)?;
        if !read.is_empty() {
            self.idset_prop(meta::IDSET_READ, read)?;
        }
        if !unread.is_empty() {
            self.idset_prop(meta::IDSET_UNREAD, unread)?;
        }
        Ok(())
    }

    pub fn state(&mut self, state: &IcsState, kind: SyncKind) -> Result<(), FxError> {
        self.write_state(state, kind, true)
    }

    pub fn upload_state(&mut self, state: &IcsState, kind: SyncKind) -> Result<(), FxError> {
        self.write_state(state, kind, false)
    }

    fn write_state(
        &mut self,
        state: &IcsState,
        kind: SyncKind,
        given: bool,
    ) -> Result<(), FxError> {
        self.marker(Marker::IncrSyncStateBegin)?;
        if given {
            self.idset_prop(meta::IDSET_GIVEN, &state.given)?;
        }
        self.idset_prop(meta::CNSET_SEEN, &state.seen)?;
        if kind == SyncKind::Contents {
            self.idset_prop(meta::CNSET_SEEN_FAI, &state.seen_fai)?;
            self.idset_prop(meta::CNSET_READ, &state.read)?;
        }
        self.marker(Marker::IncrSyncStateEnd)
    }

    pub fn end(&mut self) -> Result<(), FxError> {
        self.marker(Marker::IncrSyncEnd)
    }
}

impl FxValueSink<'_> {
    pub fn remaining(&self) -> u32 {
        self.encoder.open
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), FxError> {
        let len = u32::try_from(bytes.len()).map_err(|_| FxError::ValueLength)?;
        self.encoder.open = self
            .encoder
            .open
            .checked_sub(len)
            .ok_or(FxError::ValueLength)?;
        self.encoder.buf.extend_from_slice(bytes);
        Ok(())
    }

    pub fn buffered(&self) -> usize {
        self.encoder.buffered()
    }

    pub fn take(&mut self, budget: usize) -> (&[u8], usize) {
        self.encoder.take(budget)
    }

    pub fn compact(&mut self) {
        self.encoder.compact();
    }

    pub fn finish(self) -> Result<(), FxError> {
        if self.encoder.open == 0 {
            Ok(())
        } else {
            Err(FxError::ValueLength)
        }
    }
}

fn eid_value(eid: Eid) -> i64 {
    i64::from_le_bytes(eid.to_le_u64().to_le_bytes())
}
