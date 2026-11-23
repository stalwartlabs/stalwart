/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use super::{Marker, marker::meta};
use crate::{
    common::{FileTime, Guid, Utf16Le},
    ics::{FxError, IcsLimits},
    mapi::{
        ec::ErrorCode,
        prop::{MvDialect, MvError, MvType, MvView, PropId, PropKeyRef, PropType, PropValue, sets},
    },
};

const ATOM_MAX: usize = 17;
const NAME_HEADER_LEN: usize = 17;
const CODE_PAGE_UTF16: u16 = 1200;
const NAME_KIND_LID: u8 = 0x00;
const NAME_KIND_STRING: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FxEvent<'c> {
    Marker(Marker),
    Prop {
        key: PropKeyRef<'c>,
        ptype: PropType,
        value: PropValue<'c>,
    },
    ValueStart {
        key: PropKeyRef<'c>,
        ptype: PropType,
        total_len: u32,
    },
    ValueChunk(&'c [u8]),
    ValueEnd,
    MvStart {
        key: PropKeyRef<'c>,
        mv_type: MvType,
        count: u32,
    },
    Element(PropValue<'c>),
    ElementStart {
        total_len: u32,
    },
    MvEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Tag,
    NameHeader,
    NameLid,
    NameChars,
    Fixed,
    VarLength,
    VarData,
    VarTerm,
    ValueEnd,
    MvCount,
    MvNext,
    MvFixed,
    MvLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    Tag(PropId),
    Lid { set: Guid, lid: u32 },
    Name { set: Guid },
}

#[derive(Debug, Clone, Copy)]
struct VarState {
    remaining: u32,
    term: u8,
    element: bool,
}

#[derive(Debug, Clone)]
pub struct FxDecoder {
    limits: IcsLimits,
    stage: Stage,
    key: KeyState,
    ptype: PropType,
    name_set: Guid,
    carry: SmallVec<[u8; ATOM_MAX]>,
    atom: [u8; ATOM_MAX],
    units: Vec<u16>,
    scratch: String,
    stack: SmallVec<[Marker; 16]>,
    embed_depth: u8,
    mv_type: MvType,
    mv_remaining: u32,
    var: VarState,
    offset: u64,
    failed: Option<FxError>,
}

pub struct FxEvents<'c> {
    dec: &'c mut FxDecoder,
    input: &'c [u8],
}

enum Raw<'c> {
    Marker(Marker),
    Fixed,
    Var(&'c [u8]),
    Mv(MvView<'c>),
    ValueStart(u32),
    Chunk(&'c [u8]),
    TermChunk(usize),
    ValueEnd,
    MvStart(u32),
    ElementFixed,
    ElementVar(&'c [u8]),
    ElementStart(u32),
    MvEnd,
}

impl FxDecoder {
    pub fn new(limits: &IcsLimits) -> Self {
        FxDecoder {
            limits: *limits,
            stage: Stage::Tag,
            key: KeyState::Tag(PropId(0)),
            ptype: PropType::Null,
            name_set: Guid::NIL,
            carry: SmallVec::new(),
            atom: [0; ATOM_MAX],
            units: Vec::new(),
            scratch: String::new(),
            stack: SmallVec::new(),
            embed_depth: 0,
            mv_type: MvType::I32,
            mv_remaining: 0,
            var: VarState {
                remaining: 0,
                term: 0,
                element: false,
            },
            offset: 0,
            failed: None,
        }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    pub fn feed<'c>(&'c mut self, chunk: &'c [u8]) -> FxEvents<'c> {
        FxEvents {
            dec: self,
            input: chunk,
        }
    }

    pub fn finish(self) -> Result<(), FxError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        let offset = self.offset_u32();
        if self.stage != Stage::Tag || !self.carry.is_empty() {
            return Err(FxError::Truncated { offset });
        }
        if !self.stack.is_empty() {
            return Err(FxError::Grammar { offset });
        }
        Ok(())
    }

    fn offset_u32(&self) -> u32 {
        u32::try_from(self.offset).unwrap_or(u32::MAX)
    }

    fn key_ref(&self) -> PropKeyRef<'_> {
        match self.key {
            KeyState::Tag(id) => PropKeyRef::Tag(id),
            KeyState::Lid { set, lid } => PropKeyRef::Lid { set, lid },
            KeyState::Name { set } => PropKeyRef::Name {
                set,
                name: &self.scratch,
            },
        }
    }

    fn fixed_value(&self, ptype: PropType) -> PropValue<'_> {
        let atom = &self.atom;
        let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = *atom;
        let u16v = [b0, b1];
        let u32v = [b0, b1, b2, b3];
        let u64v = [b0, b1, b2, b3, b4, b5, b6, b7];
        match ptype {
            PropType::I16 => PropValue::I16(i16::from_le_bytes(u16v)),
            PropType::Bool => PropValue::Bool(u16::from_le_bytes(u16v) != 0),
            PropType::I32 => PropValue::I32(i32::from_le_bytes(u32v)),
            PropType::F32 => PropValue::F32(f32::from_le_bytes(u32v)),
            PropType::Error => PropValue::Error(ErrorCode(u32::from_le_bytes(u32v))),
            PropType::F64 => PropValue::F64(f64::from_le_bytes(u64v)),
            PropType::Currency => PropValue::Currency(i64::from_le_bytes(u64v)),
            PropType::AppTime => PropValue::AppTime(f64::from_le_bytes(u64v)),
            PropType::I64 => PropValue::I64(i64::from_le_bytes(u64v)),
            PropType::Time => PropValue::Time(FileTime(u64::from_le_bytes(u64v))),
            PropType::Guid => match atom.first_chunk::<16>() {
                Some(guid) => PropValue::Guid(guid),
                None => PropValue::Null,
            },
            _ => PropValue::Null,
        }
    }

    fn build<'s>(&'s self, raw: Raw<'s>) -> FxEvent<'s> {
        match raw {
            Raw::Marker(m) => FxEvent::Marker(m),
            Raw::Fixed => FxEvent::Prop {
                key: self.key_ref(),
                ptype: self.ptype,
                value: self.fixed_value(self.ptype),
            },
            Raw::Var(bytes) => FxEvent::Prop {
                key: self.key_ref(),
                ptype: self.ptype,
                value: var_value(self.ptype, bytes).unwrap_or(PropValue::Null),
            },
            Raw::Mv(view) => FxEvent::Prop {
                key: self.key_ref(),
                ptype: self.ptype,
                value: PropValue::Mv(view),
            },
            Raw::ValueStart(total_len) => FxEvent::ValueStart {
                key: self.key_ref(),
                ptype: self.ptype,
                total_len,
            },
            Raw::Chunk(bytes) => FxEvent::ValueChunk(bytes),
            Raw::TermChunk(len) => FxEvent::ValueChunk(self.atom.get(..len).unwrap_or_default()),
            Raw::ValueEnd => FxEvent::ValueEnd,
            Raw::MvStart(count) => FxEvent::MvStart {
                key: self.key_ref(),
                mv_type: self.mv_type,
                count,
            },
            Raw::ElementFixed => FxEvent::Element(self.fixed_value(self.mv_type.element_type())),
            Raw::ElementVar(bytes) => FxEvent::Element(
                var_value(self.mv_type.element_type(), bytes).unwrap_or(PropValue::Null),
            ),
            Raw::ElementStart(total_len) => FxEvent::ElementStart { total_len },
            Raw::MvEnd => FxEvent::MvEnd,
        }
    }

    fn on_marker(&mut self, m: Marker) -> Result<(), FxError> {
        let offset = self.offset_u32();
        let top = self.stack.last().copied();
        if is_end_marker(m) {
            match top {
                Some(open) if open.closes() == Some(m) => {
                    self.stack.pop();
                    if open == Marker::StartEmbed {
                        self.embed_depth = self.embed_depth.saturating_sub(1);
                    }
                    return Ok(());
                }
                _ => return Err(FxError::Grammar { offset }),
            }
        }
        let allowed = match m {
            Marker::StartTopFld => top.is_none(),
            Marker::StartSubFld
            | Marker::StartMessage
            | Marker::StartFaiMsg
            | Marker::FxErrorInfo => matches!(
                top,
                None | Some(Marker::StartTopFld) | Some(Marker::StartSubFld)
            ),
            Marker::StartRecip | Marker::NewAttach => matches!(
                top,
                None | Some(Marker::StartMessage)
                    | Some(Marker::StartFaiMsg)
                    | Some(Marker::StartEmbed)
            ),
            Marker::StartEmbed => matches!(top, None | Some(Marker::NewAttach)),
            _ => top.is_none(),
        };
        if !allowed {
            return Err(FxError::Grammar { offset });
        }
        if m.closes().is_some() {
            if self.stack.len() >= usize::from(self.limits.max_depth) {
                return Err(FxError::TooDeep { offset });
            }
            if m == Marker::StartEmbed {
                if self.embed_depth >= self.limits.max_embed_depth {
                    return Err(FxError::TooDeep { offset });
                }
                self.embed_depth = self.embed_depth.saturating_add(1);
            }
            self.stack.push(m);
        }
        Ok(())
    }

    fn dispatch(&mut self) -> Result<(), FxError> {
        let offset = self.offset_u32();
        if matches!(self.key, KeyState::Tag(id) if id == meta::IDSET_GIVEN.id()) {
            self.ptype = PropType::Binary;
            self.stage = Stage::VarLength;
            return Ok(());
        }
        self.stage = match self.ptype {
            PropType::I16
            | PropType::I32
            | PropType::F32
            | PropType::F64
            | PropType::Currency
            | PropType::AppTime
            | PropType::Error
            | PropType::Bool
            | PropType::I64
            | PropType::Time
            | PropType::Guid => Stage::Fixed,
            PropType::String8
            | PropType::Unicode
            | PropType::Binary
            | PropType::ServerId
            | PropType::Object
            | PropType::CodePageString(_) => Stage::VarLength,
            other => match other.mv_type() {
                Some(mv_type) => {
                    self.mv_type = mv_type;
                    Stage::MvCount
                }
                None => return Err(FxError::UnsupportedType { offset }),
            },
        };
        Ok(())
    }

    fn finish_name(&mut self) {
        self.scratch.clear();
        self.scratch.extend(
            char::decode_utf16(self.units.iter().copied())
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)),
        );
        if self.name_set == sets::PS_INTERNET_HEADERS {
            self.scratch.make_ascii_lowercase();
        }
        self.key = KeyState::Name { set: self.name_set };
    }

    fn check_var_len(&self, len: u32, ptype: PropType) -> Result<(), FxError> {
        let offset = self.offset_u32();
        if len > self.limits.max_value_len {
            return Err(FxError::TooLarge { offset });
        }
        if is_utf16(ptype) && !len.is_multiple_of(2) {
            return Err(FxError::BadValue { offset });
        }
        Ok(())
    }

    fn check_mv_count(&self, count: u32) -> Result<(), FxError> {
        let offset = self.offset_u32();
        if count > self.limits.max_mv_count {
            return Err(FxError::TooLarge { offset });
        }
        if let Some(size) = self.mv_type.element_type().fixed_size().map(fx_fixed_size)
            && u64::from(count).saturating_mul(size) > u64::from(self.limits.max_mv_fixed_bytes)
        {
            return Err(FxError::TooLarge { offset });
        }
        Ok(())
    }

    fn start_var(&mut self, len: u32, ptype: PropType, element: bool) -> Stage {
        let term = terminator_len(ptype);
        let (remaining, term) = if len >= u32::from(term) {
            (len.saturating_sub(u32::from(term)), term)
        } else {
            (len, 0)
        };
        self.var = VarState {
            remaining,
            term,
            element,
        };
        Stage::VarData
    }
}

impl<'c> FxEvents<'c> {
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<FxEvent<'_>>, FxError> {
        if let Some(err) = self.dec.failed {
            return Err(err);
        }
        match self.step() {
            Ok(Some(raw)) => Ok(Some(self.dec.build(raw))),
            Ok(None) => Ok(None),
            Err(err) => {
                self.dec.failed = Some(err);
                Err(err)
            }
        }
    }

    pub fn remaining(&self) -> usize {
        self.input.len()
    }

    fn advance(&mut self, n: usize) -> &'c [u8] {
        let (head, rest) = self.input.split_at_checked(n).unwrap_or((self.input, &[]));
        self.input = rest;
        self.dec.offset = self
            .dec
            .offset
            .saturating_add(u64::try_from(head.len()).unwrap_or(u64::MAX));
        head
    }

    fn fill(&mut self, n: usize) -> bool {
        let have = self.dec.carry.len();
        if have == 0 {
            if self.input.len() >= n {
                let head = self.advance(n);
                if let Some(dest) = self.dec.atom.get_mut(..n) {
                    dest.copy_from_slice(head);
                }
                return true;
            }
            let rest = self.advance(self.input.len());
            self.dec.carry.extend_from_slice(rest);
            return false;
        }
        let need = n.saturating_sub(have).min(self.input.len());
        let head = self.advance(need);
        self.dec.carry.extend_from_slice(head);
        if self.dec.carry.len() < n {
            return false;
        }
        if let Some(dest) = self.dec.atom.get_mut(..n) {
            dest.copy_from_slice(&self.dec.carry);
        }
        self.dec.carry.clear();
        true
    }

    fn atom_u32(&self) -> u32 {
        let [b0, b1, b2, b3, ..] = self.dec.atom;
        u32::from_le_bytes([b0, b1, b2, b3])
    }

    fn step(&mut self) -> Result<Option<Raw<'c>>, FxError> {
        loop {
            let offset = self.dec.offset_u32();
            match self.dec.stage {
                Stage::Tag => {
                    if !self.fill(4) {
                        return Ok(None);
                    }
                    let value = self.atom_u32();
                    if let Ok(marker) = Marker::try_from(value) {
                        self.dec.on_marker(marker)?;
                        return Ok(Some(Raw::Marker(marker)));
                    }
                    let [t0, t1, i0, i1] = value.to_le_bytes();
                    self.dec.ptype = PropType::from_code(u16::from_le_bytes([t0, t1]));
                    let id = PropId(u16::from_le_bytes([i0, i1]));
                    if id.is_named() {
                        self.dec.stage = Stage::NameHeader;
                    } else {
                        self.dec.key = KeyState::Tag(id);
                        self.dec.dispatch()?;
                    }
                }
                Stage::NameHeader => {
                    if !self.fill(NAME_HEADER_LEN) {
                        return Ok(None);
                    }
                    let (set, kind) = match self.dec.atom.split_first_chunk::<16>() {
                        Some((set, [kind, ..])) => (Guid(*set), *kind),
                        _ => return Err(FxError::BadName { offset }),
                    };
                    self.dec.name_set = set;
                    match kind {
                        NAME_KIND_LID => self.dec.stage = Stage::NameLid,
                        NAME_KIND_STRING => {
                            self.dec.units.clear();
                            self.dec.stage = Stage::NameChars;
                        }
                        _ => return Err(FxError::BadName { offset }),
                    }
                }
                Stage::NameLid => {
                    if !self.fill(4) {
                        return Ok(None);
                    }
                    self.dec.key = KeyState::Lid {
                        set: self.dec.name_set,
                        lid: self.atom_u32(),
                    };
                    self.dec.dispatch()?;
                }
                Stage::NameChars => {
                    if !self.read_name()? {
                        return Ok(None);
                    }
                    self.dec.finish_name();
                    self.dec.dispatch()?;
                }
                Stage::Fixed => {
                    let size = self.dec.ptype.fixed_size().map(fx_fixed_size).unwrap_or(0);
                    if !self.fill(usize::try_from(size).unwrap_or(0)) {
                        return Ok(None);
                    }
                    self.dec.stage = Stage::Tag;
                    return Ok(Some(Raw::Fixed));
                }
                Stage::VarLength => {
                    if !self.fill(4) {
                        return Ok(None);
                    }
                    let len = self.atom_u32();
                    self.dec.check_var_len(len, self.dec.ptype)?;
                    let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
                    if self.input.len() >= len_usize {
                        let bytes = self.advance(len_usize);
                        self.dec.stage = Stage::Tag;
                        return Ok(Some(Raw::Var(bytes)));
                    }
                    self.dec.stage = self.dec.start_var(len, self.dec.ptype, false);
                    return Ok(Some(Raw::ValueStart(len)));
                }
                Stage::VarData => {
                    if self.dec.var.remaining == 0 {
                        self.dec.stage = if self.dec.var.term == 0 {
                            Stage::ValueEnd
                        } else {
                            Stage::VarTerm
                        };
                        continue;
                    }
                    if self.input.is_empty() {
                        return Ok(None);
                    }
                    let n = usize::try_from(self.dec.var.remaining)
                        .unwrap_or(usize::MAX)
                        .min(self.input.len());
                    let chunk = self.advance(n);
                    self.dec.var.remaining = self
                        .dec
                        .var
                        .remaining
                        .saturating_sub(u32::try_from(n).unwrap_or(u32::MAX));
                    return Ok(Some(Raw::Chunk(chunk)));
                }
                Stage::VarTerm => {
                    let term = usize::from(self.dec.var.term);
                    if !self.fill(term) {
                        return Ok(None);
                    }
                    self.dec.stage = Stage::ValueEnd;
                    if self
                        .dec
                        .atom
                        .get(..term)
                        .is_some_and(|bytes| bytes.iter().any(|b| *b != 0))
                    {
                        return Ok(Some(Raw::TermChunk(term)));
                    }
                }
                Stage::ValueEnd => {
                    self.dec.stage = if self.dec.var.element {
                        Stage::MvNext
                    } else {
                        Stage::Tag
                    };
                    return Ok(Some(Raw::ValueEnd));
                }
                Stage::MvCount => {
                    if self.dec.carry.is_empty()
                        && let Some(raw) = self.try_whole_mv()?
                    {
                        return Ok(Some(raw));
                    }
                    if !self.fill(4) {
                        return Ok(None);
                    }
                    let count = self.atom_u32();
                    self.dec.check_mv_count(count)?;
                    self.dec.mv_remaining = count;
                    self.dec.stage = Stage::MvNext;
                    return Ok(Some(Raw::MvStart(count)));
                }
                Stage::MvNext => {
                    if self.dec.mv_remaining == 0 {
                        self.dec.stage = Stage::Tag;
                        return Ok(Some(Raw::MvEnd));
                    }
                    self.dec.mv_remaining = self.dec.mv_remaining.saturating_sub(1);
                    self.dec.stage = if self.dec.mv_type.element_type().fixed_size().is_some() {
                        Stage::MvFixed
                    } else {
                        Stage::MvLength
                    };
                }
                Stage::MvFixed => {
                    let size = self
                        .dec
                        .mv_type
                        .element_type()
                        .fixed_size()
                        .map(fx_fixed_size)
                        .unwrap_or(0);
                    if !self.fill(usize::try_from(size).unwrap_or(0)) {
                        return Ok(None);
                    }
                    self.dec.stage = Stage::MvNext;
                    return Ok(Some(Raw::ElementFixed));
                }
                Stage::MvLength => {
                    if !self.fill(4) {
                        return Ok(None);
                    }
                    let len = self.atom_u32();
                    let element_type = self.dec.mv_type.element_type();
                    self.dec.check_var_len(len, element_type)?;
                    let len_usize = usize::try_from(len).unwrap_or(usize::MAX);
                    if self.input.len() >= len_usize {
                        let bytes = self.advance(len_usize);
                        self.dec.stage = Stage::MvNext;
                        return Ok(Some(Raw::ElementVar(bytes)));
                    }
                    self.dec.stage = self.dec.start_var(len, element_type, true);
                    return Ok(Some(Raw::ElementStart(len)));
                }
            }
        }
    }

    fn try_whole_mv(&mut self) -> Result<Option<Raw<'c>>, FxError> {
        let offset = self.dec.offset_u32();
        let Some(count) = self
            .input
            .first_chunk::<4>()
            .map(|c| u32::from_le_bytes(*c))
        else {
            return Ok(None);
        };
        self.dec.check_mv_count(count)?;
        let input = self.input;
        match MvView::parse(
            input,
            self.dec.mv_type,
            MvDialect::FastTransfer,
            self.dec.limits.max_mv_count,
        ) {
            Ok((view, rest)) => {
                if self.dec.mv_type.element_type().fixed_size().is_none()
                    && !var_elements_within(
                        input.get(4..).unwrap_or_default(),
                        count,
                        self.dec.limits.max_value_len,
                    )
                {
                    return Err(FxError::TooLarge { offset });
                }
                self.advance(input.len().saturating_sub(rest.len()));
                self.dec.stage = Stage::Tag;
                Ok(Some(Raw::Mv(view)))
            }
            Err(MvError::Truncated) => Ok(None),
            Err(MvError::TooMany) => Err(FxError::TooLarge { offset }),
            Err(MvError::BadHasValue | MvError::Utf16) => Err(FxError::BadValue { offset }),
        }
    }

    fn read_name(&mut self) -> Result<bool, FxError> {
        let offset = self.dec.offset_u32();
        let max_units = usize::from(self.dec.limits.max_name_units);
        loop {
            if !self.dec.carry.is_empty() {
                if !self.fill(2) {
                    return Ok(false);
                }
                let [lo, hi, ..] = self.dec.atom;
                let unit = u16::from_le_bytes([lo, hi]);
                if unit == 0 {
                    return Ok(true);
                }
                if self.dec.units.len() >= max_units {
                    return Err(FxError::BadName { offset });
                }
                self.dec.units.push(unit);
                continue;
            }
            let (units, _) = self.input.as_chunks::<2>();
            let terminator = units.iter().position(|unit| *unit == [0, 0]);
            let take = terminator.unwrap_or(units.len());
            if self.dec.units.len().saturating_add(take) > max_units {
                return Err(FxError::BadName { offset });
            }
            self.dec.units.extend(
                units
                    .iter()
                    .take(take)
                    .map(|unit| u16::from_le_bytes(*unit)),
            );
            match terminator {
                Some(pos) => {
                    self.advance(pos.saturating_add(1).saturating_mul(2));
                    return Ok(true);
                }
                None => {
                    self.advance(take.saturating_mul(2));
                    let odd = self.advance(self.input.len());
                    self.dec.carry.extend_from_slice(odd);
                    return Ok(false);
                }
            }
        }
    }
}

fn fx_fixed_size(size: u8) -> u64 {
    if size == 1 { 2 } else { u64::from(size) }
}

fn is_utf16(ptype: PropType) -> bool {
    matches!(
        ptype,
        PropType::Unicode | PropType::CodePageString(CODE_PAGE_UTF16)
    )
}

const TERMINATOR: [u8; 2] = [0, 0];

fn terminator_len(ptype: PropType) -> u8 {
    match ptype {
        PropType::Unicode | PropType::CodePageString(CODE_PAGE_UTF16) => 2,
        PropType::String8 | PropType::CodePageString(_) => 1,
        _ => 0,
    }
}

fn is_end_marker(m: Marker) -> bool {
    matches!(
        m,
        Marker::EndFolder
            | Marker::EndMessage
            | Marker::EndEmbed
            | Marker::EndToRecip
            | Marker::EndAttach
            | Marker::IncrSyncStateEnd
    )
}

fn var_elements_within(mut body: &[u8], count: u32, max_len: u32) -> bool {
    for _ in 0..count {
        let Some((len, tail)) = body.split_first_chunk::<4>() else {
            return true;
        };
        let len = u32::from_le_bytes(*len);
        if len > max_len {
            return false;
        }
        let Some(tail) = usize::try_from(len).ok().and_then(|len| tail.get(len..)) else {
            return true;
        };
        body = tail;
    }
    true
}

pub(super) fn var_value(ptype: PropType, bytes: &[u8]) -> Option<PropValue<'_>> {
    let terminator = TERMINATOR
        .get(..usize::from(terminator_len(ptype)))
        .unwrap_or_default();
    unterminated_value(ptype, bytes.strip_suffix(terminator).unwrap_or(bytes))
}

pub(super) fn unterminated_value(ptype: PropType, bytes: &[u8]) -> Option<PropValue<'_>> {
    Some(match ptype {
        PropType::String8 | PropType::CodePageString(_) if !is_utf16(ptype) => {
            PropValue::String8(bytes)
        }
        PropType::Unicode | PropType::CodePageString(_) => PropValue::Unicode(Utf16Le::new(bytes)?),
        PropType::ServerId => PropValue::ServerId(bytes),
        _ => PropValue::Binary(bytes),
    })
}
