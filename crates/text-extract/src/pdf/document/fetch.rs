/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Document, table::Table};
use crate::pdf::{
    object::{Dict, Indirect, ObjRef, Object, Stream},
    objstm::ObjStm,
    xref::{Entry, NO_SLOT},
};

const MIN_RETAINED_OBJSTM: usize = 32 << 20;
const MAX_NESTED_LOADS: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Broken;

impl<'a> Document<'a> {
    pub(super) fn fetch<'t>(
        &'t self,
        table: &'t Table<'_>,
        id: ObjRef,
    ) -> Result<Object<'t>, Broken> {
        if self.source.scan_exhausted() {
            return Ok(Object::Null);
        }
        match table.entry(id.num) {
            Entry::Offset { offset, .. } => self.fetch_direct(table, offset, id.num).ok_or(Broken),
            Entry::Compressed { stream, index } => {
                self.fetch_compressed(table, stream, index, id.num)
            }
            Entry::Missing | Entry::Free { .. } => Err(Broken),
        }
    }

    pub(super) fn resolve_in<'t>(&'t self, table: &'t Table<'_>, object: Object<'t>) -> Object<'t> {
        let mut current = object;
        for _ in 0..super::MAX_REFERENCE_CHAIN {
            match current {
                Object::Ref(id) => current = self.fetch(table, id).unwrap_or_default(),
                resolved => return resolved,
            }
        }
        Object::Null
    }

    fn parse_direct(
        &self,
        table: &Table<'_>,
        offset: u32,
        num: u32,
        streams: bool,
    ) -> Option<Indirect<'a>> {
        let data = self.source.data;
        table.positions(offset).find_map(|pos| {
            let object =
                Indirect::parse(data, pos, streams).filter(|object| object.id.num == num)?;
            self.source
                .charge_scan(object.end.saturating_sub(pos))
                .then_some(object)
        })
    }

    pub(super) fn fetch_direct(
        &self,
        table: &Table<'_>,
        offset: u32,
        num: u32,
    ) -> Option<Object<'a>> {
        let object = self.parse_direct(table, offset, num, true)?;
        Some(match (object.value, object.stream_start) {
            (Object::Dict(dict), Some(start)) => {
                let length = self.stream_length(table, dict, object.id);
                Object::Stream(Stream {
                    dict,
                    data: self.source.stream_data(start, length),
                    id: object.id,
                })
            }
            (value, _) => value,
        })
    }

    fn stream_length(&self, table: &Table<'_>, dict: Dict<'a>, owner: ObjRef) -> Option<i64> {
        match dict.get(b"Length")? {
            Object::Int(length) => Some(length),
            Object::Ref(id) if id.num != owner.num => match table.entry(id.num) {
                Entry::Offset { offset, .. } => self
                    .parse_direct(table, offset, id.num, false)?
                    .value
                    .as_int(),
                Entry::Compressed { stream, index } if stream != owner.num => self
                    .fetch_compressed(table, stream, index, id.num)
                    .ok()?
                    .as_int(),
                _ => None,
            },
            _ => None,
        }
    }

    fn fetch_compressed<'t>(
        &'t self,
        table: &'t Table<'_>,
        stream: u32,
        index: u32,
        num: u32,
    ) -> Result<Object<'t>, Broken> {
        let Entry::Offset { offset, slot, .. } = table.entry(stream) else {
            return Err(Broken);
        };
        if slot == NO_SLOT || stream == num {
            return Err(Broken);
        }
        let slot = table.slot(slot).ok_or(Broken)?;
        let loaded = match slot.cell.get() {
            Some(loaded) => loaded,
            None => {
                if slot.busy.get() || self.nesting.get() >= MAX_NESTED_LOADS {
                    return Ok(Object::Null);
                }
                slot.busy.set(true);
                self.nesting.set(self.nesting.get() + 1);
                let loaded = self.load_objstm(table, offset, stream);
                self.nesting.set(self.nesting.get() - 1);
                slot.busy.set(false);
                slot.cell.get_or_init(|| loaded)
            }
        };
        let objstm = loaded.as_ref().ok_or(Broken)?;
        let (object, consumed) = objstm.object(index, num).ok_or(Broken)?;
        if !self.source.charge_scan(consumed) {
            return Ok(Object::Null);
        }
        Ok(object)
    }

    pub(super) fn load_objstm(&self, table: &Table<'_>, offset: u32, num: u32) -> Option<ObjStm> {
        let retained = self.retained.get();
        let cap = MIN_RETAINED_OBJSTM.max(self.source.data.len());
        if retained >= cap {
            self.source.mark_truncated();
            return None;
        }
        let stream = self.fetch_direct(table, offset, num)?.as_stream()?;
        let mut data = Vec::new();
        self.decode_stream(stream, &mut data);
        data.shrink_to_fit();
        if retained.saturating_add(data.len()) > cap {
            self.source.mark_truncated();
            return None;
        }
        self.retained.set(retained + data.len());
        let count = self.resolve_in(table, stream.dict.get(b"N").unwrap_or_default());
        let first = self.resolve_in(table, stream.dict.get(b"First").unwrap_or_default());
        Some(ObjStm::new(data, count.as_int(), first.as_int()))
    }
}
