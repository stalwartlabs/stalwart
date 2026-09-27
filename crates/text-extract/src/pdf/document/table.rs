/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::{
    objstm::ObjStm,
    xref::{Entries, Entry, NO_SLOT},
};
use std::{
    borrow::Cow,
    cell::{Cell, OnceCell},
};

#[derive(Default)]
pub(crate) struct Slot {
    pub(super) cell: OnceCell<Option<ObjStm>>,
    pub(super) busy: Cell<bool>,
}

pub(crate) struct Table<'a> {
    pub(super) entries: Cow<'a, Entries>,
    pub(super) slots: Vec<Slot>,
    bases: [usize; 2],
}

impl<'a> Table<'a> {
    pub(crate) fn new(
        entries: Cow<'a, Entries>,
        slots: Vec<Slot>,
        bias: usize,
        header: usize,
    ) -> Self {
        let other = if bias == header { 0 } else { header };
        Table {
            entries,
            slots,
            bases: [bias, other],
        }
    }

    #[inline]
    pub(crate) fn entry(&self, num: u32) -> Entry {
        self.entries.get(num)
    }

    pub(crate) fn positions(&self, offset: u32) -> impl Iterator<Item = usize> + '_ {
        let [first, second] = self.bases;
        let offset = offset as usize;
        std::iter::once(first)
            .chain((second != first).then_some(second))
            .filter_map(move |base| base.checked_add(offset))
    }

    pub(crate) fn slot(&self, index: u32) -> Option<&Slot> {
        self.slots.get(index as usize)
    }
}

impl Slot {
    pub(crate) fn many(count: usize) -> Vec<Slot> {
        std::iter::repeat_with(Slot::default).take(count).collect()
    }
}

pub(crate) fn assign_slots(entries: &mut Entries) -> usize {
    let mut streams: Vec<u32> = entries
        .iter()
        .filter_map(|(_, entry)| match entry {
            Entry::Compressed { stream, .. } => Some(stream),
            _ => None,
        })
        .collect();
    streams.sort_unstable();
    streams.dedup();
    let mut next = 0u32;
    for stream in streams {
        if let Some(Entry::Offset { slot, .. }) = entries.get_mut(stream)
            && *slot == NO_SLOT
        {
            *slot = next;
            next += 1;
        }
    }
    next as usize
}
