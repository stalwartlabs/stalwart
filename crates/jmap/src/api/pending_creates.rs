/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{method::set::SetResponse, object::JmapObject};
use store::write::{AssignedIds, Slot};

#[derive(Debug, Default)]
pub struct PendingCreates(Vec<(String, Slot)>);

impl PendingCreates {
    pub fn new() -> Self {
        PendingCreates(Vec::new())
    }

    pub fn push(&mut self, create_id: String, slot: Slot) {
        self.0.push((create_id, slot));
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn resolve<T>(self, response: &mut SetResponse<T>, assigned_ids: &AssignedIds)
    where
        T: JmapObject,
        u32: Into<T::Id>,
    {
        for (create_id, slot) in self.0 {
            response.created(create_id, assigned_ids.slot(slot));
        }
    }
}
