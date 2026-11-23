/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::types::{
        ids::ItemId,
        reminder::Reminder,
        value::{EwsValue, M, T},
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetRemindersBody<'x> {
    pub reminders: Vec<Reminder<'x>>,
}

impl ResponseMessage for GetRemindersBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Reminders");
        for reminder in &self.reminders {
            reminder.write(w, "Reminder");
        }
        w.end(M, "Reminders");
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        w.start(M, "Reminders");
        w.end(M, "Reminders");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PerformReminderActionBody<'x> {
    pub updated_item_ids: Vec<ItemId<'x>>,
}

impl ResponseMessage for PerformReminderActionBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "UpdatedItemIds");
        for id in &self.updated_item_ids {
            id.write(w, "ItemId");
        }
        w.end(M, "UpdatedItemIds");
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        w.start(M, "UpdatedItemIds");
        w.start(T, "ItemId").attr("Id", "");
        w.end(T, "ItemId");
        w.end(M, "UpdatedItemIds");
    }
}
