/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::ItemId,
    value::{DateTime, ews_struct},
};
use crate::ews::schema::{ReminderActionType, ReminderGroup};
use std::borrow::Cow;

ews_struct! {
    pub struct ReminderItemAction<'x> {
        action_type: req "ActionType" => ReminderActionType,
        item_id: req "ItemId" => ItemId<'x>,
        new_reminder_time: opt "NewReminderTime" => Cow<'x, str>,
    }
}

ews_struct! {
    pub struct Reminder<'x> {
        subject: req "Subject" => Cow<'x, str>,
        location: opt "Location" => Cow<'x, str>,
        reminder_time: req "ReminderTime" => DateTime,
        start_date: req "StartDate" => DateTime,
        end_date: req "EndDate" => DateTime,
        item_id: req "ItemId" => ItemId<'x>,
        recurring_master_item_id: opt "RecurringMasterItemId" => ItemId<'x>,
        reminder_group: opt "ReminderGroup" => ReminderGroup,
        uid: req "UID" => Cow<'x, str>,
    }
}
