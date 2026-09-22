/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod get;
pub mod patch;
pub mod query;
pub mod set;

use groupware::calendar::{EVENT_NOTIFICATION_IS_CHANGE, EVENT_NOTIFICATION_IS_DESTROY};
use jmap_proto::object::calendar_event_notification::CalendarEventNotificationType;

pub(crate) trait NotificationTypeFlags {
    fn from_flags(flags: u16) -> Self;
}

impl NotificationTypeFlags for CalendarEventNotificationType {
    fn from_flags(flags: u16) -> Self {
        if flags & EVENT_NOTIFICATION_IS_CHANGE != 0 {
            CalendarEventNotificationType::Updated
        } else if flags & EVENT_NOTIFICATION_IS_DESTROY != 0 {
            CalendarEventNotificationType::Destroyed
        } else {
            CalendarEventNotificationType::Created
        }
    }
}
