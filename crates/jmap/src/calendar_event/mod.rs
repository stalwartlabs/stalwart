/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::JSCalendarProperty;
use common::GroupwareResources;
use groupware::calendar::expand::RecurrenceKey;
use jmap_proto::error::set::SetError;
use types::id::Id;

pub mod copy;
pub mod get;
pub mod parse;
pub mod query;
pub mod set;

/*

TODO: Not yet implemented:

- CalendarEvent
    - Per-user properties (However, the database schema is ready to support this)
    - mayInviteSelf, mayInviteOthers and hideAttendees (stored but not enforced)

- Principal/getAvailability
  - If there are overlapping BusyPeriod time ranges with different "busyStatus" properties
    the server MUST choose the value in the following order: confirmed > unavailable > tentative.
  - Return event properties

*/

pub trait CalendarSyntheticId {
    fn new(key: RecurrenceKey, document_id: u32) -> Self;

    fn is_synthetic(&self) -> bool;

    fn recurrence_key(&self) -> Option<RecurrenceKey>;
}

impl CalendarSyntheticId for Id {
    fn new(key: RecurrenceKey, document_id: u32) -> Id {
        Id::from_parts(key.prefix(), document_id)
    }

    fn recurrence_key(&self) -> Option<RecurrenceKey> {
        RecurrenceKey::from_prefix(self.prefix_id())
    }

    fn is_synthetic(&self) -> bool {
        self.prefix_id() != 0
    }
}

pub(super) fn assert_is_unique_uid(
    resources: &GroupwareResources,
    uid: Option<&str>,
) -> trc::Result<Result<(), SetError<JSCalendarProperty<Id>>>> {
    if let Some(uid) = uid
        && !resources.uid_matches(uid).is_empty()
    {
        Ok(Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::Uid)
            .with_description(format!(
                "An event with UID {uid} already exists.",
            ))))
    } else {
        Ok(Ok(()))
    }
}
