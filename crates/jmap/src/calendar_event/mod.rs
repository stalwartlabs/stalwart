/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::JSCalendarProperty;
use common::Server;
use jmap_proto::error::set::SetError;
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField, id::Id};

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

- CalendarEvent/set
   - synthetic id update and removal

- Principal/getAvailability
  - If there are overlapping BusyPeriod time ranges with different "busyStatus" properties
    the server MUST choose the value in the following order: confirmed > unavailable > tentative.
  - Return event properties

*/

pub trait CalendarSyntheticId {
    fn new(expansion_id: u32, document_id: u32) -> Self;

    fn is_synthetic(&self) -> bool;

    fn expansion_id(&self) -> Option<u32>;
}

impl CalendarSyntheticId for Id {
    fn new(expansion_id: u32, document_id: u32) -> Id {
        Id::from_parts(expansion_id + 1, document_id)
    }

    fn expansion_id(&self) -> Option<u32> {
        let prefix = self.prefix_id();
        if prefix > 0 { Some(prefix - 1) } else { None }
    }

    fn is_synthetic(&self) -> bool {
        self.prefix_id() > 0
    }
}

pub(super) async fn assert_is_unique_uid(
    server: &Server,
    account_id: u32,
    uid: Option<&str>,
) -> trc::Result<Result<(), SetError<JSCalendarProperty<Id>>>> {
    if let Some(uid) = uid
        && server
            .document_exists(
                account_id,
                Collection::CalendarEvent,
                CalendarEventField::Uid,
                uid.as_bytes(),
            )
            .await
            .caused_by(trc::location!())?
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
