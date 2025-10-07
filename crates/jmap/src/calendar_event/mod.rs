/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::JSCalendarProperty;
use common::{DavName, DavResources, Server};
use jmap_proto::error::set::SetError;
use store::query::Filter;
use trc::AddContext;
use types::{collection::Collection, field::CalendarField, id::Id};

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
    resources: &DavResources,
    account_id: u32,
    calendar_ids: &[DavName],
    uid: Option<&str>,
) -> trc::Result<Result<(), SetError<JSCalendarProperty<Id>>>> {
    if let Some(uid) = uid {
        let hits = server
            .store()
            .filter(
                account_id,
                Collection::CalendarEvent,
                vec![Filter::eq(CalendarField::Uid, uid.as_bytes().to_vec())],
            )
            .await
            .caused_by(trc::location!())?;
        if !hits.results.is_empty() {
            for document_id in resources
                .paths
                .iter()
                .filter(move |item| {
                    item.parent_id
                        .is_some_and(|id| calendar_ids.iter().any(|ab| ab.parent_id == id))
                })
                .map(|path| resources.resources[path.resource_idx].document_id)
            {
                if hits.results.contains(document_id) {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(JSCalendarProperty::Uid)
                        .with_description(format!(
                            "Contact with UID {uid} already exists with id {}.",
                            Id::from(document_id)
                        ))));
                }
            }
        }
    }

    Ok(Ok(()))
}
