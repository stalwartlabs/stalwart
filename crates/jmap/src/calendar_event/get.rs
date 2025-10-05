/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::JmapCacheState;
use calcard::jscalendar::{JSCalendarProperty, JSCalendarValue};
use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, calendar::CalendarEvent};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::calendar_event,
    request::IntoValid,
};
use jmap_tools::{Map, Value};
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

pub trait CalendarEventGet: Sync + Send {
    fn calendar_event_get(
        &self,
        request: GetRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<calendar_event::CalendarEvent>>> + Send;
}

impl CalendarEventGet for Server {
    async fn calendar_event_get(
        &self,
        mut request: GetRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<calendar_event::CalendarEvent>> {
        todo!()

        /*let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let return_all_properties = request.properties.is_none();
        let properties =
            request.unwrap_properties(&[JSCalendarProperty::Id, JSCalendarProperty::CalendarIds]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let calendar_event_ids = if access_token.is_member(account_id) {
            cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::ReadItems], true)
        };
        let ids = if let Some(ids) = ids {
            ids
        } else {
            calendar_event_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };
        let return_id = return_all_properties || properties.contains(&JSCalendarProperty::Id);
        let return_address_book_ids =
            return_all_properties || properties.contains(&JSCalendarProperty::CalendarIds);

        for id in ids {
            // Obtain the calendar_event object
            let document_id = id.document_id();
            if !calendar_event_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }

            let _calendar_event = if let Some(calendar_event) = self
                .get_archive(account_id, Collection::CalendarEvent, document_id)
                .await?
            {
                calendar_event
            } else {
                response.not_found.push(id);
                continue;
            };

            let calendar_event = _calendar_event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            let mut result = if return_all_properties {
                calendar_event
                    .card
                    .into_jscalendar::<Id>()
                    .into_inner()
                    .into_object()
                    .unwrap()
            } else {
                Map::from_iter(
                    calendar_event
                        .card
                        .into_jscalendar::<Id>()
                        .into_inner()
                        .into_expanded_object()
                        .filter(|(k, _)| k.as_property().is_some_and(|p| properties.contains(p))),
                )
            };

            if return_id {
                result.insert_unchecked(
                    JSCalendarProperty::Id,
                    Value::Element(JSCalendarValue::Id(id)),
                );
            }

            if return_address_book_ids {
                let mut obj = Map::with_capacity(calendar_event.names.len());
                for id in calendar_event.names.iter() {
                    obj.insert_unchecked(JSCalendarProperty::IdValue(Id::from(id.parent_id)), true);
                }
                result.insert_unchecked(JSCalendarProperty::CalendarIds, Value::Object(obj));
            }

            response.list.push(result.into());
        }

        Ok(response)*/
    }
}
