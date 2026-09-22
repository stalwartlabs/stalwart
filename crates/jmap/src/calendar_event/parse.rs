/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::download::BlobDownload;
use calcard::{
    icalendar::ICalendar,
    jscalendar::{JSCalendar, JSCalendarProperty, import::ImportOptions},
};
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::calendar_event::CalendarEvent,
    request::{IntoValid, MaybeInvalid},
};
use jmap_tools::{Key, Value};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

pub trait CalendarEventParse: Sync + Send {
    fn calendar_event_parse(
        &self,
        request: ParseRequest<CalendarEvent>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ParseResponse<CalendarEvent>>> + Send;
}

impl CalendarEventParse for Server {
    async fn calendar_event_parse(
        &self,
        request: ParseRequest<CalendarEvent>,
        access_token: &AccessToken,
    ) -> trc::Result<ParseResponse<CalendarEvent>> {
        if request.blob_ids.len() > self.core.jmap.calendar_parse_max_items {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }
        let properties = request
            .properties
            .map(|v| v.into_valid().collect::<Vec<_>>());

        let mut response = ParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids.into_valid() {
            // Fetch raw message to parse
            let raw_ical = match self.blob_download(&blob_id, access_token).await? {
                Some(raw_ical) => raw_ical,
                None => {
                    response.not_found.push(MaybeInvalid::Value(blob_id));
                    continue;
                }
            };
            let Ok(ical) = ICalendar::parse(std::str::from_utf8(&raw_ical).unwrap_or_default())
            else {
                response.not_parsable.push(blob_id);
                continue;
            };
            let Some(Value::Array(mut js_calendar_entries)) = ical
                .into_jscalendar_with::<Id, BlobId, _>(ImportOptions::new())
                .ok()
                .map(JSCalendar::into_inner)
                .and_then(Value::into_object)
                .and_then(|mut group| group.remove(&Key::Property(JSCalendarProperty::Entries)))
                .filter(|entries| {
                    entries.as_array().is_some_and(|entries| {
                        !entries.is_empty()
                            && entries.iter().all(|entry| entry.as_object().is_some())
                    })
                })
            else {
                response.not_parsable.push(blob_id);
                continue;
            };

            for entry in js_calendar_entries
                .iter_mut()
                .filter_map(Value::as_object_mut)
            {
                if let Some(properties) = &properties {
                    entry
                        .as_mut_vec()
                        .retain(|(k, _)| k.as_property().is_some_and(|k| properties.contains(k)));
                }
                for property in METADATA_PROPERTIES.iter().filter(|property| {
                    properties
                        .as_ref()
                        .is_none_or(|properties| properties.contains(property))
                }) {
                    entry.insert(Key::Property(property.clone()), Value::Null);
                }
            }

            response
                .parsed
                .append(blob_id, Value::Array(js_calendar_entries));
        }

        Ok(response)
    }
}

const METADATA_PROPERTIES: [JSCalendarProperty<Id>; 5] = [
    JSCalendarProperty::Id,
    JSCalendarProperty::BaseEventId,
    JSCalendarProperty::CalendarIds,
    JSCalendarProperty::IsDraft,
    JSCalendarProperty::IsOrigin,
];
