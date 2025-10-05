/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::download::BlobDownload;
use calcard::icalendar::ICalendar;
use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::calendar_event::CalendarEvent,
    request::IntoValid,
};
use types::id::Id;
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
        let todo = "user calendar parse specific limit, same for addressbooks";
        if request.blob_ids.len() > self.core.jmap.mail_parse_max_items {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }
        let return_all_properties = request.properties.is_none();
        let properties = request
            .properties
            .map(|v| v.into_valid().collect::<Vec<_>>())
            .unwrap_or_default();

        let mut response = ParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids.into_valid() {
            // Fetch raw message to parse
            let raw_vcard = match self.blob_download(&blob_id, access_token).await? {
                Some(raw_vcard) => raw_vcard,
                None => {
                    response.not_found.push(blob_id);
                    continue;
                }
            };
            let Ok(vcard) = ICalendar::parse(std::str::from_utf8(&raw_vcard).unwrap_or_default())
            else {
                response.not_parsable.push(blob_id);
                continue;
            };
            let mut js_calendar_event = vcard.into_jscalendar::<Id>();

            if !return_all_properties {
                js_calendar_event
                    .0
                    .as_object_mut()
                    .unwrap()
                    .as_mut_vec()
                    .retain(|(k, _)| k.as_property().is_some_and(|k| properties.contains(k)));
            }

            response
                .parsed
                .append(blob_id, js_calendar_event.into_inner());
        }

        Ok(response)
    }
}
