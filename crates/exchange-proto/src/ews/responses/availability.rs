/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ResponseMessage, Status};
use crate::{
    ews::types::{
        address::EmailAddress,
        generated::{FreeBusyView, SuggestionDayResult},
        timezone::TimeZoneDefinition,
        value::{EwsValue, M, T},
    },
    xml::{XmlWrite, XmlWriter},
};

const STATUS_ELEMENT: &str = "ResponseMessage";

#[derive(Debug, Clone, PartialEq)]
pub struct FreeBusyResponse<'x> {
    pub status: Status<'x>,
    pub view: Option<FreeBusyView<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SuggestionsResponse<'x> {
    pub status: Status<'x>,
    pub days: Vec<SuggestionDayResult>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetUserAvailabilityResponse<'x> {
    pub free_busy: Vec<FreeBusyResponse<'x>>,
    pub suggestions: Option<SuggestionsResponse<'x>>,
}

impl XmlWrite for GetUserAvailabilityResponse<'_> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "GetUserAvailabilityResponse");
        if !self.free_busy.is_empty() {
            w.start(M, "FreeBusyResponseArray");
            for response in &self.free_busy {
                w.start(M, "FreeBusyResponse");
                response.status.start(w, STATUS_ELEMENT);
                w.end(M, STATUS_ELEMENT);
                if let Some(view) = response
                    .view
                    .as_ref()
                    .filter(|_| response.status.allows_body())
                {
                    w.start(M, "FreeBusyView");
                    view.write_children(w);
                    w.end(M, "FreeBusyView");
                }
                w.end(M, "FreeBusyResponse");
            }
            w.end(M, "FreeBusyResponseArray");
        }
        if let Some(suggestions) = &self.suggestions {
            w.start(M, "SuggestionsResponse");
            suggestions.status.start(w, STATUS_ELEMENT);
            w.end(M, STATUS_ELEMENT);
            if suggestions.status.allows_body() {
                w.start(M, "SuggestionDayResultArray");
                for day in &suggestions.days {
                    day.write(w, "SuggestionDayResult");
                }
                w.end(M, "SuggestionDayResultArray");
            }
            w.end(M, "SuggestionsResponse");
        }
        w.end(M, "GetUserAvailabilityResponse");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetRoomsBody<'x> {
    pub rooms: Vec<EmailAddress<'x>>,
}

impl ResponseMessage for GetRoomsBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Rooms");
        for room in &self.rooms {
            w.start(T, "Room");
            room.write(w, "Id");
            w.end(T, "Room");
        }
        w.end(M, "Rooms");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetRoomListsBody<'x> {
    pub room_lists: Vec<EmailAddress<'x>>,
}

impl ResponseMessage for GetRoomListsBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "RoomLists");
        for list in &self.room_lists {
            list.write(w, "Address");
        }
        w.end(M, "RoomLists");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetServerTimeZonesMessage<'x> {
    pub definitions: Vec<TimeZoneDefinition<'x>>,
}

impl ResponseMessage for GetServerTimeZonesMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "TimeZoneDefinitions");
        for definition in &self.definitions {
            definition.write(w, "TimeZoneDefinition");
        }
        w.end(M, "TimeZoneDefinitions");
    }
}
