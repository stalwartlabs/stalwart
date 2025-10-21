/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    request::{
        MaybeInvalid,
        deserialize::{DeserializeArguments, deserialize_request},
    },
    types::date::UTCDate,
};
use calcard::jscalendar::{JSCalendar, JSCalendarProperty};
use serde::{Deserialize, Deserializer, Serialize};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct GetAvailabilityRequest {
    pub account_id: Id,
    pub id: Id,
    pub utc_start: UTCDate,
    pub utc_end: UTCDate,
    pub show_details: bool,
    pub event_properties: Option<Vec<MaybeInvalid<JSCalendarProperty<Id>>>>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetAvailabilityResponse {
    pub list: Vec<BusyPeriod>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BusyPeriod {
    pub utc_start: UTCDate,
    pub utc_end: UTCDate,
    pub busy_status: Option<BusyStatus>,
    pub event: Option<JSCalendar<'static, Id, BlobId>>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BusyStatus {
    Confirmed,
    Tentative,
    Unavailable,
}

impl<'de> DeserializeArguments<'de> for GetAvailabilityRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"utcStart" => {
                self.utc_start = map.next_value()?;
            },
            b"utcEnd" => {
                self.utc_end = map.next_value()?;
            },
            b"id" => {
                self.id = map.next_value()?;
            },
            b"showDetails" => {
                self.show_details = map.next_value()?;
            },
            b"eventProperties" => {
                self.event_properties = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> Deserialize<'de> for GetAvailabilityRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
