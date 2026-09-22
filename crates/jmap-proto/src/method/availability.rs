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
use types::{TimeRange, blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct GetAvailabilityRequest {
    pub account_id: Id,
    pub id: Id,
    pub utc_start: Option<UTCDate>,
    pub utc_end: Option<UTCDate>,
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
    pub account_id: Option<Id>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum BusyStatus {
    Tentative,
    Unavailable,
    Confirmed,
}

impl GetAvailabilityRequest {
    pub fn time_range(&self) -> Option<TimeRange> {
        let start = self.utc_start.as_ref().filter(|date| date.is_valid())?;
        let end = self.utc_end.as_ref().filter(|date| date.is_valid())?;
        Some(TimeRange::new(start.timestamp(), end.timestamp()))
            .filter(|range| range.end > range.start)
    }
}

impl<'de> DeserializeArguments<'de> for GetAvailabilityRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = crate::request::deserialize_account_id(map)?;
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

#[cfg(test)]
mod tests {
    use super::{BusyStatus, GetAvailabilityRequest};
    use crate::types::date::UTCDate;
    use std::str::FromStr;
    use types::TimeRange;

    fn request(utc_start: Option<&str>, utc_end: Option<&str>) -> GetAvailabilityRequest {
        GetAvailabilityRequest {
            utc_start: utc_start.map(|date| UTCDate::from_str(date).expect("parsable date")),
            utc_end: utc_end.map(|date| UTCDate::from_str(date).expect("parsable date")),
            ..Default::default()
        }
    }

    #[test]
    fn time_range_requires_valid_increasing_dates() {
        assert_eq!(
            request(Some("2026-03-11T01:00:00Z"), Some("2026-03-11T06:00:00Z")).time_range(),
            Some(TimeRange::new(1773190800, 1773208800))
        );
        for (utc_start, utc_end) in [
            (None, Some("2026-03-11T06:00:00Z")),
            (Some("2026-03-11T01:00:00Z"), None),
            (None, None),
            (Some("2026-13-45T99:99:99Z"), Some("2026-03-11T06:00:00Z")),
            (Some("2026-03-11T01:00:00Z"), Some("2026-03-11T01:00:00Z")),
            (Some("2026-03-11T06:00:00Z"), Some("2026-03-11T01:00:00Z")),
        ] {
            assert_eq!(
                request(utc_start, utc_end).time_range(),
                None,
                "{utc_start:?} {utc_end:?}"
            );
        }
    }

    #[test]
    fn busy_status_precedence() {
        assert!(BusyStatus::Confirmed > BusyStatus::Unavailable);
        assert!(BusyStatus::Unavailable > BusyStatus::Tentative);
    }
}
