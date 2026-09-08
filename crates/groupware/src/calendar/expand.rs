/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ArchivedCalendarEventData;
use crate::calendar::CalendarEventData;
use ahash::AHashSet;
use calcard::{
    common::{DateTimeResult, timezone::Tz},
    icalendar::{ArchivedICalendarComponent, ICalendarComponent, ICalendarProperty},
};
use chrono::{DateTime, TimeZone};
use std::str::FromStr;
use store::write::bitpack::BitpackIterator;
use types::TimeRange;
use utils::codec::leb128::Leb128Reader;

const RECURRENCE_KEY_EPOCH: i64 = -2208988800;
const RECURRENCE_KEY_GRANULARITY: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RecurrenceKey(u32);

impl RecurrenceKey {
    pub fn from_recurrence_id(recurrence_id_naive: i64) -> Option<Self> {
        u32::try_from(
            recurrence_id_naive
                .checked_sub(RECURRENCE_KEY_EPOCH)?
                .div_euclid(RECURRENCE_KEY_GRANULARITY),
        )
        .ok()?
        .checked_add(1)
        .map(RecurrenceKey)
    }

    pub fn from_prefix(prefix: u32) -> Option<Self> {
        (prefix != 0).then_some(RecurrenceKey(prefix))
    }

    pub fn prefix(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecurrenceId {
    pub utc: i64,
    pub naive: i64,
}

pub trait ComponentRecurrenceId {
    fn recurrence_id(&self, fallback_tz: Tz) -> Option<RecurrenceId>;
}

impl ComponentRecurrenceId for ArchivedICalendarComponent {
    fn recurrence_id(&self, fallback_tz: Tz) -> Option<RecurrenceId> {
        let entry = self.property(&ICalendarProperty::RecurrenceId)?;
        resolve_recurrence_id(
            entry.tz_id(),
            entry
                .values
                .first()?
                .as_partial_date_time()?
                .to_date_time()?,
            fallback_tz,
        )
    }
}

impl ComponentRecurrenceId for ICalendarComponent {
    fn recurrence_id(&self, fallback_tz: Tz) -> Option<RecurrenceId> {
        let entry = self.property(&ICalendarProperty::RecurrenceId)?;
        resolve_recurrence_id(
            entry.tz_id(),
            entry
                .values
                .first()?
                .as_partial_date_time()?
                .to_date_time()?,
            fallback_tz,
        )
    }
}

fn resolve_recurrence_id(
    tz_id: Option<&str>,
    date_time: DateTimeResult,
    fallback_tz: Tz,
) -> Option<RecurrenceId> {
    let tz = tz_id
        .and_then(|tz_id| Tz::from_str(tz_id).ok())
        .unwrap_or(fallback_tz);
    let date_time = date_time.to_date_time_with_tz(tz)?.with_timezone(&tz);

    Some(RecurrenceId {
        utc: date_time.timestamp(),
        naive: date_time.naive_local().and_utc().timestamp(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarEventExpansion {
    pub comp_id: u32,
    pub own_recurrence_id: Option<RecurrenceId>,
    pub start: i64,
    pub end: i64,
    pub start_naive: i64,
}

impl CalendarEventExpansion {
    pub fn recurrence_id(&self) -> RecurrenceId {
        self.own_recurrence_id.unwrap_or(RecurrenceId {
            utc: self.start,
            naive: self.start_naive,
        })
    }

    pub fn recurrence_key(&self) -> Option<RecurrenceKey> {
        RecurrenceKey::from_recurrence_id(self.recurrence_id().naive)
    }
}

impl ArchivedCalendarEventData {
    pub fn expand(&self, default_tz: Tz, limit: TimeRange) -> Option<Vec<CalendarEventExpansion>> {
        let mut expansion = Vec::with_capacity(self.time_ranges.len());
        let base_offset = self.base_offset.to_native();

        'outer: for (range_index, range) in self.time_ranges.iter().enumerate() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;

            let comp_id = range.id.to_native() as u32;
            let component = self.event.components.get(comp_id as usize)?;
            let duration = range.duration.to_native() as i64;
            let component_tz = Tz::from_id(range.start_tz.to_native())?;
            let mut own_recurrence_id = self
                .time_ranges
                .iter()
                .take(range_index)
                .all(|prior| prior.id != range.id)
                .then(|| component.recurrence_id(component_tz))
                .flatten();
            let mut start_tz = component_tz;
            let mut end_tz = Tz::from_id(range.end_tz.to_native())?;
            let is_todo = component.component_type.is_todo();

            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            if instances.len() > bytes_read {
                let unpacker =
                    BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
                for start_offset in unpacker {
                    let own_recurrence_id = own_recurrence_id.take();
                    let start_date_naive = start_offset as i64 + base_offset;
                    let end_date_naive = start_date_naive + duration;
                    let (Some(start), Some(end)) = (
                        resolve_local(start_tz, start_date_naive),
                        resolve_local(end_tz, end_date_naive),
                    ) else {
                        continue;
                    };

                    if limit.is_in_range(is_todo, start, end) {
                        expansion.push(CalendarEventExpansion {
                            comp_id,
                            own_recurrence_id,
                            start,
                            end,
                            start_naive: start_date_naive,
                        });
                    } else if start > limit.end {
                        continue 'outer;
                    }
                }
            } else {
                let start_date_naive = offset_or_count as i64 + base_offset;
                let end_date_naive = start_date_naive + duration;
                if let (Some(start), Some(end)) = (
                    resolve_local(start_tz, start_date_naive),
                    resolve_local(end_tz, end_date_naive),
                ) && limit.is_in_range(is_todo, start, end)
                {
                    expansion.push(CalendarEventExpansion {
                        comp_id,
                        own_recurrence_id,
                        start,
                        end,
                        start_naive: start_date_naive,
                    });
                }
            }
        }

        Some(expansion)
    }
}

impl CalendarEventData {
    pub fn component_tz(&self, comp_id: u32) -> Option<Tz> {
        self.time_ranges
            .iter()
            .find(|range| range.id as u32 == comp_id)
            .and_then(|range| Tz::from_id(range.start_tz))
    }

    pub fn expand_from_ids(
        &self,
        keys: &mut AHashSet<RecurrenceKey>,
        default_tz: Tz,
    ) -> Option<Vec<CalendarEventExpansion>> {
        let mut expansion = Vec::with_capacity(keys.len());
        let base_offset = self.base_offset;

        for (range_index, range) in self.time_ranges.iter().enumerate() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;
            let comp_id = range.id as u32;
            let component = self.event.components.get(comp_id as usize)?;
            let duration = range.duration as i64;
            let component_tz = Tz::from_id(range.start_tz)?;
            let mut own_recurrence_id = self
                .time_ranges
                .iter()
                .take(range_index)
                .all(|prior| prior.id != range.id)
                .then(|| component.recurrence_id(component_tz))
                .flatten();
            let mut start_tz = component_tz;
            let mut end_tz = Tz::from_id(range.end_tz)?;

            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            let mut push_instance = |own_recurrence_id: Option<RecurrenceId>, start_offset: u32| {
                let start_date_naive = start_offset as i64 + base_offset;
                let recurrence_id_naive =
                    own_recurrence_id.map_or(start_date_naive, |recurrence_id| recurrence_id.naive);
                if RecurrenceKey::from_recurrence_id(recurrence_id_naive)
                    .is_none_or(|key| !keys.contains(&key))
                {
                    return;
                }

                let end_date_naive = start_date_naive + duration;
                if let (Some(start), Some(end)) = (
                    resolve_local(start_tz, start_date_naive),
                    resolve_local(end_tz, end_date_naive),
                ) {
                    expansion.push(CalendarEventExpansion {
                        comp_id,
                        own_recurrence_id,
                        start,
                        end,
                        start_naive: start_date_naive,
                    });
                }
            };

            if instances.len() > bytes_read {
                let unpacker =
                    BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
                for start_offset in unpacker {
                    push_instance(own_recurrence_id.take(), start_offset);
                }
            } else {
                push_instance(own_recurrence_id, offset_or_count);
            }
        }

        keys.retain(|key| {
            !expansion
                .iter()
                .any(|expansion| expansion.recurrence_key() == Some(*key))
        });

        Some(expansion)
    }

    pub fn expand_single(&self, comp_id: u32, default_tz: Tz) -> Option<CalendarEventExpansion> {
        let range = self.time_ranges.iter().find(|r| r.id as u32 == comp_id)?;
        let instances = range.instances.as_ref();
        let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;
        let component_tz = Tz::from_id(range.start_tz)?;
        let own_recurrence_id = self
            .event
            .components
            .get(comp_id as usize)
            .and_then(|component| component.recurrence_id(component_tz));
        let mut start_tz = component_tz;
        let mut end_tz = Tz::from_id(range.end_tz)?;

        if start_tz.is_floating() && !default_tz.is_floating() {
            start_tz = default_tz;
        }
        if end_tz.is_floating() && !default_tz.is_floating() {
            end_tz = default_tz;
        }
        let start_offset = if instances.len() > bytes_read {
            let mut unpacker =
                BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
            unpacker.next()?
        } else {
            offset_or_count
        };
        let start_date_naive = start_offset as i64 + self.base_offset;
        let end_date_naive = start_date_naive + range.duration as i64;
        let start = resolve_local(start_tz, start_date_naive)?;
        let end = resolve_local(end_tz, end_date_naive)?;

        Some(CalendarEventExpansion {
            comp_id,
            own_recurrence_id,
            start,
            end,
            start_naive: start_date_naive,
        })
    }
}

impl Default for CalendarEventExpansion {
    fn default() -> Self {
        Self {
            comp_id: u32::MAX,
            own_recurrence_id: None,
            start: i64::MAX,
            end: i64::MAX,
            start_naive: i64::MAX,
        }
    }
}

pub fn resolve_local(tz: Tz, naive_secs: i64) -> Option<i64> {
    tz.from_local_datetime(&DateTime::from_timestamp(naive_secs, 0)?.naive_local())
        .earliest()
        .map(|dt| dt.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::{Entry, Parser};
    use chrono::NaiveDate;

    fn naive(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
        NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|date| date.and_hms_opt(hour, minute, second))
            .map(|date_time| date_time.and_utc().timestamp())
            .expect("valid date")
    }

    fn key(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> RecurrenceKey {
        RecurrenceKey::from_recurrence_id(naive(year, month, day, hour, minute, 0))
            .expect("representable recurrence id")
    }

    fn event_data(ical: &str) -> CalendarEventData {
        let entry = Parser::new(ical).entry();
        let Entry::ICalendar(ical) = entry else {
            panic!("failed to parse iCalendar: {entry:?}");
        };
        CalendarEventData::new(ical, Tz::UTC, 1000, &mut None)
    }

    fn expand_key(data: &CalendarEventData, key: RecurrenceKey) -> Vec<(u32, i64)> {
        let mut keys = AHashSet::from_iter([key]);
        data.expand_from_ids(&mut keys, Tz::UTC)
            .expect("expansion")
            .into_iter()
            .map(|expansion| (expansion.comp_id, expansion.start_naive))
            .collect()
    }

    const MASTER: &str = concat!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
        "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20270101T000000Z\r\n",
        "DTSTART:20270301T090000Z\r\nDTEND:20270301T100000Z\r\n",
        "RRULE:FREQ=WEEKLY;COUNT=5\r\nSUMMARY:Weekly\r\nEND:VEVENT\r\n",
    );

    const OVERRIDE: &str = concat!(
        "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20270101T000000Z\r\n",
        "RECURRENCE-ID:20270308T090000Z\r\nDTSTART:20270308T140000Z\r\n",
        "DTEND:20270308T150000Z\r\nSUMMARY:Moved\r\nEND:VEVENT\r\n",
    );

    #[test]
    fn recurrence_key_encoding() {
        assert_eq!(
            RecurrenceKey::from_recurrence_id(RECURRENCE_KEY_EPOCH),
            Some(RecurrenceKey(1))
        );
        assert_eq!(
            RecurrenceKey::from_recurrence_id(RECURRENCE_KEY_EPOCH - 1),
            None
        );
        assert_eq!(RecurrenceKey::from_recurrence_id(i64::MAX), None);
        assert_eq!(RecurrenceKey::from_prefix(0), None);
        assert_eq!(
            RecurrenceKey::from_prefix(key(2027, 3, 15, 9, 0).prefix()),
            Some(key(2027, 3, 15, 9, 0))
        );
        assert_ne!(key(2027, 3, 15, 9, 0), key(2027, 3, 15, 9, 1));
        assert_eq!(
            RecurrenceKey::from_recurrence_id(naive(2027, 3, 15, 9, 0, 30)),
            Some(key(2027, 3, 15, 9, 0))
        );
    }

    #[test]
    fn recurrence_keys_survive_an_override() {
        let before = event_data(&format!("{MASTER}END:VCALENDAR\r\n"));
        let after = event_data(&format!("{MASTER}{OVERRIDE}END:VCALENDAR\r\n"));

        for (day, comp_id) in [(1, 1), (15, 1), (22, 1), (29, 1)] {
            let key = key(2027, 3, day, 9, 0);
            let start_naive = naive(2027, 3, day, 9, 0, 0);
            assert_eq!(expand_key(&before, key), [(comp_id, start_naive)]);
            assert_eq!(expand_key(&after, key), [(comp_id, start_naive)]);
        }

        let overridden = key(2027, 3, 8, 9, 0);
        assert_eq!(
            expand_key(&before, overridden),
            [(1, naive(2027, 3, 8, 9, 0, 0))]
        );
        assert_eq!(
            expand_key(&after, overridden),
            [(2, naive(2027, 3, 8, 14, 0, 0))]
        );
    }

    #[test]
    fn this_and_future_instances_get_distinct_keys() {
        const THIS_AND_FUTURE: &str = concat!(
            "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20270101T000000Z\r\n",
            "RECURRENCE-ID;RANGE=THISANDFUTURE:20270315T090000Z\r\n",
            "DTSTART:20270315T100000Z\r\nDTEND:20270315T113000Z\r\n",
            "SUMMARY:Longer\r\nEND:VEVENT\r\n",
        );
        let data = event_data(&format!("{MASTER}{THIS_AND_FUTURE}END:VCALENDAR\r\n"));

        assert_eq!(
            expand_key(&data, key(2027, 3, 15, 9, 0)),
            [(2, naive(2027, 3, 15, 10, 0, 0))]
        );
        assert_eq!(
            expand_key(&data, key(2027, 3, 22, 10, 0)),
            [(2, naive(2027, 3, 22, 10, 0, 0))]
        );
        assert_eq!(
            expand_key(&data, key(2027, 3, 29, 10, 0)),
            [(2, naive(2027, 3, 29, 10, 0, 0))]
        );
        assert_eq!(
            expand_key(&data, key(2027, 3, 1, 9, 0)),
            [(1, naive(2027, 3, 1, 9, 0, 0))]
        );
    }

    #[test]
    fn unmatched_recurrence_keys_are_reported_back() {
        let data = event_data(&format!("{MASTER}END:VCALENDAR\r\n"));
        let missing = key(2027, 4, 5, 9, 0);
        let present = key(2027, 3, 15, 9, 0);
        let mut keys = AHashSet::from_iter([missing, present]);

        let expansion = data.expand_from_ids(&mut keys, Tz::UTC).expect("expansion");

        assert_eq!(expansion.len(), 1);
        assert_eq!(keys.into_iter().collect::<Vec<_>>(), [missing]);
    }
}
