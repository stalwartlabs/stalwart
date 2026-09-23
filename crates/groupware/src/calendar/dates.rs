/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Alarm, ArchivedCalendarEventData, ArchivedTimezone, CalendarEventData, Timezone,
    alarm::ExpandAlarm,
    alerts::{DefaultAlerts, ICalendarDefaultAlerts},
    expand::RangeFlags,
    overlap::ICalendarOverlap,
};
use crate::calendar::ComponentTimeRange;
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarComponentType},
};
use compact_str::ToCompactString;
use indexmap::IndexMap;
use store::{
    ahash::{AHashMap, RandomState},
    write::key::KeySerializer,
};
use types::OverlapCondition;
#[cfg(test)]
use utils::codec::leb128::Leb128Reader;

const MAX_TIME_SPAN: i64 = u32::MAX as i64;

impl CalendarEventData {
    pub fn new(ical: ICalendar, default_tz: Tz, max_expansions: usize) -> Self {
        Self::new_with_default_alerts(ical, default_tz, max_expansions, &DefaultAlerts::disabled())
    }

    pub fn new_with_default_alerts(
        ical: ICalendar,
        default_tz: Tz,
        max_expansions: usize,
        default_alerts: &DefaultAlerts,
    ) -> Self {
        let mut ranges = TimeRanges::default();

        let expanded = ical.expand_dates(default_tz, max_expansions);
        let mut groups: IndexMap<(u16, u16, u16, i32, RangeFlags), Vec<i64>, RandomState> =
            IndexMap::with_capacity_and_hasher(16, RandomState::default());
        let mut components: AHashMap<u16, (Vec<Alarm>, OverlapCondition)> =
            AHashMap::with_capacity(16);

        for event in expanded.events {
            let Ok(comp_id) = u16::try_from(event.comp_id) else {
                continue;
            };
            let start_tz = event.start.timezone().as_id();
            let end_tz = event.end.timezone().as_id();
            let (start_timestamp_utc, end_timestamp_utc) = event.timestamps();
            let (start_timestamp_naive, end_timestamp_naive) = event.naive_timestamps();

            let (_, condition) = components.entry(comp_id).or_insert_with(|| {
                // Expand alarms
                let alarms = ical
                    .component_by_id(event.comp_id)
                    .map_or(&[][..], |c| c.component_ids.as_slice())
                    .iter()
                    .filter_map(|alarm_id| {
                        let id = u16::try_from(*alarm_id).ok()?;
                        ical.component_by_id(*alarm_id).and_then(|alarm| {
                            if alarm.component_type == ICalendarComponentType::VAlarm
                                && (!default_alerts.is_enabled()
                                    || ical.is_kept_with_default_alerts(alarm, default_alerts))
                            {
                                alarm.expand_alarm(id, comp_id)
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                (alarms, ical.overlap_condition(event.comp_id))
            });
            let condition = condition.for_instance(start_timestamp_utc, end_timestamp_utc);

            ranges.update_base_offset(start_timestamp_naive, end_timestamp_naive);
            ranges.update_utc_min_max(
                std::cmp::min(start_timestamp_utc, end_timestamp_utc),
                std::cmp::max(start_timestamp_utc, end_timestamp_utc),
            );
            groups
                .entry((
                    start_tz,
                    end_tz,
                    comp_id,
                    (end_timestamp_naive - start_timestamp_naive)
                        .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                    RangeFlags::of(&event.start, &event.end).with_condition(condition),
                ))
                .or_default()
                .push(start_timestamp_naive);
        }

        let mut events = Vec::with_capacity(groups.len());
        for ((start_tz, end_tz, id, duration, flags), mut instances) in groups {
            instances.sort_unstable();
            instances.dedup();
            instances.truncate(instances.partition_point(|instance| {
                instance.saturating_sub(ranges.base_offset) <= MAX_TIME_SPAN
            }));

            let instances = match instances.len() {
                0 => continue,
                1 => KeySerializer::new(std::mem::size_of::<u32>())
                    .write_leb128((instances[0] - ranges.base_offset) as u32)
                    .finalize(),
                len => {
                    // Bitpack instances
                    let mut instance_offsets = Vec::with_capacity(len);
                    for instance in instances {
                        debug_assert!(instance >= ranges.base_offset);
                        instance_offsets.push((instance - ranges.base_offset) as u32);
                    }

                    KeySerializer::new(instance_offsets.len() * std::mem::size_of::<u32>())
                        .bitpack_sorted(&instance_offsets)
                        .finalize()
                }
            };

            events.push(ComponentTimeRange {
                id,
                start_tz,
                end_tz,
                duration,
                flags: flags.bits(),
                instances: instances.into_boxed_slice(),
            });
        }

        if !expanded.errors.is_empty() {
            trc::event!(
                Calendar(trc::CalendarEvent::RuleExpansionError),
                Reason = expanded
                    .errors
                    .into_iter()
                    .map(|e| e.error.to_compact_string())
                    .collect::<Vec<_>>(),
                Details = ical.to_compact_string(),
                Limit = max_expansions,
            );
        }

        CalendarEventData {
            event: ical,
            time_ranges: events.into_boxed_slice(),
            alarms: components
                .into_values()
                .flat_map(|(alarms, _)| alarms)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            base_offset: ranges.base_offset,
            base_time_utc: (ranges.min_time_utc - ranges.base_offset).clamp(0, MAX_TIME_SPAN)
                as u32,
            duration: (ranges.max_time_utc - ranges.min_time_utc).clamp(0, MAX_TIME_SPAN) as u32,
        }
    }

    pub fn event_range(&self) -> Option<(i64, u32)> {
        if self.base_offset != 0 {
            Some((self.base_offset + self.base_time_utc as i64, self.duration))
        } else {
            None
        }
    }
}

#[derive(Default, Debug)]
struct TimeRanges {
    max_time_utc: i64,
    min_time_utc: i64,
    base_offset: i64,
}

impl TimeRanges {
    pub fn update_base_offset(&mut self, t1: i64, t2: i64) {
        let offset = std::cmp::min(t1, t2);
        if offset < self.base_offset || self.base_offset == 0 {
            self.base_offset = offset;
        }
    }

    pub fn update_utc_min_max(&mut self, min: i64, max: i64) {
        if min < self.min_time_utc || self.min_time_utc == 0 {
            self.min_time_utc = min;
        }
        if max > self.max_time_utc {
            self.max_time_utc = max;
        }
        if min < self.base_offset || self.base_offset == 0 {
            self.base_offset = min;
        }
    }
}

impl ArchivedCalendarEventData {
    pub fn event_range(&self) -> Option<(i64, u32)> {
        if self.base_offset != 0 {
            Some((
                self.base_offset.to_native() + self.base_time_utc.to_native() as i64,
                self.duration.to_native(),
            ))
        } else {
            None
        }
    }

    pub fn event_range_start(&self) -> i64 {
        self.base_offset.to_native() + self.base_time_utc.to_native() as i64
    }

    pub fn event_range_end(&self) -> i64 {
        self.base_offset.to_native()
            + self.base_time_utc.to_native() as i64
            + self.duration.to_native() as i64
    }
}

impl CalendarEventData {
    pub fn event_range_start(&self) -> i64 {
        self.base_offset + self.base_time_utc as i64
    }

    pub fn event_range_end(&self) -> i64 {
        self.base_offset + self.base_time_utc as i64 + self.duration as i64
    }
}

impl Timezone {
    pub fn tz(&self) -> Option<Tz> {
        match self {
            Timezone::IANA(iana) => Tz::from_id(*iana),
            Timezone::Custom(icalendar) => icalendar
                .timezones()
                .filter_map(|t| t.timezone().map(|x| x.1))
                .next(),
            Timezone::Default => None,
        }
    }
}

impl ArchivedTimezone {
    pub fn tz(&self) -> Option<Tz> {
        match self {
            ArchivedTimezone::IANA(iana) => Tz::from_id(iana.to_native()),
            ArchivedTimezone::Custom(icalendar) => icalendar
                .timezones()
                .filter_map(|t| t.timezone().map(|x| x.1))
                .next(),
            ArchivedTimezone::Default => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::expand::NaiveTimestamp;
    use crate::calendar::{
        ALERT_WITH_TIME, CALENDAR_SUBSCRIBED, Calendar, CalendarEventData, CalendarPreferences,
        DefaultAlert, alerts::CalendarSettings,
    };
    use calcard::icalendar::ICalendarDuration;
    use jiff::civil::DateTime;

    const ALARMED_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:long-alarm\r\n",
        "DTSTART:20300310T100000Z\r\n",
        "DTEND:20300310T110000Z\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-P1D\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n",
    );

    fn utc(day: i8, hour: i8) -> i64 {
        DateTime::new(2030, 3, day, hour, 0, 0, 0)
            .expect("valid date")
            .naive_timestamp()
    }

    fn default_alerts(offset: i64) -> DefaultAlerts {
        let calendar = Calendar {
            preferences: vec![CalendarPreferences {
                account_id: 1,
                flags: CALENDAR_SUBSCRIBED,
                default_alerts: vec![DefaultAlert {
                    id: "d".to_string(),
                    offset: ICalendarDuration::from_seconds(offset),
                    flags: ALERT_WITH_TIME,
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        DefaultAlerts::merge(
            std::iter::once(&CalendarSettings::from(&calendar)),
            1,
            None,
            true,
        )
    }

    #[test]
    fn alarm_times_do_not_widen_the_event_range() {
        let parse = || ICalendar::parse(ALARMED_EVENT).expect("failed to parse fixture");

        let data = CalendarEventData::new(parse(), Tz::UTC, 100);
        assert_eq!(data.event_range_start(), utc(10, 10));
        assert_eq!(data.event_range_end(), utc(10, 11));
        assert_eq!(data.alarms.len(), 1);

        let data = CalendarEventData::new_with_default_alerts(
            parse(),
            Tz::UTC,
            100,
            &default_alerts(-172800),
        );
        assert_eq!(data.event_range_start(), utc(10, 10));
        assert_eq!(data.event_range_end(), utc(10, 11));
    }

    #[test]
    fn duplicate_expansion_offsets_round_trip() {
        // RDATE repeats DTSTART, so the expansion yields the same offset twice
        let ical = ICalendar::parse(concat!(
            "BEGIN:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:duplicate-offsets\r\n",
            "DTSTART:20240101T120000Z\r\n",
            "DTEND:20240101T130000Z\r\n",
            "RDATE:20240101T120000Z\r\n",
            "RDATE:20240102T120000Z\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n",
        ))
        .expect("failed to parse fixture");

        let data = CalendarEventData::new(ical, Tz::UTC, 100);

        for range in data.time_ranges.iter() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>().unwrap();

            if instances.len() > bytes_read {
                let decoded = store::write::bitpack::BitpackIterator::from_bytes_and_offset(
                    instances,
                    bytes_read,
                    offset_or_count,
                )
                .collect::<Vec<_>>();

                let mut sorted = decoded.clone();
                sorted.sort_unstable();
                sorted.dedup();
                assert_eq!(
                    decoded, sorted,
                    "expansion offsets must be strictly increasing"
                );
            }
        }
    }
}
