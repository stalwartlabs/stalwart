/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Alarm, AlarmDelta, ArchivedAlarmDelta, ArchivedCalendarEventData};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarComponent, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarRelated, ICalendarValue,
    },
};
use chrono::{DateTime, TimeZone};
use std::str::FromStr;
use store::write::bitpack::BitpackIterator;
use utils::codec::leb128::Leb128Reader;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CalendarAlarm {
    pub alarm_id: u16,
    pub event_id: u16,
    pub alarm_time: i64,
    pub typ: CalendarAlarmType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CalendarAlarmType {
    Email {
        event_start: i64,
        event_start_tz: u16,
        event_end: i64,
        event_end_tz: u16,
    },
    Display {
        recurrence_id: Option<i64>,
    },
}

impl ArchivedCalendarEventData {
    pub fn next_alarm(&self, start_time: i64, default_tz: Tz) -> Option<CalendarAlarm> {
        if self.alarms.is_empty() {
            return None;
        }

        let base_offset = self.base_offset.to_native();
        let mut next_alarm: Option<CalendarAlarm> = None;

        'outer: for range in self.time_ranges.iter() {
            let comp_id = range.id.to_native();
            let Some(alarm) = self.alarms.iter().find(|a| a.parent_id == comp_id) else {
                continue;
            };

            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;

            let duration = range.duration.to_native() as i64;
            let mut start_tz = Tz::from_id(range.start_tz.to_native())?;
            let mut end_tz = Tz::from_id(range.end_tz.to_native())?;

            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            if instances.len() > bytes_read {
                // Recurring event
                let unpacker =
                    BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
                for start_offset in unpacker {
                    let start_date_naive = start_offset as i64 + base_offset;
                    let end_date_naive = start_date_naive + duration;
                    let start = start_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();
                    let end = end_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();

                    if let Some(alarm_time) = alarm.delta.to_timestamp(start, end, default_tz)
                        && alarm_time > start_time
                        && next_alarm
                            .as_ref()
                            .is_none_or(|next| alarm_time < next.alarm_time)
                    {
                        next_alarm = Some(CalendarAlarm {
                            alarm_id: alarm.id.to_native(),
                            event_id: alarm.parent_id.to_native(),
                            alarm_time,
                            typ: if alarm.is_email_alert {
                                CalendarAlarmType::Email {
                                    event_start: start_date_naive,
                                    event_start_tz: start_tz.as_id(),
                                    event_end: end_date_naive,
                                    event_end_tz: end_tz.as_id(),
                                }
                            } else {
                                let comp =
                                    &self.event.components[alarm.parent_id.to_native() as usize];

                                CalendarAlarmType::Display {
                                    recurrence_id: if comp.is_recurrent_or_override() {
                                        start_date_naive.into()
                                    } else {
                                        None
                                    },
                                }
                            },
                        });
                        continue 'outer;
                    }
                }
            } else {
                // Single event
                let start_date_naive = offset_or_count as i64 + base_offset;
                let end_date_naive = start_date_naive + duration;
                let start = start_tz
                    .from_local_datetime(
                        &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                    )
                    .single()?
                    .timestamp();
                let end = end_tz
                    .from_local_datetime(
                        &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                    )
                    .single()?
                    .timestamp();

                if let Some(alarm_time) = alarm.delta.to_timestamp(start, end, default_tz)
                    && alarm_time > start_time
                    && next_alarm
                        .as_ref()
                        .is_none_or(|next| alarm_time < next.alarm_time)
                {
                    next_alarm = Some(CalendarAlarm {
                        alarm_id: alarm.id.to_native(),
                        event_id: alarm.parent_id.to_native(),
                        alarm_time,
                        typ: if alarm.is_email_alert {
                            CalendarAlarmType::Email {
                                event_start: start_date_naive,
                                event_start_tz: start_tz.as_id(),
                                event_end: end_date_naive,
                                event_end_tz: end_tz.as_id(),
                            }
                        } else {
                            let comp = &self.event.components[alarm.parent_id.to_native() as usize];

                            CalendarAlarmType::Display {
                                recurrence_id: if comp.is_recurrent_or_override() {
                                    start_date_naive.into()
                                } else {
                                    None
                                },
                            }
                        },
                    });
                }
            }
        }

        next_alarm
    }
}

pub trait ExpandAlarm {
    fn expand_alarm(&self, id: u16, parent_id: u16) -> Option<Alarm>;
}

impl ExpandAlarm for ICalendarComponent {
    fn expand_alarm(&self, id: u16, parent_id: u16) -> Option<Alarm> {
        let mut trigger = None;
        let mut is_email_alert = false;

        for entry in self.entries.iter() {
            match &entry.name {
                ICalendarProperty::Trigger => {
                    let mut tz = None;
                    let mut trigger_start = true;

                    for param in entry.params.iter() {
                        match (&param.name, &param.value) {
                            (
                                ICalendarParameterName::Related,
                                ICalendarParameterValue::Related(related),
                            ) => {
                                trigger_start = matches!(related, ICalendarRelated::Start);
                            }
                            (
                                ICalendarParameterName::Tzid,
                                ICalendarParameterValue::Text(tz_id),
                            ) => {
                                tz = Tz::from_str(tz_id).ok();
                            }
                            _ => {}
                        }
                    }

                    trigger = match entry.values.first()? {
                        ICalendarValue::PartialDateTime(dt) => {
                            let tz = tz.unwrap_or(Tz::Floating);

                            dt.to_date_time_with_tz(tz).map(|dt| {
                                let timestamp = dt.timestamp();
                                if !dt.timezone().is_floating() {
                                    AlarmDelta::FixedUtc(timestamp)
                                } else {
                                    AlarmDelta::FixedFloating(timestamp)
                                }
                            })
                        }
                        ICalendarValue::Duration(duration) => {
                            if trigger_start {
                                Some(AlarmDelta::Start(duration.as_seconds()))
                            } else {
                                Some(AlarmDelta::End(duration.as_seconds()))
                            }
                        }
                        _ => None,
                    };
                }
                ICalendarProperty::Action => {
                    is_email_alert = is_email_alert
                        || entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .is_some_and(|v| v.eq_ignore_ascii_case("email"));
                }
                ICalendarProperty::Summary | ICalendarProperty::Description => {
                    is_email_alert = is_email_alert
                        || entry
                            .values
                            .first()
                            .and_then(|v| v.as_text())
                            .is_some_and(|v| v.contains("@email"));
                }
                _ => {}
            }
        }

        trigger.map(|delta| Alarm {
            id,
            parent_id,
            delta,
            is_email_alert,
        })
    }
}

impl AlarmDelta {
    pub fn to_timestamp(&self, start: i64, end: i64, default_tz: Tz) -> Option<i64> {
        match self {
            AlarmDelta::Start(delta) => Some(start + delta),
            AlarmDelta::End(delta) => Some(end + delta),
            AlarmDelta::FixedUtc(timestamp) => Some(*timestamp),
            AlarmDelta::FixedFloating(timestamp) => default_tz
                .from_local_datetime(&DateTime::from_timestamp(*timestamp, 0)?.naive_local())
                .single()
                .map(|dt| dt.timestamp()),
        }
    }
}

impl ArchivedAlarmDelta {
    pub fn to_timestamp(&self, start: i64, end: i64, default_tz: Tz) -> Option<i64> {
        match self {
            ArchivedAlarmDelta::Start(delta) => Some(start + delta.to_native()),
            ArchivedAlarmDelta::End(delta) => Some(end + delta.to_native()),
            ArchivedAlarmDelta::FixedUtc(timestamp) => Some(timestamp.to_native()),
            ArchivedAlarmDelta::FixedFloating(timestamp) => default_tz
                .from_local_datetime(
                    &DateTime::from_timestamp(timestamp.to_native(), 0)?.naive_local(),
                )
                .single()
                .map(|dt| dt.timestamp()),
        }
    }
}
