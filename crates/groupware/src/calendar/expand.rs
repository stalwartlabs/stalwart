/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AlarmDelta, ArchivedCalendarEventData};
use crate::calendar::CalendarEventData;
use ahash::AHashSet;
use calcard::{
    common::{
        DateTimeResult,
        timezone::{Tz, ZonedDateTime},
    },
    icalendar::{
        ArchivedICalendarComponent, ArchivedICalendarParameterName, ICalendarComponent,
        ICalendarParameterName, ICalendarProperty, ICalendarValue,
    },
};
use jiff::{SignedDuration, Timestamp, civil::DateTime};
use std::str::FromStr;
use store::write::bitpack::BitpackIterator;
use types::{OverlapCondition, OverlapRule, TimeRange};
use utils::codec::leb128::Leb128Reader;

const RECURRENCE_KEY_EPOCH: i64 = -2208988800;
const RECURRENCE_KEY_GRANULARITY: i64 = 60;
pub const SECONDS_PER_DAY: i64 = 86_400;
const NAIVE_EPOCH: DateTime = DateTime::constant(1970, 1, 1, 0, 0, 0, 0);
pub const MAX_UTC_OFFSET: i64 = SECONDS_PER_DAY;

pub trait NaiveTimestamp: Sized {
    fn naive_timestamp(&self) -> i64;

    fn from_naive_timestamp(timestamp: i64) -> Option<Self>;
}

impl NaiveTimestamp for DateTime {
    fn naive_timestamp(&self) -> i64 {
        self.duration_since(NAIVE_EPOCH).as_secs()
    }

    fn from_naive_timestamp(timestamp: i64) -> Option<Self> {
        NAIVE_EPOCH
            .checked_add(SignedDuration::from_secs(timestamp))
            .ok()
    }
}

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

    pub fn to_naive_timestamp(self) -> i64 {
        RECURRENCE_KEY_EPOCH + (self.0 as i64 - 1) * RECURRENCE_KEY_GRANULARITY
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

impl RecurrenceId {
    fn from_utc(utc: i64, tz: Tz) -> Option<Self> {
        Some(RecurrenceId {
            utc,
            naive: tz
                .from_timestamp(Timestamp::from_second(utc).ok()?)
                .naive_timestamp(),
        })
    }
}

pub trait ComponentRecurrenceId {
    fn recurrence_id(&self, fallback_tz: Tz) -> Option<RecurrenceId>;

    fn recurrence_tz(&self, fallback_tz: Tz) -> Option<Tz>;

    fn this_and_future_tz(&self, fallback_tz: Tz) -> Option<Tz>;
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

    fn recurrence_tz(&self, fallback_tz: Tz) -> Option<Tz> {
        self.property(&ICalendarProperty::RecurrenceId)
            .map(|entry| resolve_tz(entry.tz_id(), fallback_tz))
    }

    fn this_and_future_tz(&self, fallback_tz: Tz) -> Option<Tz> {
        let entry = self.property(&ICalendarProperty::RecurrenceId)?;
        entry
            .params
            .iter()
            .any(|param| param.name == ArchivedICalendarParameterName::Range)
            .then(|| resolve_tz(entry.tz_id(), fallback_tz))
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

    fn recurrence_tz(&self, fallback_tz: Tz) -> Option<Tz> {
        self.property(&ICalendarProperty::RecurrenceId)
            .map(|entry| resolve_tz(entry.tz_id(), fallback_tz))
    }

    fn this_and_future_tz(&self, fallback_tz: Tz) -> Option<Tz> {
        let entry = self.property(&ICalendarProperty::RecurrenceId)?;
        entry
            .params
            .iter()
            .any(|param| param.name == ICalendarParameterName::Range)
            .then(|| resolve_tz(entry.tz_id(), fallback_tz))
    }
}

fn resolve_tz(tz_id: Option<&str>, fallback_tz: Tz) -> Tz {
    tz_id
        .and_then(|tz_id| Tz::from_str(tz_id).ok())
        .unwrap_or(fallback_tz)
}

fn resolve_recurrence_id(
    tz_id: Option<&str>,
    date_time: DateTimeResult,
    fallback_tz: Tz,
) -> Option<RecurrenceId> {
    let tz = resolve_tz(tz_id, fallback_tz);
    let date_time = date_time.to_date_time_with_tz(tz)?.with_timezone(tz);

    Some(RecurrenceId {
        utc: date_time.timestamp(),
        naive: date_time.naive_timestamp(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecurrenceShift {
    tz: Tz,
    nominal: i64,
    exact: i64,
}

impl RecurrenceShift {
    pub(crate) fn new(
        tz: Tz,
        start_naive: i64,
        recurrence_id: RecurrenceId,
        recurrence_tz: Tz,
    ) -> Option<Self> {
        let recurrence_naive = if recurrence_tz == tz {
            recurrence_id.naive
        } else {
            RecurrenceId::from_utc(recurrence_id.utc, tz)?.naive
        };
        Some(RecurrenceShift {
            tz,
            nominal: start_naive - recurrence_naive,
            exact: resolve_local(tz, start_naive)? - recurrence_id.utc,
        })
    }

    pub(crate) fn recurrence_id(
        &self,
        tz: Tz,
        flags: RangeFlags,
        start_naive: i64,
        recurrence_tz: Tz,
    ) -> Option<RecurrenceId> {
        if tz == self.tz {
            let naive = start_naive - self.nominal;
            let utc = resolve_local(tz, naive)?;
            if recurrence_tz == tz {
                Some(RecurrenceId { utc, naive })
            } else {
                RecurrenceId::from_utc(utc, recurrence_tz)
            }
        } else {
            RecurrenceId::from_utc(
                flags.resolve_start(tz, start_naive)?.timestamp() - self.exact,
                recurrence_tz,
            )
        }
    }
}

#[derive(Debug, Default)]
struct ThisAndFutureShifts(Vec<(u32, RecurrenceShift)>);

impl ThisAndFutureShifts {
    fn recurrence_id(
        &mut self,
        comp_id: u32,
        flags: RangeFlags,
        own_recurrence_id: Option<RecurrenceId>,
        component_tz: Tz,
        start_naive: i64,
        recurrence_tz: Tz,
    ) -> Option<RecurrenceId> {
        match own_recurrence_id {
            Some(own_recurrence_id) => {
                self.0.extend(
                    RecurrenceShift::new(
                        component_tz,
                        start_naive,
                        own_recurrence_id,
                        recurrence_tz,
                    )
                    .map(|shift| (comp_id, shift)),
                );
                None
            }
            None => self
                .0
                .iter()
                .find(|(id, _)| *id == comp_id)
                .and_then(|(_, shift)| {
                    shift.recurrence_id(component_tz, flags, start_naive, recurrence_tz)
                }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarEventExpansion {
    pub comp_id: u32,
    pub own_recurrence_id: Option<RecurrenceId>,
    pub series_recurrence_id: Option<RecurrenceId>,
    pub start: i64,
    pub end: i64,
    pub start_naive: i64,
    pub end_naive: i64,
    pub start_tz: Tz,
    pub end_tz: Tz,
    pub flags: RangeFlags,
}

impl CalendarEventExpansion {
    pub fn alarm_time(&self, delta: &AlarmDelta, default_tz: Tz) -> Option<i64> {
        delta.to_timestamp(
            &self.flags.resolve_start(self.start_tz, self.start_naive)?,
            &self.flags.resolve_end(self.end_tz, self.end_naive)?,
            default_tz,
        )
    }

    pub fn recurrence_id(&self) -> RecurrenceId {
        self.own_recurrence_id
            .or(self.series_recurrence_id)
            .unwrap_or(RecurrenceId {
                utc: self.start,
                naive: self.start_naive,
            })
    }

    pub fn recurrence_key(&self) -> Option<RecurrenceKey> {
        RecurrenceKey::from_recurrence_id(self.recurrence_id().naive)
    }
}

impl ArchivedCalendarEventData {
    pub fn component_tz(&self, comp_id: u32) -> Option<Tz> {
        self.time_ranges
            .iter()
            .find(|range| range.id.to_native() as u32 == comp_id)
            .and_then(|range| Tz::from_id(range.start_tz.to_native()))
    }

    pub fn expand(
        &self,
        default_tz: Tz,
        limit: TimeRange,
        rule: OverlapRule,
    ) -> Option<Vec<CalendarEventExpansion>> {
        let mut expansion = Vec::with_capacity(self.time_ranges.len());
        let base_offset = self.base_offset.to_native();
        let mut shifts = ThisAndFutureShifts::default();

        'outer: for (range_index, range) in self.time_ranges.iter().enumerate() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;

            let comp_id = range.id.to_native() as u32;
            let component = self.event.components.get(comp_id as usize)?;
            let duration = range.duration.to_native() as i64;
            let flags = RangeFlags::from_bits(range.flags);
            let condition = flags.condition();
            let component_tz = Tz::from_id(range.start_tz.to_native())?;
            let mut own_recurrence_id = self
                .time_ranges
                .iter()
                .take(range_index)
                .all(|prior| prior.id != range.id)
                .then(|| component.recurrence_id(component_tz))
                .flatten();
            let this_and_future_tz = component.this_and_future_tz(component_tz);
            let mut start_tz = component_tz;
            let mut end_tz = Tz::from_id(range.end_tz.to_native())?;

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
                    let series_recurrence_id = this_and_future_tz.and_then(|recurrence_tz| {
                        shifts.recurrence_id(
                            comp_id,
                            flags,
                            own_recurrence_id,
                            component_tz,
                            start_date_naive,
                            recurrence_tz,
                        )
                    });
                    let (Some(start), Some(end)) = (
                        flags.resolve_start(start_tz, start_date_naive),
                        flags.resolve_end(end_tz, end_date_naive),
                    ) else {
                        continue;
                    };
                    let (start, end) = (start.timestamp(), end.timestamp());

                    if limit.matches(rule, condition, start, end) {
                        expansion.push(CalendarEventExpansion {
                            comp_id,
                            own_recurrence_id,
                            series_recurrence_id,
                            start,
                            end,
                            start_naive: start_date_naive,
                            end_naive: end_date_naive,
                            start_tz,
                            end_tz,
                            flags,
                        });
                    } else if start > limit.end {
                        continue 'outer;
                    }
                }
            } else {
                let start_date_naive = offset_or_count as i64 + base_offset;
                let end_date_naive = start_date_naive + duration;
                let series_recurrence_id = this_and_future_tz.and_then(|recurrence_tz| {
                    shifts.recurrence_id(
                        comp_id,
                        flags,
                        own_recurrence_id,
                        component_tz,
                        start_date_naive,
                        recurrence_tz,
                    )
                });
                if let (Some(start), Some(end)) = (
                    flags.resolve_start(start_tz, start_date_naive),
                    flags.resolve_end(end_tz, end_date_naive),
                ) && limit.matches(rule, condition, start.timestamp(), end.timestamp())
                {
                    expansion.push(CalendarEventExpansion {
                        comp_id,
                        own_recurrence_id,
                        series_recurrence_id,
                        start: start.timestamp(),
                        end: end.timestamp(),
                        start_naive: start_date_naive,
                        end_naive: end_date_naive,
                        start_tz,
                        end_tz,
                        flags,
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
        let mut shifts = ThisAndFutureShifts::default();

        for (range_index, range) in self.time_ranges.iter().enumerate() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;
            let comp_id = range.id as u32;
            let component = self.event.components.get(comp_id as usize)?;
            let duration = range.duration as i64;
            let flags = RangeFlags::from_bits(range.flags);
            let component_tz = Tz::from_id(range.start_tz)?;
            let mut own_recurrence_id = self
                .time_ranges
                .iter()
                .take(range_index)
                .all(|prior| prior.id != range.id)
                .then(|| component.recurrence_id(component_tz))
                .flatten();
            let this_and_future_tz = component.this_and_future_tz(component_tz);
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
                let series_recurrence_id = this_and_future_tz.and_then(|recurrence_tz| {
                    shifts.recurrence_id(
                        comp_id,
                        flags,
                        own_recurrence_id,
                        component_tz,
                        start_date_naive,
                        recurrence_tz,
                    )
                });
                let recurrence_id_naive = own_recurrence_id
                    .or(series_recurrence_id)
                    .map_or(start_date_naive, |recurrence_id| recurrence_id.naive);
                if RecurrenceKey::from_recurrence_id(recurrence_id_naive)
                    .is_none_or(|key| !keys.contains(&key))
                {
                    return;
                }

                let end_date_naive = start_date_naive + duration;
                if let (Some(start), Some(end)) = (
                    flags.resolve_start(start_tz, start_date_naive),
                    flags.resolve_end(end_tz, end_date_naive),
                ) {
                    expansion.push(CalendarEventExpansion {
                        comp_id,
                        own_recurrence_id,
                        series_recurrence_id,
                        start: start.timestamp(),
                        end: end.timestamp(),
                        start_naive: start_date_naive,
                        end_naive: end_date_naive,
                        start_tz,
                        end_tz,
                        flags,
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

    pub fn expand_base(&self, default_tz: Tz) -> Option<CalendarEventExpansion> {
        let (comp_id, component) = self
            .event
            .components
            .iter()
            .enumerate()
            .filter(|(_, component)| component.component_type.is_scheduling_object())
            .min_by_key(|(_, component)| component.is_recurrence_override())?;
        let comp_id = comp_id as u32;
        let dtstart = component.property(&ICalendarProperty::Dtstart)?;
        let start = dtstart.values.first()?.as_partial_date_time()?;
        let start_date_time = start.to_date_time()?;
        let start_date_naive = start_date_time.date_time.naive_timestamp();
        let effective_tz = |tz: Tz| {
            if tz.is_floating() && !default_tz.is_floating() {
                default_tz
            } else {
                tz
            }
        };
        let (component_tz, end_zoned) = match self
            .time_ranges
            .iter()
            .find(|range| range.id as u32 == comp_id)
        {
            Some(range) => (
                Tz::from_id(range.start_tz)?,
                RangeFlags::from_bits(range.flags).resolve_end(
                    effective_tz(Tz::from_id(range.end_tz)?),
                    start_date_naive + range.duration as i64,
                )?,
            ),
            None => {
                let resolver = self.event.build_tz_resolver();
                let start_tz = start_date_time
                    .tz()
                    .unwrap_or_else(|| resolver.resolve_or_default(dtstart.tz_id()));
                let dtend = component.property(&ICalendarProperty::Dtend);
                let end = dtend
                    .and_then(|entry| entry.values.first())
                    .and_then(ICalendarValue::as_partial_date_time)
                    .and_then(|value| value.to_date_time());
                let end_tz = end
                    .as_ref()
                    .and_then(|end| end.tz())
                    .or_else(|| {
                        dtend
                            .and_then(|entry| entry.tz_id())
                            .map(|tz_id| resolver.resolve_or_default(Some(tz_id)))
                    })
                    .unwrap_or(start_tz);
                let end = match (
                    end,
                    component
                        .property(&ICalendarProperty::Duration)
                        .and_then(|entry| entry.values.first()),
                ) {
                    (Some(end), _) => effective_tz(end_tz).from_local(end.date_time)?,
                    (None, Some(ICalendarValue::Duration(duration))) => effective_tz(start_tz)
                        .from_local(start_date_time.date_time)?
                        .checked_add_nominal(duration.to_nominal()?)?,
                    (None, _) if !start.has_time() => resolve_local_zoned(
                        effective_tz(end_tz),
                        start_date_naive + SECONDS_PER_DAY,
                    )?,
                    (None, _) => resolve_local_zoned(effective_tz(end_tz), start_date_naive)?,
                };
                (start_tz, end)
            }
        };
        let start_zoned = resolve_local_zoned(effective_tz(component_tz), start_date_naive)?;

        Some(CalendarEventExpansion {
            comp_id,
            own_recurrence_id: component.recurrence_id(component_tz),
            series_recurrence_id: None,
            start: start_zoned.timestamp(),
            end: end_zoned.timestamp(),
            start_naive: start_date_naive,
            end_naive: end_zoned.naive_timestamp(),
            start_tz: start_zoned.timezone(),
            end_tz: end_zoned.timezone(),
            flags: RangeFlags::of(&start_zoned, &end_zoned),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RangeFlags(u8);

impl RangeFlags {
    const LATER_START: u8 = 1;
    const LATER_END: u8 = 1 << 1;
    const CONDITION_SHIFT: u8 = 2;
    const CONDITION_MASK: u8 = 0b111 << Self::CONDITION_SHIFT;

    pub fn of(start: &ZonedDateTime, end: &ZonedDateTime) -> Self {
        let mut flags = RangeFlags::default();
        if Self::is_later(start) {
            flags.0 |= Self::LATER_START;
        }
        if Self::is_later(end) {
            flags.0 |= Self::LATER_END;
        }
        flags
    }

    pub fn with_condition(self, condition: OverlapCondition) -> Self {
        RangeFlags(
            (self.0 & !Self::CONDITION_MASK)
                | (((condition as u8) << Self::CONDITION_SHIFT) & Self::CONDITION_MASK),
        )
    }

    pub fn condition(self) -> OverlapCondition {
        OverlapCondition::ALL
            .get(usize::from(
                (self.0 & Self::CONDITION_MASK) >> Self::CONDITION_SHIFT,
            ))
            .copied()
            .unwrap_or_default()
    }

    pub fn from_bits(bits: u8) -> Self {
        RangeFlags(bits)
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn resolve_start(self, tz: Tz, naive_secs: i64) -> Option<ZonedDateTime> {
        self.resolve(Self::LATER_START, tz, naive_secs)
    }

    pub fn resolve_end(self, tz: Tz, naive_secs: i64) -> Option<ZonedDateTime> {
        self.resolve(Self::LATER_END, tz, naive_secs)
    }

    fn resolve(self, flag: u8, tz: Tz, naive_secs: i64) -> Option<ZonedDateTime> {
        let local = DateTime::from_naive_timestamp(naive_secs)?;
        if self.0 & flag != 0 {
            tz.from_local_later(local)
        } else {
            tz.from_local(local)
        }
    }

    fn is_later(date_time: &ZonedDateTime) -> bool {
        date_time
            .timezone()
            .from_local(date_time.naive_local())
            .is_some_and(|earlier| earlier.timestamp() < date_time.timestamp())
    }
}

pub fn resolve_local(tz: Tz, naive_secs: i64) -> Option<i64> {
    resolve_local_zoned(tz, naive_secs).map(|dt| dt.timestamp())
}

pub fn resolve_local_zoned(tz: Tz, naive_secs: i64) -> Option<ZonedDateTime> {
    tz.from_local(DateTime::from_naive_timestamp(naive_secs)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::alarm::EventAlarmData;
    use calcard::{Entry, Parser};

    fn naive(year: i16, month: i8, day: i8, hour: i8, minute: i8, second: i8) -> i64 {
        DateTime::new(year, month, day, hour, minute, second, 0)
            .expect("valid date")
            .naive_timestamp()
    }

    fn key(year: i16, month: i8, day: i8, hour: i8, minute: i8) -> RecurrenceKey {
        RecurrenceKey::from_recurrence_id(naive(year, month, day, hour, minute, 0))
            .expect("representable recurrence id")
    }

    #[test]
    fn local_times_in_a_dst_gap_resolve_to_the_offset_before_the_gap() {
        let new_york = Tz::from_str("America/New_York").expect("known time zone");
        assert_eq!(
            resolve_local(new_york, naive(2026, 3, 8, 2, 30, 0)),
            Some(naive(2026, 3, 8, 7, 30, 0)),
        );
        assert_eq!(
            resolve_local(new_york, naive(2026, 11, 1, 1, 30, 0)),
            Some(naive(2026, 11, 1, 5, 30, 0)),
        );
        assert_eq!(
            resolve_local(new_york, naive(2026, 6, 1, 12, 0, 0)),
            Some(naive(2026, 6, 1, 16, 0, 0)),
        );
    }

    fn event_data(ical: &str) -> CalendarEventData {
        let entry = Parser::new(ical).entry();
        let Entry::ICalendar(ical) = entry else {
            panic!("failed to parse iCalendar: {entry:?}");
        };
        CalendarEventData::new(ical, Tz::UTC, 1000)
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
            expand_key(&data, key(2027, 3, 22, 9, 0)),
            [(2, naive(2027, 3, 22, 10, 0, 0))]
        );
        assert_eq!(
            expand_key(&data, key(2027, 3, 29, 9, 0)),
            [(2, naive(2027, 3, 29, 10, 0, 0))]
        );
        assert_eq!(
            expand_key(&data, key(2027, 3, 1, 9, 0)),
            [(1, naive(2027, 3, 1, 9, 0, 0))]
        );
        for moved_start in [key(2027, 3, 22, 10, 0), key(2027, 3, 29, 10, 0)] {
            assert_eq!(expand_key(&data, moved_start), []);
        }

        let archived = rkyv::to_bytes::<rkyv::rancor::Error>(&data).expect("archive");
        let archived = rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&archived)
            .expect("access");
        let expanded = archived
            .expand(
                Tz::UTC,
                TimeRange::new(i64::MIN, i64::MAX),
                OverlapRule::CalDav,
            )
            .expect("expansion")
            .into_iter()
            .map(|expansion| {
                (
                    expansion.recurrence_id().naive,
                    expansion.start_naive,
                    expansion.own_recurrence_id.is_some(),
                )
            })
            .collect::<Vec<_>>();
        for expected in [
            (
                naive(2027, 3, 15, 9, 0, 0),
                naive(2027, 3, 15, 10, 0, 0),
                true,
            ),
            (
                naive(2027, 3, 22, 9, 0, 0),
                naive(2027, 3, 22, 10, 0, 0),
                false,
            ),
            (
                naive(2027, 3, 29, 9, 0, 0),
                naive(2027, 3, 29, 10, 0, 0),
                false,
            ),
        ] {
            assert!(expanded.contains(&expected), "{expected:?} in {expanded:?}");
        }
    }

    #[test]
    fn base_expansion_starts_at_dtstart() {
        const EXCLUDED_FIRST: &str = concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
            "BEGIN:VEVENT\r\nUID:u@example.com\r\nDTSTAMP:20270101T000000Z\r\n",
            "DTSTART;TZID=Europe/Berlin:20270301T090000\r\nDURATION:PT90M\r\n",
            "RRULE:FREQ=WEEKLY;COUNT=5\r\nEXDATE;TZID=Europe/Berlin:20270301T090000\r\n",
            "SUMMARY:Weekly\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let data = event_data(EXCLUDED_FIRST);
        let base = data.expand_base(Tz::UTC).expect("base expansion");
        assert_eq!(base.start_naive, naive(2027, 3, 1, 9, 0, 0));
        assert_eq!(base.start, naive(2027, 3, 1, 8, 0, 0));
        assert_eq!(base.end, naive(2027, 3, 1, 9, 30, 0));

        const FLOATING: &str = concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
            "BEGIN:VEVENT\r\nUID:f@example.com\r\nDTSTAMP:20270101T000000Z\r\n",
            "DTSTART;VALUE=DATE:20270301\r\nDTEND;VALUE=DATE:20270302\r\n",
            "SUMMARY:All day\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let Entry::ICalendar(ical) = Parser::new(FLOATING).entry() else {
            panic!("failed to parse iCalendar");
        };
        let data = CalendarEventData::new(ical, Tz::Floating, 1000);
        let tokyo = Tz::from_str("Asia/Tokyo").expect("time zone");
        let base = data.expand_base(tokyo).expect("base expansion");
        assert_eq!(base.start, naive(2027, 2, 28, 15, 0, 0));
        assert_eq!(base.end, naive(2027, 3, 1, 15, 0, 0));

        const WITHOUT_INSTANCES: &str = concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
            "BEGIN:VEVENT\r\nUID:e@example.com\r\nDTSTAMP:20270101T000000Z\r\n",
            "DTSTART;TZID=Europe/Berlin:20270301T090000\r\n",
            "DTEND;TZID=Europe/Berlin:20270301T103000\r\n",
            "RRULE:FREQ=DAILY;COUNT=1\r\nEXDATE;TZID=Europe/Berlin:20270301T090000\r\n",
            "SUMMARY:Excluded\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        );
        let data = event_data(WITHOUT_INSTANCES);
        assert!(data.time_ranges.is_empty());
        let base = data.expand_base(Tz::UTC).expect("base expansion");
        assert_eq!(base.start, naive(2027, 3, 1, 8, 0, 0));
        assert_eq!(base.end, naive(2027, 3, 1, 9, 30, 0));
    }

    #[test]
    fn utc_recurrences_ignore_the_default_time_zone() {
        let Entry::ICalendar(ical) = Parser::new(&format!("{MASTER}END:VCALENDAR\r\n")).entry()
        else {
            panic!("failed to parse iCalendar");
        };
        let data = CalendarEventData::new(ical, Tz::Floating, 1000);
        let berlin = Tz::from_str("Europe/Berlin").expect("time zone");
        let mut keys = AHashSet::from_iter([key(2027, 3, 8, 9, 0)]);
        let expansion = data.expand_from_ids(&mut keys, berlin).expect("expansion");
        assert_eq!(
            expansion
                .iter()
                .map(|expansion| (expansion.start, expansion.end))
                .collect::<Vec<_>>(),
            [(naive(2027, 3, 8, 9, 0, 0), naive(2027, 3, 8, 10, 0, 0))]
        );

        let archived = rkyv::to_bytes::<rkyv::rancor::Error>(&data).expect("archive");
        let archived = rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&archived)
            .expect("access");
        let expansion = archived
            .expand(
                berlin,
                TimeRange::new(naive(2027, 3, 1, 0, 0, 0), naive(2027, 3, 2, 0, 0, 0)),
                OverlapRule::CalDav,
            )
            .expect("expansion");
        assert_eq!(
            expansion
                .iter()
                .map(|expansion| expansion.start)
                .collect::<Vec<_>>(),
            [naive(2027, 3, 1, 9, 0, 0)]
        );
        assert_eq!(
            data.expand_base(berlin).map(|expansion| expansion.start),
            Some(naive(2027, 3, 1, 9, 0, 0))
        );
    }

    const REPEATED_HOUR: &str = concat!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
        "BEGIN:VEVENT\r\nUID:d@example.com\r\nDTSTAMP:20261001T000000Z\r\n",
        "DTSTART;TZID=America/New_York:20261101T013000\r\nDURATION:PT1H\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:s@example.com\r\nDTSTAMP:20261001T000000Z\r\n",
        "DTSTART;TZID=America/New_York:20261030T013000\r\n",
        "DTEND;TZID=America/New_York:20261030T020000\r\n",
        "RRULE:FREQ=DAILY;COUNT=4\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:m@example.com\r\nDTSTAMP:20261001T000000Z\r\n",
        "DTSTART;TZID=America/New_York:20261029T013000\r\nDURATION:PT30M\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:m@example.com\r\nDTSTAMP:20261001T000000Z\r\n",
        "RECURRENCE-ID;TZID=America/New_York;RANGE=THISANDFUTURE:20261030T013000\r\n",
        "DTSTART;TZID=Europe/London:20261030T063000\r\nDURATION:PT30M\r\n",
        "END:VEVENT\r\nEND:VCALENDAR\r\n",
    );

    #[test]
    fn readings_in_the_second_pass_of_a_repeated_hour_keep_their_instant() {
        let data = event_data(REPEATED_HOUR);
        let mut expected = data
            .event
            .expand_dates(Tz::UTC, 1000)
            .events
            .iter()
            .map(|event| {
                (
                    event.comp_id,
                    event.start.timestamp(),
                    event.end.timestamp(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort_unstable();
        for second_pass in [
            (
                1,
                naive(2026, 11, 1, 5, 30, 0),
                naive(2026, 11, 1, 6, 30, 0),
            ),
            (2, naive(2026, 11, 1, 5, 30, 0), naive(2026, 11, 1, 6, 0, 0)),
            (4, naive(2026, 11, 1, 6, 30, 0), naive(2026, 11, 1, 7, 0, 0)),
        ] {
            assert!(
                expected.contains(&second_pass),
                "{second_pass:?} in {expected:?}"
            );
        }

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&data).expect("archive");
        let archived =
            rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&bytes).expect("access");
        let expansion = archived
            .expand(
                Tz::UTC,
                TimeRange::new(i64::MIN, i64::MAX),
                OverlapRule::CalDav,
            )
            .expect("expansion");
        let instants = |expansion: &[CalendarEventExpansion]| {
            let mut instants = expansion
                .iter()
                .map(|expansion| (expansion.comp_id, expansion.start, expansion.end))
                .collect::<Vec<_>>();
            instants.sort_unstable();
            instants
        };
        assert_eq!(instants(&expansion), expected);

        let mut keys = expansion
            .iter()
            .filter_map(|expansion| expansion.recurrence_key())
            .collect::<AHashSet<_>>();
        let from_ids = data.expand_from_ids(&mut keys, Tz::UTC).expect("expansion");
        assert_eq!(instants(&from_ids), expected);

        let base = data.expand_base(Tz::UTC).expect("base expansion");
        assert_eq!(
            (base.start, base.end),
            (naive(2026, 11, 1, 5, 30, 0), naive(2026, 11, 1, 6, 30, 0))
        );
    }

    const WALL_CLOCK_SHIFT: &str = concat!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n",
        "BEGIN:VEVENT\r\nUID:w@example.com\r\nDTSTAMP:20260301T000000Z\r\n",
        "DTSTART;TZID=America/New_York:20260306T230000\r\nDURATION:PT30M\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\nEND:VEVENT\r\n",
        "BEGIN:VEVENT\r\nUID:w@example.com\r\nDTSTAMP:20260301T000000Z\r\n",
        "RECURRENCE-ID;TZID=America/New_York;RANGE=THISANDFUTURE:20260307T230000\r\n",
        "DTSTART;TZID=America/New_York:20260308T030000\r\nDURATION:PT30M\r\n",
        "END:VEVENT\r\nEND:VCALENDAR\r\n",
    );

    fn expand_all(data: &CalendarEventData) -> Vec<CalendarEventExpansion> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(data).expect("archive");
        rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&bytes)
            .expect("access")
            .expand(
                Tz::UTC,
                TimeRange::new(i64::MIN, i64::MAX),
                OverlapRule::CalDav,
            )
            .expect("expansion")
    }

    fn recurrence_ids(data: &CalendarEventData, comp_id: u32) -> Vec<(i64, i64)> {
        let mut ids = expand_all(data)
            .into_iter()
            .filter(|expansion| expansion.comp_id == comp_id)
            .map(|expansion| (expansion.start_naive, expansion.recurrence_id().naive))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn this_and_future_recurrence_ids_undo_the_shift_calcard_applied() {
        let wall_clock = event_data(WALL_CLOCK_SHIFT);
        assert_eq!(
            recurrence_ids(&wall_clock, 2),
            [
                (naive(2026, 3, 8, 3, 0, 0), naive(2026, 3, 7, 23, 0, 0)),
                (naive(2026, 3, 9, 3, 0, 0), naive(2026, 3, 8, 23, 0, 0)),
                (naive(2026, 3, 10, 3, 0, 0), naive(2026, 3, 9, 23, 0, 0)),
                (naive(2026, 3, 11, 3, 0, 0), naive(2026, 3, 10, 23, 0, 0)),
            ]
        );
        assert_eq!(
            expand_key(&wall_clock, key(2026, 3, 9, 23, 0)),
            [(2, naive(2026, 3, 10, 3, 0, 0))]
        );

        let exact = event_data(REPEATED_HOUR);
        assert_eq!(
            recurrence_ids(&exact, 4),
            [
                (naive(2026, 10, 30, 6, 30, 0), naive(2026, 10, 30, 1, 30, 0)),
                (naive(2026, 10, 31, 2, 30, 0), naive(2026, 10, 31, 1, 30, 0)),
                (naive(2026, 11, 1, 1, 30, 0), naive(2026, 11, 1, 1, 30, 0)),
                (naive(2026, 11, 2, 2, 30, 0), naive(2026, 11, 2, 1, 30, 0)),
            ]
        );
        assert_eq!(
            expand_key(&exact, key(2026, 10, 31, 1, 30)),
            [
                (2, naive(2026, 10, 31, 1, 30, 0)),
                (4, naive(2026, 10, 31, 2, 30, 0))
            ]
        );
    }

    #[test]
    fn alarm_recurrence_ids_match_the_expansion() {
        for ical in [WALL_CLOCK_SHIFT, REPEATED_HOUR] {
            let data = event_data(ical);
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&data).expect("archive");
            let archived = rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&bytes)
                .expect("access");
            let expansions = archived
                .expand(
                    Tz::UTC,
                    TimeRange::new(i64::MIN, i64::MAX),
                    OverlapRule::CalDav,
                )
                .expect("expansion");
            assert!(!expansions.is_empty());
            for expansion in expansions {
                let comp_id = expansion.comp_id as u16;
                let expected = data
                    .event
                    .components
                    .get(expansion.comp_id as usize)
                    .is_some_and(ICalendarComponent::is_recurrent_or_override)
                    .then(|| expansion.recurrence_id().naive);
                for recurrence in [
                    data.component_recurrence(comp_id, expansion.start_tz, expansion.flags),
                    archived.component_recurrence(comp_id, expansion.start_tz, expansion.flags),
                ] {
                    assert_eq!(
                        recurrence.recurrence_id(expansion.start_naive),
                        expected,
                        "{expansion:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn range_flags_keep_the_overlap_condition_apart_from_the_offset_choice() {
        for later in [
            0,
            RangeFlags::LATER_START,
            RangeFlags::LATER_END,
            RangeFlags::LATER_START | RangeFlags::LATER_END,
        ] {
            for condition in OverlapCondition::ALL {
                let flags = RangeFlags(later).with_condition(condition);
                assert_eq!(
                    RangeFlags::from_bits(flags.bits()).condition(),
                    condition,
                    "{later:#b}"
                );
                assert_eq!(
                    flags.0 & (RangeFlags::LATER_START | RangeFlags::LATER_END),
                    later
                );
                assert_eq!(
                    flags
                        .with_condition(OverlapCondition::Event)
                        .with_condition(condition),
                    flags
                );
            }
        }
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
