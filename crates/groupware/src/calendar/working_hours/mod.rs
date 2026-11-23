/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod ical;

use calcard::common::timezone::Tz;
use common::{Server, auth::AccountCache};
use jiff::{
    Timestamp,
    civil::{Date, DateTime, Time},
};
use registry::{
    schema::{
        enums::{TimeZone, Weekday},
        prelude::{Object, ObjectInner, ObjectType},
        structs::{Account, CalendarSettings, WorkingHours},
    },
    types::{EnumImpl, id::ObjectId},
};
use std::fmt::Display;
use store::{
    registry::write::{RegistryWrite, RegistryWriteResult},
    write::now,
};
use trc::AddContext;
use types::id::Id;

pub const MAX_WORKING_HOURS_SLOTS: usize = 14;
pub const MINUTES_PER_DAY: u16 = 1440;
const LAST_MINUTE_OF_DAY: u16 = MINUTES_PER_DAY - 1;
const DAYS_PER_WEEK: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkingHoursError {
    TooManySlots,
    NoDays { slot: usize },
    DuplicateDay { slot: usize },
    InvalidInterval { slot: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingSchedule {
    tz: Tz,
    intervals: Vec<(u8, u16, u16)>,
}

pub struct Unavailable<'x> {
    schedule: &'x WorkingSchedule,
    date: Option<Date>,
    last: Date,
    slot: usize,
    cursor: i64,
    end: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredCalendarSettings {
    pub settings: CalendarSettings,
    pub revision: Option<u64>,
}

pub trait WorkingHoursHandler: Sync + Send {
    fn calendar_settings(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<StoredCalendarSettings>> + Send;

    fn write_calendar_settings(
        &self,
        account_id: u32,
        settings: CalendarSettings,
        current: StoredCalendarSettings,
    ) -> impl Future<Output = trc::Result<RegistryWriteResult>> + Send;

    fn account_time_zone(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<TimeZone>>> + Send;

    fn working_hours(
        &self,
        account: &AccountCache,
    ) -> impl Future<Output = trc::Result<Option<(WorkingHours, Option<TimeZone>)>>> + Send;

    fn working_schedule(
        &self,
        account: &AccountCache,
    ) -> impl Future<Output = trc::Result<Option<WorkingSchedule>>> + Send;

    fn working_hours_vavailability(
        &self,
        account: &AccountCache,
    ) -> impl Future<Output = trc::Result<Option<String>>> + Send;

    fn update_working_hours(
        &self,
        account_id: u32,
        change: WorkingHoursChange,
    ) -> impl Future<Output = trc::Result<WorkingHoursUpdate>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkingHoursChange {
    Replace(WorkingHours),
    Disable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkingHoursUpdate {
    Updated,
    NotSupported,
    Rejected,
}

impl WorkingHoursHandler for Server {
    async fn calendar_settings(&self, account_id: u32) -> trc::Result<StoredCalendarSettings> {
        match self
            .registry()
            .get(ObjectId::new(
                ObjectType::CalendarSettings,
                Id::from(account_id),
            ))
            .await
            .caused_by(trc::location!())?
        {
            Some(Object {
                inner: ObjectInner::CalendarSettings(settings),
                revision,
            }) => Ok(StoredCalendarSettings {
                settings: *settings,
                revision: Some(revision),
            }),
            _ => Ok(StoredCalendarSettings::default()),
        }
    }

    async fn write_calendar_settings(
        &self,
        account_id: u32,
        settings: CalendarSettings,
        current: StoredCalendarSettings,
    ) -> trc::Result<RegistryWriteResult> {
        let id = Id::from(account_id);
        let object = Object::new(settings.into());
        if let Some(revision) = current.revision {
            let old_object = Object::with_revision(current.settings.into(), revision);
            self.registry()
                .write(RegistryWrite::Update {
                    object: &object,
                    id,
                    old_object: &old_object,
                })
                .await
        } else {
            self.registry()
                .write(RegistryWrite::Insert {
                    object: &object,
                    id: Some(id),
                })
                .await
        }
        .caused_by(trc::location!())
    }

    async fn account_time_zone(&self, account_id: u32) -> trc::Result<Option<TimeZone>> {
        Ok(
            match self
                .registry()
                .object::<Account>(account_id.into())
                .await
                .caused_by(trc::location!())?
            {
                Some(Account::User(account)) => account.time_zone,
                Some(Account::Resource(account)) => account.time_zone,
                Some(Account::Group(_)) | None => None,
            },
        )
    }

    async fn working_hours(
        &self,
        account: &AccountCache,
    ) -> trc::Result<Option<(WorkingHours, Option<TimeZone>)>> {
        if account.is_group_account() {
            return Ok(None);
        }
        let hours = self
            .calendar_settings(account.id)
            .await?
            .settings
            .working_hours;
        if !is_active(&hours) {
            return Ok(None);
        }
        let account_tz = if hours.time_zone.is_none() {
            self.account_time_zone(account.id).await?
        } else {
            None
        };
        Ok(Some((hours, account_tz)))
    }

    async fn working_schedule(
        &self,
        account: &AccountCache,
    ) -> trc::Result<Option<WorkingSchedule>> {
        Ok(self
            .working_hours(account)
            .await?
            .and_then(|(hours, time_zone)| WorkingSchedule::parse(&hours, time_zone).ok()))
    }

    async fn working_hours_vavailability(
        &self,
        account: &AccountCache,
    ) -> trc::Result<Option<String>> {
        Ok(self
            .working_hours(account)
            .await?
            .filter(|(hours, time_zone)| WorkingSchedule::parse(hours, *time_zone).is_ok())
            .and_then(|(hours, time_zone)| {
                ical::generate_vavailability(&hours, time_zone, account.id, now() as i64)
            }))
    }

    async fn update_working_hours(
        &self,
        account_id: u32,
        change: WorkingHoursChange,
    ) -> trc::Result<WorkingHoursUpdate> {
        if self
            .try_account(account_id)
            .await
            .caused_by(trc::location!())?
            .is_none_or(|account| account.is_group_account())
        {
            return Ok(WorkingHoursUpdate::NotSupported);
        }
        let current = self.calendar_settings(account_id).await?;
        let old_hours = &current.settings.working_hours;
        let mut settings = current.settings.clone();
        match change {
            WorkingHoursChange::Replace(mut hours) => {
                if let Some(zone) = hours.time_zone
                    && old_hours.time_zone.is_none()
                {
                    let posted = resolve_tz(Some(zone));
                    let effective = resolve_tz(self.account_time_zone(account_id).await?);
                    if posted == effective || (posted.is_utc() && effective.is_utc()) {
                        hours.time_zone = None;
                    }
                }
                settings.working_hours = hours;
            }
            WorkingHoursChange::Disable => {
                settings.working_hours.enable = false;
            }
        }
        if settings.working_hours == *old_hours {
            return Ok(WorkingHoursUpdate::Updated);
        }

        match self
            .write_calendar_settings(account_id, settings, current)
            .await?
        {
            RegistryWriteResult::Success(_) => Ok(WorkingHoursUpdate::Updated),
            _ => Ok(WorkingHoursUpdate::Rejected),
        }
    }
}

pub fn is_active(hours: &WorkingHours) -> bool {
    hours.enable && !hours.slots.is_empty()
}

impl WorkingSchedule {
    pub fn parse(
        hours: &WorkingHours,
        account_tz: Option<TimeZone>,
    ) -> Result<Self, WorkingHoursError> {
        if hours.slots.len() > MAX_WORKING_HOURS_SLOTS {
            return Err(WorkingHoursError::TooManySlots);
        }
        let mut intervals = Vec::with_capacity(
            hours
                .slots
                .values()
                .map(|slot| slot.days.len())
                .sum::<usize>()
                .min(MAX_WORKING_HOURS_SLOTS * DAYS_PER_WEEK),
        );
        for (slot_id, slot) in hours.slots.values().enumerate() {
            let (start, end) = (slot.start.minutes(), slot.end.minutes());
            if start >= end || end > MINUTES_PER_DAY {
                return Err(WorkingHoursError::InvalidInterval { slot: slot_id });
            }
            let interval = (start, end);
            if slot.days.is_empty() {
                return Err(WorkingHoursError::NoDays { slot: slot_id });
            }
            let mut seen = 0u8;
            for day in slot.days.iter() {
                let index = weekday_index(*day);
                let bit = 1u8 << index;
                if seen & bit != 0 {
                    return Err(WorkingHoursError::DuplicateDay { slot: slot_id });
                }
                seen |= bit;
                intervals.push((index, interval.0, interval.1));
            }
        }
        intervals.sort_unstable();
        intervals.dedup_by(|next, prev| {
            if next.0 == prev.0 && next.1 <= prev.2 {
                prev.2 = prev.2.max(next.2);
                true
            } else {
                false
            }
        });

        Ok(WorkingSchedule {
            tz: resolve_tz(hours.time_zone.or(account_tz)),
            intervals,
        })
    }

    pub fn is_always_available(&self) -> bool {
        self.intervals.len() == DAYS_PER_WEEK
            && self
                .intervals
                .iter()
                .all(|&(_, start, end)| start == 0 && end == MINUTES_PER_DAY)
    }

    pub fn covers_whole_week(&self) -> bool {
        self.intervals.len() == DAYS_PER_WEEK
            && self
                .intervals
                .iter()
                .all(|&(_, start, end)| start == 0 && end >= LAST_MINUTE_OF_DAY)
    }

    pub fn unavailable(&self, start: i64, end: i64) -> Unavailable<'_> {
        let range = if self.is_always_available() {
            None
        } else {
            self.local_date(start).zip(self.local_date(end))
        };
        match range {
            Some((date, last)) => Unavailable {
                schedule: self,
                date: Some(date),
                last,
                slot: 0,
                cursor: start,
                end,
            },
            None => Unavailable {
                schedule: self,
                date: None,
                last: Date::MIN,
                slot: 0,
                cursor: end,
                end,
            },
        }
    }

    fn local_date(&self, timestamp: i64) -> Option<Date> {
        Timestamp::from_second(timestamp)
            .ok()
            .map(|timestamp| self.tz.from_timestamp(timestamp).naive_local().date())
    }

    fn timestamp(&self, date: Date, minutes: u16) -> Option<i64> {
        let local = if minutes >= MINUTES_PER_DAY {
            date.tomorrow().ok()?.to_datetime(Time::midnight())
        } else {
            let hour = i8::try_from(minutes / 60).ok()?;
            let minute = i8::try_from(minutes % 60).ok()?;
            DateTime::from_parts(date, Time::new(hour, minute, 0, 0).ok()?)
        };
        self.tz.from_local(local).map(|zoned| zoned.timestamp())
    }

    fn day(&self, date: Date) -> &[(u8, u16, u16)] {
        let Ok(index) = u8::try_from(date.weekday().to_monday_zero_offset()) else {
            return &[];
        };
        let from = self
            .intervals
            .partition_point(|interval| interval.0 < index);
        let to = self
            .intervals
            .partition_point(|interval| interval.0 <= index);
        self.intervals.get(from..to).unwrap_or_default()
    }
}

impl Iterator for Unavailable<'_> {
    type Item = (i64, i64);

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor < self.end {
            let Some(date) = self.date.filter(|date| *date <= self.last) else {
                let gap = (self.cursor, self.end);
                self.cursor = self.end;
                return Some(gap);
            };
            let Some(&(_, from, to)) = self.schedule.day(date).get(self.slot) else {
                self.date = date.tomorrow().ok();
                self.slot = 0;
                continue;
            };
            self.slot += 1;
            let (Some(from), Some(to)) = (
                self.schedule.timestamp(date, from),
                self.schedule.timestamp(date, to),
            ) else {
                continue;
            };
            if to <= self.cursor {
                continue;
            }
            let gap = (self.cursor, from.min(self.end));
            self.cursor = to;
            if gap.0 < gap.1 {
                return Some(gap);
            }
        }
        None
    }
}

pub(crate) fn resolve_tz(time_zone: Option<TimeZone>) -> Tz {
    time_zone
        .and_then(|time_zone| Tz::iana(time_zone.as_str()))
        .unwrap_or(Tz::UTC)
}

pub(crate) fn weekday_index(day: Weekday) -> u8 {
    match day {
        Weekday::Monday => 0,
        Weekday::Tuesday => 1,
        Weekday::Wednesday => 2,
        Weekday::Thursday => 3,
        Weekday::Friday => 4,
        Weekday::Saturday => 5,
        Weekday::Sunday => 6,
    }
}

impl Display for WorkingHoursError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkingHoursError::TooManySlots => write!(
                f,
                "Working hours can have at most {MAX_WORKING_HOURS_SLOTS} intervals."
            ),
            WorkingHoursError::NoDays { slot } => {
                write!(f, "Working hours interval {slot} has no days.")
            }
            WorkingHoursError::DuplicateDay { slot } => {
                write!(
                    f,
                    "Working hours interval {slot} lists a day more than once."
                )
            }
            WorkingHoursError::InvalidInterval { slot } => write!(
                f,
                "Working hours interval {slot} must start before it ends, within one day."
            ),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/groupware/src/calendar/working_hours/tests.rs"]
mod tests;
