/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{blob::TzRule, roaming::UTF8_BOM};
use crate::{
    common::SystemTime,
    ews::{schema::DayOfWeek, types::recurrence::DaysOfWeek},
    xml::{Token, Tokenizer, XmlLimits, tokenizer::NoName},
};

const DAYS_PER_WEEK: usize = 7;
const MINUTES_PER_HOUR: u16 = 60;
const HOURS_PER_DAY: u16 = 24;
const MAX_MINUTE: u16 = 59;
const MAX_SECOND: u16 = 59;
const MAX_MONTH: u16 = 12;
const MAX_DAY: u16 = 31;
const MAX_WEEK_OF_MONTH: u16 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkHours {
    pub zone: TzRule,
    pub start_minutes: u16,
    pub end_minutes: u16,
    pub days: DaysOfWeek,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Zone,
    Standard,
    Daylight,
    TimeSlot,
}

impl WorkHours {
    pub fn parse(stream: &[u8]) -> Option<Self> {
        let stream = stream.strip_prefix(UTF8_BOM).unwrap_or(stream);
        let mut tokenizer = Tokenizer::new(stream, &XmlLimits::DEFAULT);
        let mut zone = TzRule::default();
        let mut bias = None;
        let mut start = None;
        let mut end = None;
        let mut days = None;
        let mut section = Section::Zone;
        let mut section_depth = 0;
        loop {
            match tokenizer.next_token::<NoName>().ok()? {
                Token::Unknown { local, .. } => {
                    hashify::fnc_map!(local.as_bytes(),
                        "Root" => {},
                        "WorkHoursVersion1" => {},
                        "TimeZone" => {},
                        "ChangeDate" => {},
                        "Standard" => {
                            section = Section::Standard;
                            section_depth = tokenizer.depth();
                        },
                        "DaylightSavings" => {
                            section = Section::Daylight;
                            section_depth = tokenizer.depth();
                        },
                        "TimeSlot" => {
                            section = Section::TimeSlot;
                            section_depth = tokenizer.depth();
                        },
                        "Bias" => {
                            let value = tokenizer.text().ok()?.trim().parse::<i16>().ok()?;
                            let value = i32::from(value);
                            match section {
                                Section::Zone => bias = Some(value),
                                Section::Standard => zone.standard_bias = value,
                                Section::Daylight => zone.daylight_bias = value,
                                Section::TimeSlot => return None,
                            }
                        },
                        "Time" => {
                            let (hour, minute, second) = clock(&tokenizer.text().ok()?)?;
                            if hour >= HOURS_PER_DAY {
                                return None;
                            }
                            let date = transition(&mut zone, section)?;
                            date.hour = hour;
                            date.minute = minute;
                            date.second = second;
                        },
                        "Date" => {
                            let text = tokenizer.text().ok()?;
                            let mut parts = text.trim().splitn(3, '/').map(|part| part.parse::<u16>().ok());
                            let (Some(Some(year)), Some(Some(month)), Some(Some(day))) =
                                (parts.next(), parts.next(), parts.next())
                            else {
                                return None;
                            };
                            let no_transition = month == 0 && day == 0;
                            let max_day = if year == 0 { MAX_WEEK_OF_MONTH } else { MAX_DAY };
                            if !no_transition
                                && (!(1..=MAX_MONTH).contains(&month) || !(1..=max_day).contains(&day))
                            {
                                return None;
                            }
                            let date = transition(&mut zone, section)?;
                            date.year = if no_transition { 0 } else { year };
                            date.month = month;
                            date.day = day;
                        },
                        "DayOfWeek" => {
                            let day = tokenizer.text().ok()?.trim().parse::<u16>().ok()?;
                            if usize::from(day) >= DAYS_PER_WEEK {
                                return None;
                            }
                            transition(&mut zone, section)?.day_of_week = day;
                        },
                        "Start" => {
                            if section != Section::TimeSlot {
                                return None;
                            }
                            start = Some(minutes(&tokenizer.text().ok()?)?);
                        },
                        "End" => {
                            if section != Section::TimeSlot {
                                return None;
                            }
                            end = Some(minutes(&tokenizer.text().ok()?)?);
                        },
                        "WorkDays" => {
                            let text = tokenizer.text().ok()?;
                            days = Some(DaysOfWeek::from_iter(
                                text.split_ascii_whitespace()
                                    .filter_map(|name| DayOfWeek::parse(name.as_bytes()))
                                    .filter(|day| DayOfWeek::ALL.get(..DAYS_PER_WEEK).is_some_and(|week| week.contains(day))),
                            ));
                        },
                        _ => tokenizer.skip_element().ok()?,
                    );
                }
                Token::End => {
                    if section != Section::Zone && tokenizer.depth() < section_depth {
                        section = Section::Zone;
                    }
                }
                Token::Eof => break,
                Token::Start { .. } | Token::Text => {}
            }
        }
        zone.bias = bias?;
        let (start_minutes, end_minutes) = (start?, end?);
        (start_minutes < end_minutes).then_some(WorkHours {
            zone,
            start_minutes,
            end_minutes,
            days: days.filter(|days| !days.is_empty())?,
        })
    }
}

fn transition(zone: &mut TzRule, section: Section) -> Option<&mut SystemTime> {
    match section {
        Section::Standard => Some(&mut zone.standard_date),
        Section::Daylight => Some(&mut zone.daylight_date),
        Section::Zone | Section::TimeSlot => None,
    }
}

fn clock(text: &str) -> Option<(u16, u16, u16)> {
    let mut parts = text.trim().splitn(3, ':');
    let hour = parts.next()?.parse::<u16>().ok()?;
    let minute = parts.next()?.parse::<u16>().ok()?;
    let second = match parts.next() {
        Some(second) => second
            .split_once('.')
            .map_or(second, |(whole, _)| whole)
            .parse::<u16>()
            .ok()?,
        None => 0,
    };
    let valid = minute <= MAX_MINUTE
        && second <= MAX_SECOND
        && (hour < HOURS_PER_DAY || (hour == HOURS_PER_DAY && minute == 0 && second == 0));
    valid.then_some((hour, minute, second))
}

fn minutes(text: &str) -> Option<u16> {
    let (hour, minute, _) = clock(text)?;
    Some(hour * MINUTES_PER_HOUR + minute)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/convert/work_hours/tests.rs"]
mod tests;
