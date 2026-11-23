/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Busy, LEVELS, Level, Refusal, RequestZone, SECONDS_PER_MINUTE, Window, civil, floating,
};
use exchange_proto::{
    common::{LocalDateTime, XsDateTime},
    convert::work_hours::WorkHours,
    ews::{
        schema::{DayOfWeek, LegacyFreeBusy, ResponseCode, SuggestionQuality},
        types::{
            availability::SuggestionsViewOptions,
            generated::{Suggestion, SuggestionDayResult},
            response_extra::{AttendeeConflict, AttendeeConflicts, IndividualConflict},
            value::{DateTime, List},
        },
    },
};
use std::ops::RangeInclusive;

const GOOD_THRESHOLDS: RangeInclusive<i32> = 1..=49;
const DEFAULT_GOOD_THRESHOLD: i32 = 25;
const MAX_RESULTS_BY_DAY: i32 = 48;
const DEFAULT_RESULTS_BY_DAY: i32 = 24;
const NON_WORK_RESULTS: RangeInclusive<i32> = 0..=48;
const DEFAULT_NON_WORK_RESULTS: i32 = 0;
const DURATIONS_MINUTES: RangeInclusive<i32> = 1..=1440;
const DEFAULT_DURATION_MINUTES: i32 = 30;
const DEFAULT_MINIMUM_QUALITY: SuggestionQuality = SuggestionQuality::Fair;
const SLOT_SECONDS: i64 = 1800;
const SLOTS_PER_DAY: i64 = 48;
const SECONDS_PER_DAY: i64 = 86_400;
const MINUTES_PER_DAY: i64 = 1440;
const EPOCH_WEEKDAY: i64 = 4;
const DAYS_PER_WEEK: i64 = 7;
const PERCENT: usize = 100;
const POOR_PERCENT: usize = 50;
const BAD_OPTIONS: &str = "SuggestionsViewOptions holds a value out of range.";
const BAD_DATES: &str = "DetailedSuggestionsWindow: dates must have zero hours, minutes and seconds and the start must not be after the end.";
const WINDOW_TOO_BIG: &str = "DetailedSuggestionsWindow is too long.";

pub(super) struct Suggestions {
    good_threshold: usize,
    max_work: usize,
    max_non_work: usize,
    minimum: SuggestionQuality,
    duration: i64,
    dates: Vec<LocalDateTime>,
    slots: Vec<Slot>,
    zone: RequestZone,
}

struct Slot {
    utc: i64,
    local: LocalDateTime,
    day: usize,
}

pub(super) struct Attendee<'a> {
    pub(super) busy: Option<&'a [Busy]>,
    pub(super) exclude: bool,
}

impl Suggestions {
    pub(super) fn parse(
        options: &SuggestionsViewOptions<'_>,
        zone: RequestZone,
        max_window: i64,
    ) -> Result<Self, Refusal> {
        let invalid = (ResponseCode::ErrorInvalidRequest, BAD_OPTIONS);
        let good_threshold = options.good_threshold.unwrap_or(DEFAULT_GOOD_THRESHOLD);
        let max_work = options
            .maximum_results_by_day
            .unwrap_or(DEFAULT_RESULTS_BY_DAY);
        let max_non_work = options
            .maximum_non_work_hour_results_by_day
            .unwrap_or(DEFAULT_NON_WORK_RESULTS);
        let duration = options
            .meeting_duration_in_minutes
            .unwrap_or(DEFAULT_DURATION_MINUTES);
        if !GOOD_THRESHOLDS.contains(&good_threshold)
            || max_work > MAX_RESULTS_BY_DAY
            || !NON_WORK_RESULTS.contains(&max_non_work)
            || !DURATIONS_MINUTES.contains(&duration)
        {
            return Err(invalid);
        }
        let window = &options.detailed_suggestions_window;
        let (Some(first), Some(last)) = (date_of(&window.start_time), date_of(&window.end_time))
        else {
            return Err((ResponseCode::ErrorInvalidRequest, BAD_DATES));
        };
        let span = last - first;
        if span < 0 {
            return Err((ResponseCode::ErrorInvalidRequest, BAD_DATES));
        }
        if span > max_window {
            return Err((ResponseCode::ErrorTimeIntervalTooBig, WINDOW_TOO_BIG));
        }
        let days = (span / SECONDS_PER_DAY).max(1);
        let mut dates = Vec::with_capacity(usize::try_from(days).unwrap_or(0));
        let mut slots = Vec::with_capacity(usize::try_from(days * SLOTS_PER_DAY).unwrap_or(0));
        let mut previous = i64::MIN;
        for day in 0..days {
            let midnight = first + day * SECONDS_PER_DAY;
            let Some(date) = civil(midnight) else {
                return Err((ResponseCode::ErrorInvalidRequest, BAD_DATES));
            };
            let index = dates.len();
            dates.push(date);
            for step in 0..SLOTS_PER_DAY {
                let Some(local) = civil(midnight + step * SLOT_SECONDS) else {
                    continue;
                };
                let Some(utc) = zone
                    .utc_of_local(local)
                    .filter(|utc| *utc > previous && zone.local_naive(*utc) == Some(local))
                else {
                    continue;
                };
                previous = utc;
                slots.push(Slot {
                    utc,
                    local,
                    day: index,
                });
            }
        }
        Ok(Suggestions {
            good_threshold: usize::try_from(good_threshold).unwrap_or(0),
            max_work: usize::try_from(max_work).unwrap_or(0),
            max_non_work: usize::try_from(max_non_work).unwrap_or(0),
            minimum: options
                .minimum_suggestion_quality
                .unwrap_or(DEFAULT_MINIMUM_QUALITY),
            duration: i64::from(duration) * SECONDS_PER_MINUTE,
            dates,
            slots,
            zone,
        })
    }

    pub(super) fn scan_window(&self) -> Option<Window> {
        let (first, last) = (self.slots.first()?, self.slots.last()?);
        Some(Window {
            start: first.utc,
            end: last.utc.saturating_add(self.duration),
            interval: SLOT_SECONDS,
            zone: self.zone,
        })
    }

    pub(super) fn build(
        &self,
        attendees: &[Attendee<'_>],
        work_hours: Option<&WorkHours>,
    ) -> Vec<SuggestionDayResult> {
        let count = self.slots.len().max(1);
        let levels = self.levels(attendees, count);
        let rows = || attendees.iter().zip(levels.chunks_exact(count));
        let resolved = attendees
            .iter()
            .filter(|attendee| attendee.busy.is_some())
            .count();
        let mut slots = self.slots.iter().enumerate().peekable();
        let mut days = Vec::with_capacity(self.dates.len());
        for (day, date) in self.dates.iter().enumerate() {
            let mut suggestions = Vec::new();
            let (mut work, mut non_work) = (0usize, 0usize);
            let mut best: Option<SuggestionQuality> = None;
            while let Some((index, slot)) = slots.next_if(|(_, slot)| slot.day == day) {
                if work >= self.max_work && non_work >= self.max_non_work {
                    continue;
                }
                let mut conflicts = 0usize;
                let mut excluded = false;
                for (attendee, row) in rows() {
                    if row.get(index).copied().flatten().is_some() {
                        conflicts += 1;
                        excluded |= attendee.exclude;
                    }
                }
                let quality = self.quality(conflicts, resolved);
                if excluded || quality > self.minimum {
                    continue;
                }
                let is_work_time =
                    work_hours.is_none_or(|hours| within(hours, slot.utc, self.duration));
                let (taken, cap) = if is_work_time {
                    (&mut work, self.max_work)
                } else {
                    (&mut non_work, self.max_non_work)
                };
                if *taken >= cap {
                    continue;
                }
                *taken += 1;
                best = Some(best.map_or(quality, |best| best.min(quality)));
                suggestions.push(Suggestion {
                    meeting_time: floating(slot.local),
                    is_work_time,
                    suggestion_quality: quality,
                    attendee_conflict_data_array: Some(AttendeeConflicts(
                        rows()
                            .map(|(attendee, row)| match attendee.busy {
                                Some(_) => AttendeeConflict::Individual(IndividualConflict {
                                    busy_type: row
                                        .get(index)
                                        .copied()
                                        .flatten()
                                        .map_or(LegacyFreeBusy::Free, Level::legacy),
                                }),
                                None => AttendeeConflict::Unknown,
                            })
                            .collect(),
                    )),
                });
            }
            days.push(SuggestionDayResult {
                date: floating(*date),
                day_quality: best.unwrap_or(SuggestionQuality::Poor),
                suggestion_array: Some(List(suggestions)),
            });
        }
        days
    }

    fn levels(&self, attendees: &[Attendee<'_>], count: usize) -> Vec<Option<Level>> {
        let mut levels = vec![None; count * attendees.len()];
        let mut marks = vec![[0i32; LEVELS]; count + 1];
        for (attendee, row) in attendees.iter().zip(levels.chunks_exact_mut(count)) {
            let Some(busy) = attendee.busy else {
                continue;
            };
            marks.fill([0; LEVELS]);
            for busy in busy {
                let first = self
                    .slots
                    .partition_point(|slot| slot.utc.saturating_add(self.duration) <= busy.start);
                let last = self.slots.partition_point(|slot| slot.utc < busy.end);
                if first >= last {
                    continue;
                }
                let rank = busy.level.rank();
                if let Some(mark) = marks.get_mut(first).and_then(|mark| mark.get_mut(rank)) {
                    *mark += 1;
                }
                if let Some(mark) = marks.get_mut(last).and_then(|mark| mark.get_mut(rank)) {
                    *mark -= 1;
                }
            }
            let mut active = [0i32; LEVELS];
            for (cell, mark) in row.iter_mut().zip(&marks) {
                for (active, mark) in active.iter_mut().zip(mark) {
                    *active += mark;
                }
                *cell = active
                    .iter()
                    .rposition(|count| *count > 0)
                    .and_then(|rank| Level::ALL.get(rank).copied());
            }
        }
        levels
    }

    fn quality(&self, conflicts: usize, resolved: usize) -> SuggestionQuality {
        if conflicts == 0 || resolved == 0 {
            return SuggestionQuality::Excellent;
        }
        if conflicts.saturating_mul(PERCENT) <= self.good_threshold.saturating_mul(resolved) {
            SuggestionQuality::Good
        } else if conflicts.saturating_mul(PERCENT) < POOR_PERCENT.saturating_mul(resolved) {
            SuggestionQuality::Fair
        } else {
            SuggestionQuality::Poor
        }
    }
}

fn date_of(time: &DateTime) -> Option<i64> {
    match time {
        DateTime::Parsed(XsDateTime { local, .. })
            if local.hour == 0 && local.minute == 0 && local.second == 0 && local.nanos == 0 =>
        {
            Some(local.to_unix_seconds().0)
        }
        _ => None,
    }
}

fn within(hours: &WorkHours, utc: i64, duration: i64) -> bool {
    let Some(local) = RequestZone::Rule(hours.zone).local_naive(utc) else {
        return true;
    };
    let naive = local.to_unix_seconds().0;
    let weekday = (naive.div_euclid(SECONDS_PER_DAY) + EPOCH_WEEKDAY).rem_euclid(DAYS_PER_WEEK);
    let minute = naive.rem_euclid(SECONDS_PER_DAY) / SECONDS_PER_MINUTE;
    let end = minute + duration / SECONDS_PER_MINUTE;
    usize::try_from(weekday)
        .ok()
        .and_then(|weekday| DayOfWeek::ALL.get(weekday))
        .is_some_and(|day| hours.days.contains(*day))
        && i64::from(hours.start_minutes) <= minute
        && end <= i64::from(hours.end_minutes).min(MINUTES_PER_DAY)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/availability/suggest/tests.rs"]
mod tests;
