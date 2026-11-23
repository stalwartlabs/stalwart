/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::timezone::ZonedDateTime,
    datecalc::RRule,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarFrequency, ICalendarProperty,
        ICalendarRecurrenceRule,
    },
};
use jiff::{SignedDuration, Span as JiffSpan, Timestamp};
use smallvec::SmallVec;

use super::{
    alarm::{
        AlarmOwner, AlarmState, SIGNAL_NEVER, TargetAlarms, acknowledged, alarm_state,
        clear_acknowledged, ensure_uid, set_acknowledged, snooze_alarm, triggers_at,
    },
    patch::{push_alarm, remove_components, timestamp},
    series::{MAX_INSTANCE_SCAN, MAX_RECURRENCE_RULES, Series, Span, recurrence_rules},
    to_message::{Trigger, alarm_fire, file_time, reminder},
};
use crate::common::time::FileTime;

const SECONDS_PER_DAY: i64 = 86_400;
const DAYS_PER_WEEK: i64 = 7;
const SEEK_MARGIN_PERIODS: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SeriesSignal {
    At(Timestamp),
    Never,
}

impl SeriesSignal {
    pub fn file_time(self) -> FileTime {
        match self {
            SeriesSignal::At(at) => file_time(at),
            SeriesSignal::Never => SIGNAL_NEVER,
        }
    }
}

pub(super) fn series_signal(series: &Series<'_>) -> Option<SeriesSignal> {
    let master = series.master.filter(|_| series.is_recurring())?;
    let trigger = Trigger::of(series, master)?;
    let master_ack = acknowledged(series, master);
    if master_ack.is_none()
        && !series
            .overrides()
            .any(|(index, _, _)| acknowledged(series, index).is_some())
    {
        return None;
    }
    let scan = MasterScan::of(
        series,
        master,
        trigger,
        master_ack.unwrap_or(Timestamp::MIN),
    )
    .filter(|scan| scan.complete)?;
    let mut next = scan.after;
    if let Some(ack) = master_ack.filter(|_| scan.at)
        && let AlarmState::Snoozed(at) = alarm_state(series, master, ack, AlarmOwner::Series)
    {
        next = earliest(next, at);
    }
    for (index, fire) in override_fires(series) {
        match alarm_state(series, index, fire, AlarmOwner::Component) {
            AlarmState::Pending => next = earliest(next, fire),
            AlarmState::Snoozed(at) => next = earliest(next, at),
            AlarmState::Dismissed => {}
        }
    }
    Some(next.map_or(SeriesSignal::Never, SeriesSignal::At))
}

fn first_signal(series: &Series<'_>, master: usize) -> Option<SeriesSignal> {
    let span = series.span(series.component(master)?)?;
    let delta = reminder(series, master, &span)?;
    let start = span.start.to_timestamp();
    Some(SeriesSignal::At(
        start
            .checked_sub(SignedDuration::from_mins(i64::from(delta)))
            .unwrap_or(start),
    ))
}

fn earliest(current: Option<Timestamp>, candidate: Timestamp) -> Option<Timestamp> {
    Some(current.map_or(candidate, |current| current.min(candidate)))
}

fn override_fires<'s>(series: &'s Series<'_>) -> impl Iterator<Item = (usize, Timestamp)> + 's {
    series
        .overrides()
        .filter(|(_, _, id)| !series.excluded(*id))
        .filter_map(|(index, component, _)| {
            let span = series.span(component)?;
            Some((index, alarm_fire(series, index, &span)?))
        })
}

struct MasterScan {
    before: Option<Timestamp>,
    at: bool,
    after: Option<Timestamp>,
    complete: bool,
}

impl MasterScan {
    fn of(series: &Series<'_>, master: usize, trigger: Trigger, bound: Timestamp) -> Option<Self> {
        let component = series.component(master)?;
        let span = series.span(component)?;
        let mut scan = MasterScan {
            before: None,
            at: false,
            after: None,
            complete: !series.rules_capped(),
        };
        if let Trigger::At(fire) = trigger {
            scan.note(fire, bound);
            return Some(scan);
        }
        let mut skipped: SmallVec<[Timestamp; 8]> = series
            .exdates()
            .map(|zoned| zoned.to_timestamp())
            .chain(series.overrides().map(|(_, _, id)| id.0))
            .collect();
        skipped.sort_unstable();
        let duration = span.duration();
        let fire = |start: ZonedDateTime| {
            if skipped.binary_search(&start.to_timestamp()).is_ok() {
                return None;
            }
            let end = start.checked_add(duration)?;
            trigger.fire(&Span {
                start,
                end,
                all_day: span.all_day,
            })
        };
        if let Some(at) = fire(span.start) {
            scan.note(at, bound);
        }
        let mut rdates = series.dates(component, &ICalendarProperty::Rdate);
        for start in rdates.by_ref().take(MAX_INSTANCE_SCAN) {
            if let Some(at) = fire(start) {
                scan.note(at, bound);
            }
        }
        if rdates.next().is_some() {
            scan.complete = false;
        }
        for value in recurrence_rules(component).take(MAX_RECURRENCE_RULES) {
            if bound == Timestamp::MAX && value.count.is_none() && value.until.is_none() {
                scan.complete = false;
                continue;
            }
            if let Some(seed) = seek(&span, value, trigger, bound)
                && scan.walk(value, seed, span.all_day, Seed::Skip, bound, &fire)
            {
                continue;
            }
            scan.walk(value, span.start, span.all_day, Seed::Keep, bound, &fire);
        }
        Some(scan)
    }

    fn walk(
        &mut self,
        value: &ICalendarRecurrenceRule,
        seed: ZonedDateTime,
        all_day: bool,
        mode: Seed,
        bound: Timestamp,
        fire: &impl Fn(ZonedDateTime) -> Option<Timestamp>,
    ) -> bool {
        let Ok(rule) = RRule::from_ical(value, seed, all_day) else {
            self.complete = false;
            return false;
        };
        let mut instants = rule.iter();
        if mode == Seed::Skip {
            instants.next();
        }
        let mut seen_before = false;
        for start in instants.by_ref().take(MAX_INSTANCE_SCAN) {
            let Some(at) = fire(start) else {
                continue;
            };
            seen_before |= at < bound;
            if self.note(at, bound) {
                return seen_before;
            }
        }
        if instants.next().is_some() {
            self.complete = false;
        }
        seen_before
    }

    fn note(&mut self, fire: Timestamp, bound: Timestamp) -> bool {
        if fire < bound {
            self.before = Some(self.before.map_or(fire, |before| before.max(fire)));
            false
        } else if fire == bound {
            self.at = true;
            false
        } else {
            self.after = earliest(self.after, fire);
            true
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Seed {
    Keep,
    Skip,
}

fn seek(
    span: &Span,
    rule: &ICalendarRecurrenceRule,
    trigger: Trigger,
    bound: Timestamp,
) -> Option<ZonedDateTime> {
    if rule.count.is_some() || !rule.bysetpos.is_empty() || bound == Timestamp::MAX {
        return None;
    }
    let unit = match rule.freq {
        ICalendarFrequency::Daily => 1,
        ICalendarFrequency::Weekly => DAYS_PER_WEEK,
        _ => return None,
    };
    let period = i64::from(rule.interval.unwrap_or(1).max(1)) * unit;
    let lead = match trigger {
        Trigger::Start(offset) => offset,
        Trigger::End(offset) => offset.checked_add(span.duration())?,
        Trigger::At(_) => return None,
    };
    let target = bound.checked_sub(lead).ok()?;
    let days = target.duration_since(span.start.to_timestamp()).as_secs() / SECONDS_PER_DAY;
    let periods = days / period - SEEK_MARGIN_PERIODS;
    if periods <= 0 {
        return None;
    }
    let local = span
        .start
        .naive_local()
        .checked_add(
            JiffSpan::new()
                .try_days(periods.checked_mul(period)?)
                .ok()?,
        )
        .ok()?;
    span.start.timezone().from_local(local)
}

pub(super) struct SignalEdit {
    signal: FileTime,
    before: Option<FileTime>,
    now: Timestamp,
}

#[derive(Clone, Copy)]
enum AckChange {
    Set(Timestamp),
    Clear,
    Keep,
}

struct Plan {
    master: usize,
    master_ack: Option<Timestamp>,
    overrides: SmallVec<[(usize, AckChange); 4]>,
    snooze: Option<(usize, Timestamp)>,
}

impl SignalEdit {
    pub fn of(ical: &ICalendar, target: usize, signal: FileTime, now: Timestamp) -> Option<Self> {
        let series = Series::new(ical)?;
        if series.master != Some(target) || !series.is_recurring() {
            return None;
        }
        let before = series_signal(&series)
            .or_else(|| first_signal(&series, target))
            .map(SeriesSignal::file_time);
        Some(SignalEdit {
            signal,
            before,
            now,
        })
    }

    pub fn apply(self, ical: &mut ICalendar) {
        if self.before == Some(self.signal) {
            return;
        }
        if let Some(plan) = self.plan(ical) {
            plan.write(ical);
        }
    }

    fn plan(&self, ical: &ICalendar) -> Option<Plan> {
        let series = Series::new(ical)?;
        let master = series.master?;
        let trigger = Trigger::of(&series, master)?;
        let never = self.signal == SIGNAL_NEVER;
        let bound = if never {
            Timestamp::MAX
        } else {
            timestamp(self.signal)
        };
        let scan = MasterScan::of(&series, master, trigger, bound).filter(|scan| scan.complete)?;
        let fires: SmallVec<[(usize, Timestamp); 4]> = override_fires(&series).collect();
        let snooze = if never || scan.at || fires.iter().any(|(_, fire)| *fire == bound) {
            None
        } else {
            let latest = fires
                .iter()
                .map(|(_, fire)| *fire)
                .filter(|fire| *fire < bound)
                .max()
                .max(scan.before)?;
            if latest > self.now || bound <= self.now {
                return None;
            }
            let owner = if scan.before == Some(latest) {
                master
            } else {
                fires.iter().find(|(_, fire)| *fire == latest)?.0
            };
            Some((owner, bound))
        };
        let overrides = fires
            .iter()
            .map(|(index, fire)| {
                let dismissed = acknowledged(&series, *index).is_some_and(|ack| ack >= *fire);
                let action = match (*fire < bound, dismissed) {
                    (true, false) => AckChange::Set(*fire),
                    (false, true) => AckChange::Clear,
                    _ => AckChange::Keep,
                };
                (*index, action)
            })
            .collect();
        Some(Plan {
            master,
            master_ack: scan.before,
            overrides,
            snooze,
        })
    }
}

impl Plan {
    fn write(self, ical: &mut ICalendar) {
        let mut removed: SmallVec<[usize; 4]> = SmallVec::new();
        let master = (
            self.master,
            self.master_ack.map_or(AckChange::Clear, AckChange::Set),
        );
        for (index, action) in self.overrides.into_iter().chain([master]) {
            let alarms = TargetAlarms::of(ical, index);
            let kept = match self.snooze {
                Some((owner, at)) if owner == index => alarms.snoozes.iter().copied().find(|id| {
                    ical.components
                        .get(*id)
                        .is_some_and(|alarm| triggers_at(alarm, at))
                }),
                _ => None,
            };
            removed.extend(
                alarms
                    .snoozes
                    .iter()
                    .copied()
                    .filter(|id| Some(*id) != kept),
            );
            let Some(reminder) = alarms.reminder else {
                continue;
            };
            let event_uid = match self.snooze {
                Some((owner, _)) if owner == index && kept.is_none() => ical
                    .components
                    .get(index)
                    .and_then(ICalendarComponent::uid)
                    .map(str::to_string),
                _ => None,
            };
            let Some(alarm) = ical.components.get_mut(reminder) else {
                continue;
            };
            match action {
                AckChange::Set(at) => set_acknowledged(alarm, at),
                AckChange::Clear => clear_acknowledged(alarm),
                AckChange::Keep => {}
            }
            if let Some((event_uid, (_, at))) = event_uid.zip(self.snooze) {
                let reminder_uid = ensure_uid(alarm, &event_uid);
                push_alarm(ical, index, snooze_alarm(reminder_uid, at));
            }
        }
        remove_components(ical, &removed);
    }
}
