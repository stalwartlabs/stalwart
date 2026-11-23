/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EwsContext,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use ahash::AHashSet;
use exchange_proto::{
    common::{LocalDateTime, SystemTime, XsDateTime, XsDuration, XsZone},
    convert::blob::{TzDefinition, TzRule, iana_to_windows},
    ews::{
        MessageResult, Operation, Status,
        requests::availability::GetServerTimeZones,
        responses::availability::GetServerTimeZonesMessage,
        schema::DayOfWeek,
        schema::TransitionTargetKind,
        types::{
            timezone::{
                Period, TimeZoneDefinition, Transition, TransitionTarget, TransitionsGroup,
            },
            value::DateTime,
        },
    },
};
use http_proto::HttpResponse;
use jiff::tz::{self, TimeZone};
use std::{borrow::Cow, ops::RangeInclusive};

const YEARS: RangeInclusive<i16> = 2000..=2037;
const PERIOD_PREFIX: &str = "trule:Microsoft/Registry/";
const STANDARD: &str = "Standard";
const DAYLIGHT: &str = "Daylight";
const LAST_OCCURRENCE: i32 = -1;
const LAST_WEEK: u16 = 5;
const SECONDS_PER_MINUTE: u64 = 60;
const DAYS: [DayOfWeek; 7] = [
    DayOfWeek::Sunday,
    DayOfWeek::Monday,
    DayOfWeek::Tuesday,
    DayOfWeek::Wednesday,
    DayOfWeek::Thursday,
    DayOfWeek::Friday,
    DayOfWeek::Saturday,
];

pub(crate) fn get_server_time_zones(
    ctx: &EwsContext,
    request: &GetServerTimeZones<'_>,
) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx
        .envelope(&mut out)
        .shape_a(Operation::GetServerTimeZones);
    messages.message(&MessageResult {
        status: Status::SUCCESS,
        body: Some(server_time_zones(request)),
    });
    messages.finish();
    ews_response(out)
}

pub(crate) fn server_time_zones(
    request: &GetServerTimeZones<'_>,
) -> GetServerTimeZonesMessage<'static> {
    let full = request.return_full_time_zone_data.unwrap_or(true);
    let wanted = request.ids.as_deref();
    let mut seen = AHashSet::new();
    let mut found: Vec<(&'static str, TimeZone)> = Vec::new();
    let db = tz::db();
    for name in db.available() {
        let Some(windows) = iana_to_windows(name.as_str()) else {
            continue;
        };
        if wanted.is_some_and(|ids| !ids.iter().any(|id| id == windows)) || !seen.insert(windows) {
            continue;
        }
        if let Ok(zone) = db.get(name.as_str()) {
            found.push((windows, zone));
        }
        if wanted.is_some_and(|ids| ids.len() == found.len()) {
            break;
        }
    }
    found.sort_unstable_by_key(|(windows, _)| *windows);

    let definitions = found
        .iter()
        .map(|(windows, zone)| {
            if full {
                time_zone_definition(&TzDefinition::from_time_zone(windows, zone, YEARS))
            } else {
                TimeZoneDefinition {
                    id: Some(Cow::Borrowed(windows)),
                    name: Some(Cow::Borrowed(windows)),
                    periods: Vec::new(),
                    groups: Vec::new(),
                    transitions: None,
                }
            }
        })
        .collect();
    GetServerTimeZonesMessage { definitions }
}

pub(crate) fn time_zone_definition(definition: &TzDefinition) -> TimeZoneDefinition<'static> {
    let key = &*definition.key_name;
    let mut periods = Vec::with_capacity(definition.rules.len() * 2);
    let mut groups = Vec::with_capacity(definition.rules.len());
    let mut transitions = Vec::with_capacity(definition.rules.len());
    for (group, rule) in definition.rules.iter().enumerate() {
        let standard = period_id(key, rule.year, STANDARD);
        periods.push(Period {
            bias: Some(minutes(rule.bias.saturating_add(rule.standard_bias))),
            name: Some(Cow::Borrowed(STANDARD)),
            id: Some(Cow::Owned(standard.clone())),
        });
        let group_transitions = if rule.has_daylight() {
            let daylight = period_id(key, rule.year, DAYLIGHT);
            periods.push(Period {
                bias: Some(minutes(rule.bias.saturating_add(rule.daylight_bias))),
                name: Some(Cow::Borrowed(DAYLIGHT)),
                id: Some(Cow::Owned(daylight.clone())),
            });
            vec![
                recurring(daylight, &rule.daylight_date),
                recurring(standard, &rule.standard_date),
            ]
        } else {
            vec![Transition::Plain {
                to: target(TransitionTargetKind::Period, standard),
            }]
        };
        let group_id = group.to_string();
        groups.push(TransitionsGroup {
            id: Some(Cow::Owned(group_id.clone())),
            transitions: group_transitions,
        });
        let to = target(TransitionTargetKind::Group, group_id);
        transitions.push(match year_start(rule).filter(|_| group > 0) {
            Some(date_time) => Transition::AbsoluteDate { to, date_time },
            None => Transition::Plain { to },
        });
    }
    TimeZoneDefinition {
        id: Some(Cow::Owned(key.to_string())),
        name: Some(Cow::Owned(key.to_string())),
        periods,
        groups,
        transitions: Some(TransitionsGroup {
            id: None,
            transitions,
        }),
    }
}

fn period_id(key: &str, year: u16, kind: &str) -> String {
    format!("{PERIOD_PREFIX}{key}/{year}-{kind}")
}

fn target(kind: TransitionTargetKind, value: String) -> TransitionTarget<'static> {
    TransitionTarget {
        kind,
        value: Cow::Owned(value),
    }
}

fn minutes(bias: i32) -> XsDuration {
    XsDuration {
        negative: bias < 0,
        seconds: u64::from(bias.unsigned_abs()) * SECONDS_PER_MINUTE,
    }
}

fn recurring(period: String, date: &SystemTime) -> Transition<'static> {
    Transition::RecurringDay {
        to: target(TransitionTargetKind::Period, period),
        time_offset: XsDuration {
            negative: false,
            seconds: u64::from(date.hour) * 3600
                + u64::from(date.minute) * SECONDS_PER_MINUTE
                + u64::from(date.second),
        },
        month: i32::from(date.month),
        day_of_week: DAYS
            .get(usize::from(date.day_of_week))
            .copied()
            .unwrap_or(DayOfWeek::Sunday),
        occurrence: if date.day >= LAST_WEEK {
            LAST_OCCURRENCE
        } else {
            i32::from(date.day)
        },
    }
}

fn year_start(rule: &TzRule) -> Option<DateTime> {
    LocalDateTime::new(rule.year, 1, 1, 0, 0, 0, 0).map(|local| {
        DateTime::Parsed(XsDateTime {
            local,
            zone: XsZone::Floating,
        })
    })
}
