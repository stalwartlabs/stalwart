/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    recurrence::{RelativeYearly, required},
    value::{DateTime, EwsValue, T, ews_fields},
};
use crate::{
    common::XsDuration,
    ews::{
        parser::{ParseErrorKind, Parser, Result},
        schema::{DayOfWeek, TransitionTargetKind},
    },
    xml::{
        Attrs, XmlWriter,
        value::{XsDate, XsTime},
    },
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub struct TimeZoneDefinition<'x> {
    pub id: Option<Cow<'x, str>>,
    pub name: Option<Cow<'x, str>>,
    pub periods: Vec<Period<'x>>,
    pub groups: Vec<TransitionsGroup<'x>>,
    pub transitions: Option<TransitionsGroup<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Period<'x> {
    pub bias: Option<XsDuration>,
    pub name: Option<Cow<'x, str>>,
    pub id: Option<Cow<'x, str>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransitionsGroup<'x> {
    pub id: Option<Cow<'x, str>>,
    pub transitions: Vec<Transition<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionTarget<'x> {
    pub kind: TransitionTargetKind,
    pub value: Cow<'x, str>,
}

impl<'x> EwsValue<'x> for TransitionTarget<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let kind = p
            .attr_enum(attrs, "Kind", TransitionTargetKind::parse)?
            .ok_or_else(|| p.error(ParseErrorKind::MissingAttribute("Kind")))?;
        Ok(TransitionTarget {
            kind,
            value: p.text()?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local)
            .attr("Kind", self.kind.as_str())
            .close_start();
        w.text(&self.value);
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition<'x> {
    Plain {
        to: TransitionTarget<'x>,
    },
    AbsoluteDate {
        to: TransitionTarget<'x>,
        date_time: DateTime,
    },
    RecurringDay {
        to: TransitionTarget<'x>,
        time_offset: XsDuration,
        month: i32,
        day_of_week: DayOfWeek,
        occurrence: i32,
    },
    RecurringDate {
        to: TransitionTarget<'x>,
        time_offset: XsDuration,
        month: i32,
        day: i32,
    },
}

#[derive(Clone, Copy)]
enum TransitionKind {
    Plain,
    AbsoluteDate,
    RecurringDay,
    RecurringDate,
}

fn transition_kind(local: &str) -> Option<TransitionKind> {
    hashify::map!(local.as_bytes(), TransitionKind,
        "Transition" => TransitionKind::Plain,
        "AbsoluteDateTransition" => TransitionKind::AbsoluteDate,
        "RecurringDayTransition" => TransitionKind::RecurringDay,
        "RecurringDateTransition" => TransitionKind::RecurringDate,
    )
    .copied()
}

ews_fields! {
    struct TransitionScratch<'x> {
        to: "To" => TransitionTarget<'x>,
        date_time: "DateTime" => DateTime,
        time_offset: "TimeOffset" => XsDuration,
        month: "Month" => i32,
        day_of_week: "DayOfWeek" => DayOfWeek,
        occurrence: "Occurrence" => i32,
        day: "Day" => i32,
    }
}

impl<'x> Transition<'x> {
    fn parse(p: &mut Parser<'x>, kind: TransitionKind) -> Result<Self> {
        let mut scratch = TransitionScratch::default();
        while let Some(child) = p.child()? {
            if !scratch.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        let to = required(p, scratch.to, "To")?;
        Ok(match kind {
            TransitionKind::Plain => Transition::Plain { to },
            TransitionKind::AbsoluteDate => Transition::AbsoluteDate {
                to,
                date_time: required(p, scratch.date_time, "DateTime")?,
            },
            TransitionKind::RecurringDay => Transition::RecurringDay {
                to,
                time_offset: required(p, scratch.time_offset, "TimeOffset")?,
                month: required(p, scratch.month, "Month")?,
                day_of_week: required(p, scratch.day_of_week, "DayOfWeek")?,
                occurrence: required(p, scratch.occurrence, "Occurrence")?,
            },
            TransitionKind::RecurringDate => Transition::RecurringDate {
                to,
                time_offset: required(p, scratch.time_offset, "TimeOffset")?,
                month: required(p, scratch.month, "Month")?,
                day: required(p, scratch.day, "Day")?,
            },
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>) {
        let (name, to) = match self {
            Transition::Plain { to } => ("Transition", to),
            Transition::AbsoluteDate { to, .. } => ("AbsoluteDateTransition", to),
            Transition::RecurringDay { to, .. } => ("RecurringDayTransition", to),
            Transition::RecurringDate { to, .. } => ("RecurringDateTransition", to),
        };
        w.start(T, name);
        to.write(w, "To");
        match self {
            Transition::Plain { .. } => {}
            Transition::AbsoluteDate { date_time, .. } => date_time.write(w, "DateTime"),
            Transition::RecurringDay {
                time_offset,
                month,
                day_of_week,
                occurrence,
                ..
            } => {
                EwsValue::write(time_offset, w, "TimeOffset");
                month.write(w, "Month");
                day_of_week.write(w, "DayOfWeek");
                occurrence.write(w, "Occurrence");
            }
            Transition::RecurringDate {
                time_offset,
                month,
                day,
                ..
            } => {
                EwsValue::write(time_offset, w, "TimeOffset");
                month.write(w, "Month");
                day.write(w, "Day");
            }
        }
        w.end(T, name);
    }
}

impl<'x> TransitionsGroup<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let id = p.attr(attrs, "Id")?;
        let mut transitions = Vec::new();
        while let Some(child) = p.child()? {
            let Some(kind) = transition_kind(child.local) else {
                p.skip()?;
                continue;
            };
            p.expect_types(&child)?;
            p.count_id()?;
            transitions.push(Transition::parse(p, kind)?);
        }
        Ok(TransitionsGroup { id, transitions })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(id) = &self.id {
            w.attr("Id", id);
        }
        for transition in &self.transitions {
            transition.write(w);
        }
        w.end(T, local);
    }
}

impl<'x> EwsValue<'x> for TimeZoneDefinition<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let mut definition = TimeZoneDefinition {
            id: p.attr(attrs, "Id")?,
            name: p.attr(attrs, "Name")?,
            periods: Vec::new(),
            groups: Vec::new(),
            transitions: None,
        };
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "Periods" => {
                    p.expect_types(&child)?;
                    while let Some(period) = p.child()? {
                        if period.local != "Period" {
                            p.skip()?;
                            continue;
                        }
                        p.expect_types(&period)?;
                        p.count_id()?;
                        definition.periods.push(Period {
                            bias: p.attr_value(&period.attrs, "Bias")?,
                            name: p.attr(&period.attrs, "Name")?,
                            id: p.attr(&period.attrs, "Id")?,
                        });
                        p.skip_rest()?;
                    }
                },
                "TransitionsGroups" => {
                    p.expect_types(&child)?;
                    while let Some(group) = p.child()? {
                        if group.local != "TransitionsGroup" {
                            p.skip()?;
                            continue;
                        }
                        p.expect_types(&group)?;
                        definition.groups.push(TransitionsGroup::parse(p, &group.attrs)?);
                    }
                },
                "Transitions" => {
                    p.expect_types(&child)?;
                    definition.transitions = Some(TransitionsGroup::parse(p, &child.attrs)?);
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(definition)
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(id) = &self.id {
            w.attr("Id", id);
        }
        if let Some(name) = &self.name {
            w.attr("Name", name);
        }
        if !self.periods.is_empty() {
            w.start(T, "Periods");
            for period in &self.periods {
                w.start(T, "Period");
                if let Some(bias) = &period.bias {
                    let mut text = Vec::new();
                    bias.write(&mut text);
                    w.attr("Bias", std::str::from_utf8(&text).unwrap_or_default());
                }
                if let Some(name) = &period.name {
                    w.attr("Name", name);
                }
                if let Some(id) = &period.id {
                    w.attr("Id", id);
                }
                w.empty();
            }
            w.end(T, "Periods");
        }
        if !self.groups.is_empty() {
            w.start(T, "TransitionsGroups");
            for group in &self.groups {
                group.write(w, "TransitionsGroup");
            }
            w.end(T, "TransitionsGroups");
        }
        if let Some(transitions) = &self.transitions {
            transitions.write(w, "Transitions");
        }
        w.end(T, local);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeChangePattern {
    RelativeYearly(RelativeYearly),
    AbsoluteDate(XsDate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeChange<'x> {
    pub time_zone_name: Option<Cow<'x, str>>,
    pub offset: XsDuration,
    pub pattern: TimeChangePattern,
    pub time: XsTime,
}

impl<'x> EwsValue<'x> for TimeChange<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let time_zone_name = p.attr(attrs, "TimeZoneName")?;
        let mut offset = None;
        let mut pattern = None;
        let mut time = None;
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "Offset" => {
                    p.expect_types(&child)?;
                    offset = Some(p.value("Offset")?);
                },
                "RelativeYearlyRecurrence" => {
                    p.expect_types(&child)?;
                    pattern = Some(TimeChangePattern::RelativeYearly(RelativeYearly::parse_fields(p)?));
                },
                "AbsoluteDate" => {
                    p.expect_types(&child)?;
                    pattern = Some(TimeChangePattern::AbsoluteDate(p.value("AbsoluteDate")?));
                },
                "Time" => {
                    p.expect_types(&child)?;
                    time = Some(p.value("Time")?);
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(TimeChange {
            time_zone_name,
            offset: required(p, offset, "Offset")?,
            pattern: required(p, pattern, "TimeChangePattern")?,
            time: required(p, time, "Time")?,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(name) = &self.time_zone_name {
            w.attr("TimeZoneName", name);
        }
        EwsValue::write(&self.offset, w, "Offset");
        match &self.pattern {
            TimeChangePattern::RelativeYearly(yearly) => {
                w.start(T, "RelativeYearlyRecurrence");
                yearly.write_fields(w);
                w.end(T, "RelativeYearlyRecurrence");
            }
            TimeChangePattern::AbsoluteDate(date) => EwsValue::write(date, w, "AbsoluteDate"),
        }
        EwsValue::write(&self.time, w, "Time");
        w.end(T, local);
    }
}

ews_fields! {
    pub struct TimeZoneFields<'x> {
        base_offset: "BaseOffset" => XsDuration,
        standard: "Standard" => TimeChange<'x>,
        daylight: "Daylight" => TimeChange<'x>,
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TimeZone<'x> {
    pub time_zone_name: Option<Cow<'x, str>>,
    pub fields: TimeZoneFields<'x>,
}

impl<'x> EwsValue<'x> for TimeZone<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let time_zone_name = p.attr(attrs, "TimeZoneName")?;
        let mut fields = TimeZoneFields::default();
        while let Some(child) = p.child()? {
            if !fields.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Ok(TimeZone {
            time_zone_name,
            fields,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(name) = &self.time_zone_name {
            w.attr("TimeZoneName", name);
        }
        self.fields.write_fields(w);
        w.end(T, local);
    }
}
