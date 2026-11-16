/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        IanaParse, LinkRelation, PartialDateTime,
        parser::Boolean,
        timezone::{Tz, ZonedDateTime},
    },
    icalendar::*,
    jscalendar::{
        JSCalendarDateTime, JSCalendarId, JSCalendarProperty, JSCalendarValue,
        export::ConvertedComponent, ext::JSCalendarKeyExt,
    },
    jscontact::export::params::ParamValue,
};
use jiff::{Timestamp, civil, tz::Offset};
use jmap_tools::{Key, Value};
use std::str::FromStr;

impl ICalendarEntry {
    pub(super) fn import_converted<I: JSCalendarId, B: JSCalendarId>(
        self,
        path: &[JSCalendarProperty<I>],
        conversions: &mut Option<ConvertedComponent<'_, I, B>>,
    ) -> Self {
        self.import_converted_with_id(path, conversions, None)
    }

    pub(super) fn import_converted_with_id<I: JSCalendarId, B: JSCalendarId>(
        mut self,
        path: &[JSCalendarProperty<I>],
        conversions: &mut Option<ConvertedComponent<'_, I, B>>,
        id: Option<&str>,
    ) -> Self {
        let Some(conversions) = conversions
            .as_mut()
            .filter(|c| c.converted_props_count < c.converted_props.len())
        else {
            return self;
        };

        // Obtain jsid
        let value = self.values.first().and_then(|v| v.as_text());
        let jsid = if matches!(self.name, ICalendarProperty::RelatedTo) {
            value
        } else {
            id.or_else(|| self.jsid())
        };

        let mut matched_once = false;

        'outer: for (keys, value) in conversions.converted_props.iter_mut() {
            if matches!(value, Value::Null) {
                continue;
            }

            for (pos, item) in path.iter().enumerate() {
                if !keys
                    .iter()
                    .any(|k| matches!(k, Key::Property(p) if p == item))
                {
                    if pos == 0 && matched_once {
                        // Array is sorted, so if we didn't match the first item,
                        // we won't match any further.
                        break 'outer;
                    } else {
                        continue 'outer;
                    }
                } else {
                    matched_once = true;
                }
            }

            if jsid
                .map(Key::Borrowed)
                .is_none_or(|prop_id| keys.iter().any(|k| k.same_key(&prop_id)))
            {
                self.import_converted_properties(std::mem::take(value));
                conversions.converted_props_count += 1;
                break;
            }
        }

        // Update binary contents
        if self
            .parameter(&ICalendarParameterName::Value)
            .is_some_and(|v| {
                matches!(
                    v,
                    ICalendarParameterValue::Value(ICalendarValueType::Binary)
                )
            })
            && let Some(ICalendarValue::Uri(Uri::Data(data))) = self.values.first_mut()
        {
            let bin = ICalendarValue::Binary(std::mem::take(&mut data.data));
            if let Some(content_type) = data.content_type.take()
                && !self.has_parameter(&ICalendarParameterName::Fmttype)
            {
                self.params.push(ICalendarParameter::fmttype(content_type));
            }
            self.values[0] = bin;
        }

        self
    }

    pub(super) fn import_converted_properties<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        props: Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) {
        for (key, value) in props.into_expanded_object() {
            match key {
                Key::Property(JSCalendarProperty::Name) => {
                    if let Some(name) = value.into_string() {
                        self.name = ICalendarProperty::parse(name.as_bytes())
                            .unwrap_or(ICalendarProperty::Other(name.to_ascii_uppercase()));
                    }
                }
                Key::Property(JSCalendarProperty::Parameters) => {
                    self.import_jcal_params(value);
                }
                _ => {}
            }
        }
    }

    pub(super) fn import_jcal_params<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        params: Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) {
        for (key, value) in params.into_expanded_object() {
            let (first, rest) = match value {
                Value::Array(values) => (None, values),
                value => (Some(value), Vec::new()),
            };
            let mut values = first
                .into_iter()
                .chain(rest)
                .filter_map(ParamValue::try_from_value)
                .peekable();

            if values.peek().is_none() {
                continue;
            }

            let key = key.to_string();
            let Some(param) = ICalendarParameterName::try_parse(key.as_bytes()) else {
                let key = key.into_owned();

                for value in values {
                    self.params.push(ICalendarParameter {
                        name: ICalendarParameterName::Other(key.to_ascii_uppercase()),
                        value: value.into_string().into_owned().into(),
                    });
                }

                continue;
            };

            for value in values {
                let value = match &param {
                    ICalendarParameterName::Value => {
                        let value = value.into_string();
                        ICalendarValueType::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Value)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Size | ICalendarParameterName::Order => {
                        match value.into_number() {
                            Ok(n) => ICalendarParameterValue::Integer(n.unsigned_abs()),
                            Err(value) => {
                                ICalendarParameterValue::Text(value.into_string().into_owned())
                            }
                        }
                    }
                    ICalendarParameterName::Rsvp | ICalendarParameterName::Derived => {
                        let value = value.into_string();
                        Boolean::parse(value.as_bytes())
                            .map(|v| ICalendarParameterValue::Bool(v.0))
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Altrep
                    | ICalendarParameterName::DelegatedFrom
                    | ICalendarParameterName::DelegatedTo
                    | ICalendarParameterName::Dir
                    | ICalendarParameterName::Member
                    | ICalendarParameterName::SentBy
                    | ICalendarParameterName::Schema => {
                        ICalendarParameterValue::Uri(Uri::parse(value.into_string().into_owned()))
                    }
                    ICalendarParameterName::Range => {
                        let value = value.into_string();
                        if value.eq_ignore_ascii_case("THISANDFUTURE") {
                            ICalendarParameterValue::Bool(true)
                        } else {
                            ICalendarParameterValue::Text(value.into_owned())
                        }
                    }
                    ICalendarParameterName::Gap => {
                        let value = value.into_string();
                        ICalendarDuration::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Duration)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Cutype => {
                        let value = value.into_string();
                        ICalendarUserTypes::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Cutype)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Fbtype => {
                        let value = value.into_string();
                        ICalendarFreeBusyType::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Fbtype)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Partstat => {
                        let value = value.into_string();
                        ICalendarParticipationStatus::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Partstat)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Related => {
                        let value = value.into_string();
                        ICalendarRelated::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Related)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Reltype => {
                        let value = value.into_string();
                        ICalendarRelationshipType::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Reltype)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Role => {
                        let value = value.into_string();
                        ICalendarParticipationRole::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Role)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::ScheduleAgent => {
                        let value = value.into_string();
                        ICalendarScheduleAgentValue::parse(value.as_bytes())
                            .map(ICalendarParameterValue::ScheduleAgent)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::ScheduleForceSend => {
                        let value = value.into_string();
                        ICalendarScheduleForceSendValue::parse(value.as_bytes())
                            .map(ICalendarParameterValue::ScheduleForceSend)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Display => {
                        let value = value.into_string();
                        ICalendarDisplayType::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Display)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Feature => {
                        let value = value.into_string();
                        ICalendarFeatureType::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Feature)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    ICalendarParameterName::Linkrel => {
                        let value = value.into_string();
                        LinkRelation::parse(value.as_bytes())
                            .map(ICalendarParameterValue::Linkrel)
                            .unwrap_or_else(|| ICalendarParameterValue::Text(value.into_owned()))
                    }
                    _ => ICalendarParameterValue::Text(value.into_string().into_owned()),
                };

                self.params.push(ICalendarParameter {
                    name: param.clone(),
                    value,
                });
            }
        }
    }
}

impl ICalendarEntry {
    /*
     A DATE value has no time and no timezone: the TZID parameter MUST NOT be applied to
     it (Section 3.2.19 of [RFC5545]).
    */

    pub(super) fn with_date(mut self, dt: ZonedDateTime, is_date: bool) -> Self {
        if !is_date {
            return self.with_date_time(dt);
        }

        debug_assert!(self.values.is_empty());
        self.retain_date_params();
        self.values
            .push(PartialDateTime::from_date_timestamp(dt.naive_timestamp()).into());
        self
    }

    pub(super) fn with_dates(mut self, dts: Vec<ZonedDateTime>, is_date: bool) -> Self {
        if !is_date {
            return self.with_date_times(dts);
        }

        debug_assert!(self.values.is_empty());
        self.retain_date_params();
        for dt in dts {
            self.values
                .push(PartialDateTime::from_date_timestamp(dt.naive_timestamp()).into());
        }
        self
    }

    pub(super) fn with_date_time(mut self, dt: ZonedDateTime) -> Self {
        debug_assert!(self.values.is_empty());

        self.remove_non_date_time_value_type();

        // Best effort to restore the original timezone
        let tz_id = self.tz_id();
        let has_tz_id = tz_id.is_some();
        self.insert_date(
            dt,
            has_tz_id,
            !has_tz_id,
            tz_id.and_then(|id| Tz::from_str(id).ok()),
        );
        self
    }

    pub(super) fn with_period(mut self, dt: ZonedDateTime, duration: ICalendarDuration) -> Self {
        self = self.with_date_time(dt);

        if let Some(ICalendarValue::PartialDateTime(start)) = self.values.pop() {
            self.values.push(ICalendarValue::Period(Box::new(
                ICalendarPeriod::Duration { start, duration },
            )));
        }

        if !self.has_parameter(&ICalendarParameterName::Value) {
            self.params
                .push(ICalendarParameter::value(ICalendarValueType::Period));
        }

        self
    }

    pub(super) fn with_date_times(mut self, dts: Vec<ZonedDateTime>) -> Self {
        debug_assert!(self.values.is_empty());

        self.remove_non_date_time_value_type();
        let tz_id = self.tz_id();
        let has_tz_id = tz_id.is_some();
        let entry_tz = tz_id
            .and_then(|id| Tz::from_str(id).ok())
            .or_else(|| dts.first().map(|dt| dt.timezone()));

        for (pos, dt) in dts.into_iter().enumerate() {
            self.insert_date(dt, has_tz_id, pos == 0, entry_tz);
        }

        self
    }

    fn remove_non_date_time_value_type(&mut self) {
        self.params.retain(|param| {
            !matches!(
                (&param.name, &param.value),
                (
                    ICalendarParameterName::Value,
                    ICalendarParameterValue::Value(
                        ICalendarValueType::Period | ICalendarValueType::Date
                    )
                )
            )
        });
    }

    fn retain_date_params(&mut self) {
        let mut has_date_type = false;
        self.params
            .retain(|param| match (&param.name, &param.value) {
                (ICalendarParameterName::Tzid, _) => false,
                (
                    ICalendarParameterName::Value,
                    ICalendarParameterValue::Value(ICalendarValueType::Date),
                ) => {
                    has_date_type = true;
                    true
                }
                (ICalendarParameterName::Value, _) => false,
                _ => true,
            });
        if !has_date_type {
            self.params
                .push(ICalendarParameter::value(ICalendarValueType::Date));
        }
    }

    fn insert_date(
        &mut self,
        mut dt: ZonedDateTime,
        has_tz_id: bool,
        add_tz_id: bool,
        entry_tz: Option<Tz>,
    ) {
        if let Some(tz) = entry_tz
            && tz != dt.timezone()
        {
            dt = dt.with_timezone(tz);
        }

        let tz = dt.timezone();
        if has_tz_id {
            self.values
                .push(PartialDateTime::from_naive_timestamp(dt.naive_timestamp()).into());
        } else if tz.is_utc() {
            self.values
                .push(PartialDateTime::from_utc_timestamp(dt.timestamp()).into());
        } else {
            if add_tz_id && let Some(tz_name) = tz.name() {
                self.params
                    .push(ICalendarParameter::tzid(tz_name.into_owned()));
            }
            self.values
                .push(PartialDateTime::from_naive_timestamp(dt.naive_timestamp()).into());
        }
    }
}

impl JSCalendarDateTime {
    pub fn to_utc_date_time(&self) -> Option<ZonedDateTime> {
        Timestamp::from_second(self.timestamp)
            .ok()
            .map(|timestamp| Tz::UTC.from_timestamp(timestamp))
    }

    pub fn to_naive_date_time(&self) -> Option<civil::DateTime> {
        Timestamp::from_second(self.timestamp)
            .ok()
            .map(|timestamp| Offset::UTC.to_datetime(timestamp))
    }
}

impl From<JSCalendarDateTime> for PartialDateTime {
    fn from(dt: JSCalendarDateTime) -> Self {
        if !dt.is_local {
            Self::from_utc_timestamp(dt.timestamp)
        } else {
            Self::from_naive_timestamp(dt.timestamp)
        }
    }
}
