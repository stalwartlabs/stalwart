/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::TestResult;
use crate::runtime::message::headers::HeaderRef;
use crate::{
    Context, Sieve,
    bytecode::ops,
    compiler::{
        Number,
        grammar::{Comparator, MatchType, tests::test_date::DatePart},
    },
    runtime::{RuntimeError, handler::Handler},
};
use calcard::common::timezone::Tz;
use mail_parser::{DateTime, HeaderForm, HeaderValue};
use smallvec::SmallVec;

pub(crate) const ZONE_OFFSET: u8 = 0;
pub(crate) const ZONE_ORIGINAL: u8 = 1;
pub(crate) const ZONE_LOCAL: u8 = 2;
pub(crate) const ZONE_NAMED: u8 = 3;

impl<'x> Context<'x> {
    pub(crate) fn test_date<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        test: &ops::TestDate,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let Some(header_name) = self.parse_header_name(script, test.header_name)? else {
            return Ok(TestResult::Bool(false ^ test.is_not));
        };
        let header_names = [header_name];
        let comparator = Comparator::from_code(test.comparator);
        let match_type = test.match_type.match_type();
        let date_part = DatePart::from_code(test.date_part);
        let zone = test.zone;

        let result = match &match_type {
            MatchType::Count(rel_match) => {
                let mut date_count = 0;
                let mut meter = self.scan_meter(1);
                self.find_headers(
                    &header_names,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        if self.find_dates(header).is_some() {
                            date_count += 1;
                        }
                        false
                    },
                );
                self.settle_scan(meter)?;

                self.eval_values(script, test.key_list)?
                    .iter()
                    .any(|key| rel_match.cmp(&Number::from(date_count), &key.to_number()))
            }
            MatchType::List => {
                let mut values: SmallVec<[&'x str; 4]> = SmallVec::new();
                let mut meter = self.scan_meter(1);
                self.find_headers(
                    &header_names,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        if let Some(dt) = self.find_dates(header) {
                            let value = date_part.eval(&zone.eval(dt));
                            if !value.is_empty() && !values.iter().any(|v| *v == value) {
                                values.push(self.alloc_string(value));
                            }
                        }
                        false
                    },
                );
                self.settle_scan(meter)?;
                if !values.is_empty() {
                    let lists = self.eval_strings(script, test.key_list)?;
                    return TestResult::from_reply(
                        handler.list_contains(self, &lists, &values, comparator.as_match()),
                        test.is_not,
                    );
                }
                false
            }
            _ => {
                let key_list = self.eval_keys(script, test.key_list)?;
                let mut captured_values = Vec::new();
                let mut error = None;
                let mut meter = self.scan_meter(key_list.len());

                let result = self.find_headers(
                    &header_names,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        let Some(dt) = self.find_dates(header) else {
                            return false;
                        };
                        let value = date_part.eval(&zone.eval(dt));
                        for key in &key_list {
                            match self.key_matches(
                                script,
                                &comparator,
                                &match_type,
                                key,
                                &value,
                                &mut captured_values,
                            ) {
                                Ok(true) => return true,
                                Ok(false) => (),
                                Err(err) => {
                                    error = Some(err);
                                    return true;
                                }
                            }
                        }
                        false
                    },
                );
                self.settle_scan(meter)?;
                if let Some(err) = error {
                    return Err(err);
                }
                if !captured_values.is_empty() {
                    self.set_match_variables(captured_values);
                }
                result
            }
        };

        Ok(TestResult::Bool(result ^ test.is_not))
    }

    pub(crate) fn test_current_date<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        test: &ops::TestCurrentDate,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let comparator = Comparator::from_code(test.comparator);
        let match_type = test.match_type.match_type();
        let date_part = DatePart::from_code(test.date_part);
        let mut result = false;

        match &match_type {
            MatchType::Count(rel_match) => {
                result = self
                    .eval_values(script, test.key_list)?
                    .iter()
                    .any(|key| rel_match.cmp(&Number::from(1.0), &key.to_number()));
            }
            MatchType::List => {
                let value = date_part.eval(&self.current_date_time(test.zone));
                if !value.is_empty() {
                    let lists = self.eval_strings(script, test.key_list)?;
                    return TestResult::from_reply(
                        handler.list_contains(
                            self,
                            &lists,
                            &[value.as_str()],
                            comparator.as_match(),
                        ),
                        test.is_not,
                    );
                }
            }
            _ => {
                let value = date_part.eval(&self.current_date_time(test.zone));
                let keys = self.eval_keys(script, test.key_list)?;
                let mut captured_values = Vec::new();

                for key in &keys {
                    if self.key_matches(
                        script,
                        &comparator,
                        &match_type,
                        key,
                        &value,
                        &mut captured_values,
                    )? {
                        result = true;
                        break;
                    }
                }

                if !captured_values.is_empty() {
                    self.set_match_variables(captured_values);
                }
            }
        }

        Ok(TestResult::Bool(result ^ test.is_not))
    }

    fn current_date_time(&self, zone: ops::Zone) -> DateTime {
        zone.eval(DateTime::from_timestamp(self.current_time))
    }

    pub(crate) fn find_dates(&self, header: HeaderRef<'x>) -> Option<DateTime> {
        match header.value() {
            HeaderValue::DateTime(dt) => dt.is_valid().then_some(dt),
            _ => header
                .parse_as(HeaderForm::Date)
                .value()
                .as_datetime()
                .filter(DateTime::is_valid),
        }
    }
}

impl DatePart {
    fn eval(&self, dt: &DateTime) -> String {
        match self {
            DatePart::Year => format!("{:04}", dt.year),
            DatePart::Month => format!("{:02}", dt.month),
            DatePart::Day => format!("{:02}", dt.day),
            DatePart::Date => format!("{:04}-{:02}-{:02}", dt.year, dt.month, dt.day,),
            DatePart::Julian => ((dt.julian_day() as f64 - 2400000.5) as i64).to_string(),
            DatePart::Hour => format!("{:02}", dt.hour),
            DatePart::Minute => format!("{:02}", dt.minute),
            DatePart::Second => format!("{:02}", dt.second),
            DatePart::Time => format!("{:02}:{:02}:{:02}", dt.hour, dt.minute, dt.second,),
            DatePart::Iso8601 => dt.to_rfc3339(),
            DatePart::Std11 => dt.to_rfc822(),
            DatePart::Zone => format!(
                "{}{:02}{:02}",
                if dt.tz_before_gmt && (dt.tz_hour > 0 || dt.tz_minute > 0) {
                    "-"
                } else {
                    "+"
                },
                dt.tz_hour,
                dt.tz_minute
            ),
            DatePart::Weekday => dt.day_of_week().to_string(),
        }
    }
}

impl ops::Zone {
    pub(crate) fn eval(&self, dt: DateTime) -> DateTime {
        match self.kind {
            ZONE_OFFSET => dt.to_timezone(self.time),
            ZONE_ORIGINAL => dt,
            ZONE_NAMED => {
                let offset = self
                    .named_zone()
                    .map_or(0, |tz| tz.offset_at_unix(dt.to_timestamp()));
                dt.to_timezone(i64::from(offset))
            }
            _ => DateTime::from_timestamp(dt.to_timestamp()),
        }
    }

    pub(crate) fn named_zone(&self) -> Option<Tz> {
        u16::try_from(self.time).ok().and_then(Tz::from_iana_id)
    }
}
