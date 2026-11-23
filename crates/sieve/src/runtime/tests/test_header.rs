/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ScanMeter, TestResult};
use crate::{
    Context, Sieve,
    bytecode::{
        ops::{self, MimeOpts},
        rec::{Range, Rec, tag},
    },
    compiler::{
        Number,
        grammar::{Comparator, MatchType},
    },
    runtime::{
        RuntimeError,
        eval::ValueRef,
        handler::Handler,
        message::{
            headers::HeaderRef,
            parts::{PartCursor, Scope},
        },
    },
};
use ahash::AHashSet;
use mail_parser::{HeaderForm, HeaderKey, HeaderName, HeaderValue, MessagePart, PartId};
use smallvec::SmallVec;

pub(crate) type HeaderNames<'x> = SmallVec<[HeaderName<'x>; 4]>;
pub(crate) type HeaderKeys<'x> = SmallVec<[HeaderKey<'x>; 4]>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MimeOptsRef<'x> {
    None,
    Type,
    Subtype,
    ContentType,
    Param(SmallVec<[&'x str; 2]>),
}

impl<'x> Context<'x> {
    pub(crate) fn test_header<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        test: &ops::TestHeader,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let key_list = self.eval_keys(script, test.key_list)?;
        let header_list = self.parse_header_names(script, test.header_list)?;
        let mime_opts = self.mime_opts(script, &test.mime_opts)?;
        let comparator = Comparator::from_code(test.comparator);
        let match_type = test.match_type.match_type();

        let result = match &match_type {
            MatchType::Is | MatchType::Contains | MatchType::Value(_) => {
                let mut meter = self.scan_meter(key_list.len());
                let result = self.find_headers(
                    &header_list,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        self.find_header_values(header, &mime_opts, |value| {
                            key_list.iter().any(|key| match &match_type {
                                MatchType::Is => comparator.is(&value, &key.value),
                                MatchType::Contains => {
                                    comparator.contains(value, key.value.to_string().as_ref())
                                }
                                MatchType::Value(rel_match) => {
                                    comparator.relational(rel_match, &value, &key.value)
                                }
                                _ => false,
                            })
                        })
                    },
                );
                self.settle_scan(meter)?;
                result
            }
            MatchType::Matches(capture_positions) | MatchType::Regex(capture_positions) => {
                let mut meter = self.scan_meter(key_list.len());
                let mut captured_values = Vec::new();
                let is_matches = matches!(&match_type, MatchType::Matches(_));
                let to_lower = comparator.is_casemap();
                let mut error = None;
                let result = self.find_headers(
                    &header_list,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        self.find_header_values(header, &mime_opts, |value| {
                            for key in &key_list {
                                let matched = if is_matches {
                                    self.glob_matches(
                                        script,
                                        to_lower,
                                        key,
                                        value,
                                        *capture_positions,
                                        &mut captured_values,
                                    )
                                } else {
                                    self.regex_matches(
                                        script,
                                        key,
                                        value,
                                        *capture_positions,
                                        &mut captured_values,
                                    )
                                };
                                match matched {
                                    Ok(true) => return true,
                                    Ok(false) => (),
                                    Err(err) => {
                                        error = Some(err);
                                        return true;
                                    }
                                }
                            }
                            false
                        })
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
            MatchType::Count(rel_match) => {
                let mut count: i64 = 0;
                let mut meter = self.scan_meter(1);
                self.find_headers(
                    &header_list,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        match &mime_opts {
                            MimeOptsRef::None => {
                                count += 1;
                            }
                            MimeOptsRef::Type | MimeOptsRef::Subtype | MimeOptsRef::ContentType => {
                                if let HeaderValue::ContentType(_) = header.value() {
                                    count += 1;
                                }
                            }
                            MimeOptsRef::Param(params) => {
                                if let HeaderValue::ContentType(ct) = header.value() {
                                    count +=
                                        ct.attributes()
                                            .filter(|(name, _)| {
                                                params.iter().any(|p| p.eq_ignore_ascii_case(name))
                                            })
                                            .count() as i64;
                                }
                            }
                        }

                        false
                    },
                );
                self.settle_scan(meter)?;

                key_list
                    .iter()
                    .any(|key| rel_match.cmp(&Number::from(count), &key.value.to_number()))
            }
            MatchType::List => {
                let mut values: Vec<&str> = Vec::new();
                let mut seen: AHashSet<&str> = AHashSet::new();
                let mut meter = self.scan_meter(1);
                self.find_headers(
                    &header_list,
                    test.index,
                    test.mime_anychild,
                    &mut meter,
                    |header, _| {
                        self.find_header_values(header, &mime_opts, |value| {
                            if !value.is_empty() && !seen.contains(value) {
                                let value = self.alloc_str(value);
                                seen.insert(value);
                                values.push(value);
                            }
                            false
                        })
                    },
                );
                self.settle_scan(meter)?;

                if !values.is_empty() {
                    let lists: SmallVec<[&str; 4]> = key_list
                        .iter()
                        .map(|key| self.intern_cow(key.value.clone().into_string()))
                        .collect();
                    return TestResult::from_reply(
                        handler.list_contains(self, &lists, &values, comparator.as_match()),
                        test.is_not,
                    );
                }

                false
            }
        };

        Ok(TestResult::Bool(result ^ test.is_not))
    }

    pub(crate) fn mime_opts(
        &self,
        script: &'x Sieve<'x>,
        opts: &MimeOpts,
    ) -> Result<MimeOptsRef<'x>, RuntimeError> {
        Ok(match opts.kind {
            0 => MimeOptsRef::Type,
            1 => MimeOptsRef::Subtype,
            2 => MimeOptsRef::ContentType,
            3 => MimeOptsRef::Param(
                self.eval_strings(script, opts.params)?
                    .into_iter()
                    .collect(),
            ),
            _ => MimeOptsRef::None,
        })
    }

    pub(crate) fn parse_header_names(
        &self,
        script: &'x Sieve<'x>,
        header_names: Range,
    ) -> Result<HeaderNames<'x>, RuntimeError> {
        let mut result = HeaderNames::with_capacity(header_names.len as usize);
        let mut iter = script.recs(header_names)?;
        while let Some(rec) = iter.next() {
            if rec.tag == tag::HEADER {
                result.push(borrow_header_name(script.header_name(rec.c)?));
            } else {
                let value = ValueRef::decode(script, rec, &mut iter)?;
                let value = self.eval_value_ref(script, value)?;
                if let Some(header_name) =
                    self.parse_header_name_str(self.intern_cow(value.into_string()))
                {
                    result.push(header_name);
                }
            }
        }
        Ok(result)
    }

    #[inline(always)]
    pub(crate) fn parse_header_name(
        &self,
        script: &'x Sieve<'x>,
        header_name: Rec,
    ) -> Result<Option<HeaderName<'x>>, RuntimeError> {
        if header_name.tag == tag::HEADER {
            return Ok(Some(borrow_header_name(script.header_name(header_name.c)?)));
        }
        let name = self.eval_str(script, header_name)?;
        Ok(self.parse_header_name_str(name))
    }

    #[inline(always)]
    pub(crate) fn parse_header_name_str(&self, name: &'x str) -> Option<HeaderName<'x>> {
        HeaderName::parse(name)
    }

    pub(crate) fn find_headers(
        &self,
        header_names: &[HeaderName<'_>],
        index: Option<i32>,
        any_child: bool,
        meter: &mut ScanMeter,
        mut visitor_fnc: impl FnMut(HeaderRef<'x>, PartId) -> bool,
    ) -> bool {
        let Some(part) = self.current_part() else {
            return false;
        };
        if !any_child {
            return self.edits.hidden_end(part.id()).is_none()
                && (!meter.charge_headers(part)
                    || self.find_part_headers(
                        part,
                        header_names.iter().map(|name| (name, name.key())),
                        index,
                        &mut visitor_fnc,
                    ));
        }
        let keys: HeaderKeys<'_> = header_names.iter().map(HeaderName::key).collect();
        let mut parts = PartCursor::subtree(part, true, Scope::Message);
        while let Some(part) = self.advance(&mut parts) {
            if !meter.charge_headers(part) {
                return true;
            }
            if self.find_part_headers(
                part,
                header_names.iter().zip(keys.iter().copied()),
                index,
                &mut visitor_fnc,
            ) {
                return true;
            }
        }
        false
    }

    #[inline(always)]
    fn find_part_headers<'s, 'n: 's>(
        &self,
        part: MessagePart<'x>,
        mut names: impl Iterator<Item = (&'s HeaderName<'n>, HeaderKey<'s>)>,
        index: Option<i32>,
        visitor_fnc: &mut impl FnMut(HeaderRef<'x>, PartId) -> bool,
    ) -> bool {
        let id = part.id();
        match self.edits.headers(id) {
            None => {
                let headers = part.headers();
                names.any(|(_, key)| {
                    visit_indexed(
                        || headers.all_key(key).map(HeaderRef::Parsed),
                        index,
                        |header| visitor_fnc(header, id),
                    )
                })
            }
            Some(edited) => names.any(|(name, _)| {
                visit_indexed(
                    || {
                        edited
                            .iter()
                            .filter(|header| header.is_named(name))
                            .copied()
                    },
                    index,
                    |header| visitor_fnc(header, id),
                )
            }),
        }
    }

    pub(crate) fn find_header_values(
        &self,
        header: HeaderRef<'x>,
        mime_opts: &MimeOptsRef<'_>,
        mut visitor_fnc: impl FnMut(&str) -> bool,
    ) -> bool {
        if let MimeOptsRef::None = mime_opts {
            return match (header, header.value()) {
                (HeaderRef::Added(added), _) => visitor_fnc(added.value),
                (header, HeaderValue::Text(text))
                    if matches!(
                        header.name(),
                        HeaderName::Subject
                            | HeaderName::Comments
                            | HeaderName::ContentDescription
                            | HeaderName::ContentLocation
                            | HeaderName::ContentTransferEncoding,
                    ) =>
                {
                    visitor_fnc(text)
                }
                (header, _) => visitor_fnc(
                    header
                        .parse_as(HeaderForm::Text)
                        .value()
                        .as_text()
                        .unwrap_or_default(),
                ),
            };
        }

        let parsed;
        let content_type = match header {
            HeaderRef::Added(_) => {
                parsed = header.parse_as(HeaderForm::ContentType);
                parsed.value().as_content_type()
            }
            header => header.value().as_content_type(),
        };
        let Some(content_type) = content_type else {
            return visitor_fnc("");
        };

        match mime_opts {
            MimeOptsRef::Type => visitor_fnc(content_type.ctype()),
            MimeOptsRef::Subtype => visitor_fnc(content_type.subtype().unwrap_or_default()),
            MimeOptsRef::ContentType => match content_type.subtype() {
                Some(subtype) => visitor_fnc(&format!("{}/{}", content_type.ctype(), subtype)),
                None => visitor_fnc(content_type.ctype()),
            },
            MimeOptsRef::Param(params) => {
                for param in params {
                    for (name, value) in content_type.attributes() {
                        if param.eq_ignore_ascii_case(name) && visitor_fnc(value) {
                            return true;
                        }
                    }
                }
                visitor_fnc("")
            }
            MimeOptsRef::None => visitor_fnc(""),
        }
    }
}

#[inline(always)]
fn visit_indexed<'x, I: Iterator<Item = HeaderRef<'x>>>(
    named: impl Fn() -> I,
    index: Option<i32>,
    mut visit: impl FnMut(HeaderRef<'x>) -> bool,
) -> bool {
    match index {
        None => named().any(visit),
        Some(0) => false,
        Some(index) if index > 0 => named().nth(index as usize - 1).is_some_and(visit),
        Some(index) => {
            let position = index.unsigned_abs() as usize;
            let count = named().count();
            count >= position && named().nth(count - position).is_some_and(&mut visit)
        }
    }
}

pub(crate) fn borrow_header_name<'y>(name: &'y HeaderName<'static>) -> HeaderName<'y> {
    match name {
        HeaderName::Other(name) => HeaderName::Other(std::borrow::Cow::Borrowed(name.as_ref())),
        other => other.clone(),
    }
}
