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
        grammar::{AddressPart, Comparator, MatchType},
    },
    runtime::{RuntimeError, handler::Handler},
};
use ahash::AHashSet;
use mail_parser::{
    AddressList, HeaderForm, HeaderValue, Mailbox, parse_address_detail_part, parse_address_domain,
    parse_address_local_part, parse_address_user_part,
};
use smallvec::SmallVec;

impl<'x> Context<'x> {
    pub(crate) fn test_address<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        test: &ops::TestAddress,
        handler: &mut H,
    ) -> Result<TestResult, RuntimeError> {
        let key_list = self.eval_keys(script, test.key_list)?;
        let header_list = self.parse_header_names(script, test.header_list)?;
        let address_part = AddressPart::from_code(test.address_part);
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
                        self.find_addresses(header, &address_part, |value| {
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
                        self.find_addresses(header, &address_part, |value| {
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
                        self.find_addresses(header, &address_part, |value| {
                            if !value.is_empty() {
                                count += 1;
                            }
                            false
                        })
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
                        self.find_addresses(header, &address_part, |value| {
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

    pub(crate) fn find_addresses(
        &self,
        header: HeaderRef<'x>,
        part: &AddressPart,
        mut visitor_fnc: impl FnMut(&str) -> bool,
    ) -> bool {
        if let HeaderValue::Address(list) = header.value() {
            return visit_addresses(list, part, &mut visitor_fnc);
        }
        match header.parse_as(HeaderForm::Addresses).value().as_address() {
            Some(list) => visit_addresses(list, part, &mut visitor_fnc),
            None => visitor_fnc(""),
        }
    }
}

fn visit_addresses(
    list: AddressList<'_>,
    part: &AddressPart,
    visitor_fnc: &mut impl FnMut(&str) -> bool,
) -> bool {
    list.mailboxes()
        .any(|mailbox| part.eval(mailbox).is_some_and(&mut *visitor_fnc))
}

impl AddressPart {
    pub(crate) fn eval<'x>(&self, mailbox: Mailbox<'x>) -> Option<&'x str> {
        let email = mailbox.address().or(mailbox.name());
        match (self, email) {
            (AddressPart::All, _) => email,
            (AddressPart::LocalPart, Some(email)) if !email.is_empty() => {
                parse_address_local_part(email)
            }
            (AddressPart::Domain, Some(email)) if !email.is_empty() => parse_address_domain(email),
            (AddressPart::User, Some(email)) if !email.is_empty() => parse_address_user_part(email),
            (AddressPart::Detail, Some(email)) if !email.is_empty() => {
                parse_address_detail_part(email)
            }
            (AddressPart::Name, _) => mailbox.name(),
            _ => email,
        }
    }

    pub(crate) fn eval_strict<'x>(&self, mailbox: Mailbox<'x>) -> Option<&'x str> {
        match (self, mailbox.address()) {
            (AddressPart::All, Some(email)) => Some(email),
            (AddressPart::LocalPart, Some(email)) if !email.is_empty() => {
                parse_address_local_part(email)
            }
            (AddressPart::Domain, Some(email)) if !email.is_empty() => parse_address_domain(email),
            (AddressPart::User, Some(email)) if !email.is_empty() => parse_address_user_part(email),
            (AddressPart::Detail, Some(email)) if !email.is_empty() => {
                parse_address_detail_part(email)
            }
            (AddressPart::Name, _) => mailbox.name(),
            (_, email) => email,
        }
    }

    pub(crate) fn eval_string<'x>(&self, addr: &'x str) -> Option<&'x str> {
        if !addr.is_empty() {
            match self {
                AddressPart::All => addr.into(),
                AddressPart::LocalPart => parse_address_local_part(addr),
                AddressPart::Domain => parse_address_domain(addr),
                AddressPart::User => parse_address_user_part(addr),
                AddressPart::Detail => parse_address_detail_part(addr),
                _ => addr.into(),
            }
        } else {
            addr.into()
        }
    }
}
