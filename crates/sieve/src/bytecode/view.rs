/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Corrupt, Decoded,
    cursor::Cursor,
    ops::{self, skip_op},
    rec::{Range, Rec, tag},
};
use crate::{
    Envelope, Sieve,
    compiler::grammar::{
        AddressPart, Comparator, MatchType, actions::action_vacation::Period,
        tests::test_date::DatePart,
    },
    runtime::{
        actions::action_vacation::{PERIOD_DAYS, PERIOD_SECONDS},
        tests::test_date::{ZONE_LOCAL, ZONE_NAMED, ZONE_OFFSET},
    },
};
use mail_parser::HeaderName;
use std::fmt::{self, Debug, Formatter};

#[derive(Debug, Clone, Copy)]
pub enum Value<'s> {
    Text(&'s str),
    Number(i64),
    Float(f64),
    Regex(&'s str),
    Glob(&'s str),
    Header(&'s HeaderName<'static>),
    Local(u16),
    Match(u8),
    Global(&'s str),
    Env(&'s str),
    Envelope(Envelope),
    List(Values<'s>),
    None,
    Other(u8),
}

#[derive(Clone, Copy)]
pub struct Values<'s> {
    sieve: &'s Sieve<'s>,
    range: Range,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagAction {
    Set,
    Add,
    Remove,
}

#[derive(Debug, Clone, Copy)]
pub enum BodyPart<'s> {
    Raw,
    Content(Values<'s>),
    Text,
}

#[derive(Debug, Clone, Copy)]
pub enum MimePart<'s> {
    Type,
    Subtype,
    ContentType,
    Param(Values<'s>),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    Local,
    Offset(i64),
    Named(&'static str),
}

impl Zone {
    fn new(zone: ops::Zone) -> Decoded<Self> {
        match zone.kind {
            ZONE_LOCAL => Ok(Zone::Local),
            ZONE_OFFSET => Ok(Zone::Offset(zone.time)),
            ZONE_NAMED => zone
                .named_zone()
                .and_then(|tz| tz.iana_name())
                .map(Zone::Named)
                .ok_or(Corrupt),
            _ => Err(Corrupt),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Matcher {
    pub match_type: MatchType,
    pub is_not: bool,
    comparator: u8,
}

#[derive(Debug, Clone, Copy)]
pub enum Op<'s> {
    Require,
    Keep,
    FileInto {
        copy: bool,
        create: bool,
        folder: Value<'s>,
        flags: Values<'s>,
        mailbox_id: Value<'s>,
        special_use: Value<'s>,
    },
    Redirect {
        copy: bool,
        list: bool,
        address: Value<'s>,
    },
    Discard,
    Stop,
    TestTrue,
    TestFalse,
    TestAddress {
        headers: Values<'s>,
        keys: Values<'s>,
        address_part: AddressPart,
        matcher: Matcher,
        index: Option<i32>,
        mime_anychild: bool,
    },
    TestEnvelope {
        envelopes: Values<'s>,
        keys: Values<'s>,
        address_part: AddressPart,
        matcher: Matcher,
    },
    TestExists {
        headers: Values<'s>,
        mime_anychild: bool,
        is_not: bool,
    },
    TestHeader {
        headers: Values<'s>,
        keys: Values<'s>,
        matcher: Matcher,
        index: Option<i32>,
        mime: MimePart<'s>,
        mime_anychild: bool,
    },
    TestSize {
        over: bool,
        limit: u64,
        is_not: bool,
    },
    TestBody {
        keys: Values<'s>,
        part: BodyPart<'s>,
        matcher: Matcher,
        include_subject: bool,
    },
    TestCurrentDate {
        zone: Zone,
        date_part: DatePart,
        keys: Values<'s>,
        matcher: Matcher,
    },
    TestEnvironment {
        source: Values<'s>,
        keys: Values<'s>,
        matcher: Matcher,
    },
    TestSpamTest {
        value: Value<'s>,
        percent: bool,
        matcher: Matcher,
    },
    TestString {
        source: Values<'s>,
        keys: Values<'s>,
        matcher: Matcher,
    },
    TestHasFlag {
        variables: Values<'s>,
        flags: Values<'s>,
        matcher: Matcher,
    },
    Jmp(u32),
    Jz(u32),
    Jnz(u32),
    Set {
        name: Value<'s>,
        value: Value<'s>,
        has_modifiers: bool,
    },
    EditFlags {
        action: FlagAction,
        variable: Value<'s>,
        flags: Values<'s>,
    },
    AddHeader {
        last: bool,
        name: Value<'s>,
        value: Value<'s>,
    },
    DeleteHeader {
        name: Value<'s>,
        index: Option<i32>,
        matcher: Matcher,
        patterns: Values<'s>,
        mime_anychild: bool,
    },
    Reject {
        ereject: bool,
        reason: Value<'s>,
    },
    TestVacation {
        addresses: Values<'s>,
        period: Period,
        handle: Value<'s>,
        reason: Value<'s>,
    },
    Vacation {
        subject: Value<'s>,
        from: Value<'s>,
        mime: bool,
        has_fcc: bool,
        reason: Value<'s>,
    },
    Include {
        global: bool,
        once: bool,
        optional: bool,
        name: Value<'s>,
    },
    Other(u8),
}

pub struct Ops<'s> {
    sieve: &'s Sieve<'s>,
    cursor: Cursor<'s>,
}

impl Sieve<'_> {
    pub fn ops(&self) -> Ops<'_> {
        Ops {
            sieve: self,
            cursor: Cursor::new(self.code(), 0),
        }
    }
}

impl<'s> Iterator for Ops<'s> {
    type Item = Result<(u32, Op<'s>), Corrupt>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.at_end() {
            return None;
        }
        let pos = u32::try_from(self.cursor.pos).map_err(|_| Corrupt);
        let result = pos.and_then(|pos| self.decode().map(|op| (pos, op)));
        if result.is_err() {
            self.cursor.pos = usize::MAX;
        }
        Some(result)
    }
}

impl<'s> Ops<'s> {
    fn decode(&mut self) -> Decoded<Op<'s>> {
        let s = self.sieve;
        let c = &mut self.cursor;
        let value = |rec: Rec| Value::new(s, rec);
        let values = |range: Range| Values { sieve: s, range };
        Ok(match c.u8()? {
            ops::Require::OP => {
                ops::Require::decode(c)?;
                Op::Require
            }
            ops::Keep::OP => {
                ops::Keep::decode(c)?;
                Op::Keep
            }
            ops::FileInto::OP => {
                let op = ops::FileInto::decode(c)?;
                Op::FileInto {
                    copy: op.copy,
                    create: op.create,
                    folder: value(op.folder),
                    flags: values(op.flags),
                    mailbox_id: value(op.mailbox_id),
                    special_use: value(op.special_use),
                }
            }
            ops::Redirect::OP => {
                let op = ops::Redirect::decode(c)?;
                Op::Redirect {
                    copy: op.copy,
                    list: op.list,
                    address: value(op.address),
                }
            }
            ops::Discard::OP => Op::Discard,
            ops::Stop::OP => Op::Stop,
            ops::TestTrue::OP => Op::TestTrue,
            ops::TestFalse::OP => Op::TestFalse,
            ops::TestAddress::OP => {
                let op = ops::TestAddress::decode(c)?;
                Op::TestAddress {
                    headers: values(op.header_list),
                    keys: values(op.key_list),
                    address_part: AddressPart::from_code(op.address_part),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                    index: op.index,
                    mime_anychild: op.mime_anychild,
                }
            }
            ops::TestEnvelope::OP => {
                let op = ops::TestEnvelope::decode(c)?;
                Op::TestEnvelope {
                    envelopes: values(op.envelope_list),
                    keys: values(op.key_list),
                    address_part: AddressPart::from_code(op.address_part),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                }
            }
            ops::TestExists::OP => {
                let op = ops::TestExists::decode(c)?;
                Op::TestExists {
                    headers: values(op.header_names),
                    mime_anychild: op.mime_anychild,
                    is_not: op.is_not,
                }
            }
            ops::TestHeader::OP => {
                let op = ops::TestHeader::decode(c)?;
                Op::TestHeader {
                    headers: values(op.header_list),
                    keys: values(op.key_list),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                    index: op.index,
                    mime: match op.mime_opts.kind {
                        0 => MimePart::Type,
                        1 => MimePart::Subtype,
                        2 => MimePart::ContentType,
                        3 => MimePart::Param(values(op.mime_opts.params)),
                        _ => MimePart::None,
                    },
                    mime_anychild: op.mime_anychild,
                }
            }
            ops::TestSize::OP => {
                let op = ops::TestSize::decode(c)?;
                Op::TestSize {
                    over: op.over,
                    limit: op.limit,
                    is_not: op.is_not,
                }
            }
            ops::TestBody::OP => {
                let op = ops::TestBody::decode(c)?;
                Op::TestBody {
                    keys: values(op.key_list),
                    part: match op.body_transform.kind {
                        0 => BodyPart::Raw,
                        1 => BodyPart::Content(values(op.body_transform.content_types)),
                        _ => BodyPart::Text,
                    },
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                    include_subject: op.include_subject,
                }
            }
            ops::TestCurrentDate::OP => {
                let op = ops::TestCurrentDate::decode(c)?;
                Op::TestCurrentDate {
                    zone: Zone::new(op.zone)?,
                    date_part: DatePart::from_code(op.date_part),
                    keys: values(op.key_list),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                }
            }
            ops::TestEnvironment::OP => {
                let op = ops::TestEnvironment::decode(c)?;
                Op::TestEnvironment {
                    source: values(op.source),
                    keys: values(op.key_list),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                }
            }
            ops::TestSpamTest::OP => {
                let op = ops::TestSpamTest::decode(c)?;
                Op::TestSpamTest {
                    value: value(op.value),
                    percent: op.percent,
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                }
            }
            ops::TestString::OP => {
                let op = ops::TestString::decode(c)?;
                Op::TestString {
                    source: values(op.source),
                    keys: values(op.key_list),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                }
            }
            ops::TestHasFlag::OP => {
                let op = ops::TestHasFlag::decode(c)?;
                Op::TestHasFlag {
                    variables: values(op.variable_list),
                    flags: values(op.flags),
                    matcher: Matcher::new(op.match_type, op.comparator, op.is_not),
                }
            }
            ops::Jmp::OP => Op::Jmp(ops::Jmp::decode(c)?.target.0),
            ops::Jz::OP => Op::Jz(ops::Jz::decode(c)?.target.0),
            ops::Jnz::OP => Op::Jnz(ops::Jnz::decode(c)?.target.0),
            ops::Set::OP => {
                let op = ops::Set::decode(c)?;
                Op::Set {
                    name: value(op.name),
                    value: value(op.value),
                    has_modifiers: !op.modifiers.is_empty(),
                }
            }
            ops::EditFlags::OP => {
                let op = ops::EditFlags::decode(c)?;
                Op::EditFlags {
                    action: match op.action {
                        0 => FlagAction::Set,
                        1 => FlagAction::Add,
                        _ => FlagAction::Remove,
                    },
                    variable: value(op.name),
                    flags: values(op.flags),
                }
            }
            ops::AddHeader::OP => {
                let op = ops::AddHeader::decode(c)?;
                Op::AddHeader {
                    last: op.last,
                    name: value(op.field_name),
                    value: value(op.value),
                }
            }
            ops::DeleteHeader::OP => {
                let op = ops::DeleteHeader::decode(c)?;
                Op::DeleteHeader {
                    name: value(op.field_name),
                    index: op.index,
                    matcher: Matcher::new(op.match_type, op.comparator, false),
                    patterns: values(op.value_patterns),
                    mime_anychild: op.mime_anychild,
                }
            }
            ops::Reject::OP => {
                let op = ops::Reject::decode(c)?;
                Op::Reject {
                    ereject: op.ereject,
                    reason: value(op.reason),
                }
            }
            ops::TestVacation::OP => {
                let op = ops::TestVacation::decode(c)?;
                Op::TestVacation {
                    addresses: values(op.addresses),
                    period: match op.period.kind {
                        PERIOD_DAYS => Period::Days(op.period.value),
                        PERIOD_SECONDS => Period::Seconds(op.period.value),
                        _ => Period::Default,
                    },
                    handle: value(op.handle),
                    reason: value(op.reason),
                }
            }
            ops::Vacation::OP => {
                let op = ops::Vacation::decode(c)?;
                Op::Vacation {
                    subject: value(op.subject),
                    from: value(op.from),
                    mime: op.mime,
                    has_fcc: op.fcc.present,
                    reason: value(op.reason),
                }
            }
            ops::Include::OP => {
                let op = ops::Include::decode(c)?;
                Op::Include {
                    global: op.global,
                    once: op.once,
                    optional: op.optional,
                    name: value(op.value),
                }
            }
            other => {
                skip_op(other, c)?;
                Op::Other(other)
            }
        })
    }
}

impl Matcher {
    fn new(match_type: ops::Match, comparator: u8, is_not: bool) -> Self {
        Matcher {
            match_type: match_type.match_type(),
            comparator,
            is_not,
        }
    }

    pub fn comparator(&self) -> Comparator {
        Comparator::from_code(self.comparator)
    }
}

impl<'s> Value<'s> {
    fn new(sieve: &'s Sieve<'s>, rec: Rec) -> Self {
        let text = |rec: Rec| sieve.str(rec.str()).ok();
        match rec.tag {
            tag::NONE | tag::VARIABLE_NONE => Value::None,
            tag::TEXT => text(rec).map_or(Value::Other(rec.tag), Value::Text),
            tag::INT => Value::Number(rec.e as i64),
            tag::FLOAT => Value::Float(f64::from_bits(rec.e)),
            tag::REGEX => text(rec).map_or(Value::Other(rec.tag), Value::Regex),
            tag::GLOB => text(rec).map_or(Value::Other(rec.tag), Value::Glob),
            tag::HEADER => sieve
                .header_name(rec.c)
                .map_or(Value::Other(rec.tag), Value::Header),
            tag::VAR_LOCAL => Value::Local(rec.c),
            tag::VAR_MATCH => Value::Match(rec.b),
            tag::VAR_GLOBAL => text(rec).map_or(Value::Other(rec.tag), Value::Global),
            tag::VAR_ENV => text(rec).map_or(Value::Other(rec.tag), Value::Env),
            tag::ENVELOPE => Value::Envelope(Envelope::from_code(rec.b)),
            tag::LIST => Value::List(Values {
                sieve,
                range: rec.range(),
            }),
            other => Value::Other(other),
        }
    }
}

impl Debug for Values<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'s> Values<'s> {
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Value<'s>> + use<'s> {
        let sieve = self.sieve;
        sieve
            .recs(self.range)
            .into_iter()
            .flatten()
            .filter(|rec| rec.tag != tag::CONT)
            .map(move |rec| Value::new(sieve, rec))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/sieve/src/bytecode/view/tests.rs"]
mod tests;
