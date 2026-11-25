/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AUTO_SUBMITTED_HEADER, AUTO_SUBMITTED_PATTERN, DayMask, FLAGGED_FLAG, FORMAT_VERSION,
    FORWARDED_BY_HEADER, IS_SPAM_PERCENT, JUNK_FLAG, MINUTES_PER_DAY, ManagedRule, ManagedScript,
    NOT_JUNK_FLAG, RULE_ENABLED, RULE_MATCH_ANY, RuleError, SENDER_AUTHENTICATED_ENV,
    SENDERS_HEADER, SenderListKind, VOICEMAIL_CLASSES, VOICEMAIL_HEADER, VacationResponse,
    api_keyword,
    emit::{
        ANY_KEYWORD_PATTERN, AUTO_FORWARDED_HEADER, AUTO_FORWARDED_VALUE, AWAY_UNSET, AWAY_VALUE,
        CALENDAR_CONTENT_TYPE, ENCRYPTED, IMPORTANCE_HEADER, KEYWORDS_HEADER, MEETING_CANCELLATION,
        MEETING_REQUEST, MEETING_RESPONSE, MESSAGE_FLAG_HEADER, NON_DELIVERY_REPORT,
        PRIORITY_HEADER, PRIVATE_EVENT_CLASSES, READ_RECEIPT, REPLY_HANDLE_PREFIX, SIGNED,
        VACATION_END, VACATION_HTML_PART, VACATION_MASK_HTML, VACATION_MASK_TEXT,
        VACATION_MULTIPART, VACATION_SEPARATOR, VACATION_TEXT_PART,
    },
    is_custom_keyword, sensitivity_level,
};
use crate::mailbox::{JUNK_ID, TRASH_ID};
use encodify::base64::LENIENT;
use jmap_proto::types::date::UTCDate;
use registry::{
    schema::{
        enums::{
            MailRuleAddressOperator, MailRuleImportanceLevel, MailRuleMessageKind,
            MailRuleSensitivityLevel, MailRuleSentToMePlacement, MailRuleTextOperator, TimeZone,
        },
        structs::{
            MailRule, MailRuleActions, MailRuleAddressTest, MailRuleCondition, MailRuleConditions,
            MailRuleDate, MailRuleHeaderName, MailRuleHeaderTest, MailRuleImportance,
            MailRuleKeywordTest, MailRuleMessageType, MailRuleRedirect, MailRuleReject,
            MailRuleReply, MailRuleSchedule, MailRuleSensitivity, MailRuleSentToMe, MailRuleSize,
            MailRuleSpamScore, MailRuleTextTest, WorkingHoursSlot,
        },
    },
    types::{EnumImpl, datetime::UTCDateTime, list::List, localtime::LocalTime, map::Map},
};
use sieve::{
    Envelope, Sieve,
    bytecode::view::{BodyPart, FlagAction, Matcher, MimePart, Op, Value, Values, Zone},
    compiler::grammar::{
        AddressPart, Comparator, MatchType, RelationalMatch, actions::action_vacation::Period,
        tests::test_date::DatePart,
    },
};
use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter, Write},
    str::FromStr,
};
use types::id::Id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    pub pos: u32,
    pub reason: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sep {
    First,
    And,
    Or,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ActionSlot {
    ClearKeywords,
    RemoveKeywords,
    AddKeywords,
    SetImportance,
    Redirect,
    Reply,
    CopyTo,
    MoveTo,
    Discard,
    Reject,
    Stop,
}

impl ActionSlot {
    fn may_repeat(self) -> bool {
        matches!(self, ActionSlot::CopyTo | ActionSlot::MoveTo)
    }
}

struct RuleHeader {
    name: String,
    is_enabled: bool,
    position: u64,
    has_match_any: bool,
}

struct Expr<'s> {
    tests: Vec<(Sep, Op<'s>)>,
    end: u32,
}

struct Decoder<'s> {
    ops: Vec<(u32, Op<'s>)>,
    idx: usize,
    code_len: u32,
    dollar_var: u16,
    header_var: Option<u16>,
    away_var: Option<u16>,
    keywords_var: Option<u16>,
}

impl ManagedScript {
    pub fn decode(sieve: &Sieve<'_>) -> Result<ManagedScript, DecodeError> {
        Self::decode_with_op_count(sieve).map(|(script, _)| script)
    }

    pub fn verify(&self, compiled: &Sieve<'_>) -> Result<usize, RuleError> {
        match Self::decode_with_op_count(compiled) {
            Ok((decoded, instructions)) if decoded == *self => Ok(instructions),
            Ok(_) => Err(RuleError::Decode(DecodeError {
                pos: 0,
                reason: "reads back differently",
            })),
            Err(err) => Err(RuleError::Decode(err)),
        }
    }

    fn decode_with_op_count(sieve: &Sieve<'_>) -> Result<(ManagedScript, usize), DecodeError> {
        let ops = sieve
            .ops()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DecodeError {
                pos: 0,
                reason: "corrupted program",
            })?;
        let code_len = u32::try_from(sieve.code_len()).map_err(|_| DecodeError {
            pos: 0,
            reason: "program too large",
        })?;
        let mut decoder = Decoder {
            ops,
            idx: 0,
            code_len,
            dollar_var: 0,
            header_var: None,
            away_var: None,
            keywords_var: None,
        };
        decoder.run().map(|script| (script, decoder.ops.len()))
    }
}

impl<'s> Decoder<'s> {
    fn run(&mut self) -> Result<ManagedScript, DecodeError> {
        if !matches!(self.next()?, Op::Require) {
            return Err(self.error("expected require"));
        }
        match self.next()? {
            Op::Set {
                name: Value::Local(var),
                value: Value::Text("$"),
                has_modifiers: false,
            } => self.dollar_var = var,
            _ => return Err(self.error("expected dollar variable")),
        }
        self.away_var = self.declaration(AWAY_UNSET)?;
        self.keywords_var = self.declaration("")?;

        let mut script = ManagedScript::default();
        let mut has_senders = false;
        while self.idx < self.ops.len() {
            let header = self.header()?;
            let mut fields = header.splitn(5, ' ');
            if fields.next() != Some(FORMAT_VERSION) {
                return Err(self.error("unsupported version"));
            }
            match fields.next().unwrap_or_default() {
                "last" => {
                    let last_id = fields
                        .next()
                        .and_then(|id| id.parse::<u64>().ok())
                        .filter(|id| *id > 0)
                        .ok_or_else(|| self.error("invalid last id header"))?;
                    if script.last_id != 0 {
                        return Err(self.error("duplicate last id"));
                    }
                    script.last_id = last_id;
                }
                "vacation" => {
                    let mask = fields
                        .next()
                        .and_then(|mask| mask.parse::<u8>().ok())
                        .ok_or_else(|| self.error("invalid vacation header"))?;
                    if script.vacation.is_some() {
                        return Err(self.error("duplicate vacation"));
                    }
                    script.vacation = Some(self.vacation(mask)?);
                }
                SENDERS_HEADER if !has_senders && fields.next().is_none() => {
                    has_senders = true;
                    self.sender_lists(&mut script)?;
                }
                id => {
                    let (Some(id), Some(position), Some(flags), Some(name)) = (
                        id.parse::<u64>().ok(),
                        fields.next().and_then(|pos| pos.parse::<u64>().ok()),
                        fields
                            .next()
                            .and_then(|flags| flags.parse::<u8>().ok())
                            .filter(|flags| flags & !(RULE_ENABLED | RULE_MATCH_ANY) == 0),
                        fields.next(),
                    ) else {
                        return Err(self.error("invalid rule header"));
                    };
                    let header = RuleHeader {
                        name: name.to_string(),
                        is_enabled: flags & RULE_ENABLED != 0,
                        position,
                        has_match_any: flags & RULE_MATCH_ANY != 0,
                    };
                    let rule = self.rule(id, header)?;
                    script.rules.push(ManagedRule { id, rule });
                }
            }
        }

        script.last_id = script.last_id.max(script.max_rule_id());
        if !script.blocked_senders.finish_decoded() || !script.safe_senders.finish_decoded() {
            return Err(self.error("invalid sender list entries"));
        }
        let vars = script.vars();
        if vars.away != self.away_var.is_some() || vars.keywords != self.keywords_var.is_some() {
            return Err(self.error("invalid variable declarations"));
        }

        Ok(script)
    }

    fn declaration(&mut self, initial: &str) -> Result<Option<u16>, DecodeError> {
        let Some(&Op::Set {
            name: Value::Local(var),
            value,
            has_modifiers: false,
        }) = self.peek()
        else {
            return Ok(None);
        };
        if self.is_script_var(var) || self.text(value)? != initial {
            return Ok(None);
        }
        self.idx += 1;
        Ok(Some(var))
    }

    fn is_script_var(&self, var: u16) -> bool {
        var == self.dollar_var || self.away_var == Some(var) || self.keywords_var == Some(var)
    }

    fn header(&mut self) -> Result<Cow<'s, str>, DecodeError> {
        match self.next()? {
            Op::Set {
                name: Value::Local(var),
                value,
                has_modifiers: false,
            } if !self.is_script_var(var) && self.header_var.is_none_or(|header| header == var) => {
                self.header_var = Some(var);
                self.text(value)
            }
            _ => Err(self.error("expected rule header")),
        }
    }

    fn sender_lists(&mut self, script: &mut ManagedScript) -> Result<(), DecodeError> {
        let mut last_arm = None;
        loop {
            let expr = self.expr()?;
            let kind = match self.next()? {
                Op::EditFlags {
                    action: FlagAction::Add,
                    variable: Value::None,
                    flags,
                } if self.is_text(flags, NOT_JUNK_FLAG)? => SenderListKind::Safe,
                op @ Op::FileInto { .. } if self.is_junk_fileinto(&op)? => {
                    if !matches!(self.next()?, Op::Stop) {
                        return Err(self.error("expected stop"));
                    }
                    SenderListKind::Blocked
                }
                _ => return Err(self.error("unexpected sender list action")),
            };

            let address = match (kind, expr.tests.as_slice()) {
                (SenderListKind::Safe, [(Sep::First, auth), (Sep::And, address)])
                    if self.is_authenticated_test(auth)? =>
                {
                    address
                }
                (SenderListKind::Blocked, [(Sep::First, address)]) => address,
                _ => return Err(self.error("invalid sender list test")),
            };
            let Op::TestAddress {
                headers,
                keys,
                address_part,
                matcher,
                index: None,
                mime_anychild: false,
            } = *address
            else {
                return Err(self.error("invalid sender list address test"));
            };
            if matcher.is_not
                || matcher.comparator() != Comparator::AsciiCaseMap
                || !matches!(self.header_names(headers)?.as_slice(), [from] if from == "from")
            {
                return Err(self.error("invalid sender list address test"));
            }
            let is_domain = match (address_part, matcher.match_type) {
                (AddressPart::All, MatchType::Is) => false,
                (AddressPart::Domain, MatchType::Matches(_)) => true,
                _ => return Err(self.error("invalid sender list match")),
            };
            let arm = (is_domain, kind == SenderListKind::Blocked);
            if last_arm.is_some_and(|last| last >= arm) {
                return Err(self.error("invalid sender list order"));
            }
            last_arm = Some(arm);
            let list = script.senders_mut(kind);
            if is_domain {
                for domain in self.domain_keys(keys)? {
                    let mut entry = String::with_capacity(domain.len() + 1);
                    entry.push('@');
                    entry.push_str(&domain);
                    list.push_decoded(entry);
                }
            } else {
                for key in keys.iter() {
                    list.push_decoded(self.string(key)?);
                }
            }

            if let Some(Op::Jmp(_)) = self.peek() {
                self.next()?;
                if expr.end != self.pos() {
                    return Err(self.error("invalid sender list chain"));
                }
            } else if expr.end == self.pos() {
                return Ok(());
            } else {
                return Err(self.error("invalid sender list chain"));
            }
        }
    }

    fn rule(&mut self, id: u64, header: RuleHeader) -> Result<MailRule, DecodeError> {
        let Expr { tests, end } = self.expr()?;
        let (is_enabled, mut conditions) = self.rule_conditions(&tests, header.has_match_any)?;
        if is_enabled != header.is_enabled {
            return Err(self.error("rule state mismatch"));
        }

        let has_exceptions = match self.peek() {
            Some(op) => is_test(op) && !self.is_forward_guard(op) && !self.is_spam_guard(op)?,
            None => false,
        };
        if has_exceptions {
            let expr = self.expr()?;
            let else_start = expr.end;
            conditions.match_none = self.exceptions(&expr.tests)?;
            match self.next()? {
                Op::Jmp(target) if target == end && else_start == self.pos() => {}
                _ => return Err(self.error("invalid exceptions block")),
            }
        }

        Ok(MailRule {
            name: header.name,
            is_enabled,
            position: header.position,
            conditions,
            actions: self.rule_actions(id, end)?,
        })
    }

    fn rule_actions(&mut self, id: u64, end: u32) -> Result<MailRuleActions, DecodeError> {
        let mut actions = MailRuleActions::default();
        let mut last_slot: Option<ActionSlot> = None;
        while self.pos() < end {
            let op = self.next()?;
            let slot = match op {
                Op::EditFlags {
                    action: FlagAction::Add,
                    variable: Value::None,
                    flags,
                } => {
                    let flags = self.strings(flags)?;
                    if matches!(flags.as_slice(), [flag] if flag == JUNK_FLAG)
                        && self.at_junk_move()?
                    {
                        actions.move_to.push_unchecked(Id::from(JUNK_ID));
                        ActionSlot::MoveTo
                    } else {
                        self.keyword_tracking(FlagAction::Add, &flags)?;
                        actions.add_keywords = api_keywords(flags);
                        ActionSlot::AddKeywords
                    }
                }
                Op::EditFlags {
                    action: FlagAction::Remove,
                    variable: Value::None,
                    flags,
                } => {
                    if let (Some(Value::Local(var)), Some(keywords)) =
                        (single(flags), self.keywords_var)
                        && var == keywords
                    {
                        self.keywords_reset()?;
                        actions.clear_keywords = true;
                        ActionSlot::ClearKeywords
                    } else {
                        let flags = self.strings(flags)?;
                        self.keyword_tracking(FlagAction::Remove, &flags)?;
                        actions.remove_keywords = api_keywords(flags);
                        ActionSlot::RemoveKeywords
                    }
                }
                Op::DeleteHeader { .. } if self.is_delete_header(&op, IMPORTANCE_HEADER) => {
                    actions.set_importance = Some(self.set_importance()?);
                    ActionSlot::SetImportance
                }
                Op::TestHeader { .. } if self.is_forward_guard(&op) => {
                    actions.redirect = Some(self.forward_guard(op)?);
                    ActionSlot::Redirect
                }
                Op::Redirect {
                    copy,
                    list: false,
                    address,
                } => {
                    actions.redirect = Some(self.redirect(address, copy)?);
                    ActionSlot::Redirect
                }
                Op::TestSpamTest { .. } if self.is_spam_guard(&op)? => {
                    actions.reply = Some(self.reply(id)?);
                    ActionSlot::Reply
                }
                Op::FileInto {
                    copy,
                    create: false,
                    folder: Value::Text("INBOX"),
                    flags,
                    mailbox_id,
                    special_use: Value::None,
                } if flags.is_empty() && !matches!(mailbox_id, Value::None) => {
                    let mailbox_id = self.mailbox_id(mailbox_id)?;
                    if copy {
                        actions.copy_to.push_unchecked(mailbox_id);
                        ActionSlot::CopyTo
                    } else if matches!(mailbox_id.document_id(), TRASH_ID | JUNK_ID) {
                        return Err(self.error("invalid special mailbox move"));
                    } else {
                        actions.move_to.push_unchecked(mailbox_id);
                        ActionSlot::MoveTo
                    }
                }
                Op::FileInto { .. } if self.is_trash_fileinto(&op) => {
                    actions.move_to.push_unchecked(Id::from(TRASH_ID));
                    ActionSlot::MoveTo
                }
                Op::Discard => {
                    actions.discard = true;
                    ActionSlot::Discard
                }
                Op::Reject { reason, .. } => {
                    actions.reject = Some(MailRuleReject {
                        reason: self.string(reason)?,
                    });
                    ActionSlot::Reject
                }
                Op::Stop => {
                    actions.stop_processing = true;
                    ActionSlot::Stop
                }
                _ => return Err(self.error("unexpected rule action")),
            };
            if last_slot.is_some_and(|last| slot < last || (slot == last && !slot.may_repeat())) {
                return Err(self.error("invalid action order"));
            }
            last_slot = Some(slot);
        }
        if self.pos() != end || last_slot.is_none() {
            return Err(self.error("invalid rule actions"));
        }
        Ok(actions)
    }

    fn mailbox_id(&self, value: Value<'s>) -> Result<Id, DecodeError> {
        Id::from_str(&self.text(value)?).map_err(|_| self.error("invalid mailbox id"))
    }

    fn reply(&mut self, id: u64) -> Result<MailRuleReply, DecodeError> {
        let Op::Jz(guard_end) = self.next()? else {
            return Err(self.error("expected reply guard"));
        };
        let Op::TestVacation {
            addresses,
            period: period @ (Period::Days(_) | Period::Seconds(0)),
            handle,
            ..
        } = self.next()?
        else {
            return Err(self.error("expected reply"));
        };
        if !addresses.is_empty() {
            return Err(self.error("invalid reply addresses"));
        }
        let days = match period {
            Period::Days(days) => days,
            _ => 0,
        };
        let handle = self.text(handle)?;
        if handle
            .strip_prefix(REPLY_HANDLE_PREFIX)
            .is_none_or(|rule_id| rule_id.parse::<u64>().ok() != Some(id))
        {
            return Err(self.error("invalid reply handle"));
        }
        let (subject, text_body, html_body) = self.vacation_action()?;
        if guard_end != self.pos() {
            return Err(self.error("invalid reply guard"));
        }
        Ok(MailRuleReply {
            subject,
            text_body,
            html_body,
            days,
        })
    }

    fn redirect(
        &mut self,
        first: Value<'s>,
        keep_copy: bool,
    ) -> Result<MailRuleRedirect, DecodeError> {
        let mut addresses = vec![self.string(first)?];
        while let Some(&Op::Redirect {
            copy,
            list: false,
            address,
        }) = self.peek()
        {
            if copy != keep_copy {
                return Err(self.error("mixed redirects"));
            }
            self.idx += 1;
            addresses.push(self.string(address)?);
        }
        Ok(MailRuleRedirect {
            addresses: Map::new(addresses),
            keep_copy,
        })
    }

    fn forward_guard(&mut self, test: Op<'s>) -> Result<MailRuleRedirect, DecodeError> {
        let Op::TestHeader { keys, .. } = test else {
            return Err(self.error("invalid forward guard"));
        };
        let forwarder = single(keys)
            .map(|key| self.text(key))
            .transpose()?
            .filter(|forwarder| !forwarder.is_empty())
            .ok_or_else(|| self.error("invalid forward guard"))?;
        let Op::Jz(end) = self.next()? else {
            return Err(self.error("invalid forward guard"));
        };
        match self.next()? {
            Op::AddHeader {
                last: false,
                name: Value::Header(name),
                value,
            } if name.as_str().eq_ignore_ascii_case(FORWARDED_BY_HEADER)
                && self.text(value)? == forwarder => {}
            _ => return Err(self.error("invalid forward guard")),
        }
        let Op::Redirect {
            copy,
            list: false,
            address,
        } = self.next()?
        else {
            return Err(self.error("invalid forward guard"));
        };
        let redirect = self.redirect(address, copy)?;
        match self.next()? {
            Op::DeleteHeader {
                name: Value::Header(name),
                index: None,
                matcher:
                    matcher @ Matcher {
                        match_type: MatchType::Is,
                        is_not: false,
                        ..
                    },
                patterns,
                mime_anychild: false,
            } if name.as_str().eq_ignore_ascii_case(FORWARDED_BY_HEADER)
                && matcher.comparator() == Comparator::AsciiCaseMap
                && self.is_text(patterns, &forwarder)? => {}
            _ => return Err(self.error("invalid forward guard")),
        }
        if self.pos() == end {
            Ok(redirect)
        } else {
            Err(self.error("invalid forward guard"))
        }
    }

    fn is_forward_guard(&self, op: &Op<'s>) -> bool {
        matches!(
            op,
            Op::TestHeader {
                headers,
                matcher: matcher @ Matcher {
                    match_type: MatchType::Contains,
                    is_not: true,
                    ..
                },
                index: None,
                mime: MimePart::None,
                mime_anychild: false,
                ..
            } if matcher.comparator() == Comparator::AsciiCaseMap
                && self.header_names(*headers).is_ok_and(|names| {
                    matches!(names.as_slice(), [name] if name.eq_ignore_ascii_case(FORWARDED_BY_HEADER))
                })
        )
    }

    fn vacation(&mut self, mask: u8) -> Result<VacationResponse, DecodeError> {
        let mut vacation = VacationResponse {
            is_enabled: true,
            ..Default::default()
        };
        let mut stage = 0;
        let mut is_away_set = false;
        loop {
            let mut op = self.next()?;
            if let Op::Set {
                name: Value::Local(var),
                value,
                has_modifiers: false,
            } = op
                && Some(var) == self.away_var
                && !is_away_set
                && stage < 4
                && self.text(value)? == AWAY_VALUE
            {
                is_away_set = true;
                op = self.next()?;
                if !matches!(op, Op::TestSpamTest { .. }) {
                    return Err(self.error("invalid away flag"));
                }
            }
            let (next_stage, date) = match op {
                Op::TestFalse if stage == 0 => {
                    vacation.is_enabled = false;
                    (1, None)
                }
                Op::TestCurrentDate {
                    zone: Zone::Local,
                    date_part: DatePart::Iso8601,
                    keys,
                    matcher:
                        Matcher {
                            match_type: MatchType::Value(relation),
                            is_not: false,
                            ..
                        },
                } if stage < 3 => {
                    let date = single(keys)
                        .map(|key| self.text(key))
                        .transpose()?
                        .and_then(|key| UTCDate::from_str(&key).ok())
                        .and_then(|date| u64::try_from(date.timestamp()).ok())
                        .ok_or_else(|| self.error("invalid vacation date"))?;
                    match relation {
                        RelationalMatch::Ge if stage < 2 => (2, Some((true, date))),
                        RelationalMatch::Le => (3, Some((false, date))),
                        _ => return Err(self.error("invalid vacation date")),
                    }
                }
                Op::TestSpamTest { .. }
                    if stage < 4
                        && is_away_set == self.away_var.is_some()
                        && self.is_spam_guard(&op)? =>
                {
                    (4, None)
                }
                Op::TestVacation {
                    addresses,
                    period: Period::Default,
                    handle: Value::None,
                    ..
                } if stage == 4 && addresses.is_empty() => break,
                _ => return Err(self.error("unexpected vacation test")),
            };
            if !matches!(self.next()?, Op::Jz(_)) {
                return Err(self.error("expected vacation block"));
            }
            match date {
                Some((true, date)) => vacation.from_date = Some(date),
                Some((false, date)) => vacation.to_date = Some(date),
                None => {}
            }
            stage = next_stage;
        }
        let (subject, text, html) = self.vacation_action()?;
        vacation.subject = subject;
        if mask & VACATION_MASK_TEXT != 0 {
            vacation.text_body = Some(text);
        }
        if mask & VACATION_MASK_HTML != 0 {
            vacation.html_body = Some(html.ok_or_else(|| self.error("missing vacation html"))?);
        }
        Ok(vacation)
    }

    fn vacation_action(&mut self) -> Result<(Option<String>, String, Option<String>), DecodeError> {
        let Op::Jz(target) = self.next()? else {
            return Err(self.error("expected vacation jump"));
        };
        let Op::Vacation {
            subject,
            from: Value::None,
            mime: true,
            has_fcc: false,
            reason,
        } = self.next()?
        else {
            return Err(self.error("expected vacation action"));
        };
        if target != self.pos() {
            return Err(self.error("invalid vacation jump"));
        }
        let subject = match subject {
            Value::None => None,
            subject => Some(self.string(subject)?),
        };
        let (text, html) = parse_reason(&self.string(reason)?)
            .ok_or_else(|| self.error("invalid vacation reason"))?;
        Ok((subject, text, html))
    }

    fn set_importance(&mut self) -> Result<MailRuleImportanceLevel, DecodeError> {
        let (
            Some((_, priority @ Op::DeleteHeader { .. })),
            Some((
                _,
                Op::AddHeader {
                    last: false,
                    name: Value::Header(name),
                    value,
                },
            )),
        ) = (self.ops.get(self.idx), self.ops.get(self.idx + 1))
        else {
            return Err(self.error("invalid importance action"));
        };
        if !self.is_delete_header(priority, PRIORITY_HEADER)
            || !name.as_str().eq_ignore_ascii_case(IMPORTANCE_HEADER)
        {
            return Err(self.error("invalid importance action"));
        }
        let level = MailRuleImportanceLevel::parse(&self.text(*value)?)
            .ok_or_else(|| self.error("invalid importance value"))?;
        self.idx += 2;
        Ok(level)
    }

    fn is_delete_header(&self, op: &Op<'s>, expected: &str) -> bool {
        matches!(
            op,
            Op::DeleteHeader {
                name: Value::Header(name),
                index: None,
                patterns,
                mime_anychild: false,
                ..
            } if patterns.is_empty() && name.as_str().eq_ignore_ascii_case(expected)
        )
    }

    fn is_spam_guard(&self, op: &Op<'s>) -> Result<bool, DecodeError> {
        Ok(match op {
            Op::TestSpamTest {
                value,
                percent: true,
                matcher:
                    matcher @ Matcher {
                        match_type: MatchType::Value(RelationalMatch::Ge),
                        is_not: true,
                        ..
                    },
            } => {
                matcher.comparator() == Comparator::AsciiNumeric
                    && self.number(*value)? == Some(IS_SPAM_PERCENT)
            }
            _ => false,
        })
    }

    fn number(&self, value: Value<'s>) -> Result<Option<u64>, DecodeError> {
        Ok(match value {
            Value::Number(number) => u64::try_from(number).ok(),
            value => self.text(value)?.parse::<u64>().ok(),
        })
    }

    fn schedule(
        &self,
        first: &Op<'s>,
        tests: &mut &[(Sep, Op<'s>)],
    ) -> Result<(List<WorkingHoursSlot>, &'static str), DecodeError> {
        let Op::TestCurrentDate {
            zone: Zone::Named(zone),
            ..
        } = *first
        else {
            return Err(self.error("invalid zone"));
        };
        let mut slots = List::default();
        let mut days = self.schedule_days(first, zone)?;
        loop {
            let start = self.schedule_time(tests, RelationalMatch::Ge, zone)?;
            let end = self.schedule_time(tests, RelationalMatch::Lt, zone)?;
            let slot = match (start, end) {
                (Some(start), Some(end)) if start < end => WorkingHoursSlot {
                    days: days.days(),
                    start,
                    end,
                },
                (Some(start), None) => {
                    let [(Sep::Or, next), rest @ ..] = *tests else {
                        return Err(self.error("invalid schedule"));
                    };
                    *tests = rest;
                    if self.schedule_days(next, zone)? != days.next_day()
                        || self
                            .schedule_time(tests, RelationalMatch::Ge, zone)?
                            .is_some()
                    {
                        return Err(self.error("invalid schedule"));
                    }
                    let end = self
                        .schedule_time(tests, RelationalMatch::Lt, zone)?
                        .filter(|end| *end < start && end.minutes() > 0)
                        .ok_or_else(|| self.error("invalid schedule"))?;
                    WorkingHoursSlot {
                        days: days.days(),
                        start,
                        end,
                    }
                }
                _ => return Err(self.error("invalid schedule")),
            };
            slots.push_unchecked(slot);
            match *tests {
                [(Sep::Or, next), rest @ ..] if is_weekday_test(next) => {
                    *tests = rest;
                    days = self.schedule_days(next, zone)?;
                }
                _ => return Ok((slots, zone)),
            }
        }
    }

    fn schedule_days(&self, op: &Op<'s>, expected_zone: &str) -> Result<DayMask, DecodeError> {
        let Op::TestCurrentDate {
            zone: Zone::Named(zone),
            date_part: DatePart::Weekday,
            keys,
            matcher:
                matcher @ Matcher {
                    match_type: MatchType::Is,
                    is_not: false,
                    ..
                },
        } = *op
        else {
            return Err(self.error("invalid schedule"));
        };
        if zone != expected_zone || matcher.comparator() != Comparator::AsciiCaseMap {
            return Err(self.error("invalid schedule"));
        }
        DayMask::from_sieve_keys(
            keys.iter()
                .map(|key| self.text(key).ok().and_then(|key| key.parse::<u16>().ok())),
        )
        .ok_or_else(|| self.error("invalid schedule"))
    }

    fn schedule_time(
        &self,
        tests: &mut &[(Sep, Op<'s>)],
        relation: RelationalMatch,
        expected_zone: &str,
    ) -> Result<Option<LocalTime>, DecodeError> {
        let [
            (
                Sep::And,
                Op::TestCurrentDate {
                    zone,
                    date_part: DatePart::Time,
                    keys,
                    matcher:
                        matcher @ Matcher {
                            match_type: MatchType::Value(found),
                            is_not: false,
                            ..
                        },
                },
            ),
            rest @ ..,
        ] = *tests
        else {
            return Ok(None);
        };
        if *found != relation {
            return Ok(None);
        }
        if !matches!(zone, Zone::Named(zone) if *zone == expected_zone)
            || matcher.comparator() != Comparator::AsciiCaseMap
        {
            return Err(self.error("invalid schedule"));
        }
        *tests = rest;
        single(*keys)
            .map(|key| self.text(key))
            .transpose()?
            .and_then(|key| {
                key.strip_suffix(":00")
                    .and_then(|time| LocalTime::from_str(time).ok())
            })
            .filter(|time| relation == RelationalMatch::Lt || time.minutes() < MINUTES_PER_DAY)
            .map(Some)
            .ok_or_else(|| self.error("invalid schedule"))
    }

    fn rule_conditions(
        &self,
        mut tests: &[(Sep, Op<'s>)],
        has_match_any: bool,
    ) -> Result<(bool, MailRuleConditions), DecodeError> {
        let mut is_enabled = true;
        match tests {
            [(_, Op::TestTrue)] if !has_match_any => {
                return Ok((true, MailRuleConditions::default()));
            }
            [(_, Op::TestFalse)] if !has_match_any => {
                return Ok((false, MailRuleConditions::default()));
            }
            [(_, Op::TestFalse), rest @ ..] if matches!(rest.first(), Some((Sep::And, _))) => {
                is_enabled = false;
                tests = rest;
            }
            _ => {}
        }

        let mut match_all = Vec::new();
        let mut clause_start = 0;
        while let [(sep, op), rest @ ..] = tests {
            tests = rest;
            if *sep != Sep::Or {
                if match_all.len() > clause_start + 1 {
                    return Err(self.error("mixed condition operators"));
                }
                clause_start = match_all.len();
            }
            match_all.push(self.condition_at(op, &mut tests)?);
        }
        if match_all.is_empty() {
            return Err(self.error("missing conditions"));
        }
        let match_any = if has_match_any {
            match_all.split_off(clause_start)
        } else if match_all.len() > clause_start + 1 {
            return Err(self.error("mixed condition operators"));
        } else {
            Vec::new()
        };
        Ok((
            is_enabled,
            MailRuleConditions {
                match_all: List::from(match_all),
                match_any: List::from(match_any),
                match_none: List::default(),
            },
        ))
    }

    fn exceptions(
        &self,
        mut tests: &[(Sep, Op<'s>)],
    ) -> Result<List<MailRuleCondition>, DecodeError> {
        let mut exceptions = Vec::new();
        while let [(sep, op), rest @ ..] = tests {
            tests = rest;
            if *sep == Sep::And {
                return Err(self.error("invalid exceptions"));
            }
            exceptions.push(self.condition_at(op, &mut tests)?);
        }
        Ok(List::from(exceptions))
    }

    fn condition_at(
        &self,
        op: &Op<'s>,
        tests: &mut &[(Sep, Op<'s>)],
    ) -> Result<MailRuleCondition, DecodeError> {
        match op {
            Op::TestTrue => self.all_group(tests),
            Op::TestFalse => self.any_group(tests),
            op => self.condition(op),
        }
    }

    fn all_group(&self, tests: &mut &[(Sep, Op<'s>)]) -> Result<MailRuleCondition, DecodeError> {
        let [(Sep::And, test), rest @ ..] = *tests else {
            return Err(self.error("invalid nested test"));
        };
        *tests = rest;
        let schedule = match test {
            Op::TestTrue => {
                let [(Sep::And, first), rest @ ..] = *tests else {
                    return Err(self.error("invalid schedule"));
                };
                *tests = rest;
                let (slots, zone) = self.schedule(first, tests)?;
                let zone = TimeZone::parse(zone).ok_or_else(|| self.error("invalid zone"))?;
                Some((slots, Some(zone)))
            }
            test if is_weekday_test(test) => Some((self.schedule(test, tests)?.0, None)),
            _ => None,
        };
        if let Some((slots, time_zone)) = schedule {
            return Ok(MailRuleCondition::Schedule(MailRuleSchedule {
                slots,
                time_zone,
            }));
        }
        let placement = self.sent_to_me(test)?;
        let placement = if let [(Sep::And, count), rest @ ..] = *tests
            && placement == MailRuleSentToMePlacement::To
            && is_only_to_count(self, count)?
        {
            *tests = rest;
            MailRuleSentToMePlacement::OnlyTo
        } else {
            placement
        };
        Ok(MailRuleCondition::SentToMe(MailRuleSentToMe { placement }))
    }

    fn any_group(&self, tests: &mut &[(Sep, Op<'s>)]) -> Result<MailRuleCondition, DecodeError> {
        let [(Sep::Or, first), (Sep::Or, second), rest @ ..] = *tests else {
            return Err(self.error("invalid nested test"));
        };
        *tests = rest;
        Ok(match (*first, *second) {
            (
                Op::TestHasFlag {
                    variables,
                    flags,
                    matcher,
                },
                Op::TestExists {
                    headers,
                    mime_anychild: false,
                    is_not: false,
                },
            ) if variables.is_empty()
                && is_plain(matcher)
                && matcher.match_type == MatchType::Is
                && self.is_text(flags, FLAGGED_FLAG)?
                && is_header(headers, MESSAGE_FLAG_HEADER) =>
            {
                MailRuleCondition::Flagged
            }
            (
                Op::TestHasFlag {
                    variables,
                    flags,
                    matcher,
                },
                Op::TestHeader {
                    headers,
                    keys,
                    matcher: header_matcher,
                    index: None,
                    mime: MimePart::None,
                    mime_anychild: false,
                },
            ) if variables.is_empty()
                && is_plain(matcher)
                && matcher.match_type == MatchType::Is
                && is_plain(header_matcher)
                && header_matcher.match_type == MatchType::Contains
                && is_header(headers, KEYWORDS_HEADER) =>
            {
                let keywords = self.strings(flags)?;
                if !self.is_texts(keys, keywords.iter().map(String::as_str))? {
                    return Err(self.error("invalid keyword test"));
                }
                MailRuleCondition::Keyword(MailRuleKeywordTest {
                    keywords: api_keywords(keywords),
                })
            }
            (
                Op::TestExists {
                    headers,
                    mime_anychild: false,
                    is_not: false,
                },
                Op::TestHasFlag {
                    variables,
                    flags,
                    matcher,
                },
            ) if is_plain(matcher)
                && matches!(matcher.match_type, MatchType::Matches(_))
                && matches!(single(variables), Some(Value::Local(var)) if Some(var) == self.keywords_var)
                && is_header(headers, KEYWORDS_HEADER)
                && self.is_text(flags, ANY_KEYWORD_PATTERN)? =>
            {
                MailRuleCondition::AnyKeyword
            }
            (
                Op::TestHeader {
                    headers,
                    keys,
                    matcher,
                    index: None,
                    mime: MimePart::None,
                    mime_anychild: false,
                },
                Op::TestExists {
                    headers: forwarded,
                    mime_anychild: false,
                    is_not: false,
                },
            ) if is_plain(matcher)
                && matcher.match_type == MatchType::Is
                && is_header(headers, AUTO_FORWARDED_HEADER)
                && self.is_text(keys, AUTO_FORWARDED_VALUE)?
                && is_header(forwarded, FORWARDED_BY_HEADER) =>
            {
                MailRuleCondition::MessageType(MailRuleMessageType {
                    kind: MailRuleMessageKind::AutomaticForward,
                })
            }
            _ => return Err(self.error("invalid nested test")),
        })
    }

    fn is_away_guard(&self, op: &Op<'s>) -> Result<bool, DecodeError> {
        Ok(match *op {
            Op::TestString {
                source,
                keys,
                matcher,
            } if is_plain(matcher) && matcher.match_type == MatchType::Is => {
                matches!(single(source), Some(Value::Local(var)) if Some(var) == self.away_var)
                    && self.is_text(keys, AWAY_VALUE)?
            }
            _ => false,
        })
    }

    fn keyword_tracking(
        &mut self,
        action: FlagAction,
        flags: &[String],
    ) -> Result<(), DecodeError> {
        let Some(keywords) = self.keywords_var else {
            return Ok(());
        };
        let mut custom = flags
            .iter()
            .map(String::as_str)
            .filter(|flag| is_custom_keyword(flag))
            .peekable();
        if custom.peek().is_none() {
            return Ok(());
        }
        match self.next()? {
            Op::EditFlags {
                action: found,
                variable: Value::Local(var),
                flags: tracked,
            } if found == action && var == keywords && self.is_texts(tracked, custom)? => Ok(()),
            _ => Err(self.error("invalid keyword tracking")),
        }
    }

    fn keywords_reset(&mut self) -> Result<(), DecodeError> {
        match self.next()? {
            Op::Set {
                name: Value::Local(var),
                value,
                has_modifiers: false,
            } if Some(var) == self.keywords_var && self.text(value)?.is_empty() => Ok(()),
            _ => Err(self.error("invalid keyword reset")),
        }
    }

    fn sent_to_me(&self, op: &Op<'s>) -> Result<MailRuleSentToMePlacement, DecodeError> {
        let Op::TestAddress {
            headers,
            address_part: AddressPart::All,
            matcher:
                matcher @ Matcher {
                    match_type: MatchType::Is,
                    ..
                },
            index: None,
            mime_anychild: false,
            ..
        } = op
        else {
            return Err(self.error("invalid sent to me test"));
        };
        if matcher.comparator() != Comparator::AsciiCaseMap {
            return Err(self.error("invalid sent to me test"));
        }
        let names = self.header_names(*headers)?;
        Ok(
            match (
                names
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice(),
                matcher.is_not,
            ) {
                (["to"], false) => MailRuleSentToMePlacement::To,
                (["cc"], false) => MailRuleSentToMePlacement::Cc,
                (["to", "cc"], false) => MailRuleSentToMePlacement::ToOrCc,
                (["to"], true) => MailRuleSentToMePlacement::NotTo,
                _ => return Err(self.error("invalid sent to me test")),
            },
        )
    }

    fn condition(&self, op: &Op<'s>) -> Result<MailRuleCondition, DecodeError> {
        Ok(match *op {
            Op::TestAddress {
                headers,
                keys,
                address_part,
                matcher,
                index: None,
                mime_anychild: false,
            } if !matcher.is_not && matcher.comparator() == Comparator::AsciiCaseMap => {
                let operator = match (address_part, matcher.match_type) {
                    (AddressPart::All, MatchType::Is) => MailRuleAddressOperator::Is,
                    (AddressPart::All, MatchType::Contains) => MailRuleAddressOperator::Contains,
                    (AddressPart::All, MatchType::Matches(_)) => MailRuleAddressOperator::Matches,
                    (AddressPart::Domain, MatchType::Matches(_)) => MailRuleAddressOperator::Domain,
                    _ => return Err(self.error("invalid address test")),
                };
                let values = if operator == MailRuleAddressOperator::Domain {
                    Map::new(self.domain_keys(keys)?)
                } else {
                    Map::new(self.strings(keys)?)
                };
                let test = MailRuleAddressTest { operator, values };
                let names = self.header_names(headers)?;
                match names
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice()
                {
                    ["from"] => MailRuleCondition::From(test),
                    ["to"] => MailRuleCondition::To(test),
                    ["cc"] => MailRuleCondition::Cc(test),
                    ["to", "cc"] => MailRuleCondition::ToOrCc(test),
                    _ => return Err(self.error("invalid address headers")),
                }
            }
            Op::TestHeader {
                headers,
                keys,
                matcher,
                index: None,
                mime,
                mime_anychild,
            } if matcher.comparator() == Comparator::AsciiCaseMap => {
                let names = self.header_names(headers)?;
                let names = names.iter().map(String::as_str).collect::<Vec<_>>();
                let values = self.strings(keys)?;
                let is_exact = matcher.match_type == MatchType::Is;
                match (names.as_slice(), mime, mime_anychild, matcher.is_not) {
                    (["content-type"], MimePart::Param(param), true, false)
                        if is_exact && self.is_text(param, "method")? =>
                    {
                        let kind = if values == MEETING_REQUEST {
                            MailRuleMessageKind::MeetingRequest
                        } else if values == MEETING_RESPONSE {
                            MailRuleMessageKind::MeetingResponse
                        } else if values == MEETING_CANCELLATION {
                            MailRuleMessageKind::MeetingCancellation
                        } else {
                            return Err(self.error("invalid meeting test"));
                        };
                        MailRuleCondition::MessageType(MailRuleMessageType { kind })
                    }
                    (["content-type"], MimePart::Param(param), false, false)
                        if is_exact && self.is_text(param, "report-type")? =>
                    {
                        let kind = if values == NON_DELIVERY_REPORT {
                            MailRuleMessageKind::NonDeliveryReport
                        } else if values == READ_RECEIPT {
                            MailRuleMessageKind::ReadReceipt
                        } else {
                            return Err(self.error("invalid report test"));
                        };
                        MailRuleCondition::MessageType(MailRuleMessageType { kind })
                    }
                    (["content-type"], MimePart::ContentType, false, false) if is_exact => {
                        let kind = if values == SIGNED {
                            MailRuleMessageKind::Signed
                        } else if values == ENCRYPTED {
                            MailRuleMessageKind::Encrypted
                        } else {
                            return Err(self.error("invalid content type test"));
                        };
                        MailRuleCondition::MessageType(MailRuleMessageType { kind })
                    }
                    (["content-type"], MimePart::ContentType, true, false) => {
                        MailRuleCondition::AttachmentType(MailRuleTextTest {
                            operator: text_operator(matcher.match_type)
                                .ok_or_else(|| self.error("invalid attachment type match"))?,
                            values: Map::new(values),
                        })
                    }
                    (["content-disposition"], MimePart::Param(param), true, false)
                        if self.is_text(param, "filename")? =>
                    {
                        MailRuleCondition::AttachmentName(MailRuleTextTest {
                            operator: text_operator(matcher.match_type)
                                .ok_or_else(|| self.error("invalid attachment name match"))?,
                            values: Map::new(values),
                        })
                    }
                    (["list-id", "list-unsubscribe"], MimePart::None, false, false)
                        if matches!(matcher.match_type, MatchType::Matches(_))
                            && values == ["*"] =>
                    {
                        MailRuleCondition::MailingList
                    }
                    (["content-disposition"], MimePart::None, true, false)
                        if matcher.match_type == MatchType::Contains
                            && values == ["attachment"] =>
                    {
                        MailRuleCondition::HasAttachment
                    }
                    (["importance", "x-priority"], MimePart::None, false, is_not)
                        if matches!(matcher.match_type, MatchType::Matches(_)) =>
                    {
                        let level = match (values.first().map(String::as_str), is_not) {
                            (Some("high"), false) if values.len() == 3 => {
                                MailRuleImportanceLevel::High
                            }
                            (Some("low"), false) if values.len() == 3 => {
                                MailRuleImportanceLevel::Low
                            }
                            (Some("high"), true) if values.len() == 6 => {
                                MailRuleImportanceLevel::Normal
                            }
                            _ => return Err(self.error("invalid importance test")),
                        };
                        MailRuleCondition::Importance(MailRuleImportance { level })
                    }
                    ([name], MimePart::None, false, false) => {
                        let operator = text_operator(matcher.match_type)
                            .ok_or_else(|| self.error("invalid header match"))?;
                        if *name == "sensitivity"
                            && operator == MailRuleTextOperator::Is
                            && let [value] = values.as_slice()
                            && let Some(level) = sensitivity_level(value)
                        {
                            MailRuleCondition::Sensitivity(MailRuleSensitivity { level })
                        } else if *name == VOICEMAIL_HEADER
                            && operator == MailRuleTextOperator::Is
                            && values == VOICEMAIL_CLASSES
                        {
                            MailRuleCondition::MessageType(MailRuleMessageType {
                                kind: MailRuleMessageKind::Voicemail,
                            })
                        } else if *name == AUTO_SUBMITTED_HEADER
                            && operator == MailRuleTextOperator::Matches
                            && values == [AUTO_SUBMITTED_PATTERN]
                        {
                            MailRuleCondition::MessageType(MailRuleMessageType {
                                kind: MailRuleMessageKind::AutomaticReply,
                            })
                        } else if *name == "subject" {
                            MailRuleCondition::Subject(MailRuleTextTest {
                                operator,
                                values: Map::new(values),
                            })
                        } else {
                            MailRuleCondition::Header(MailRuleHeaderTest {
                                header: name.to_string(),
                                operator,
                                values: Map::new(values),
                            })
                        }
                    }
                    _ => return Err(self.error("invalid header test")),
                }
            }
            Op::TestExists {
                headers,
                mime_anychild: false,
                is_not: true,
            } if matches!(self.header_names(headers)?.as_slice(), [name] if name == "sensitivity") => {
                MailRuleCondition::Sensitivity(MailRuleSensitivity {
                    level: MailRuleSensitivityLevel::Normal,
                })
            }
            Op::TestExists {
                headers,
                mime_anychild: false,
                is_not: false,
            } => {
                let Ok([header]) = <[String; 1]>::try_from(self.header_names(headers)?) else {
                    return Err(self.error("invalid exists test"));
                };
                MailRuleCondition::HeaderExists(MailRuleHeaderName { header })
            }
            Op::TestBody {
                keys,
                part: BodyPart::Content(types),
                matcher:
                    matcher @ Matcher {
                        match_type: MatchType::Contains,
                        is_not: false,
                        ..
                    },
                include_subject: false,
            } if matcher.comparator() == Comparator::AsciiCaseMap
                && self.is_text(types, CALENDAR_CONTENT_TYPE)?
                && self.strings(keys)? == PRIVATE_EVENT_CLASSES =>
            {
                MailRuleCondition::PrivateEvent
            }
            Op::TestBody {
                keys,
                part: BodyPart::Text,
                matcher,
                include_subject,
            } if !matcher.is_not && matcher.comparator() == Comparator::AsciiCaseMap => {
                let test = MailRuleTextTest {
                    operator: text_operator(matcher.match_type)
                        .ok_or_else(|| self.error("invalid body match"))?,
                    values: Map::new(self.strings(keys)?),
                };
                if include_subject {
                    MailRuleCondition::SubjectOrBody(test)
                } else {
                    MailRuleCondition::Body(test)
                }
            }
            Op::TestEnvelope {
                envelopes,
                keys,
                address_part,
                matcher,
            } if !matcher.is_not
                && matcher.comparator() == Comparator::AsciiCaseMap
                && matches!(single(envelopes), Some(Value::Envelope(Envelope::To))) =>
            {
                let operator = match (address_part, matcher.match_type) {
                    (AddressPart::Detail, match_type) => {
                        return Ok(MailRuleCondition::RecipientDetail(MailRuleTextTest {
                            operator: text_operator(match_type)
                                .ok_or_else(|| self.error("invalid recipient detail match"))?,
                            values: Map::new(self.strings(keys)?),
                        }));
                    }
                    (AddressPart::All, MatchType::Is) => MailRuleAddressOperator::Is,
                    (AddressPart::All, MatchType::Contains) => MailRuleAddressOperator::Contains,
                    (AddressPart::All, MatchType::Matches(_)) => MailRuleAddressOperator::Matches,
                    (AddressPart::Domain, MatchType::Matches(_)) => MailRuleAddressOperator::Domain,
                    _ => return Err(self.error("invalid envelope test")),
                };
                let values = if operator == MailRuleAddressOperator::Domain {
                    Map::new(self.domain_keys(keys)?)
                } else {
                    Map::new(self.strings(keys)?)
                };
                MailRuleCondition::RecipientAddress(MailRuleAddressTest { operator, values })
            }
            Op::TestCurrentDate {
                zone: Zone::Local,
                date_part: DatePart::Iso8601,
                keys,
                matcher:
                    matcher @ Matcher {
                        match_type:
                            MatchType::Value(relation @ (RelationalMatch::Ge | RelationalMatch::Le)),
                        is_not: false,
                        ..
                    },
            } if matcher.comparator() == Comparator::AsciiCaseMap => {
                let date = single(keys)
                    .map(|key| self.text(key))
                    .transpose()?
                    .and_then(|key| UTCDateTime::from_str(&key).ok())
                    .ok_or_else(|| self.error("invalid date"))?;
                let date = MailRuleDate { date };
                if relation == RelationalMatch::Ge {
                    MailRuleCondition::ReceivedAfter(date)
                } else {
                    MailRuleCondition::ReceivedBefore(date)
                }
            }
            Op::TestSize {
                over,
                limit,
                is_not: false,
            } if limit > 0 && limit % 1024 == 0 => {
                let size = MailRuleSize {
                    kilobytes: limit / 1024,
                };
                if over {
                    MailRuleCondition::SizeOver(size)
                } else {
                    MailRuleCondition::SizeUnder(size)
                }
            }
            Op::TestSpamTest {
                value,
                percent: true,
                matcher:
                    matcher @ Matcher {
                        match_type: MatchType::Value(RelationalMatch::Ge),
                        is_not: false,
                        ..
                    },
            } if matcher.comparator() == Comparator::AsciiNumeric => match self.number(value)? {
                Some(percent @ 1..=100) => {
                    MailRuleCondition::SpamScore(MailRuleSpamScore { percent })
                }
                _ => return Err(self.error("invalid spam score")),
            },
            Op::TestString { .. } if self.is_away_guard(op)? => MailRuleCondition::IsAway,
            _ => return Err(self.error("unexpected condition")),
        })
    }

    fn expr(&mut self) -> Result<Expr<'s>, DecodeError> {
        let mut tests = Vec::new();
        let mut sep = Sep::First;
        loop {
            let op = self.next()?;
            if !is_test(&op) {
                return Err(self.error("expected test"));
            }
            tests.push((sep, op));
            match self.next()? {
                Op::Jz(target) if self.is_jump_at(target) => sep = Sep::And,
                Op::Jnz(target) if self.is_jump_at(target) => sep = Sep::Or,
                Op::Jz(target) => return Ok(Expr { tests, end: target }),
                _ => return Err(self.error("expected jump")),
            }
        }
    }

    fn is_authenticated_test(&self, op: &Op<'s>) -> Result<bool, DecodeError> {
        Ok(match op {
            Op::TestEnvironment {
                source,
                keys,
                matcher:
                    Matcher {
                        match_type: MatchType::Is,
                        is_not: false,
                        ..
                    },
            } => {
                let mut source = source.iter();
                matches!(
                    (source.next(), source.next()),
                    (Some(Value::Env(name)), None) if name == SENDER_AUTHENTICATED_ENV
                ) && self.is_text(*keys, "yes")?
            }
            _ => false,
        })
    }

    fn is_junk_fileinto(&self, op: &Op<'s>) -> Result<bool, DecodeError> {
        Ok(match op {
            Op::FileInto {
                copy: false,
                create: false,
                folder: Value::Text("Junk"),
                flags,
                mailbox_id: Value::None,
                special_use: Value::Text("\\Junk"),
            } => self.is_text(*flags, JUNK_FLAG)?,
            _ => false,
        })
    }

    fn at_junk_move(&mut self) -> Result<bool, DecodeError> {
        let (
            Some((
                _,
                Op::FileInto {
                    copy: false,
                    create: false,
                    folder: Value::Text("INBOX"),
                    mailbox_id,
                    special_use: Value::None,
                    flags,
                },
            )),
            Some((
                _,
                Op::EditFlags {
                    action: FlagAction::Remove,
                    variable: Value::None,
                    flags: removed,
                },
            )),
        ) = (self.ops.get(self.idx), self.ops.get(self.idx + 1))
        else {
            return Ok(false);
        };
        if !flags.is_empty()
            || matches!(mailbox_id, Value::None)
            || !self.is_text(*removed, JUNK_FLAG)?
            || self.mailbox_id(*mailbox_id)? != Id::from(JUNK_ID)
        {
            return Ok(false);
        }
        self.idx += 2;
        Ok(true)
    }

    fn is_trash_fileinto(&self, op: &Op<'s>) -> bool {
        matches!(
            op,
            Op::FileInto {
                copy: false,
                create: false,
                folder: Value::Text("Trash"),
                mailbox_id: Value::None,
                special_use: Value::Text("\\Trash"),
                flags,
            } if flags.is_empty()
        )
    }

    fn header_names(&self, values: Values<'s>) -> Result<Vec<String>, DecodeError> {
        values
            .iter()
            .map(|value| match value {
                Value::Header(name) => Ok(name.as_str().to_ascii_lowercase()),
                Value::Number(_) | Value::Float(_) => self.string(value),
                _ => Err(self.error("expected header name")),
            })
            .collect()
    }

    fn domain_keys(&self, values: Values<'s>) -> Result<Vec<String>, DecodeError> {
        let keys = self.strings(values)?;
        let mut domains = Vec::with_capacity(keys.len() / 2);
        let mut keys = keys.into_iter();
        while let Some(domain) = keys.next() {
            if keys
                .next()
                .as_deref()
                .and_then(|wildcard| wildcard.strip_prefix("*."))
                .is_none_or(|wildcard| wildcard != domain)
            {
                return Err(self.error("invalid domain keys"));
            }
            domains.push(domain);
        }
        if domains.is_empty() {
            return Err(self.error("invalid domain keys"));
        }
        Ok(domains)
    }

    fn strings(&self, values: Values<'s>) -> Result<Vec<String>, DecodeError> {
        values.iter().map(|value| self.string(value)).collect()
    }

    fn is_texts<'e>(
        &self,
        values: Values<'s>,
        mut expected: impl Iterator<Item = &'e str>,
    ) -> Result<bool, DecodeError> {
        for value in values.iter() {
            match expected.next() {
                Some(expected) if self.text(value)? == expected => {}
                _ => return Ok(false),
            }
        }
        Ok(expected.next().is_none())
    }

    fn is_text(&self, values: Values<'s>, expected: &str) -> Result<bool, DecodeError> {
        single(values).map_or(Ok(false), |value| Ok(self.text(value)? == expected))
    }

    fn text(&self, value: Value<'s>) -> Result<Cow<'s, str>, DecodeError> {
        match value {
            Value::Text(text) => Ok(Cow::Borrowed(text)),
            value => self.string(value).map(Cow::Owned),
        }
    }

    fn string(&self, value: Value<'s>) -> Result<String, DecodeError> {
        let mut out = String::new();
        self.append(&mut out, value, true)?;
        Ok(out)
    }

    fn append(&self, out: &mut String, value: Value<'s>, nested: bool) -> Result<(), DecodeError> {
        match value {
            Value::Text(text) | Value::Glob(text) => out.push_str(text),
            Value::Number(number) => {
                let _ = write!(out, "{number}");
            }
            Value::Float(number) => {
                let _ = write!(out, "{number}");
            }
            Value::Local(var) if var == self.dollar_var => out.push('$'),
            Value::List(values) if nested => {
                for value in values.iter() {
                    self.append(out, value, false)?;
                }
            }
            _ => return Err(self.error("unexpected value")),
        }
        Ok(())
    }

    fn next(&mut self) -> Result<Op<'s>, DecodeError> {
        let op = self
            .ops
            .get(self.idx)
            .map(|(_, op)| *op)
            .ok_or_else(|| self.error("unexpected end of program"))?;
        self.idx += 1;
        Ok(op)
    }

    fn peek(&self) -> Option<&Op<'s>> {
        self.ops.get(self.idx).map(|(_, op)| op)
    }

    fn pos(&self) -> u32 {
        self.ops
            .get(self.idx)
            .map_or(self.code_len, |(pos, _)| *pos)
    }

    fn is_jump_at(&self, target: u32) -> bool {
        self.ops
            .binary_search_by_key(&target, |(pos, _)| *pos)
            .ok()
            .and_then(|idx| self.ops.get(idx))
            .is_some_and(|(_, op)| matches!(op, Op::Jz(_) | Op::Jnz(_)))
    }

    #[cold]
    fn error(&self, reason: &'static str) -> DecodeError {
        DecodeError {
            pos: self.pos(),
            reason,
        }
    }
}

fn is_weekday_test(op: &Op<'_>) -> bool {
    matches!(
        op,
        Op::TestCurrentDate {
            date_part: DatePart::Weekday,
            ..
        }
    )
}

fn api_keywords(flags: Vec<String>) -> Map<String> {
    Map::new(flags.into_iter().map(api_keyword).collect())
}

fn single(values: Values<'_>) -> Option<Value<'_>> {
    let mut values = values.iter();
    match (values.next(), values.next()) {
        (Some(value), None) => Some(value),
        _ => None,
    }
}

fn is_header(headers: Values<'_>, name: &str) -> bool {
    matches!(single(headers), Some(Value::Header(found)) if found.as_str().eq_ignore_ascii_case(name))
}

fn is_test(op: &Op<'_>) -> bool {
    matches!(
        op,
        Op::TestTrue
            | Op::TestFalse
            | Op::TestAddress { .. }
            | Op::TestEnvelope { .. }
            | Op::TestExists { .. }
            | Op::TestHeader { .. }
            | Op::TestSize { .. }
            | Op::TestBody { .. }
            | Op::TestCurrentDate { .. }
            | Op::TestEnvironment { .. }
            | Op::TestSpamTest { .. }
            | Op::TestString { .. }
            | Op::TestHasFlag { .. }
    )
}

fn is_plain(matcher: Matcher) -> bool {
    !matcher.is_not && matcher.comparator() == Comparator::AsciiCaseMap
}

fn is_only_to_count(decoder: &Decoder<'_>, op: &Op<'_>) -> Result<bool, DecodeError> {
    Ok(match op {
        Op::TestAddress {
            headers,
            keys,
            address_part: AddressPart::All,
            matcher:
                matcher @ Matcher {
                    match_type: MatchType::Count(RelationalMatch::Eq),
                    is_not: false,
                    ..
                },
            index: None,
            mime_anychild: false,
        } => {
            matcher.comparator() == Comparator::AsciiNumeric
                && matches!(decoder.header_names(*headers)?.as_slice(), [to, cc] if to == "to" && cc == "cc")
                && decoder.is_text(*keys, "1")?
        }
        _ => false,
    })
}

fn text_operator(match_type: MatchType) -> Option<MailRuleTextOperator> {
    match match_type {
        MatchType::Is => Some(MailRuleTextOperator::Is),
        MatchType::Contains => Some(MailRuleTextOperator::Contains),
        MatchType::Matches(_) => Some(MailRuleTextOperator::Matches),
        _ => None,
    }
}

fn parse_reason(reason: &str) -> Option<(String, Option<String>)> {
    if let Some(rest) = reason.strip_prefix(VACATION_MULTIPART) {
        let rest = rest.strip_prefix(VACATION_TEXT_PART)?;
        let (text, rest) = rest.split_once(VACATION_SEPARATOR)?;
        let html = rest
            .strip_prefix(VACATION_HTML_PART)?
            .strip_suffix(VACATION_END)?;
        Some((decode_base64(text)?, Some(decode_base64(html)?)))
    } else {
        Some((
            decode_base64(reason.strip_prefix(VACATION_TEXT_PART)?)?,
            None,
        ))
    }
}

fn decode_base64(value: &str) -> Option<String> {
    LENIENT
        .decode(value.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Managed Sieve script decode error at {}: {}",
            self.pos, self.reason
        )
    }
}
