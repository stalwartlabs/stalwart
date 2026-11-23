/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AUTO_SUBMITTED_HEADER, AUTO_SUBMITTED_PATTERN, DEFAULT_VACATION_TEXT, DOLLAR_VAR, DayMask,
    FLAGGED_FLAG, FORMAT_VERSION, FORWARDED_BY_HEADER, ForwarderId, HEADER_VAR, IS_SPAM_PERCENT,
    JUNK_FLAG, ManagedRule, ManagedScript, NOT_JUNK_FLAG, RULE_ENABLED, RULE_MATCH_ANY,
    SENDERS_HEADER, ScriptVars, SenderListKind, UTC_ZONE, VOICEMAIL_CLASSES, VOICEMAIL_HEADER,
    VacationResponse, is_custom_keyword, script_keyword,
};
use crate::mailbox::{JUNK_ID, TRASH_ID};
use encodify::base64::STANDARD;
use jmap_proto::types::date::UTCDate;
use mail_parser::decoders::html::html_to_text;
use registry::{
    schema::{
        enums::{
            MailRuleAddressOperator, MailRuleImportanceLevel, MailRuleMessageKind,
            MailRuleSensitivityLevel, MailRuleSentToMePlacement, MailRuleTextOperator, TimeZone,
        },
        structs::{
            MailRuleActions, MailRuleAddressTest, MailRuleCondition, MailRuleConditions,
            MailRuleRedirect, MailRuleReply, MailRuleSchedule, MailRuleTextTest,
        },
    },
    types::{EnumImpl, list::List, localtime::LocalTime, map::Map},
};
use std::fmt::Write;
use types::id::Id;

const CAPABILITY_NAMES: [&str; 20] = [
    "body",
    "comparator-i;ascii-numeric",
    "copy",
    "date",
    "editheader",
    "envelope",
    "environment",
    "fileinto",
    "imap4flags",
    "mailboxid",
    "mime",
    "reject",
    "relational",
    "spamtest",
    "spamtestplus",
    "special-use",
    "subaddress",
    "vacation",
    "vacation-seconds",
    "variables",
];
const SENDER_AUTHENTICATED_TEST: &str =
    "environment :is \"vnd.stalwart.sender-authenticated\" \"yes\"";
const JUNK_ACTION: &str = "fileinto :specialuse \"\\\\Junk\" :flags \"$junk\" \"Junk\";\r\n";
const TRASH_ACTION: &str = "fileinto :specialuse \"\\\\Trash\" \"Trash\";\r\n";
const RECIPIENT_HEADERS: &str = "[\"to\", \"cc\"]";
const IMPORTANCE_HEADERS: &str = "[\"importance\", \"x-priority\"]";
const IMPORTANCE_HIGH: &str = "[\"high\", \"1*\", \"2*\"]";
const IMPORTANCE_LOW: &str = "[\"low\", \"4*\", \"5*\"]";
const IMPORTANCE_ANY: &str = "[\"high\", \"low\", \"1*\", \"2*\", \"4*\", \"5*\"]";
const ONLY_TO_COUNT: &str =
    "address :count \"eq\" :comparator \"i;ascii-numeric\" [\"to\", \"cc\"] \"1\"";
const HAS_ATTACHMENT: &str =
    "header :mime :anychild :contains \"content-disposition\" \"attachment\"";
const SPAM_SCORE: &str = "spamtest :percent :value \"ge\" :comparator \"i;ascii-numeric\" ";
const MAILING_LIST: &str = "header :matches [\"list-id\", \"list-unsubscribe\"] \"*\"";
const MEETING_METHOD: &str = "header :mime :anychild :param \"method\" :is \"content-type\" ";
const REPORT_TYPE: &str = "header :mime :param \"report-type\" :is \"content-type\" ";
const ROOT_CONTENT_TYPE: &str = "header :mime :contenttype :is \"content-type\" ";
const AWAY_DECLARATION: &str = "set \"away\" \"0\";\r\n";
const AWAY_START: &str = "set \"away\" \"1\";\r\n";
const AWAY_TEST: &str = "string :is \"${away}\" \"1\"";
const KEYWORDS_DECLARATION: &str = "set \"keywords\" \"\";\r\n";
const KEYWORDS_ADD: &str = "addflag \"keywords\" ";
const KEYWORDS_REMOVE: &str = "removeflag \"keywords\" ";
const CLEAR_KEYWORDS: &str = "removeflag \"${keywords}\";\r\nset \"keywords\" \"\";\r\n";
pub(crate) const KEYWORDS_HEADER: &str = "keywords";
pub(crate) const ANY_KEYWORD_PATTERN: &str = "?*";
pub(crate) const MESSAGE_FLAG_HEADER: &str = "x-message-flag";
pub(crate) const AUTO_FORWARDED_HEADER: &str = "x-ms-exchange-organization-autoforwarded";
pub(crate) const AUTO_FORWARDED_VALUE: &str = "true";
pub(crate) const AWAY_VALUE: &str = "1";
pub(crate) const AWAY_UNSET: &str = "0";
pub(crate) const MEETING_REQUEST: &[&str] = &["request"];
pub(crate) const MEETING_RESPONSE: &[&str] = &["reply", "counter"];
pub(crate) const MEETING_CANCELLATION: &[&str] = &["cancel"];
pub(crate) const NON_DELIVERY_REPORT: &[&str] = &["delivery-status"];
pub(crate) const READ_RECEIPT: &[&str] = &["disposition-notification"];
pub(crate) const SIGNED: &[&str] = &["multipart/signed"];
pub(crate) const ENCRYPTED: &[&str] = &[
    "multipart/encrypted",
    "application/pkcs7-mime",
    "application/x-pkcs7-mime",
];
pub(crate) const IMPORTANCE_HEADER: &str = "Importance";
pub(crate) const PRIORITY_HEADER: &str = "X-Priority";
pub(crate) const CALENDAR_CONTENT_TYPE: &str = "text/calendar";
pub(crate) const PRIVATE_EVENT_CLASSES: &[&str] = &["CLASS:PRIVATE", "CLASS:CONFIDENTIAL"];
pub(crate) const VACATION_SEPARATOR: &str = "--stalwart-vacation\r\n";
pub(crate) const VACATION_END: &str = "--stalwart-vacation--\r\n";
pub(crate) const VACATION_TEXT_PART: &str = concat!(
    "Content-Type: text/plain; charset=\"utf-8\"\r\n",
    "Content-Transfer-Encoding: base64\r\n\r\n"
);
pub(crate) const VACATION_HTML_PART: &str = concat!(
    "Content-Type: text/html; charset=\"utf-8\"\r\n",
    "Content-Transfer-Encoding: base64\r\n\r\n"
);
pub(crate) const VACATION_MULTIPART: &str = concat!(
    "Content-Type: multipart/alternative; boundary=\"stalwart-vacation\"\r\n\r\n",
    "--stalwart-vacation\r\n"
);
pub(crate) const VACATION_MASK_TEXT: u8 = 1;
pub(crate) const VACATION_MASK_HTML: u8 = 2;
const BASE64_LINE: usize = 76;
pub(crate) const REPLY_HANDLE_PREFIX: &str = "rule";

#[derive(Clone, Copy)]
struct Capabilities(u32);

impl Capabilities {
    const BODY: u32 = 1 << 0;
    const NUMERIC: u32 = 1 << 1;
    const COPY: u32 = 1 << 2;
    const DATE: u32 = 1 << 3;
    const EDITHEADER: u32 = 1 << 4;
    const ENVELOPE: u32 = 1 << 5;
    const ENVIRONMENT: u32 = 1 << 6;
    const FILEINTO: u32 = 1 << 7;
    const IMAP4FLAGS: u32 = 1 << 8;
    const MAILBOXID: u32 = 1 << 9;
    const MIME: u32 = 1 << 10;
    const REJECT: u32 = 1 << 11;
    const RELATIONAL: u32 = 1 << 12;
    const SPAMTEST: u32 = 1 << 13;
    const SPAMTESTPLUS: u32 = 1 << 14;
    const SPECIAL_USE: u32 = 1 << 15;
    const SUBADDRESS: u32 = 1 << 16;
    const VACATION: u32 = 1 << 17;
    const VACATION_SECONDS: u32 = 1 << 18;
    const VARIABLES: u32 = 1 << 19;
    const SPECIAL_FOLDER: u32 = Self::FILEINTO | Self::SPECIAL_USE;
    const JUNK_FOLDER: u32 = Self::SPECIAL_FOLDER | Self::IMAP4FLAGS;
    const MAILBOX: u32 = Self::FILEINTO | Self::MAILBOXID;
    const NUMERIC_RELATION: u32 = Self::RELATIONAL | Self::NUMERIC;
    const SPAM_SCORE: u32 = Self::SPAMTEST | Self::SPAMTESTPLUS | Self::NUMERIC_RELATION;

    fn of(script: &ManagedScript, forwarder: Option<ForwarderId>) -> Self {
        let mut caps = Self::VARIABLES;
        let mut forwards = false;
        if let Some(vacation) = &script.vacation {
            caps |= Self::VACATION | Self::SPAM_SCORE;
            if vacation.from_date.is_some() || vacation.to_date.is_some() {
                caps |= Self::DATE | Self::RELATIONAL;
            }
        }
        if !script.blocked_senders.is_empty() {
            caps |= Self::JUNK_FOLDER;
        }
        if !script.safe_senders.is_empty() {
            caps |= Self::IMAP4FLAGS | Self::ENVIRONMENT;
        }
        for rule in &script.rules {
            forwards |= rule.rule.actions.redirect.is_some();
            caps |= rule
                .conditions()
                .map(Self::of_condition)
                .fold(Self::of_actions(&rule.rule.actions), |caps, cap| caps | cap);
        }
        if forwards && forwarder.is_some() {
            caps |= Self::EDITHEADER;
        }
        Capabilities(caps)
    }

    fn of_condition(condition: &MailRuleCondition) -> u32 {
        match condition {
            MailRuleCondition::SentToMe(sent_to_me)
                if sent_to_me.placement == MailRuleSentToMePlacement::OnlyTo =>
            {
                Self::NUMERIC_RELATION
            }
            MailRuleCondition::Body(_)
            | MailRuleCondition::SubjectOrBody(_)
            | MailRuleCondition::PrivateEvent => Self::BODY,
            MailRuleCondition::HasAttachment
            | MailRuleCondition::AttachmentName(_)
            | MailRuleCondition::AttachmentType(_) => Self::MIME,
            MailRuleCondition::MessageType(message_type) => match message_type.kind {
                MailRuleMessageKind::AutomaticReply
                | MailRuleMessageKind::AutomaticForward
                | MailRuleMessageKind::Voicemail => 0,
                MailRuleMessageKind::MeetingRequest
                | MailRuleMessageKind::MeetingResponse
                | MailRuleMessageKind::MeetingCancellation
                | MailRuleMessageKind::NonDeliveryReport
                | MailRuleMessageKind::ReadReceipt
                | MailRuleMessageKind::Signed
                | MailRuleMessageKind::Encrypted => Self::MIME,
            },
            MailRuleCondition::Keyword(_)
            | MailRuleCondition::AnyKeyword
            | MailRuleCondition::Flagged => Self::IMAP4FLAGS,
            MailRuleCondition::SpamScore(_) => Self::SPAM_SCORE,
            MailRuleCondition::RecipientAddress(_) => Self::ENVELOPE,
            MailRuleCondition::RecipientDetail(_) => Self::ENVELOPE | Self::SUBADDRESS,
            MailRuleCondition::ReceivedAfter(_) | MailRuleCondition::ReceivedBefore(_) => {
                Self::DATE | Self::RELATIONAL
            }
            MailRuleCondition::Schedule(_) => Self::DATE | Self::RELATIONAL,
            _ => 0,
        }
    }

    fn of_actions(actions: &MailRuleActions) -> u32 {
        let mut caps = 0;
        if actions.clear_keywords
            || !actions.add_keywords.is_empty()
            || !actions.remove_keywords.is_empty()
        {
            caps |= Self::IMAP4FLAGS;
        }
        if actions.set_importance.is_some() {
            caps |= Self::EDITHEADER;
        }
        if actions
            .redirect
            .as_ref()
            .is_some_and(|redirect| redirect.keep_copy)
        {
            caps |= Self::COPY;
        }
        if let Some(reply) = &actions.reply {
            caps |= Self::VACATION | Self::SPAM_SCORE;
            if reply.days == 0 {
                caps |= Self::VACATION_SECONDS;
            }
        }
        if !actions.copy_to.is_empty() {
            caps |= Self::MAILBOX | Self::COPY;
        }
        for id in actions.move_to.iter() {
            caps |= match id.document_id() {
                TRASH_ID => Self::SPECIAL_FOLDER,
                JUNK_ID => Self::MAILBOX | Self::IMAP4FLAGS,
                _ => Self::MAILBOX,
            };
        }
        if actions.reject.is_some() {
            caps |= Self::REJECT;
        }
        caps
    }

    fn write_require(self, out: &mut String) {
        out.push_str("require ");
        write_list(
            out,
            CAPABILITY_NAMES
                .iter()
                .enumerate()
                .filter(|(bit, _)| self.0 & (1 << bit) != 0)
                .map(|(_, name)| *name),
        );
        out.push_str(";\r\n");
    }
}

impl ManagedScript {
    pub fn emit(
        &self,
        forwarder: Option<ForwarderId>,
        addresses: &[String],
        account_zone: Option<TimeZone>,
    ) -> String {
        let mut out = String::with_capacity(1024);
        Capabilities::of(self, forwarder).write_require(&mut out);
        let _ = write!(out, "set \"{DOLLAR_VAR}\" \"$\";\r\n");
        let vars = self.vars();
        if vars.away {
            out.push_str(AWAY_DECLARATION);
        }
        if vars.keywords {
            out.push_str(KEYWORDS_DECLARATION);
        }
        if self.last_id > self.max_rule_id() {
            let _ = write!(
                out,
                "set \"{HEADER_VAR}\" \"{FORMAT_VERSION} last {}\";\r\n",
                self.last_id
            );
        }

        self.emit_sender_lists(&mut out);
        if let Some(vacation) = &self.vacation {
            vacation.emit(&mut out, vars);
        }
        for rule in &self.rules {
            rule.emit_header(&mut out);
            emit_body(&mut out, rule, forwarder, addresses, account_zone, vars);
        }
        out
    }

    fn emit_sender_lists(&self, out: &mut String) {
        if self.blocked_senders.is_empty() && self.safe_senders.is_empty() {
            return;
        }
        let _ = write!(
            out,
            "set \"{HEADER_VAR}\" \"{FORMAT_VERSION} {SENDERS_HEADER}\";\r\n"
        );
        let mut is_first = true;
        for (kind, is_domain) in [
            (SenderListKind::Safe, false),
            (SenderListKind::Blocked, false),
            (SenderListKind::Safe, true),
            (SenderListKind::Blocked, true),
        ] {
            let list = self.senders(kind);
            let has_keys = if is_domain {
                list.domains().next().is_some()
            } else {
                list.addresses().next().is_some()
            };
            if !has_keys {
                continue;
            }
            out.push_str(if is_first { "if " } else { "elsif " });
            is_first = false;
            if kind == SenderListKind::Safe {
                out.push_str("allof(");
                out.push_str(SENDER_AUTHENTICATED_TEST);
                out.push_str(", ");
            }
            if is_domain {
                out.push_str("address :domain :matches \"from\" ");
                write_domain_keys(out, list.domains());
            } else {
                out.push_str("address :is :all \"from\" ");
                write_list(out, list.addresses());
            }
            match kind {
                SenderListKind::Safe => {
                    out.push_str(") {\r\naddflag ");
                    write_quoted(out, NOT_JUNK_FLAG);
                    out.push_str(";\r\n");
                }
                SenderListKind::Blocked => {
                    out.push_str(" {\r\n");
                    out.push_str(JUNK_ACTION);
                    out.push_str("stop;\r\n");
                }
            }
            out.push_str("}\r\n");
        }
    }
}

impl ManagedRule {
    fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.rule.is_enabled {
            flags |= RULE_ENABLED;
        }
        if !self.rule.conditions.match_any.is_empty() {
            flags |= RULE_MATCH_ANY;
        }
        flags
    }

    fn emit_header(&self, out: &mut String) {
        let _ = write!(
            out,
            "set \"{HEADER_VAR}\" \"{FORMAT_VERSION} {} {} {} ",
            self.id,
            self.rule.position,
            self.flags()
        );
        write_escaped(out, &self.rule.name);
        out.push_str("\";\r\n");
    }
}

impl VacationResponse {
    fn emit(&self, out: &mut String, vars: ScriptVars) {
        let mut mask = 0;
        if self.text_body.is_some() {
            mask |= VACATION_MASK_TEXT;
        }
        if self.html_body.is_some() {
            mask |= VACATION_MASK_HTML;
        }
        let _ = write!(
            out,
            "set \"{HEADER_VAR}\" \"{FORMAT_VERSION} vacation {mask}\";\r\n"
        );
        let mut blocks = 0;
        if !self.is_enabled {
            out.push_str("if false {\r\n");
            blocks += 1;
        }
        for (relation, date) in [("ge", self.from_date), ("le", self.to_date)] {
            if let Some(date) = date {
                let _ = write!(
                    out,
                    "if currentdate :value \"{relation}\" \"iso8601\" \"{}\" {{\r\n",
                    UTCDate::from(date)
                );
                blocks += 1;
            }
        }
        if vars.away {
            out.push_str(AWAY_START);
        }
        write_spam_guard(out);
        blocks += 1;

        let derived_text;
        let text = match (&self.text_body, &self.html_body) {
            (Some(text), _) => text.as_str(),
            (None, Some(html)) => {
                derived_text = html_to_text(html);
                derived_text.as_str()
            }
            (None, None) => DEFAULT_VACATION_TEXT,
        };
        out.push_str("vacation ");
        write_vacation_message(
            out,
            self.subject.as_deref(),
            text,
            self.html_body.as_deref(),
        );
        for _ in 0..blocks {
            out.push_str("}\r\n");
        }
    }
}

fn write_vacation_message(out: &mut String, subject: Option<&str>, text: &str, html: Option<&str>) {
    out.push_str(":mime ");
    if let Some(subject) = subject {
        out.push_str(":subject ");
        write_quoted(out, subject);
        out.push(' ');
    }
    out.reserve((text.len() + html.map_or(0, str::len)) * 4 / 3 + 256);
    out.push('"');
    if let Some(html) = html {
        write_escaped(out, VACATION_MULTIPART);
        write_escaped(out, VACATION_TEXT_PART);
        write_base64(out, text.as_bytes());
        out.push_str(VACATION_SEPARATOR);
        write_escaped(out, VACATION_HTML_PART);
        write_base64(out, html.as_bytes());
        out.push_str(VACATION_END);
    } else {
        write_escaped(out, VACATION_TEXT_PART);
        write_base64(out, text.as_bytes());
    }
    out.push_str("\";\r\n");
}

fn emit_body(
    out: &mut String,
    rule: &ManagedRule,
    forwarder: Option<ForwarderId>,
    me: &[String],
    account_zone: Option<TimeZone>,
    vars: ScriptVars,
) {
    let is_enabled = rule.rule.is_enabled;
    let MailRuleConditions {
        match_all,
        match_any,
        match_none,
    } = &rule.rule.conditions;
    out.push_str("if ");
    if match_all.is_empty() && match_any.is_empty() {
        out.push_str(if is_enabled { "true" } else { "false" });
    } else {
        let is_wrapped = !is_enabled || !match_all.is_empty();
        if is_wrapped {
            out.push_str("allof(");
        }
        if !is_enabled {
            out.push_str("false, ");
        }
        write_conditions(out, match_all, me, account_zone);
        if !match_any.is_empty() {
            if !match_all.is_empty() {
                out.push_str(", ");
            }
            out.push_str("anyof(");
            write_conditions(out, match_any, me, account_zone);
            out.push(')');
        }
        if is_wrapped {
            out.push(')');
        }
    }
    out.push_str(" {\r\n");
    if !match_none.is_empty() {
        out.push_str("if anyof(");
        write_conditions(out, match_none, me, account_zone);
        out.push_str(") {\r\n} else {\r\n");
    }
    write_actions(out, rule.id, &rule.rule.actions, forwarder, vars);
    if !match_none.is_empty() {
        out.push_str("}\r\n");
    }
    out.push_str("}\r\n");
}

fn write_conditions(
    out: &mut String,
    conditions: &List<MailRuleCondition>,
    me: &[String],
    account_zone: Option<TimeZone>,
) {
    for (idx, condition) in conditions.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        write_condition(out, condition, me, account_zone);
    }
}

fn write_schedule(out: &mut String, schedule: &MailRuleSchedule, account_zone: Option<TimeZone>) {
    let (marker, zone) = match schedule.time_zone {
        Some(zone) => ("allof(true, true, ", Some(zone)),
        None => ("allof(true, ", account_zone),
    };
    let zone = zone.map_or(UTC_ZONE, |zone| zone.as_str());
    out.push_str(marker);
    let groups = schedule.slots.len()
        + schedule
            .slots
            .iter()
            .filter(|slot| slot.end < slot.start)
            .count();
    if groups > 1 {
        out.push_str("anyof(");
    }
    for (idx, slot) in schedule.slots.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let days = DayMask::of(&slot.days);
        if slot.start < slot.end {
            write_slot(out, zone, days, Some(slot.start), Some(slot.end));
        } else {
            write_slot(out, zone, days, Some(slot.start), None);
            out.push_str(", ");
            write_slot(out, zone, days.next_day(), None, Some(slot.end));
        }
    }
    if groups > 1 {
        out.push(')');
    }
    out.push(')');
}

fn write_slot(
    out: &mut String,
    zone: &str,
    days: DayMask,
    start: Option<LocalTime>,
    end: Option<LocalTime>,
) {
    let _ = write!(out, "allof(currentdate :zone \"{zone}\" :is \"weekday\" [");
    for (idx, key) in days.sieve_keys().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "\"{key}\"");
    }
    out.push(']');
    if let Some(start) = start {
        let _ = write!(
            out,
            ", currentdate :zone \"{zone}\" :value \"ge\" \"time\" \"{start}:00\""
        );
    }
    if let Some(end) = end {
        let _ = write!(
            out,
            ", currentdate :zone \"{zone}\" :value \"lt\" \"time\" \"{end}:00\""
        );
    }
    out.push(')');
}

fn write_condition(
    out: &mut String,
    condition: &MailRuleCondition,
    me: &[String],
    account_zone: Option<TimeZone>,
) {
    match condition {
        MailRuleCondition::From(test) => write_address_test(out, "address", "\"from\"", test),
        MailRuleCondition::To(test) => write_address_test(out, "address", "\"to\"", test),
        MailRuleCondition::Cc(test) => write_address_test(out, "address", "\"cc\"", test),
        MailRuleCondition::ToOrCc(test) => {
            write_address_test(out, "address", RECIPIENT_HEADERS, test)
        }
        MailRuleCondition::SentToMe(sent_to_me) => {
            let (prefix, headers) = match sent_to_me.placement {
                MailRuleSentToMePlacement::To | MailRuleSentToMePlacement::OnlyTo => ("", "\"to\""),
                MailRuleSentToMePlacement::Cc => ("", "\"cc\""),
                MailRuleSentToMePlacement::ToOrCc => ("", RECIPIENT_HEADERS),
                MailRuleSentToMePlacement::NotTo => ("not ", "\"to\""),
            };
            let _ = write!(out, "allof(true, {prefix}address :is :all {headers} ");
            if me.is_empty() {
                out.push_str("\"\"");
            } else {
                write_list(out, me.iter().map(String::as_str));
            }
            if sent_to_me.placement == MailRuleSentToMePlacement::OnlyTo {
                out.push_str(", ");
                out.push_str(ONLY_TO_COUNT);
            }
            out.push(')');
        }
        MailRuleCondition::Subject(test) => write_header_test(out, "subject", test),
        MailRuleCondition::Body(MailRuleTextTest { operator, values }) => {
            out.push_str("body :text ");
            out.push_str(text_operator(*operator));
            write_list(out, values.iter().map(String::as_str));
        }
        MailRuleCondition::Header(test) => {
            out.push_str("header ");
            out.push_str(text_operator(test.operator));
            write_quoted(out, &test.header);
            out.push(' ');
            write_list(out, test.values.iter().map(String::as_str));
        }
        MailRuleCondition::SizeOver(size) => {
            let _ = write!(out, "size :over {}", size.kilobytes.saturating_mul(1024));
        }
        MailRuleCondition::SizeUnder(size) => {
            let _ = write!(out, "size :under {}", size.kilobytes.saturating_mul(1024));
        }
        MailRuleCondition::Keyword(test) => {
            out.push_str("anyof(false, hasflag ");
            write_list(out, script_keywords(&test.keywords));
            let _ = write!(out, ", header :contains \"{KEYWORDS_HEADER}\" ");
            write_list(out, script_keywords(&test.keywords));
            out.push(')');
        }
        MailRuleCondition::AnyKeyword => {
            let _ = write!(
                out,
                "anyof(false, exists \"{KEYWORDS_HEADER}\", hasflag :matches \"keywords\" \"{ANY_KEYWORD_PATTERN}\")"
            );
        }
        MailRuleCondition::Flagged => {
            out.push_str("anyof(false, hasflag ");
            write_quoted(out, FLAGGED_FLAG);
            let _ = write!(out, ", exists \"{MESSAGE_FLAG_HEADER}\")");
        }
        MailRuleCondition::HasAttachment => out.push_str(HAS_ATTACHMENT),
        MailRuleCondition::Importance(importance) => {
            let (prefix, keys) = match importance.level {
                MailRuleImportanceLevel::High => ("", IMPORTANCE_HIGH),
                MailRuleImportanceLevel::Low => ("", IMPORTANCE_LOW),
                MailRuleImportanceLevel::Normal => ("not ", IMPORTANCE_ANY),
            };
            let _ = write!(out, "{prefix}header :matches {IMPORTANCE_HEADERS} {keys}");
        }
        MailRuleCondition::Sensitivity(sensitivity) => match sensitivity.level {
            MailRuleSensitivityLevel::Normal => out.push_str("not exists \"sensitivity\""),
            level => {
                let _ = write!(
                    out,
                    "header :is \"sensitivity\" \"{}\"",
                    sensitivity_value(level)
                );
            }
        },
        MailRuleCondition::SpamScore(score) => {
            let _ = write!(out, "{SPAM_SCORE}\"{}\"", score.percent);
        }
        MailRuleCondition::IsAway => out.push_str(AWAY_TEST),
        MailRuleCondition::MessageType(message_type) => {
            let (test, keys) = match message_type.kind {
                MailRuleMessageKind::MeetingRequest => (MEETING_METHOD, MEETING_REQUEST),
                MailRuleMessageKind::MeetingResponse => (MEETING_METHOD, MEETING_RESPONSE),
                MailRuleMessageKind::MeetingCancellation => (MEETING_METHOD, MEETING_CANCELLATION),
                MailRuleMessageKind::NonDeliveryReport => (REPORT_TYPE, NON_DELIVERY_REPORT),
                MailRuleMessageKind::ReadReceipt => (REPORT_TYPE, READ_RECEIPT),
                MailRuleMessageKind::Signed => (ROOT_CONTENT_TYPE, SIGNED),
                MailRuleMessageKind::Encrypted => (ROOT_CONTENT_TYPE, ENCRYPTED),
                MailRuleMessageKind::AutomaticReply => {
                    let _ = write!(
                        out,
                        "header :matches \"{AUTO_SUBMITTED_HEADER}\" \"{AUTO_SUBMITTED_PATTERN}\""
                    );
                    return;
                }
                MailRuleMessageKind::AutomaticForward => {
                    let _ = write!(
                        out,
                        "anyof(false, header :is \"{AUTO_FORWARDED_HEADER}\" \"{AUTO_FORWARDED_VALUE}\", exists \"{FORWARDED_BY_HEADER}\")"
                    );
                    return;
                }
                MailRuleMessageKind::Voicemail => {
                    let _ = write!(out, "header :is \"{VOICEMAIL_HEADER}\" ");
                    write_list(out, VOICEMAIL_CLASSES.iter().copied());
                    return;
                }
            };
            out.push_str(test);
            write_list(out, keys.iter().copied());
        }
        MailRuleCondition::HeaderExists(header) => {
            out.push_str("exists ");
            write_quoted(out, &header.header);
        }
        MailRuleCondition::AttachmentName(test) => {
            out.push_str("header :mime :anychild :param \"filename\" ");
            out.push_str(text_operator(test.operator));
            out.push_str("\"content-disposition\" ");
            write_list(out, test.values.iter().map(String::as_str));
        }
        MailRuleCondition::AttachmentType(test) => {
            out.push_str("header :mime :anychild :contenttype ");
            out.push_str(text_operator(test.operator));
            out.push_str("\"content-type\" ");
            write_list(out, test.values.iter().map(String::as_str));
        }
        MailRuleCondition::MailingList => out.push_str(MAILING_LIST),
        MailRuleCondition::RecipientAddress(test) => {
            write_address_test(out, "envelope", "\"to\"", test)
        }
        MailRuleCondition::RecipientDetail(test) => {
            out.push_str("envelope :detail ");
            out.push_str(text_operator(test.operator));
            out.push_str("\"to\" ");
            write_list(out, test.values.iter().map(String::as_str));
        }
        MailRuleCondition::SubjectOrBody(MailRuleTextTest { operator, values }) => {
            out.push_str("body :text :subject ");
            out.push_str(text_operator(*operator));
            write_list(out, values.iter().map(String::as_str));
        }
        MailRuleCondition::ReceivedAfter(date) => {
            let _ = write!(
                out,
                "currentdate :value \"ge\" \"iso8601\" \"{}\"",
                date.date
            );
        }
        MailRuleCondition::ReceivedBefore(date) => {
            let _ = write!(
                out,
                "currentdate :value \"le\" \"iso8601\" \"{}\"",
                date.date
            );
        }
        MailRuleCondition::Schedule(schedule) => write_schedule(out, schedule, account_zone),
        MailRuleCondition::PrivateEvent => {
            out.push_str("body :content ");
            write_quoted(out, CALENDAR_CONTENT_TYPE);
            out.push_str(" :contains ");
            write_list(out, PRIVATE_EVENT_CLASSES.iter().copied());
        }
    }
}

fn write_address_test(
    out: &mut String,
    test_name: &str,
    headers: &str,
    test: &MailRuleAddressTest,
) {
    let operator = match test.operator {
        MailRuleAddressOperator::Is => " :is :all ",
        MailRuleAddressOperator::Contains => " :contains :all ",
        MailRuleAddressOperator::Matches => " :matches :all ",
        MailRuleAddressOperator::Domain => " :domain :matches ",
    };
    out.push_str(test_name);
    out.push_str(operator);
    out.push_str(headers);
    out.push(' ');
    let values = test.values.iter().map(String::as_str);
    if test.operator == MailRuleAddressOperator::Domain {
        write_domain_keys(out, values);
    } else {
        write_list(out, values);
    }
}

fn write_header_test(out: &mut String, header: &str, test: &MailRuleTextTest) {
    out.push_str("header ");
    out.push_str(text_operator(test.operator));
    write_quoted(out, header);
    out.push(' ');
    write_list(out, test.values.iter().map(String::as_str));
}

fn write_actions(
    out: &mut String,
    rule_id: u64,
    actions: &MailRuleActions,
    forwarder: Option<ForwarderId>,
    vars: ScriptVars,
) {
    if actions.clear_keywords {
        out.push_str(CLEAR_KEYWORDS);
    }
    for (command, tracking, keywords) in [
        ("removeflag ", KEYWORDS_REMOVE, &actions.remove_keywords),
        ("addflag ", KEYWORDS_ADD, &actions.add_keywords),
    ] {
        if keywords.is_empty() {
            continue;
        }
        write_flag_edit(out, command, keywords);
        if vars.keywords {
            write_keyword_tracking(out, tracking, keywords);
        }
    }
    if let Some(level) = actions.set_importance {
        let _ = write!(
            out,
            "deleteheader \"{IMPORTANCE_HEADER}\";\r\ndeleteheader \"{PRIORITY_HEADER}\";\r\naddheader \"{IMPORTANCE_HEADER}\" \"{}\";\r\n",
            level.as_str()
        );
    }
    if let Some(redirect) = &actions.redirect {
        write_guarded_redirect(out, redirect, forwarder);
    }
    if let Some(reply) = &actions.reply {
        write_reply(out, rule_id, reply);
    }
    for id in actions.copy_to.iter() {
        write_file_into(out, "fileinto :copy", id);
    }
    for id in actions.move_to.iter() {
        match id.document_id() {
            TRASH_ID => out.push_str(TRASH_ACTION),
            JUNK_ID => {
                let _ = write!(out, "addflag \"{JUNK_FLAG}\";\r\n");
                write_file_into(out, "fileinto", id);
                let _ = write!(out, "removeflag \"{JUNK_FLAG}\";\r\n");
            }
            _ => write_file_into(out, "fileinto", id),
        }
    }
    if actions.discard {
        out.push_str("discard;\r\n");
    }
    if let Some(reject) = &actions.reject {
        out.push_str("reject ");
        write_quoted(out, &reject.reason);
        out.push_str(";\r\n");
    }
    if actions.stop_processing {
        out.push_str("stop;\r\n");
    }
}

fn write_file_into(out: &mut String, command: &str, mailbox_id: &Id) {
    let _ = write!(out, "{command} :mailboxid \"{mailbox_id}\" \"INBOX\";\r\n");
}

fn write_reply(out: &mut String, rule_id: u64, reply: &MailRuleReply) {
    let MailRuleReply {
        subject,
        text_body,
        html_body,
        days,
    } = reply;
    let period = if *days == 0 { ":seconds" } else { ":days" };
    write_spam_guard(out);
    let _ = write!(
        out,
        "vacation {period} {days} :handle \"{REPLY_HANDLE_PREFIX}{rule_id}\" "
    );
    write_vacation_message(out, subject.as_deref(), text_body, html_body.as_deref());
    out.push_str("}\r\n");
}

fn write_guarded_redirect(
    out: &mut String,
    redirect: &MailRuleRedirect,
    forwarder: Option<ForwarderId>,
) {
    let Some(forwarder) = forwarder else {
        write_redirect(out, redirect);
        return;
    };
    let _ = write!(
        out,
        "if not header :contains \"{FORWARDED_BY_HEADER}\" \"{forwarder}\" {{\r\naddheader \"{FORWARDED_BY_HEADER}\" \"{forwarder}\";\r\n"
    );
    write_redirect(out, redirect);
    let _ = write!(
        out,
        "deleteheader \"{FORWARDED_BY_HEADER}\" \"{forwarder}\";\r\n}}\r\n"
    );
}

fn write_spam_guard(out: &mut String) {
    let _ = write!(out, "if not {SPAM_SCORE}\"{IS_SPAM_PERCENT}\" {{\r\n");
}

fn write_flag_edit(out: &mut String, command: &str, keywords: &Map<String>) {
    out.push_str(command);
    write_list(out, script_keywords(keywords));
    out.push_str(";\r\n");
}

fn script_keywords(keywords: &Map<String>) -> impl Iterator<Item = &str> {
    keywords.iter().map(|keyword| script_keyword(keyword))
}

fn write_keyword_tracking(out: &mut String, command: &str, keywords: &Map<String>) {
    let mut custom = keywords
        .iter()
        .map(String::as_str)
        .filter(|keyword| is_custom_keyword(keyword))
        .peekable();
    if custom.peek().is_some() {
        out.push_str(command);
        write_list(out, custom);
        out.push_str(";\r\n");
    }
}

fn write_redirect(out: &mut String, redirect: &MailRuleRedirect) {
    for address in redirect.addresses.iter() {
        out.push_str(if redirect.keep_copy {
            "redirect :copy "
        } else {
            "redirect "
        });
        write_quoted(out, address);
        out.push_str(";\r\n");
    }
}

fn text_operator(operator: MailRuleTextOperator) -> &'static str {
    match operator {
        MailRuleTextOperator::Contains => ":contains ",
        MailRuleTextOperator::Is => ":is ",
        MailRuleTextOperator::Matches => ":matches ",
    }
}

pub(crate) fn sensitivity_value(level: MailRuleSensitivityLevel) -> &'static str {
    match level {
        MailRuleSensitivityLevel::Normal => "normal",
        MailRuleSensitivityLevel::Personal => "personal",
        MailRuleSensitivityLevel::Private => "private",
        MailRuleSensitivityLevel::Confidential => "company-confidential",
    }
}

fn write_list<'x>(out: &mut String, values: impl Iterator<Item = &'x str>) {
    out.push('[');
    for (idx, value) in values.enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        write_quoted(out, value);
    }
    out.push(']');
}

fn write_domain_keys<'x>(out: &mut String, domains: impl Iterator<Item = &'x str>) {
    out.push('[');
    for (idx, domain) in domains.enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        write_quoted(out, domain);
        out.push_str(", \"*.");
        write_escaped(out, domain);
        out.push('"');
    }
    out.push(']');
}

fn write_quoted(out: &mut String, value: &str) {
    out.push('"');
    write_escaped(out, value);
    out.push('"');
}

fn write_escaped(out: &mut String, value: &str) {
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            '$' if chars.peek() == Some(&'{') => {
                let _ = write!(out, "${{{DOLLAR_VAR}}}");
            }
            _ => out.push(ch),
        }
    }
}

fn write_base64(out: &mut String, bytes: &[u8]) {
    let encoded = STANDARD.encode(bytes);
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(BASE64_LINE));
        out.push_str(line);
        out.push_str("\r\n");
        rest = tail;
    }
}
