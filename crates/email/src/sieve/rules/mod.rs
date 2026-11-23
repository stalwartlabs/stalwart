/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mailbox::JUNK_ID;
use decode::DecodeError;
use registry::{
    schema::{
        enums::{
            MailRuleAddressOperator, MailRuleMessageKind, MailRuleSensitivityLevel,
            MailRuleTextOperator, Weekday,
        },
        structs::{
            MailRule, MailRuleActions, MailRuleCondition, MailRuleConditions, MailRuleMessageType,
            MailRuleRedirect, MailRuleSchedule, MailRuleSensitivity, MailRuleTextTest,
        },
    },
    types::{
        EnumImpl,
        list::List,
        localtime::LocalTime,
        map::{Map, MapItem},
    },
};
use std::fmt::{self, Display, Formatter};
use types::{id::Id, keyword::Keyword};

pub mod decode;
pub mod emit;
pub mod managed;

pub const MANAGED_SCRIPT_NAME: &str = "managed";
pub const MANAGED_SCRIPT_ID: u32 = 0;
pub const SENDER_AUTHENTICATED_ENV: &str = "vnd.stalwart.sender-authenticated";
pub const NOT_JUNK_FLAG: &str = "$notjunk";
pub const FLAGGED_FLAG: &str = "\\Flagged";
pub const MAX_SIZE_KB: u64 = 1 << 32;
pub const MAX_TIMESTAMP: i64 = 32_535_215_999;
pub const MAX_SCHEDULE_SLOTS: usize = 14;
pub const MINUTES_PER_DAY: u16 = 24 * 60;

pub const MAX_SENDER_ENTRIES: usize = 1024;

pub(crate) const JUNK_FLAG: &str = "$junk";
const MAX_ADDRESS_VALUE_LEN: usize = 320;
pub(crate) const FORMAT_VERSION: &str = "1";
pub(crate) const HEADER_VAR: &str = "rule";
pub(crate) const DOLLAR_VAR: &str = "d";
pub(crate) const SENDERS_HEADER: &str = "senders";
pub(crate) const FORWARDED_BY_HEADER: &str = "X-Forwarded-By";
const FORWARDER_ID_CONTEXT: &str = "Stalwart mail rules X-Forwarded-By";
pub(crate) const DEFAULT_VACATION_TEXT: &str = "I am away.";
pub(crate) const AUTO_SUBMITTED_HEADER: &str = "auto-submitted";
pub(crate) const AUTO_SUBMITTED_PATTERN: &str = "auto-*";
pub(crate) const IS_SPAM_PERCENT: u64 = 50;
pub(crate) const RULE_ENABLED: u8 = 1;
pub(crate) const RULE_MATCH_ANY: u8 = 1 << 1;
pub(crate) const VOICEMAIL_HEADER: &str = "content-class";
pub(crate) const VOICEMAIL_CLASSES: &[&str] = &["voice", "voice-ca"];
pub(crate) const UTC_ZONE: &str = "UTC";
const DAYS_PER_WEEK: u16 = 7;

macro_rules! system_flags {
    ($($keyword:tt => $flag:tt),+ $(,)?) => {
        pub(crate) fn script_keyword(keyword: &str) -> &str {
            hashify::map!(keyword.as_bytes(), &str, $($keyword => $flag),+)
                .copied()
                .unwrap_or(keyword)
        }

        pub(crate) fn api_keyword(flag: String) -> String {
            match hashify::map!(flag.as_bytes(), &str, $($flag => $keyword),+) {
                Some(keyword) => keyword.to_string(),
                None => flag,
            }
        }
    };
}

system_flags! {
    "$seen" => "\\Seen",
    "$flagged" => "\\Flagged",
    "$answered" => "\\Answered",
    "$draft" => "\\Draft",
    "$deleted" => "\\Deleted",
    "$recent" => "\\Recent",
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DayMask(u8);

impl DayMask {
    const ALL: u8 = (1 << DAYS_PER_WEEK) - 1;

    fn of(days: &Map<Weekday>) -> Self {
        DayMask(days.iter().fold(0, |mask, day| mask | (1 << day.to_id())))
    }

    fn from_sieve_keys(keys: impl Iterator<Item = Option<u16>>) -> Option<Self> {
        let mut mask = 0u8;
        let mut last = None;
        for key in keys {
            let id = key.filter(|key| *key < DAYS_PER_WEEK)? + DAYS_PER_WEEK - 1;
            let id = id % DAYS_PER_WEEK;
            if last.is_some_and(|last| id <= last) {
                return None;
            }
            last = Some(id);
            mask |= 1 << id;
        }
        (mask != 0).then_some(DayMask(mask))
    }

    fn next_day(self) -> Self {
        DayMask(((self.0 << 1) | (self.0 >> (DAYS_PER_WEEK - 1))) & Self::ALL)
    }

    fn ids(self) -> impl Iterator<Item = u16> {
        (0..DAYS_PER_WEEK).filter(move |id| self.0 & (1 << id) != 0)
    }

    fn sieve_keys(self) -> impl Iterator<Item = u16> {
        self.ids().map(|id| (id + 1) % DAYS_PER_WEEK)
    }

    fn days(self) -> Map<Weekday> {
        Map::new(self.ids().filter_map(Weekday::from_id).collect())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ManagedScript {
    pub rules: Vec<ManagedRule>,
    pub blocked_senders: SenderList,
    pub safe_senders: SenderList,
    pub vacation: Option<VacationResponse>,
    pub last_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderListKind {
    Blocked,
    Safe,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SenderList(Vec<SenderEntry>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderEntry {
    pub id: u64,
    pub entry: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwarderId(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRule {
    pub id: u64,
    pub rule: MailRule,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VacationResponse {
    pub is_enabled: bool,
    pub from_date: Option<u64>,
    pub to_date: Option<u64>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ScriptVars {
    pub(crate) away: bool,
    pub(crate) keywords: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    InvalidEntry(String),
    InvalidHeaderName(String),
    InvalidKeyword(String),
    ConflictingKeyword(String),
    InvalidDomain(String),
    AddressTooLong,
    InvalidSize(u64),
    InvalidDate(i64),
    InvalidSchedule,
    RejectNotAlone,
    EntryExists(u64),
    EntryIdTaken,
    TooManyEntries,
    NotFound(u64),
    Empty(&'static str),
    Compile(String),
    Decode(DecodeError),
    TooManyInstructions { instructions: usize, limit: usize },
}

pub fn is_managed_script(name: &str) -> bool {
    name.eq_ignore_ascii_case(MANAGED_SCRIPT_NAME)
}

impl ManagedScript {
    pub fn runs_anything(&self) -> bool {
        self.rules.iter().any(|rule| rule.rule.is_enabled)
            || !self.blocked_senders.is_empty()
            || !self.safe_senders.is_empty()
            || self.vacation.as_ref().is_some_and(|v| v.is_enabled)
    }

    pub fn uses_account_zone(&self) -> bool {
        self.rules
            .iter()
            .flat_map(ManagedRule::conditions)
            .any(|condition| {
                matches!(
                    condition,
                    MailRuleCondition::Schedule(schedule) if schedule.time_zone.is_none()
                )
            })
    }

    pub fn senders(&self, kind: SenderListKind) -> &SenderList {
        match kind {
            SenderListKind::Blocked => &self.blocked_senders,
            SenderListKind::Safe => &self.safe_senders,
        }
    }

    pub fn into_senders(self, kind: SenderListKind) -> SenderList {
        match kind {
            SenderListKind::Blocked => self.blocked_senders,
            SenderListKind::Safe => self.safe_senders,
        }
    }

    pub fn senders_mut(&mut self, kind: SenderListKind) -> &mut SenderList {
        match kind {
            SenderListKind::Blocked => &mut self.blocked_senders,
            SenderListKind::Safe => &mut self.safe_senders,
        }
    }

    pub fn next_id(&self) -> u64 {
        self.max_rule_id().max(self.last_id) + 1
    }

    pub(crate) fn vars(&self) -> ScriptVars {
        let mut vars = ScriptVars::default();
        for rule in &self.rules {
            vars.keywords |= rule.rule.actions.clear_keywords;
            for condition in rule.conditions() {
                vars.away |= matches!(condition, MailRuleCondition::IsAway);
                vars.keywords |= matches!(condition, MailRuleCondition::AnyKeyword);
            }
        }
        vars
    }

    pub(crate) fn max_rule_id(&self) -> u64 {
        self.rules.iter().map(|rule| rule.id).max().unwrap_or(0)
    }

    pub fn rule(&self, id: u64) -> Option<&ManagedRule> {
        self.rules.iter().find(|rule| rule.id == id)
    }

    pub fn upsert(&mut self, mut rule: ManagedRule) -> Result<(), RuleError> {
        rule.canonicalize()?;
        self.last_id = self.last_id.max(rule.id);
        if let Some(existing) = self.rules.iter_mut().find(|other| other.id == rule.id) {
            *existing = rule;
        } else {
            self.rules.push(rule);
        }
        self.sort();
        Ok(())
    }

    pub fn remove(&mut self, id: u64) -> Result<ManagedRule, RuleError> {
        self.rules
            .iter()
            .position(|rule| rule.id == id)
            .map(|idx| self.rules.remove(idx))
            .ok_or(RuleError::NotFound(id))
    }

    pub fn set_vacation(&mut self, mut vacation: VacationResponse) {
        vacation.canonicalize();
        self.vacation = Some(vacation);
    }

    pub(crate) fn sort(&mut self) {
        self.rules
            .sort_unstable_by_key(|rule| (rule.rule.position, rule.id));
    }
}

impl ManagedRule {
    pub fn canonicalize(&mut self) -> Result<(), RuleError> {
        canonicalize_rule(&mut self.rule)
    }

    pub(crate) fn conditions(&self) -> impl Iterator<Item = &MailRuleCondition> {
        let conditions = &self.rule.conditions;
        conditions
            .match_all
            .iter()
            .chain(conditions.match_any.iter())
            .chain(conditions.match_none.iter())
    }
}

impl SenderList {
    pub fn entry_id(entry: &str) -> u64 {
        blake3::hash(entry.as_bytes())
            .as_bytes()
            .first_chunk()
            .map_or(0, |bytes| u64::from_be_bytes(*bytes) >> 1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SenderEntry> {
        self.0.iter()
    }

    pub fn insert(&mut self, entry: &str) -> Result<u64, RuleError> {
        let mut entry = entry.trim().to_lowercase();
        strip_line_breaks(&mut entry);
        validate_list_entry(&entry)?;
        let id = Self::entry_id(&entry);
        let idx = match self
            .0
            .binary_search_by(|other| other.entry.as_str().cmp(&entry))
        {
            Ok(_) => return Err(RuleError::EntryExists(id)),
            Err(idx) => idx,
        };
        if self.0.len() >= MAX_SENDER_ENTRIES {
            return Err(RuleError::TooManyEntries);
        }
        if self.0.iter().any(|other| other.id == id) {
            return Err(RuleError::EntryIdTaken);
        }
        self.0.insert(idx, SenderEntry { id, entry });
        Ok(id)
    }

    pub fn remove(&mut self, id: u64) -> Option<SenderEntry> {
        self.0
            .iter()
            .position(|entry| entry.id == id)
            .map(|idx| self.0.remove(idx))
    }

    pub(crate) fn addresses(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .map(|entry| entry.entry.as_str())
            .filter(|entry| !entry.starts_with('@'))
    }

    pub(crate) fn domains(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter_map(|entry| entry.entry.strip_prefix('@'))
    }

    pub(crate) fn push_decoded(&mut self, entry: String) {
        self.0.push(SenderEntry {
            id: Self::entry_id(&entry),
            entry,
        });
    }

    pub(crate) fn finish_decoded(&mut self) -> bool {
        self.0.sort_unstable_by(|a, b| a.entry.cmp(&b.entry));
        self.0.len() <= MAX_SENDER_ENTRIES
            && self
                .0
                .windows(2)
                .all(|pair| matches!(pair, [a, b] if a.entry != b.entry))
    }
}

impl IntoIterator for SenderList {
    type Item = SenderEntry;
    type IntoIter = std::vec::IntoIter<SenderEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl ForwarderId {
    pub fn new(secret: &[u8], account_id: u32) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(FORWARDER_ID_CONTEXT);
        hasher.update(secret);
        hasher.update(&account_id.to_be_bytes());
        ForwarderId(
            hasher
                .finalize()
                .as_bytes()
                .first_chunk()
                .map_or(0, |bytes| u64::from_be_bytes(*bytes)),
        )
    }
}

impl Display for ForwarderId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl VacationResponse {
    pub fn canonicalize(&mut self) {
        if let Some(subject) = &mut self.subject {
            strip_line_breaks(subject);
        }
    }
}

fn canonicalize_rule(rule: &mut MailRule) -> Result<(), RuleError> {
    canonicalize_line(&mut rule.name, "name")?;
    let MailRuleConditions {
        match_all,
        match_any,
        match_none,
    } = &mut rule.conditions;
    for list in [match_all, match_any, match_none] {
        *list = std::mem::take(list)
            .into_iter()
            .map(canonicalize_condition)
            .collect::<Result<List<_>, _>>()?;
    }
    canonicalize_actions(&mut rule.actions)
}

fn canonicalize_condition(condition: MailRuleCondition) -> Result<MailRuleCondition, RuleError> {
    Ok(match condition {
        MailRuleCondition::From(mut test) => {
            canonicalize_address_test(&mut test.operator, &mut test.values)?;
            MailRuleCondition::From(test)
        }
        MailRuleCondition::To(mut test) => {
            canonicalize_address_test(&mut test.operator, &mut test.values)?;
            MailRuleCondition::To(test)
        }
        MailRuleCondition::Cc(mut test) => {
            canonicalize_address_test(&mut test.operator, &mut test.values)?;
            MailRuleCondition::Cc(test)
        }
        MailRuleCondition::ToOrCc(mut test) => {
            canonicalize_address_test(&mut test.operator, &mut test.values)?;
            MailRuleCondition::ToOrCc(test)
        }
        MailRuleCondition::Subject(mut test) => {
            canonicalize_values(&mut test.values)?;
            MailRuleCondition::Subject(test)
        }
        MailRuleCondition::Body(mut test) => {
            canonicalize_values(&mut test.values)?;
            MailRuleCondition::Body(test)
        }
        MailRuleCondition::Header(mut test) => {
            canonicalize_header_name(&mut test.header)?;
            canonicalize_values(&mut test.values)?;
            if test.header == "subject" {
                MailRuleCondition::Subject(MailRuleTextTest {
                    operator: test.operator,
                    values: test.values,
                })
            } else if let (true, MailRuleTextOperator::Is, [value]) = (
                test.header == "sensitivity",
                test.operator,
                test.values.as_slice(),
            ) && let Some(level) = sensitivity_level(value)
            {
                MailRuleCondition::Sensitivity(MailRuleSensitivity { level })
            } else if test.header == VOICEMAIL_HEADER
                && test.operator == MailRuleTextOperator::Is
                && test.values.len() == VOICEMAIL_CLASSES.len()
                && VOICEMAIL_CLASSES.iter().all(|class| {
                    test.values
                        .iter()
                        .any(|value| value.eq_ignore_ascii_case(class))
                })
            {
                MailRuleCondition::MessageType(MailRuleMessageType {
                    kind: MailRuleMessageKind::Voicemail,
                })
            } else if test.header == AUTO_SUBMITTED_HEADER
                && test.operator == MailRuleTextOperator::Matches
                && matches!(test.values.as_slice(), [value] if value == AUTO_SUBMITTED_PATTERN)
            {
                MailRuleCondition::MessageType(MailRuleMessageType {
                    kind: MailRuleMessageKind::AutomaticReply,
                })
            } else {
                MailRuleCondition::Header(test)
            }
        }
        MailRuleCondition::HeaderExists(mut header) => {
            canonicalize_header_name(&mut header.header)?;
            MailRuleCondition::HeaderExists(header)
        }
        MailRuleCondition::AttachmentName(mut test) => {
            canonicalize_values(&mut test.values)?;
            MailRuleCondition::AttachmentName(test)
        }
        MailRuleCondition::AttachmentType(mut test) => {
            canonicalize_values(&mut test.values)?;
            MailRuleCondition::AttachmentType(test)
        }
        MailRuleCondition::RecipientAddress(mut test) => {
            canonicalize_address_test(&mut test.operator, &mut test.values)?;
            MailRuleCondition::RecipientAddress(test)
        }
        MailRuleCondition::RecipientDetail(mut test) => {
            canonicalize_values(&mut test.values)?;
            MailRuleCondition::RecipientDetail(test)
        }
        MailRuleCondition::SubjectOrBody(mut test) => {
            canonicalize_values(&mut test.values)?;
            MailRuleCondition::SubjectOrBody(test)
        }
        MailRuleCondition::ReceivedAfter(date) | MailRuleCondition::ReceivedBefore(date)
            if !(0..=MAX_TIMESTAMP).contains(&date.date.timestamp()) =>
        {
            return Err(RuleError::InvalidDate(date.date.timestamp()));
        }
        MailRuleCondition::Schedule(mut schedule) => {
            canonicalize_schedule(&mut schedule)?;
            MailRuleCondition::Schedule(schedule)
        }
        MailRuleCondition::SizeOver(size) | MailRuleCondition::SizeUnder(size)
            if size.kilobytes == 0 || size.kilobytes > MAX_SIZE_KB =>
        {
            return Err(RuleError::InvalidSize(size.kilobytes));
        }
        MailRuleCondition::Keyword(mut test) => {
            canonicalize_keywords(&mut test.keywords)?;
            if test.keywords.is_empty() {
                return Err(RuleError::Empty("keywords"));
            }
            MailRuleCondition::Keyword(test)
        }
        condition => condition,
    })
}

fn canonicalize_actions(actions: &mut MailRuleActions) -> Result<(), RuleError> {
    let MailRuleActions {
        add_keywords,
        remove_keywords,
        clear_keywords,
        set_importance,
        redirect,
        reply,
        copy_to,
        move_to,
        discard,
        reject,
        stop_processing,
    } = actions;
    canonicalize_keywords(add_keywords)?;
    canonicalize_keywords(remove_keywords)?;
    if let Some(keyword) = remove_keywords
        .iter()
        .find(|keyword| add_keywords.contains(keyword))
    {
        return Err(RuleError::ConflictingKeyword(keyword.clone()));
    }
    if let Some(redirect) = redirect {
        canonicalize_values(&mut redirect.addresses)?;
        check_address_lengths(&redirect.addresses)?;
        if redirect.addresses.is_empty() {
            return Err(RuleError::Empty("redirect addresses"));
        }
    }
    if let Some(subject) = reply.as_mut().and_then(|reply| reply.subject.as_mut()) {
        canonicalize_line(subject, "reply subject")?;
    }
    canonicalize_mailboxes(copy_to)?;
    canonicalize_mailboxes(move_to)?;
    move_to
        .inner_mut()
        .sort_by_key(|id| id.document_id() == JUNK_ID);

    let has_other_action = *clear_keywords
        || !add_keywords.is_empty()
        || !remove_keywords.is_empty()
        || set_importance.is_some()
        || redirect.is_some()
        || reply.is_some()
        || !copy_to.is_empty()
        || !move_to.is_empty()
        || *discard;
    if let Some(reject) = reject {
        if has_other_action {
            return Err(RuleError::RejectNotAlone);
        }
        canonicalize_line(&mut reject.reason, "reject reason")?;
        *stop_processing = true;
    } else if !has_other_action && !*stop_processing {
        return Err(RuleError::Empty("actions"));
    }
    Ok(())
}

fn canonicalize_set<T: MapItem>(
    set: &mut Map<T>,
    mut canonicalize: impl FnMut(T) -> Result<T, RuleError>,
) -> Result<(), RuleError> {
    let items = std::mem::take(set.inner_mut());
    set.inner_mut().reserve_exact(items.len());
    for item in items {
        set.push(canonicalize(item)?);
    }
    Ok(())
}

fn canonicalize_mailboxes(mailboxes: &mut Map<Id>) -> Result<(), RuleError> {
    canonicalize_set(mailboxes, |id| Ok(Id::from(id.document_id())))
}

fn canonicalize_keywords(keywords: &mut Map<String>) -> Result<(), RuleError> {
    canonicalize_set(keywords, canonical_keyword)
}

pub fn canonical_keyword(mut keyword: String) -> Result<String, RuleError> {
    strip_line_breaks(&mut keyword);
    match Keyword::try_parse(&keyword) {
        Some(system) if keyword != system.as_str() => Ok(system.as_str().to_string()),
        Some(_) => Ok(keyword),
        None if Keyword::is_valid_jmap_name(&keyword) => {
            keyword.make_ascii_lowercase();
            Ok(keyword)
        }
        None => Err(RuleError::InvalidKeyword(keyword)),
    }
}

pub(crate) fn is_custom_keyword(keyword: &str) -> bool {
    Keyword::try_parse(keyword).is_none()
}

fn canonicalize_schedule(schedule: &mut MailRuleSchedule) -> Result<(), RuleError> {
    if schedule.slots.is_empty() {
        return Err(RuleError::Empty("schedule slots"));
    }
    if schedule.slots.len() > MAX_SCHEDULE_SLOTS {
        return Err(RuleError::InvalidSchedule);
    }
    schedule.slots = std::mem::take(&mut schedule.slots).into_iter().collect();
    for slot in schedule.slots.values_mut() {
        let days = slot.days.inner_mut();
        days.sort_unstable_by_key(EnumImpl::to_id);
        days.dedup();
        if days.is_empty() {
            return Err(RuleError::Empty("schedule days"));
        }
        if slot.end.minutes() == 0 {
            slot.end = LocalTime::from_minutes(MINUTES_PER_DAY);
        }
        let (start, end) = (slot.start.minutes(), slot.end.minutes());
        if start >= MINUTES_PER_DAY || end > MINUTES_PER_DAY || start == end {
            return Err(RuleError::InvalidSchedule);
        }
    }
    Ok(())
}

fn canonicalize_header_name(header: &mut String) -> Result<(), RuleError> {
    header.make_ascii_lowercase();
    if !header.is_empty()
        && header
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(RuleError::InvalidHeaderName(std::mem::take(header)))
    }
}

fn canonicalize_address_test(
    operator: &mut MailRuleAddressOperator,
    values: &mut Map<String>,
) -> Result<(), RuleError> {
    canonicalize_values(values)?;
    check_address_lengths(values)?;
    if *operator == MailRuleAddressOperator::Domain {
        canonicalize_set(values, |domain| {
            let domain = domain.trim().trim_start_matches('@').to_ascii_lowercase();
            validate_domain(&domain)?;
            Ok(domain)
        })?;
    }
    Ok(())
}

fn check_address_lengths(values: &Map<String>) -> Result<(), RuleError> {
    if values
        .iter()
        .all(|value| value.len() <= MAX_ADDRESS_VALUE_LEN)
    {
        Ok(())
    } else {
        Err(RuleError::AddressTooLong)
    }
}

pub fn active_redirects(rule: &MailRule) -> Option<&MailRuleRedirect> {
    rule.actions.redirect.as_ref().filter(|_| rule.is_enabled)
}

pub fn is_same_redirects(
    left: Option<&MailRuleRedirect>,
    right: Option<&MailRuleRedirect>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => {
            left.keep_copy == right.keep_copy
                && is_same_addresses(left.addresses.as_slice(), right.addresses.as_slice())
        }
        (left, right) => left.is_none() && right.is_none(),
    }
}

pub fn is_same_addresses(left: &[String], right: &[String]) -> bool {
    let covers = |outer: &[String], inner: &[String]| {
        inner.iter().all(|address| {
            outer
                .iter()
                .any(|other| other.eq_ignore_ascii_case(address))
        })
    };
    left.len() == right.len() && covers(left, right) && covers(right, left)
}

pub(crate) fn sensitivity_level(value: &str) -> Option<MailRuleSensitivityLevel> {
    hashify::map!(
        value.as_bytes(),
        MailRuleSensitivityLevel,
        "personal" => MailRuleSensitivityLevel::Personal,
        "private" => MailRuleSensitivityLevel::Private,
        "company-confidential" => MailRuleSensitivityLevel::Confidential,
    )
    .copied()
}

fn canonicalize_values(values: &mut Map<String>) -> Result<(), RuleError> {
    canonicalize_set(values, |mut value| {
        strip_line_breaks(&mut value);
        if value.is_empty() {
            Err(RuleError::Empty("values"))
        } else {
            Ok(value)
        }
    })
}

fn canonicalize_line(value: &mut String, what: &'static str) -> Result<(), RuleError> {
    if value.contains(['\r', '\n']) {
        strip_line_breaks(value);
        if value.is_empty() {
            return Err(RuleError::Empty(what));
        }
    }
    Ok(())
}

fn strip_line_breaks(value: &mut String) {
    if value.contains(['\r', '\n']) {
        value.retain(|ch| !matches!(ch, '\r' | '\n'));
    }
}

fn validate_list_entry(entry: &str) -> Result<(), RuleError> {
    let is_valid = !entry.contains(|ch: char| ch.is_whitespace() || ch.is_control())
        && match entry.strip_prefix('@') {
            Some(domain) => validate_domain(domain).is_ok(),
            None => entry
                .rsplit_once('@')
                .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty()),
        };
    if is_valid {
        Ok(())
    } else {
        Err(RuleError::InvalidEntry(entry.to_string()))
    }
}

fn validate_domain(domain: &str) -> Result<(), RuleError> {
    if !domain.is_empty()
        && !domain
            .bytes()
            .any(|ch| matches!(ch, b'*' | b'?' | b'\\' | b'@') || ch.is_ascii_whitespace())
    {
        Ok(())
    } else {
        Err(RuleError::InvalidDomain(domain.to_string()))
    }
}

impl Display for RuleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::InvalidEntry(entry) => write!(
                f,
                "Invalid entry {entry:?}: use an email address or a domain written as @example.org."
            ),
            RuleError::InvalidHeaderName(name) => write!(f, "Invalid header name {name:?}."),
            RuleError::InvalidKeyword(keyword) => write!(f, "Invalid keyword {keyword:?}."),
            RuleError::ConflictingKeyword(keyword) => write!(
                f,
                "The keyword {keyword:?} cannot be both added and removed."
            ),
            RuleError::InvalidDomain(domain) => write!(f, "Invalid domain {domain:?}."),
            RuleError::AddressTooLong => write!(
                f,
                "An address value is too long: use at most {MAX_ADDRESS_VALUE_LEN} bytes."
            ),
            RuleError::InvalidSize(size) => {
                write!(f, "Invalid size {size}: use 1 to {MAX_SIZE_KB} kilobytes.")
            }
            RuleError::InvalidDate(timestamp) => {
                write!(
                    f,
                    "Invalid date {timestamp}: use a date between 1970 and 3000."
                )
            }
            RuleError::InvalidSchedule => write!(
                f,
                "Invalid schedule: use at most {MAX_SCHEDULE_SLOTS} slots per condition, each starting before 24:00 and ending at a different time."
            ),
            RuleError::RejectNotAlone => {
                write!(f, "A rule that rejects mail cannot have other actions.")
            }
            RuleError::EntryExists(_) => write!(f, "The entry is already in the list."),
            RuleError::EntryIdTaken => write!(
                f,
                "The entry cannot be added because its identifier is taken, remove a similar entry first."
            ),
            RuleError::TooManyEntries => {
                write!(
                    f,
                    "The list cannot have more than {MAX_SENDER_ENTRIES} entries."
                )
            }
            RuleError::NotFound(id) => write!(f, "Rule {id} not found."),
            RuleError::Empty(what) => write!(f, "The rule {what} must not be empty."),
            RuleError::Compile(err) => write!(f, "The rules script failed to compile: {err}."),
            RuleError::Decode(err) => write!(f, "The rules cannot be stored: {err}."),
            RuleError::TooManyInstructions {
                instructions,
                limit,
            } => write!(
                f,
                "The rules script has {instructions} instructions, above the limit of {limit} (maxCpuCycles)."
            ),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/email/src/sieve/rules/tests/mod.rs"]
mod tests;
