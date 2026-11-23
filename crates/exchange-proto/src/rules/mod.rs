/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/rules/tests.rs"]
mod tests;

use std::ops::RangeInclusive;

pub const MAX_VALUES: usize = 64;
pub const MAX_STRING_LEN: usize = 255;
pub const MAX_ADDRESS_LEN: usize = 320;
pub const STORED_ID_BASE: u64 = 1 << 62;
pub const RECEIVED_SECONDS: RangeInclusive<i64> = 0..=253_402_300_799;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuleState(pub u32);

impl RuleState {
    pub const ENABLED: u32 = 0x01;
    pub const ERROR: u32 = 0x02;
    pub const ONLY_WHEN_OOF: u32 = 0x04;
    pub const KEEP_OOF_HIST: u32 = 0x08;
    pub const EXIT_LEVEL: u32 = 0x10;
    pub const SKIP_IF_SCL_IS_SAFE: u32 = 0x20;
    pub const PARSE_ERROR: u32 = 0x40;
    pub const OOF_DISABLED: u32 = 0x80;
    pub const ONLY_WHEN_OOF_EX: u32 = 0x100;
    const OOF_ONLY: u32 = Self::ONLY_WHEN_OOF | Self::ONLY_WHEN_OOF_EX;
    const SERVER_SET: u32 = Self::ERROR | Self::PARSE_ERROR;

    pub const fn stored(self) -> Self {
        RuleState(self.0 & !Self::SERVER_SET)
    }

    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub const fn with(self, flag: u32, set: bool) -> Self {
        if set {
            RuleState(self.0 | flag)
        } else {
            RuleState(self.0 & !flag)
        }
    }

    pub const fn is_oof_only(self) -> bool {
        self.has(Self::OOF_ONLY)
    }

    pub const fn with_oof_only(self, oof_only: bool) -> Self {
        if oof_only {
            self.with(Self::ONLY_WHEN_OOF, true)
        } else {
            self.with(Self::OOF_ONLY, false)
        }
    }

    pub const fn is_enabled(self) -> bool {
        if self.is_oof_only() {
            !self.has(Self::OOF_DISABLED)
        } else {
            self.has(Self::ENABLED)
        }
    }

    pub const fn with_enabled(self, enabled: bool) -> Self {
        if !enabled {
            self.with(Self::ENABLED, false)
                .with(Self::OOF_DISABLED, self.is_oof_only())
        } else if self.is_enabled() {
            self
        } else {
            self.with(Self::OOF_DISABLED, false)
                .with(Self::ENABLED, true)
        }
    }

    pub const fn runs(self) -> bool {
        self.is_enabled() && !self.is_oof_only()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    pub next_id: u64,
    pub rules: Vec<ManagedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRule {
    pub id: RuleId,
    pub sequence: i32,
    pub state: RuleState,
    pub name: String,
    pub body: RuleBody,
    pub mapi: Option<Box<MapiRule>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapiRule {
    pub provider: Box<str>,
    pub provider_data: Box<[u8]>,
    pub user_flags: u32,
    pub level: u32,
    pub condition: Box<[u8]>,
    pub actions: Box<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleBody {
    Logic(RuleLogic),
    Delegate(DelegateRule),
    StoredOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateRule {
    pub mode: DeliverMode,
    pub recipients: Vec<DelegateRecipient>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegateRecipient {
    pub principal_id: u32,
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliverMode {
    #[default]
    DelegatesOnly,
    DelegatesAndMe,
    DelegatesAndSendInformationToMe,
    NoForward,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleLogic {
    pub conditions: Vec<Predicate>,
    pub exceptions: Vec<Predicate>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Text {
        field: TextField,
        values: Vec<String>,
    },
    Address {
        field: AddressField,
        values: Vec<String>,
    },
    Me(MeKind),
    Importance(Level),
    Sensitivity(SensitivityLevel),
    HasAttachments,
    Size {
        min_kb: Option<u32>,
        max_kb: Option<u32>,
    },
    Flagged,
    Categories(Vec<String>),
    MessageType(MessageKind),
    ReceivedAfter(i64),
    ReceivedBefore(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    MeetingRequest,
    MeetingResponse,
    NonDeliveryReport,
    ReadReceipt,
    AutomaticReply,
    AutomaticForward,
    Signed,
    Encrypted,
    Voicemail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextField {
    Subject,
    Body,
    SubjectOrBody,
    Sender,
    Recipient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressField {
    From,
    SentTo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeKind {
    To,
    Cc,
    ToOrCc,
    NotTo,
    OnlyTo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitivityLevel {
    Normal,
    Personal,
    Private,
    Confidential,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Move {
        mailbox_id: u32,
    },
    Copy {
        mailbox_id: u32,
    },
    Delete,
    PermanentDelete,
    MarkAsRead,
    SetImportance(Level),
    AssignCategories(Vec<String>),
    Redirect {
        kind: RedirectKind,
        addresses: Vec<String>,
    },
    ServerReply(Box<ServerReply>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerReply {
    pub template: String,
    pub subject: Option<String>,
    pub text_body: String,
    pub html_body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    Forward,
    ForwardAsAttachment,
    Redirect,
}

impl RuleSet {
    pub fn new() -> Self {
        RuleSet {
            next_id: 1,
            rules: Vec::new(),
        }
    }

    pub fn allocate_id(&mut self) -> Option<RuleId> {
        let id = self.next_id.max(1);
        self.next_id = id.checked_add(1)?;
        Some(RuleId(id))
    }

    pub fn position(&self, id: RuleId) -> Option<usize> {
        self.rules.iter().position(|rule| rule.id == id)
    }

    pub fn remove(&mut self, index: usize) -> Option<ManagedRule> {
        (index < self.rules.len()).then(|| self.rules.remove(index))
    }

    pub fn sort(&mut self) {
        self.rules.sort_by_key(|rule| (rule.sequence, rule.id));
    }

    pub fn renumber(&mut self) {
        for (sequence, rule) in (1..)
            .map(|n: i32| n.saturating_mul(10))
            .zip(&mut self.rules)
        {
            rule.sequence = sequence;
        }
    }

    pub fn delegate(&self) -> Option<(usize, &ManagedRule, &DelegateRule)> {
        self.rules
            .iter()
            .enumerate()
            .find_map(|(index, rule)| match &rule.body {
                RuleBody::Delegate(delegate) => Some((index, rule, delegate)),
                _ => None,
            })
    }
}

impl RuleLogic {
    pub fn is_valid(&self) -> bool {
        self.conditions
            .iter()
            .chain(&self.exceptions)
            .all(Predicate::is_valid)
            && self.actions.iter().all(Action::is_valid)
            && self.received_bounds_are_valid()
    }

    fn received_bounds_are_valid(&self) -> bool {
        let count = |predicates: &[Predicate], after: bool| {
            predicates
                .iter()
                .filter(|predicate| match predicate {
                    Predicate::ReceivedAfter(_) => after,
                    Predicate::ReceivedBefore(_) => !after,
                    _ => false,
                })
                .count()
        };
        count(&self.conditions, true) <= 1
            && count(&self.conditions, false) <= 1
            && count(&self.exceptions, true).saturating_add(count(&self.exceptions, false)) <= 1
            && match Self::received_range(&self.conditions) {
                (Some(after), Some(before)) => after <= before,
                _ => true,
            }
    }

    pub fn received_range(predicates: &[Predicate]) -> (Option<i64>, Option<i64>) {
        predicates
            .iter()
            .fold((None, None), |(after, before), predicate| match predicate {
                Predicate::ReceivedAfter(at) => (Some(*at), before),
                Predicate::ReceivedBefore(at) => (after, Some(*at)),
                _ => (after, before),
            })
    }
}

impl DelegateRule {
    pub fn forwards(&self) -> &[DelegateRecipient] {
        match self.mode {
            DeliverMode::NoForward => &[],
            DeliverMode::DelegatesOnly
            | DeliverMode::DelegatesAndMe
            | DeliverMode::DelegatesAndSendInformationToMe => &self.recipients,
        }
    }

    pub fn has_recipient(&self, principal_id: u32) -> bool {
        self.recipients
            .iter()
            .any(|recipient| recipient.principal_id == principal_id)
    }

    pub fn deletes_own_copy(&self) -> bool {
        self.mode == DeliverMode::DelegatesOnly && !self.forwards().is_empty()
    }

    pub fn is_valid(&self) -> bool {
        self.recipients.len() <= MAX_VALUES
            && self
                .recipients
                .iter()
                .all(|recipient| is_valid_address(&recipient.address))
    }
}

impl Predicate {
    pub fn is_valid(&self) -> bool {
        match self {
            Predicate::Text { values, .. } => is_valid_list(values, is_valid_text),
            Predicate::Address { values, .. } => is_valid_list(values, is_valid_address),
            Predicate::Size { min_kb, max_kb } => match (min_kb, max_kb) {
                (None, None) => false,
                (Some(min), Some(max)) => min <= max,
                _ => true,
            },
            Predicate::Categories(keywords) => is_valid_list(keywords, is_valid_text),
            Predicate::Me(_)
            | Predicate::Importance(_)
            | Predicate::Sensitivity(_)
            | Predicate::HasAttachments
            | Predicate::Flagged
            | Predicate::MessageType(_) => true,
            Predicate::ReceivedAfter(seconds) | Predicate::ReceivedBefore(seconds) => {
                RECEIVED_SECONDS.contains(seconds)
            }
        }
    }
}

impl Action {
    pub fn is_valid(&self) -> bool {
        match self {
            Action::AssignCategories(keywords) => is_valid_list(keywords, is_valid_text),
            Action::Redirect { addresses, .. } => is_valid_list(addresses, is_valid_address),
            Action::ServerReply(reply) => {
                !reply.template.is_empty()
                    && reply.template.len() <= MAX_STRING_LEN
                    && reply.subject.as_deref().is_none_or(is_valid_text)
            }
            Action::Move { .. }
            | Action::Copy { .. }
            | Action::Delete
            | Action::PermanentDelete
            | Action::MarkAsRead
            | Action::SetImportance(_) => true,
        }
    }
}

pub fn is_valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_STRING_LEN && !value.contains(['\r', '\n'])
}

pub fn is_valid_address(value: &str) -> bool {
    value.len() <= MAX_ADDRESS_LEN
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
        && !value.contains(['\r', '\n', '"', ' ', ','])
}

fn is_valid_list(values: &[String], is_valid: fn(&str) -> bool) -> bool {
    (1..=MAX_VALUES).contains(&values.len()) && values.iter().all(|value| is_valid(value))
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}
