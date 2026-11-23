/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::sidecar::StoredRedirect;
use email::{mailbox::TRASH_ID, sieve::rules::MAX_TIMESTAMP};
use exchange_proto::convert::category::is_category_keyword;
use exchange_proto::rules::{
    Action, AddressField, DelegateRule, Level, MAX_STRING_LEN, MAX_VALUES, ManagedRule, MeKind,
    MessageKind, Predicate, RedirectKind, RuleLogic, RuleState, SensitivityLevel, ServerReply,
    TextField,
};
use registry::{
    schema::{
        enums::{
            MailRuleAddressOperator, MailRuleImportanceLevel, MailRuleMessageKind,
            MailRuleSensitivityLevel, MailRuleSentToMePlacement, MailRuleTextOperator,
        },
        structs::{
            MailRule, MailRuleActions, MailRuleAddressTest, MailRuleCondition, MailRuleConditions,
            MailRuleDate, MailRuleHeaderName, MailRuleImportance, MailRuleKeywordTest,
            MailRuleMessageType, MailRuleRedirect, MailRuleReply, MailRuleSensitivity,
            MailRuleSentToMe, MailRuleSize, MailRuleTextTest,
        },
    },
    types::{
        datetime::UTCDateTime,
        list::List,
        map::{Map, MapItem},
    },
};
use std::{iter, mem};
use store::blake3;
use types::{id::Id, keyword::Keyword};

pub(crate) const DELEGATE_RULE_NAME: &str = "Delegate Rule";
pub(crate) const FORWARDED_BY_HEADER: &str = "X-Forwarded-By";
const MAX_MAPPED_ITEMS: usize = 2 * MAX_VALUES;
const REDIRECT_KINDS: [RedirectKind; 3] = [
    RedirectKind::Forward,
    RedirectKind::ForwardAsAttachment,
    RedirectKind::Redirect,
];
const DELEGATE_KINDS: [MailRuleMessageKind; 3] = [
    MailRuleMessageKind::MeetingRequest,
    MailRuleMessageKind::MeetingResponse,
    MailRuleMessageKind::MeetingCancellation,
];

pub(crate) fn can_map(logic: &RuleLogic) -> bool {
    logic.conditions.iter().all(can_be_condition)
        && logic.exceptions.iter().all(can_be_exception)
        && logic
            .exceptions
            .iter()
            .filter(|predicate| {
                matches!(
                    predicate,
                    Predicate::Size {
                        min_kb: Some(1..),
                        max_kb: Some(_),
                    }
                )
            })
            .count()
            <= 1
}

pub(crate) fn can_be_condition(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::Size { max_kb, .. } => *max_kb != Some(0),
        _ => has_core_date(predicate),
    }
}

pub(crate) fn can_be_exception(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::Size {
            min_kb: None | Some(0),
            max_kb: None,
        } => false,
        _ => has_core_date(predicate),
    }
}

fn has_core_date(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::ReceivedAfter(at) | Predicate::ReceivedBefore(at) => *at <= MAX_TIMESTAMP,
        _ => true,
    }
}

pub(crate) fn mail_rule(rule: &ManagedRule, logic: &RuleLogic) -> MailRule {
    let mut mail_rule = rule_header(rule);
    let conditions = &mut mail_rule.conditions;
    for predicate in &logic.conditions {
        push_condition(conditions, predicate);
    }
    for predicate in &logic.exceptions {
        push_exception(conditions, predicate);
    }

    let actions = &mut mail_rule.actions;
    if logic.actions.contains(&Action::MarkAsRead) {
        actions
            .add_keywords
            .push_unchecked(Keyword::Seen.as_str().to_string());
    }
    let mut to_trash = false;
    for action in &logic.actions {
        match action {
            Action::Move {
                mailbox_id: TRASH_ID,
            }
            | Action::Delete => to_trash = true,
            Action::Move { mailbox_id } => {
                push_bounded(&mut actions.move_to, &Id::from(*mailbox_id))
            }
            Action::Copy { mailbox_id } => {
                push_bounded(&mut actions.copy_to, &Id::from(*mailbox_id))
            }
            Action::PermanentDelete => {
                actions.discard = true;
                actions.stop_processing = true;
            }
            Action::SetImportance(level) => actions.set_importance = Some(core_level(*level)),
            Action::AssignCategories(keywords) => {
                for keyword in keywords {
                    push_bounded(&mut actions.add_keywords, keyword);
                }
            }
            Action::ServerReply(reply) if actions.reply.is_none() => {
                actions.reply = Some(MailRuleReply {
                    subject: reply.subject.clone(),
                    text_body: reply.text_body.clone(),
                    html_body: reply.html_body.clone(),
                    days: 0,
                })
            }
            Action::MarkAsRead | Action::Redirect { .. } | Action::ServerReply(_) => {}
        }
    }
    if to_trash {
        push_bounded(&mut actions.move_to, &Id::from(TRASH_ID));
    }
    let mut addresses = Map::default();
    for kind in REDIRECT_KINDS {
        for action in &logic.actions {
            if let Action::Redirect {
                kind: action_kind,
                addresses: values,
            } = action
                && *action_kind == kind
            {
                for address in values {
                    push_bounded(&mut addresses, address);
                }
            }
        }
    }
    if !addresses.is_empty() {
        actions.redirect = Some(MailRuleRedirect {
            addresses,
            keep_copy: true,
        });
    }
    mail_rule
}

fn push_bounded<T: MapItem + Clone>(set: &mut Map<T>, item: &T) {
    if set.len() <= MAX_MAPPED_ITEMS && !set.contains(item) {
        set.push_unchecked(item.clone());
    }
}

fn push_condition(conditions: &mut MailRuleConditions, predicate: &Predicate) {
    let all = &mut conditions.match_all;
    match *predicate {
        Predicate::Size { min_kb, max_kb } => {
            if let Some(min) = min_kb.filter(|kb| *kb > 0) {
                all.push(MailRuleCondition::SizeOver(size(min)));
            }
            if let Some(max) = max_kb {
                all.push(MailRuleCondition::SizeUnder(size(max)));
            }
        }
        _ => {
            if let Some(condition) = condition(predicate) {
                all.push(condition);
            }
        }
    }
}

fn push_exception(conditions: &mut MailRuleConditions, predicate: &Predicate) {
    let MailRuleConditions {
        match_any,
        match_none,
        ..
    } = conditions;
    match *predicate {
        Predicate::Size { min_kb, max_kb } => match (min_kb.filter(|kb| *kb > 0), max_kb) {
            (None, Some(0)) => {}
            (None, Some(max)) => match_none.push(MailRuleCondition::SizeUnder(size(max))),
            (Some(min), None) => match_none.push(MailRuleCondition::SizeOver(size(min))),
            (Some(min), Some(max)) if match_any.is_empty() => {
                match_any.push(MailRuleCondition::SizeUnder(size(min)));
                match_any.push(MailRuleCondition::SizeOver(size(max)));
            }
            _ => match_none.push(MailRuleCondition::SizeOver(size(0))),
        },
        _ => {
            if let Some(condition) = condition(predicate) {
                match_none.push(condition);
            }
        }
    }
}

fn size(kilobytes: u32) -> MailRuleSize {
    MailRuleSize {
        kilobytes: kilobytes.into(),
    }
}

pub(crate) fn delegate_mail_rule(rule: &ManagedRule, delegate: &DelegateRule) -> MailRule {
    let mut mail_rule = rule_header(rule);
    mail_rule.name = DELEGATE_RULE_NAME.to_string();
    mail_rule.conditions.match_any = DELEGATE_KINDS
        .into_iter()
        .map(|kind| MailRuleCondition::MessageType(MailRuleMessageType { kind }))
        .collect();
    mail_rule.conditions.match_none = List::from(vec![
        MailRuleCondition::PrivateEvent,
        MailRuleCondition::Sensitivity(MailRuleSensitivity {
            level: MailRuleSensitivityLevel::Private,
        }),
        MailRuleCondition::HeaderExists(MailRuleHeaderName {
            header: FORWARDED_BY_HEADER.to_string(),
        }),
    ]);
    let actions = &mut mail_rule.actions;
    actions.redirect = Some(MailRuleRedirect {
        addresses: delegate
            .forwards()
            .iter()
            .map(|recipient| recipient.address.clone())
            .collect::<Vec<_>>()
            .into(),
        keep_copy: true,
    });
    if delegate.deletes_own_copy() {
        actions.move_to.push_unchecked(Id::from(TRASH_ID));
        actions.stop_processing = true;
    }
    mail_rule
}

pub(crate) fn with_header(current: &MailRule, rule: &ManagedRule) -> MailRule {
    let mut conditions = current.conditions.clone();
    let away = rule.state.is_oof_only();
    if away != is_away(&conditions) {
        let all = mem::take(&mut conditions.match_all).into_iter();
        conditions.match_all = if away {
            iter::once(MailRuleCondition::IsAway).chain(all).collect()
        } else {
            if is_only_away(&conditions.match_any) {
                conditions.match_any = List::default();
            }
            all.filter(|condition| !matches!(condition, MailRuleCondition::IsAway))
                .collect()
        };
    }
    let current_actions = &current.actions;
    MailRule {
        name: truncated_name(&rule.name),
        is_enabled: rule.state.is_enabled(),
        position: position(rule),
        conditions,
        actions: MailRuleActions {
            stop_processing: rule.state.has(RuleState::EXIT_LEVEL)
                || (current_actions.discard && current_actions.stop_processing),
            ..current_actions.clone()
        },
    }
}

fn rule_header(rule: &ManagedRule) -> MailRule {
    MailRule {
        name: truncated_name(&rule.name),
        is_enabled: rule.state.is_enabled(),
        position: position(rule),
        conditions: MailRuleConditions {
            match_all: rule
                .state
                .is_oof_only()
                .then_some(MailRuleCondition::IsAway)
                .into_iter()
                .collect(),
            ..Default::default()
        },
        actions: MailRuleActions {
            stop_processing: rule.state.has(RuleState::EXIT_LEVEL),
            ..Default::default()
        },
    }
}

fn position(rule: &ManagedRule) -> u64 {
    u64::try_from(rule.sequence).unwrap_or(0)
}

fn is_away(conditions: &MailRuleConditions) -> bool {
    conditions
        .match_all
        .iter()
        .any(|condition| matches!(condition, MailRuleCondition::IsAway))
        || is_only_away(&conditions.match_any)
}

fn is_only_away(conditions: &List<MailRuleCondition>) -> bool {
    conditions.len() == 1
        && conditions
            .iter()
            .all(|condition| matches!(condition, MailRuleCondition::IsAway))
}

fn truncated_name(name: &str) -> String {
    let name = name.trim();
    if name.len() <= MAX_STRING_LEN {
        return name.to_string();
    }
    let mut end = MAX_STRING_LEN;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name.get(..end).unwrap_or_default().trim_end().to_string()
}

fn condition(predicate: &Predicate) -> Option<MailRuleCondition> {
    Some(match predicate {
        Predicate::Text { field, values } => {
            let text = || MailRuleTextTest {
                operator: MailRuleTextOperator::Contains,
                values: Map::new(values.clone()),
            };
            let address = || MailRuleAddressTest {
                operator: MailRuleAddressOperator::Contains,
                values: Map::new(values.clone()),
            };
            match field {
                TextField::Subject => MailRuleCondition::Subject(text()),
                TextField::Body => MailRuleCondition::Body(text()),
                TextField::SubjectOrBody => MailRuleCondition::SubjectOrBody(text()),
                TextField::Sender => MailRuleCondition::From(address()),
                TextField::Recipient => MailRuleCondition::ToOrCc(address()),
            }
        }
        Predicate::Address { field, values } => {
            let test = MailRuleAddressTest {
                operator: MailRuleAddressOperator::Is,
                values: Map::new(values.clone()),
            };
            match field {
                AddressField::From => MailRuleCondition::From(test),
                AddressField::SentTo => MailRuleCondition::ToOrCc(test),
            }
        }
        Predicate::Me(kind) => MailRuleCondition::SentToMe(MailRuleSentToMe {
            placement: match kind {
                MeKind::To => MailRuleSentToMePlacement::To,
                MeKind::Cc => MailRuleSentToMePlacement::Cc,
                MeKind::ToOrCc => MailRuleSentToMePlacement::ToOrCc,
                MeKind::NotTo => MailRuleSentToMePlacement::NotTo,
                MeKind::OnlyTo => MailRuleSentToMePlacement::OnlyTo,
            },
        }),
        Predicate::Importance(level) => MailRuleCondition::Importance(MailRuleImportance {
            level: core_level(*level),
        }),
        Predicate::Sensitivity(level) => MailRuleCondition::Sensitivity(MailRuleSensitivity {
            level: match level {
                SensitivityLevel::Normal => MailRuleSensitivityLevel::Normal,
                SensitivityLevel::Personal => MailRuleSensitivityLevel::Personal,
                SensitivityLevel::Private => MailRuleSensitivityLevel::Private,
                SensitivityLevel::Confidential => MailRuleSensitivityLevel::Confidential,
            },
        }),
        Predicate::HasAttachments => MailRuleCondition::HasAttachment,
        Predicate::Size { .. } => return None,
        Predicate::Flagged => MailRuleCondition::Flagged,
        Predicate::Categories(keywords) => MailRuleCondition::Keyword(MailRuleKeywordTest {
            keywords: Map::new(keywords.clone()),
        }),
        Predicate::MessageType(kind) => MailRuleCondition::MessageType(MailRuleMessageType {
            kind: match kind {
                MessageKind::MeetingRequest => MailRuleMessageKind::MeetingRequest,
                MessageKind::MeetingResponse => MailRuleMessageKind::MeetingResponse,
                MessageKind::NonDeliveryReport => MailRuleMessageKind::NonDeliveryReport,
                MessageKind::ReadReceipt => MailRuleMessageKind::ReadReceipt,
                MessageKind::AutomaticReply => MailRuleMessageKind::AutomaticReply,
                MessageKind::AutomaticForward => MailRuleMessageKind::AutomaticForward,
                MessageKind::Signed => MailRuleMessageKind::Signed,
                MessageKind::Encrypted => MailRuleMessageKind::Encrypted,
                MessageKind::Voicemail => MailRuleMessageKind::Voicemail,
            },
        }),
        Predicate::ReceivedAfter(at) => MailRuleCondition::ReceivedAfter(MailRuleDate {
            date: UTCDateTime::from_timestamp(*at),
        }),
        Predicate::ReceivedBefore(at) => MailRuleCondition::ReceivedBefore(MailRuleDate {
            date: UTCDateTime::from_timestamp(*at),
        }),
    })
}

const fn core_level(level: Level) -> MailRuleImportanceLevel {
    match level {
        Level::Low => MailRuleImportanceLevel::Low,
        Level::Normal => MailRuleImportanceLevel::Normal,
        Level::High => MailRuleImportanceLevel::High,
    }
}

const fn exchange_level(level: MailRuleImportanceLevel) -> Level {
    match level {
        MailRuleImportanceLevel::Low => Level::Low,
        MailRuleImportanceLevel::Normal => Level::Normal,
        MailRuleImportanceLevel::High => Level::High,
    }
}

pub(crate) fn rule_logic(
    rule: &MailRule,
    redirects: &[StoredRedirect],
    reply_template: Option<&str>,
) -> Option<RuleLogic> {
    let MailRuleConditions {
        match_all,
        match_any,
        match_none,
    } = &rule.conditions;
    let mut conditions = match_all
        .iter()
        .filter(|condition| !matches!(condition, MailRuleCondition::IsAway))
        .map(predicate)
        .collect::<Option<Vec<_>>>()?;
    let mut exceptions = match_none
        .iter()
        .map(predicate)
        .collect::<Option<Vec<_>>>()?;
    let mut any = match_any.iter();
    match (any.next(), any.next(), any.next()) {
        (None, ..) | (Some(MailRuleCondition::IsAway), None, _) => {}
        (Some(only), None, _) => conditions.push(predicate(only)?),
        (
            Some(MailRuleCondition::SizeUnder(under)),
            Some(MailRuleCondition::SizeOver(over)),
            None,
        ) => exceptions.push(Predicate::Size {
            min_kb: Some(u32::try_from(under.kilobytes).ok()?),
            max_kb: Some(u32::try_from(over.kilobytes).ok()?),
        }),
        _ => return None,
    }
    merge_size_range(&mut conditions);
    let logic = RuleLogic {
        conditions,
        exceptions,
        actions: logic_actions(&rule.actions, redirects, reply_template)?,
    };
    logic.is_valid().then_some(logic)
}

fn merge_size_range(conditions: &mut Vec<Predicate>) {
    let mut sizes = conditions.iter().filter_map(|predicate| match *predicate {
        Predicate::Size { min_kb, max_kb } => Some((min_kb, max_kb)),
        _ => None,
    });
    let range = match (sizes.next(), sizes.next(), sizes.next()) {
        (Some((Some(min), None)), Some((None, Some(max))), None)
        | (Some((None, Some(max))), Some((Some(min), None)), None)
            if min <= max =>
        {
            Predicate::Size {
                min_kb: Some(min),
                max_kb: Some(max),
            }
        }
        _ => return,
    };
    let mut range = Some(range);
    conditions.retain_mut(|predicate| match predicate {
        Predicate::Size { .. } => match range.take() {
            Some(range) => {
                *predicate = range;
                true
            }
            None => false,
        },
        _ => true,
    });
}

fn logic_actions(
    core: &MailRuleActions,
    redirects: &[StoredRedirect],
    reply_template: Option<&str>,
) -> Option<Vec<Action>> {
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
        stop_processing: _,
    } = core;
    if *clear_keywords || !remove_keywords.is_empty() || reject.is_some() {
        return None;
    }
    let mut actions = Vec::new();
    let seen = Keyword::Seen;
    let seen = seen.as_str();
    if add_keywords.iter().any(|keyword| keyword == seen) {
        actions.push(Action::MarkAsRead);
    }
    for keyword in add_keywords.iter().filter(|keyword| *keyword != seen) {
        if !is_category_keyword(keyword) {
            return None;
        }
        match actions.last_mut() {
            Some(Action::AssignCategories(block)) if block.len() < MAX_VALUES => {
                block.push(keyword.clone())
            }
            _ => actions.push(Action::AssignCategories(vec![keyword.clone()])),
        }
    }
    if let Some(level) = set_importance {
        actions.push(Action::SetImportance(exchange_level(*level)));
    }
    if let Some(redirect) = redirect {
        if !redirect.keep_copy {
            return None;
        }
        push_redirects(&mut actions, redirect.addresses.as_slice(), redirects);
    }
    if let Some(reply) = reply {
        if reply.days != 0 {
            return None;
        }
        actions.push(Action::ServerReply(Box::new(ServerReply {
            template: reply_template?.to_string(),
            subject: reply.subject.clone(),
            text_body: reply.text_body.clone(),
            html_body: reply.html_body.clone(),
        })));
    }
    actions.extend(copy_to.iter().map(|id| Action::Copy {
        mailbox_id: id.document_id(),
    }));
    actions.extend(move_to.iter().map(|id| match id.document_id() {
        TRASH_ID => Action::Delete,
        mailbox_id => Action::Move { mailbox_id },
    }));
    if *discard {
        actions.push(Action::PermanentDelete);
    }
    Some(actions)
}

fn push_redirects(actions: &mut Vec<Action>, addresses: &[String], redirects: &[StoredRedirect]) {
    let start = actions.len();
    for address in addresses {
        let kind = redirects
            .iter()
            .find(|redirect| redirect.address.eq_ignore_ascii_case(address))
            .map_or(RedirectKind::Forward, |redirect| redirect.kind());
        let block = actions
            .iter_mut()
            .skip(start)
            .find_map(|action| match action {
                Action::Redirect {
                    kind: block_kind,
                    addresses,
                } if *block_kind == kind => Some(addresses),
                _ => None,
            });
        match block {
            Some(block) => block.push(address.clone()),
            None => actions.push(Action::Redirect {
                kind,
                addresses: vec![address.clone()],
            }),
        }
    }
}

fn predicate(condition: &MailRuleCondition) -> Option<Predicate> {
    Some(match condition {
        MailRuleCondition::Subject(test) => text(TextField::Subject, test)?,
        MailRuleCondition::Body(test) => text(TextField::Body, test)?,
        MailRuleCondition::SubjectOrBody(test) => text(TextField::SubjectOrBody, test)?,
        MailRuleCondition::From(test) => address(TextField::Sender, AddressField::From, test)?,
        MailRuleCondition::ToOrCc(test) => {
            address(TextField::Recipient, AddressField::SentTo, test)?
        }
        MailRuleCondition::SentToMe(sent_to_me) => Predicate::Me(match sent_to_me.placement {
            MailRuleSentToMePlacement::To => MeKind::To,
            MailRuleSentToMePlacement::Cc => MeKind::Cc,
            MailRuleSentToMePlacement::ToOrCc => MeKind::ToOrCc,
            MailRuleSentToMePlacement::NotTo => MeKind::NotTo,
            MailRuleSentToMePlacement::OnlyTo => MeKind::OnlyTo,
        }),
        MailRuleCondition::Importance(importance) => {
            Predicate::Importance(exchange_level(importance.level))
        }
        MailRuleCondition::Sensitivity(sensitivity) => {
            Predicate::Sensitivity(match sensitivity.level {
                MailRuleSensitivityLevel::Normal => SensitivityLevel::Normal,
                MailRuleSensitivityLevel::Personal => SensitivityLevel::Personal,
                MailRuleSensitivityLevel::Private => SensitivityLevel::Private,
                MailRuleSensitivityLevel::Confidential => SensitivityLevel::Confidential,
            })
        }
        MailRuleCondition::HasAttachment => Predicate::HasAttachments,
        MailRuleCondition::SizeOver(size) => Predicate::Size {
            min_kb: Some(u32::try_from(size.kilobytes).ok()?),
            max_kb: None,
        },
        MailRuleCondition::SizeUnder(size) => Predicate::Size {
            min_kb: None,
            max_kb: Some(u32::try_from(size.kilobytes).ok()?),
        },
        MailRuleCondition::Flagged => Predicate::Flagged,
        MailRuleCondition::Keyword(test)
            if test
                .keywords
                .iter()
                .all(|keyword| is_category_keyword(keyword)) =>
        {
            Predicate::Categories(test.keywords.as_slice().to_vec())
        }
        MailRuleCondition::MessageType(message_type) => {
            Predicate::MessageType(match message_type.kind {
                MailRuleMessageKind::MeetingRequest => MessageKind::MeetingRequest,
                MailRuleMessageKind::MeetingResponse => MessageKind::MeetingResponse,
                MailRuleMessageKind::NonDeliveryReport => MessageKind::NonDeliveryReport,
                MailRuleMessageKind::ReadReceipt => MessageKind::ReadReceipt,
                MailRuleMessageKind::AutomaticReply => MessageKind::AutomaticReply,
                MailRuleMessageKind::AutomaticForward => MessageKind::AutomaticForward,
                MailRuleMessageKind::Signed => MessageKind::Signed,
                MailRuleMessageKind::Encrypted => MessageKind::Encrypted,
                MailRuleMessageKind::Voicemail => MessageKind::Voicemail,
                MailRuleMessageKind::MeetingCancellation => return None,
            })
        }
        MailRuleCondition::ReceivedAfter(date) => Predicate::ReceivedAfter(date.date.timestamp()),
        MailRuleCondition::ReceivedBefore(date) => Predicate::ReceivedBefore(date.date.timestamp()),
        _ => return None,
    })
}

fn text(field: TextField, test: &MailRuleTextTest) -> Option<Predicate> {
    (test.operator == MailRuleTextOperator::Contains).then(|| Predicate::Text {
        field,
        values: test.values.as_slice().to_vec(),
    })
}

fn address(contains: TextField, is: AddressField, test: &MailRuleAddressTest) -> Option<Predicate> {
    let values = test.values.as_slice().to_vec();
    match test.operator {
        MailRuleAddressOperator::Contains => Some(Predicate::Text {
            field: contains,
            values,
        }),
        MailRuleAddressOperator::Is => Some(Predicate::Address { field: is, values }),
        MailRuleAddressOperator::Domain | MailRuleAddressOperator::Matches => None,
    }
}

pub(crate) fn rule_hash(rule: &MailRule) -> u64 {
    let mut hasher = blake3::Hasher::new();
    let normalized = MailRule {
        is_enabled: false,
        position: 0,
        ..rule.clone()
    };
    if serde_json::to_writer(&mut hasher, &normalized).is_err() {
        return 0;
    }
    hasher
        .finalize()
        .as_bytes()
        .first_chunk()
        .map_or(0, |bytes| u64::from_be_bytes(*bytes))
}

pub(crate) fn rule_state(rule: &MailRule, stored: u32) -> RuleState {
    let current = RuleState(stored).stored();
    let state = current
        .with(RuleState::EXIT_LEVEL, rule.actions.stop_processing)
        .with_oof_only(is_away(&rule.conditions));
    if rule.is_enabled && !current.is_enabled() {
        state
            .with(RuleState::OOF_DISABLED, false)
            .with(RuleState::ENABLED, true)
    } else {
        state.with_enabled(rule.is_enabled)
    }
}

pub(crate) fn rule_sequence(rule: &MailRule) -> i32 {
    i32::try_from(rule.position).unwrap_or(i32::MAX)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/rules/map/tests.rs"]
mod tests;
