/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MapiLimits,
    prop::{CountWidth, PropTag, PropType, PropValue, codec::write_str_utf16, decode_value, tags},
    restriction::{self, RelOp, Restriction, RestrictionBytes, RestrictionNode},
    rule::{
        ActionBlock, ActionType, ForwardFlavor, RuleActions, RuleActionsWriter, SMTP_ADDRESS_TYPE,
    },
};
use crate::{
    common::LeReader,
    rules::{
        Action, AddressField, DelegateRule, Level, MeKind, MessageKind, Predicate, RedirectKind,
        RuleLogic, SensitivityLevel, TextField,
    },
};
use std::{borrow::Cow, slice};

mod message;
mod people;

pub use message::RuleNames;

const FUZZY_SUBSTRING_IGNORECASE: u32 = 0x0001_0001;
const BITMASK_NOT_ZERO: u8 = 0x01;
const MSGFLAG_HASATTACH: u32 = 0x10;
const KB: u32 = 1024;
const MAX_DEPTH: u8 = 8;
const EX_ADDRESS_TYPE: &str = "EX";
const FUZZY_PREFIX: u32 = 0x0000_0002;
const DELEGATED_BY_RULE: PropTag = PropTag(0x3FE3_000B);
const MEETING_CLASS_PREFIX: &str = "IPM.Schedule.Meeting";
const SENSITIVITY_PRIVATE: i32 = 2;
const DELEGATE_CONDITIONS: u16 = 3;
const SENSITIVITY_CLAUSES: u16 = 2;
const DELEGATE_CONDITION_LEN: usize = 96;
pub const DELEGATE_PROVIDER: &str = "Schedule+ EMS Interface";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedRule {
    pub conditions: Vec<MappedPredicate>,
    pub exceptions: Vec<MappedPredicate>,
    pub actions: Vec<MappedAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedPredicate {
    Ready(Predicate),
    Address {
        field: AddressField,
        recipients: Vec<RuleRecipient>,
    },
    Me(MeKind),
    Categories(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedAction {
    File {
        copy: bool,
        folder_id: u64,
    },
    Ready(Action),
    Redirect {
        kind: RedirectKind,
        recipients: Vec<RuleRecipient>,
    },
    AssignCategories(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleRecipient {
    Smtp(String),
    Directory(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFolder {
    Mailbox(u32),
    Trash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedDelegate {
    pub recipients: Vec<RuleRecipient>,
    pub deletes_own_copy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedRule {
    pub condition: Vec<u8>,
    pub actions: Vec<u8>,
}

impl MappedRule {
    pub fn decode(condition: &[u8], actions: &[u8], names: &RuleNames) -> Option<Self> {
        let (conditions, exceptions) = decode_conditions(condition, names)?;
        let actions = RuleActions::parse(actions)
            .ok()?
            .iter()
            .map(|block| decode_action(&block, names))
            .collect::<Option<Vec<_>>>()?;
        Some(MappedRule {
            conditions,
            exceptions,
            actions,
        })
    }
}

impl MappedDelegate {
    pub fn decode(actions: &[u8]) -> Option<Self> {
        let mut recipients = Vec::new();
        let mut deletes_own_copy = false;
        let blocks = RuleActions::parse(actions).ok()?;
        if blocks.is_empty() {
            return None;
        }
        for block in blocks.iter() {
            match (block.kind?, block.flavor, block.flags) {
                (ActionType::Delegate, 0, 0) => recipients.extend(self::recipients(&block)?),
                (ActionType::Delete, 0, 0) if block.data.is_empty() && !deletes_own_copy => {
                    deletes_own_copy = true
                }
                _ => return None,
            }
        }
        Some(MappedDelegate {
            recipients,
            deletes_own_copy,
        })
    }
}

impl EncodedRule {
    pub fn delegate(rule: &DelegateRule) -> Option<Self> {
        let mut condition = Vec::with_capacity(DELEGATE_CONDITION_LEN);
        condition.push(restriction::AND);
        condition.extend_from_slice(&DELEGATE_CONDITIONS.to_le_bytes());
        condition.push(restriction::CONTENT);
        condition.extend_from_slice(&FUZZY_PREFIX.to_le_bytes());
        condition.extend_from_slice(&tags::MESSAGE_CLASS.0.to_le_bytes());
        condition.extend_from_slice(&tags::MESSAGE_CLASS.0.to_le_bytes());
        write_str_utf16(&mut condition, MEETING_CLASS_PREFIX);
        condition.push(restriction::NOT);
        condition.push(restriction::EXIST);
        condition.extend_from_slice(&DELEGATED_BY_RULE.0.to_le_bytes());
        condition.push(restriction::OR);
        condition.extend_from_slice(&SENSITIVITY_CLAUSES.to_le_bytes());
        condition.push(restriction::NOT);
        condition.push(restriction::EXIST);
        condition.extend_from_slice(&tags::SENSITIVITY.0.to_le_bytes());
        encode_property(
            &mut condition,
            RelOp::Ne,
            tags::SENSITIVITY,
            SENSITIVITY_PRIVATE,
        );
        let forwards = rule.forwards();
        if forwards.is_empty() && !rule.deletes_own_copy() {
            return None;
        }
        let mut writer = RuleActionsWriter::new();
        if !forwards.is_empty() {
            writer.forward_smtp(
                ActionType::Delegate,
                ForwardFlavor(0),
                forwards.iter().map(|recipient| recipient.address.as_str()),
            );
        }
        if rule.deletes_own_copy() {
            writer.simple(ActionType::Delete);
        }
        Some(EncodedRule {
            condition,
            actions: writer.finish()?,
        })
    }

    pub fn encode<'x>(
        logic: &'x RuleLogic,
        names: &RuleNames,
        folder_id: impl Fn(RuleFolder) -> Option<u64>,
        category: impl Fn(&'x str) -> Cow<'x, str>,
    ) -> Option<Self> {
        let encoder = Encoder {
            names,
            category: &category,
        };
        let mut condition = Vec::new();
        encoder.conditions(logic, &mut condition)?;
        let mut writer = RuleActionsWriter::new();
        for action in &logic.actions {
            match action {
                Action::Move { mailbox_id, .. } => writer.move_to(
                    ActionType::Move,
                    folder_id(RuleFolder::Mailbox(*mailbox_id))?,
                ),
                Action::Copy { mailbox_id, .. } => writer.move_to(
                    ActionType::Copy,
                    folder_id(RuleFolder::Mailbox(*mailbox_id))?,
                ),
                Action::Delete => writer.move_to(ActionType::Move, folder_id(RuleFolder::Trash)?),
                Action::PermanentDelete => writer.simple(ActionType::Delete),
                Action::MarkAsRead => writer.simple(ActionType::MarkAsRead),
                Action::SetImportance(level) => {
                    writer.tag_i32(tags::IMPORTANCE, importance_value(*level))
                }
                Action::AssignCategories(keywords) => writer.tag_strings(
                    names.keywords_tag()?,
                    keywords.iter().map(|keyword| category(keyword)),
                ),
                Action::Redirect { kind, addresses } => writer.forward_smtp(
                    ActionType::Forward,
                    forward_flavor(*kind),
                    addresses.iter().map(String::as_str),
                ),
                Action::ServerReply(_) => return None,
            }
        }
        Some(EncodedRule {
            condition,
            actions: writer.finish()?,
        })
    }
}

fn decode_conditions(
    bytes: &[u8],
    names: &RuleNames,
) -> Option<(Vec<MappedPredicate>, Vec<MappedPredicate>)> {
    let Some(tree) = RestrictionBytes(bytes)
        .decode(CountWidth::Rop, false, MAX_DEPTH)
        .ok()?
    else {
        return Some((Vec::new(), Vec::new()));
    };
    let top = match tree.nodes.get(usize::from(tree.root))? {
        RestrictionNode::And(range) => {
            let children = tree
                .children
                .get(usize::from(range.start)..usize::from(range.end))?;
            if people::composite(&tree, tree.root).is_none() && !message::is_ndr(&tree, children) {
                children
            } else {
                slice::from_ref(&tree.root)
            }
        }
        _ => slice::from_ref(&tree.root),
    };
    let mut conditions = Vec::with_capacity(top.len());
    let mut exceptions = Vec::new();
    let mut size = SizeBounds::default();
    for &index in top {
        match tree.nodes.get(usize::from(index))? {
            RestrictionNode::Property { op, tag, value } if tag.id() == tags::MESSAGE_SIZE.id() => {
                size.add(*op, value)?
            }
            RestrictionNode::Not(child) => exceptions.extend(exception_list(&tree, *child, names)?),
            _ => conditions.push(predicate(&tree, index, names)?),
        }
    }
    if let Some(predicate) = size.predicate() {
        conditions.push(MappedPredicate::Ready(predicate));
    }
    Some((conditions, exceptions))
}

#[derive(Default)]
struct SizeBounds {
    min_kb: Option<u32>,
    max_kb: Option<u32>,
}

impl SizeBounds {
    fn add(&mut self, op: RelOp, value: &PropValue<'_>) -> Option<()> {
        let PropValue::I32(bytes) = value else {
            return None;
        };
        let bytes = u32::try_from(*bytes).ok()?;
        if !bytes.is_multiple_of(KB) {
            return None;
        }
        let slot = match op {
            RelOp::Ge => &mut self.min_kb,
            RelOp::Le => &mut self.max_kb,
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(bytes.checked_div(KB)?);
        Some(())
    }

    fn predicate(self) -> Option<Predicate> {
        (self.min_kb.is_some() || self.max_kb.is_some()).then_some(Predicate::Size {
            min_kb: self.min_kb,
            max_kb: self.max_kb,
        })
    }
}

fn exception_list(
    tree: &Restriction<'_>,
    index: u16,
    names: &RuleNames,
) -> Option<Vec<MappedPredicate>> {
    if let Some(predicate) = predicate(tree, index, names) {
        return Some(vec![predicate]);
    }
    let RestrictionNode::Or(range) = tree.nodes.get(usize::from(index))? else {
        return None;
    };
    tree.children
        .get(usize::from(range.start)..usize::from(range.end))?
        .iter()
        .map(|child| predicate(tree, *child, names))
        .collect()
}

fn predicate(tree: &Restriction<'_>, index: u16, names: &RuleNames) -> Option<MappedPredicate> {
    let node = tree.nodes.get(usize::from(index))?;
    match node {
        RestrictionNode::Content { .. } => text(tree, slice::from_ref(&index)),
        RestrictionNode::Or(range) => {
            let children = tree
                .children
                .get(usize::from(range.start)..usize::from(range.end))?;
            if let Some(predicate) =
                message::decode_classes(tree, children).or_else(|| text(tree, children))
            {
                return Some(MappedPredicate::Ready(predicate));
            }
            return match categories(tree, children, names) {
                Some(categories) => Some(MappedPredicate::Categories(categories)),
                None => people::decode(tree, index),
            };
        }
        RestrictionNode::And(range)
            if message::is_ndr(
                tree,
                tree.children
                    .get(usize::from(range.start)..usize::from(range.end))?,
            ) =>
        {
            Some(Predicate::MessageType(MessageKind::NonDeliveryReport))
        }
        RestrictionNode::Property {
            op: RelOp::Eq,
            tag,
            value: PropValue::I32(value),
        } if tag.id() == tags::IMPORTANCE.id() || tag.id() == tags::SENSITIVITY.id() => {
            if tag.id() == tags::IMPORTANCE.id() {
                importance_level(*value).map(Predicate::Importance)
            } else {
                Some(Predicate::Sensitivity(match value {
                    0 => SensitivityLevel::Normal,
                    1 => SensitivityLevel::Personal,
                    2 => SensitivityLevel::Private,
                    3 => SensitivityLevel::Confidential,
                    _ => return None,
                }))
            }
        }
        RestrictionNode::Property { op, tag, value } => {
            if let Some(predicate) = message::decode_property(names, *op, *tag, value) {
                return Some(MappedPredicate::Ready(predicate));
            }
            return match message::category(names, node) {
                Some(category) => Some(MappedPredicate::Categories(vec![category])),
                None => people::decode(tree, index),
            };
        }
        RestrictionNode::Bitmask {
            all_set: true,
            tag,
            mask: MSGFLAG_HASATTACH,
        } if tag.id() == tags::MESSAGE_FLAGS.id() => Some(Predicate::HasAttachments),
        _ => return people::decode(tree, index),
    }
    .map(MappedPredicate::Ready)
}

fn categories(tree: &Restriction<'_>, indexes: &[u16], names: &RuleNames) -> Option<Vec<String>> {
    indexes
        .iter()
        .map(|index| message::category(names, tree.nodes.get(usize::from(*index))?))
        .collect()
}

fn text(tree: &Restriction<'_>, indexes: &[u16]) -> Option<Predicate> {
    let mut subjects = Vec::new();
    let mut bodies = Vec::new();
    for index in indexes {
        let RestrictionNode::Content {
            fuzzy: FUZZY_SUBSTRING_IGNORECASE,
            tag,
            value,
        } = tree.nodes.get(usize::from(*index))?
        else {
            return None;
        };
        let target = if tag.id() == tags::SUBJECT.id() {
            &mut subjects
        } else if tag.id() == tags::BODY.id() {
            &mut bodies
        } else {
            return None;
        };
        target.push(string_value(value)?);
    }
    let (field, values) = match (subjects.is_empty(), bodies.is_empty()) {
        (false, true) => (TextField::Subject, subjects),
        (true, false) => (TextField::Body, bodies),
        (false, false) if subjects == bodies => (TextField::SubjectOrBody, subjects),
        _ => return None,
    };
    Some(Predicate::Text { field, values })
}

fn string_value(value: &PropValue<'_>) -> Option<String> {
    let value = match value {
        PropValue::Unicode(text) => {
            let mut out = String::new();
            text.to_string_lossy(&mut out);
            out
        }
        PropValue::String8(bytes) => std::str::from_utf8(bytes).ok()?.to_string(),
        _ => return None,
    };
    (!value.is_empty()).then_some(value)
}

fn decode_action(block: &ActionBlock<'_>, names: &RuleNames) -> Option<MappedAction> {
    if block.flags != 0 {
        return None;
    }
    match (block.kind?, block.flavor) {
        (kind @ (ActionType::Move | ActionType::Copy), 0) => Some(MappedAction::File {
            copy: kind == ActionType::Copy,
            folder_id: block.folder_id()?,
        }),
        (ActionType::Delete, 0) if block.data.is_empty() => {
            Some(MappedAction::Ready(Action::PermanentDelete))
        }
        (ActionType::MarkAsRead, 0) if block.data.is_empty() => {
            Some(MappedAction::Ready(Action::MarkAsRead))
        }
        (ActionType::Tag, 0) => {
            let (tag, value) = block.data.split_first_chunk::<4>()?;
            let tag = PropTag(u32::from_le_bytes(*tag));
            if tag == tags::IMPORTANCE {
                let value = <[u8; 4]>::try_from(value).ok()?;
                Some(MappedAction::Ready(Action::SetImportance(
                    importance_level(i32::from_le_bytes(value))?,
                )))
            } else if Some(tag) == names.keywords_tag() {
                assigned_categories(value).map(MappedAction::AssignCategories)
            } else {
                None
            }
        }
        (ActionType::Forward, flavor) => Some(MappedAction::Redirect {
            kind: redirect_kind(ForwardFlavor(flavor))?,
            recipients: recipients(block)?,
        }),
        _ => None,
    }
}

fn assigned_categories(bytes: &[u8]) -> Option<Vec<String>> {
    let mut r = LeReader::new(bytes);
    let PropValue::Mv(view) = decode_value(
        &mut r,
        PropType::MvUnicode,
        CountWidth::Rop,
        &MapiLimits::DEFAULT,
    )
    .ok()?
    else {
        return None;
    };
    if !r.is_empty() || view.count() == 0 {
        return None;
    }
    view.iter().map(|value| string_value(&value)).collect()
}

fn redirect_kind(flavor: ForwardFlavor) -> Option<RedirectKind> {
    const REDIRECT: u32 = ForwardFlavor::PRESERVE_SENDER | ForwardFlavor::DO_NOT_MUNGE;
    match flavor.0 {
        0 => Some(RedirectKind::Forward),
        ForwardFlavor::AS_ATTACHMENT => Some(RedirectKind::ForwardAsAttachment),
        REDIRECT => Some(RedirectKind::Redirect),
        _ => None,
    }
}

fn forward_flavor(kind: RedirectKind) -> ForwardFlavor {
    ForwardFlavor(match kind {
        RedirectKind::Forward => 0,
        RedirectKind::ForwardAsAttachment => ForwardFlavor::AS_ATTACHMENT,
        RedirectKind::Redirect => ForwardFlavor::PRESERVE_SENDER | ForwardFlavor::DO_NOT_MUNGE,
    })
}

fn recipients(block: &ActionBlock<'_>) -> Option<Vec<RuleRecipient>> {
    let blocks = block.recipients(&MapiLimits::DEFAULT).ok()?;
    if blocks.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(blocks.len());
    for properties in blocks.iter() {
        let mut smtp = None;
        let mut address_type = None;
        let mut address = None;
        for (tag, value) in properties.iter() {
            let target = if tag.id() == tags::SMTP_ADDRESS.id() {
                &mut smtp
            } else if tag.id() == tags::ADDRESS_TYPE.id() {
                &mut address_type
            } else if tag.id() == tags::EMAIL_ADDRESS.id() {
                &mut address
            } else {
                continue;
            };
            *target = string_value(&value);
        }
        out.push(match (smtp, address_type, address) {
            (Some(smtp), _, _) => RuleRecipient::Smtp(smtp),
            (None, Some(kind), Some(address)) if kind.eq_ignore_ascii_case(SMTP_ADDRESS_TYPE) => {
                RuleRecipient::Smtp(address)
            }
            (None, kind, Some(address))
                if address.starts_with('/')
                    && kind
                        .as_deref()
                        .is_none_or(|kind| kind.eq_ignore_ascii_case(EX_ADDRESS_TYPE)) =>
            {
                RuleRecipient::Directory(address)
            }
            _ => return None,
        });
    }
    (out.len() == blocks.len()).then_some(out)
}

struct Encoder<'e, 'x> {
    names: &'e RuleNames,
    category: &'e dyn Fn(&'x str) -> Cow<'x, str>,
}

impl<'x> Encoder<'_, 'x> {
    fn conditions(&self, logic: &'x RuleLogic, out: &mut Vec<u8>) -> Option<()> {
        let mut size = None;
        let mut items = 0usize;
        for predicate in &logic.conditions {
            match predicate {
                Predicate::Size { min_kb, max_kb } => {
                    if size.replace((*min_kb, *max_kb)).is_some() {
                        return None;
                    }
                    items = items
                        .saturating_add(usize::from(min_kb.is_some()))
                        .saturating_add(usize::from(max_kb.is_some()));
                }
                _ => items = items.saturating_add(1),
            }
        }
        items = items.saturating_add(usize::from(!logic.exceptions.is_empty()));
        if items != 1 {
            out.push(restriction::AND);
            out.extend_from_slice(&u16::try_from(items).ok()?.to_le_bytes());
        }
        for predicate in &logic.conditions {
            if !matches!(predicate, Predicate::Size { .. }) {
                self.predicate(predicate, out)?;
            }
        }
        if let Some((min_kb, max_kb)) = size {
            for (op, kb) in [(RelOp::Ge, min_kb), (RelOp::Le, max_kb)] {
                if let Some(kb) = kb {
                    let bytes = i32::try_from(kb.checked_mul(KB)?).ok()?;
                    encode_property(out, op, tags::MESSAGE_SIZE, bytes);
                }
            }
        }
        if let Some((first, rest)) = logic.exceptions.split_first() {
            out.push(restriction::NOT);
            if rest.is_empty() {
                self.predicate(first, out)?;
            } else {
                out.push(restriction::OR);
                out.extend_from_slice(&u16::try_from(logic.exceptions.len()).ok()?.to_le_bytes());
                for predicate in &logic.exceptions {
                    self.predicate(predicate, out)?;
                }
            }
        }
        Some(())
    }

    fn predicate(&self, predicate: &'x Predicate, out: &mut Vec<u8>) -> Option<()> {
        match predicate {
            Predicate::Text { field, values } => {
                let fields: &[PropTag] = match field {
                    TextField::Subject => &[tags::SUBJECT],
                    TextField::Body => &[tags::BODY],
                    TextField::SubjectOrBody => &[tags::SUBJECT, tags::BODY],
                    TextField::Sender | TextField::Recipient => return None,
                };
                let count = values.len().checked_mul(fields.len())?;
                match count {
                    0 => return None,
                    1 => {}
                    _ => {
                        out.push(restriction::OR);
                        out.extend_from_slice(&u16::try_from(count).ok()?.to_le_bytes());
                    }
                }
                for value in values {
                    for tag in fields {
                        out.push(restriction::CONTENT);
                        out.extend_from_slice(&FUZZY_SUBSTRING_IGNORECASE.to_le_bytes());
                        out.extend_from_slice(&tag.0.to_le_bytes());
                        out.extend_from_slice(&tag.0.to_le_bytes());
                        write_str_utf16(out, value);
                    }
                }
            }
            Predicate::Importance(level) => {
                encode_property(out, RelOp::Eq, tags::IMPORTANCE, importance_value(*level))
            }
            Predicate::Sensitivity(level) => encode_property(
                out,
                RelOp::Eq,
                tags::SENSITIVITY,
                match level {
                    SensitivityLevel::Normal => 0,
                    SensitivityLevel::Personal => 1,
                    SensitivityLevel::Private => 2,
                    SensitivityLevel::Confidential => 3,
                },
            ),
            Predicate::HasAttachments => {
                out.push(restriction::BITMASK);
                out.push(BITMASK_NOT_ZERO);
                out.extend_from_slice(&tags::MESSAGE_FLAGS.0.to_le_bytes());
                out.extend_from_slice(&MSGFLAG_HASATTACH.to_le_bytes());
            }
            Predicate::Address { .. } | Predicate::Me(_) => return people::encode(predicate, out),
            Predicate::Flagged => message::encode_flagged(out),
            Predicate::Categories(keywords) => {
                return message::encode_categories(
                    self.names,
                    keywords.iter().map(|keyword| (self.category)(keyword)),
                    out,
                );
            }
            Predicate::MessageType(kind) => return message::encode_kind(self.names, *kind, out),
            Predicate::ReceivedAfter(seconds) => message::encode_received(out, RelOp::Gt, *seconds),
            Predicate::ReceivedBefore(seconds) => {
                message::encode_received(out, RelOp::Lt, *seconds)
            }
            Predicate::Size { .. } => return None,
        }
        Some(())
    }
}

fn importance_level(value: i32) -> Option<Level> {
    match value {
        0 => Some(Level::Low),
        1 => Some(Level::Normal),
        2 => Some(Level::High),
        _ => None,
    }
}

const fn importance_value(level: Level) -> i32 {
    match level {
        Level::Low => 0,
        Level::Normal => 1,
        Level::High => 2,
    }
}

fn encode_property(out: &mut Vec<u8>, op: RelOp, tag: PropTag, value: i32) {
    out.push(restriction::PROPERTY);
    out.push(op.to_wire());
    out.extend_from_slice(&tag.0.to_le_bytes());
    out.extend_from_slice(&tag.0.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rule_logic/tests.rs"]
mod tests;
