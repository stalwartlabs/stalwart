/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MappedPredicate, RuleRecipient};
use crate::{
    mapi::{
        prop::{PropTag, PropValue, codec::write_str_utf16, tags},
        recipient::{one_off, smtp_search_key},
        restriction::{self, RelOp, Restriction, RestrictionNode},
        rule::SMTP_ADDRESS_TYPE,
    },
    rules::{AddressField, MeKind, Predicate},
};
use std::{slice, str};

const COMMENT_MARKER: PropTag = PropTag(0x6000_0003);
const ANY_BINARY: PropTag = PropTag(0x0001_0102);
const ANY_UNICODE: PropTag = PropTag(0x0001_001F);
const COMMENT_VALUES: u8 = 4;
const COMMENT_MARKER_VALUE: i32 = 1;
const DT_MAILUSER: i32 = 0;
const RESTRICTION_PRESENT: u8 = 1;
const FUZZY_SUBSTRING: u32 = 0x0000_0001;
const RECIPIENT_SEPARATOR: &str = ";";
const COMPOSITE_CLAUSES: u16 = 3;
const CC_ME: [(PropTag, bool); 3] = [
    (tags::MESSAGE_CC_ME, true),
    (tags::MESSAGE_RECIP_ME, true),
    (tags::MESSAGE_TO_ME, false),
];

pub(super) fn decode(tree: &Restriction<'_>, index: u16) -> Option<MappedPredicate> {
    match tree.nodes.get(usize::from(index))? {
        RestrictionNode::Sub { tag, child } if tag.id() == tags::MESSAGE_RECIPIENTS.id() => {
            addresses(tree, *child, AddressField::SentTo)
        }
        RestrictionNode::Comment { .. } | RestrictionNode::Or(_) => {
            addresses(tree, index, AddressField::From)
        }
        RestrictionNode::Property { .. } => match flag(tree, index)? {
            (tag, true) if tag.id() == tags::MESSAGE_TO_ME.id() => Some(MeKind::To),
            (tag, false) if tag.id() == tags::MESSAGE_TO_ME.id() => Some(MeKind::NotTo),
            (tag, true) if tag.id() == tags::MESSAGE_RECIP_ME.id() => Some(MeKind::ToOrCc),
            (tag, true) if tag.id() == tags::MESSAGE_CC_ME.id() => Some(MeKind::Cc),
            _ => None,
        }
        .map(MappedPredicate::Me),
        RestrictionNode::And(_) => composite(tree, index).map(MappedPredicate::Me),
        _ => None,
    }
}

pub(super) fn composite(tree: &Restriction<'_>, index: u16) -> Option<MeKind> {
    let RestrictionNode::And(range) = tree.nodes.get(usize::from(index))? else {
        return None;
    };
    let [first, second, third] = tree
        .children
        .get(usize::from(range.start)..usize::from(range.end))?
    else {
        return None;
    };
    if [*first, *second, *third]
        .into_iter()
        .zip(CC_ME)
        .all(|(index, (tag, value))| {
            flag(tree, index).is_some_and(|(found, set)| found.id() == tag.id() && set == value)
        })
    {
        return Some(MeKind::Cc);
    }
    let to_me = flag(tree, *first)
        .is_some_and(|(tag, value)| tag.id() == tags::MESSAGE_TO_ME.id() && value);
    let single_to = matches!(
        tree.nodes.get(usize::from(*second)),
        Some(RestrictionNode::Not(child)) if matches!(
            tree.nodes.get(usize::from(*child)),
            Some(RestrictionNode::Content {
                fuzzy: FUZZY_SUBSTRING,
                tag,
                value: PropValue::Unicode(value),
            }) if tag.id() == tags::DISPLAY_TO.id() && value.eq_ignore_ascii_case(RECIPIENT_SEPARATOR)
        )
    );
    let no_cc = matches!(
        tree.nodes.get(usize::from(*third)),
        Some(RestrictionNode::Property {
            op: RelOp::Eq,
            tag,
            value: PropValue::Unicode(value),
        }) if tag.id() == tags::DISPLAY_CC.id() && value.is_empty()
    );
    (to_me && single_to && no_cc).then_some(MeKind::OnlyTo)
}

fn flag(tree: &Restriction<'_>, index: u16) -> Option<(PropTag, bool)> {
    match tree.nodes.get(usize::from(index))? {
        RestrictionNode::Property {
            op: RelOp::Eq,
            tag,
            value: PropValue::Bool(value),
        } => Some((*tag, *value)),
        _ => None,
    }
}

fn addresses(tree: &Restriction<'_>, index: u16, field: AddressField) -> Option<MappedPredicate> {
    let indexes = match tree.nodes.get(usize::from(index))? {
        RestrictionNode::Or(range) => tree
            .children
            .get(usize::from(range.start)..usize::from(range.end))?,
        _ => slice::from_ref(&index),
    };
    let key = search_key_tag(field);
    let recipients = indexes
        .iter()
        .map(|index| recipient(tree, *index, key))
        .collect::<Option<Vec<_>>>()?;
    (!recipients.is_empty()).then_some(MappedPredicate::Address { field, recipients })
}

fn recipient(tree: &Restriction<'_>, index: u16, key: PropTag) -> Option<RuleRecipient> {
    let index = match tree.nodes.get(usize::from(index))? {
        RestrictionNode::Comment {
            child: Some(child), ..
        } => *child,
        _ => index,
    };
    let RestrictionNode::Property {
        op: RelOp::Eq,
        tag,
        value: PropValue::Binary(bytes),
    } = tree.nodes.get(usize::from(index))?
    else {
        return None;
    };
    if tag.id() != key.id() {
        return None;
    }
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let (kind, value) = str::from_utf8(bytes).ok()?.split_once(':')?;
    if value.is_empty() {
        return None;
    }
    hashify::fnc_map_ignore_case!(kind.as_bytes(),
        "EX" => { return Some(RuleRecipient::Directory(value.to_string())); },
        "SMTP" => { return Some(RuleRecipient::Smtp(value.to_ascii_lowercase())); },
        _ => {}
    );
    None
}

fn search_key_tag(field: AddressField) -> PropTag {
    match field {
        AddressField::From => tags::SENDER_SEARCH_KEY,
        AddressField::SentTo => tags::SEARCH_KEY,
    }
}

pub(super) fn encode(predicate: &Predicate, out: &mut Vec<u8>) -> Option<()> {
    match predicate {
        Predicate::Address { field, values } => {
            if values.is_empty() {
                return None;
            }
            if *field == AddressField::SentTo {
                out.push(restriction::SUB);
                out.extend_from_slice(&tags::MESSAGE_RECIPIENTS.0.to_le_bytes());
            }
            match values.len() {
                1 => {}
                count => {
                    out.push(restriction::OR);
                    out.extend_from_slice(&u16::try_from(count).ok()?.to_le_bytes());
                }
            }
            let key = search_key_tag(*field);
            for address in values {
                encode_person(out, key, address)?;
            }
            Some(())
        }
        Predicate::Me(kind) => {
            match kind {
                MeKind::To => encode_flag(out, tags::MESSAGE_TO_ME, true),
                MeKind::NotTo => encode_flag(out, tags::MESSAGE_TO_ME, false),
                MeKind::ToOrCc => encode_flag(out, tags::MESSAGE_RECIP_ME, true),
                MeKind::Cc => {
                    out.push(restriction::AND);
                    out.extend_from_slice(&COMPOSITE_CLAUSES.to_le_bytes());
                    for (tag, value) in CC_ME {
                        encode_flag(out, tag, value);
                    }
                }
                MeKind::OnlyTo => {
                    out.push(restriction::AND);
                    out.extend_from_slice(&COMPOSITE_CLAUSES.to_le_bytes());
                    encode_flag(out, tags::MESSAGE_TO_ME, true);
                    out.push(restriction::NOT);
                    out.push(restriction::CONTENT);
                    out.extend_from_slice(&FUZZY_SUBSTRING.to_le_bytes());
                    out.extend_from_slice(&tags::DISPLAY_TO.0.to_le_bytes());
                    out.extend_from_slice(&tags::DISPLAY_TO.0.to_le_bytes());
                    write_str_utf16(out, RECIPIENT_SEPARATOR);
                    out.push(restriction::PROPERTY);
                    out.push(RelOp::Eq.to_wire());
                    out.extend_from_slice(&tags::DISPLAY_CC.0.to_le_bytes());
                    out.extend_from_slice(&tags::DISPLAY_CC.0.to_le_bytes());
                    write_str_utf16(out, "");
                }
            }
            Some(())
        }
        _ => None,
    }
}

fn encode_flag(out: &mut Vec<u8>, tag: PropTag, value: bool) {
    out.push(restriction::PROPERTY);
    out.push(RelOp::Eq.to_wire());
    out.extend_from_slice(&tag.0.to_le_bytes());
    out.extend_from_slice(&tag.0.to_le_bytes());
    out.push(u8::from(value));
}

fn encode_person(out: &mut Vec<u8>, key: PropTag, address: &str) -> Option<()> {
    let entry_id = one_off(address, SMTP_ADDRESS_TYPE, address)?;
    out.push(restriction::COMMENT);
    out.push(COMMENT_VALUES);
    out.extend_from_slice(&COMMENT_MARKER.0.to_le_bytes());
    out.extend_from_slice(&COMMENT_MARKER_VALUE.to_le_bytes());
    encode_binary(out, ANY_BINARY, &entry_id)?;
    out.extend_from_slice(&ANY_UNICODE.0.to_le_bytes());
    write_str_utf16(out, address);
    out.extend_from_slice(&tags::DISPLAY_TYPE.0.to_le_bytes());
    out.extend_from_slice(&DT_MAILUSER.to_le_bytes());
    out.push(RESTRICTION_PRESENT);
    out.push(restriction::PROPERTY);
    out.push(RelOp::Eq.to_wire());
    out.extend_from_slice(&key.0.to_le_bytes());
    encode_binary(out, ANY_BINARY, &smtp_search_key(address))
}

fn encode_binary(out: &mut Vec<u8>, tag: PropTag, bytes: &[u8]) -> Option<()> {
    out.extend_from_slice(&tag.0.to_le_bytes());
    out.extend_from_slice(&u16::try_from(bytes.len()).ok()?.to_le_bytes());
    out.extend_from_slice(bytes);
    Some(())
}
