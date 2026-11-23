/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FUZZY_SUBSTRING_IGNORECASE, string_value};
use crate::{
    common::{FileTime, UtcSeconds},
    mapi::{
        prop::{
            CountWidth, NamedPropMap, PropId, PropTag, PropType, PropValue,
            codec::{encode_value, write_str_utf16},
            tags::{self, named},
        },
        restriction::{self, RelOp, Restriction, RestrictionNode},
    },
    rules::{MessageKind, Predicate},
};
use std::borrow::Cow;

const FUZZY_PREFIX_LOOSE: u32 = 0x0005_0002;
const FUZZY_FULLSTRING_LOOSE: u32 = 0x0005_0000;
const FUZZY_PREFIX_IGNORECASE: u32 = 0x0001_0002;
const FLAG_STATUS_FLAGGED: i32 = 2;
const NDR_PREFIX: &str = "REPORT";
const NDR_MARKER: &str = ".NDR";
const NDR_CLAUSES: u16 = 2;

const MEETING_REQUEST: &[&str] = &[
    "IPM.Schedule.Meeting.Request",
    "IPM.Schedule.Meeting.Canceled",
];
const MEETING_RESPONSE: &[&str] = &[
    "IPM.Schedule.Meeting.Resp.Pos",
    "IPM.Schedule.Meeting.Resp.Neg",
    "IPM.Schedule.Meeting.Resp.Tent",
];
const ENCRYPTED: &[&str] = &[
    "IPM.Note.Secure",
    "IPM.Note.SMIME.SignedEncrypted",
    "IPM.Note.SMIME.Encrypted",
];
const AUTOMATIC_REPLY: &[&str] = &["IPM.Note.Rules.OofTemplate.Microsoft"];
const VOICEMAIL: &[&str] = &[
    "IPM.Note.Microsoft.Voicemail.UM.CA",
    "IPM.Note.rpmsg.Microsoft.Voicemail.UM.CA",
    "IPM.Note.rpmsg.Microsoft.Voicemail.UM",
    "IPM.Note.Microsoft.Voicemail.UM",
    "IPM.Note.Microsoft.Missed.Voice",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleNames {
    pub keywords: Option<PropId>,
    pub read_receipt: Option<PropId>,
    pub signed: Option<PropId>,
}

impl RuleNames {
    pub fn resolve(map: &dyn NamedPropMap) -> Self {
        RuleNames {
            keywords: map.id(named::KEYWORDS.key),
            read_receipt: map.id(named::IS_READ_RECEIPT.key),
            signed: map.id(named::IS_SIGNED.key),
        }
    }

    pub(super) fn keywords_tag(&self) -> Option<PropTag> {
        self.keywords
            .map(|id| PropTag::new(id, PropType::MvUnicode))
    }

    fn kind_of(&self, tag: PropTag) -> Option<MessageKind> {
        let id = Some(tag.id());
        if tag.id() == tags::AUTO_FORWARDED.id() {
            Some(MessageKind::AutomaticForward)
        } else if id == self.read_receipt {
            Some(MessageKind::ReadReceipt)
        } else if id == self.signed {
            Some(MessageKind::Signed)
        } else {
            None
        }
    }

    fn flag_tag(&self, kind: MessageKind) -> Option<PropTag> {
        let id = match kind {
            MessageKind::AutomaticForward => return Some(tags::AUTO_FORWARDED),
            MessageKind::ReadReceipt => self.read_receipt?,
            MessageKind::Signed => self.signed?,
            _ => return None,
        };
        Some(PropTag::new(id, PropType::Bool))
    }
}

fn class_set(kind: MessageKind) -> Option<(u32, &'static [&'static str])> {
    match kind {
        MessageKind::MeetingRequest => Some((FUZZY_PREFIX_LOOSE, MEETING_REQUEST)),
        MessageKind::MeetingResponse => Some((FUZZY_PREFIX_LOOSE, MEETING_RESPONSE)),
        MessageKind::Encrypted => Some((FUZZY_FULLSTRING_LOOSE, ENCRYPTED)),
        MessageKind::AutomaticReply => Some((FUZZY_PREFIX_LOOSE, AUTOMATIC_REPLY)),
        MessageKind::Voicemail => Some((FUZZY_PREFIX_LOOSE, VOICEMAIL)),
        MessageKind::NonDeliveryReport
        | MessageKind::ReadReceipt
        | MessageKind::AutomaticForward
        | MessageKind::Signed => None,
    }
}

fn class_kind(class: &str) -> Option<MessageKind> {
    hashify::map!(
        class.as_bytes(),
        MessageKind,
        "IPM.Schedule.Meeting.Request" => MessageKind::MeetingRequest,
        "IPM.Schedule.Meeting.Canceled" => MessageKind::MeetingRequest,
        "IPM.Schedule.Meeting.Resp.Pos" => MessageKind::MeetingResponse,
        "IPM.Schedule.Meeting.Resp.Neg" => MessageKind::MeetingResponse,
        "IPM.Schedule.Meeting.Resp.Tent" => MessageKind::MeetingResponse,
        "IPM.Note.Secure" => MessageKind::Encrypted,
        "IPM.Note.SMIME.SignedEncrypted" => MessageKind::Encrypted,
        "IPM.Note.SMIME.Encrypted" => MessageKind::Encrypted,
        "IPM.Note.Rules.OofTemplate.Microsoft" => MessageKind::AutomaticReply,
        "IPM.Note.Microsoft.Voicemail.UM.CA" => MessageKind::Voicemail,
        "IPM.Note.rpmsg.Microsoft.Voicemail.UM.CA" => MessageKind::Voicemail,
        "IPM.Note.rpmsg.Microsoft.Voicemail.UM" => MessageKind::Voicemail,
        "IPM.Note.Microsoft.Voicemail.UM" => MessageKind::Voicemail,
        "IPM.Note.Microsoft.Missed.Voice" => MessageKind::Voicemail,
    )
    .copied()
}

fn message_class(tree: &Restriction<'_>, index: u16) -> Option<(u32, String)> {
    match tree.nodes.get(usize::from(index))? {
        RestrictionNode::Content { fuzzy, tag, value } if tag.id() == tags::MESSAGE_CLASS.id() => {
            Some((*fuzzy, string_value(value)?))
        }
        _ => None,
    }
}

pub(super) fn decode_classes(tree: &Restriction<'_>, children: &[u16]) -> Option<Predicate> {
    let mut kind = None;
    let mut seen = 0u32;
    for &index in children {
        let (fuzzy, class) = message_class(tree, index)?;
        let found = class_kind(&class)?;
        if *kind.get_or_insert(found) != found {
            return None;
        }
        let (expected, classes) = class_set(found)?;
        let bit = 1u32 << classes.iter().position(|known| *known == class)?;
        if fuzzy != expected || seen & bit != 0 {
            return None;
        }
        seen |= bit;
    }
    let kind = kind?;
    let (_, classes) = class_set(kind)?;
    (seen == (1u32 << classes.len()).wrapping_sub(1)).then_some(Predicate::MessageType(kind))
}

pub(super) fn is_ndr(tree: &Restriction<'_>, children: &[u16]) -> bool {
    let [prefix, marker] = children else {
        return false;
    };
    matches!(
        (message_class(tree, *prefix), message_class(tree, *marker)),
        (Some((FUZZY_PREFIX_IGNORECASE, prefix)), Some((FUZZY_SUBSTRING_IGNORECASE, marker)))
            if prefix == NDR_PREFIX && marker == NDR_MARKER
    )
}

pub(super) fn decode_property(
    names: &RuleNames,
    op: RelOp,
    tag: PropTag,
    value: &PropValue<'_>,
) -> Option<Predicate> {
    match (op, value) {
        (RelOp::Eq, PropValue::Bool(true)) => names.kind_of(tag).map(Predicate::MessageType),
        (RelOp::Eq, PropValue::I32(FLAG_STATUS_FLAGGED)) if tag.id() == tags::FLAG_STATUS.id() => {
            Some(Predicate::Flagged)
        }
        (RelOp::Gt | RelOp::Lt, PropValue::Time(time))
            if tag.id() == tags::MESSAGE_DELIVERY_TIME.id() =>
        {
            let (UtcSeconds(seconds), 0) = time.to_utc() else {
                return None;
            };
            Some(if op == RelOp::Gt {
                Predicate::ReceivedAfter(seconds)
            } else {
                Predicate::ReceivedBefore(seconds)
            })
        }
        _ => None,
    }
}

pub(super) fn category(names: &RuleNames, node: &RestrictionNode<'_>) -> Option<String> {
    let RestrictionNode::Property {
        op: RelOp::Eq,
        tag,
        value: value @ PropValue::Unicode(_),
    } = node
    else {
        return None;
    };
    (Some(tag.id()) == names.keywords)
        .then(|| string_value(value))
        .flatten()
}

pub(super) fn encode_kind(names: &RuleNames, kind: MessageKind, out: &mut Vec<u8>) -> Option<()> {
    if let Some((fuzzy, classes)) = class_set(kind) {
        out.push(restriction::OR);
        out.extend_from_slice(&u16::try_from(classes.len()).ok()?.to_le_bytes());
        for class in classes {
            encode_class(out, fuzzy, class);
        }
    } else if kind == MessageKind::NonDeliveryReport {
        out.push(restriction::AND);
        out.extend_from_slice(&NDR_CLAUSES.to_le_bytes());
        encode_class(out, FUZZY_PREFIX_IGNORECASE, NDR_PREFIX);
        encode_class(out, FUZZY_SUBSTRING_IGNORECASE, NDR_MARKER);
    } else {
        let tag = names.flag_tag(kind)?;
        encode_value_property(out, RelOp::Eq, tag, tag, &PropValue::Bool(true));
    }
    Some(())
}

pub(super) fn encode_flagged(out: &mut Vec<u8>) {
    encode_value_property(
        out,
        RelOp::Eq,
        tags::FLAG_STATUS,
        tags::FLAG_STATUS,
        &PropValue::I32(FLAG_STATUS_FLAGGED),
    );
}

pub(super) fn encode_received(out: &mut Vec<u8>, op: RelOp, seconds: i64) {
    encode_value_property(
        out,
        op,
        tags::MESSAGE_DELIVERY_TIME,
        tags::MESSAGE_DELIVERY_TIME,
        &PropValue::Time(FileTime::from_utc(UtcSeconds(seconds), 0)),
    );
}

pub(super) fn encode_categories<'x>(
    names: &RuleNames,
    categories: impl ExactSizeIterator<Item = Cow<'x, str>>,
    out: &mut Vec<u8>,
) -> Option<()> {
    let tag = names.keywords_tag()?;
    let value_tag = tag.with_type(PropType::Unicode);
    match categories.len() {
        0 => return None,
        1 => {}
        count => {
            out.push(restriction::OR);
            out.extend_from_slice(&u16::try_from(count).ok()?.to_le_bytes());
        }
    }
    for name in categories {
        out.push(restriction::PROPERTY);
        out.push(RelOp::Eq.to_wire());
        out.extend_from_slice(&tag.0.to_le_bytes());
        out.extend_from_slice(&value_tag.0.to_le_bytes());
        write_str_utf16(out, &name);
    }
    Some(())
}

fn encode_class(out: &mut Vec<u8>, fuzzy: u32, class: &str) {
    out.push(restriction::CONTENT);
    out.extend_from_slice(&fuzzy.to_le_bytes());
    out.extend_from_slice(&tags::MESSAGE_CLASS.0.to_le_bytes());
    out.extend_from_slice(&tags::MESSAGE_CLASS.0.to_le_bytes());
    write_str_utf16(out, class);
}

fn encode_value_property(
    out: &mut Vec<u8>,
    op: RelOp,
    tag: PropTag,
    value_tag: PropTag,
    value: &PropValue<'_>,
) {
    out.push(restriction::PROPERTY);
    out.push(op.to_wire());
    out.extend_from_slice(&tag.0.to_le_bytes());
    out.extend_from_slice(&value_tag.0.to_le_bytes());
    encode_value(out, value, CountWidth::Rop);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/rule_logic/message/tests.rs"]
mod tests;
