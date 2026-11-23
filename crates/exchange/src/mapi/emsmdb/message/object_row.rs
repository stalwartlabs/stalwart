/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::BODY_SOURCES;
use crate::{
    eas::convert::flag::MEETING_TYPE_KEY,
    store::{ArchivedExchangeProperty, ExchangeProperty, object::ExchangeObject},
};
use exchange_proto::{
    common::FileTime,
    convert::{
        mime::reference_ids,
        model::PropBag as ContentBag,
        tags::{KEYWORDS_NAME, message_flags},
    },
    mapi::prop::{
        OwnedPropValue, PropId, PropKey, PropKeyRef, PropType, sets::PS_PUBLIC_STRINGS, tags,
    },
};

const LID_CATEGORIES: u32 = 0x2328;
const FLAG_STATUS_COMPLETE: i32 = 1;
const FLAG_STATUS_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::FLAG_STATUS.id());
const MESSAGE_FLAGS_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::MESSAGE_FLAGS.id());

const NOT_CARRIED: [PropId; 29] = [
    tags::MID.id(),
    tags::FOLDER_ID.id(),
    tags::PARENT_FOLDER_ID.id(),
    tags::ENTRY_ID.id(),
    tags::PARENT_ENTRY_ID.id(),
    tags::RECORD_KEY.id(),
    tags::INSTANCE_KEY.id(),
    tags::SOURCE_KEY.id(),
    tags::PARENT_SOURCE_KEY.id(),
    tags::CHANGE_KEY.id(),
    tags::PREDECESSOR_CHANGE_LIST.id(),
    tags::CHANGE_NUMBER.id(),
    tags::OBJECT_TYPE.id(),
    tags::ACCESS.id(),
    tags::ACCESS_LEVEL.id(),
    tags::ASSOCIATED.id(),
    tags::MESSAGE_SIZE.id(),
    tags::MESSAGE_SIZE_EXTENDED.id(),
    tags::HAS_ATTACHMENTS.id(),
    tags::MESSAGE_FLAGS.id(),
    tags::READ.id(),
    tags::MESSAGE_CLASS.id(),
    tags::CREATION_TIME.id(),
    tags::LAST_MODIFICATION_TIME.id(),
    tags::LOCAL_COMMIT_TIME.id(),
    tags::STORE_ENTRY_ID.id(),
    tags::NATIVE_BODY.id(),
    tags::RTF_IN_SYNC.id(),
    tags::HTML.id(),
];

pub fn is_carried(key: PropKeyRef<'_>) -> bool {
    match key {
        PropKeyRef::Tag(id) => !NOT_CARRIED.contains(&id) && !BODY_SOURCES.contains(&id),
        PropKeyRef::Lid { .. } | PropKeyRef::Name { .. } => !is_category(key),
    }
}

pub fn is_carried_value(key: PropKeyRef<'_>, value: &OwnedPropValue) -> bool {
    key != FLAG_STATUS_KEY || matches!(value, OwnedPropValue::I32(FLAG_STATUS_COMPLETE))
}

pub fn is_flag_complete(props: &ContentBag) -> bool {
    props
        .get_any(FLAG_STATUS_KEY)
        .is_some_and(|value| is_carried_value(FLAG_STATUS_KEY, value))
}

pub fn flag_status_key() -> PropKey {
    PropKey::tag(tags::FLAG_STATUS.id())
}

pub fn category_keys() -> [PropKeyRef<'static>; 2] {
    [
        PropKeyRef::Name {
            set: PS_PUBLIC_STRINGS,
            name: KEYWORDS_NAME,
        },
        PropKeyRef::Lid {
            set: PS_PUBLIC_STRINGS,
            lid: LID_CATEGORIES,
        },
    ]
}

pub fn is_category(key: PropKeyRef<'_>) -> bool {
    category_keys().contains(&key)
}

pub fn category_names(props: &ContentBag) -> Option<&[Box<str>]> {
    category_keys()
        .into_iter()
        .find_map(|key| match props.get_any(key) {
            Some(OwnedPropValue::MvUnicode(names)) => Some(names.as_ref()),
            _ => None,
        })
}

pub fn encode_key(key: PropKeyRef<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    key.write_canonical(&mut out);
    out
}

pub fn encode_property(key: PropKeyRef<'_>, value: &OwnedPropValue) -> ExchangeProperty {
    let mut encoded = Vec::new();
    value.write_canonical(&mut encoded);
    ExchangeProperty {
        key: encode_key(key),
        value: encoded,
    }
}

pub fn carried_properties(
    props: &ContentBag,
    keep: impl Fn(PropKeyRef<'_>) -> bool,
) -> Vec<ExchangeProperty> {
    encoded_properties(props, |key, value| {
        is_carried(key) && is_carried_value(key, value) && keep(key)
    })
}

pub fn fai_properties(props: &ContentBag) -> Vec<ExchangeProperty> {
    encoded_properties(props, |key, value| match key {
        PropKeyRef::Tag(id) if id == tags::CREATION_TIME.id() => {
            matches!(value, OwnedPropValue::Time(_))
        }
        PropKeyRef::Tag(id) => {
            id == tags::HTML.id() || BODY_SOURCES.contains(&id) || is_carried(key)
        }
        PropKeyRef::Lid { .. } | PropKeyRef::Name { .. } => true,
    })
}

fn insert_missing(properties: &mut Vec<ExchangeProperty>, property: ExchangeProperty) {
    if let Err(at) = properties.binary_search_by(|probe| probe.key.cmp(&property.key)) {
        properties.insert(at, property);
    }
}

pub fn stamp_creation_time(properties: &mut Vec<ExchangeProperty>, time: FileTime) {
    insert_missing(
        properties,
        encode_property(
            PropKeyRef::Tag(tags::CREATION_TIME.id()),
            &OwnedPropValue::Time(time),
        ),
    );
}

pub fn carry_creation_time<'x>(
    properties: &mut Vec<ExchangeProperty>,
    stored: impl IntoIterator<Item = &'x ArchivedExchangeProperty>,
) {
    let key = encode_key(PropKeyRef::Tag(tags::CREATION_TIME.id()));
    if let Some(found) = stored
        .into_iter()
        .find(|property| property.key.as_slice() == key.as_slice())
    {
        insert_missing(
            properties,
            ExchangeProperty {
                key,
                value: found.value.to_vec(),
            },
        );
    }
}

pub fn carry_meeting_type(
    properties: &mut Vec<ExchangeProperty>,
    uploaded: &ContentBag,
    current: &ExchangeObject,
) {
    if uploaded.get_any(MEETING_TYPE_KEY).is_some() {
        return;
    }
    let key = encode_key(MEETING_TYPE_KEY);
    if let Some(value) = current.property(&key) {
        let value = value.to_vec();
        insert_missing(properties, ExchangeProperty { key, value });
    }
}

pub fn carry_message_class(
    properties: &mut Vec<ExchangeProperty>,
    uploaded: &ContentBag,
    implied: Option<&str>,
) {
    if let Some(class) = uploaded.text(tags::MESSAGE_CLASS.id())
        && implied.is_none_or(|implied| !implied.eq_ignore_ascii_case(class))
    {
        insert_missing(
            properties,
            encode_property(
                PropKeyRef::Tag(tags::MESSAGE_CLASS.id()),
                &OwnedPropValue::Unicode(class.into()),
            ),
        );
    }
}

pub fn carry_resend(properties: &mut Vec<ExchangeProperty>, uploaded: &ContentBag) {
    if is_resend(uploaded) {
        insert_missing(
            properties,
            encode_property(
                MESSAGE_FLAGS_KEY,
                &OwnedPropValue::I32(message_flags::RESEND),
            ),
        );
    }
}

pub fn is_resend(props: &ContentBag) -> bool {
    props
        .get(MESSAGE_FLAGS_KEY, PropType::I32)
        .is_some_and(has_resend)
}

pub fn set_resend(object: &mut ExchangeObject, resend: bool) {
    if resend {
        let property = encode_property(
            MESSAGE_FLAGS_KEY,
            &OwnedPropValue::I32(message_flags::RESEND),
        );
        object.set_property(property.key, property.value);
    } else {
        object.remove_property(&encode_key(MESSAGE_FLAGS_KEY));
    }
}

pub fn resend_key() -> PropKeyRef<'static> {
    MESSAGE_FLAGS_KEY
}

fn has_resend(value: &OwnedPropValue) -> bool {
    matches!(value, OwnedPropValue::I32(flags) if flags & message_flags::RESEND != 0)
}

fn mark_resend(props: &mut ContentBag) {
    let flags = match props.get(MESSAGE_FLAGS_KEY, PropType::I32) {
        Some(OwnedPropValue::I32(flags)) => *flags,
        _ => 0,
    };
    props.set(
        PropKey::tag(tags::MESSAGE_FLAGS.id()),
        OwnedPropValue::I32(flags | message_flags::RESEND),
    );
}

pub const MESSAGE_CLASS_KEY: [u8; 3] = tags::MESSAGE_CLASS.id().canonical_key();

pub fn recipient_properties(props: &ContentBag) -> Vec<ExchangeProperty> {
    encoded_properties(props, |key, value| {
        key != PropKeyRef::Tag(tags::ROWID.id()) && !matches!(value, OwnedPropValue::Error(_))
    })
}

fn encoded_properties(
    props: &ContentBag,
    keep: impl Fn(PropKeyRef<'_>, &OwnedPropValue) -> bool,
) -> Vec<ExchangeProperty> {
    let mut out = props
        .iter()
        .filter(|(key, value)| keep(key.as_ref(), value))
        .map(|(key, value)| encode_property(key.as_ref(), value))
        .collect::<Vec<_>>();
    out.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    out.dedup_by(|a, b| a.key == b.key);
    out
}

pub fn decode_property(key: &[u8], value: &[u8]) -> Option<(PropKey, OwnedPropValue)> {
    let (key, rest) = PropKey::read_canonical(key)?;
    let (value, tail) = OwnedPropValue::read_canonical(value)?;
    (rest.is_empty() && tail.is_empty()).then_some((key, value))
}

pub fn decoded_properties<'x>(
    properties: impl IntoIterator<Item = &'x ArchivedExchangeProperty>,
) -> impl Iterator<Item = (PropKey, OwnedPropValue)> {
    properties.into_iter().filter_map(|property| {
        decode_property(property.key.as_slice(), property.value.as_slice())
            .filter(|(key, _)| !is_category(key.as_ref()))
    })
}

pub fn merge_properties<'x>(
    properties: impl IntoIterator<Item = &'x ArchivedExchangeProperty>,
    bag: &mut ContentBag,
) {
    let mut parts = CarriedParts::default();
    for (key, value) in decoded_properties(properties) {
        let Some(value) = parts.take(key.as_ref(), value) else {
            continue;
        };
        if key.as_ref() != FLAG_STATUS_KEY || bag.get_any(FLAG_STATUS_KEY).is_none() {
            bag.set(key, value);
        }
    }
    parts.apply(bag);
}

#[derive(Debug, Default)]
pub struct CarriedParts {
    prefix: Option<OwnedPropValue>,
    normalized: Option<OwnedPropValue>,
    references: Option<OwnedPropValue>,
    resend: bool,
}

impl CarriedParts {
    pub fn take(&mut self, key: PropKeyRef<'_>, value: OwnedPropValue) -> Option<OwnedPropValue> {
        match key {
            PropKeyRef::Tag(id) if id == tags::SUBJECT_PREFIX.id() => self.prefix = Some(value),
            PropKeyRef::Tag(id) if id == tags::NORMALIZED_SUBJECT.id() => {
                self.normalized = Some(value)
            }
            PropKeyRef::Tag(id) if id == tags::INTERNET_REFERENCES.id() => {
                self.references = Some(value)
            }
            key if key == MESSAGE_FLAGS_KEY => self.resend |= has_resend(&value),
            _ => return Some(value),
        }
        None
    }

    pub fn apply(self, bag: &mut ContentBag) {
        if self.resend {
            mark_resend(bag);
        }
        self.apply_envelope(bag);
    }

    pub fn apply_envelope(self, bag: &mut ContentBag) {
        if let Some(references) = self.references.filter(|references| {
            match (
                unicode_text(Some(references)),
                bag.text(tags::INTERNET_REFERENCES.id()),
            ) {
                (Some(carried), Some(current)) => reference_ids(carried).eq(reference_ids(current)),
                (_, None) => true,
                (None, Some(_)) => false,
            }
        }) {
            bag.set(PropKey::tag(tags::INTERNET_REFERENCES.id()), references);
        }
        if self.prefix.is_none() && self.normalized.is_none() {
            return;
        }
        let composes = match bag.text(tags::SUBJECT.id()) {
            Some(subject) => {
                let head = unicode_text(self.prefix.as_ref())
                    .or_else(|| bag.text(tags::SUBJECT_PREFIX.id()))
                    .unwrap_or_default();
                let tail = unicode_text(self.normalized.as_ref())
                    .or_else(|| bag.text(tags::NORMALIZED_SUBJECT.id()));
                subject.strip_prefix(head) == tail
            }
            None => true,
        };
        if composes {
            for (tag, value) in [
                (tags::SUBJECT_PREFIX, self.prefix),
                (tags::NORMALIZED_SUBJECT, self.normalized),
            ] {
                if let Some(value) = value {
                    bag.set(PropKey::tag(tag.id()), value);
                }
            }
        }
    }
}

fn unicode_text(value: Option<&OwnedPropValue>) -> Option<&str> {
    match value {
        Some(OwnedPropValue::Unicode(text)) => Some(text),
        _ => None,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/object_row/tests.rs"]
mod tests;
