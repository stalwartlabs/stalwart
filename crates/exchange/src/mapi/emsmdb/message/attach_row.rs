/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::load::MAX_DECODED;
use crate::store::{
    ExchangeProperty,
    object::{ArchivedExchangeObject, ExchangeObject},
    properties_size,
};
use exchange_proto::{
    convert::{
        mime::{AttachmentOrder, AttachmentSlot, attachment_slots},
        model::{Attachment, MessageContent},
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, tags},
};

const KEY_ATTACH: u8 = 3;
const SLOT_LEN: usize = 1 + 8 + 2;
const KEY_CAPACITY: usize = SLOT_LEN + 24;
const CONFLICT_HEADROOM: usize = 4096;
const MAX_SHARE_DIVISOR: usize = 2;

const NOT_CARRIED: [PropId; 13] = [
    tags::ATTACH_DATA_BINARY.id(),
    tags::ATTACH_METHOD.id(),
    tags::ATTACH_SIZE.id(),
    tags::ATTACH_LONG_FILENAME.id(),
    tags::ATTACH_FILENAME.id(),
    tags::ATTACH_EXTENSION.id(),
    tags::ATTACH_MIME_TAG.id(),
    tags::ATTACH_NUMBER.id(),
    tags::OBJECT_TYPE.id(),
    tags::INSTANCE_KEY.id(),
    tags::RECORD_KEY.id(),
    tags::ACCESS.id(),
    tags::ACCESS_LEVEL.id(),
];

#[derive(Clone, Copy, PartialEq, Eq)]
struct SlotKey(AttachmentSlot);

impl SlotKey {
    fn write(self, out: &mut Vec<u8>) {
        out.push(KEY_ATTACH);
        out.extend_from_slice(&self.0.fingerprint.to_be_bytes());
        out.extend_from_slice(&self.0.occurrence.to_be_bytes());
    }

    fn read(key: &[u8]) -> Option<(Self, &[u8])> {
        let (kind, rest) = key.split_first()?;
        let (fingerprint, rest) = rest.split_first_chunk::<8>()?;
        let (occurrence, rest) = rest.split_first_chunk::<2>()?;
        (*kind == KEY_ATTACH).then_some((
            SlotKey(AttachmentSlot {
                fingerprint: u64::from_be_bytes(*fingerprint),
                occurrence: u16::from_be_bytes(*occurrence),
            }),
            rest,
        ))
    }
}

struct SlotIndex(Vec<(AttachmentSlot, usize)>);

impl SlotIndex {
    fn new(content: &MessageContent) -> Self {
        let mut slots = attachment_slots(content, AttachmentOrder::Stored)
            .into_iter()
            .enumerate()
            .map(|(index, slot)| (slot, index))
            .collect::<Vec<_>>();
        slots.sort_unstable();
        SlotIndex(slots)
    }

    fn get(&self, slot: AttachmentSlot) -> Option<usize> {
        self.0
            .binary_search_by_key(&slot, |(candidate, _)| *candidate)
            .ok()
            .and_then(|position| self.0.get(position))
            .map(|(_, index)| *index)
    }
}

fn is_attachment_carried(key: PropKeyRef<'_>, value: &OwnedPropValue) -> bool {
    !matches!(value, OwnedPropValue::Error(_))
        && !matches!(key, PropKeyRef::Tag(id) if NOT_CARRIED.contains(&id))
}

pub fn is_attachment_entry(key: &[u8]) -> bool {
    key.first() == Some(&KEY_ATTACH)
}

pub fn is_valid_attachment_entry(key: &[u8], value: &[u8]) -> bool {
    SlotKey::read(key)
        .and_then(|(_, prop)| PropKeyRef::read_canonical(prop))
        .zip(OwnedPropValue::read_canonical(value))
        .is_some_and(|((prop, key_tail), (decoded, value_tail))| {
            key_tail.is_empty() && value_tail.is_empty() && is_attachment_carried(prop, &decoded)
        })
}

pub fn attachment_entry(key: &[u8], value: &[u8]) -> Option<ExchangeProperty> {
    is_valid_attachment_entry(key, value).then(|| ExchangeProperty {
        key: key.to_vec(),
        value: value.to_vec(),
    })
}

pub fn push_attachment_properties(
    account_id: u32,
    content: &MessageContent,
    max_size: usize,
    properties: &mut Vec<ExchangeProperty>,
) {
    let slots = attachment_slots(
        content,
        AttachmentOrder::Export {
            max_decoded: MAX_DECODED,
        },
    );
    push_entries(
        account_id,
        &content.attachments,
        &slots,
        max_size,
        |_, _, _| true,
        properties,
    );
}

pub fn push_imported_attachment_properties(
    account_id: u32,
    uploaded: &MessageContent,
    stored: &MessageContent,
    current: &ExchangeObject,
    max_size: usize,
    properties: &mut Vec<ExchangeProperty>,
) {
    if uploaded.attachments.is_empty() {
        return;
    }
    let index = SlotIndex::new(stored);
    let slots = attachment_slots(uploaded, AttachmentOrder::Stored);
    push_entries(
        account_id,
        &uploaded.attachments,
        &slots,
        max_size,
        |slot, key, encoded| {
            index
                .get(slot)
                .and_then(|index| stored.attachments.get(index))
                .is_some_and(|stored| {
                    current.property(encoded).is_some() || stored.props.get_any(key).is_none()
                })
        },
        properties,
    );
}

fn push_entries(
    account_id: u32,
    attachments: &[Attachment],
    slots: &[AttachmentSlot],
    max_size: usize,
    keep: impl Fn(AttachmentSlot, PropKeyRef<'_>, &[u8]) -> bool,
    properties: &mut Vec<ExchangeProperty>,
) {
    let start = properties.len();
    let used = properties_size(
        properties
            .iter()
            .map(|property| (property.key.as_slice(), property.value.as_slice())),
    );
    let mut budget = max_size
        .saturating_sub(usize::try_from(used).unwrap_or(usize::MAX))
        .saturating_sub(CONFLICT_HEADROOM)
        .min(max_size / MAX_SHARE_DIVISOR);
    let mut dropped = 0u64;
    let mut dropped_size = 0u64;
    let mut key_buf = Vec::with_capacity(KEY_CAPACITY);
    let mut value_buf = Vec::new();
    for (slot, attachment) in slots.iter().zip(attachments) {
        for (key, value) in attachment.props.iter() {
            let key = key.as_ref();
            if !is_attachment_carried(key, value) {
                continue;
            }
            key_buf.clear();
            SlotKey(*slot).write(&mut key_buf);
            key.write_canonical(&mut key_buf);
            if !keep(*slot, key, &key_buf) {
                continue;
            }
            value_buf.clear();
            value.write_canonical(&mut value_buf);
            let size = key_buf.len().saturating_add(value_buf.len());
            if size <= budget {
                budget -= size;
                properties.push(ExchangeProperty {
                    key: key_buf.as_slice().to_vec(),
                    value: value_buf.as_slice().to_vec(),
                });
            } else {
                dropped = dropped.saturating_add(1);
                dropped_size = dropped_size.saturating_add(u64::try_from(size).unwrap_or(u64::MAX));
            }
        }
    }
    if dropped > 0 {
        dropped_attachment_properties(account_id, dropped, dropped_size);
    }
    if let Some(added) = properties.get_mut(start..) {
        added.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    }
    properties.dedup_by(|a, b| a.key == b.key);
}

#[cold]
#[inline(never)]
fn dropped_attachment_properties(account_id: u32, count: u64, size: u64) {
    trc::event!(
        Limit(trc::LimitEvent::SizeRequest),
        AccountId = account_id,
        Total = count,
        Size = size,
        Details = "MAPI attachment properties not stored"
    );
}

pub fn merge_attachment_properties(row: &ArchivedExchangeObject, content: &mut MessageContent) {
    merge_attachment_entries(
        row.properties_in_set(&[KEY_ATTACH])
            .map(|property| (property.key.as_slice(), property.value.as_slice())),
        content,
    );
}

pub fn merge_attachment_entries<'x>(
    entries: impl Iterator<Item = (&'x [u8], &'x [u8])>,
    content: &mut MessageContent,
) {
    let mut entries = entries.peekable();
    if entries.peek().is_none() || content.attachments.is_empty() {
        return;
    }
    let index = SlotIndex::new(content);
    let mut matched: Option<(SlotKey, Option<usize>)> = None;
    for (key, value) in entries {
        let Some((slot, key)) = SlotKey::read(key) else {
            continue;
        };
        let position = match matched {
            Some((previous, position)) if previous == slot => position,
            _ => {
                let position = index.get(slot.0);
                matched = Some((slot, position));
                position
            }
        };
        let Some(attachment) = position.and_then(|position| content.attachments.get_mut(position))
        else {
            continue;
        };
        let Some((key, [])) = PropKey::read_canonical(key) else {
            continue;
        };
        let Some((value, [])) = OwnedPropValue::read_canonical(value) else {
            continue;
        };
        if is_attachment_carried(key.as_ref(), &value)
            && attachment.props.get_any(key.as_ref()).is_none()
        {
            attachment.props.set(key, value);
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/attach_row/tests.rs"]
mod tests;
