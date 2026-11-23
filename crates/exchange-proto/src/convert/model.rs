/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use bytes::Bytes;

use crate::{
    convert::tags,
    mapi::prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, PropType},
};

#[derive(Debug, Clone, Default)]
pub struct PropBag {
    props: Vec<(PropKey, OwnedPropValue)>,
}

impl PropBag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(mut props: Vec<(PropKey, OwnedPropValue)>) -> Self {
        props.reverse();
        props.sort_by(|(a, va), (b, vb)| {
            a.as_ref()
                .cmp(&b.as_ref())
                .then_with(|| entry_class(va).cmp(&entry_class(vb)))
        });
        props.dedup_by(|(a, va), (b, vb)| {
            a.as_ref() == b.as_ref() && entry_class(va) == entry_class(vb)
        });
        PropBag { props }
    }

    fn position(&self, key: PropKeyRef<'_>, class: PropType) -> Result<usize, usize> {
        self.props.binary_search_by(|(k, v)| {
            k.as_ref()
                .cmp(&key)
                .then_with(|| v.ptype().storage_class().code().cmp(&class.code()))
        })
    }

    pub fn get(&self, key: PropKeyRef<'_>, ptype: PropType) -> Option<&OwnedPropValue> {
        let index = self.position(key, ptype.storage_class()).ok()?;
        self.props.get(index).map(|(_, value)| value)
    }

    pub fn get_any(&self, key: PropKeyRef<'_>) -> Option<&OwnedPropValue> {
        let start = self.props.partition_point(|(k, _)| k.as_ref() < key);
        self.props
            .get(start)
            .filter(|(k, _)| k.as_ref() == key)
            .map(|(_, value)| value)
    }

    pub fn set(&mut self, key: PropKey, value: OwnedPropValue) {
        match self.position(key.as_ref(), value.ptype().storage_class()) {
            Ok(index) => {
                if let Some(slot) = self.props.get_mut(index) {
                    slot.1 = value;
                }
            }
            Err(index) => self.props.insert(index, (key, value)),
        }
    }

    pub fn remove(&mut self, key: PropKeyRef<'_>, ptype: PropType) -> Option<OwnedPropValue> {
        let index = self.position(key, ptype.storage_class()).ok()?;
        Some(self.props.remove(index).1)
    }

    pub fn remove_any(&mut self, key: PropKeyRef<'_>) {
        let start = self.props.partition_point(|(k, _)| k.as_ref() < key);
        let end = self.props.partition_point(|(k, _)| k.as_ref() <= key);
        self.props.drain(start..end);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PropKey, &OwnedPropValue)> {
        self.props.iter().map(|(key, value)| (key, value))
    }

    pub fn into_entries(self) -> impl Iterator<Item = (PropKey, OwnedPropValue)> {
        self.props.into_iter()
    }

    pub fn text(&self, id: PropId) -> Option<&str> {
        match self.get(PropKeyRef::Tag(id), PropType::Unicode)? {
            OwnedPropValue::Unicode(value) => Some(value),
            _ => None,
        }
    }

    pub fn subject(&self) -> Option<Cow<'_, str>> {
        self.text(tags::SUBJECT)
            .map(Cow::Borrowed)
            .or_else(|| self.composed_subject())
    }

    pub fn composed_subject(&self) -> Option<Cow<'_, str>> {
        let normalized = self.text(tags::NORMALIZED_SUBJECT)?;
        Some(match self.text(tags::SUBJECT_PREFIX) {
            Some(prefix) if !prefix.is_empty() => {
                let mut subject = String::with_capacity(prefix.len() + normalized.len());
                subject.push_str(prefix);
                subject.push_str(normalized);
                Cow::Owned(subject)
            }
            _ => Cow::Borrowed(normalized),
        })
    }

    pub fn has_named(&self) -> bool {
        self.props
            .last()
            .is_some_and(|(key, _)| !matches!(key.as_ref(), PropKeyRef::Tag(_)))
    }

    pub fn len(&self) -> usize {
        self.props.len()
    }

    pub fn is_empty(&self) -> bool {
        self.props.is_empty()
    }
}

fn entry_class(value: &OwnedPropValue) -> u16 {
    value.ptype().storage_class().code()
}

#[derive(Debug, Clone, Default)]
pub struct MessageContent {
    pub props: PropBag,
    pub recipients: Vec<PropBag>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub props: PropBag,
    pub data: AttachData,
}

#[derive(Debug, Clone)]
pub enum AttachData {
    None,
    Bytes(Bytes),
    Embedded(Box<MessageContent>),
    Deferred(BlobRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobRef {
    pub id: u64,
    pub offset: u32,
    pub len: u32,
}

#[derive(Debug, Clone, Default)]
pub struct PatchReport {
    pub unmapped: PropBag,
    pub lossy: LossKinds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LossKind {
    Recurrence = 0,
    TimeZone = 1,
    Reminder = 2,
    BusyStatus = 3,
    ExceptionDetail = 4,
    ContactField = 5,
}

impl LossKind {
    const ALL: [LossKind; 6] = [
        LossKind::Recurrence,
        LossKind::TimeZone,
        LossKind::Reminder,
        LossKind::BusyStatus,
        LossKind::ExceptionDetail,
        LossKind::ContactField,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LossKinds(u8);

impl LossKinds {
    pub fn insert(&mut self, kind: LossKind) {
        self.0 |= kind.bit();
    }

    pub fn contains(self, kind: LossKind) -> bool {
        self.0 & kind.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = LossKind> {
        LossKind::ALL
            .into_iter()
            .filter(move |kind| self.contains(*kind))
    }
}
