/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EntryKind, FORMAT_VERSION, MetadataKinds,
    codec::{Reader, bytes_len, varint_len, write_bytes, write_varint},
    json::{EncodedJson, JsonView},
    registry::Namespace,
    view::{MetadataView, RawKey},
    xml::{DavValueView, XmlError, XmlName, XmlValue},
};
use std::borrow::Cow;

pub const STORAGE_TRAILER_CAPACITY: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum EntryKey<'x> {
    Vendor(Cow<'x, str>),
    Registered(u16),
    Dav(XmlName<'x>),
    Imap(Cow<'x, str>),
}

#[derive(Debug, Clone)]
struct Entry<'x> {
    key: EntryKey<'x>,
    value: Cow<'x, [u8]>,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataBuilder<'x> {
    entries: Vec<Entry<'x>>,
    written: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataEdit {
    RemovalOnly,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMetadata {
    bytes: Vec<u8>,
    kinds: MetadataKinds,
    entries: usize,
}

impl<'x> EntryKey<'x> {
    fn kind(&self) -> EntryKind {
        match self {
            EntryKey::Vendor(_) => EntryKind::JmapVendor,
            EntryKey::Registered(_) => EntryKind::JmapRegistered,
            EntryKey::Dav(_) => EntryKind::Dav,
            EntryKey::Imap(_) => EntryKind::Imap,
        }
    }

    fn from_raw(key: RawKey<'x>) -> Self {
        match key {
            RawKey::Vendor(name) => EntryKey::Vendor(Cow::Borrowed(name)),
            RawKey::Registered(id) => EntryKey::Registered(id),
            RawKey::Dav(namespace, name) => EntryKey::Dav(XmlName::borrowed(namespace, name)),
            RawKey::Imap(name) => EntryKey::Imap(Cow::Borrowed(name)),
        }
    }

    fn from_namespace(namespace: &Namespace<'x>) -> Self {
        match namespace {
            Namespace::Registered(namespace) => EntryKey::Registered(namespace.id),
            Namespace::Vendor(name) => EntryKey::Vendor(Cow::Borrowed(name)),
        }
    }

    fn code(&self) -> u64 {
        let value = match self {
            EntryKey::Vendor(name) | EntryKey::Imap(name) => name.len() as u64,
            EntryKey::Registered(id) => u64::from(*id),
            EntryKey::Dav(name) => name.name.len() as u64,
        };
        self.kind().code(value)
    }

    fn encoded_len(&self) -> usize {
        varint_len(self.code())
            + match self {
                EntryKey::Vendor(name) | EntryKey::Imap(name) => name.len(),
                EntryKey::Registered(_) => 0,
                EntryKey::Dav(name) => name.key_len(),
            }
    }

    fn write(&self, out: &mut Vec<u8>) {
        write_varint(out, self.code());
        match self {
            EntryKey::Vendor(name) | EntryKey::Imap(name) => out.extend_from_slice(name.as_bytes()),
            EntryKey::Registered(_) => {}
            EntryKey::Dav(name) => name.write_key(out),
        }
    }

    fn into_owned(self) -> EntryKey<'static> {
        match self {
            EntryKey::Vendor(name) => EntryKey::Vendor(Cow::Owned(name.into_owned())),
            EntryKey::Registered(id) => EntryKey::Registered(id),
            EntryKey::Dav(name) => EntryKey::Dav(name.into_owned()),
            EntryKey::Imap(name) => EntryKey::Imap(Cow::Owned(name.into_owned())),
        }
    }
}

impl<'x> MetadataBuilder<'x> {
    pub fn new() -> Self {
        MetadataBuilder {
            entries: Vec::new(),
            written: false,
        }
    }

    pub fn from_view(view: &MetadataView<'x>) -> Self {
        let mut entries = Vec::with_capacity(view.len());
        entries.extend(view.raw_entries().map(|entry| Entry {
            key: EntryKey::from_raw(entry.key),
            value: Cow::Borrowed(entry.value.remaining()),
        }));
        if !entries.is_sorted_by(|a, b| a.key < b.key) {
            entries.sort_unstable_by(|a, b| a.key.cmp(&b.key));
            entries.dedup_by(|a, b| a.key == b.key);
        }
        MetadataBuilder {
            entries,
            written: false,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn edit(&self) -> MetadataEdit {
        if self.written {
            MetadataEdit::Write
        } else {
            MetadataEdit::RemovalOnly
        }
    }

    pub fn kinds(&self) -> MetadataKinds {
        self.entries
            .iter()
            .fold(MetadataKinds::NONE, |kinds, entry| {
                kinds.union(entry.key.kind().kinds())
            })
    }

    fn find(&self, key: &EntryKey<'_>) -> Result<usize, usize> {
        self.entries.binary_search_by(|entry| entry.key.cmp(key))
    }

    fn value(&self, key: &EntryKey<'_>) -> Option<&[u8]> {
        self.find(key)
            .ok()
            .and_then(|position| self.entries.get(position))
            .map(|entry| entry.value.as_ref())
    }

    fn upsert(&mut self, key: EntryKey<'x>, value: Cow<'x, [u8]>) {
        match self.find(&key) {
            Ok(position) => {
                if let Some(entry) = self.entries.get_mut(position)
                    && entry.value != value
                {
                    entry.value = value;
                    self.written = true;
                }
            }
            Err(position) => {
                self.entries.insert(position, Entry { key, value });
                self.written = true;
            }
        }
    }

    fn remove_key(&mut self, key: &EntryKey<'_>) -> bool {
        match self.find(key) {
            Ok(position) => {
                self.entries.remove(position);
                true
            }
            Err(_) => false,
        }
    }

    fn clear_kinds(&mut self, kinds: MetadataKinds) {
        self.entries
            .retain(|entry| !kinds.intersects(entry.key.kind().kinds()));
    }

    pub fn jmap(&self, namespace: &Namespace<'_>) -> Option<JsonView<'_>> {
        self.value(&EntryKey::from_namespace(namespace))
            .map(|value| JsonView::new(unsafe { Reader::trusted(value) }))
    }

    pub fn set_jmap(&mut self, namespace: Namespace<'x>, value: EncodedJson) {
        self.upsert(
            EntryKey::from_namespace(&namespace),
            Cow::Owned(value.into_bytes()),
        );
    }

    pub fn remove_jmap(&mut self, namespace: &Namespace<'_>) -> bool {
        self.remove_key(&EntryKey::from_namespace(namespace))
    }

    pub fn clear_jmap(&mut self) {
        self.clear_kinds(MetadataKinds::JMAP);
    }

    pub fn dav(&self, name: &XmlName<'_>) -> Option<DavValueView<'_>> {
        self.value(&EntryKey::Dav(XmlName::borrowed(
            name.namespace(),
            name.name(),
        )))
        .map(|value| DavValueView::new(unsafe { Reader::trusted(value) }))
    }

    pub fn set_dav(&mut self, name: XmlName<'x>, value: &XmlValue<'_>) -> Result<usize, XmlError> {
        name.validate_property()?;
        let value = value.encode()?;
        let len = value.len();
        self.upsert(EntryKey::Dav(name), Cow::Owned(value));
        Ok(len)
    }

    pub fn remove_dav(&mut self, name: &XmlName<'_>) -> bool {
        self.remove_key(&EntryKey::Dav(XmlName::borrowed(
            name.namespace(),
            name.name(),
        )))
    }

    pub fn clear_dav(&mut self) {
        self.clear_kinds(MetadataKinds::DAV);
    }

    pub fn imap(&self, name: &str) -> Option<&[u8]> {
        self.value(&EntryKey::Imap(Cow::Borrowed(name)))
            .and_then(|value| unsafe { Reader::trusted(value) }.bytes())
    }

    pub fn set_imap(&mut self, name: Cow<'x, str>, value: &[u8]) {
        let mut encoded = Vec::with_capacity(bytes_len(value.len()));
        write_bytes(&mut encoded, value);
        self.upsert(EntryKey::Imap(name), Cow::Owned(encoded));
    }

    pub fn remove_imap(&mut self, name: &str) -> bool {
        self.remove_key(&EntryKey::Imap(Cow::Borrowed(name)))
    }

    pub fn clear_imap(&mut self) {
        self.clear_kinds(MetadataKinds::IMAP);
    }

    pub fn encoded_len(&self) -> usize {
        2 + varint_len(self.entries.len() as u64)
            + self
                .entries
                .iter()
                .map(|entry| entry.key.encoded_len() + entry.value.len())
                .sum::<usize>()
    }

    pub fn encode(&self) -> Option<EncodedMetadata> {
        if self.entries.is_empty() {
            return None;
        }
        let len = self.encoded_len();
        let kinds = self.kinds();
        let mut bytes = Vec::with_capacity(len + STORAGE_TRAILER_CAPACITY);
        bytes.push(FORMAT_VERSION);
        bytes.push(kinds.bits());
        write_varint(&mut bytes, self.entries.len() as u64);
        for entry in &self.entries {
            entry.key.write(&mut bytes);
            bytes.extend_from_slice(&entry.value);
        }
        debug_assert_eq!(bytes.len(), len, "metadata container length mismatch");
        Some(EncodedMetadata {
            bytes,
            kinds,
            entries: self.entries.len(),
        })
    }

    pub fn into_owned(self) -> MetadataBuilder<'static> {
        MetadataBuilder {
            entries: self
                .entries
                .into_iter()
                .map(|entry| Entry {
                    key: entry.key.into_owned(),
                    value: Cow::Owned(entry.value.into_owned()),
                })
                .collect(),
            written: self.written,
        }
    }
}

impl EncodedMetadata {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    pub fn kinds(&self) -> MetadataKinds {
        self.kinds
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    pub fn view(&self) -> MetadataView<'_> {
        unsafe { MetadataView::from_trusted(&self.bytes) }.unwrap_or_else(MetadataView::empty)
    }
}
