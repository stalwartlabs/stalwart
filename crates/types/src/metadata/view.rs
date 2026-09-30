/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EntryKind, FORMAT_VERSION, MetadataKinds,
    codec::{Reader, TrustedReader},
    json::{JsonView, validate_namespace_value, value_span},
    registry::{Namespace, RegisteredNamespace},
    xml::{
        DavValueView, XmlName, check_property_name, dav_value_span, read_ns_ref, validate_dav_value,
    },
};

const EMPTY_CONTAINER: [u8; 3] = [FORMAT_VERSION, 0, 0];

#[derive(Debug, Clone, Copy)]
pub struct MetadataView<'x> {
    bytes: &'x [u8],
    kinds: MetadataKinds,
    count: usize,
    entries: TrustedReader<'x>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawKey<'x> {
    Vendor(&'x str),
    Registered(u16),
    Dav(Option<&'x str>, &'x str),
    Imap(&'x str),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RawEntry<'x> {
    pub key: RawKey<'x>,
    pub value: TrustedReader<'x>,
}

#[derive(Debug, Clone)]
pub(crate) struct RawEntries<'x> {
    reader: TrustedReader<'x>,
    remaining: usize,
}

#[derive(Debug, Clone)]
pub struct JmapEntries<'x> {
    entries: RawEntries<'x>,
}

#[derive(Debug, Clone)]
pub struct DavEntries<'x> {
    entries: RawEntries<'x>,
}

#[derive(Debug, Clone)]
pub struct ImapEntries<'x> {
    entries: RawEntries<'x>,
}

fn header<const TRUSTED: bool>(
    bytes: &[u8],
    reader: &mut Reader<'_, TRUSTED>,
) -> Option<(MetadataKinds, usize)> {
    (reader.u8()? == FORMAT_VERSION).then_some(())?;
    let kinds = MetadataKinds::from_bits(reader.u8()?)?;
    let count = reader.len()?;
    (count <= bytes.len()).then_some((kinds, count))
}

fn validate(bytes: &[u8]) -> Option<()> {
    let mut reader = Reader::checked(bytes);
    let (kinds, count) = header(bytes, &mut reader)?;
    let mut found = MetadataKinds::NONE;
    let mut previous = EntryKind::JmapVendor;

    for _ in 0..count {
        let code = reader.varint()?;
        let kind = EntryKind::from_code(code);
        let value = code >> 2;
        if kind < previous {
            return None;
        }
        previous = kind;
        found.insert(kind.kinds());

        match kind {
            EntryKind::JmapVendor => {
                reader.text(usize::try_from(value).ok()?)?;
                validate_namespace_value(&mut reader)?;
            }
            EntryKind::JmapRegistered => {
                u16::try_from(value).ok()?;
                validate_namespace_value(&mut reader)?;
            }
            EntryKind::Dav => {
                let namespace = read_ns_ref(&mut reader)?;
                let name = reader.text(usize::try_from(value).ok()?)?;
                check_property_name(namespace, name).ok()?;
                validate_dav_value(&mut reader)?;
            }
            EntryKind::Imap => {
                reader.text(usize::try_from(value).ok()?)?;
                reader.bytes()?;
            }
        }
    }

    (reader.is_empty() && found == kinds).then_some(())
}

fn parse_entry<'x>(reader: &mut TrustedReader<'x>) -> Option<RawEntry<'x>> {
    let code = reader.varint()?;
    let value = code >> 2;
    let key = match EntryKind::from_code(code) {
        EntryKind::JmapVendor => RawKey::Vendor(reader.text(usize::try_from(value).ok()?)?),
        EntryKind::JmapRegistered => RawKey::Registered(u16::try_from(value).ok()?),
        EntryKind::Dav => {
            let namespace = read_ns_ref(reader)?;
            RawKey::Dav(namespace, reader.text(usize::try_from(value).ok()?)?)
        }
        EntryKind::Imap => RawKey::Imap(reader.text(usize::try_from(value).ok()?)?),
    };
    let value = match key {
        RawKey::Vendor(_) | RawKey::Registered(_) => value_span(reader)?,
        RawKey::Dav(..) => dav_value_span(reader)?,
        RawKey::Imap(_) => {
            let start = *reader;
            reader.bytes()?;
            reader.consumed_since(&start)?
        }
    };
    Some(RawEntry { key, value })
}

impl RawKey<'_> {
    pub(crate) const fn kind(&self) -> EntryKind {
        match self {
            RawKey::Vendor(_) => EntryKind::JmapVendor,
            RawKey::Registered(_) => EntryKind::JmapRegistered,
            RawKey::Dav(..) => EntryKind::Dav,
            RawKey::Imap(_) => EntryKind::Imap,
        }
    }
}

impl<'x> Iterator for RawEntries<'x> {
    type Item = RawEntry<'x>;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        let entry = parse_entry(&mut self.reader);
        if entry.is_none() {
            self.remaining = 0;
        }
        entry
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

impl RawEntries<'_> {
    fn stop(&mut self) {
        self.remaining = 0;
    }
}

impl<'x> MetadataView<'x> {
    pub fn new(bytes: &'x [u8]) -> Option<Self> {
        validate(bytes)?;
        unsafe { Self::from_trusted(bytes) }
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn from_trusted(bytes: &'x [u8]) -> Option<Self> {
        let mut entries = unsafe { Reader::trusted(bytes) };
        let (kinds, count) = header(bytes, &mut entries)?;
        Some(MetadataView {
            bytes,
            kinds,
            count,
            entries,
        })
    }

    pub fn empty() -> Self {
        MetadataView {
            bytes: &EMPTY_CONTAINER,
            kinds: MetadataKinds::NONE,
            count: 0,
            entries: Reader::empty(),
        }
    }

    pub fn kinds(&self) -> MetadataKinds {
        self.kinds
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn as_bytes(&self) -> &'x [u8] {
        self.bytes
    }

    pub(crate) fn raw_entries(&self) -> RawEntries<'x> {
        RawEntries {
            reader: self.entries,
            remaining: self.count,
        }
    }

    fn entries_of(&self, kinds: MetadataKinds) -> RawEntries<'x> {
        if self.kinds.intersects(kinds) {
            self.raw_entries()
        } else {
            RawEntries {
                reader: Reader::empty(),
                remaining: 0,
            }
        }
    }

    pub fn jmap(&self) -> JmapEntries<'x> {
        JmapEntries {
            entries: self.entries_of(MetadataKinds::JMAP),
        }
    }

    pub fn jmap_namespace(&self, namespace: &Namespace<'_>) -> Option<JsonView<'x>> {
        let wanted = match namespace {
            Namespace::Registered(namespace) => RawKey::Registered(namespace.id),
            Namespace::Vendor(name) => RawKey::Vendor(name),
        };
        let mut entries = self.entries_of(MetadataKinds::JMAP);
        while let Some(entry) = entries.next() {
            if entry.key == wanted {
                return Some(JsonView::new(entry.value));
            } else if entry.key.kind() > wanted.kind() {
                entries.stop();
            }
        }
        None
    }

    pub fn dav(&self) -> DavEntries<'x> {
        DavEntries {
            entries: self.entries_of(MetadataKinds::DAV),
        }
    }

    pub fn dav_property(&self, name: &XmlName<'_>) -> Option<DavValueView<'x>> {
        self.dav()
            .find(|(entry, _)| entry.matches(name.namespace(), name.name()))
            .map(|(_, value)| value)
    }

    pub fn imap(&self) -> ImapEntries<'x> {
        ImapEntries {
            entries: self.entries_of(MetadataKinds::IMAP),
        }
    }

    pub fn imap_entry(&self, name: &str) -> Option<&'x [u8]> {
        self.imap()
            .find(|(entry, _)| *entry == name)
            .map(|(_, value)| value)
    }
}

impl<'x> Iterator for JmapEntries<'x> {
    type Item = (Namespace<'x>, JsonView<'x>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            let namespace = match entry.key {
                RawKey::Vendor(name) => Namespace::Vendor(name),
                RawKey::Registered(id) => match RegisteredNamespace::by_id(id) {
                    Some(namespace) => Namespace::Registered(namespace),
                    None => continue,
                },
                RawKey::Dav(..) | RawKey::Imap(_) => {
                    self.entries.stop();
                    return None;
                }
            };
            return Some((namespace, JsonView::new(entry.value)));
        }
    }
}

impl<'x> Iterator for DavEntries<'x> {
    type Item = (XmlName<'x>, DavValueView<'x>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            match entry.key {
                RawKey::Dav(namespace, name) => {
                    return Some((
                        XmlName::borrowed(namespace, name),
                        DavValueView::new(entry.value),
                    ));
                }
                RawKey::Imap(_) => {
                    self.entries.stop();
                    return None;
                }
                RawKey::Vendor(_) | RawKey::Registered(_) => {}
            }
        }
    }
}

impl<'x> Iterator for ImapEntries<'x> {
    type Item = (&'x str, &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.next()?;
            if let RawKey::Imap(name) = entry.key {
                let mut value = entry.value;
                return value.bytes().map(|value| (name, value));
            }
        }
    }
}
