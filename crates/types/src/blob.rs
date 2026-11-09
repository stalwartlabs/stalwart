/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base32::STALWART;
use jmap_tools::{Element, Property, Value};
use std::{
    io::{Cursor, Write},
    ops::Range,
    str::FromStr,
    time::SystemTime,
};
use utils::codec::leb128::{Leb128, Leb128Iterator};

use crate::blob_hash::{BLOB_HASH_LEN, BlobHash};

const B_LINKED: u8 = 0x10;
const B_RESERVED: u8 = 0x20;
const B_EMBEDDED: u8 = 0x40;
const B_QUEUED: u8 = B_LINKED | B_RESERVED;
const B_CLASS_MASK: u8 = B_LINKED | B_RESERVED | B_EMBEDDED;
const B_NESTED: u8 = 0x80;
const ENCODING_MASK: u8 = 0x0F;
const ENCODING_NONE: u8 = 0;
const ENCODING_QUOTED_PRINTABLE: u8 = 1;
const ENCODING_BASE64: u8 = 2;
const MAX_LEB128_LEN: usize = 10;
const MAX_CLASS_LEN: usize = 2 * MAX_LEB128_LEN;
const MAX_RANGE_LEN: usize = 2 * MAX_LEB128_LEN;
const MAX_CONTAINER_LEN: usize = 1 + MAX_RANGE_LEN;
const MAX_SERIALIZED_LEN: usize = 1
    + BLOB_HASH_LEN
    + MAX_CLASS_LEN
    + MAX_RANGE_LEN
    + 1
    + MAX_SECTION_CONTAINERS * MAX_CONTAINER_LEN;

pub const MAX_SECTION_CONTAINERS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlobClass {
    Reserved {
        account_id: u32,
        expires: u64,
    },
    Linked {
        account_id: u32,
        collection: u8,
        document_id: u32,
    },
    Embedded {
        account_id: u32,
        collection: u8,
        document_id: u32,
    },
    Queued {
        queue_id: u64,
    },
}

impl Default for BlobClass {
    fn default() -> Self {
        BlobClass::Reserved {
            account_id: u32::MAX,
            expires: u64::MAX,
        }
    }
}

impl AsRef<BlobClass> for BlobClass {
    fn as_ref(&self) -> &BlobClass {
        self
    }
}

impl BlobClass {
    pub fn account_id(&self) -> u32 {
        match self {
            BlobClass::Reserved { account_id, .. }
            | BlobClass::Linked { account_id, .. }
            | BlobClass::Embedded { account_id, .. } => *account_id,
            BlobClass::Queued { .. } => u32::MAX,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            BlobClass::Reserved { expires, .. } => {
                *expires
                    > SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs())
            }
            BlobClass::Linked { .. } | BlobClass::Embedded { .. } | BlobClass::Queued { .. } => {
                true
            }
        }
    }

    pub fn is_superuser(&self) -> bool {
        matches!(self, BlobClass::Reserved { account_id, expires } if *account_id == u32::MAX && *expires == u64::MAX)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId {
    pub hash: BlobHash,
    pub class: BlobClass,
    pub section: Option<BlobSection>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncodedRange {
    pub offset_start: usize,
    pub size: usize,
    pub encoding: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobSection {
    Single(EncodedRange),
    Nested(Box<NestedSection>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NestedSection {
    containers: Vec<EncodedRange>,
    part: EncodedRange,
}

impl EncodedRange {
    pub fn new(offset_start: usize, size: usize, encoding: u8) -> Self {
        EncodedRange {
            offset_start,
            size,
            encoding,
        }
    }

    pub fn range(&self) -> Range<usize> {
        self.offset_start..self.offset_start.saturating_add(self.size)
    }

    pub fn is_encoded(&self) -> bool {
        self.encoding != ENCODING_NONE
    }

    pub fn is_container(&self) -> bool {
        matches!(self.encoding, ENCODING_QUOTED_PRINTABLE | ENCODING_BASE64)
    }

    fn shifted(self, shift: usize) -> Option<Self> {
        Some(EncodedRange {
            offset_start: self.offset_start.checked_add(shift)?,
            ..self
        })
    }

    fn marker(&self) -> u8 {
        self.encoding.saturating_add(1) & ENCODING_MASK
    }

    fn from_leb128<T>(it: &mut T, encoding: u8) -> Option<Self>
    where
        T: Leb128Iterator,
    {
        Some(EncodedRange {
            offset_start: it.next_leb128()?,
            size: it.next_leb128()?,
            encoding,
        })
    }

    fn write_range(&self, writer: &mut impl Write) {
        let _ = writer.write_all(&self.offset_start.to_leb128());
        let _ = writer.write_all(&self.size.to_leb128());
    }
}

impl BlobSection {
    pub fn new(offset_start: usize, size: usize, encoding: u8) -> Self {
        BlobSection::Single(EncodedRange::new(offset_start, size, encoding))
    }

    pub fn nested(containers: Vec<EncodedRange>, part: EncodedRange) -> Option<Self> {
        match containers.len() {
            0 => Some(BlobSection::Single(part)),
            1..=MAX_SECTION_CONTAINERS if containers.iter().all(EncodedRange::is_container) => {
                Some(BlobSection::Nested(Box::new(NestedSection {
                    containers,
                    part,
                })))
            }
            _ => None,
        }
    }

    pub fn part(&self) -> &EncodedRange {
        match self {
            BlobSection::Single(part) => part,
            BlobSection::Nested(nested) => &nested.part,
        }
    }

    pub fn containers(&self) -> &[EncodedRange] {
        match self {
            BlobSection::Single(_) => &[],
            BlobSection::Nested(nested) => &nested.containers,
        }
    }

    pub fn outermost(&self) -> &EncodedRange {
        self.containers().first().unwrap_or(self.part())
    }

    fn marker(&self) -> u8 {
        match self {
            BlobSection::Single(part) => part.marker(),
            BlobSection::Nested(nested) => B_NESTED | nested.part.marker(),
        }
    }

    fn from_leb128<T>(it: &mut T, marker: u8) -> Option<Option<Self>>
    where
        T: Leb128Iterator,
    {
        let Some(encoding) = (marker & ENCODING_MASK).checked_sub(1) else {
            return (marker & B_NESTED == 0).then_some(None);
        };
        let part = EncodedRange::from_leb128(it, encoding)?;
        if marker & B_NESTED == 0 {
            return Some(Some(BlobSection::Single(part)));
        }
        let count = usize::from(it.next()?);
        if !(1..=MAX_SECTION_CONTAINERS).contains(&count) {
            return None;
        }
        let mut containers = Vec::with_capacity(count);
        for _ in 0..count {
            let encoding = it.next()?;
            let container = EncodedRange::from_leb128(it, encoding)?;
            if !container.is_container() {
                return None;
            }
            containers.push(container);
        }
        BlobSection::nested(containers, part).map(Some)
    }

    fn write_levels(&self, writer: &mut impl Write) {
        self.part().write_range(writer);
        if let BlobSection::Nested(nested) = self {
            let _ = writer.write_all(&[nested.containers.len() as u8]);
            for container in &nested.containers {
                let _ = writer.write_all(&[container.encoding]);
                container.write_range(writer);
            }
        }
    }
}

impl FromStr for BlobId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BlobId::from_base32(s).ok_or(())
    }
}

impl BlobId {
    pub fn new(hash: BlobHash, class: BlobClass) -> Self {
        BlobId {
            hash,
            class,
            section: None,
        }
    }

    pub fn new_section(
        hash: BlobHash,
        class: BlobClass,
        offset_start: usize,
        offset_end: usize,
        encoding: impl Into<u8>,
    ) -> Self {
        BlobId {
            hash,
            class,
            section: BlobSection::new(offset_start, offset_end - offset_start, encoding.into())
                .into(),
        }
    }

    pub fn inner_part(&self, containers: &[EncodedRange], part: EncodedRange) -> Option<Self> {
        let (mut levels, shift) = match &self.section {
            None => (Vec::new(), 0),
            Some(section) => {
                let base = section.part();
                let mut levels = Vec::with_capacity(
                    section.containers().len() + usize::from(base.is_encoded()) + containers.len(),
                );
                levels.extend_from_slice(section.containers());
                if base.is_encoded() {
                    levels.push(*base);
                    (levels, 0)
                } else {
                    (levels, base.offset_start)
                }
            }
        };
        let part = match containers.split_first() {
            Some((first, rest)) => {
                levels.push(first.shifted(shift)?);
                levels.extend_from_slice(rest);
                part
            }
            None => part.shifted(shift)?,
        };
        Some(BlobId {
            hash: self.hash.clone(),
            class: self.class.clone(),
            section: Some(BlobSection::nested(levels, part)?),
        })
    }

    #[inline]
    pub fn from_base32(value: impl AsRef<[u8]>) -> Option<Self> {
        BlobId::from_iter(&mut STALWART.decoder(value.as_ref()))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(it: &mut T) -> Option<Self>
    where
        T: Leb128Iterator,
    {
        let class = it.next()?;

        let mut hash = BlobHash::default();
        for byte in hash.as_mut().iter_mut() {
            *byte = it.next()?;
        }

        BlobId {
            hash,
            class: match class & B_CLASS_MASK {
                B_QUEUED => BlobClass::Queued {
                    queue_id: it.next_leb128()?,
                },
                marker if marker & B_EMBEDDED != 0 => BlobClass::Embedded {
                    account_id: it.next_leb128()?,
                    collection: it.next()?,
                    document_id: it.next_leb128()?,
                },
                marker if marker & B_LINKED != 0 => BlobClass::Linked {
                    account_id: it.next_leb128()?,
                    collection: it.next()?,
                    document_id: it.next_leb128()?,
                },
                _ => BlobClass::Reserved {
                    account_id: it.next_leb128()?,
                    expires: it.next_leb128()?,
                },
            },
            section: BlobSection::from_leb128(it, class)?,
        }
        .into()
    }

    fn serialize_as(&self, writer: &mut impl Write) {
        let marker = self.section.as_ref().map_or(0, BlobSection::marker)
            | match self.class {
                BlobClass::Linked { .. } => B_LINKED,
                BlobClass::Embedded { .. } => B_EMBEDDED,
                BlobClass::Reserved { .. } => B_RESERVED,
                BlobClass::Queued { .. } => B_QUEUED,
            };

        let _ = writer.write_all(&[marker]);
        let _ = writer.write_all(self.hash.as_ref());

        match &self.class {
            BlobClass::Reserved {
                account_id,
                expires,
            } => {
                let _ = writer.write_all(&account_id.to_leb128());
                let _ = writer.write_all(&expires.to_leb128());
            }
            BlobClass::Linked {
                account_id,
                collection,
                document_id,
            }
            | BlobClass::Embedded {
                account_id,
                collection,
                document_id,
            } => {
                let _ = writer.write_all(&account_id.to_leb128());
                let _ = writer.write_all(&[*collection]);
                let _ = writer.write_all(&document_id.to_leb128());
            }
            BlobClass::Queued { queue_id } => {
                let _ = writer.write_all(&queue_id.to_leb128());
            }
        }

        if let Some(section) = &self.section {
            section.write_levels(writer);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hash.is_empty()
    }
}

impl serde::Serialize for BlobId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for BlobId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        BlobId::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid BlobId"))
    }
}

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = Cursor::new([0u8; MAX_SERIALIZED_LEN]);
        self.serialize_as(&mut bytes);
        let len = bytes.position() as usize;
        write!(
            f,
            "{}",
            STALWART.display(bytes.get_ref().get(..len).unwrap_or_default())
        )
    }
}

impl<'x, P: Property, E: Element + From<BlobId>> From<BlobId> for Value<'x, P, E> {
    fn from(id: BlobId) -> Self {
        Value::Element(E::from(id))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/types/src/blob/tests.rs"]
mod tests;
