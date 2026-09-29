/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base32::STALWART;
use jmap_tools::{Element, Property, Value};
use std::{borrow::Borrow, io::Cursor, ops::Range, str::FromStr, time::SystemTime};
use utils::codec::leb128::{Leb128Iterator, Leb128Writer};

use crate::blob_hash::{BLOB_HASH_LEN, BlobHash};

const B_LINKED: u8 = 0x10;
const B_RESERVED: u8 = 0x20;
const B_EMBEDDED: u8 = 0x40;
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
            BlobClass::Linked { .. } | BlobClass::Embedded { .. } => true,
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

    fn from_leb128<T, U>(it: &mut T, encoding: u8) -> Option<Self>
    where
        T: Iterator<Item = U> + Leb128Iterator<U>,
        U: Borrow<u8>,
    {
        Some(EncodedRange {
            offset_start: it.next_leb128()?,
            size: it.next_leb128()?,
            encoding,
        })
    }

    fn write_range(&self, writer: &mut impl Leb128Writer) {
        let _ = writer.write_leb128(self.offset_start);
        let _ = writer.write_leb128(self.size);
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

    fn from_leb128<T, U>(it: &mut T, marker: u8) -> Option<Option<Self>>
    where
        T: Iterator<Item = U> + Leb128Iterator<U>,
        U: Borrow<u8>,
    {
        let Some(encoding) = (marker & ENCODING_MASK).checked_sub(1) else {
            return (marker & B_NESTED == 0).then_some(None);
        };
        let part = EncodedRange::from_leb128(it, encoding)?;
        if marker & B_NESTED == 0 {
            return Some(Some(BlobSection::Single(part)));
        }
        let count = usize::from(*it.next()?.borrow());
        if !(1..=MAX_SECTION_CONTAINERS).contains(&count) {
            return None;
        }
        let mut containers = Vec::with_capacity(count);
        for _ in 0..count {
            let encoding = *it.next()?.borrow();
            let container = EncodedRange::from_leb128(it, encoding)?;
            if !container.is_container() {
                return None;
            }
            containers.push(container);
        }
        BlobSection::nested(containers, part).map(Some)
    }

    fn write_levels(&self, writer: &mut impl Leb128Writer) {
        self.part().write_range(writer);
        if let BlobSection::Nested(nested) = self {
            let _ = writer.write(&[nested.containers.len() as u8]);
            for container in &nested.containers {
                let _ = writer.write(&[container.encoding]);
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
    pub fn from_iter<T, U>(it: &mut T) -> Option<Self>
    where
        T: Iterator<Item = U> + Leb128Iterator<U>,
        U: Borrow<u8>,
    {
        let class = *it.next()?.borrow();

        let mut hash = BlobHash::default();
        for byte in hash.as_mut().iter_mut() {
            *byte = *it.next()?.borrow();
        }

        let account_id: u32 = it.next_leb128()?;

        BlobId {
            hash,
            class: if (class & B_EMBEDDED) != 0 {
                BlobClass::Embedded {
                    account_id,
                    collection: *it.next()?.borrow(),
                    document_id: it.next_leb128()?,
                }
            } else if (class & B_LINKED) != 0 {
                BlobClass::Linked {
                    account_id,
                    collection: *it.next()?.borrow(),
                    document_id: it.next_leb128()?,
                }
            } else {
                BlobClass::Reserved {
                    account_id,
                    expires: it.next_leb128()?,
                }
            },
            section: BlobSection::from_leb128(it, class)?,
        }
        .into()
    }

    fn serialize_as(&self, writer: &mut impl Leb128Writer) {
        let marker = self.section.as_ref().map_or(0, BlobSection::marker)
            | match self.class {
                BlobClass::Linked { .. } => B_LINKED,
                BlobClass::Embedded { .. } => B_EMBEDDED,
                BlobClass::Reserved { .. } => B_RESERVED,
            };

        let _ = writer.write(&[marker]);
        let _ = writer.write(self.hash.as_ref());

        match &self.class {
            BlobClass::Reserved {
                account_id,
                expires,
            } => {
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write_leb128(*expires);
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
                let _ = writer.write_leb128(*account_id);
                let _ = writer.write(&[*collection]);
                let _ = writer.write_leb128(*document_id);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_id_round_trip() {
        let hash = BlobHash::generate(b"embedded");
        for class in [
            BlobClass::Reserved {
                account_id: 7,
                expires: 1_900_000_000,
            },
            BlobClass::Linked {
                account_id: 7,
                collection: 3,
                document_id: 42,
            },
            BlobClass::Embedded {
                account_id: 7,
                collection: 3,
                document_id: 42,
            },
        ] {
            let blob_id = BlobId::new(hash.clone(), class);
            assert_eq!(BlobId::from_str(&blob_id.to_string()), Ok(blob_id.clone()));

            let section = BlobId::new_section(hash.clone(), blob_id.class.clone(), 5, 17, 2u8);
            assert_eq!(BlobId::from_str(&section.to_string()), Ok(section));
        }
    }

    fn linked() -> BlobId {
        BlobId::new(
            BlobHash::generate(b"message"),
            BlobClass::Linked {
                account_id: 7,
                collection: 3,
                document_id: 300,
            },
        )
    }

    fn with_section(section: BlobSection) -> BlobId {
        BlobId {
            section: Some(section),
            ..linked()
        }
    }

    #[test]
    fn single_sections_keep_their_encoding() {
        let blob_id =
            BlobId::new_section(linked().hash, linked().class, 1_000, 1_000 + 70_000, 2u8);
        let mut expected = vec![B_LINKED | 3];
        expected.extend_from_slice(blob_id.hash.as_ref());
        expected.extend_from_slice(&[7, 3, 0xAC, 0x02, 0xE8, 0x07, 0xF0, 0xA2, 0x04]);
        assert_eq!(
            blob_id.to_string(),
            STALWART.display(expected.as_slice()).to_string()
        );
    }

    #[test]
    fn nested_sections_round_trip() {
        let part = EncodedRange::new(300, 45, 1);
        for containers in [
            vec![EncodedRange::new(1_000, 70_000, 2)],
            vec![
                EncodedRange::new(1_000, 70_000, 2),
                EncodedRange::new(12, 4_000, 2),
            ],
            vec![EncodedRange::new(usize::MAX, usize::MAX, 1); MAX_SECTION_CONTAINERS],
        ] {
            let section = BlobSection::nested(containers.clone(), part).expect("nested");
            assert_eq!(section.containers(), containers.as_slice());
            assert_eq!(section.part(), &part);
            assert_eq!(section.outermost(), &containers[0]);
            let blob_id = with_section(section);
            let encoded = blob_id.to_string();
            assert!(encoded.len() <= MAX_SERIALIZED_LEN * 8 / 5 + 1);
            assert_eq!(BlobId::from_str(&encoded), Ok(blob_id));
        }
        let widest = BlobId {
            hash: BlobHash::generate(b"widest"),
            class: BlobClass::Reserved {
                account_id: u32::MAX,
                expires: u64::MAX,
            },
            section: BlobSection::nested(
                vec![EncodedRange::new(usize::MAX, usize::MAX, 2); MAX_SECTION_CONTAINERS],
                EncodedRange::new(usize::MAX, usize::MAX, 14),
            ),
        };
        let mut bytes = Vec::new();
        widest.serialize_as(&mut bytes);
        assert!(bytes.len() <= MAX_SERIALIZED_LEN);
        assert_eq!(BlobId::from_str(&widest.to_string()), Ok(widest));

        let single = BlobSection::nested(vec![], part).expect("single");
        assert_eq!(single, BlobSection::Single(part));
        assert_eq!(single.outermost(), &part);
        assert!(BlobSection::nested(vec![part; MAX_SECTION_CONTAINERS + 1], part).is_none());
    }

    #[test]
    fn hostile_nested_sections_are_rejected() {
        let valid = with_section(
            BlobSection::nested(vec![EncodedRange::new(1, 2, 2)], EncodedRange::new(3, 4, 0))
                .expect("nested"),
        );
        let mut bytes = Vec::new();
        valid.serialize_as(&mut bytes);
        let parse = |bytes: &[u8]| BlobId::from_base32(STALWART.display(bytes).to_string());
        assert_eq!(parse(&bytes), Some(valid));

        let count_at = bytes.len() - 4;
        for count in [0, MAX_SECTION_CONTAINERS as u8 + 1, u8::MAX] {
            let mut forged = bytes.clone();
            forged[count_at] = count;
            assert_eq!(parse(&forged), None, "count {count}");
        }
        for len in 1..bytes.len() {
            assert_eq!(parse(&bytes[..len]), None, "truncated at {len}");
        }
        let mut no_part = bytes.clone();
        no_part[0] &= !ENCODING_MASK;
        assert_eq!(parse(&no_part), None);
    }

    #[test]
    fn nested_sections_accept_only_encoded_containers() {
        let part = EncodedRange::new(3, 4, 0);
        for encoding in 0..=u8::MAX {
            let containers = vec![EncodedRange::new(1, 2, encoding); MAX_SECTION_CONTAINERS];
            let is_container = matches!(encoding, 1 | 2);
            assert_eq!(
                BlobSection::nested(containers.clone(), part).is_some(),
                is_container,
                "encoding {encoding}"
            );
            let mut bytes = Vec::new();
            with_section(
                BlobSection::nested(
                    vec![EncodedRange::new(1, 2, 1); MAX_SECTION_CONTAINERS],
                    part,
                )
                .expect("nested"),
            )
            .serialize_as(&mut bytes);
            let first_container = bytes.len() - MAX_SECTION_CONTAINERS * 3;
            for container in 0..MAX_SECTION_CONTAINERS {
                bytes[first_container + container * 3] = encoding;
            }
            let forged = BlobId::from_base32(STALWART.display(bytes.as_slice()).to_string());
            assert_eq!(forged.is_some(), is_container, "encoding {encoding}");
            if let Some(forged) = forged {
                assert!(
                    forged
                        .section
                        .expect("section")
                        .containers()
                        .iter()
                        .all(EncodedRange::is_container)
                );
            }
        }
    }

    #[test]
    fn inner_parts_compose_with_the_parsed_section() {
        let part = EncodedRange::new(10, 20, 2);
        let container = EncodedRange::new(100, 200, 1);
        let inner = |base: &BlobId, containers: &[EncodedRange]| {
            base.inner_part(containers, part)
                .and_then(|blob_id| blob_id.section)
        };

        assert_eq!(inner(&linked(), &[]), Some(BlobSection::Single(part)));
        assert_eq!(
            inner(&linked(), &[container]),
            BlobSection::nested(vec![container], part)
        );

        let identity = with_section(BlobSection::new(5_000, 900, 0));
        assert_eq!(inner(&identity, &[]), Some(BlobSection::new(5_010, 20, 2)));
        assert_eq!(
            inner(&identity, &[container]),
            BlobSection::nested(vec![EncodedRange::new(5_100, 200, 1)], part)
        );

        let encoded = EncodedRange::new(5_000, 900, 2);
        let base64 = with_section(BlobSection::Single(encoded));
        assert_eq!(
            inner(&base64, &[]),
            BlobSection::nested(vec![encoded], part)
        );
        assert_eq!(
            inner(&base64, &[container]),
            BlobSection::nested(vec![encoded, container], part)
        );

        let outer = EncodedRange::new(1, 2, 1);
        let nested = with_section(
            BlobSection::nested(vec![outer], EncodedRange::new(7, 9, 0)).expect("nested"),
        );
        assert_eq!(
            inner(&nested, &[container]),
            BlobSection::nested(vec![outer, EncodedRange::new(107, 200, 1)], part)
        );
        let nested = with_section(BlobSection::nested(vec![outer], encoded).expect("nested"));
        assert_eq!(
            inner(&nested, &[]),
            BlobSection::nested(vec![outer, encoded], part)
        );

        let deepest = with_section(
            BlobSection::nested(vec![outer; MAX_SECTION_CONTAINERS], encoded).expect("nested"),
        );
        assert_eq!(inner(&deepest, &[]), None);
        assert_eq!(
            with_section(BlobSection::new(usize::MAX, 1, 0)).inner_part(&[], part),
            None
        );
        for blob_id in [linked(), identity, base64, nested] {
            let composed = blob_id.inner_part(&[container], part).expect("composed");
            assert_eq!(composed.hash, blob_id.hash);
            assert_eq!(composed.class, blob_id.class);
        }
    }
}
