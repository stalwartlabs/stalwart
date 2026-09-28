/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::DocumentId;
use jmap_tools::{Element, Property, Value};
use encodify::base32::{STALWART, U64Text};
use std::{ops::Deref, str::FromStr};

#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Copy,
    PartialOrd,
    Ord,
)]
#[rkyv(derive(Debug), compare(PartialEq))]
#[repr(transparent)]
pub struct Id(u64);

impl Default for Id {
    fn default() -> Self {
        Id(u64::MAX)
    }
}

impl FromStr for Id {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        STALWART.decode_u64(s).map(Id).map_err(|_| ())
    }
}

impl From<&ArchivedId> for Id {
    fn from(value: &ArchivedId) -> Self {
        Id(value.0.to_native())
    }
}

impl Id {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn singleton() -> Self {
        Self::new(20080258862541)
    }

    pub fn as_string(&self) -> String {
        self.text().as_str().to_string()
    }

    pub fn text(&self) -> U64Text {
        STALWART.encode_u64(self.0)
    }

    #[inline(always)]
    pub fn from_parts(prefix_id: DocumentId, doc_id: DocumentId) -> Id {
        Id(((prefix_id as u64) << 32) | doc_id as u64)
    }

    #[inline(always)]
    pub fn id(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub fn document_id(&self) -> DocumentId {
        self.0 as DocumentId
    }

    #[inline(always)]
    pub fn prefix_id(&self) -> DocumentId {
        (self.0 >> 32) as DocumentId
    }

    #[inline(always)]
    pub fn is_singleton(&self) -> bool {
        self.0 == 20080258862541
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.0 != u64::MAX
    }
}

impl From<u64> for Id {
    fn from(id: u64) -> Self {
        Id(id)
    }
}

impl From<u32> for Id {
    fn from(id: u32) -> Self {
        Id(id as u64)
    }
}

impl From<Id> for u64 {
    fn from(id: Id) -> Self {
        id.0
    }
}

impl From<&Id> for u64 {
    fn from(id: &Id) -> Self {
        id.0
    }
}

impl From<(u32, u32)> for Id {
    fn from(id: (u32, u32)) -> Self {
        Id::from_parts(id.0, id.1)
    }
}

impl Deref for Id {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<u64> for Id {
    fn as_ref(&self) -> &u64 {
        &self.0
    }
}

impl From<Id> for u32 {
    fn from(id: Id) -> Self {
        id.document_id()
    }
}

impl From<Id> for String {
    fn from(id: Id) -> Self {
        id.as_string()
    }
}

impl serde::Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.text().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Id::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid JMAP ID"))
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text().as_str())
    }
}

impl<'x, P: Property, E: Element + From<Id>> From<Id> for Value<'x, P, E> {
    fn from(id: Id) -> Self {
        Value::Element(E::from(id))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::id::Id;

    #[test]
    fn parse_jmap_id() {
        for number in [
            0,
            1,
            10,
            1000,
            Id::singleton().id(),
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let id = Id::from(number);
            assert_eq!(Id::from_str(&id.to_string()).unwrap(), id);
        }
    }

    #[test]
    fn text_renders_base32() {
        for (value, text) in [
            (0, "a"),
            (1, "b"),
            (31, "3"),
            (32, "ba"),
            (33, "bb"),
            (1023, "33"),
            (1024, "baa"),
            ((1 << 60) - 1, "333333333333"),
            (1 << 60, "baaaaaaaaaaaa"),
            (1 << 63, "iaaaaaaaaaaaa"),
            (u64::MAX - 1, "p333333333331"),
            (u64::MAX, "p333333333333"),
            (Id::singleton().id(), "singleton"),
            (Id::from_parts(1000, 5000).id(), "d0aaaae2i"),
        ] {
            let id = Id::from(value);
            assert_eq!(id.text().as_str(), text);
            assert_eq!(id.as_string(), text);
            assert_eq!(id.to_string(), text);
            assert_eq!(format!("{id:>20}"), text);
            assert_eq!(Id::from_str(text), Ok(id));
        }
    }

    #[test]
    fn parse_rejects_invalid_text() {
        for text in [
            "",
            "p333333333333p333333333333",
            "baaaaaaaaaaaaa",
            "q333333333333",
            "Singleton",
            "SINGLETON",
            "a-b",
        ] {
            assert_eq!(Id::from_str(text), Err(()), "{text:?}");
        }
        assert_eq!(Id::from_str("aaaaaaaaaaaab"), Ok(Id::from(1u64)));
    }
}
