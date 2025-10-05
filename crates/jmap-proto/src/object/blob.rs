/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId, MaybeReference, parse_ref},
    request::deserialize::DeserializeArguments,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct Blob;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobProperty {
    Id,
    BlobId,
    Type,
    Size,
    Digest(DigestProperty),
    Data(DataProperty),
    IsEncodingProblem,
    IsTruncated,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestProperty {
    Sha,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataProperty {
    AsText,
    AsBase64,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobValue {
    BlobId(BlobId),
    IdReference(String),
}

impl Property for BlobProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        BlobProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            BlobProperty::BlobId => "blobId",
            BlobProperty::Id => "id",
            BlobProperty::Size => "size",
            BlobProperty::Type => "type",
            BlobProperty::IsEncodingProblem => "isEncodingProblem",
            BlobProperty::IsTruncated => "isTruncated",
            BlobProperty::Data(data) => match data {
                DataProperty::AsText => "data:asText",
                DataProperty::AsBase64 => "data:asBase64",
                DataProperty::Default => "data",
            },
            BlobProperty::Digest(digest) => match digest {
                DigestProperty::Sha => "digest:sha",
                DigestProperty::Sha256 => "digest:sha-256",
                DigestProperty::Sha512 => "digest:sha-512",
            },
        }
        .into()
    }
}

impl Element for BlobValue {
    type Property = BlobProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                BlobProperty::BlobId => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(BlobValue::BlobId(v)),
                    MaybeReference::Reference(v) => Some(BlobValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            BlobValue::BlobId(blob_id) => blob_id.to_string().into(),
            BlobValue::IdReference(r) => format!("#{r}").into(),
        }
    }
}

impl BlobProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"blobId" => BlobProperty::BlobId,
            b"id" => BlobProperty::Id,
            b"size" => BlobProperty::Size,
            b"type" => BlobProperty::Type,
            b"isEncodingProblem" => BlobProperty::IsEncodingProblem,
            b"isTruncated" => BlobProperty::IsTruncated,
            b"data:asText" => BlobProperty::Data(DataProperty::AsText),
            b"data:asBase64" => BlobProperty::Data(DataProperty::AsBase64),
            b"data" => BlobProperty::Data(DataProperty::Default),
            b"digest:sha" => BlobProperty::Digest(DigestProperty::Sha),
            b"digest:sha-256" => BlobProperty::Digest(DigestProperty::Sha256),
            b"digest:sha-512" => BlobProperty::Digest(DigestProperty::Sha512),
        )
    }
}

impl FromStr for BlobProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BlobProperty::parse(s).ok_or(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct BlobGetArguments {
    pub offset: Option<usize>,
    pub length: Option<usize>,
}

impl<'de> DeserializeArguments<'de> for BlobGetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
             b"offset" => {
                self.offset = map.next_value()?;
            },
            b"length" => {
                self.length = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl JmapObject for Blob {
    type Property = BlobProperty;

    type Element = BlobValue;

    type Id = BlobId;

    type Filter = ();

    type Comparator = ();

    type GetArguments = BlobGetArguments;

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = BlobProperty::Id;
}

impl From<BlobId> for BlobValue {
    fn from(id: BlobId) -> Self {
        BlobValue::BlobId(id)
    }
}

impl JmapObjectId for BlobValue {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            BlobValue::BlobId(id) => Some(AnyId::BlobId(id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let BlobValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::BlobId(id) = new_id {
            *self = BlobValue::BlobId(id);
            return true;
        }
        false
    }
}

impl JmapObjectId for BlobProperty {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<AnyId> {
        None
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        false
    }
}
