/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::ahash_is_empty;
use crate::{
    error::set::SetError,
    object::{AnyId, blob::BlobProperty},
    request::{
        deserialize::{DeserializeArguments, deserialize_request},
        reference::MaybeIdReference,
    },
    response::Response,
};
use ahash::AHashMap;
use mail_parser::decoders::base64::base64_decode;
use serde::{Deserialize, Deserializer};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, Default)]
pub struct BlobUploadRequest {
    pub account_id: Id,
    pub create: VecMap<String, UploadObject>,
}

#[derive(Debug, Clone, Default)]
pub struct UploadObject {
    pub type_: Option<String>,
    pub data: Vec<DataSourceObject>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DataSourceObject {
    Id {
        id: MaybeIdReference<BlobId>,
        length: Option<usize>,
        offset: Option<usize>,
    },
    Value(Vec<u8>),
    #[default]
    Null,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobUploadResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "ahash_is_empty")]
    pub created: AHashMap<String, BlobUploadResponseObject>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError<BlobProperty>>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobUploadResponseObject {
    pub id: BlobId,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    pub size: usize,
}

impl<'de> DeserializeArguments<'de> for BlobUploadRequest {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"create" => {
                self.create = map.next_value()?;
            }
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for UploadObject {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"type" => {
                self.type_ = map.next_value()?;
            },
            b"data" => {
                self.data = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for DataSourceObject {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"data:asText" => {
                *self = DataSourceObject::Value(map.next_value::<String>().map(|v| v.into_bytes())?);
            },
            b"data:asBase64" => {
                *self = DataSourceObject::Value(base64_decode(map.next_value::<Cow<'_, str>>()?.as_bytes()).ok_or_else(|| serde::de::Error::custom("Failed to decode base64 data"))?);
            },
            b"blobId" => {
                match self {
                    DataSourceObject::Id { id, .. } => {
                        *id = map.next_value()?;
                    },
                    _ => {
                        *self = DataSourceObject::Id {
                            id: map.next_value()?,
                            length: None,
                            offset: None,
                        };
                    }
                }
            },
            b"offset" => {
                match self {
                    DataSourceObject::Id { offset, .. } => {
                        *offset = map.next_value()?;
                    },
                    _ => {
                        *self = DataSourceObject::Id {
                            id: MaybeIdReference::Invalid("".into()),
                            length: None,
                            offset: map.next_value()?,
                        };
                    }
                }
            },
            b"length" => {
                match self {
                    DataSourceObject::Id { length, .. } => {
                        *length = map.next_value()?;
                    },
                    _ => {
                        *self = DataSourceObject::Id {
                            id: MaybeIdReference::Invalid("".into()),
                            length: map.next_value()?,
                            offset: None,
                        };
                    }
                }
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl BlobUploadResponse {
    pub fn update_created_ids(&self, response: &mut Response) {
        for (user_id, obj) in &self.created {
            response
                .created_ids
                .insert(user_id.clone(), AnyId::BlobId(obj.id.clone()));
        }
    }
}

impl<'de> Deserialize<'de> for DataSourceObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<'de> Deserialize<'de> for UploadObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<'de> Deserialize<'de> for BlobUploadRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}
