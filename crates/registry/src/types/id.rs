/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{
        IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonPatch,
        RegistryValue,
    },
    pickle::{Pickle, PickledStream},
    schema::prelude::ObjectType,
    types::{EnumImpl, error::PatchError},
};
use std::{fmt::Display, str::FromStr};
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::{BLOB_HASH_LEN, BlobHash},
    id::Id,
};

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, serde::Serialize)]
pub struct ObjectId {
    object: ObjectType,
    id: Id,
}

impl ObjectId {
    pub fn new(object: ObjectType, id: Id) -> Self {
        Self { object, id }
    }

    #[inline(always)]
    pub fn id(&self) -> Id {
        self.id
    }

    #[inline(always)]
    pub fn object(&self) -> ObjectType {
        self.object
    }

    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        self.id.is_valid()
    }
}

impl Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.object.as_str(), self.id)
    }
}

impl ObjectType {
    pub fn id(&self, id: Id) -> ObjectId {
        ObjectId::new(*self, id)
    }

    pub fn singleton(&self) -> ObjectId {
        ObjectId::new(*self, Id::singleton())
    }
}

impl Default for ObjectId {
    fn default() -> Self {
        ObjectId::new(ObjectType::Account, Id::default())
    }
}

impl Pickle for Id {
    fn pickle(&self, out: &mut Vec<u8>) {
        self.id().pickle(out);
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        u64::unpickle(data).map(Id::new)
    }
}

impl Pickle for BlobId {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.hash.as_slice());
    }

    fn unpickle(stream: &mut PickledStream<'_>) -> Option<Self> {
        stream.read_bytes(BLOB_HASH_LEN).map(|bytes| {
            BlobId::new(
                BlobHash::try_from_hash_slice(bytes).unwrap(),
                BlobClass::Reserved {
                    account_id: 0,
                    expires: 0,
                },
            )
        })
    }
}

impl RegistryJsonPatch for Id {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Element(RegistryValue::Id(value)), None) => {
                *self = value;
                Ok(MaybeUnpatched::Patched)
            }
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = Id::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(MaybeUnpatched::Patched)
                } else {
                    Err(PatchError::new(pointer, "Failed to parse Id from string"))
                }
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for Id, expected a string value",
            )),
        }
    }
}

impl RegistryJsonPatch for BlobId {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Element(RegistryValue::BlobId(value)), None) => {
                *self = value;
                Ok(MaybeUnpatched::Patched)
            }
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = BlobId::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(MaybeUnpatched::Patched)
                } else {
                    Err(PatchError::new(
                        pointer,
                        "Failed to parse BlobId from string",
                    ))
                }
            }
            _ => Err(PatchError::new(
                pointer,
                "Invalid path for BlobId, expected a string value",
            )),
        }
    }
}

impl IntoValue for Id {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Element(RegistryValue::Id(self))
    }
}

impl IntoValue for BlobId {
    fn into_value(self) -> JmapValue<'static> {
        JmapValue::Element(RegistryValue::BlobId(self))
    }
}
