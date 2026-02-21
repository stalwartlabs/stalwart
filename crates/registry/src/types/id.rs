/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{JsonPointerPatch, RegistryJsonPatch, RegistryValue},
    pickle::{Pickle, PickledStream},
    schema::prelude::ObjectType,
    types::{EnumImpl, error::PatchError},
};
use std::{fmt::Display, str::FromStr};
use types::{blob::BlobId, id::Id};

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
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
        out.extend_from_slice(&self.id().to_be_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<u64>()];
        arr.copy_from_slice(data.read_bytes(8)?);
        let id = u64::from_be_bytes(arr);

        Some(Id::new(id))
    }
}

impl RegistryJsonPatch for Id {
    fn patch(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: jmap_tools::Value<'_, crate::schema::prelude::Property, crate::jmap::RegistryValue>,
    ) -> Result<(), PatchError> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Element(RegistryValue::Id(value)), None) => {
                *self = value;
                Ok(())
            }
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = Id::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(())
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
    fn patch(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: jmap_tools::Value<'_, crate::schema::prelude::Property, crate::jmap::RegistryValue>,
    ) -> Result<(), PatchError> {
        match (value, pointer.next()) {
            (jmap_tools::Value::Element(RegistryValue::BlobId(value)), None) => {
                *self = value;
                Ok(())
            }
            (jmap_tools::Value::Str(value), None) => {
                if let Ok(new_value) = BlobId::from_str(value.as_ref()) {
                    *self = new_value;
                    Ok(())
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
