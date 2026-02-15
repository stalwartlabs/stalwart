/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{JsonPointerPatch, RegistryJsonPatch, RegistryValue},
    pickle::{Pickle, PickledStream},
    schema::prelude::Object,
    types::{EnumType, error::PatchError},
};
use std::{fmt::Display, str::FromStr};
use types::{blob::BlobId, id::Id};

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct ObjectId {
    object: Object,
    id: u64,
}

impl ObjectId {
    pub fn new(object: Object, id: impl Into<u64>) -> Self {
        Self {
            object,
            id: id.into(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn object(&self) -> Object {
        self.object
    }

    pub fn is_valid(&self) -> bool {
        self.id != u64::MAX
    }
}

impl Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.object.as_str(), Id::new(self.id))
    }
}

impl Object {
    pub fn id(&self, id: u64) -> ObjectId {
        ObjectId::new(*self, id)
    }

    pub fn singleton(&self) -> ObjectId {
        ObjectId::new(*self, 20080258862541u64)
    }
}

impl Default for ObjectId {
    fn default() -> Self {
        ObjectId::new(Object::Account, u64::MAX)
    }
}

impl Pickle for Id {
    fn pickle(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id().to_le_bytes());
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        let mut arr = [0u8; std::mem::size_of::<u64>()];
        arr.copy_from_slice(data.read_bytes(8)?);
        let id = u64::from_le_bytes(arr);

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
