/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::prelude::Property,
    types::{error::PatchError, string::StringValidator},
};
use jmap_tools::{JsonPointer, Value};
use std::fmt::Debug;
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

pub mod patch;
pub mod properties;
pub mod ser;

pub type JmapValue<'x> = Value<'x, Property, RegistryValue>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegistryValue {
    Id(Id),
    BlobId(BlobId),
    IdReference(String),
}

pub type PatchResult<'x> = Result<MaybeUnpatched<'x>, PatchError>;

pub enum MaybeUnpatched<'x> {
    Unpatched {
        property: Property,
        value: JmapValue<'x>,
    },
    UnpatchedMany {
        properties: VecMap<Property, JmapValue<'x>>,
    },
    Patched,
}

#[derive(Clone)]
pub struct JsonPointerPatch<'x> {
    ptr: &'x JsonPointer<Property>,
    pos: usize,
    validators: &'x [StringValidator],
    is_create: bool,
}

pub trait RegistryJsonPatch: Debug + Default {
    fn patch<'x>(&mut self, pointer: JsonPointerPatch<'_>, value: JmapValue<'x>)
    -> PatchResult<'x>;
}
pub trait RegistryJsonPropertyPatch: Debug + Default {
    fn patch_property<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x>;
}

pub trait RegistryJsonEnumPatch: Debug {
    fn patch<'x>(&mut self, pointer: JsonPointerPatch<'_>, value: JmapValue<'x>)
    -> PatchResult<'x>;
}

pub trait IntoValue {
    fn into_value(self) -> JmapValue<'static>;
}
