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

#[derive(Clone)]
pub struct JsonPointerPatch<'x> {
    ptr: &'x JsonPointer<Property>,
    pos: usize,
    validators: &'x [StringValidator],
    is_create: bool,
}

pub trait RegistryJsonPatch: Debug + Default {
    fn patch(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'_>,
    ) -> Result<(), PatchError>;
}
pub trait RegistryJsonPropertyPatch: Debug + Default {
    fn patch_property(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'_>,
    ) -> Result<(), PatchError>;
}

pub trait RegistryJsonEnumPatch: Debug {
    fn patch(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'_>,
    ) -> Result<(), PatchError>;
}

pub trait IntoValue {
    fn into_value(self) -> JmapValue<'static>;
}
