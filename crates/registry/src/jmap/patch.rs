/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::{
        JmapValue, JsonPointerPatch, MaybeUnpatched, PatchResult, RegistryJsonEnumPatch,
        RegistryJsonPatch, RegistryJsonPropertyPatch, RegistryValue,
    },
    schema::prelude::Property,
    types::{
        EnumImpl,
        error::PatchError,
        string::{StringValidator, StringValidatorResult},
    },
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Value};
use std::fmt::Debug;
use utils::map::vec_map::VecMap;

impl<'x> JsonPointerPatch<'x> {
    pub fn new(ptr: &'x JsonPointer<Property>) -> Self {
        Self {
            ptr,
            pos: 0,
            validators: &[],
            is_create: false,
        }
    }

    pub fn cloned(&self) -> Self {
        Self {
            ptr: self.ptr,
            pos: 0,
            validators: &[],
            is_create: false,
        }
    }

    pub fn with_create(mut self, is_create: bool) -> Self {
        self.is_create = is_create;
        self
    }

    pub fn with_validators(mut self, validators: &'x [StringValidator]) -> Self {
        self.validators = validators;
        self
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&JsonPointerItem<Property>> {
        self.ptr.as_slice().get(self.pos).inspect(|_| self.pos += 1)
    }

    pub fn next_property(&mut self) -> Option<Property> {
        self.next().and_then(|item| {
            if let JsonPointerItem::Key(Key::Property(prop)) = item {
                Some(*prop)
            } else {
                None
            }
        })
    }

    pub fn peek(&self) -> Option<&JsonPointerItem<Property>> {
        self.ptr.as_slice().get(self.pos)
    }

    pub fn path(&self) -> String {
        self.ptr.to_string()
    }

    pub fn has_next(&self) -> bool {
        self.ptr.as_slice().len() > self.pos
    }

    pub fn assert_eof(&self) -> PatchResult<'static> {
        if self.has_next() {
            Err(PatchError::new(self.cloned(), "Invalid JSON Pointer path"))
        } else {
            Ok(MaybeUnpatched::Patched)
        }
    }

    pub fn assert_read_only(self) -> Result<Self, PatchError> {
        if self.is_create {
            Ok(self)
        } else {
            Err(PatchError::new(
                self.cloned(),
                "Cannot modify read-only property",
            ))
        }
    }
}

impl<T: RegistryJsonPatch> RegistryJsonPatch for Option<T> {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Value::Null = value {
            *self = None;
            pointer.assert_eof()
        } else if let Some(inner) = self {
            inner.patch(pointer, value)
        } else {
            let mut inner = T::default();
            inner.patch(pointer, value).inspect(|_| *self = Some(inner))
        }
    }
}

impl<T: RegistryJsonEnumPatch + Default> RegistryJsonEnumPatch for Option<T> {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Value::Null = value {
            *self = None;
            pointer.assert_eof()
        } else if let Some(inner) = self {
            inner.patch(pointer, value)
        } else {
            let mut inner = T::default();
            inner.patch(pointer, value).inspect(|_| *self = Some(inner))
        }
    }
}

impl RegistryJsonPatch for String {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(value) = value.into_string().filter(|v| !v.is_empty()) {
            let mut value = value.into_owned();

            for validator in pointer.validators {
                match validator.validate(&value) {
                    StringValidatorResult::Valid => {}
                    StringValidatorResult::Replace(new_value) => value = new_value,
                    StringValidatorResult::Invalid(err) => {
                        return Err(PatchError::new(pointer, err));
                    }
                }
            }

            *self = value;
            pointer.assert_eof()
        } else {
            Err(PatchError::new(pointer, "Invalid value for property."))
        }
    }
}

impl RegistryJsonPatch for bool {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(new_value) = value.as_bool() {
            *self = new_value;
            pointer.assert_eof()
        } else {
            Err(PatchError::new(
                pointer,
                "Invalid value for boolean property (expected true or false)",
            ))
        }
    }
}

impl RegistryJsonPatch for u64 {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(new_value) = value.as_u64() {
            *self = new_value;
            pointer.assert_eof()
        } else {
            Err(PatchError::new(
                pointer,
                "Invalid value for unsigned integer property (expected non-negative integer)",
            ))
        }
    }
}

impl RegistryJsonPatch for i64 {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(new_value) = value.as_i64() {
            *self = new_value;
            pointer.assert_eof()
        } else {
            Err(PatchError::new(
                pointer,
                "Invalid value for signed integer property (expected integer)",
            ))
        }
    }
}

impl RegistryJsonPatch for trc::Key {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: super::JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(new_value) = value.as_str().and_then(|v| trc::Key::try_parse(v.as_ref())) {
            *self = new_value;
            pointer.assert_eof()
        } else {
            Err(PatchError::new(
                pointer,
                format!("Invalid value {:?} for enum type {:?}.", value, self),
            ))
        }
    }
}

impl<T: EnumImpl> RegistryJsonEnumPatch for T {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if let Some(new_value) = value.as_str().and_then(|v| T::parse(v.as_ref())) {
            *self = new_value;
            pointer.assert_eof()
        } else {
            Err(PatchError::new(
                pointer,
                format!("Invalid value {:?} for enum type {:?}.", value, self),
            ))
        }
    }
}

impl<T: RegistryJsonPatch> RegistryJsonPatch for Vec<T> {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (pointer.next(), value) {
            (Some(JsonPointerItem::Number(idx)), Value::Null) => {
                if *idx < self.len() as u64 {
                    self.remove(*idx as usize);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Number(idx)), value) => {
                if let Some(inner) = self.get_mut(*idx as usize) {
                    return inner.patch(pointer, value);
                } else if *idx == self.len() as u64 {
                    let mut inner = T::default();
                    return inner.patch(pointer, value).inspect(|_| self.push(inner));
                }
            }
            (None, Value::Array(items)) => {
                self.clear();
                for item in items {
                    let mut inner = T::default();
                    inner.patch(pointer.clone(), item)?;
                    self.push(inner);
                }
                return Ok(MaybeUnpatched::Patched);
            }
            _ => {}
        }

        Err(PatchError::new(pointer, "Invalid value for array property"))
    }
}

impl<T: RegistryJsonEnumPatch + Default> RegistryJsonEnumPatch for Vec<T> {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (pointer.next(), value) {
            (Some(JsonPointerItem::Number(idx)), Value::Null) => {
                if *idx < self.len() as u64 {
                    self.remove(*idx as usize);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Number(idx)), value) => {
                if let Some(inner) = self.get_mut(*idx as usize) {
                    return inner.patch(pointer, value);
                } else if *idx == self.len() as u64 {
                    let mut inner = T::default();
                    return inner.patch(pointer, value).inspect(|_| self.push(inner));
                }
            }
            (None, Value::Array(items)) => {
                self.clear();
                for item in items {
                    let mut inner = T::default();
                    inner.patch(pointer.clone(), item)?;
                    self.push(inner);
                }
                return Ok(MaybeUnpatched::Patched);
            }
            _ => {}
        }

        Err(PatchError::new(pointer, "Invalid value for array property"))
    }
}

impl<K: MapItem, V: RegistryJsonPatch> RegistryJsonPatch for VecMap<K, V> {
    fn patch<'x>(
        &mut self,
        mut pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        match (pointer.next(), value) {
            (Some(JsonPointerItem::Number(idx)), Value::Null) => {
                if let Some(key) = K::try_from_integer(*idx) {
                    self.remove(&key);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Key(key)), Value::Null) => {
                if let Some(key) = K::try_from_string(key.to_string().as_ref()) {
                    self.remove(&key);
                    return Ok(MaybeUnpatched::Patched);
                }
            }
            (Some(JsonPointerItem::Key(key)), value) => {
                if let Some(key) = K::try_from_string(key.to_string().as_ref()) {
                    return self.get_mut_or_insert(key).patch(pointer, value);
                }
            }
            (Some(JsonPointerItem::Number(idx)), value) => {
                if let Some(key) = K::try_from_integer(*idx) {
                    return self.get_mut_or_insert(key).patch(pointer, value);
                }
            }
            (None, Value::Object(items)) => {
                self.clear();
                for (key, value) in items.into_vec() {
                    if let Some(key) = K::try_from_string(key.to_string().as_ref()) {
                        let mut inner = V::default();
                        inner.patch(pointer.clone(), value)?;
                        self.set(key, inner);
                    } else {
                        return Err(PatchError::new(
                            pointer.clone(),
                            "Invalid key for object property",
                        ));
                    }
                }
                return Ok(MaybeUnpatched::Patched);
            }
            _ => {}
        }

        Err(PatchError::new(
            pointer,
            "Invalid value for object property",
        ))
    }
}

impl<T: RegistryJsonPropertyPatch> RegistryJsonPatch for T {
    fn patch<'x>(
        &mut self,
        pointer: JsonPointerPatch<'_>,
        value: JmapValue<'x>,
    ) -> PatchResult<'x> {
        if pointer.has_next() {
            self.patch_property(pointer, value)
        } else if let Some(object) = value.into_object() {
            let mut ptr = JsonPointer::new(vec![JsonPointerItem::Root]);
            let mut unpatched = VecMap::new();
            for (key, value) in object.into_vec() {
                if let Some(property) = key.as_property() {
                    ptr.as_mut_slice()[0] = JsonPointerItem::Key(Key::Property(*property));
                    match self.patch_property(JsonPointerPatch::new(&ptr), value) {
                        Ok(MaybeUnpatched::Patched) => {}
                        Ok(MaybeUnpatched::Unpatched { property, value }) => {
                            unpatched.append(property, value);
                        }
                        Ok(MaybeUnpatched::UnpatchedMany { properties }) => {
                            unpatched.extend(properties.into_iter());
                        }
                        Err(mut e) => {
                            if !e.path.is_empty() {
                                e.path = format!("{}/{}", e.path, property.as_str());
                            } else {
                                e.path = property.as_str().to_string();
                            }
                            return Err(e);
                        }
                    }
                } else {
                    return Err(PatchError::new(pointer.clone(), "Invalid key for object"));
                }
            }
            if unpatched.is_empty() {
                Ok(MaybeUnpatched::Patched)
            } else {
                Ok(MaybeUnpatched::UnpatchedMany {
                    properties: unpatched,
                })
            }
        } else {
            Err(PatchError::new(pointer, "Invalid value type for object"))
        }
    }
}

trait MapItem: Sized + PartialEq + Eq + Debug {
    fn try_from_string(value: &str) -> Option<Self>;
    fn try_from_integer(value: u64) -> Option<Self>;
}

impl MapItem for String {
    fn try_from_string(value: &str) -> Option<Self> {
        let value = value.trim();
        if !value.is_empty() {
            Some(value.to_string())
        } else {
            None
        }
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        Some(value.to_string())
    }
}

impl MapItem for u32 {
    fn try_from_string(value: &str) -> Option<Self> {
        value.parse().ok()
    }

    fn try_from_integer(value: u64) -> Option<Self> {
        value.try_into().ok()
    }
}

impl<T: EnumImpl> MapItem for T {
    fn try_from_string(value: &str) -> Option<Self> {
        Self::parse(value)
    }

    fn try_from_integer(_: u64) -> Option<Self> {
        None
    }
}

pub fn object_type<T: EnumImpl>(
    pointer: &JsonPointerPatch<'_>,
    value: &Value<'_, Property, RegistryValue>,
) -> Result<T, PatchError> {
    value
        .as_object()
        .and_then(|obj| obj.get(&jmap_tools::Key::Property(Property::Type)))
        .and_then(|v| v.as_str())
        .and_then(|v| T::parse(v.as_ref()))
        .ok_or_else(|| {
            PatchError::new(
                pointer.clone(),
                "Missing or invalid '@type' property in object",
            )
        })
}
