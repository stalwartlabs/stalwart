/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::violation::namespace_path;
use crate::matches_id;
use jmap_proto::{
    error::set::SetError,
    object::{
        JmapObject,
        metadata::{MetadataProperty, MetadataRoot},
    },
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Map, Null, Property, Value};
use std::{cmp::Ordering, mem};
use types::{
    id::Id,
    metadata::{EncodedJson, JsonError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum PatchMode {
    Create,
    #[default]
    Update,
}

#[derive(Debug, Default)]
pub struct MetadataPatches {
    mode: PatchMode,
    pub(super) patches: Vec<Patch>,
}

#[derive(Debug)]
pub(super) struct Patch {
    pub key: PatchKey,
    pub value: PatchValue,
}

#[derive(Debug)]
pub(super) struct PatchKey {
    pub root: MetadataRoot,
    pub namespace: Option<String>,
    pub pointer: JsonPointer<Null>,
}

#[derive(Debug)]
pub(super) enum PatchValue {
    Remove,
    Set(Result<EncodedJson, InvalidValue>),
    Replace(Vec<Member>),
    Clear,
}

#[derive(Debug)]
pub(super) struct Member {
    pub namespace: String,
    pub value: Result<EncodedJson, InvalidValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InvalidValue {
    pub error: JsonError,
    pub depth: u32,
}

const MAX_VALUE_NESTING: u32 = 128;
const UNSUPPORTED: &str = "Metadata is not supported on this object.";

impl MetadataPatches {
    pub fn for_create() -> Self {
        MetadataPatches {
            mode: PatchMode::Create,
            patches: Vec::new(),
        }
    }

    pub fn for_update() -> Self {
        MetadataPatches {
            mode: PatchMode::Update,
            patches: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn has_shared(&self) -> bool {
        self.has_root(MetadataRoot::Shared)
    }

    pub fn has_private(&self) -> bool {
        self.has_root(MetadataRoot::Private)
    }

    fn has_root(&self, root: MetadataRoot) -> bool {
        self.patches.iter().any(|patch| patch.key.root == root)
    }

    pub(super) fn reject_unsupported<P, E>(object: &Value<'_, P, E>) -> Result<(), SetError<P>>
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        if !P::has_metadata(object) {
            return Ok(());
        }
        Err(SetError::invalid_properties()
            .with_properties(
                object
                    .as_object()
                    .into_iter()
                    .flat_map(|object| object.keys())
                    .filter_map(|key| key.as_property())
                    .filter(|property| property.metadata_root().is_some())
                    .cloned(),
            )
            .with_description(UNSUPPORTED))
    }

    pub(super) fn extract<P, E>(
        mut self,
        object: &mut Value<'_, P, E>,
    ) -> Result<Option<Self>, SetError<P>>
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        if !P::has_metadata(object) {
            return Ok(None);
        }
        let Value::Object(object) = object else {
            return Ok(None);
        };
        let entries = mem::take(object.as_mut_vec());
        let remaining = object.as_mut_vec();
        remaining.reserve(entries.len());
        for (key, value) in entries {
            match key {
                Key::Property(property) if property.metadata_root().is_some() => {
                    self.push(&property, value)?
                }
                key => remaining.push((key, value)),
            }
        }
        Ok(Some(self))
    }

    pub fn push<P, E>(&mut self, property: &P, value: Value<'_, P, E>) -> Result<(), SetError<P>>
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        let key = if let Some(root) = property.as_metadata_root() {
            PatchKey::root(root)
        } else if let Some((root, pointer)) = property.metadata_pointer() {
            PatchKey::parse(root, pointer)?
        } else {
            return Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("Not a metadata property."));
        };
        let root = key.root;

        let value = match (key.namespace.as_deref(), value) {
            (None, Value::Null) if self.mode == PatchMode::Create => {
                return Err(root_error(root, "Metadata must be an object on create."));
            }
            (None, Value::Null) => PatchValue::Replace(Vec::new()),
            (None, Value::Object(members)) => {
                let mut namespaces = Vec::with_capacity(members.len());
                for (namespace, value) in members.into_vec() {
                    let namespace = namespace.to_string().into_owned();
                    if !value.is_object() {
                        return Err(namespace_error(
                            root,
                            &namespace,
                            "Namespace values must be objects.",
                        ));
                    }
                    namespaces.push(Member {
                        value: encode(&value),
                        namespace,
                    });
                }
                PatchValue::Replace(namespaces)
            }
            (None, _) => return Err(root_error(root, "Metadata must be an object.")),
            (Some(_), _) if self.mode == PatchMode::Create => {
                return Err(root_error(
                    root,
                    "Metadata patches are not allowed on create.",
                ));
            }
            (Some(_), Value::Null) => PatchValue::Remove,
            (Some(namespace), value) if key.pointer.is_empty() && !value.is_object() => {
                return Err(namespace_error(
                    root,
                    namespace,
                    "Namespace values must be objects.",
                ));
            }
            (Some(_), value) => PatchValue::Set(encode(&value)),
        };

        self.patches.push(Patch { key, value });
        Ok(())
    }
}

impl PatchValue {
    pub(super) fn is_removal(&self) -> bool {
        match self {
            PatchValue::Remove | PatchValue::Clear => true,
            PatchValue::Replace(members) => members.is_empty(),
            PatchValue::Set(_) => false,
        }
    }
}

impl PatchKey {
    fn root(root: MetadataRoot) -> Self {
        PatchKey {
            root,
            namespace: None,
            pointer: JsonPointer::new(Vec::new()),
        }
    }

    fn parse<P: MetadataProperty>(
        root: MetadataRoot,
        pointer: &JsonPointer<P>,
    ) -> Result<Self, SetError<P>> {
        let mut segments = pointer.as_slice().iter().skip(1).map(|item| match item {
            JsonPointerItem::Key(key) => Ok(key.to_string().into_owned()),
            _ => Err(SetError::invalid_patch()
                .with_property(Key::Owned(pointer.to_string()))
                .with_description(format!(
                    "Invalid {} patch pointer {pointer}.",
                    root.as_str()
                ))),
        });
        let namespace = segments.next().transpose()?;
        let items = segments
            .map(|segment| segment.map(|segment| JsonPointerItem::Key(Key::Owned(segment))))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PatchKey {
            root,
            namespace,
            pointer: JsonPointer::new(items),
        })
    }

    pub fn cmp_path(&self, other: &Self) -> Ordering {
        root_rank(self.root)
            .cmp(&root_rank(other.root))
            .then_with(|| self.namespace.cmp(&other.namespace))
            .then_with(|| self.pointer.cmp(&other.pointer))
    }

    pub fn is_prefix_of(&self, other: &Self) -> bool {
        self.root == other.root
            && match (&self.namespace, &other.namespace) {
                (None, _) => true,
                (Some(namespace), Some(other_namespace)) => {
                    namespace == other_namespace
                        && other
                            .pointer
                            .as_slice()
                            .starts_with(self.pointer.as_slice())
                }
                (Some(_), None) => false,
            }
    }

    pub fn is_deep(&self) -> bool {
        !self.pointer.is_empty()
    }

    pub fn to_path(&self) -> String {
        let mut path = JsonPointer::<Null>::encode(
            [self.root.as_str()]
                .into_iter()
                .chain(self.namespace.as_deref()),
        );
        if !self.pointer.is_empty() {
            path.push('/');
            path.push_str(&self.pointer.to_string());
        }
        path
    }
}

fn encode<P: Property, E: Element<Property = P>>(
    value: &Value<'_, P, E>,
) -> Result<EncodedJson, InvalidValue> {
    EncodedJson::encode(value).map_err(|error| InvalidValue {
        error,
        depth: value_depth(value, 0),
    })
}

pub(super) fn value_depth<P: Property, E: Element<Property = P>>(
    value: &Value<'_, P, E>,
    nesting: u32,
) -> u32 {
    if nesting >= MAX_VALUE_NESTING {
        return nesting;
    }
    match value {
        Value::Object(object) => {
            1 + object
                .values()
                .map(|value| value_depth(value, nesting + 1))
                .max()
                .unwrap_or_default()
        }
        Value::Array(items) => items
            .iter()
            .map(|value| value_depth(value, nesting + 1))
            .max()
            .unwrap_or_default(),
        _ => 0,
    }
}

pub fn is_empty_update<T: JmapObject>(object: &Map<'_, T::Property, T::Element>, id: Id) -> bool {
    object.iter().all(|(key, value)| {
        matches!(key, Key::Property(property) if *property == T::ID_PROPERTY)
            && matches_id(value, id)
    })
}

fn root_rank(root: MetadataRoot) -> u8 {
    match root {
        MetadataRoot::Shared => 0,
        MetadataRoot::Private => 1,
    }
}

fn root_error<P: MetadataProperty>(root: MetadataRoot, description: &'static str) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(P::from_metadata_root(root))
        .with_description(description)
}

fn namespace_error<P: MetadataProperty>(
    root: MetadataRoot,
    namespace: &str,
    description: &'static str,
) -> SetError<P> {
    SetError::invalid_properties()
        .with_property(Key::Owned(namespace_path(root, namespace)))
        .with_description(description)
}
