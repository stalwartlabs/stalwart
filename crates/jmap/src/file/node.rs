/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::{acl::JmapRights, parent_ref::ParentRef};
use common::storage::dav::{
    FILE_KIND_DIRECTORY, FILE_KIND_FILE, FILE_KIND_SYMLINK, FORBIDDEN_FILE_NAME_CHARS,
    FORBIDDEN_FILE_NODE_NAMES, MAX_DAV_FILE_NAME_LEN,
};
use groupware::file::{
    FileNode, FileNodeContent, FileNodeRole, FileProperties,
    symlink::{SymlinkTargetBuilder, symlink_target_elements},
};
use jmap_proto::{
    error::set::SetError,
    object::{
        AnyId,
        file_node::{self, FileNodeNodeType, FileNodeProperty, FileNodeValue},
        metadata::MetadataProperty,
    },
    references::resolve::ResolveCreatedReference,
};
use jmap_tools::{JsonPointerItem, Key, Value};
use std::borrow::Cow;
use store::write::now;
use types::{acl::AclGrant, blob::BlobId, blob_hash::BlobHash, id::Id, media_type};

pub(crate) const MAX_NAME_LEN: usize = MAX_DAV_FILE_NAME_LEN;
const MEDIA_TYPE_OCTET_STREAM: &str = "application/octet-stream";

#[derive(Debug, Default)]
pub(super) struct NodePatch {
    pub name: Option<String>,
    pub parent: Option<ParentRef>,
    pub kind: Option<u8>,
    pub blob_id: Option<Option<BlobId>>,
    pub target: Option<Option<String>>,
    pub size: Option<u64>,
    pub media_type: Option<Option<String>>,
    pub executable: Option<bool>,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub role: Option<Option<FileNodeRole>>,
    pub subscribed: Option<bool>,
    pub acls: Option<Vec<AclGrant>>,
    pub my_rights: Option<Value<'static, FileNodeProperty, FileNodeValue>>,
    pub server_modified: bool,
    pub server_accessed: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct PatchEffects {
    pub renamed: bool,
    pub moved: bool,
    pub content: bool,
    pub acls: bool,
    pub role: bool,
    pub subscription: bool,
}

impl PatchEffects {
    pub fn changes_node(&self) -> bool {
        self.renamed || self.moved || self.content || self.acls || self.role
    }
}

pub(super) struct ResolvedBlob {
    pub hash: BlobHash,
    pub size: u32,
}

impl NodePatch {
    pub fn parse<R: ResolveCreatedReference<FileNodeProperty, FileNodeValue>>(
        expected_id: Option<Id>,
        updates: Value<'_, FileNodeProperty, FileNodeValue>,
        node: &FileNode,
        is_create: bool,
        resolver: &R,
    ) -> Result<Self, SetError<FileNodeProperty>> {
        let mut patch = NodePatch::default();

        for (property, mut value) in updates.into_expanded_object() {
            let Key::Property(property) = property else {
                return Err(SetError::invalid_properties()
                    .with_property(property.to_owned())
                    .with_description("Invalid property."));
            };

            resolver.resolve_self_references(&mut value, 0, false)?;

            match (property, value) {
                (property, _) if property.metadata_root().is_some() => todo!(),
                (FileNodeProperty::Name, Value::Str(value)) => {
                    validate_name(&value)?;
                    patch.name = Some(value.into_owned());
                }
                (FileNodeProperty::ParentId, Value::Element(FileNodeValue::Id(value))) => {
                    patch.parent = Some(ParentRef::from_id(value));
                }
                (FileNodeProperty::ParentId, Value::Null) => {
                    patch.parent = Some(ParentRef::ROOT);
                }
                (FileNodeProperty::NodeType, Value::Str(value)) => {
                    let kind = FileNodeNodeType::parse(&value)
                        .map(node_type_id)
                        .ok_or_else(|| {
                            invalid(FileNodeProperty::NodeType, "Unsupported nodeType.")
                        })?;
                    if !is_create && kind != node.kind_id() {
                        return Err(invalid(
                            FileNodeProperty::NodeType,
                            "nodeType is immutable after creation.",
                        ));
                    }
                    patch.kind = Some(kind);
                }
                (FileNodeProperty::BlobId, Value::Element(FileNodeValue::BlobId(value))) => {
                    patch.blob_id = Some(Some(value));
                }
                (FileNodeProperty::BlobId, Value::Null) => {
                    patch.blob_id = Some(None);
                }
                (FileNodeProperty::Target, Value::Array(elements)) => {
                    let mut builder = SymlinkTargetBuilder::with_capacity(
                        elements
                            .iter()
                            .map(|e| e.as_str().map_or(0, |s| s.len() + 1))
                            .sum(),
                    );
                    for element in elements {
                        let Value::Str(element) = element else {
                            return Err(invalid(
                                FileNodeProperty::Target,
                                "target elements must be strings.",
                            ));
                        };
                        builder
                            .push(&element)
                            .map_err(|err| invalid(FileNodeProperty::Target, err.description()))?;
                    }
                    patch.target =
                        Some(Some(builder.build().map_err(|err| {
                            invalid(FileNodeProperty::Target, err.description())
                        })?));
                }
                (FileNodeProperty::Target, Value::Null) => {
                    patch.target = Some(None);
                }
                (FileNodeProperty::Size, Value::Number(value))
                    if let Some(size) = value.as_u64() =>
                {
                    patch.size = Some(size);
                }
                (FileNodeProperty::Size, Value::Null) => {}
                (FileNodeProperty::Type, Value::Str(value)) => {
                    if !media_type::is_valid_media_type(&value) {
                        return Err(invalid(
                            FileNodeProperty::Type,
                            "type is not a valid media type.",
                        ));
                    }
                    patch.media_type = Some(Some(value.into_owned()));
                }
                (FileNodeProperty::Type, Value::Null) => {
                    patch.media_type = Some(None);
                }
                (FileNodeProperty::Executable, Value::Bool(value)) => {
                    patch.executable = Some(value);
                }
                (FileNodeProperty::Executable, Value::Null) => {
                    patch.executable = Some(false);
                }
                (FileNodeProperty::Created, Value::Element(FileNodeValue::Date(value))) => {
                    patch.created = Some(value.timestamp());
                }
                (FileNodeProperty::Modified, Value::Element(FileNodeValue::Date(value))) => {
                    patch.modified = Some(value.timestamp());
                }
                (FileNodeProperty::Modified, Value::Null) => {
                    patch.modified = Some(now() as i64);
                    patch.server_modified = true;
                }
                (FileNodeProperty::Accessed, Value::Element(FileNodeValue::Date(value))) => {
                    patch.accessed = Some(value.timestamp());
                }
                (FileNodeProperty::Accessed, Value::Null) => {
                    patch.accessed = Some(now() as i64);
                    patch.server_accessed = true;
                }
                (FileNodeProperty::Role, Value::Str(value)) => {
                    patch.role =
                        Some(Some(FileNodeRole::parse(&value).ok_or_else(|| {
                            invalid(FileNodeProperty::Role, "Unsupported role.")
                        })?));
                }
                (FileNodeProperty::Role, Value::Null) => {
                    patch.role = Some(None);
                }
                (FileNodeProperty::IsSubscribed, Value::Bool(value)) => {
                    patch.subscribed = Some(value);
                }
                (FileNodeProperty::IsSubscribed, Value::Null) => {
                    patch.subscribed = Some(true);
                }
                (FileNodeProperty::ShareWith, value) => {
                    patch.acls = Some(JmapRights::acl_set::<file_node::FileNode>(value)?);
                }
                (FileNodeProperty::Pointer(pointer), value)
                    if matches!(
                        pointer.first(),
                        Some(JsonPointerItem::Key(Key::Property(
                            FileNodeProperty::ShareWith
                        )))
                    ) =>
                {
                    let mut pointer = pointer.iter();
                    pointer.next();
                    let current = patch.acls.take().unwrap_or_else(|| node.acls.clone());
                    patch.acls = Some(JmapRights::acl_patch::<file_node::FileNode>(
                        current, pointer, value,
                    )?);
                }
                (FileNodeProperty::Id, value) => {
                    if !expected_id.is_some_and(|expected| crate::matches_id(&value, expected)) {
                        return Err(invalid(
                            FileNodeProperty::Id,
                            "The id property is immutable.",
                        ));
                    }
                }
                (FileNodeProperty::Changed, Value::Element(FileNodeValue::Date(value)))
                    if !is_create && value.timestamp() == node.changed => {}
                (FileNodeProperty::Changed, _) => {
                    return Err(invalid(
                        FileNodeProperty::Changed,
                        "changed is server-set and not settable by clients.",
                    ));
                }
                (FileNodeProperty::MyRights, value @ Value::Object(_)) if !is_create => {
                    patch.my_rights = Some(value.into_owned());
                }
                (property, _) => {
                    return Err(invalid(property, "Field could not be set."));
                }
            }
        }

        Ok(patch)
    }

    pub fn echoes_type(&self) -> bool {
        match &self.media_type {
            Some(Some(media_type)) => {
                media_type::media_type_essence(media_type).as_deref() != Some(media_type.as_str())
            }
            Some(None) | None => true,
        }
    }

    pub fn blob_to_resolve(&self, node: &FileNode) -> Option<&BlobId> {
        self.blob_id
            .as_ref()
            .and_then(Option::as_ref)
            .filter(|blob_id| {
                blob_id.section.is_some()
                    || node
                        .file()
                        .is_none_or(|file| file.blob_hash != blob_id.hash)
            })
    }

    pub fn apply(
        self,
        node: &mut FileNode,
        is_create: bool,
        blob: Option<ResolvedBlob>,
        personal_id: u32,
    ) -> Result<PatchEffects, SetError<FileNodeProperty>> {
        let mut effects = PatchEffects::default();
        let current_kind = node.kind_id();
        let kind = if is_create {
            let inferred = if matches!(self.blob_id, Some(Some(_))) || node.file().is_some() {
                FILE_KIND_FILE
            } else if matches!(self.target, Some(Some(_))) || node.symlink_target().is_some() {
                FILE_KIND_SYMLINK
            } else {
                FILE_KIND_DIRECTORY
            };
            match self.kind {
                Some(kind) if kind != inferred => {
                    return Err(invalid(
                        FileNodeProperty::NodeType,
                        match kind {
                            FILE_KIND_FILE => "file nodes require a blobId.",
                            FILE_KIND_SYMLINK => "symlink nodes require a target.",
                            _ => "directory nodes cannot have a blobId or target.",
                        },
                    ));
                }
                _ => inferred,
            }
        } else {
            current_kind
        };

        match kind {
            FILE_KIND_FILE => {
                if matches!(self.blob_id, Some(None)) {
                    return Err(invalid(
                        FileNodeProperty::BlobId,
                        "blobId cannot be null for file nodes.",
                    ));
                } else if self.target.as_ref().is_some_and(Option::is_some) {
                    return Err(invalid(
                        FileNodeProperty::Target,
                        "target must be null for file nodes.",
                    ));
                } else if self.role.as_ref().is_some_and(Option::is_some) {
                    return Err(invalid(
                        FileNodeProperty::Role,
                        "role must be null for file nodes.",
                    ));
                }
                let mut file = match std::mem::take(&mut node.content) {
                    FileNodeContent::File(file) => file,
                    _ => FileProperties::default(),
                };
                if let Some(blob) = blob {
                    file.blob_hash = blob.hash;
                    file.size = blob.size;
                    effects.content = true;
                } else if file.blob_hash.is_empty() {
                    return Err(invalid(
                        FileNodeProperty::BlobId,
                        "blobId is required for file nodes.",
                    ));
                }
                if let Some(size) = self.size
                    && size != file.size as u64
                {
                    return Err(invalid(
                        FileNodeProperty::Size,
                        "size does not match the size of the blob.",
                    ));
                }
                if let Some(media_type) = self.media_type {
                    effects.content |= file.media_type != media_type;
                    file.media_type = media_type;
                }
                if let Some(executable) = self.executable {
                    effects.content |= file.executable != executable;
                    file.executable = executable;
                }
                node.content = FileNodeContent::File(file);
            }
            _ => {
                if matches!(self.blob_id, Some(Some(_))) {
                    return Err(invalid(
                        FileNodeProperty::BlobId,
                        "blobId must be null for directory and symlink nodes.",
                    ));
                } else if self.size.is_some() {
                    return Err(invalid(
                        FileNodeProperty::Size,
                        "size must be null for directory and symlink nodes.",
                    ));
                } else if matches!(self.media_type, Some(Some(_))) {
                    return Err(invalid(
                        FileNodeProperty::Type,
                        "type must be null for directory and symlink nodes.",
                    ));
                } else if self.executable == Some(true) {
                    return Err(invalid(
                        FileNodeProperty::Executable,
                        "executable may only be set on file nodes.",
                    ));
                }

                if kind == FILE_KIND_SYMLINK {
                    if self.role.as_ref().is_some_and(Option::is_some) {
                        return Err(invalid(
                            FileNodeProperty::Role,
                            "role must be null for symlink nodes.",
                        ));
                    }
                    match self.target {
                        Some(Some(target)) => {
                            effects.content |= node.symlink_target() != Some(target.as_str());
                            node.content = FileNodeContent::Symlink(target);
                        }
                        Some(None) => {
                            return Err(invalid(
                                FileNodeProperty::Target,
                                "target cannot be null for symlink nodes.",
                            ));
                        }
                        None if node.symlink_target().is_none() => {
                            return Err(invalid(
                                FileNodeProperty::Target,
                                "target is required for symlink nodes.",
                            ));
                        }
                        None => {}
                    }
                } else if self.target.as_ref().is_some_and(Option::is_some) {
                    return Err(invalid(
                        FileNodeProperty::Target,
                        "target must be null for directory nodes.",
                    ));
                } else {
                    node.content = FileNodeContent::Directory;
                }
            }
        }

        if let Some(role) = self.role {
            effects.role = node.role != role;
            node.role = role;
        }
        if let Some(name) = self.name
            && name != node.name
        {
            node.name = name;
            effects.renamed = true;
        }
        if let Some(parent) = self.parent {
            effects.moved = parent != ParentRef::from_stored(node.parent_id) || parent.is_pending();
            node.parent_id = parent.as_stored();
        }
        if let Some(created) = self.created {
            effects.content |= node.created != created;
            node.created = created;
        }
        if let Some(modified) = self.modified {
            effects.content |= node.modified != modified;
            node.modified = modified;
        }
        if let Some(accessed) = self.accessed {
            effects.content |= node.accessed != accessed;
            node.accessed = accessed;
        }
        if let Some(subscribed) = self.subscribed
            && node.is_subscribed(personal_id) != subscribed
        {
            node.set_subscribed(personal_id, subscribed);
            effects.subscription = true;
        }
        if let Some(acls) = self.acls {
            effects.acls = node.acls != acls;
            node.acls = acls;
        }

        if node.name.is_empty() {
            return Err(invalid(FileNodeProperty::Name, "Missing name."));
        }

        Ok(effects)
    }
}

pub(crate) fn validate_name(name: &str) -> Result<(), SetError<FileNodeProperty>> {
    if !(1..=MAX_NAME_LEN).contains(&name.len()) {
        Err(invalid(
            FileNodeProperty::Name,
            "Name must be between 1 and 255 octets.",
        ))
    } else if name.contains(|c: char| FORBIDDEN_FILE_NAME_CHARS.contains(c) || c.is_control()) {
        Err(invalid(
            FileNodeProperty::Name,
            "Name contains a forbidden character.",
        ))
    } else if is_reserved_name(name) {
        Err(invalid(
            FileNodeProperty::Name,
            "Name is reserved and cannot be used.",
        ))
    } else {
        Ok(())
    }
}

fn is_reserved_name(name: &str) -> bool {
    let stem = match name.split_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => name,
    };
    FORBIDDEN_FILE_NODE_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name) || reserved.eq_ignore_ascii_case(stem))
}

pub(super) fn node_type_id(node_type: FileNodeNodeType) -> u8 {
    match node_type {
        FileNodeNodeType::File => FILE_KIND_FILE,
        FileNodeNodeType::Directory => FILE_KIND_DIRECTORY,
        FileNodeNodeType::Symlink => FILE_KIND_SYMLINK,
    }
}

pub(super) fn node_type_from_id(kind: u8) -> FileNodeNodeType {
    match kind {
        FILE_KIND_FILE => FileNodeNodeType::File,
        FILE_KIND_SYMLINK => FileNodeNodeType::Symlink,
        _ => FileNodeNodeType::Directory,
    }
}

pub(super) fn target_value(target: &str) -> Value<'static, FileNodeProperty, FileNodeValue> {
    Value::Array(
        symlink_target_elements(target)
            .map(|element| Value::Str(Cow::Owned(element.to_string())))
            .collect(),
    )
}

pub(super) fn default_media_type() -> &'static str {
    MEDIA_TYPE_OCTET_STREAM
}

pub(super) fn invalid(
    property: FileNodeProperty,
    description: &'static str,
) -> SetError<FileNodeProperty> {
    SetError::invalid_properties()
        .with_property(property)
        .with_description(description)
}

pub(super) struct NoResolver;

impl ResolveCreatedReference<FileNodeProperty, FileNodeValue> for NoResolver {
    fn get_created_id(&self, _: &str) -> Option<AnyId> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names() {
        for name in ["CON", "con.txt", "Aux.tar.gz", "..", ".", "LPT9.log"] {
            assert!(is_reserved_name(name), "{name}");
        }
        for name in ["console.txt", ".bashrc", "auxiliary", "com10", "a.con"] {
            assert!(!is_reserved_name(name), "{name}");
        }
        assert!(validate_name("a\u{1}b").is_err());
        assert!(validate_name(&"a".repeat(256)).is_err());
        assert!(validate_name("ok name (1).txt").is_ok());
    }

    #[test]
    fn size_is_an_unsigned_int() {
        let node = FileNode::default();
        for (size, expected) in [("5", Some(5)), ("-5", None), ("5.5", None)] {
            let json = format!(r#"{{"size": {size}}}"#);
            let updates = Value::parse_json(&json).expect("valid JSON");
            assert_eq!(
                NodePatch::parse(None, updates, &node, true, &NoResolver)
                    .ok()
                    .and_then(|patch| patch.size),
                expected,
                "{size}"
            );
        }
    }
}
