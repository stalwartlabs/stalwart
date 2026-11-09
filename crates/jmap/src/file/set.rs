/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    get::{date_value, my_rights},
    node::{NodePatch, PatchEffects, default_media_type, invalid},
    writer::{Claim, FileNodeWriter, NodeRef, Placement, Rejection, WriteOptions, fetch_archive},
};
use crate::{
    api::{
        metadata::{
            MetadataAccess, MetadataPatches, MetadataTarget, MetadataType, NewMetadata,
            ObjectMetadata, PreparedMetadata, is_empty_update, reject_uncommitted,
        },
        parent_ref::{CreateResolver, ParentRef},
    },
    changes::state::JmapCacheState,
};
use common::{
    Server,
    auth::AccessToken,
    storage::dav::{FILE_KIND_DIRECTORY, FilePresence},
};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::{
        AnyId,
        file_node::{self, FileNodeProperty, FileNodeValue},
    },
    references::resolve::ResolveCreatedReference,
    request::{MaybeInvalid, capability::CapabilityIds},
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use std::borrow::Cow;
use store::{
    ahash::{AHashMap, AHashSet},
    write::{Archive, ArchiveBytes, Slot},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
    id::Id,
    media_type::media_type_essence,
};
use utils::map::bitmap::Bitmap;

pub trait FileNodeSet: Sync + Send {
    fn file_node_set(
        &self,
        request: SetRequest<'_, file_node::FileNode>,
        access_token: &AccessToken,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<SetResponse<file_node::FileNode>>> + Send;
}

pub(super) type NodeValues = Map<'static, FileNodeProperty, FileNodeValue>;

pub(super) struct PreparedCreate {
    create_id: String,
    slot: Slot,
    node: FileNode,
    parent: ParentRef,
    omitted: Omitted,
    metadata: Option<PreparedMetadata>,
}

struct PreparedUpdate {
    id: Id,
    archive: Archive<ArchiveBytes>,
    node: FileNode,
    parent: ParentRef,
    previous: (ParentRef, String),
    effects: PatchEffects,
    growth: u64,
    report_size: bool,
    echo: Omitted,
    metadata: Option<PreparedMetadata>,
}

enum Planned {
    Create(PreparedCreate),
    Update(PreparedUpdate),
}

#[derive(Debug, Default, Clone, Copy)]
struct Omitted {
    media_type: bool,
    executable: bool,
    created: bool,
    modified: bool,
    accessed: bool,
    subscribed: bool,
}

impl Omitted {
    fn is_empty(&self) -> bool {
        !(self.media_type
            || self.executable
            || self.created
            || self.modified
            || self.accessed
            || self.subscribed)
    }

    fn insert_into(&self, node: &FileNode, values: &mut NodeValues) {
        if let Some(file) = node.file() {
            if self.media_type {
                values.insert_unchecked(
                    Key::Property(FileNodeProperty::MediaType),
                    Value::Str(normalized_media_type(file.media_type.as_deref())),
                );
            }
            if self.executable {
                values.insert_unchecked(
                    Key::Property(FileNodeProperty::Executable),
                    Value::Bool(file.executable),
                );
            }
        }
        for (is_echoed, property, timestamp) in [
            (self.created, FileNodeProperty::Created, node.created),
            (self.modified, FileNodeProperty::Modified, node.modified),
            (self.accessed, FileNodeProperty::Accessed, node.accessed),
        ] {
            if is_echoed {
                values.insert_unchecked(Key::Property(property), date_value(Some(timestamp)));
            }
        }
        if self.subscribed {
            values.insert_unchecked(
                Key::Property(FileNodeProperty::IsSubscribed),
                Value::Bool(true),
            );
        }
    }
}

pub(super) struct CreatedNode {
    pub create_id: String,
    pub slot: Slot,
    pub values: NodeValues,
}

enum RejectedKey {
    Create(String),
    Update(Id),
}

impl FileNodeSet for Server {
    async fn file_node_set(
        &self,
        mut request: SetRequest<'_, file_node::FileNode>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
        using: CapabilityIds,
    ) -> trc::Result<SetResponse<file_node::FileNode>> {
        let account_id = request.account_id.document_id();
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::FileNode);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(sampled.assert_state(cache.get_state(false), &request.if_in_state)?);
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let options = WriteOptions {
            on_exists: request.arguments.on_exists,
            remove_children: request
                .arguments
                .on_destroy_remove_children
                .unwrap_or(false),
            case_insensitive: request
                .arguments
                .compare_case_insensitively
                .unwrap_or(false),
        };
        let mut writer =
            FileNodeWriter::new(self, access_token, account_id, &cache, options, metadata);
        if request.has_creates()
            || request.update.as_ref().is_some_and(|updates| {
                updates.values().any(|object| {
                    object.as_object().is_some_and(|object| {
                        object.contains_key(&Key::Property(FileNodeProperty::BlobId))
                    })
                })
            })
        {
            writer = writer.with_quota().await?;
        }

        let moving = request
            .update
            .as_ref()
            .map(|updates| {
                updates
                    .iter()
                    .filter_map(|(id, object)| match id {
                        MaybeInvalid::Value(id)
                            if object.as_object().is_some_and(|object| {
                                object.contains_key(&Key::Property(FileNodeProperty::ParentId))
                            }) =>
                        {
                            Some(id.document_id())
                        }
                        _ => None,
                    })
                    .collect::<AHashSet<_>>()
            })
            .unwrap_or_default();
        let (destroy_groups, not_destroyed) = writer.plan_destroys(will_destroy, &moving);
        for (id, err) in not_destroyed {
            response.not_destroyed.append(id, err);
        }

        let mut planned = Vec::new();
        let mut pending_creates: AHashMap<String, Slot> = AHashMap::new();
        for (create_id, object) in request.unwrap_create() {
            let resolver = CreateResolver::new(&pending_creates);
            match prepare_create(
                &mut writer,
                create_id,
                FileNode::default(),
                object,
                &resolver,
                None,
            )
            .await?
            {
                Ok(create) => {
                    pending_creates.insert(create.create_id.clone(), create.slot);
                    planned.push(Planned::Create(create));
                }
                Err((create_id, err)) => response.not_created.append(create_id, err),
            }
        }

        writer
            .metadata
            .preload_updates(self, request.update.as_ref(), |document_id| {
                cache
                    .resources
                    .find_any(document_id)
                    .map(|resource| resource.metadata_kinds())
            })
            .await?;
        for (id, mut object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue;
                }
            };
            let patches = match writer
                .metadata
                .extract(MetadataPatches::for_update(), &mut object)
            {
                Ok(patches) => patches,
                Err(err) => {
                    response.not_updated.append(id, err);
                    continue;
                }
            };
            let resolver = CreateResolver::new(&pending_creates);
            match prepare_update(&mut writer, id, object, patches, &resolver).await? {
                Ok(update) => planned.push(Planned::Update(update)),
                Err(err) => response.not_updated.append(id, err),
            }
        }

        let mut created = Vec::new();
        let mut awaiting_existing = Vec::new();
        let mut unprocessed = planned
            .iter()
            .map(Planned::node_ref)
            .collect::<AHashSet<_>>();
        let mut allow_defer = true;
        while !planned.is_empty() {
            let pending = planned.len();
            let mut deferred = Vec::new();
            for mut item in planned {
                let node_ref = item.node_ref();
                match item.place(&mut writer, allow_defer.then_some(&unprocessed)) {
                    Claim::Deferred => deferred.push(item),
                    Claim::Rejected(rejection) => {
                        unprocessed.remove(&node_ref);
                        let key = item.reject(&mut writer);
                        match rejection.existing {
                            Some(slot) => awaiting_existing.push((key, rejection.error, slot)),
                            None => key.append(&mut response, rejection.error),
                        }
                    }
                    Claim::Accepted { renamed } => {
                        unprocessed.remove(&node_ref);
                        match item {
                            Planned::Create(create) => {
                                created.push(commit_create(&mut writer, create, renamed)?);
                            }
                            Planned::Update(update) => {
                                let id = update.id;
                                let values = commit_update(&mut writer, update, renamed)?;
                                response.updated.append(id, values);
                            }
                        }
                    }
                }
            }
            if deferred.len() == pending {
                for index in resolve_name_cycles(&mut writer, &deferred)
                    .into_iter()
                    .rev()
                {
                    if let Planned::Update(update) = deferred.remove(index) {
                        unprocessed.remove(&NodeRef::Node(update.id.document_id()));
                        let id = update.id;
                        let values = commit_update(&mut writer, update, false)?;
                        response.updated.append(id, values);
                    }
                }
            }
            allow_defer = deferred.len() < pending;
            planned = deferred;
        }

        let (destroyed, not_destroyed) = writer.execute_destroys(destroy_groups).await?;
        response.destroyed.extend(destroyed);
        for (id, err) in not_destroyed {
            response.not_destroyed.append(id, err);
        }
        writer.finish();

        if !writer.batch.is_empty() {
            let assigned_ids = match writer.metadata.commit(self, writer.batch).await {
                Ok(assigned_ids) => assigned_ids,
                Err(err) if err.is_assertion_failure() => {
                    reject_uncommitted(
                        &mut response,
                        created.into_iter().map(|create| create.create_id),
                        "Another process modified this file node, please try again.",
                    );
                    for (key, err, _) in awaiting_existing {
                        key.append(&mut response, err);
                    }
                    return Ok(response);
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            };

            for (key, err, slot) in awaiting_existing {
                key.append(
                    &mut response,
                    err.with_existing_id(Id::from(assigned_ids.slot(slot))),
                );
            }
            for create in created {
                let mut values = create.values;
                values.insert_unchecked(
                    Key::Property(FileNodeProperty::Id),
                    Value::Element(FileNodeValue::Id(Id::from(assigned_ids.slot(create.slot)))),
                );
                response
                    .created
                    .insert(create.create_id, Value::Object(values));
            }

            response.new_state =
                State::Exact(assigned_ids.last_change_id(account_id, SyncCollection::FileNode))
                    .into();
        } else {
            for (key, err, _) in awaiting_existing {
                key.append(&mut response, err);
            }
        }

        Ok(response)
    }
}

impl Planned {
    fn node_ref(&self) -> NodeRef {
        match self {
            Planned::Create(create) => NodeRef::Pending(create.slot),
            Planned::Update(update) => NodeRef::Node(update.id.document_id()),
        }
    }

    fn place(
        &mut self,
        writer: &mut FileNodeWriter<'_>,
        unprocessed: Option<&AHashSet<NodeRef>>,
    ) -> Claim {
        match self {
            Planned::Create(create) => place_create(writer, create, unprocessed),
            Planned::Update(update) => place_update(writer, update, unprocessed),
        }
    }

    fn reject(self, writer: &mut FileNodeWriter<'_>) -> RejectedKey {
        match self {
            Planned::Create(create) => {
                writer.discard_create(create.slot);
                RejectedKey::Create(create.create_id)
            }
            Planned::Update(update) => RejectedKey::Update(update.id),
        }
    }
}

impl RejectedKey {
    fn append(
        self,
        response: &mut SetResponse<file_node::FileNode>,
        err: SetError<FileNodeProperty>,
    ) {
        match self {
            RejectedKey::Create(create_id) => response.not_created.append(create_id, err),
            RejectedKey::Update(id) => response.not_updated.append(id, err),
        }
    }
}

pub(super) async fn create_node<R: ResolveCreatedReference<FileNodeProperty, FileNodeValue>>(
    writer: &mut FileNodeWriter<'_>,
    create_id: String,
    node: FileNode,
    object: Value<'_, FileNodeProperty, FileNodeValue>,
    resolver: &R,
    copy_source: Option<u32>,
) -> trc::Result<Result<CreatedNode, (String, Rejection)>> {
    let mut create =
        match prepare_create(writer, create_id, node, object, resolver, copy_source).await? {
            Ok(create) => create,
            Err((create_id, err)) => return Ok(Err((create_id, err.into()))),
        };
    match place_create(writer, &mut create, None) {
        Claim::Accepted { renamed } => commit_create(writer, create, renamed).map(Ok),
        Claim::Rejected(rejection) => {
            writer.discard_create(create.slot);
            Ok(Err((create.create_id, rejection)))
        }
        Claim::Deferred => {
            writer.discard_create(create.slot);
            Ok(Err((create.create_id, SetError::already_exists().into())))
        }
    }
}

async fn prepare_create<R: ResolveCreatedReference<FileNodeProperty, FileNodeValue>>(
    writer: &mut FileNodeWriter<'_>,
    create_id: String,
    mut node: FileNode,
    mut object: Value<'_, FileNodeProperty, FileNodeValue>,
    resolver: &R,
    copy_source: Option<u32>,
) -> trc::Result<Result<PreparedCreate, (String, SetError<FileNodeProperty>)>> {
    let new_metadata = match writer
        .metadata
        .extract(MetadataPatches::for_create(), &mut object)
    {
        Ok(patches) => match copy_source {
            Some(source_id) => Some(NewMetadata::Copy { patches, source_id }),
            None => patches.map(NewMetadata::Create),
        },
        Err(err) => return Ok(Err((create_id, err))),
    };
    let patch = match NodePatch::parse(None, object, &node, true, resolver) {
        Ok(patch) => patch,
        Err(err) => return Ok(Err((create_id, err))),
    };
    match (patch.kind, copy_source) {
        (None, None) => {
            return Ok(Err((
                create_id,
                invalid(FileNodeProperty::Type, "@type is required on creation."),
            )));
        }
        (Some(kind), Some(_)) if kind != node.kind_id() => {
            return Ok(Err((
                create_id,
                invalid(
                    FileNodeProperty::Type,
                    "@type must match the @type of the source node.",
                ),
            )));
        }
        _ => {}
    }
    let parent = patch.parent.unwrap_or(ParentRef::ROOT);
    if parent.is_root() && !writer.is_owner() {
        return Ok(Err((
            create_id,
            SetError::forbidden()
                .with_description("Cannot create top-level folder in a shared account."),
        )));
    } else if !writer.can_add_to(parent) {
        return Ok(Err((
            create_id,
            SetError::forbidden()
                .with_description("You are not allowed to create file nodes in this folder."),
        )));
    }
    let blob = match patch.blob_to_resolve(&node) {
        Some(blob_id) => match writer.resolve_blob(blob_id).await? {
            Ok(blob) => Some(blob),
            Err(err) => return Ok(Err((create_id, err))),
        },
        None => None,
    };
    let omitted = Omitted {
        media_type: patch.echoes_type(),
        executable: !matches!(patch.executable, Some(Some(_))),
        created: patch.created.is_none() || patch.server_created,
        modified: patch.modified.is_none() || patch.server_modified,
        accessed: patch.accessed.is_none() || patch.server_accessed,
        subscribed: patch.kind.unwrap_or_else(|| node.kind_id()) == FILE_KIND_DIRECTORY
            && !matches!(patch.subscribed, Some(Some(_))),
    };
    let effects = match patch.apply(&mut node, blob, writer.personal_id) {
        Ok(effects) => effects,
        Err(err) => return Ok(Err((create_id, err))),
    };
    if effects.acls
        && writer
            .inherited_rights(parent)
            .is_some_and(|rights| !rights.contains(Acl::Share))
    {
        return Ok(Err((
            create_id,
            SetError::forbidden().with_description("You are not allowed to share this file node."),
        )));
    }
    if !node.acls.is_empty()
        && let Err(err) = writer
            .validate_acls(
                &node.acls,
                writer.inherited_rights(parent),
                &[] as &[AclGrant],
            )
            .await
    {
        return Ok(Err((create_id, err)));
    }
    let metadata_access = match (&new_metadata, writer.inherited_rights(parent)) {
        (Some(_), Some(rights)) => MetadataAccess {
            may_write_shared: rights.contains(Acl::ModifyMetadata),
            may_read: rights.contains(Acl::Read) || rights.contains(Acl::ReadItems),
        },
        _ => MetadataAccess::FULL,
    };
    let metadata = match writer
        .metadata
        .prepare_new(writer.server, new_metadata, metadata_access)
        .await?
    {
        Ok(metadata) => metadata,
        Err(err) => return Ok(Err((create_id, err))),
    };

    let slot = writer
        .batch
        .reserve_document_id(writer.account_id, Collection::FileNode);
    writer.stage_create(slot, parent);
    Ok(Ok(PreparedCreate {
        create_id,
        slot,
        node,
        parent,
        omitted,
        metadata,
    }))
}

fn place_create(
    writer: &mut FileNodeWriter<'_>,
    create: &mut PreparedCreate,
    unprocessed: Option<&AHashSet<NodeRef>>,
) -> Claim {
    match writer.validate_placement(None, create.parent, true, unprocessed) {
        Ok(Placement::Ready) => {}
        Ok(Placement::Deferred) => return Claim::Deferred,
        Err(err) => return Claim::Rejected(err.into()),
    }
    if let Err(err) = writer
        .validate_quota(create.node.is_directory())
        .and_then(|_| writer.validate_disk_quota(create.node.size() as u64))
    {
        return Claim::Rejected(err.into());
    }
    if let Some(role) = create.node.role() {
        match writer.validate_role(NodeRef::Pending(create.slot), role, unprocessed) {
            Ok(Placement::Ready) => {}
            Ok(Placement::Deferred) => return Claim::Deferred,
            Err(err) => return Claim::Rejected(err.into()),
        }
    }
    writer.claim_name(
        None,
        Some(create.slot),
        None,
        create.parent,
        &mut create.node,
        unprocessed,
    )
}

fn commit_create(
    writer: &mut FileNodeWriter<'_>,
    create: PreparedCreate,
    renamed: bool,
) -> trc::Result<CreatedNode> {
    let PreparedCreate {
        create_id,
        slot,
        mut node,
        parent,
        omitted,
        metadata,
    } = create;
    writer.register_created(slot, parent, node.is_directory());
    if let Some(role) = node.role() {
        writer.register_role(NodeRef::Pending(slot), Some(role));
    }
    node.stamp_insert(
        omitted.created && node.created == 0,
        omitted.modified && node.modified == 0,
        omitted.accessed && node.accessed == 0,
    );
    node.parent_id = parent.as_stored();
    node.set_presence(
        metadata
            .as_ref()
            .and_then(PreparedMetadata::file_presence)
            .unwrap_or(FilePresence::NONE),
    );
    writer.reserve_disk_quota(node.size() as u64);
    let values = created_values(&node, &omitted, writer.inherited_rights(parent), renamed);
    if let Some(metadata) = metadata {
        writer.metadata.write(metadata, slot, &mut writer.batch)?;
    }
    node.insert_stamped(
        writer.access_token.changed_by(),
        writer.account_id,
        slot,
        parent.slot(),
        &mut writer.batch,
    )
    .caused_by(trc::location!())?;
    Ok(CreatedNode {
        create_id,
        slot,
        values,
    })
}

async fn prepare_update(
    writer: &mut FileNodeWriter<'_>,
    id: Id,
    object: Value<'_, FileNodeProperty, FileNodeValue>,
    metadata_patches: Option<MetadataPatches>,
    resolver: &CreateResolver<'_>,
) -> trc::Result<Result<PreparedUpdate, SetError<FileNodeProperty>>> {
    let is_metadata_only = metadata_patches.is_some()
        && object
            .as_object()
            .is_some_and(|object| is_empty_update::<file_node::FileNode>(object, id));
    let document_id = id.document_id();
    if writer.is_destroyed(document_id) {
        return Ok(Err(SetError::will_destroy()));
    } else if !writer.is_visible(document_id) {
        return Ok(Err(SetError::not_found()));
    } else if let Err(err) =
        writer.validate_sent_properties(document_id, &object, metadata_patches.as_ref())
    {
        return Ok(Err(err));
    }
    let Some(archive) = fetch_archive(writer.server, writer.account_id, document_id).await? else {
        return Ok(Err(SetError::not_found()));
    };
    let current = archive
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut node = current
        .deserialize::<FileNode>()
        .caused_by(trc::location!())?;
    let old_parent = ParentRef::from_stored(node.parent_id);

    let patch = match NodePatch::parse(Some(id), object, &node, false, resolver) {
        Ok(patch) => patch,
        Err(err) => return Ok(Err(err)),
    };
    let blob = match patch.blob_to_resolve(&node) {
        Some(_) if !writer.has_right(document_id, Acl::ModifyItems) => {
            return Ok(Err(SetError::forbidden().with_description(
                "You are not allowed to modify the content of this file node.",
            )));
        }
        Some(blob_id) => match writer.resolve_blob(blob_id).await? {
            Ok(blob) => Some(blob),
            Err(err) => return Ok(Err(err)),
        },
        None => None,
    };
    if node.is_directory()
        && let Some(requested @ Value::Object(_)) = patch.my_rights.as_ref()
        && !same_object(requested, &my_rights(writer.node_rights_of(document_id)))
    {
        return Ok(Err(invalid(
            FileNodeProperty::MyRights,
            "myRights is server-set and not settable by clients.",
        )));
    }
    let report_size = blob.is_some() && patch.size.is_none();
    let replaces_content = blob.is_some();
    let echo = Omitted {
        media_type: patch.media_type.is_some() && patch.echoes_type(),
        executable: matches!(patch.executable, Some(None)),
        created: patch.server_created,
        modified: patch.server_modified,
        accessed: patch.server_accessed,
        subscribed: node.is_directory() && matches!(patch.subscribed, Some(None)),
    };
    let parent = patch.parent.unwrap_or(old_parent);
    let previous = (old_parent, node.name.clone());
    let effects = match patch.apply(&mut node, blob, writer.personal_id) {
        Ok(effects) => effects,
        Err(err) => return Ok(Err(err)),
    };
    let growth = if replaces_content {
        (node.size() as u64).saturating_sub(current.inner.size() as u64)
    } else {
        0
    };
    if !is_metadata_only
        && let Err(err) = writer.validate_update_rights(document_id, old_parent, parent, &effects)
    {
        return Ok(Err(err));
    }
    if effects.acls
        && let Err(err) = writer
            .validate_acls(
                &node.acls,
                writer.rights_of(document_id),
                &current.inner.acls,
            )
            .await
    {
        return Ok(Err(err));
    }
    let metadata = match metadata_patches {
        Some(patches) => {
            let access = MetadataAccess {
                may_write_shared: writer.has_right(document_id, Acl::ModifyMetadata),
                may_read: writer.is_readable(document_id),
            };
            match writer
                .metadata
                .prepare_for(
                    writer.server,
                    patches,
                    access,
                    MetadataTarget::Update { document_id },
                )
                .await?
            {
                Ok(metadata) => Some(metadata),
                Err(err) => return Ok(Err(err)),
            }
        }
        None => None,
    };

    Ok(Ok(PreparedUpdate {
        id,
        archive,
        node,
        parent,
        previous,
        effects,
        growth,
        report_size,
        echo,
        metadata,
    }))
}

fn place_update(
    writer: &mut FileNodeWriter<'_>,
    update: &mut PreparedUpdate,
    unprocessed: Option<&AHashSet<NodeRef>>,
) -> Claim {
    let document_id = update.id.document_id();
    if writer.is_destroyed(document_id) {
        return Claim::Rejected(SetError::will_destroy().into());
    }
    if let Err(err) = writer.validate_disk_quota(update.growth) {
        return Claim::Rejected(err.into());
    }
    if let Some(unprocessed) = unprocessed
        && (update.effects.renamed || update.effects.moved)
        && writer
            .holder_of(update.parent, &update.node.name)
            .is_some_and(|holder| {
                holder != NodeRef::Node(document_id) && unprocessed.contains(&holder)
            })
    {
        return Claim::Deferred;
    }
    match writer.validate_placement(
        Some(document_id),
        update.parent,
        update.effects.moved,
        unprocessed,
    ) {
        Ok(Placement::Ready) => {}
        Ok(Placement::Deferred) => return Claim::Deferred,
        Err(err) => return Claim::Rejected(err.into()),
    }
    if update.effects.role
        && let Some(role) = update.node.role()
    {
        match writer.validate_role(NodeRef::Node(document_id), role, unprocessed) {
            Ok(Placement::Ready) => {}
            Ok(Placement::Deferred) => return Claim::Deferred,
            Err(err) => return Claim::Rejected(err.into()),
        }
    }
    if !update.effects.renamed && !update.effects.moved {
        return Claim::Accepted { renamed: false };
    }
    writer.claim_name(
        Some(document_id),
        None,
        Some((update.previous.0, update.previous.1.as_str())),
        update.parent,
        &mut update.node,
        unprocessed,
    )
}

fn commit_update(
    writer: &mut FileNodeWriter<'_>,
    update: PreparedUpdate,
    renamed: bool,
) -> trc::Result<Option<Value<'static, FileNodeProperty, FileNodeValue>>> {
    let document_id = update.id.document_id();
    let metadata = update.metadata;
    if !update.effects.changes_node() && !update.effects.subscription {
        if let Some(metadata) = metadata {
            if let Some(presence) = metadata.file_presence() {
                FileNode::rewrite_presence(
                    &update
                        .archive
                        .to_unarchived::<FileNode>()
                        .caused_by(trc::location!())?,
                    presence,
                    writer.account_id,
                    document_id,
                    &mut writer.batch,
                )
                .caused_by(trc::location!())?;
            }
            writer
                .metadata
                .write(metadata, document_id, &mut writer.batch)?;
            writer.batch.commit_point();
        }
        if update.echo.is_empty() {
            return Ok(None);
        }
        let mut values = Map::with_capacity(2);
        update.echo.insert_into(&update.node, &mut values);
        return Ok(Some(Value::Object(values)));
    }
    let current = update
        .archive
        .to_unarchived::<FileNode>()
        .caused_by(trc::location!())?;
    let mut node = update.node;
    node.parent_id = update.parent.as_stored();
    node.stamp_update(false);
    if let Some(presence) = metadata.as_ref().and_then(PreparedMetadata::file_presence) {
        node.set_presence(presence);
    }
    writer.register_update(
        document_id,
        update.parent,
        &update.effects,
        node.is_directory(),
    );
    if update.effects.role {
        writer.register_role(NodeRef::Node(document_id), node.role());
    }

    let mut values = Map::with_capacity(3);
    if writer.is_readable(document_id) {
        values.insert_unchecked(
            Key::Property(FileNodeProperty::Changed),
            date_value(Some(node.changed)),
        );
    }
    if renamed {
        values.insert_unchecked(
            Key::Property(FileNodeProperty::Name),
            Value::Str(Cow::Owned(node.name.clone())),
        );
    }
    if update.report_size
        && let Some(file) = node.file()
    {
        values.insert_unchecked(
            Key::Property(FileNodeProperty::Size),
            Value::Number(file.size.into()),
        );
    }
    update.echo.insert_into(&node, &mut values);

    if let Some(metadata) = metadata {
        writer
            .metadata
            .write(metadata, document_id, &mut writer.batch)?;
    }
    writer.reserve_disk_quota(update.growth);
    node.update_stamped(
        writer.access_token.changed_by(),
        current,
        writer.account_id,
        document_id,
        update.parent.slot(),
        &mut writer.batch,
    )
    .caused_by(trc::location!())?;
    if update.effects.renamed || update.effects.moved {
        writer.log_vanished_href(document_id);
    }
    Ok(Some(Value::Object(values)))
}

fn resolve_name_cycles(writer: &mut FileNodeWriter<'_>, deferred: &[Planned]) -> Vec<usize> {
    const UNVISITED: u8 = 0;
    const VISITING: u8 = 1;
    const VISITED: u8 = 2;

    let updates = deferred
        .iter()
        .enumerate()
        .filter_map(|(index, item)| match item {
            Planned::Update(update) => Some((update.id.document_id(), index)),
            Planned::Create(_) => None,
        })
        .collect::<AHashMap<_, _>>();
    let waits_on = deferred
        .iter()
        .map(|item| match item {
            Planned::Update(update) => match writer.holder_of(update.parent, &update.node.name) {
                Some(NodeRef::Node(holder_id)) => updates.get(&holder_id).copied(),
                _ => None,
            },
            Planned::Create(_) => None,
        })
        .collect::<Vec<_>>();

    let mut state = vec![UNVISITED; deferred.len()];
    let mut path = Vec::new();
    let mut committed = Vec::new();
    for start in 0..deferred.len() {
        path.clear();
        let mut current = Some(start);
        while let Some(index) = current {
            match state.get(index).copied() {
                Some(UNVISITED) => {
                    state[index] = VISITING;
                    path.push(index);
                    current = waits_on.get(index).copied().flatten();
                }
                Some(VISITING) => {
                    let cycle = path
                        .iter()
                        .copied()
                        .skip_while(|member| *member != index)
                        .collect::<Vec<_>>();
                    if claim_cycle(writer, deferred, &cycle) {
                        committed.extend(cycle);
                    }
                    current = None;
                }
                _ => current = None,
            }
        }
        for index in &path {
            state[*index] = VISITED;
        }
    }
    committed.sort_unstable();
    committed
}

fn claim_cycle(writer: &mut FileNodeWriter<'_>, deferred: &[Planned], cycle: &[usize]) -> bool {
    let members = cycle
        .iter()
        .filter_map(|index| match deferred.get(*index) {
            Some(Planned::Update(update)) => Some(update),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut staged = Vec::with_capacity(members.len());
    let mut roles = Vec::new();
    let mut valid = writer
        .validate_disk_quota(members.iter().map(|update| update.growth).sum())
        .is_ok();
    for update in &members {
        let document_id = update.id.document_id();
        if !valid
            || writer.is_destroyed(document_id)
            || !matches!(
                writer.validate_placement(
                    Some(document_id),
                    update.parent,
                    update.effects.moved,
                    None
                ),
                Ok(Placement::Ready)
            )
            || (update.effects.role
                && update.node.role().is_some_and(|role| {
                    roles.contains(&role)
                        || !matches!(
                            writer.validate_role(NodeRef::Node(document_id), role, None),
                            Ok(Placement::Ready)
                        )
                }))
        {
            valid = false;
            break;
        }
        if update.effects.role
            && let Some(role) = update.node.role()
        {
            roles.push(role);
        }
        if update.effects.moved {
            writer.stage_move(document_id, update.parent);
            staged.push(document_id);
        }
    }
    let claimed = valid
        && writer.claim_cycle(members.iter().map(|update| {
            (
                update.id.document_id(),
                update.previous.0,
                update.previous.1.as_str(),
                update.parent,
                update.node.name.as_str(),
            )
        }));
    if !claimed {
        for document_id in staged {
            writer.unstage_move(document_id);
        }
    }
    claimed
}

fn created_values(
    node: &FileNode,
    omitted: &Omitted,
    rights: Option<Bitmap<Acl>>,
    renamed: bool,
) -> NodeValues {
    let mut values = Map::with_capacity(10);
    if renamed {
        values.insert_unchecked(
            Key::Property(FileNodeProperty::Name),
            Value::Str(Cow::Owned(node.name.clone())),
        );
    }
    if let Some(file) = node.file() {
        values.insert_unchecked(
            Key::Property(FileNodeProperty::Size),
            Value::Number(file.size.into()),
        );
    }
    omitted.insert_into(node, &mut values);
    values.insert_unchecked(
        Key::Property(FileNodeProperty::Changed),
        date_value(Some(node.changed)),
    );
    if node.is_directory() {
        values.insert_unchecked(Key::Property(FileNodeProperty::MyRights), my_rights(rights));
    }
    values
}

fn normalized_media_type(media_type: Option<&str>) -> Cow<'static, str> {
    media_type
        .and_then(media_type_essence)
        .map_or(Cow::Borrowed(default_media_type()), |essence| {
            Cow::Owned(essence.into_owned())
        })
}

fn same_object(
    a: &Value<'_, FileNodeProperty, FileNodeValue>,
    b: &Value<'_, FileNodeProperty, FileNodeValue>,
) -> bool {
    match (a.as_object(), b.as_object()) {
        (Some(a), Some(b)) => {
            a.len() == b.len() && a.iter().all(|(key, value)| b.get(key) == Some(value))
        }
        _ => false,
    }
}

impl ResolveCreatedReference<FileNodeProperty, FileNodeValue> for CreateResolver<'_> {
    fn get_created_id(&self, id_ref: &str) -> Option<AnyId> {
        self.created_id(id_ref)
    }
}
