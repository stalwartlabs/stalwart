/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FileNodeQuota, ObjectCounts,
    node::{PatchEffects, ResolvedBlob, invalid, validate_name},
};
use crate::{api::acl::JmapAcl, api::parent_ref::ParentRef, blob::download::BlobDownload};
use common::{
    GroupwareResources, Server,
    auth::AccessToken,
    sharing::file::FileNodeAccess,
    storage::dav::{FILE_KIND_SYMLINK, MAX_FILE_NODE_DEPTH},
};
use groupware::{DestroyArchive, file::FileNode};
use jmap_proto::{
    error::set::SetError,
    object::file_node::{FileNodeProperty, OnExists},
};
use std::borrow::Cow;
use store::{
    Deserialize, U64_LEN, ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{Archive, ArchiveBytes, BatchBuilder, BlobLink, BlobOp, Slot, ValueClass, now},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    blob::{BlobClass, BlobId},
    collection::{Collection, SyncCollection, VanishedCollection},
    id::Id,
};
use utils::map::bitmap::Bitmap;

const RENAME_ATTEMPTS: u32 = 10_000;
const MAX_ANCESTOR_WALK: usize = MAX_FILE_NODE_DEPTH * 4;

#[derive(Debug, Clone, Copy)]
pub(super) struct WriteOptions {
    pub on_exists: OnExists,
    pub remove_children: bool,
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum NodeRef {
    Node(u32),
    Pending(Slot),
}

pub(super) enum Claim {
    Accepted { renamed: bool },
    Deferred,
    Rejected(Rejection),
}

pub(super) enum Placement {
    Ready,
    Deferred,
}

pub(super) struct Rejection {
    pub error: SetError<FileNodeProperty>,
    pub existing: Option<Slot>,
}

pub(super) struct DestroyGroup {
    pub id: Id,
    pub ids: Vec<u32>,
    pub path: Option<String>,
    pub requires_empty: bool,
}

pub(super) struct FileNodeWriter<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub cache: &'x GroupwareResources,
    pub personal_id: u32,
    pub batch: BatchBuilder,
    pub implicit_destroys: Vec<DestroyGroup>,
    access: Option<FileNodeAccess>,
    options: WriteOptions,
    siblings: AHashMap<ParentRef, AHashMap<Cow<'x, str>, NodeRef>>,
    destroyed: AHashSet<u32>,
    parents: AHashMap<NodeRef, ParentRef>,
    accepted_folders: AHashSet<Slot>,
    touched: AHashSet<u32>,
    received: AHashSet<u32>,
    logged_subtrees: Vec<u32>,
    cached_heights: AHashMap<u32, usize>,
    rename_suffixes: AHashMap<(ParentRef, String), u32>,
    quota: FileNodeQuota,
    created: usize,
    destroyed_counts: ObjectCounts,
}

pub(super) struct TemporaryBlobSize(Option<u64>);

impl NodeRef {
    #[inline(always)]
    pub fn from_parent(parent: ParentRef) -> Option<NodeRef> {
        match parent {
            ParentRef::Root => None,
            ParentRef::Node(document_id) => Some(NodeRef::Node(document_id)),
            ParentRef::Pending(slot) => Some(NodeRef::Pending(slot)),
        }
    }
}

impl From<SetError<FileNodeProperty>> for Rejection {
    fn from(error: SetError<FileNodeProperty>) -> Self {
        Rejection {
            error,
            existing: None,
        }
    }
}

impl<'x> FileNodeWriter<'x> {
    pub fn new(
        server: &'x Server,
        access_token: &'x AccessToken,
        account_id: u32,
        cache: &'x GroupwareResources,
        options: WriteOptions,
    ) -> Self {
        let access = (!access_token.is_member(account_id)).then(|| cache.file_access(access_token));
        FileNodeWriter {
            server,
            access_token,
            account_id,
            cache,
            personal_id: access_token.personal_id(account_id, Collection::FileNode),
            batch: BatchBuilder::new(),
            implicit_destroys: Vec::new(),
            access,
            options,
            siblings: AHashMap::new(),
            destroyed: AHashSet::new(),
            parents: AHashMap::new(),
            accepted_folders: AHashSet::new(),
            touched: AHashSet::new(),
            received: AHashSet::new(),
            logged_subtrees: Vec::new(),
            cached_heights: AHashMap::new(),
            rename_suffixes: AHashMap::new(),
            quota: FileNodeQuota::unlimited(),
            created: 0,
            destroyed_counts: ObjectCounts::default(),
        }
    }

    pub async fn with_quota(mut self) -> trc::Result<Self> {
        let account = self
            .server
            .account(self.account_id)
            .await
            .caused_by(trc::location!())?;
        self.quota = FileNodeQuota::new(self.server, &account, self.cache);
        Ok(self)
    }

    pub fn validate_quota(&self, is_folder: bool) -> Result<(), SetError<FileNodeProperty>> {
        let folders = self.accepted_folders.len();
        self.quota.validate(
            is_folder,
            ObjectCounts {
                files: self.created.saturating_sub(folders),
                folders,
            },
            self.destroyed_counts,
        )
    }

    #[inline(always)]
    pub fn is_owner(&self) -> bool {
        self.access.is_none()
    }

    #[inline(always)]
    pub fn has_right(&self, document_id: u32, acl: Acl) -> bool {
        self.access
            .as_ref()
            .is_none_or(|access| access.has_acl(document_id, acl))
    }

    pub fn rights_of(&self, document_id: u32) -> Option<Bitmap<Acl>> {
        self.access.as_ref().map(|access| access.acl(document_id))
    }

    #[inline(always)]
    pub fn is_visible(&self, document_id: u32) -> bool {
        self.access
            .as_ref()
            .is_none_or(|access| access.discoverable.contains(document_id))
    }

    #[inline(always)]
    pub fn is_destroyed(&self, document_id: u32) -> bool {
        self.destroyed.contains(&document_id)
    }

    pub fn inherited_rights(&self, parent: ParentRef) -> Option<Bitmap<Acl>> {
        let access = self.access.as_ref()?;
        Some(
            self.ancestors(NodeRef::from_parent(parent))
                .find_map(|node| match node {
                    NodeRef::Node(document_id) => Some(access.acl(document_id)),
                    NodeRef::Pending(_) => None,
                })
                .unwrap_or_default(),
        )
    }

    pub fn plan_destroys(
        &mut self,
        ids: Vec<Id>,
        moving: &AHashSet<u32>,
    ) -> (Vec<DestroyGroup>, Vec<(Id, SetError<FileNodeProperty>)>) {
        let mut failed = Vec::new();
        let mut requested = AHashMap::with_capacity(ids.len());
        for id in ids {
            let document_id = id.document_id();
            if self.cache.resources.find_any(document_id).is_some() && self.is_visible(document_id)
            {
                requested.insert(document_id, id);
            } else {
                failed.push((id, SetError::not_found()));
            }
        }

        let remove_children = self.options.remove_children;
        let mut subtrees: AHashMap<u32, Vec<u32>> = AHashMap::with_capacity(requested.len());
        let mut rejected: AHashMap<u32, SetError<FileNodeProperty>> = AHashMap::new();
        let mut order = requested
            .keys()
            .map(|&document_id| (self.depth_of(ParentRef::Node(document_id)), document_id))
            .collect::<Vec<_>>();
        order.sort_unstable();
        let mut covered = AHashSet::new();
        for (_, document_id) in order {
            if covered.contains(&document_id) {
                continue;
            }
            let ids = if remove_children {
                self.subtree_ids(document_id)
            } else {
                vec![document_id]
            };
            if ids.iter().any(|id| !self.has_right(*id, Acl::Delete)) {
                rejected.insert(
                    document_id,
                    SetError::forbidden()
                        .with_description("You are not allowed to delete this file node."),
                );
            } else if remove_children {
                covered.extend(ids.iter().copied());
            }
            subtrees.insert(document_id, ids);
        }

        if !remove_children {
            let children = requested
                .keys()
                .filter_map(|&document_id| {
                    let children = self.cache.children_ids(document_id).collect::<Vec<_>>();
                    (!children.is_empty()).then_some((document_id, children))
                })
                .collect::<Vec<_>>();
            loop {
                let mut changed = false;
                for (document_id, children) in &children {
                    if !rejected.contains_key(document_id)
                        && children.iter().any(|child| {
                            (!requested.contains_key(child) && !moving.contains(child))
                                || rejected.contains_key(child)
                        })
                    {
                        rejected.insert(*document_id, SetError::node_has_children());
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
        }

        let mut groups = Vec::with_capacity(requested.len());
        let mut roots = requested
            .into_iter()
            .filter_map(|(document_id, id)| match rejected.remove(&document_id) {
                Some(err) => {
                    failed.push((id, err));
                    None
                }
                None => Some((document_id, id)),
            })
            .collect::<Vec<_>>();
        roots.sort_unstable_by_key(|(document_id, _)| self.depth_of(ParentRef::Node(*document_id)));
        for (document_id, id) in roots {
            if self.destroyed.contains(&document_id) {
                continue;
            }
            let ids = subtrees.remove(&document_id).unwrap_or_default();
            self.mark_destroyed(&ids);
            groups.push(DestroyGroup {
                id,
                path: self.vanished_href(document_id),
                ids,
                requires_empty: !remove_children,
            });
        }

        (groups, failed)
    }

    pub async fn execute_destroys(
        &mut self,
        groups: Vec<DestroyGroup>,
    ) -> trc::Result<(Vec<Id>, Vec<(Id, SetError<FileNodeProperty>)>)> {
        let mut destroyed = Vec::with_capacity(groups.len());
        let mut failed = Vec::new();
        let mut kept = AHashSet::new();
        for group in groups
            .into_iter()
            .rev()
            .chain(std::mem::take(&mut self.implicit_destroys))
        {
            let root_id = group.id.document_id();
            if group.requires_empty
                && self.cache.children_ids(root_id).any(|child| {
                    kept.contains(&child)
                        || (!self.destroyed.contains(&child)
                            && self.parent_of(NodeRef::Node(child)) == Some(NodeRef::Node(root_id)))
                })
            {
                kept.insert(root_id);
                failed.push((group.id, SetError::node_has_children()));
                continue;
            }
            if group.ids.len() > 1 {
                destroyed.extend(
                    group
                        .ids
                        .iter()
                        .filter(|id| **id != group.id.document_id())
                        .map(|id| Id::from(*id)),
                );
            }
            destroyed.push(group.id);
            DestroyArchive(group.ids)
                .delete_batch(
                    self.server,
                    self.access_token.account_tenant_ids(),
                    self.account_id,
                    group.path,
                    &mut self.batch,
                )
                .await
                .caused_by(trc::location!())?;
        }
        Ok((destroyed, failed))
    }

    pub fn validate_placement(
        &mut self,
        document_id: Option<u32>,
        parent: ParentRef,
        moved: bool,
        unprocessed: Option<&AHashSet<NodeRef>>,
    ) -> Result<Placement, SetError<FileNodeProperty>> {
        match parent {
            ParentRef::Root => {
                if !self.is_owner() && moved {
                    return Err(SetError::forbidden()
                        .with_description("Cannot create top-level folder in a shared account."));
                }
            }
            ParentRef::Pending(slot) => {
                if !self.accepted_folders.contains(&slot) {
                    return match unprocessed {
                        Some(unprocessed) if unprocessed.contains(&NodeRef::Pending(slot)) => {
                            Ok(Placement::Deferred)
                        }
                        _ => Err(invalid(
                            FileNodeProperty::ParentId,
                            "Parent ID does not exist or is not a folder.",
                        )),
                    };
                }
            }
            ParentRef::Node(parent_id) => {
                if self.destroyed.contains(&parent_id) {
                    return Err(invalid(
                        FileNodeProperty::ParentId,
                        "Parent is being destroyed in this request.",
                    ));
                } else if !self
                    .cache
                    .container_resource_by_id(parent_id)
                    .is_some_and(|_| self.is_visible(parent_id))
                {
                    return Err(invalid(
                        FileNodeProperty::ParentId,
                        "Parent ID does not exist or is not a folder.",
                    ));
                }
            }
        }
        if !moved || parent.is_root() {
            return Ok(Placement::Ready);
        }
        if let Some(document_id) = document_id
            && self.is_ancestor_or_self(document_id, parent)
        {
            return Err(invalid(
                FileNodeProperty::ParentId,
                "Circular reference in parent ids.",
            ));
        }
        let height = document_id.map_or(1, |id| self.subtree_height(id));
        if self.depth_of(parent) + height > MAX_FILE_NODE_DEPTH {
            return Err(invalid(
                FileNodeProperty::ParentId,
                "Maximum folder depth exceeded.",
            ));
        }
        Ok(Placement::Ready)
    }

    pub fn can_add_to(&self, parent: ParentRef) -> bool {
        match parent {
            _ if self.is_owner() => true,
            ParentRef::Root => false,
            ParentRef::Pending(slot) => self.parents.contains_key(&NodeRef::Pending(slot)),
            ParentRef::Node(parent_id) => self.has_right(parent_id, Acl::AddItems),
        }
    }

    pub fn validate_update_rights(
        &self,
        document_id: u32,
        old_parent: ParentRef,
        new_parent: ParentRef,
        effects: &PatchEffects,
    ) -> Result<(), SetError<FileNodeProperty>> {
        if self.is_owner() {
            return Ok(());
        }
        let forbidden =
            |description: &'static str| Err(SetError::forbidden().with_description(description));
        if !effects.changes_node()
            && !effects.subscription
            && !self.has_right(document_id, Acl::Modify)
            && !self.has_right(document_id, Acl::ModifyItems)
        {
            forbidden("You are not allowed to modify this file node.")
        } else if (effects.renamed || effects.moved || effects.role)
            && !self.has_right(document_id, Acl::Modify)
        {
            forbidden("You are not allowed to rename or move this file node.")
        } else if effects.moved
            && (!self.can_add_to(new_parent)
                || old_parent
                    .document_id()
                    .is_none_or(|parent_id| !self.has_right(parent_id, Acl::RemoveItems)))
        {
            forbidden("You are not allowed to move this file node to the requested folder.")
        } else if effects.content && !self.has_right(document_id, Acl::ModifyItems) {
            forbidden("You are not allowed to modify the content of this file node.")
        } else if effects.acls && !self.has_right(document_id, Acl::Share) {
            forbidden("You are not allowed to share this file node.")
        } else if effects.subscription
            && !self.has_right(document_id, Acl::Read)
            && !self.has_right(document_id, Acl::ReadItems)
        {
            forbidden("You are not allowed to subscribe to this file node.")
        } else {
            Ok(())
        }
    }

    pub async fn validate_acls(
        &self,
        acls: &[AclGrant],
        previous: Option<&[AclGrant]>,
    ) -> trc::Result<Result<(), SetError<FileNodeProperty>>> {
        if let Err(err) = self.server.acl_validate(acls).await {
            return Ok(Err(err.into()));
        }
        self.server
            .refresh_acls(acls, previous)
            .await
            .caused_by(trc::location!())?;
        Ok(Ok(()))
    }

    pub async fn resolve_blob(
        &self,
        blob_id: &BlobId,
    ) -> trc::Result<Result<ResolvedBlob, SetError<FileNodeProperty>>> {
        if !self
            .server
            .has_access_blob(blob_id, self.access_token)
            .await?
        {
            return Ok(Err(SetError::forbidden().with_description(format!(
                "You do not have access to blobId {blob_id}."
            ))));
        }

        let (hash, size) = if let Some(section) = &blob_id.section {
            let Some(bytes) = self
                .server
                .get_blob_section(&blob_id.hash, section)
                .await
                .caused_by(trc::location!())?
            else {
                return Ok(Err(blob_not_found()));
            };
            let (hash, _) = self
                .server
                .put_temporary_blob(self.account_id, &bytes, 60)
                .await
                .caused_by(trc::location!())?;
            (hash, bytes.len() as u64)
        } else {
            let known_size = match &blob_id.class {
                BlobClass::Reserved {
                    account_id,
                    expires,
                } => self
                    .server
                    .store()
                    .get_value::<TemporaryBlobSize>(ValueKey {
                        account_id: *account_id,
                        collection: 0,
                        document_id: 0,
                        class: ValueClass::Blob(BlobOp::Link {
                            hash: blob_id.hash.clone(),
                            to: BlobLink::Temporary { until: *expires },
                        }),
                    })
                    .await
                    .caused_by(trc::location!())?
                    .and_then(|size| size.0),
                BlobClass::Linked {
                    account_id,
                    collection,
                    document_id,
                } if *account_id == self.account_id
                    && *collection == u8::from(Collection::FileNode) =>
                {
                    self.cache
                        .resources
                        .find_any(*document_id)
                        .and_then(|resource| resource.size())
                        .map(u64::from)
                }
                BlobClass::Linked { .. } => None,
            };
            match known_size {
                Some(size) => (blob_id.hash.clone(), size),
                None => match self
                    .server
                    .blob_store()
                    .get_blob(blob_id.hash.as_slice(), 0..usize::MAX)
                    .await
                    .caused_by(trc::location!())?
                {
                    Some(bytes) => (blob_id.hash.clone(), bytes.len() as u64),
                    None => return Ok(Err(blob_not_found())),
                },
            }
        };

        Ok(u32::try_from(size)
            .map(|size| ResolvedBlob { hash, size })
            .map_err(|_| SetError::too_large().with_description("File is too large.")))
    }

    pub fn stage_create(&mut self, slot: Slot, parent: ParentRef) {
        self.parents.insert(NodeRef::Pending(slot), parent);
    }

    pub fn discard_create(&mut self, slot: Slot) {
        self.parents.remove(&NodeRef::Pending(slot));
    }

    pub fn stage_move(&mut self, document_id: u32, parent: ParentRef) {
        self.parents.insert(NodeRef::Node(document_id), parent);
    }

    pub fn unstage_move(&mut self, document_id: u32) {
        if !self.touched.contains(&document_id) {
            self.parents.remove(&NodeRef::Node(document_id));
        }
    }

    pub fn register_created(&mut self, slot: Slot, parent: ParentRef, is_folder: bool) {
        self.created += 1;
        if is_folder {
            self.accepted_folders.insert(slot);
        }
        if let ParentRef::Node(parent_id) = parent {
            self.received.insert(parent_id);
        }
    }

    pub fn register_update(
        &mut self,
        document_id: u32,
        parent: ParentRef,
        effects: &PatchEffects,
        is_directory: bool,
    ) {
        self.touched.insert(document_id);
        if effects.moved {
            self.parents.insert(NodeRef::Node(document_id), parent);
            if let ParentRef::Node(parent_id) = parent {
                self.received.insert(parent_id);
            }
        }
        if is_directory && (effects.moved || effects.renamed || effects.acls) {
            self.logged_subtrees.push(document_id);
        }
    }

    pub fn log_vanished_href(&mut self, document_id: u32) {
        if let Some(href) = self.vanished_href(document_id) {
            self.batch
                .with_account_id(self.account_id)
                .log_vanished_item(VanishedCollection::FileNode, href);
        }
    }

    pub fn holder_of(&mut self, parent: ParentRef, name: &str) -> Option<NodeRef> {
        self.load_siblings(parent);
        self.siblings
            .get(&parent)
            .and_then(|names| names.get(fold_name(name, self.options.case_insensitive).as_ref()))
            .copied()
    }

    pub fn claim_name(
        &mut self,
        document_id: Option<u32>,
        slot: Option<Slot>,
        previous: Option<(ParentRef, &str)>,
        parent: ParentRef,
        node: &mut FileNode,
        unprocessed: Option<&AHashSet<NodeRef>>,
    ) -> Claim {
        let holder = self
            .holder_of(parent, &node.name)
            .filter(|holder| document_id.is_none_or(|id| *holder != NodeRef::Node(id)));

        let mut renamed = false;
        if let Some(holder) = holder {
            if unprocessed.is_some_and(|unprocessed| unprocessed.contains(&holder)) {
                return Claim::Deferred;
            }

            if let NodeRef::Node(holder_id) = holder
                && !self.is_visible(holder_id)
            {
                return match self.options.on_exists {
                    OnExists::Rename => match self.unique_name(parent, &node.name) {
                        Some(name) => {
                            node.name = name;
                            self.register_name(document_id, slot, previous, parent, node);
                            Claim::Accepted { renamed: true }
                        }
                        None => Claim::Rejected(SetError::already_exists().into()),
                    },
                    _ => Claim::Rejected(SetError::already_exists().into()),
                };
            }

            let on_exists = match (self.options.on_exists, holder) {
                (OnExists::Newest, NodeRef::Node(holder_id)) => {
                    let incoming = if node.modified == 0 {
                        now() as i64
                    } else {
                        node.modified
                    };
                    if self
                        .cache
                        .resources
                        .find_any(holder_id)
                        .and_then(|resource| resource.modified_at())
                        .is_some_and(|existing| incoming > existing)
                    {
                        OnExists::Replace
                    } else {
                        OnExists::Reject
                    }
                }
                (OnExists::Newest, _) => OnExists::Reject,
                (on_exists, _) => on_exists,
            };

            match (on_exists, holder) {
                (OnExists::Rename, _) => match self.unique_name(parent, &node.name) {
                    Some(name) => {
                        node.name = name;
                        renamed = true;
                    }
                    None => return Claim::Rejected(already_exists(holder)),
                },
                (OnExists::Replace, NodeRef::Node(holder_id))
                    if self.cache.resources.find_any(holder_id).is_some() =>
                {
                    if let Err(err) = self.replace(holder_id, document_id) {
                        return Claim::Rejected(err.into());
                    }
                }
                (_, holder) => return Claim::Rejected(already_exists(holder)),
            }
        }

        self.register_name(document_id, slot, previous, parent, node);
        Claim::Accepted { renamed }
    }

    fn register_name(
        &mut self,
        document_id: Option<u32>,
        slot: Option<Slot>,
        previous: Option<(ParentRef, &str)>,
        parent: ParentRef,
        node: &FileNode,
    ) {
        if let Some((previous_parent, previous_name)) = previous {
            self.load_siblings(previous_parent);
            let previous_key = fold_name(previous_name, self.options.case_insensitive);
            if let Some(names) = self.siblings.get_mut(&previous_parent)
                && document_id
                    .is_some_and(|id| names.get(previous_key.as_ref()) == Some(&NodeRef::Node(id)))
            {
                names.remove(previous_key.as_ref());
            }
        }

        let holder = match (document_id, slot) {
            (Some(document_id), _) => NodeRef::Node(document_id),
            (None, Some(slot)) => NodeRef::Pending(slot),
            (None, None) => return,
        };
        let key = self.fold(&node.name).into_owned();
        self.siblings
            .entry(parent)
            .or_default()
            .insert(Cow::Owned(key), holder);
    }

    pub fn claim_cycle<'y>(
        &mut self,
        entries: impl Iterator<Item = (u32, ParentRef, &'y str, ParentRef, &'y str)> + Clone,
    ) -> bool {
        for (_, previous_parent, _, parent, _) in entries.clone() {
            self.load_siblings(previous_parent);
            self.load_siblings(parent);
        }
        let moving = entries
            .clone()
            .map(|(document_id, ..)| document_id)
            .collect::<AHashSet<_>>();
        let case_insensitive = self.options.case_insensitive;
        let mut targets = AHashSet::new();
        for (document_id, _, _, parent, name) in entries.clone() {
            let key = fold_name(name, case_insensitive);
            let holder = self
                .siblings
                .get(&parent)
                .and_then(|names| names.get(key.as_ref()))
                .copied();
            let is_free = match holder {
                None => true,
                Some(NodeRef::Node(holder_id)) => {
                    holder_id == document_id || moving.contains(&holder_id)
                }
                Some(NodeRef::Pending(_)) => false,
            };
            if !is_free || !targets.insert((parent, key)) {
                return false;
            }
        }
        for (document_id, previous_parent, previous_name, ..) in entries.clone() {
            let key = fold_name(previous_name, case_insensitive);
            if let Some(names) = self.siblings.get_mut(&previous_parent)
                && names.get(key.as_ref()) == Some(&NodeRef::Node(document_id))
            {
                names.remove(key.as_ref());
            }
        }
        for (document_id, _, _, parent, name) in entries {
            let key = fold_name(name, case_insensitive).into_owned();
            self.siblings
                .entry(parent)
                .or_default()
                .insert(Cow::Owned(key), NodeRef::Node(document_id));
        }
        true
    }

    pub fn finish(&mut self) {
        let subtrees = std::mem::take(&mut self.logged_subtrees);
        if subtrees.is_empty() {
            return;
        }
        let mut logged = AHashSet::new();
        self.batch
            .with_account_id(self.account_id)
            .with_collection(Collection::FileNode);
        for document_id in subtrees {
            for child in self.subtree_ids(document_id) {
                if child != document_id
                    && !self.destroyed.contains(&child)
                    && !self.touched.contains(&child)
                    && logged.insert(child)
                {
                    self.batch
                        .with_document(child)
                        .log_item_update(SyncCollection::FileNode, None);
                }
            }
        }
        if !logged.is_empty() {
            self.batch.commit_point();
        }
    }

    fn replace(
        &mut self,
        holder_id: u32,
        claimant: Option<u32>,
    ) -> Result<(), SetError<FileNodeProperty>> {
        let ids = self
            .subtree_ids(holder_id)
            .into_iter()
            .filter(|id| !self.destroyed.contains(id))
            .collect::<Vec<_>>();
        if ids.iter().any(|id| {
            claimant == Some(*id) || self.touched.contains(id) || self.received.contains(id)
        }) {
            return Err(SetError::already_exists()
                .with_existing_id(Id::from(holder_id))
                .with_description(
                    "The existing file node is modified in this request and cannot be replaced.",
                ));
        }
        if ids.len() > 1 && !self.options.remove_children {
            return Err(SetError::node_has_children());
        }
        if ids.iter().any(|id| !self.has_right(*id, Acl::Delete)) {
            return Err(SetError::forbidden()
                .with_description("You are not allowed to replace the existing file node."));
        }
        if let Some(holder) = self.cache.resources.find_any(holder_id)
            && let Some(name) = holder.container_name()
            && let Some(names) = self
                .siblings
                .get_mut(&holder.parent_id().map_or(ParentRef::ROOT, ParentRef::Node))
        {
            names.remove(fold_name(name, self.options.case_insensitive).as_ref());
        }
        self.mark_destroyed(&ids);
        self.implicit_destroys.push(DestroyGroup {
            id: Id::from(holder_id),
            path: self.vanished_href(holder_id),
            ids,
            requires_empty: false,
        });
        Ok(())
    }

    fn mark_destroyed(&mut self, ids: &[u32]) {
        for &id in ids {
            if self.destroyed.insert(id) {
                if self.cache.container_resource_by_id(id).is_some() {
                    self.destroyed_counts.folders += 1;
                } else {
                    self.destroyed_counts.files += 1;
                }
            }
        }
    }

    fn unique_name(&mut self, parent: ParentRef, base: &str) -> Option<String> {
        use std::fmt::Write;
        let (stem, ext) = match base.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => (stem, ext),
            _ => (base, ""),
        };
        let names = self.siblings.get(&parent);
        let mut candidate = String::with_capacity(base.len() + 8);
        let hint = (parent, base.to_string());
        let first = self.rename_suffixes.get(&hint).copied().unwrap_or(2);
        for n in first..RENAME_ATTEMPTS {
            let suffix_len =
                if ext.is_empty() { 0 } else { ext.len() + 1 } + n.ilog10() as usize + 4;
            let max_stem = super::node::MAX_NAME_LEN.checked_sub(suffix_len)?;
            let stem = stem
                .char_indices()
                .map(|(start, ch)| start + ch.len_utf8())
                .take_while(|end| *end <= max_stem)
                .last()
                .and_then(|end| stem.get(..end))
                .unwrap_or_default();
            candidate.clear();
            let _ = if ext.is_empty() {
                write!(candidate, "{stem} ({n})")
            } else {
                write!(candidate, "{stem} ({n}).{ext}")
            };
            if names.is_none_or(|names| !names.contains_key(self.fold(&candidate).as_ref()))
                && validate_name(&candidate).is_ok()
            {
                self.rename_suffixes.insert(hint, n + 1);
                return Some(candidate);
            }
        }
        None
    }

    fn load_siblings(&mut self, parent: ParentRef) {
        if self.siblings.contains_key(&parent) {
            return;
        }
        let cache = self.cache;
        let mut names = AHashMap::new();
        let push =
            |names: &mut AHashMap<Cow<'x, str>, NodeRef>, document_id: u32, name: &'x str| {
                if !self.destroyed.contains(&document_id) {
                    names.insert(
                        fold_name(name, self.options.case_insensitive),
                        NodeRef::Node(document_id),
                    );
                }
            };
        match parent {
            ParentRef::Root => {
                for resource in cache.resources.iter() {
                    if resource.parent_id().is_none()
                        && let Some(name) = resource.container_name()
                    {
                        push(&mut names, resource.document_id(), name);
                    }
                }
            }
            ParentRef::Node(parent_id) => {
                for child in cache.children(parent_id) {
                    if let Some(name) = child.resource.container_name() {
                        push(&mut names, child.document_id(), name);
                    }
                }
            }
            ParentRef::Pending(_) => {}
        }
        self.siblings.insert(parent, names);
    }

    #[inline(always)]
    fn fold<'y>(&self, name: &'y str) -> Cow<'y, str> {
        fold_name(name, self.options.case_insensitive)
    }

    fn subtree_ids(&self, document_id: u32) -> Vec<u32> {
        match self.cache.any_resource_path_by_id(document_id) {
            Some(path) => {
                let mut ids = self
                    .cache
                    .subtree(path.path())
                    .map(|resource| (resource.hierarchy_seq(), resource.document_id()))
                    .collect::<Vec<_>>();
                ids.sort_unstable_by(|a, b| b.cmp(a));
                ids.dedup_by_key(|(_, id)| *id);
                ids.into_iter().map(|(_, id)| id).collect()
            }
            None => vec![document_id],
        }
    }

    fn vanished_href(&self, document_id: u32) -> Option<String> {
        self.cache
            .any_resource_path_by_id(document_id)
            .filter(|path| path.resource.file_kind() != Some(FILE_KIND_SYMLINK))
            .map(|path| self.cache.format_resource(path))
    }

    fn parent_of(&self, node: NodeRef) -> Option<NodeRef> {
        match self.parents.get(&node) {
            Some(parent) => NodeRef::from_parent(*parent),
            None => match node {
                NodeRef::Node(document_id) => self
                    .cache
                    .resources
                    .find_any(document_id)
                    .and_then(|resource| resource.parent_id())
                    .map(NodeRef::Node),
                NodeRef::Pending(_) => None,
            },
        }
    }

    fn ancestors(&self, start: Option<NodeRef>) -> impl Iterator<Item = NodeRef> + '_ {
        std::iter::successors(start, |node| self.parent_of(*node)).take(MAX_ANCESTOR_WALK)
    }

    fn depth_of(&self, parent: ParentRef) -> usize {
        self.ancestors(NodeRef::from_parent(parent)).count()
    }

    fn is_ancestor_or_self(&self, ancestor: u32, parent: ParentRef) -> bool {
        self.ancestors(NodeRef::from_parent(parent))
            .any(|node| node == NodeRef::Node(ancestor))
    }

    fn subtree_height(&mut self, document_id: u32) -> usize {
        if self.cache.container_resource_by_id(document_id).is_none() {
            return 1;
        }
        let target = NodeRef::Node(document_id);
        let nodes = self
            .parents
            .keys()
            .copied()
            .filter(|node| *node != target)
            .collect::<Vec<_>>();
        let mut height = self.cached_height(document_id);
        for node in nodes {
            let distance = self
                .ancestors(self.parent_of(node))
                .position(|ancestor| ancestor == target);
            if let Some(distance) = distance {
                let node_height = match node {
                    NodeRef::Node(id) => self.cached_height(id),
                    NodeRef::Pending(_) => 1,
                };
                height = height.max(distance + 1 + node_height);
            }
        }
        height
    }

    fn cached_height(&mut self, document_id: u32) -> usize {
        if let Some(height) = self.cached_heights.get(&document_id) {
            return *height;
        }
        let height = match self.cache.any_resource_path_by_id(document_id) {
            Some(root) if root.is_container() => {
                let base = root.path().bytes().filter(|b| *b == b'/').count();
                self.cache
                    .subtree(root.path())
                    .map(|resource| {
                        resource.path().bytes().filter(|b| *b == b'/').count() - base + 1
                    })
                    .max()
                    .unwrap_or(1)
            }
            _ => 1,
        };
        self.cached_heights.insert(document_id, height);
        height
    }
}

fn already_exists(holder: NodeRef) -> Rejection {
    match holder {
        NodeRef::Node(holder_id) => SetError::already_exists()
            .with_existing_id(Id::from(holder_id))
            .into(),
        NodeRef::Pending(slot) => Rejection {
            error: SetError::already_exists(),
            existing: Some(slot),
        },
    }
}

pub(super) fn fold_name(name: &str, case_insensitive: bool) -> Cow<'_, str> {
    if case_insensitive && name.chars().any(|c| c.is_uppercase()) {
        Cow::Owned(name.to_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

fn blob_not_found() -> SetError<FileNodeProperty> {
    SetError::invalid_properties()
        .with_property(FileNodeProperty::BlobId)
        .with_description("Blob could not be found.")
}

impl Deserialize for TemporaryBlobSize {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Ok(TemporaryBlobSize(
            bytes
                .try_into()
                .ok()
                .map(|bytes: [u8; U64_LEN]| u64::from_be_bytes(bytes)),
        ))
    }
}

pub(super) async fn fetch_archive(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::FileNode,
            document_id,
        ))
        .await
        .caused_by(trc::location!())
}
