/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    folder_id::{STORED_PENDING_ADD, STORED_PENDING_DELETE, SYNC_GROUPS, folder_type, is_listed},
    response::EasResponse,
};
use crate::{
    folders::{
        ExchangeFolders, FolderEntry, FolderNode, FolderTree, FolderWriteError, FolderWrites,
        SpecialFolder,
    },
    store::{
        FolderRef,
        eas::{EasDeviceState, EasDeviceWrite, EasHierarchyState, EasStore, StoredFolder},
    },
};
use ahash::AHashSet;
use common::Server;
use exchange_proto::{
    common::token::TokenBuf,
    eas::{
        commands::folder::{
            FolderChanges, FolderEntry as WireFolder, FolderSyncRequest, FolderSyncResponse,
        },
        http::Command,
        status::FolderStatus,
        wbxml::{Decoder, Encoder},
    },
    ids::eas::EasHierarchyKey,
};
use std::mem;
use store::{
    rand::{self, RngExt},
    write::{Archive, ArchiveBytes, BatchBuilder},
};

pub(crate) const MAX_STATE_ATTEMPTS: usize = 5;
pub(super) const ROOT_PARENT_ID: &str = "0";

pub trait EasFolderSync: Sync + Send {
    fn eas_folder_sync(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

struct WireEntry {
    server_id: TokenBuf,
    parent_id: TokenBuf,
    name: std::sync::Arc<str>,
    folder_type: exchange_proto::eas::types::FolderType,
}

pub(super) enum KeyCheck {
    Valid {
        base: [u64; SYNC_GROUPS],
        generation: u32,
    },
    Invalid,
}

impl EasFolderSync for Server {
    async fn eas_folder_sync(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(status(FolderStatus::MALFORMED_REQUEST));
        };
        let request = match FolderSyncRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::FolderSync,
                    err.status(Command::FolderSync),
                ));
            }
        };

        let mut tree = self
            .exchange_folder_tree(ctx.account_id, ctx.data_types)
            .await?;
        let mut creates_task_list = ctx.allows(EasDataKind::Calendar)
            && tree
                .special(SpecialFolder::Tasks)
                .is_some_and(|entry| entry.node == FolderNode::Special(SpecialFolder::Tasks))
            && tree
                .special(SpecialFolder::Calendar)
                .is_some_and(|entry| matches!(entry.node, FolderNode::Stored(_)));
        let mut creates_notes = ctx.allows(EasDataKind::Mail)
            && tree
                .special(SpecialFolder::Notes)
                .is_some_and(|entry| entry.node == FolderNode::Special(SpecialFolder::Notes));

        for _ in 0..MAX_STATE_ATTEMPTS {
            let (archive, mut state) = read_state(self, ctx).await?;
            let initial = request.sync_key.is_initial();
            if initial {
                state.sync = None;
            }
            let hierarchy = &mut state.hierarchy;
            let KeyCheck::Valid { base, generation } = (if initial {
                hierarchy.nonce = rand::rng().random();
                hierarchy.generation = 0;
                hierarchy.folders.clear();
                KeyCheck::Valid {
                    base: [0; SYNC_GROUPS],
                    generation: 0,
                }
            } else {
                check_key(hierarchy, request.sync_key.as_str())
            }) else {
                return Ok(status(FolderStatus::INVALID_SYNC_KEY));
            };
            let mut created = false;
            if mem::take(&mut creates_task_list) {
                created |= is_created(
                    self.folder_task_list(&ctx.access_token, ctx.account_id)
                        .await,
                );
            }
            if mem::take(&mut creates_notes) {
                created |= is_created(self.folder_notes(&ctx.access_token, ctx.account_id).await);
            }
            if created {
                tree = self
                    .exchange_folder_tree(ctx.account_id, ctx.data_types)
                    .await?;
            }
            let settled = settle(&mut hierarchy.folders, generation == hierarchy.generation);

            let diff = diff(&tree, &hierarchy.folders, &base);
            if diff.is_empty() && !initial {
                if settled || hierarchy.generation != generation {
                    hierarchy.generation = generation;
                    if !write_state(self, ctx, archive.as_ref(), state).await? {
                        continue;
                    }
                }
                return Ok(respond(ctx, request.sync_key.as_str(), diff, initial));
            }

            let next = EasHierarchyKey {
                nonce: hierarchy.nonce,
                generation: generation.wrapping_add(1),
                groups: current_groups(&tree, &base),
            };
            let Some(key) = next.encode() else {
                return Ok(status(FolderStatus::SERVER_ERROR));
            };
            for entry in &diff.adds {
                if let Some(node) = FolderNode::from_eas_collection_id(entry.server_id.as_str()) {
                    let mut stored = node.to_stored();
                    stored.kind |= STORED_PENDING_ADD;
                    hierarchy.folders.push(stored);
                }
            }
            for deleted in &diff.deletes {
                if let Some(stored) = hierarchy
                    .folders
                    .iter_mut()
                    .find(|stored| same_folder(**stored, *deleted))
                {
                    stored.kind |= STORED_PENDING_DELETE;
                }
            }
            hierarchy.generation = next.generation;
            if !write_state(self, ctx, archive.as_ref(), state).await? {
                continue;
            }
            return Ok(respond(ctx, key.as_str(), diff, initial));
        }

        Ok(status(FolderStatus::SERVER_ERROR))
    }
}

fn is_created(result: trc::Result<Result<FolderRef, FolderWriteError>>) -> bool {
    match result {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => false,
        Err(err) => {
            trc::error!(err.caused_by(trc::location!()));
            false
        }
    }
}

struct Diff {
    adds: Vec<WireEntry>,
    updates: Vec<WireEntry>,
    deletes: Vec<StoredFolder>,
    delete_ids: Vec<TokenBuf>,
}

impl Diff {
    fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.updates.is_empty() && self.deletes.is_empty()
    }
}

pub(super) fn check_key(hierarchy: &EasHierarchyState, key: &str) -> KeyCheck {
    match EasHierarchyKey::decode(key) {
        Some(key)
            if key.nonce == hierarchy.nonce
                && hierarchy.generation != 0
                && (key.generation == hierarchy.generation
                    || key.generation.wrapping_add(1) == hierarchy.generation) =>
        {
            KeyCheck::Valid {
                base: key.groups,
                generation: key.generation,
            }
        }
        _ => KeyCheck::Invalid,
    }
}

pub(super) fn is_current(hierarchy: &EasHierarchyState, tree: &FolderTree) -> bool {
    if hierarchy.generation == 0 {
        return false;
    }
    let mut held = 0;
    for stored in &hierarchy.folders {
        if stored.kind & STORED_PENDING_DELETE != 0 {
            continue;
        }
        let Some(node) = FolderNode::from_eas_stored(*stored) else {
            continue;
        };
        match tree.get(node) {
            Some(entry) if is_listed(entry) => held += 1,
            _ => return false,
        }
    }
    held == tree.iter().filter(|entry| is_listed(entry)).count()
}

pub(super) fn settle(folders: &mut Vec<StoredFolder>, confirmed: bool) -> bool {
    const PENDING: u8 = STORED_PENDING_ADD | STORED_PENDING_DELETE;
    if !folders.iter().any(|stored| stored.kind & PENDING != 0) {
        return false;
    }
    if confirmed {
        folders.retain(|stored| stored.kind & STORED_PENDING_DELETE == 0);
        for stored in folders.iter_mut() {
            stored.kind &= !STORED_PENDING_ADD;
        }
    } else {
        folders.retain(|stored| stored.kind & STORED_PENDING_ADD == 0);
        for stored in folders.iter_mut() {
            stored.kind &= !STORED_PENDING_DELETE;
        }
    }
    true
}

pub(super) fn same_folder(a: StoredFolder, b: StoredFolder) -> bool {
    a.id == b.id
        && (a.kind & !(STORED_PENDING_ADD | STORED_PENDING_DELETE))
            == (b.kind & !(STORED_PENDING_ADD | STORED_PENDING_DELETE))
}

fn diff(tree: &FolderTree, held: &[StoredFolder], base: &[u64; SYNC_GROUPS]) -> Diff {
    let held_nodes: AHashSet<FolderNode> = held
        .iter()
        .filter_map(|stored| FolderNode::from_eas_stored(*stored))
        .collect();
    let mut diff = Diff {
        adds: Vec::new(),
        updates: Vec::new(),
        deletes: Vec::new(),
        delete_ids: Vec::new(),
    };
    let mut listed = AHashSet::with_capacity(tree.len());
    for entry in tree.iter().filter(|entry| is_listed(entry)) {
        listed.insert(entry.node);
        if !held_nodes.contains(&entry.node) {
            diff.adds.push(wire_entry(entry));
        } else if base
            .get(entry.node.eas_sync_group())
            .is_some_and(|base| entry.change_id > *base)
        {
            diff.updates.push(wire_entry(entry));
        }
    }
    for node in held_nodes {
        if !listed.contains(&node) {
            diff.deletes.push(node.to_stored());
            diff.delete_ids.push(node.eas_collection_id());
        }
    }
    diff
}

fn wire_entry(entry: &FolderEntry) -> WireEntry {
    WireEntry {
        server_id: entry.node.eas_collection_id(),
        parent_id: match entry.parent {
            Some(FolderNode::Special(SpecialFolder::IpmSubtree | SpecialFolder::Root)) | None => {
                let mut root = TokenBuf::new();
                root.try_push_ascii(ROOT_PARENT_ID.as_bytes());
                root
            }
            Some(parent) => parent.eas_collection_id(),
        },
        name: entry.name.clone(),
        folder_type: folder_type(entry),
    }
}

fn current_groups(tree: &FolderTree, base: &[u64; SYNC_GROUPS]) -> [u64; SYNC_GROUPS] {
    let mut groups = *base;
    for entry in tree.iter().filter(|entry| is_listed(entry)) {
        if let Some(group) = groups.get_mut(entry.node.eas_sync_group()) {
            *group = (*group).max(entry.change_id);
        }
    }
    groups
}

pub(super) async fn read_state(
    server: &Server,
    ctx: &EasContext<'_>,
) -> trc::Result<(Option<Archive<ArchiveBytes>>, EasDeviceState)> {
    server
        .eas_device_state_seen(ctx.account_id, ctx.device.slot)
        .await
}

pub(super) async fn write_state(
    server: &Server,
    ctx: &EasContext<'_>,
    previous: Option<&Archive<ArchiveBytes>>,
    next: EasDeviceState,
) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    EasDeviceWrite {
        account_id: ctx.account_id,
        slot: ctx.device.slot,
        previous,
        next,
    }
    .build(&mut batch)?;
    match server.store().write_batch(&mut batch).await {
        Ok(_) => Ok(true),
        Err(err) if err.is_assertion_failure() => Ok(false),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

fn respond(ctx: &EasContext<'_>, key: &str, diff: Diff, initial: bool) -> EasResponse {
    let response = FolderSyncResponse {
        status: FolderStatus::SUCCESS,
        sync_key: Some(key),
        changes: Some(FolderChanges {
            updates: diff.updates.iter().map(WireEntry::as_wire).collect(),
            deletes: diff.delete_ids.iter().map(TokenBuf::as_str).collect(),
            adds: diff.adds.iter().map(WireEntry::as_wire).collect(),
        }),
    };
    let mut encoder = Encoder::new(ctx.version);
    response.encode(&mut encoder);
    let segments = encoder.finish();
    if initial {
        EasResponse::Resync(segments)
    } else {
        EasResponse::Wbxml(segments)
    }
}

impl WireEntry {
    fn as_wire(&self) -> WireFolder<'_> {
        WireFolder {
            server_id: self.server_id.as_str(),
            parent_id: self.parent_id.as_str(),
            display_name: &self.name,
            folder_type: self.folder_type,
        }
    }
}

fn status(status: FolderStatus) -> EasResponse {
    EasResponse::status(Command::FolderSync, status.into())
}
