/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    folder_id::{STORED_PENDING_ADD, STORED_PENDING_DELETE, is_listed},
    folder_sync::{
        KeyCheck, MAX_STATE_ATTEMPTS, ROOT_PARENT_ID, check_key, read_state, same_folder, settle,
        write_state,
    },
    response::EasResponse,
};
use crate::{
    folders::{
        ContainerClass, ExchangeFolders, FolderContents, FolderCreate, FolderEntry, FolderNode,
        FolderTree, FolderUpdate, FolderWriteError, FolderWrites, SpecialFolder, WritableFolder,
    },
    store::{
        FolderKind, FolderRef,
        eas::{EasFolderWrite as FolderStateWrite, EasStore, StoredFolder},
    },
};
use common::Server;
use exchange_proto::{
    common::token::TokenBuf,
    eas::{
        commands::{
            CommandError,
            folder::{
                FolderCreateRequest, FolderCreateResponse, FolderDeleteRequest,
                FolderDeleteResponse, FolderUpdateRequest, FolderUpdateResponse,
            },
        },
        http::Command,
        status::{FolderStatus, Status},
        tokens::ProtocolVersion,
        types::FolderType,
        wbxml::Decoder,
    },
    ids::eas::EasHierarchyKey,
};
use smallvec::SmallVec;
use std::iter;
use store::write::BatchBuilder;

pub trait EasFolderWrite: Sync + Send {
    fn eas_folder_create(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;

    fn eas_folder_update(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;

    fn eas_folder_delete(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

enum HierarchyEdit<'x> {
    Create(Placement<'x>),
    Update(Placement<'x>),
    Delete(FolderNode),
}

struct Placement<'x> {
    node: FolderNode,
    parent: FolderNode,
    name: &'x str,
}

impl EasFolderWrite for Server {
    async fn eas_folder_create(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        const COMMAND: Command = Command::FolderCreate;
        let request = match parse(decoder, ctx.version, COMMAND, FolderCreateRequest::parse) {
            Ok(request) => request,
            Err(failed) => return Ok(EasResponse::status(COMMAND, failed)),
        };
        let sync_key = request.sync_key.as_str();
        if !key_matches(self, ctx, sync_key).await? {
            return Ok(status(COMMAND, FolderStatus::INVALID_SYNC_KEY));
        }
        let Some((kind, data_kind, class)) = writable_kind(request.folder_type) else {
            return Ok(status(COMMAND, FolderStatus::MALFORMED_REQUEST));
        };
        let Some(parent) = wire_parent(&request.parent_id) else {
            return Ok(status(COMMAND, FolderStatus::PARENT_NOT_FOUND));
        };
        let written = if ctx.allows(data_kind) {
            self.folder_create(
                &ctx.access_token,
                ctx.account_id,
                FolderCreate {
                    kind,
                    parent,
                    name: &request.display_name,
                    class: class.as_ref().map(ContainerClass::as_str),
                    search: None,
                    client_key: None,
                },
            )
            .await?
        } else {
            Err(FolderWriteError::Forbidden)
        };
        let node = match written {
            Ok(written) => FolderNode::Stored(written.folder),
            Err(err) => return Ok(status(COMMAND, create_status(err))),
        };
        let edit = HierarchyEdit::Create(Placement {
            node,
            parent,
            name: &request.display_name,
        });
        Ok(match advance(self, ctx, sync_key, &edit).await? {
            Ok(key) => {
                let server_id = node.eas_collection_id();
                EasResponse::encode(ctx.version, |encoder| {
                    FolderCreateResponse {
                        status: FolderStatus::SUCCESS,
                        sync_key: Some(key.as_str()),
                        server_id: Some(server_id.as_str()),
                    }
                    .encode(encoder)
                })
            }
            Err(failed) => status(COMMAND, failed),
        })
    }

    async fn eas_folder_update(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        const COMMAND: Command = Command::FolderUpdate;
        let request = match parse(decoder, ctx.version, COMMAND, FolderUpdateRequest::parse) {
            Ok(request) => request,
            Err(failed) => return Ok(EasResponse::status(COMMAND, failed)),
        };
        let sync_key = request.sync_key.as_str();
        if !key_matches(self, ctx, sync_key).await? {
            return Ok(status(COMMAND, FolderStatus::INVALID_SYNC_KEY));
        }
        let Some(parent) = wire_parent(&request.parent_id) else {
            return Ok(status(COMMAND, FolderStatus::PARENT_NOT_FOUND));
        };
        let name = request.display_name.as_ref();
        let (node, update) = {
            let tree = self
                .exchange_folder_tree(ctx.account_id, ctx.data_types)
                .await?;
            let Some(entry) = listed_entry(ctx, &tree, &request.server_id) else {
                return Ok(status(COMMAND, FolderStatus::NOT_FOUND));
            };
            let update = FolderUpdate {
                name: (*entry.name != *name).then_some(name),
                parent: (listed_parent(entry.parent) != parent).then_some(parent),
            };
            (entry.node, update)
        };
        if (update.name.is_some() || update.parent.is_some())
            && let Err(err) = self
                .folder_update(&ctx.access_token, ctx.account_id, node, update)
                .await?
        {
            return Ok(status(COMMAND, update_status(err)));
        }
        let edit = HierarchyEdit::Update(Placement { node, parent, name });
        Ok(match advance(self, ctx, sync_key, &edit).await? {
            Ok(key) => EasResponse::encode(ctx.version, |encoder| {
                FolderUpdateResponse {
                    status: FolderStatus::SUCCESS,
                    sync_key: Some(key.as_str()),
                }
                .encode(encoder)
            }),
            Err(failed) => status(COMMAND, failed),
        })
    }

    async fn eas_folder_delete(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        const COMMAND: Command = Command::FolderDelete;
        let request = match parse(decoder, ctx.version, COMMAND, FolderDeleteRequest::parse) {
            Ok(request) => request,
            Err(failed) => return Ok(EasResponse::status(COMMAND, failed)),
        };
        let sync_key = request.sync_key.as_str();
        if !key_matches(self, ctx, sync_key).await? {
            return Ok(status(COMMAND, FolderStatus::INVALID_SYNC_KEY));
        }
        let (node, removed) = {
            let tree = self
                .exchange_folder_tree(ctx.account_id, ctx.data_types)
                .await?;
            let Some(entry) = listed_entry(ctx, &tree, &request.server_id) else {
                return Ok(status(COMMAND, FolderStatus::NOT_FOUND));
            };
            let removed = stored_subtree(&tree, entry.node).collect::<SmallVec<[FolderRef; 4]>>();
            (entry.node, removed)
        };
        if let Err(err) = self
            .folder_destroy(
                &ctx.access_token,
                ctx.account_id,
                node,
                FolderContents::Remove,
            )
            .await?
        {
            return Ok(status(COMMAND, delete_status(err)));
        }
        if let Err(err) = forget_folder_states(self, ctx, &removed).await {
            trc::error!(err.details("Failed to clear EAS folder states"));
        }
        Ok(
            match advance(self, ctx, sync_key, &HierarchyEdit::Delete(node)).await? {
                Ok(key) => EasResponse::encode(ctx.version, |encoder| {
                    FolderDeleteResponse {
                        status: FolderStatus::SUCCESS,
                        sync_key: Some(key.as_str()),
                    }
                    .encode(encoder)
                }),
                Err(failed) => status(COMMAND, failed),
            },
        )
    }
}

pub(super) fn stored_subtree(
    tree: &FolderTree,
    node: FolderNode,
) -> impl Iterator<Item = FolderRef> {
    iter::once(node)
        .chain(tree.descendants(node).map(|entry| entry.node))
        .filter_map(|node| match node {
            FolderNode::Stored(folder) => Some(folder),
            FolderNode::Special(_) => None,
        })
}

pub(super) async fn forget_folder_states(
    server: &Server,
    ctx: &EasContext<'_>,
    removed: &[FolderRef],
) -> trc::Result<()> {
    let mut batch = BatchBuilder::new();
    for &folder in removed {
        let Some(previous) = server
            .eas_folder_state(ctx.account_id, ctx.device.slot, folder)
            .await?
        else {
            continue;
        };
        FolderStateWrite {
            account_id: ctx.account_id,
            slot: ctx.device.slot,
            folder,
            previous: Some(&previous),
            next: None,
        }
        .build(&mut batch)?;
        batch.commit_point();
    }
    if batch.is_empty() {
        return Ok(());
    }
    match server.store().write_batch(&mut batch).await {
        Ok(_) => Ok(()),
        Err(err) if err.is_assertion_failure() => Ok(()),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

fn parse<'a, T>(
    decoder: Option<&mut Decoder<'a>>,
    version: ProtocolVersion,
    command: Command,
    parse: impl FnOnce(&mut Decoder<'a>, ProtocolVersion) -> Result<T, CommandError>,
) -> Result<T, Status> {
    let Some(decoder) = decoder else {
        return Err(FolderStatus::MALFORMED_REQUEST.into());
    };
    parse(decoder, version).map_err(|err| err.status(command))
}

async fn key_matches(server: &Server, ctx: &EasContext<'_>, key: &str) -> trc::Result<bool> {
    let (_, state) = read_state(server, ctx).await?;
    Ok(matches!(
        check_key(&state.hierarchy, key),
        KeyCheck::Valid { .. }
    ))
}

async fn advance(
    server: &Server,
    ctx: &EasContext<'_>,
    key: &str,
    edit: &HierarchyEdit<'_>,
) -> trc::Result<Result<TokenBuf, FolderStatus>> {
    let tree = match edit {
        HierarchyEdit::Create(_) | HierarchyEdit::Update(_) => Some(
            server
                .exchange_folder_tree(ctx.account_id, ctx.data_types)
                .await?,
        ),
        HierarchyEdit::Delete(_) => None,
    };
    for _ in 0..MAX_STATE_ATTEMPTS {
        let (archive, mut state) = read_state(server, ctx).await?;
        let hierarchy = &mut state.hierarchy;
        let KeyCheck::Valid { base, generation } = check_key(hierarchy, key) else {
            return Ok(Err(FolderStatus::INVALID_SYNC_KEY));
        };
        settle(&mut hierarchy.folders, generation == hierarchy.generation);
        let mut groups = base;
        match edit {
            HierarchyEdit::Create(placement) => {
                let stored = placement.node.to_stored();
                if !hierarchy
                    .folders
                    .iter()
                    .any(|held| same_folder(*held, stored))
                {
                    hierarchy.folders.push(StoredFolder {
                        kind: stored.kind | STORED_PENDING_ADD,
                        id: stored.id,
                    });
                }
                if let Some(tree) = &tree {
                    raise_watermark(tree, &mut groups, placement);
                }
            }
            HierarchyEdit::Update(placement) => {
                if let Some(tree) = &tree {
                    raise_watermark(tree, &mut groups, placement);
                }
            }
            HierarchyEdit::Delete(node) => {
                let stored = node.to_stored();
                if let Some(held) = hierarchy
                    .folders
                    .iter_mut()
                    .find(|held| same_folder(**held, stored))
                {
                    held.kind |= STORED_PENDING_DELETE;
                }
            }
        }
        let next = EasHierarchyKey {
            nonce: hierarchy.nonce,
            generation: generation.wrapping_add(1),
            groups,
        };
        let Some(token) = next.encode() else {
            return Ok(Err(FolderStatus::SERVER_ERROR));
        };
        hierarchy.generation = next.generation;
        if write_state(server, ctx, archive.as_ref(), state).await? {
            return Ok(Ok(token));
        }
    }
    Ok(Err(FolderStatus::SERVER_ERROR))
}

fn listed_entry<'t>(
    ctx: &EasContext<'_>,
    tree: &'t FolderTree,
    server_id: &str,
) -> Option<&'t FolderEntry> {
    let entry = tree.get(FolderNode::from_eas_collection_id(server_id)?)?;
    let data_kind = match entry.node {
        FolderNode::Stored(FolderRef { kind, .. }) => match kind {
            FolderKind::Mailbox => Some(EasDataKind::Mail),
            FolderKind::Calendar => Some(EasDataKind::Calendar),
            FolderKind::AddressBook => Some(EasDataKind::Contacts),
            FolderKind::FileNode | FolderKind::Virtual => None,
        },
        FolderNode::Special(_) => None,
    };
    (is_listed(entry) && data_kind.is_none_or(|data_kind| ctx.allows(data_kind))).then_some(entry)
}

fn raise_watermark(tree: &FolderTree, groups: &mut [u64], placement: &Placement<'_>) {
    let Some(entry) = tree.get(placement.node).filter(|entry| {
        is_listed(entry)
            && listed_parent(entry.parent) == placement.parent
            && *entry.name == *placement.name
    }) else {
        return;
    };
    let group = placement.node.eas_sync_group();
    let Some(base) = groups.get_mut(group) else {
        return;
    };
    let moved_past_base = tree
        .iter()
        .filter(|other| other.change_id > *base && other.node.eas_sync_group() == group)
        .any(|other| other.node != entry.node && is_listed(other));
    if !moved_past_base {
        *base = (*base).max(entry.change_id);
    }
}

fn writable_kind(
    folder_type: FolderType,
) -> Option<(WritableFolder, EasDataKind, Option<ContainerClass>)> {
    match folder_type {
        FolderType::GENERIC | FolderType::USER_MAIL => {
            Some((WritableFolder::Mailbox, EasDataKind::Mail, None))
        }
        FolderType::USER_CALENDAR => Some((WritableFolder::Calendar, EasDataKind::Calendar, None)),
        FolderType::USER_TASKS => Some((
            WritableFolder::Calendar,
            EasDataKind::Calendar,
            Some(ContainerClass::Task),
        )),
        FolderType::USER_CONTACTS => {
            Some((WritableFolder::AddressBook, EasDataKind::Contacts, None))
        }
        _ => None,
    }
}

fn wire_parent(parent_id: &str) -> Option<FolderNode> {
    if parent_id == ROOT_PARENT_ID {
        Some(FolderNode::Special(SpecialFolder::IpmSubtree))
    } else {
        FolderNode::from_eas_collection_id(parent_id)
    }
}

fn listed_parent(parent: Option<FolderNode>) -> FolderNode {
    match parent {
        Some(FolderNode::Special(SpecialFolder::Root)) | None => {
            FolderNode::Special(SpecialFolder::IpmSubtree)
        }
        Some(parent) => parent,
    }
}

fn create_status(err: FolderWriteError) -> FolderStatus {
    match err {
        FolderWriteError::AlreadyExists(_) => FolderStatus::ALREADY_EXISTS,
        FolderWriteError::NotFound | FolderWriteError::ParentNotFound => {
            FolderStatus::PARENT_NOT_FOUND
        }
        FolderWriteError::InvalidParent
        | FolderWriteError::Forbidden
        | FolderWriteError::Protected => FolderStatus::SPECIAL_FOLDER,
        FolderWriteError::Conflict => FolderStatus::SERVER_ERROR,
        FolderWriteError::OverQuota
        | FolderWriteError::HasChildren
        | FolderWriteError::HasItems => FolderStatus::UNKNOWN_ERROR,
        FolderWriteError::EmptyName
        | FolderWriteError::NameTooLong
        | FolderWriteError::Unsupported
        | FolderWriteError::InvalidSearch
        | FolderWriteError::Cycle
        | FolderWriteError::TooDeep => FolderStatus::MALFORMED_REQUEST,
    }
}

fn update_status(err: FolderWriteError) -> FolderStatus {
    match err {
        FolderWriteError::AlreadyExists(_)
        | FolderWriteError::Forbidden
        | FolderWriteError::Protected => FolderStatus::ALREADY_EXISTS,
        FolderWriteError::NotFound => FolderStatus::NOT_FOUND,
        FolderWriteError::ParentNotFound => FolderStatus::PARENT_NOT_FOUND,
        FolderWriteError::Conflict => FolderStatus::SERVER_ERROR,
        FolderWriteError::OverQuota
        | FolderWriteError::HasChildren
        | FolderWriteError::HasItems => FolderStatus::UNKNOWN_ERROR,
        FolderWriteError::EmptyName
        | FolderWriteError::NameTooLong
        | FolderWriteError::Unsupported
        | FolderWriteError::InvalidSearch
        | FolderWriteError::InvalidParent
        | FolderWriteError::Cycle
        | FolderWriteError::TooDeep => FolderStatus::MALFORMED_REQUEST,
    }
}

fn delete_status(err: FolderWriteError) -> FolderStatus {
    match err {
        FolderWriteError::NotFound => FolderStatus::NOT_FOUND,
        FolderWriteError::Forbidden | FolderWriteError::Protected => FolderStatus::SPECIAL_FOLDER,
        FolderWriteError::Conflict => FolderStatus::SERVER_ERROR,
        _ => FolderStatus::UNKNOWN_ERROR,
    }
}

fn status(command: Command, status: FolderStatus) -> EasResponse {
    EasResponse::status(command, status.into())
}
