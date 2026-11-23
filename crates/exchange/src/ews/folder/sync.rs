/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FolderCounts, FolderFieldSet, FolderRenderer, FolderSelector, resolve_folder};
use crate::{
    ews::{
        context::EwsContext,
        reply::{RESPONSE_CAPACITY, ews_response},
    },
    folders::{FolderEntry, FolderNode, FolderTree, HierarchyVersion, SpecialFolder},
    store::{FolderKind, FolderRef},
};
use ahash::AHashSet;
use common::Server;
use exchange_proto::{
    common::token::TokenBuf,
    ews::{
        MessageResult, Operation, Status,
        requests::sync::SyncFolderHierarchy,
        responses::sync::{FolderSyncChange, SyncFolderHierarchyMessage},
        schema::ResponseCode,
        types::ids::{EwsIdStr, FolderId},
    },
    ids::{
        ews::{EwsObjectId, EwsSyncState, HierarchyPage},
        token::ObjectKind,
    },
};
use http_proto::HttpResponse;
use std::borrow::Cow;
use store::query::log::{Change, Query};
use trc::AddContext;
use types::{collection::SyncCollection, type_state::DataType};

const PAGE_SIZE: usize = 512;
const GROUPS: usize = 4;
const VIRTUAL_GROUP: usize = 3;
const LOGGED_GROUPS: [(SyncCollection, ObjectKind, DataType); 3] = [
    (
        SyncCollection::Email,
        ObjectKind::MailFolder,
        DataType::Email,
    ),
    (
        SyncCollection::Calendar,
        ObjectKind::Calendar,
        DataType::CalendarEvent,
    ),
    (
        SyncCollection::AddressBook,
        ObjectKind::AddressBook,
        DataType::ContactCard,
    ),
];
const ROOT_SPECIAL_BASE: u32 = 0xFFFF_FF00;
const ROOT_KIND_SHIFT: u32 = 29;
const ROOT_ID_MASK: u32 = (1 << ROOT_KIND_SHIFT) - 1;
const INVALID_STATE: &str = "Synchronization state data is corrupt or otherwise invalid.";

pub(crate) async fn sync_folder_hierarchy(
    server: &Server,
    ctx: &EwsContext,
    request: &SyncFolderHierarchy<'_>,
) -> trc::Result<HttpResponse> {
    let tree = ctx.folder_tree(server).await?;
    let result = match request.folder.as_ref() {
        Some(folder) => resolve_folder(server, ctx, &tree, FolderSelector::from(folder)).await?,
        None => tree
            .special(SpecialFolder::IpmSubtree)
            .ok_or_else(super::folder_not_found),
    };
    let result = match result {
        Ok(root) => sync(server, ctx, &tree, root, request).await?,
        Err(status) => Err(status),
    };

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx
        .envelope(&mut out)
        .shape_a(Operation::SyncFolderHierarchy);
    match result {
        Ok(delta) => {
            let fields = FolderFieldSet::from_shape(&request.shape);
            let renderer = FolderRenderer {
                tree: &tree,
                access: &ctx.access,
                account_id: ctx.account.account_id,
                fields,
                counts: FolderCounts::load(
                    server,
                    ctx,
                    fields,
                    delta.changes.iter().filter_map(|change| match change {
                        Delta::Create(entry) | Delta::Update(entry) => Some(*entry),
                        Delta::Delete(..) => None,
                    }),
                )
                .await?,
            };
            let account_id = ctx.account.account_id;
            messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(SyncFolderHierarchyMessage {
                    state: Cow::Borrowed(delta.state.as_str()),
                    includes_last_folder_in_range: delta.last,
                    changes: delta
                        .changes
                        .iter()
                        .map(|change| match change {
                            Delta::Create(entry) => {
                                FolderSyncChange::Create(renderer.render(entry))
                            }
                            Delta::Update(entry) => {
                                FolderSyncChange::Update(renderer.render(entry))
                            }
                            Delta::Delete(kind, id) => FolderSyncChange::Delete(FolderId {
                                id: EwsIdStr::Minted(
                                    EwsObjectId::Folder {
                                        account: account_id,
                                        kind: *kind,
                                        id: *id,
                                    }
                                    .encode(),
                                ),
                                change_key: None,
                            }),
                        })
                        .collect(),
                }),
            });
        }
        Err(status) => {
            messages.message(&MessageResult::<SyncFolderHierarchyMessage> { status, body: None })
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

#[derive(Default)]
struct GroupLog {
    inserted: AHashSet<u32>,
    updated: AHashSet<u32>,
    deleted: AHashSet<u32>,
}

enum Delta<'t> {
    Create(&'t FolderEntry),
    Update(&'t FolderEntry),
    Delete(ObjectKind, u32),
}

struct HierarchyDelta<'t> {
    changes: Vec<Delta<'t>>,
    state: TokenBuf,
    last: bool,
}

async fn sync<'t>(
    server: &Server,
    ctx: &EwsContext,
    tree: &'t FolderTree,
    root: &'t FolderEntry,
    request: &SyncFolderHierarchy<'_>,
) -> trc::Result<Result<HierarchyDelta<'t>, Status<'static>>> {
    let current = groups_of(&tree.version());
    let current_synthetic = tree
        .descendants(root.node)
        .filter_map(|entry| match entry.node {
            FolderNode::Special(special) => Some(special.bit()),
            FolderNode::Stored(_) => None,
        })
        .fold(0, |mask, bit| mask | bit);
    let root_key = root_key(root.special, root.node);
    let delegate = ctx.access.is_delegate();
    let visible = if ctx.targets_caller() {
        None
    } else if delegate {
        Some(tree.stored_hash(ctx.account.account_id))
    } else {
        Some(FolderTree::account_hash(ctx.account.account_id))
    };
    let (base, base_synthetic, offset) =
        match request.state.as_deref().filter(|state| !state.is_empty()) {
            None => (None, 0, 0),
            Some(state) => match EwsSyncState::decode(state) {
                Some(EwsSyncState::Hierarchy {
                    root: state_root,
                    groups,
                    synthetic,
                    page,
                    visible: state_visible,
                }) if state_root == Some(root_key) && state_visible == visible => (
                    Some(groups),
                    synthetic,
                    page.filter(|page| {
                        page.snapshot == current && page.synthetic == current_synthetic
                    })
                    .map_or(0, |page| page.offset as usize),
                ),
                _ => return Ok(Err(invalid_state())),
            },
        };

    let base = base.filter(|groups| *groups != [0; GROUPS]);
    let mut changes = Vec::new();
    match base {
        None => {
            changes.extend(tree.descendants(root.node).map(Delta::Create));
        }
        Some(base) => {
            let virtual_base = base[VIRTUAL_GROUP];
            if virtual_base < tree.version().virtual_horizon {
                return Ok(Err(invalid_state()));
            }
            changes.extend(
                tree.virtual_deletions()
                    .iter()
                    .filter(|(_, change)| *change > virtual_base)
                    .filter_map(|&(id, _)| {
                        FolderNode::Stored(FolderRef {
                            kind: FolderKind::Virtual,
                            id,
                        })
                        .object_id()
                    })
                    .map(|(kind, id)| Delta::Delete(kind, id)),
            );
            changes.extend(
                SpecialFolder::ALL
                    .iter()
                    .filter(|special| base_synthetic & !current_synthetic & special.bit() != 0)
                    .filter_map(|special| FolderNode::Special(*special).object_id())
                    .map(|(kind, id)| Delta::Delete(kind, id)),
            );
            let flipped = base_synthetic ^ current_synthetic;
            let reparented = SpecialFolder::ALL
                .iter()
                .filter(|special| flipped & special.bit() != 0)
                .filter_map(|special| tree.special(*special))
                .flat_map(|entry| tree.descendants(entry.node))
                .filter_map(|entry| match entry.node {
                    FolderNode::Special(special) => Some(special.bit()),
                    FolderNode::Stored(_) => None,
                })
                .fold(0, |mask, bit| mask | bit);
            let mut logged: [GroupLog; 3] = Default::default();
            for (((collection, kind, data_type), logged), (&from, &to)) in LOGGED_GROUPS
                .iter()
                .zip(logged.iter_mut())
                .zip(base.iter().zip(current.iter()))
            {
                if to <= from || !ctx.account.data_types.contains(*data_type) {
                    continue;
                }
                let log = server
                    .store()
                    .changes(
                        ctx.account.account_id,
                        (*collection).into(),
                        Query::Since(from),
                    )
                    .await
                    .caused_by(trc::location!())?;
                if log.needs_full_rebuild(from) {
                    return Ok(Err(invalid_state()));
                }
                if delegate {
                    logged
                        .updated
                        .extend(log.changes.iter().filter_map(|change| match *change {
                            Change::UpdateContainer(id) => u32::try_from(id).ok(),
                            Change::UpdateContainerPartial(id, partial)
                                if partial.has_properties() =>
                            {
                                u32::try_from(id).ok()
                            }
                            _ => None,
                        }));
                    continue;
                }
                for change in &log.changes {
                    let (set, id) = match *change {
                        Change::InsertContainer(id) => (&mut logged.inserted, id),
                        Change::UpdateContainer(id) => (&mut logged.updated, id),
                        Change::UpdateContainerPartial(id, partial) if partial.has_properties() => {
                            (&mut logged.updated, id)
                        }
                        Change::DeleteContainer(id) => (&mut logged.deleted, id),
                        _ => continue,
                    };
                    if let Ok(id) = u32::try_from(id) {
                        set.insert(id);
                    }
                }
                changes.extend(
                    logged
                        .deleted
                        .iter()
                        .filter(|id| {
                            logged.inserted.contains(id)
                                == FolderNode::from_object_id(*kind, **id)
                                    .is_some_and(|node| tree.get(node).is_some())
                        })
                        .map(|id| Delta::Delete(*kind, *id)),
                );
            }
            for entry in tree.descendants(root.node) {
                let (group, id) = match entry.node {
                    FolderNode::Stored(FolderRef { kind, id }) => match kind {
                        FolderKind::Mailbox => (0, id),
                        FolderKind::Calendar => (1, id),
                        FolderKind::AddressBook => (2, id),
                        FolderKind::FileNode | FolderKind::Virtual => {
                            if entry.change_id > virtual_base {
                                changes.push(Delta::Update(entry));
                            }
                            continue;
                        }
                    },
                    FolderNode::Special(special) => {
                        if (!base_synthetic | reparented) & special.bit() != 0 {
                            changes.push(Delta::Create(entry));
                        }
                        continue;
                    }
                };
                let Some(logged) = logged.get(group) else {
                    continue;
                };
                if logged.inserted.contains(&id) {
                    changes.push(Delta::Create(entry));
                } else if logged.updated.contains(&id) {
                    changes.push(Delta::Update(entry));
                }
            }
        }
    }

    let end = offset.saturating_add(PAGE_SIZE).min(changes.len());
    let last = end == changes.len();
    let offset = offset.min(end);
    changes.truncate(end);
    changes.drain(..offset);
    let state = match (last, base) {
        (false, base) => EwsSyncState::Hierarchy {
            root: Some(root_key),
            groups: base.unwrap_or_default(),
            synthetic: base_synthetic,
            page: Some(HierarchyPage {
                snapshot: current,
                synthetic: current_synthetic,
                offset: u32::try_from(end).unwrap_or(u32::MAX),
            }),
            visible,
        },
        (true, _) => EwsSyncState::Hierarchy {
            root: Some(root_key),
            groups: current,
            synthetic: current_synthetic,
            page: None,
            visible,
        },
    };
    let Some(state) = state.encode() else {
        return Ok(Err(invalid_state()));
    };
    Ok(Ok(HierarchyDelta {
        changes,
        state,
        last,
    }))
}

fn groups_of(version: &HierarchyVersion) -> [u64; GROUPS] {
    [
        version.mail,
        version.calendar,
        version.address_book,
        version.virtual_change,
    ]
}

fn root_key(special: Option<SpecialFolder>, node: FolderNode) -> u32 {
    match (special, node) {
        (
            Some(special),
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar | FolderKind::AddressBook,
                ..
            }),
        )
        | (Some(special), FolderNode::Special(_))
        | (None, FolderNode::Special(special)) => ROOT_SPECIAL_BASE | u32::from(special.code()),
        (_, FolderNode::Stored(FolderRef { kind, id })) => {
            ((kind as u32) << ROOT_KIND_SHIFT) | (id & ROOT_ID_MASK)
        }
    }
}

fn invalid_state() -> Status<'static> {
    Status::error(ResponseCode::ErrorInvalidSyncStateData, INVALID_STATE)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/folder/sync/tests.rs"]
mod tests;
