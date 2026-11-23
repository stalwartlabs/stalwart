/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderContents, FolderCreate, FolderUpdate, FolderWriteError, FolderWriteResult, FolderWritten,
    WritableFolder, WriteOutcome, container_tree, mailbox::mailbox_name,
};
use crate::{
    folders::{FolderNode, FolderTree, SpecialFolder},
    store::{
        FolderKind, FolderRef,
        account::{ExchangeAccountStore, ExchangeCounter, MAX_UPDATE_ATTEMPTS},
        account_key,
        folder::{
            FaiFolder, FolderStore, SearchDefinition, VirtualFolder, VirtualFolderNext,
            VirtualFolderWrite,
        },
        object::ExchangeObject,
    },
};
use common::{Server, auth::AccessToken};
use std::mem;
use store::write::{
    Archive, ArchiveBytes, BatchBuilder, metadata::ExchangeClass, serialize::rkyv_deserialize,
};
use trc::{AddContext, EventType, LimitEvent};
use types::collection::Collection;

const SEARCH_SCOPE_MAX: usize = 4096;

type Rows<'x> = Vec<(u32, Option<&'x Archive<ArchiveBytes>>, VirtualFolderNext)>;

pub(super) async fn create(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    create: FolderCreate<'_>,
) -> FolderWriteResult {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let is_search = create.search.is_some();
    let tree = if is_search {
        container_tree(server, account_id).await?
    } else {
        WritableFolder::Virtual
            .folder_tree(server, account_id)
            .await?
    };
    let parent = match placement(server, &tree, create.parent, is_search, None) {
        Ok(parent) => parent,
        Err(err) => return Ok(Err(err)),
    };
    let name = match mailbox_name(server, create.name)
        .and_then(|name| {
            if is_search {
                Ok(name)
            } else {
                assert_unique_name(&tree, parent, None, name).map(|()| name)
            }
        })
        .and_then(|name| {
            create
                .search
                .map_or(Ok(()), |search| validate_scope(&tree, search))
                .map(|()| name)
        }) {
        Ok(name) => name,
        Err(err) => return Ok(Err(err)),
    };
    let parent_row = match parent_row(server, account_id, parent).await? {
        Ok(parent_row) => parent_row,
        Err(err) => return Ok(Err(err)),
    };
    let mut folder = VirtualFolder {
        change: 0,
        modified: 0,
        parent: parent.to_stored(),
        name: name.to_string(),
        container_class: create.class.unwrap_or_default().to_string(),
        search: create.search.cloned(),
        properties: Vec::new(),
    };
    if !has_quota(server, account_id, folder.quota_size()).await? {
        return Ok(Err(FolderWriteError::OverQuota));
    }
    write(
        server,
        access_token,
        account_id,
        parent_row.as_ref(),
        [(ExchangeCounter::Folder, 1), (ExchangeCounter::Change, 1)],
        |[id, change]| {
            let id = u32::try_from(id).map_err(|_| exhausted())?;
            folder.stamp(change);
            if let Some(search) = &mut folder.search {
                search.started = change;
            }
            Ok((
                id,
                change,
                vec![(id, None, VirtualFolderNext::Live(folder.clone()))],
            ))
        },
    )
    .await
}

pub(super) async fn update(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
    update: FolderUpdate<'_>,
) -> FolderWriteResult {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let node = virtual_node(id);
    let tree = WritableFolder::Virtual
        .folder_tree(server, account_id)
        .await?;
    let (Some(entry), Some(previous)) = (tree.get(node), read_row(server, account_id, id).await?)
    else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let mut folder = previous
        .deserialize::<VirtualFolder>()
        .caused_by(trc::location!())?;
    let is_search = folder.search.is_some();
    let stored_parent = folder.parent;
    let mut parent_row = None;
    let parent = match update.parent {
        Some(parent) => match placement(server, &tree, parent, is_search, Some(node)) {
            Ok(placed) => {
                folder.parent = placed.to_stored();
                if folder.parent != stored_parent {
                    parent_row = match self::parent_row(server, account_id, placed).await? {
                        Ok(parent_row) => parent_row,
                        Err(err) => return Ok(Err(err)),
                    };
                }
                Some(placed)
            }
            Err(err) => return Ok(Err(err)),
        },
        None => entry.parent,
    };
    let name = match update
        .name
        .map(|name| mailbox_name(server, name))
        .transpose()
    {
        Ok(name) => name.unwrap_or(&entry.name),
        Err(err) => return Ok(Err(err)),
    };
    if folder.parent == stored_parent && name == &*entry.name {
        return Ok(Ok(FolderWritten {
            folder: node_ref(id),
            change_id: None,
            outcome: WriteOutcome::Written,
        }));
    }
    if let Some(parent) = parent
        && !is_search
        && let Err(err) = assert_unique_name(&tree, parent, Some(node), name)
    {
        return Ok(Err(err));
    }
    let previous_size = folder.quota_size();
    name.clone_into(&mut folder.name);
    let growth = folder.quota_size() - previous_size;
    if growth > 0 && !has_quota(server, account_id, growth).await? {
        return Ok(Err(FolderWriteError::OverQuota));
    }
    write(
        server,
        access_token,
        account_id,
        parent_row.as_ref(),
        [(ExchangeCounter::Change, 1)],
        |[change]| {
            folder.stamp(change);
            Ok((
                id,
                change,
                vec![(id, Some(&previous), VirtualFolderNext::Live(folder.clone()))],
            ))
        },
    )
    .await
}

pub(super) async fn set_search(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
    search: &SearchDefinition,
) -> FolderWriteResult {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let Some(previous) = read_row(server, account_id, id).await? else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let mut folder = previous
        .deserialize::<VirtualFolder>()
        .caused_by(trc::location!())?;
    match &folder.search {
        None => return Ok(Err(FolderWriteError::InvalidSearch)),
        Some(current) if current == search => {
            return Ok(Ok(FolderWritten {
                folder: node_ref(id),
                change_id: None,
                outcome: WriteOutcome::Written,
            }));
        }
        Some(_) => {}
    }
    let tree = container_tree(server, account_id).await?;
    if let Err(err) = validate_scope(&tree, search) {
        return Ok(Err(err));
    }
    let previous_size = folder.quota_size();
    folder.search = Some(search.clone());
    let growth = folder.quota_size() - previous_size;
    if growth > 0 && !has_quota(server, account_id, growth).await? {
        return Ok(Err(FolderWriteError::OverQuota));
    }
    write(
        server,
        access_token,
        account_id,
        None,
        [(ExchangeCounter::Change, 1)],
        |[change]| {
            folder.stamp(change);
            if let Some(search) = &mut folder.search {
                search.started = change;
            }
            Ok((
                id,
                change,
                vec![(id, Some(&previous), VirtualFolderNext::Live(folder.clone()))],
            ))
        },
    )
    .await
}

pub(super) async fn set_class(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
    class: &str,
) -> FolderWriteResult {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let Some(previous) = read_row(server, account_id, id).await? else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let mut folder = previous
        .deserialize::<VirtualFolder>()
        .caused_by(trc::location!())?;
    if folder.container_class == class {
        return Ok(Ok(FolderWritten {
            folder: node_ref(id),
            change_id: None,
            outcome: WriteOutcome::Written,
        }));
    }
    let previous_size = folder.quota_size();
    class.clone_into(&mut folder.container_class);
    let growth = folder.quota_size() - previous_size;
    if growth > 0 && !has_quota(server, account_id, growth).await? {
        return Ok(Err(FolderWriteError::OverQuota));
    }
    write(
        server,
        access_token,
        account_id,
        None,
        [(ExchangeCounter::Change, 1)],
        |[change]| {
            folder.stamp(change);
            Ok((
                id,
                change,
                vec![(id, Some(&previous), VirtualFolderNext::Live(folder.clone()))],
            ))
        },
    )
    .await
}

pub(super) async fn edit_properties(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
    mut edit: impl FnMut(&mut ExchangeObject) -> bool,
) -> FolderWriteResult {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    for _ in 0..MAX_UPDATE_ATTEMPTS {
        let Some(previous) = read_row(server, account_id, id).await? else {
            return Ok(Err(FolderWriteError::NotFound));
        };
        let mut folder = previous
            .deserialize::<VirtualFolder>()
            .caused_by(trc::location!())?;
        let previous_size = folder.quota_size();
        let mut object = ExchangeObject {
            properties: mem::take(&mut folder.properties),
            ..Default::default()
        };
        if !edit(&mut object) {
            return Ok(Ok(FolderWritten {
                folder: node_ref(id),
                change_id: None,
                outcome: WriteOutcome::Written,
            }));
        }
        folder.properties = object.properties;
        let growth = folder.quota_size() - previous_size;
        if growth > 0 && !has_quota(server, account_id, growth).await? {
            return Ok(Err(FolderWriteError::OverQuota));
        }
        match write(
            server,
            access_token,
            account_id,
            None,
            [(ExchangeCounter::Change, 1)],
            |[change]| {
                folder.stamp(change);
                Ok((
                    id,
                    change,
                    vec![(id, Some(&previous), VirtualFolderNext::Live(folder.clone()))],
                ))
            },
        )
        .await?
        {
            Err(FolderWriteError::Conflict) => {}
            result => return Ok(result),
        }
    }
    Ok(Err(FolderWriteError::Conflict))
}

pub(super) async fn search(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
) -> trc::Result<Result<SearchDefinition, FolderWriteError>> {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let Some(row) = read_row(server, account_id, id).await? else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    match row.unarchive::<VirtualFolder>()?.search.as_ref() {
        Some(search) => rkyv_deserialize(search).caused_by(trc::location!()).map(Ok),
        None => Ok(Err(FolderWriteError::InvalidSearch)),
    }
}

pub(super) async fn destroy(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    id: u32,
    contents: FolderContents,
) -> FolderWriteResult {
    if !access_token.is_member(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let node = virtual_node(id);
    let tree = WritableFolder::Virtual
        .folder_tree(server, account_id)
        .await?;
    if tree.get(node).is_none() {
        return Ok(Err(FolderWriteError::NotFound));
    }
    let mut ids = vec![id];
    for entry in tree.descendants(node) {
        match entry.node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Virtual,
                id,
            }) => ids.push(id),
            _ => return Ok(Err(FolderWriteError::Protected)),
        }
    }
    if contents == FolderContents::Keep {
        if ids.len() > 1 {
            return Ok(Err(FolderWriteError::HasChildren));
        }
        let mut has_items = false;
        server
            .fai_messages(account_id, FaiFolder::from(node_ref(id)), |_, _| {
                has_items = true;
                Ok(false)
            })
            .await
            .caused_by(trc::location!())?;
        if has_items {
            return Ok(Err(FolderWriteError::HasItems));
        }
    }
    let mut rows = Vec::with_capacity(ids.len());
    for &id in &ids {
        match read_row(server, account_id, id).await? {
            Some(previous) => rows.push((id, previous)),
            None if rows.is_empty() => return Ok(Err(FolderWriteError::NotFound)),
            None => return Ok(Err(FolderWriteError::Conflict)),
        }
    }
    write(
        server,
        access_token,
        account_id,
        None,
        [(ExchangeCounter::Change, 1)],
        |[change]| {
            Ok((
                id,
                change,
                rows.iter()
                    .map(|(id, previous)| {
                        (*id, Some(previous), VirtualFolderNext::Deleted { change })
                    })
                    .collect(),
            ))
        },
    )
    .await
}

fn placement(
    server: &Server,
    tree: &FolderTree,
    parent: FolderNode,
    is_search: bool,
    moving: Option<FolderNode>,
) -> Result<FolderNode, FolderWriteError> {
    if Some(parent) == moving {
        return Err(FolderWriteError::Cycle);
    }
    let Some(entry) = tree.get(parent) else {
        return Err(FolderWriteError::ParentNotFound);
    };
    if is_search {
        return Ok(match parent {
            FolderNode::Special(SpecialFolder::Root) => parent,
            _ => FolderNode::Special(SpecialFolder::Finder),
        });
    }
    match parent {
        FolderNode::Special(special) if !entry.ipm && special != SpecialFolder::IpmSubtree => {}
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Virtual,
            ..
        }) => {}
        _ => return Err(FolderWriteError::InvalidParent),
    }
    let mut next = Some(parent);
    for _ in 0..server.core.email.mailbox_max_depth {
        let Some(node) = next else {
            return Ok(parent);
        };
        if Some(node) == moving {
            return Err(FolderWriteError::Cycle);
        }
        next = tree.get(node).and_then(|entry| entry.parent);
    }
    Err(FolderWriteError::TooDeep)
}

fn assert_unique_name(
    tree: &FolderTree,
    parent: FolderNode,
    current: Option<FolderNode>,
    name: &str,
) -> Result<(), FolderWriteError> {
    let lower_name = || name.chars().flat_map(char::to_lowercase);
    match tree
        .children(parent)
        .find_map(|sibling| match sibling.node {
            FolderNode::Stored(_) | FolderNode::Special(_)
                if Some(sibling.node) != current
                    && sibling
                        .name
                        .chars()
                        .flat_map(char::to_lowercase)
                        .eq(lower_name()) =>
            {
                Some(sibling.node)
            }
            _ => None,
        }) {
        Some(existing) => Err(FolderWriteError::AlreadyExists(existing)),
        None => Ok(()),
    }
}

async fn write<'x, const N: usize>(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    parent: Option<&(u32, Archive<ArchiveBytes>)>,
    counters: [(ExchangeCounter, u32); N],
    mut rows: impl FnMut([u64; N]) -> trc::Result<(u32, u64, Rows<'x>)> + Send,
) -> FolderWriteResult {
    let owner = server
        .exchange_quota_owner(access_token, account_id)
        .await?;
    let max_size = server.core.exchange.max_object_size;
    for _ in 0..MAX_UPDATE_ATTEMPTS {
        let reservation = server.reserve_exchange_ids(account_id, counters).await?;
        let (id, change, rows) = rows(reservation.ids())?;
        let mut batch = BatchBuilder::new();
        if let Some((parent_id, parent)) = parent {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(ExchangeClass::Folder { id: *parent_id }, parent);
        }
        for (id, previous, next) in rows {
            match (VirtualFolderWrite {
                owner,
                id,
                previous,
                next,
                max_size,
            })
            .build(&mut batch)
            {
                Ok(()) => {}
                Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                    return Ok(Err(FolderWriteError::OverQuota));
                }
                Err(err) => return Err(err),
            }
        }
        let reserved = reservation.seal(&mut batch);
        match server.commit_batch(batch).await {
            Ok(_) => {
                return Ok(Ok(FolderWritten {
                    folder: node_ref(id),
                    change_id: Some(change),
                    outcome: WriteOutcome::Written,
                }));
            }
            Err(err) if err.is_assertion_failure() => {
                if !reserved.is_stale(server).await? {
                    return Ok(Err(FolderWriteError::Conflict));
                }
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
    Ok(Err(FolderWriteError::Conflict))
}

async fn parent_row(
    server: &Server,
    account_id: u32,
    parent: FolderNode,
) -> trc::Result<Result<Option<(u32, Archive<ArchiveBytes>)>, FolderWriteError>> {
    let FolderNode::Stored(FolderRef {
        kind: FolderKind::Virtual,
        id,
    }) = parent
    else {
        return Ok(Ok(None));
    };
    let Some(row) = read_row(server, account_id, id).await? else {
        return Ok(Err(FolderWriteError::ParentNotFound));
    };
    if row.unarchive::<VirtualFolder>()?.search.is_some() {
        return Ok(Err(FolderWriteError::InvalidParent));
    }
    Ok(Ok(Some((id, row))))
}

fn validate_scope(tree: &FolderTree, search: &SearchDefinition) -> Result<(), FolderWriteError> {
    if search.scope.len() > SEARCH_SCOPE_MAX {
        return Err(FolderWriteError::InvalidSearch);
    }
    for folder in &search.scope {
        match FolderNode::from_stored(folder.kind, folder.id) {
            Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Virtual,
                ..
            }))
            | None => return Err(FolderWriteError::InvalidSearch),
            Some(FolderNode::Special(special)) if tree.special(special).is_none() => {
                return Err(FolderWriteError::InvalidSearch);
            }
            Some(node @ FolderNode::Stored(_)) if tree.get(node).is_none() => {
                return Err(FolderWriteError::InvalidSearch);
            }
            Some(_) => {}
        }
    }
    Ok(())
}

async fn read_row(
    server: &Server,
    account_id: u32,
    id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(account_key(account_id, ExchangeClass::Folder { id }))
        .await
        .caused_by(trc::location!())
}

async fn has_quota(server: &Server, account_id: u32, size: i64) -> trc::Result<bool> {
    let account = server
        .account(account_id)
        .await
        .caused_by(trc::location!())?;
    match server
        .has_available_quota(&account, u64::try_from(size).unwrap_or_default())
        .await
    {
        Ok(()) => Ok(true),
        Err(err) if err.matches(EventType::Limit(LimitEvent::Quota)) => Ok(false),
        Err(err) => Err(err),
    }
}

fn virtual_node(id: u32) -> FolderNode {
    FolderNode::Stored(node_ref(id))
}

fn node_ref(id: u32) -> FolderRef {
    WritableFolder::Virtual.folder_ref(id)
}

#[cold]
fn exhausted() -> trc::Error {
    trc::StoreEvent::UnexpectedError
        .into_err()
        .details("Exchange folder id counter exhausted.")
        .caused_by(trc::location!())
}
