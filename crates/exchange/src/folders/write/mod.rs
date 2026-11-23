/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod acl;
mod groupware;
mod mailbox;
mod virtual_folder;

pub use self::acl::{AclEdit, AclWriteError, AclWriteResult};
use self::{groupware::CalendarContent, mailbox::MailboxContent};
use super::{ContainerClass, ExchangeFolders, FolderNode, FolderTree, SpecialFolder};
use crate::{
    cache::ExchangeCacheFetch,
    store::{
        FolderKind, FolderRef,
        account::bump_objects_epoch,
        folder::SearchDefinition,
        object::{ExchangeObject, StoredPlacement},
    },
};
use common::{Server, auth::AccessToken, cache::exchange::FolderKey};
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use std::iter::successors;
use store::write::{AssignedIds, BatchBuilder, PendingId, metadata::ExchangeClass};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    special_use::SpecialUse,
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritableFolder {
    Mailbox,
    Calendar,
    AddressBook,
    Virtual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderContents {
    Keep,
    Remove,
}

#[derive(Debug, Clone, Copy)]
pub struct FolderCreate<'x> {
    pub kind: WritableFolder,
    pub parent: FolderNode,
    pub name: &'x str,
    pub class: Option<&'x str>,
    pub search: Option<&'x SearchDefinition>,
    pub client_key: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FolderUpdate<'x> {
    pub name: Option<&'x str>,
    pub parent: Option<FolderNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Written,
    Destroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderWritten {
    pub folder: FolderRef,
    pub change_id: Option<u64>,
    pub outcome: WriteOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderWriteError {
    NotFound,
    Forbidden,
    Protected,
    Unsupported,
    EmptyName,
    NameTooLong,
    ParentNotFound,
    InvalidParent,
    Cycle,
    TooDeep,
    AlreadyExists(FolderNode),
    OverQuota,
    HasChildren,
    HasItems,
    InvalidSearch,
    Conflict,
}

pub type FolderWriteResult = trc::Result<Result<FolderWritten, FolderWriteError>>;

impl WritableFolder {
    pub fn from_class(class: &ContainerClass) -> Self {
        class.family().unwrap_or(WritableFolder::Mailbox)
    }

    fn of(node: FolderNode) -> Result<(Self, u32), FolderWriteError> {
        match node {
            FolderNode::Stored(FolderRef { kind, id }) => match kind {
                FolderKind::Mailbox => Ok((WritableFolder::Mailbox, id)),
                FolderKind::Calendar => Ok((WritableFolder::Calendar, id)),
                FolderKind::AddressBook => Ok((WritableFolder::AddressBook, id)),
                FolderKind::Virtual => Ok((WritableFolder::Virtual, id)),
                FolderKind::FileNode => Err(FolderWriteError::Unsupported),
            },
            FolderNode::Special(_) => Err(FolderWriteError::Protected),
        }
    }

    fn collection(self) -> Collection {
        match self {
            WritableFolder::Mailbox => Collection::Mailbox,
            WritableFolder::Calendar => Collection::Calendar,
            WritableFolder::AddressBook => Collection::AddressBook,
            WritableFolder::Virtual => Collection::Principal,
        }
    }

    fn sync_collection(self) -> SyncCollection {
        match self {
            WritableFolder::Mailbox => SyncCollection::Email,
            WritableFolder::Calendar => SyncCollection::Calendar,
            WritableFolder::AddressBook => SyncCollection::AddressBook,
            WritableFolder::Virtual => SyncCollection::None,
        }
    }

    pub fn data_type(self) -> DataType {
        match self {
            WritableFolder::Mailbox | WritableFolder::Virtual => DataType::Email,
            WritableFolder::Calendar => DataType::CalendarEvent,
            WritableFolder::AddressBook => DataType::ContactCard,
        }
    }

    async fn folder_tree(self, server: &Server, account_id: u32) -> trc::Result<FolderTree> {
        server
            .exchange_folder_tree(account_id, Bitmap::from(self.data_type()))
            .await
            .caused_by(trc::location!())
    }

    fn folder_kind(self) -> FolderKind {
        match self {
            WritableFolder::Mailbox => FolderKind::Mailbox,
            WritableFolder::Calendar => FolderKind::Calendar,
            WritableFolder::AddressBook => FolderKind::AddressBook,
            WritableFolder::Virtual => FolderKind::Virtual,
        }
    }

    fn folder_ref(self, id: u32) -> FolderRef {
        FolderRef {
            kind: self.folder_kind(),
            id,
        }
    }

    fn accepts_class(self, class: &ContainerClass) -> bool {
        WritableFolder::from_class(class) == self
            || (self == WritableFolder::Calendar && *class == ContainerClass::Task)
    }

    fn accepts_parent(self, parent: FolderNode) -> bool {
        let (special, kind) = match self {
            WritableFolder::Mailbox => return mailbox_parent(parent).is_some(),
            WritableFolder::Calendar => (SpecialFolder::Calendar, FolderKind::Calendar),
            WritableFolder::AddressBook => (SpecialFolder::Contacts, FolderKind::AddressBook),
            WritableFolder::Virtual => return true,
        };
        match parent {
            FolderNode::Special(SpecialFolder::Tasks) => self == WritableFolder::Calendar,
            FolderNode::Special(folder) => folder == SpecialFolder::IpmSubtree || folder == special,
            FolderNode::Stored(folder) => folder.kind == kind || folder.kind == FolderKind::Mailbox,
        }
    }
}

fn mailbox_parent(parent: FolderNode) -> Option<Option<u32>> {
    match parent {
        FolderNode::Special(SpecialFolder::IpmSubtree) => Some(None),
        FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id,
        }) => Some(Some(id)),
        _ => None,
    }
}

pub trait FolderWrites: Sync + Send {
    fn folder_create(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        create: FolderCreate<'_>,
    ) -> impl Future<Output = FolderWriteResult> + Send;

    fn folder_update(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        update: FolderUpdate<'_>,
    ) -> impl Future<Output = FolderWriteResult> + Send;

    fn folder_destroy(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        contents: FolderContents,
    ) -> impl Future<Output = FolderWriteResult> + Send;

    fn folder_set_search(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        search: &SearchDefinition,
    ) -> impl Future<Output = FolderWriteResult> + Send;

    fn folder_search(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
    ) -> impl Future<Output = trc::Result<Result<SearchDefinition, FolderWriteError>>> + Send;

    fn folder_set_class(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        class: &str,
    ) -> impl Future<Output = FolderWriteResult> + Send;

    fn folder_edit_properties(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        edit: impl FnMut(&mut ExchangeObject) -> bool + Send,
    ) -> impl Future<Output = FolderWriteResult> + Send;

    fn folder_set_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        edit: AclEdit<'_>,
    ) -> impl Future<Output = AclWriteResult> + Send;

    fn folder_task_list(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Result<FolderRef, FolderWriteError>>> + Send;

    fn folder_event_calendar(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Result<FolderRef, FolderWriteError>>> + Send;

    fn folder_notes(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Result<FolderRef, FolderWriteError>>> + Send;

    fn folder_sync_issues(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = FolderWriteResult> + Send;
}

impl FolderWrites for Server {
    async fn folder_create(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        create: FolderCreate<'_>,
    ) -> FolderWriteResult {
        let class = match create.kind {
            WritableFolder::Virtual => None,
            kind => match create.class.map(ContainerClass::parse) {
                Some(class) if !kind.accepts_class(&class) => {
                    return Ok(Err(FolderWriteError::Unsupported));
                }
                class => class,
            },
        };
        if (create.search.is_some() && create.kind != WritableFolder::Virtual)
            || (create.client_key.is_some() && create.kind == WritableFolder::Virtual)
        {
            return Ok(Err(FolderWriteError::Unsupported));
        }
        if !create.kind.accepts_parent(create.parent) {
            return Ok(Err(FolderWriteError::InvalidParent));
        }
        if matches!(
            create.kind,
            WritableFolder::Calendar | WritableFolder::AddressBook
        ) && matches!(create.parent, FolderNode::Stored(_))
            && container_tree(self, account_id)
                .await?
                .get(create.parent)
                .is_none()
        {
            return Ok(Err(FolderWriteError::ParentNotFound));
        }
        let result = match create.kind {
            WritableFolder::Mailbox => {
                mailbox::create(
                    self,
                    access_token,
                    account_id,
                    mailbox_parent(create.parent).flatten(),
                    create.name,
                    class
                        .filter(|class| *class != ContainerClass::Note)
                        .map_or(MailboxContent::Mail, MailboxContent::Class),
                    create.client_key,
                )
                .await?
            }
            WritableFolder::Calendar => {
                let content = if class == Some(ContainerClass::Task) {
                    if let Err(err) = groupware::task_list(self, access_token, account_id).await? {
                        return Ok(Err(err));
                    }
                    CalendarContent::Tasks
                } else {
                    CalendarContent::Events
                };
                groupware::create_calendar(
                    self,
                    access_token,
                    account_id,
                    create.name,
                    create.parent,
                    content,
                    create.client_key,
                )
                .await?
            }
            WritableFolder::AddressBook => {
                groupware::create_address_book(
                    self,
                    access_token,
                    account_id,
                    create.name,
                    create.parent,
                    create.client_key,
                )
                .await?
            }
            WritableFolder::Virtual => {
                virtual_folder::create(self, access_token, account_id, create).await?
            }
        };
        Ok(finish(self, account_id, result))
    }

    async fn folder_update(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        update: FolderUpdate<'_>,
    ) -> FolderWriteResult {
        let (kind, document_id) = match WritableFolder::of(folder) {
            Ok(target) => target,
            Err(err) => return Ok(Err(err)),
        };
        if kind == WritableFolder::Virtual {
            let result =
                virtual_folder::update(self, access_token, account_id, document_id, update).await?;
            return Ok(finish(self, account_id, result));
        }
        if let Some(parent) = update.parent {
            if parent == folder {
                return Ok(Err(FolderWriteError::Cycle));
            }
            if kind != WritableFolder::Mailbox && in_deleted_items(self, account_id, parent).await?
            {
                let result = self
                    .folder_destroy(access_token, account_id, folder, FolderContents::Remove)
                    .await?;
                return Ok(result.map(|written| FolderWritten {
                    outcome: WriteOutcome::Destroyed,
                    ..written
                }));
            }
            if !kind.accepts_parent(parent) {
                return Ok(Err(FolderWriteError::InvalidParent));
            }
        }
        if update.name.is_some() || update.parent.is_some() {
            let tree = match (kind, update.parent) {
                (WritableFolder::Mailbox, _) | (_, None) => {
                    kind.folder_tree(self, account_id).await?
                }
                (_, Some(_)) => container_tree(self, account_id).await?,
            };
            if is_distinguished(&tree, folder) {
                return Ok(Err(FolderWriteError::Protected));
            }
            if let Some(parent @ FolderNode::Stored(_)) = update.parent
                && kind != WritableFolder::Mailbox
            {
                if tree.get(parent).is_none() {
                    return Ok(Err(FolderWriteError::ParentNotFound));
                }
                if tree.in_subtree(folder, parent) {
                    return Ok(Err(FolderWriteError::Cycle));
                }
            }
        }
        let result = match kind {
            WritableFolder::Mailbox => {
                mailbox::update(
                    self,
                    access_token,
                    account_id,
                    document_id,
                    update.name,
                    update.parent.and_then(mailbox_parent),
                )
                .await?
            }
            WritableFolder::Calendar | WritableFolder::AddressBook => {
                groupware::update(
                    self,
                    access_token,
                    account_id,
                    kind,
                    document_id,
                    update.name,
                    update.parent,
                )
                .await?
            }
            WritableFolder::Virtual => return Ok(Err(FolderWriteError::Unsupported)),
        };
        Ok(finish(self, account_id, result))
    }

    async fn folder_destroy(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        contents: FolderContents,
    ) -> FolderWriteResult {
        let (kind, document_id) = match WritableFolder::of(folder) {
            Ok(target) => target,
            Err(err) => return Ok(Err(err)),
        };
        if kind == WritableFolder::Virtual {
            let result =
                virtual_folder::destroy(self, access_token, account_id, document_id, contents)
                    .await?;
            return Ok(finish(self, account_id, result));
        }
        let mut subtree = vec![document_id];
        let mut containers = Vec::new();
        {
            let tree = match kind {
                WritableFolder::Mailbox => container_tree(self, account_id).await?,
                kind => kind.folder_tree(self, account_id).await?,
            };
            if is_distinguished(&tree, folder) {
                return Ok(Err(FolderWriteError::Protected));
            }
            for entry in tree.descendants(folder) {
                if entry.special.is_some() && contents == FolderContents::Remove {
                    return Ok(Err(FolderWriteError::Protected));
                }
                let FolderNode::Stored(FolderRef { kind: child, id }) = entry.node else {
                    continue;
                };
                match child {
                    FolderKind::Mailbox
                        if kind == WritableFolder::Mailbox
                            && contents == FolderContents::Remove =>
                    {
                        subtree.push(id)
                    }
                    FolderKind::Calendar => containers.push((WritableFolder::Calendar, id)),
                    FolderKind::AddressBook => containers.push((WritableFolder::AddressBook, id)),
                    _ => {}
                }
            }
        }
        if !containers.is_empty() && contents == FolderContents::Keep {
            return Ok(Err(FolderWriteError::HasChildren));
        }
        for (kind, id) in containers.into_iter().rev() {
            let destroyed = match kind {
                WritableFolder::Calendar => {
                    groupware::destroy_calendar(
                        self,
                        access_token,
                        account_id,
                        id,
                        FolderContents::Remove,
                    )
                    .await?
                }
                _ => {
                    groupware::destroy_address_book(
                        self,
                        access_token,
                        account_id,
                        id,
                        FolderContents::Remove,
                    )
                    .await?
                }
            };
            if let Err(err) = finish(self, account_id, destroyed) {
                return Ok(Err(err));
            }
        }
        let result = match kind {
            WritableFolder::Mailbox => {
                mailbox::destroy(self, access_token, account_id, &subtree, contents).await?
            }
            WritableFolder::Calendar => {
                groupware::destroy_calendar(self, access_token, account_id, document_id, contents)
                    .await?
            }
            WritableFolder::AddressBook => {
                groupware::destroy_address_book(
                    self,
                    access_token,
                    account_id,
                    document_id,
                    contents,
                )
                .await?
            }
            WritableFolder::Virtual => return Ok(Err(FolderWriteError::Unsupported)),
        };
        Ok(finish(self, account_id, result))
    }

    async fn folder_set_search(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        search: &SearchDefinition,
    ) -> FolderWriteResult {
        let id = match virtual_id(folder) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let result = virtual_folder::set_search(self, access_token, account_id, id, search).await?;
        Ok(finish(self, account_id, result))
    }

    async fn folder_search(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
    ) -> trc::Result<Result<SearchDefinition, FolderWriteError>> {
        match virtual_id(folder) {
            Ok(id) => virtual_folder::search(self, access_token, account_id, id).await,
            Err(err) => Ok(Err(err)),
        }
    }

    async fn folder_set_class(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        class: &str,
    ) -> FolderWriteResult {
        let id = match virtual_id(folder) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let result = virtual_folder::set_class(self, access_token, account_id, id, class).await?;
        Ok(finish(self, account_id, result))
    }

    async fn folder_edit_properties(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        edit: impl FnMut(&mut ExchangeObject) -> bool + Send,
    ) -> FolderWriteResult {
        let id = match virtual_id(folder) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let result =
            virtual_folder::edit_properties(self, access_token, account_id, id, edit).await?;
        Ok(finish(self, account_id, result))
    }

    async fn folder_set_acl(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        folder: FolderNode,
        edit: AclEdit<'_>,
    ) -> AclWriteResult {
        let (kind, document_id) = match WritableFolder::of(folder) {
            Ok(target) => target,
            Err(err) => return Ok(Err(err.into())),
        };
        let result = acl::set_acl(self, access_token, account_id, kind, document_id, edit).await?;
        if result.is_ok_and(|written| written.change_id.is_some()) {
            self.mark_exchange_stale(account_id);
        }
        Ok(result)
    }

    async fn folder_task_list(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Result<FolderRef, FolderWriteError>> {
        groupware::task_list(self, access_token, account_id).await
    }

    async fn folder_event_calendar(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Result<FolderRef, FolderWriteError>> {
        groupware::event_calendar(self, access_token, account_id).await
    }

    async fn folder_notes(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Result<FolderRef, FolderWriteError>> {
        mailbox::notes(self, access_token, account_id).await
    }

    async fn folder_sync_issues(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> FolderWriteResult {
        mailbox::sync_issues(self, access_token, account_id).await
    }
}

pub(super) async fn container_tree(server: &Server, account_id: u32) -> trc::Result<FolderTree> {
    server
        .exchange_folder_tree(
            account_id,
            Bitmap::from(DataType::Email)
                .with_item(DataType::CalendarEvent)
                .with_item(DataType::ContactCard),
        )
        .await
        .caused_by(trc::location!())
}

fn virtual_id(folder: FolderNode) -> Result<u32, FolderWriteError> {
    match WritableFolder::of(folder)? {
        (WritableFolder::Virtual, id) => Ok(id),
        _ => Err(FolderWriteError::Unsupported),
    }
}

async fn in_deleted_items(
    server: &Server,
    account_id: u32,
    folder: FolderNode,
) -> trc::Result<bool> {
    let FolderNode::Stored(FolderRef {
        kind: FolderKind::Mailbox,
        id,
    }) = folder
    else {
        return Ok(false);
    };
    let cache = server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?;
    let Some(trash_id) = cache
        .mailbox_by_role(&SpecialUse::Trash)
        .map(|mailbox| mailbox.document_id)
    else {
        return Ok(false);
    };
    Ok(successors(Some(id), |id| {
        cache
            .mailbox_by_id(id)
            .and_then(|mailbox| mailbox.parent_id())
    })
    .take(cache.mailboxes.items.len())
    .any(|id| id == trash_id))
}

fn is_distinguished(tree: &FolderTree, folder: FolderNode) -> bool {
    tree.get(folder)
        .is_some_and(|entry| entry.special.is_some())
}

fn finish(
    server: &Server,
    account_id: u32,
    result: Result<FolderWritten, FolderWriteError>,
) -> Result<FolderWritten, FolderWriteError> {
    if result.is_ok_and(|written| written.change_id.is_some()) {
        server.mark_exchange_stale(account_id);
    }
    result
}

fn set_folder_alias(
    batch: &mut BatchBuilder,
    account_id: u32,
    kind: WritableFolder,
    document_id: PendingId,
    client_key: Option<u32>,
) {
    if let Some(client_key) = client_key {
        batch
            .with_account_id(account_id)
            .with_collection(kind.collection())
            .with_pending_document(document_id)
            .set(
                ExchangeClass::Alias,
                StoredPlacement::folder(client_key).serialize(),
            );
        bump_objects_epoch(batch, account_id);
    }
}

async fn clear_folder_aliases(
    server: &Server,
    batch: &mut BatchBuilder,
    account_id: u32,
    kind: WritableFolder,
    ids: &[u32],
) -> trc::Result<bool> {
    let cache = server.get_cached_exchange(account_id).await?;
    let folder_kind = kind.folder_kind() as u8;
    let mut cleared = false;
    for &id in ids {
        if cache.folder_aliases.contains_key(&FolderKey {
            kind: folder_kind,
            id,
        }) {
            batch
                .with_account_id(account_id)
                .with_collection(kind.collection())
                .with_document(id)
                .clear(ExchangeClass::Alias);
            cleared = true;
        }
    }
    if cleared {
        bump_objects_epoch(batch, account_id);
    }
    Ok(cleared)
}

async fn commit(
    server: &Server,
    account_id: u32,
    kind: WritableFolder,
    batch: BatchBuilder,
    document_id: impl FnOnce(&AssignedIds) -> u32,
) -> FolderWriteResult {
    match server.commit_batch(batch).await {
        Ok(assigned_ids) => Ok(Ok(FolderWritten {
            folder: kind.folder_ref(document_id(&assigned_ids)),
            change_id: Some(assigned_ids.last_change_id(account_id, kind.sync_collection())),
            outcome: WriteOutcome::Written,
        })),
        Err(err) if err.is_assertion_failure() => Ok(Err(FolderWriteError::Conflict)),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}
