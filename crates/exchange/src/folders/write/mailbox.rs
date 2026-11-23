/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderContents, FolderWriteError, FolderWriteResult, FolderWritten, WritableFolder,
    WriteOutcome, clear_folder_aliases, commit, finish, groupware::read_container,
    set_folder_alias,
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::{ContainerClass, FolderNode, SYNC_ISSUES_FOLDERS, SpecialFolder, special_name},
    store::{
        FolderRef,
        account::ExchangeAccountStore,
        object::{ExchangeObject, ExchangeObjectWrite, ObjectVersion, OwnerStamp},
    },
};
use common::{
    MessageStoreCache, Server,
    auth::AccessToken,
    sharing::EffectiveAcl,
    storage::{create_lock::CreateLock, index::ObjectIndexBuilder},
};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::{
        Mailbox,
        destroy::{MailboxDestroy, MailboxDestroyError},
        manage::MailboxFnc,
    },
};
use registry::schema::enums::StorageQuota;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, assert::AssertValue},
};
use trc::{AddContext, EventType, LimitEvent};
use types::{
    acl::{Acl, AclGrant},
    collection::Collection,
    field::MailboxField,
    special_use::SpecialUse,
};

const VIRTUAL_IPM_SPECIALS: [SpecialFolder; 2] = [SpecialFolder::Outbox, SpecialFolder::SyncIssues];

pub(super) enum MailboxContent {
    Mail,
    Class(ContainerClass),
    Role(SpecialUse),
    Special,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReservedNames {
    Refuse,
    Allow,
}

pub(super) async fn notes(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<Result<FolderRef, FolderWriteError>> {
    if let Some(first) = first_memos(server, account_id).await? {
        return Ok(Ok(WritableFolder::Mailbox.folder_ref(first)));
    }
    let result = create(
        server,
        access_token,
        account_id,
        None,
        &special_name(SpecialFolder::Notes),
        MailboxContent::Role(SpecialUse::Memos),
        None,
    )
    .await?;
    let created = match finish(server, account_id, result) {
        Ok(written) => written.folder,
        Err(err @ FolderWriteError::AlreadyExists(_)) => {
            let holder = first_memos(server, account_id)
                .await?
                .map(|first| WritableFolder::Mailbox.folder_ref(first));
            return Ok(holder.ok_or(err));
        }
        Err(err) => return Ok(Err(err)),
    };
    match first_memos(server, account_id).await? {
        Some(first) if first != created.id => {
            if server
                .mailbox_destroy(account_id, created.id, access_token, false, None)
                .await
                .caused_by(trc::location!())?
                .is_ok()
            {
                server.mark_exchange_stale(account_id);
            }
            Ok(Ok(WritableFolder::Mailbox.folder_ref(first)))
        }
        _ => Ok(Ok(created)),
    }
}

pub(super) async fn sync_issues(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> FolderWriteResult {
    let parent = match special_mailbox(
        server,
        access_token,
        account_id,
        None,
        SpecialFolder::SyncIssues,
    )
    .await?
    {
        Ok(parent) => parent,
        Err(err) => return Ok(Err(err)),
    };
    let mut change_id = parent.change_id;
    for folder in SYNC_ISSUES_FOLDERS {
        match special_mailbox(
            server,
            access_token,
            account_id,
            Some(parent.folder.id),
            folder,
        )
        .await?
        {
            Ok(child) => change_id = change_id.max(child.change_id),
            Err(err) => return Ok(Err(err)),
        }
    }
    Ok(Ok(FolderWritten {
        folder: parent.folder,
        change_id,
        outcome: WriteOutcome::Written,
    }))
}

async fn special_mailbox(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    parent: Option<u32>,
    folder: SpecialFolder,
) -> FolderWriteResult {
    let name = folder.display_name();
    let result = create(
        server,
        access_token,
        account_id,
        parent,
        name,
        MailboxContent::Special,
        None,
    )
    .await?;
    let written = match finish(server, account_id, result) {
        Ok(written) => written,
        Err(err @ FolderWriteError::AlreadyExists(_)) => {
            return Ok(first_named(server, account_id, parent, name)
                .await?
                .map(|first| FolderWritten {
                    folder: WritableFolder::Mailbox.folder_ref(first),
                    change_id: None,
                    outcome: WriteOutcome::Written,
                })
                .ok_or(err));
        }
        Err(err) => return Ok(Err(err)),
    };
    let created = written.folder.id;
    match first_named(server, account_id, parent, name).await? {
        Some(first) if first != created => {
            match server
                .mailbox_destroy(account_id, created, access_token, false, None)
                .await
                .caused_by(trc::location!())?
            {
                Ok(_) => server.mark_exchange_stale(account_id),
                Err(_) => {
                    trc::error!(
                        trc::ResourceEvent::Error
                            .into_err()
                            .account_id(account_id)
                            .document_id(created)
                            .details("MAPI logon kept a duplicate Sync Issues mailbox")
                            .caused_by(trc::location!())
                    );
                }
            }
            Ok(Ok(FolderWritten {
                folder: WritableFolder::Mailbox.folder_ref(first),
                ..written
            }))
        }
        _ => Ok(Ok(written)),
    }
}

async fn first_named(
    server: &Server,
    account_id: u32,
    parent: Option<u32>,
    name: &str,
) -> trc::Result<Option<u32>> {
    Ok(server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?
        .mailboxes
        .items
        .iter()
        .filter(|mailbox| {
            mailbox.role == SpecialUse::None
                && mailbox.parent_id() == parent
                && mailbox.name.eq_ignore_ascii_case(name)
        })
        .map(|mailbox| mailbox.document_id)
        .min())
}

async fn first_memos(server: &Server, account_id: u32) -> trc::Result<Option<u32>> {
    Ok(server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?
        .mailboxes
        .items
        .iter()
        .filter(|mailbox| mailbox.role == SpecialUse::Memos)
        .map(|mailbox| mailbox.document_id)
        .min())
}

async fn lock_names(server: &Server, account_id: u32) -> trc::Result<Option<CreateLock>> {
    match server.lock_mailbox_names(account_id).await {
        Ok(lock) => Ok(Some(lock)),
        Err(err) if err.matches(EventType::Limit(LimitEvent::ConcurrentRequest)) => Ok(None),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

pub(super) async fn create(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    parent: Option<u32>,
    name: &str,
    content: MailboxContent,
    client_key: Option<u32>,
) -> FolderWriteResult {
    let Some(lock) = lock_names(server, account_id).await? else {
        return Ok(Err(FolderWriteError::Conflict));
    };
    let result = create_locked(
        server,
        access_token,
        account_id,
        parent,
        name,
        content,
        client_key,
    )
    .await;
    server.unlock_mailbox_names(lock).await;
    result
}

async fn create_locked(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    parent: Option<u32>,
    name: &str,
    content: MailboxContent,
    client_key: Option<u32>,
) -> FolderWriteResult {
    let cache = server
        .get_current_messages(account_id)
        .await
        .caused_by(trc::location!())?;
    if let MailboxContent::Role(role) = content
        && let Some(mailbox) = cache.mailbox_by_role(&role)
    {
        return Ok(Err(FolderWriteError::AlreadyExists(FolderNode::Stored(
            WritableFolder::Mailbox.folder_ref(mailbox.document_id),
        ))));
    }
    let account = server
        .account(account_id)
        .await
        .caused_by(trc::location!())?;
    if cache.mailboxes.items.len() as u64
        >= u64::from(server.object_quota(account.object_quotas(), StorageQuota::MaxMailboxes))
    {
        return Ok(Err(FolderWriteError::OverQuota));
    }
    let name = match mailbox_name(server, name) {
        Ok(name) => name,
        Err(err) => return Ok(Err(err)),
    };
    let is_shared = access_token.is_shared(account_id);
    let reserved = match content {
        MailboxContent::Special => ReservedNames::Allow,
        MailboxContent::Mail | MailboxContent::Class(_) | MailboxContent::Role(_) => {
            ReservedNames::Refuse
        }
    };
    if let Err(err) = validate_parent(server, &cache, access_token, is_shared, None, parent)
        .and_then(|()| assert_unique_name(&cache, None, parent, name, reserved))
    {
        return Ok(Err(err));
    }

    let mailbox = Mailbox::new(name).with_parent_id(parent.map_or(0, |parent_id| parent_id + 1));
    let mut mailbox = match content {
        MailboxContent::Special => mailbox,
        MailboxContent::Mail | MailboxContent::Class(_) | MailboxContent::Role(_) => {
            mailbox.with_subscriber(access_token.personal_id(account_id, Collection::Mailbox))
        }
    };
    let shared_parent = match parent.and_then(|parent_id| cache.mailbox_by_id(&parent_id)) {
        Some(cached) if !cached.acls.is_empty() => {
            read_container(
                server,
                account_id,
                WritableFolder::Mailbox,
                cached.document_id,
            )
            .await?
        }
        _ => None,
    };
    if let Some(archive) = &shared_parent {
        let acls = &archive
            .unarchive::<Mailbox>()
            .caused_by(trc::location!())?
            .acls;
        mailbox.acls.extend(acls.iter().map(AclGrant::from));
    }
    let mailbox = match content {
        MailboxContent::Role(role) => mailbox.with_role(role),
        MailboxContent::Mail | MailboxContent::Class(_) | MailboxContent::Special => mailbox,
    };
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Mailbox);
    if let Some(parent_id) = parent {
        batch.with_document(parent_id).assert_value(
            MailboxField::Archive,
            shared_parent.as_ref().map_or(AssertValue::Some, |archive| {
                AssertValue::Archive(archive.version)
            }),
        );
    }
    let slot = batch.reserve_document_id(account_id, Collection::Mailbox);
    batch
        .create_document(slot)
        .custom(ObjectIndexBuilder::<(), _>::new().with_changes(mailbox))
        .caused_by(trc::location!())?;
    if let MailboxContent::Class(class) = content {
        let mut object = ExchangeObject::default();
        object.set_property(ContainerClass::property_key(), class.property_value());
        let written = ExchangeObjectWrite {
            owner: server
                .exchange_quota_owner(access_token, account_id)
                .await?,
            collection: Collection::Mailbox,
            document_id: PendingId::Slot(slot),
            stamp: OwnerStamp::Logged,
            version: ObjectVersion::Server,
            previous: None,
            next: Some(object),
            max_size: server.core.exchange.max_object_size,
        }
        .build(&mut batch);
        match written {
            Ok(()) => {}
            Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                return Ok(Err(FolderWriteError::OverQuota));
            }
            Err(err) => return Err(err),
        }
    }
    set_folder_alias(
        &mut batch,
        account_id,
        WritableFolder::Mailbox,
        PendingId::Slot(slot),
        client_key,
    );
    commit(
        server,
        account_id,
        WritableFolder::Mailbox,
        batch,
        |assigned_ids| assigned_ids.slot(slot),
    )
    .await
}

pub(super) async fn update(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    name: Option<&str>,
    parent: Option<Option<u32>>,
) -> FolderWriteResult {
    let unchanged = Ok(Ok(FolderWritten {
        folder: WritableFolder::Mailbox.folder_ref(document_id),
        change_id: None,
        outcome: WriteOutcome::Written,
    }));
    let Some(archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::Mailbox,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let current = archive
        .into_deserialized::<Mailbox>()
        .caused_by(trc::location!())?;
    let is_shared = access_token.is_shared(account_id);
    if is_shared
        && !current
            .inner
            .acls
            .effective_acl(access_token)
            .contains(Acl::Modify)
    {
        return Ok(Err(FolderWriteError::Forbidden));
    }

    let mut changes = current.inner.clone();
    if let Some(name) = name {
        match mailbox_name(server, name) {
            Ok(name) => changes.name = name.into(),
            Err(err) => return Ok(Err(err)),
        }
    }
    if let Some(parent) = parent {
        changes.parent_id = parent.map_or(0, |parent_id| parent_id + 1);
    }
    let parent_changed = changes.parent_id != current.inner.parent_id;
    if !parent_changed && changes.name == current.inner.name {
        return unchanged;
    }

    let Some(lock) = lock_names(server, account_id).await? else {
        return Ok(Err(FolderWriteError::Conflict));
    };
    let result = update_locked(
        server,
        access_token,
        account_id,
        document_id,
        current,
        changes,
    )
    .await;
    server.unlock_mailbox_names(lock).await;
    result
}

async fn update_locked(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    current: Archive<Mailbox>,
    changes: Mailbox,
) -> FolderWriteResult {
    let is_shared = access_token.is_shared(account_id);
    let parent_changed = changes.parent_id != current.inner.parent_id;
    let cache = server
        .get_current_messages(account_id)
        .await
        .caused_by(trc::location!())?;
    let parent = changes.parent_id.checked_sub(1);
    let validation = if parent_changed {
        validate_parent(
            server,
            &cache,
            access_token,
            is_shared,
            Some(document_id),
            parent,
        )
    } else {
        Ok(())
    };
    if let Err(err) = validation.and_then(|()| {
        assert_unique_name(
            &cache,
            Some(document_id),
            parent,
            &changes.name,
            ReservedNames::Refuse,
        )
    }) {
        return Ok(Err(err));
    }

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Mailbox);
    if let Some(parent_id) = parent.filter(|_| parent_changed) {
        batch
            .with_document(parent_id)
            .assert_value(MailboxField::Archive, AssertValue::Some);
    }
    batch
        .with_document(document_id)
        .custom(
            ObjectIndexBuilder::new()
                .with_changes(changes)
                .with_current(current),
        )
        .caused_by(trc::location!())?;
    commit(server, account_id, WritableFolder::Mailbox, batch, |_| {
        document_id
    })
    .await
}

pub(super) async fn destroy(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    subtree: &[u32],
    contents: FolderContents,
) -> FolderWriteResult {
    let Some(&document_id) = subtree.first() else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let cache = server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?;
    if contents == FolderContents::Remove
        && access_token.is_shared(account_id)
        && subtree.iter().any(|id| {
            cache.mailbox_by_id(id).is_some_and(|mailbox| {
                let acl = mailbox.acls.as_slice().effective_acl(access_token);
                !acl.contains(Acl::Delete) || !acl.contains(Acl::RemoveItems)
            })
        })
    {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let flagged = subtree
        .iter()
        .copied()
        .filter(|id| {
            cache
                .mailbox_by_id(id)
                .is_some_and(|mailbox| !mailbox.metadata_kinds.is_empty())
        })
        .collect::<RoaringBitmap>();
    let containers = server
        .preload_container_cleanup(
            access_token.changed_by(),
            account_id,
            Collection::Mailbox,
            &flagged,
        )
        .await
        .caused_by(trc::location!())?;
    let mut change_id = None;
    for &mailbox_id in subtree.iter().rev() {
        match server
            .mailbox_destroy(
                account_id,
                mailbox_id,
                access_token,
                contents == FolderContents::Remove,
                Some(&containers),
            )
            .await
            .inspect_err(|_| {
                if change_id.is_some() {
                    server.mark_exchange_stale(account_id);
                }
            })? {
            Ok(destroyed) => change_id = destroyed.or(change_id),
            Err(err) => {
                if change_id.is_some() {
                    server.mark_exchange_stale(account_id);
                }
                return Ok(Err(match err {
                    MailboxDestroyError::CannotDestroy => FolderWriteError::Protected,
                    MailboxDestroyError::Forbidden => FolderWriteError::Forbidden,
                    MailboxDestroyError::HasChildren => FolderWriteError::HasChildren,
                    MailboxDestroyError::HasEmails => FolderWriteError::HasItems,
                    MailboxDestroyError::NotFound => FolderWriteError::NotFound,
                    MailboxDestroyError::AssertionFailed => FolderWriteError::Conflict,
                }));
            }
        }
    }
    if change_id.is_some() {
        let mut batch = BatchBuilder::new();
        match clear_folder_aliases(
            server,
            &mut batch,
            account_id,
            WritableFolder::Mailbox,
            subtree,
        )
        .await
        {
            Ok(true) => {
                if let Err(err) = server.commit_batch(batch).await {
                    trc::error!(err.caused_by(trc::location!()));
                }
            }
            Ok(false) => {}
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
            }
        }
    }
    Ok(Ok(FolderWritten {
        folder: WritableFolder::Mailbox.folder_ref(document_id),
        change_id,
        outcome: WriteOutcome::Written,
    }))
}

pub(super) fn mailbox_name<'x>(
    server: &Server,
    name: &'x str,
) -> Result<&'x str, FolderWriteError> {
    let name = name.trim();
    if name.is_empty() {
        Err(FolderWriteError::EmptyName)
    } else if server.core.email.is_mailbox_name_too_long(name) {
        Err(FolderWriteError::NameTooLong)
    } else {
        Ok(name)
    }
}

fn validate_parent(
    server: &Server,
    cache: &MessageStoreCache,
    access_token: &AccessToken,
    is_shared: bool,
    current: Option<u32>,
    parent: Option<u32>,
) -> Result<(), FolderWriteError> {
    let current_id = current.map_or(u32::MAX, |document_id| document_id + 1);
    let mut parent_id = parent.map_or(0, |parent_id| parent_id + 1);
    for depth in 0..server.core.email.mailbox_max_depth {
        if parent_id == current_id {
            return Err(FolderWriteError::Cycle);
        }
        let Some(document_id) = parent_id.checked_sub(1) else {
            return if depth == 0 && is_shared {
                Err(FolderWriteError::Forbidden)
            } else {
                Ok(())
            };
        };
        let Some(mailbox) = cache.mailbox_by_id(&document_id) else {
            return Err(FolderWriteError::ParentNotFound);
        };
        if depth == 0
            && is_shared
            && !mailbox
                .acls
                .as_slice()
                .effective_acl(access_token)
                .contains(Acl::CreateChild)
        {
            return Err(FolderWriteError::Forbidden);
        }
        parent_id = mailbox.parent_id().map_or(0, |parent_id| parent_id + 1);
    }
    Err(FolderWriteError::TooDeep)
}

fn assert_unique_name(
    cache: &MessageStoreCache,
    current: Option<u32>,
    parent: Option<u32>,
    name: &str,
    reserved: ReservedNames,
) -> Result<(), FolderWriteError> {
    let same_name = |other: &str| {
        other
            .chars()
            .flat_map(char::to_lowercase)
            .eq(name.chars().flat_map(char::to_lowercase))
    };
    let mut renames_itself = false;
    for mailbox in cache
        .mailboxes
        .items
        .iter()
        .filter(|mailbox| mailbox.parent_id() == parent && same_name(&mailbox.name))
    {
        if Some(mailbox.document_id) != current {
            return Err(FolderWriteError::AlreadyExists(FolderNode::Stored(
                WritableFolder::Mailbox.folder_ref(mailbox.document_id),
            )));
        }
        renames_itself = true;
    }
    if parent.is_some() || renames_itself || reserved == ReservedNames::Allow {
        return Ok(());
    }
    match VIRTUAL_IPM_SPECIALS
        .into_iter()
        .find(|special| same_name(special.display_name()))
    {
        Some(special) => Err(FolderWriteError::AlreadyExists(FolderNode::Special(
            special,
        ))),
        None => Ok(()),
    }
}
