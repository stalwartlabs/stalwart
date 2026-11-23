/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderContents, FolderWriteError, FolderWriteResult, FolderWritten, WritableFolder,
    WriteOutcome, clear_folder_aliases, commit, finish, set_folder_alias,
};
use crate::{
    folders::{FolderNode, FolderTree, SpecialFolder, special_name},
    store::{
        FolderRef,
        account::ExchangeAccountStore,
        account_key,
        object::{
            ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion, OwnerStamp,
        },
    },
};
use common::{
    DavName, GroupwareResources, Server, auth::AccessToken, sharing::EffectiveAcl,
    storage::metadata::ContainerCleanup,
};
use groupware::{
    DestroyArchive,
    cache::GroupwareCache,
    calendar::{
        CALENDAR_SUBSCRIBED, Calendar, CalendarPreferences, EVENT_HAS_ALARMS, SupportedComponent,
        privacy::EventPrivacy,
    },
    contact::{AddressBook, AddressBookPreferences},
};
use registry::schema::enums::StorageQuota;
use std::ops::RangeInclusive;
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, BatchBuilder, PendingId, ValueClass, assert::AssertValue,
        metadata::ExchangeClass,
    },
};
use trc::{AddContext, EventType, LimitEvent};
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};
use utils::map::bitmap::Bitmap;

const NAME_LENGTH: RangeInclusive<usize> = 1..=255;
const DEFAULT_LIST_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CalendarContent {
    Events,
    Tasks,
    DefaultEvents { previous: Option<u32> },
    DefaultTasks { previous: Option<u32> },
}

impl CalendarContent {
    fn supported_components(self) -> u64 {
        match self {
            CalendarContent::Events | CalendarContent::DefaultEvents { .. } => 0,
            CalendarContent::Tasks | CalendarContent::DefaultTasks { .. } => {
                Bitmap::from(SupportedComponent::VTodo).into()
            }
        }
    }
}

fn stored_special(tree: &FolderTree, folder: SpecialFolder) -> Option<FolderRef> {
    match tree.special(folder)?.node {
        FolderNode::Stored(folder) => Some(folder),
        _ => None,
    }
}

pub(super) async fn task_list(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<Result<FolderRef, FolderWriteError>> {
    let mut revalidate = false;
    for _ in 0..DEFAULT_LIST_ATTEMPTS {
        let previous = server
            .store()
            .get_value::<u32>(account_key(account_id, ExchangeClass::TaskList))
            .await
            .caused_by(trc::location!())?;
        if revalidate {
            server
                .inner
                .mark_cache_stale(account_id, SyncCollection::Calendar);
        }
        let tree = WritableFolder::Calendar
            .folder_tree(server, account_id)
            .await?;
        if let Some(folder) = stored_special(&tree, SpecialFolder::Tasks) {
            return Ok(Ok(folder));
        }
        if previous.is_some() && !revalidate {
            revalidate = true;
            continue;
        }
        let name = special_name(SpecialFolder::Tasks);
        let result = create_calendar(
            server,
            access_token,
            account_id,
            &name,
            FolderNode::Special(SpecialFolder::IpmSubtree),
            CalendarContent::DefaultTasks { previous },
            None,
        )
        .await?;
        match finish(server, account_id, result) {
            Err(FolderWriteError::Conflict) => revalidate = true,
            result => return Ok(result.map(|written| written.folder)),
        }
    }
    Ok(Err(FolderWriteError::Conflict))
}

pub(super) async fn event_calendar(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<Result<FolderRef, FolderWriteError>> {
    let mut revalidate = false;
    for _ in 0..DEFAULT_LIST_ATTEMPTS {
        let checked = if revalidate {
            let previous = default_calendar_id(server, account_id).await?;
            server
                .inner
                .mark_cache_stale(account_id, SyncCollection::Calendar);
            Some(previous)
        } else {
            None
        };
        let tree = WritableFolder::Calendar
            .folder_tree(server, account_id)
            .await?;
        if let Some(folder) = stored_special(&tree, SpecialFolder::Calendar) {
            return Ok(Ok(folder));
        }
        let previous = match checked {
            Some(previous) => previous,
            None => {
                if default_calendar_id(server, account_id).await?.is_some() {
                    revalidate = true;
                    continue;
                }
                None
            }
        };
        let name = special_name(SpecialFolder::Calendar);
        let result = create_calendar(
            server,
            access_token,
            account_id,
            &name,
            FolderNode::Special(SpecialFolder::IpmSubtree),
            CalendarContent::DefaultEvents { previous },
            None,
        )
        .await?;
        match finish(server, account_id, result) {
            Err(FolderWriteError::Conflict) => revalidate = true,
            result => return Ok(result.map(|written| written.folder)),
        }
    }
    Ok(Err(FolderWriteError::Conflict))
}

async fn default_calendar_id(server: &Server, account_id: u32) -> trc::Result<Option<u32>> {
    server
        .store()
        .get_value::<u32>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
        })
        .await
        .caused_by(trc::location!())
}

pub(super) async fn create_calendar(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    name: &str,
    parent: FolderNode,
    content: CalendarContent,
    client_key: Option<u32>,
) -> FolderWriteResult {
    let kind = WritableFolder::Calendar;
    if let Err(err) = assert_may_create(server, access_token, account_id, kind).await? {
        return Ok(Err(err));
    }
    if let Err(err) = groupware_name(name) {
        return Ok(Err(err));
    }
    let personal_id = access_token.personal_id(account_id, Collection::Calendar);
    let mut calendar = Calendar {
        name: DavName::new_with_rand_name(0).name,
        preferences: vec![CalendarPreferences {
            account_id,
            ..Default::default()
        }],
        supported_components: content.supported_components(),
        ..Default::default()
    };
    calendar.preferences_mut(personal_id).flags |= CALENDAR_SUBSCRIBED;
    if access_token.is_member(account_id) {
        calendar.subscribe_member(personal_id);
    }
    calendar.preferences_mut(personal_id).name = name.into();
    calendar.sync_owner_preferences(account_id, personal_id);

    let mut batch = BatchBuilder::new();
    let slot = batch.reserve_document_id(account_id, Collection::Calendar);
    calendar
        .insert(access_token.changed_by(), account_id, slot, &mut batch)
        .caused_by(trc::location!())?;
    if let Err(err) = stage_parent(
        server,
        access_token,
        account_id,
        kind,
        PendingId::Slot(slot),
        parent,
        &mut batch,
    )
    .await?
    {
        return Ok(Err(err));
    }
    set_folder_alias(
        &mut batch,
        account_id,
        kind,
        PendingId::Slot(slot),
        client_key,
    );
    match content {
        CalendarContent::DefaultEvents { previous } => {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(
                    PrincipalField::DefaultCalendarId,
                    previous.map_or(AssertValue::None, AssertValue::U32),
                )
                .set(PrincipalField::DefaultCalendarId, PendingId::Slot(slot));
        }
        CalendarContent::DefaultTasks { previous } => {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(
                    ExchangeClass::TaskList,
                    previous.map_or(AssertValue::None, AssertValue::U32),
                )
                .set(ExchangeClass::TaskList, PendingId::Slot(slot));
        }
        CalendarContent::Events | CalendarContent::Tasks => (),
    }
    commit(server, account_id, kind, batch, |assigned_ids| {
        assigned_ids.slot(slot)
    })
    .await
}

pub(super) async fn create_address_book(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    name: &str,
    parent: FolderNode,
    client_key: Option<u32>,
) -> FolderWriteResult {
    let kind = WritableFolder::AddressBook;
    if let Err(err) = assert_may_create(server, access_token, account_id, kind).await? {
        return Ok(Err(err));
    }
    if let Err(err) = groupware_name(name) {
        return Ok(Err(err));
    }
    let personal_id = access_token.personal_id(account_id, Collection::AddressBook);
    let mut address_book = AddressBook {
        name: DavName::new_with_rand_name(0).name,
        preferences: vec![AddressBookPreferences {
            account_id,
            ..Default::default()
        }],
        ..Default::default()
    };
    address_book.preferences_mut(personal_id).name = name.into();

    let mut batch = BatchBuilder::new();
    let slot = batch.reserve_document_id(account_id, Collection::AddressBook);
    address_book
        .insert(access_token.changed_by(), account_id, slot, &mut batch)
        .caused_by(trc::location!())?;
    if let Err(err) = stage_parent(
        server,
        access_token,
        account_id,
        kind,
        PendingId::Slot(slot),
        parent,
        &mut batch,
    )
    .await?
    {
        return Ok(Err(err));
    }
    set_folder_alias(
        &mut batch,
        account_id,
        kind,
        PendingId::Slot(slot),
        client_key,
    );
    commit(server, account_id, kind, batch, |assigned_ids| {
        assigned_ids.slot(slot)
    })
    .await
}

pub(super) async fn update(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    kind: WritableFolder,
    document_id: u32,
    name: Option<&str>,
    parent: Option<FolderNode>,
) -> FolderWriteResult {
    let unchanged = Ok(Ok(FolderWritten {
        folder: kind.folder_ref(document_id),
        change_id: None,
        outcome: WriteOutcome::Written,
    }));
    if name.is_none() && parent.is_none() {
        return unchanged;
    }
    if let Some(Err(err)) = name.map(groupware_name) {
        return Ok(Err(err));
    }
    let Some(archive) = read_container(server, account_id, kind, document_id).await? else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let is_shared = access_token.is_shared(account_id);
    if is_shared && parent.is_some() {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let changed_by = access_token.changed_by();
    let personal_id = access_token.personal_id(account_id, kind.collection());
    let mut batch = BatchBuilder::new();
    let mut renamed = false;
    if kind == WritableFolder::Calendar {
        let calendar = archive
            .to_unarchived::<Calendar>()
            .caused_by(trc::location!())?;
        if is_shared && !may_read(calendar.inner.acls.effective_acl(access_token)) {
            return Ok(Err(FolderWriteError::NotFound));
        }
        if let Some(name) = name.filter(|name| {
            calendar
                .inner
                .preferences(personal_id)
                .is_none_or(|preferences| preferences.name.as_str() != *name)
        }) {
            let mut new_calendar = calendar
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;
            if !is_shared {
                new_calendar.inherit_owner_preferences(account_id, personal_id);
            }
            if access_token.is_member(account_id) {
                new_calendar.subscribe_member(personal_id);
            }
            new_calendar.preferences_mut(personal_id).name = name.into();
            if !is_shared {
                new_calendar.sync_owner_preferences(account_id, personal_id);
            }
            new_calendar
                .update(changed_by, calendar, account_id, document_id, &mut batch)
                .caused_by(trc::location!())?;
            renamed = true;
        }
    } else {
        let address_book = archive
            .to_unarchived::<AddressBook>()
            .caused_by(trc::location!())?;
        if is_shared && !may_read(address_book.inner.acls.effective_acl(access_token)) {
            return Ok(Err(FolderWriteError::NotFound));
        }
        if let Some(name) =
            name.filter(|name| address_book.inner.preferences(personal_id).name.as_str() != *name)
        {
            let mut new_address_book = address_book
                .deserialize::<AddressBook>()
                .caused_by(trc::location!())?;
            new_address_book.preferences_mut(personal_id).name = name.into();
            new_address_book
                .update(
                    changed_by,
                    address_book,
                    account_id,
                    document_id,
                    &mut batch,
                )
                .caused_by(trc::location!())?;
            renamed = true;
        }
    }
    let moved = match parent {
        Some(parent) => match stage_parent(
            server,
            access_token,
            account_id,
            kind,
            PendingId::Assigned(document_id),
            parent,
            &mut batch,
        )
        .await?
        {
            Ok(moved) => moved,
            Err(err) => return Ok(Err(err)),
        },
        None => false,
    };
    if !renamed && !moved {
        return unchanged;
    }
    if !renamed {
        batch
            .with_account_id(account_id)
            .with_collection(kind.collection())
            .with_document(document_id)
            .log_container_update(kind.sync_collection());
    }
    commit(server, account_id, kind, batch, |_| document_id).await
}

async fn stage_parent(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    kind: WritableFolder,
    document_id: PendingId,
    parent: FolderNode,
    batch: &mut BatchBuilder,
) -> trc::Result<Result<bool, FolderWriteError>> {
    let previous = match document_id {
        PendingId::Assigned(document_id) => server
            .exchange_object(account_id, kind.collection(), document_id)
            .await
            .caused_by(trc::location!())?,
        PendingId::Slot(_) => None,
    };
    let mut next = previous
        .as_ref()
        .map(|previous| previous.deserialize::<ExchangeObject>())
        .transpose()
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let key = FolderNode::parent_property_key();
    let changed = match parent {
        FolderNode::Stored(_) => {
            let value = parent.parent_property_value();
            let changed = next.property(&key) != Some(value.as_slice());
            if changed {
                next.set_property(key, value);
            }
            changed
        }
        FolderNode::Special(_) => next.remove_property(&key).is_some(),
    };
    if !changed {
        return Ok(Ok(false));
    }
    let written = ExchangeObjectWrite {
        owner: server
            .exchange_quota_owner(access_token, account_id)
            .await?,
        collection: kind.collection(),
        document_id,
        stamp: OwnerStamp::Logged,
        version: ObjectVersion::Server,
        previous: previous.as_ref(),
        next: Some(next),
        max_size: server.core.exchange.max_object_size,
    }
    .build(batch);
    match written {
        Ok(()) => Ok(Ok(true)),
        Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
            Ok(Err(FolderWriteError::OverQuota))
        }
        Err(err) => Err(err),
    }
}

pub(super) async fn destroy_calendar(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    contents: FolderContents,
) -> FolderWriteResult {
    let kind = WritableFolder::Calendar;
    let cache = server
        .fetch_groupware_resources(
            access_token.account_id(),
            account_id,
            kind.sync_collection(),
        )
        .await
        .caused_by(trc::location!())?;
    if !cache.has_container_id(&document_id) {
        return Ok(Err(FolderWriteError::NotFound));
    }
    let Some(archive) = read_container(server, account_id, kind, document_id).await? else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let calendar = archive
        .to_unarchived::<Calendar>()
        .caused_by(trc::location!())?;
    let is_shared = access_token.is_shared(account_id);
    if is_shared
        && !calendar
            .inner
            .acls
            .effective_acl(access_token)
            .contains(Acl::Delete)
    {
        return Ok(Err(FolderWriteError::Forbidden));
    }

    let mut has_visible_children = false;
    let mut has_restricted_children = false;
    for flags in cache
        .children(document_id)
        .map(|child| child.resource.event_flags().unwrap_or_default())
    {
        match EventPrivacy::from_flags(flags) {
            EventPrivacy::Public => has_visible_children = true,
            EventPrivacy::Private => {
                has_visible_children = true;
                has_restricted_children = true;
            }
            EventPrivacy::Secret => {
                has_visible_children |= !is_shared;
                has_restricted_children = true;
            }
        }
    }
    if has_visible_children && contents == FolderContents::Keep {
        return Ok(Err(FolderWriteError::HasItems));
    }
    if is_shared && has_restricted_children {
        return Ok(Err(FolderWriteError::Forbidden));
    }

    let (children_ids, cleanup) = children_cleanup(
        server,
        access_token,
        account_id,
        &cache,
        document_id,
        Collection::CalendarEvent,
    )
    .await?;
    let account_info = server
        .account_info(access_token.account_id())
        .await
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();
    DestroyArchive(calendar)
        .delete_with_events(
            server,
            access_token,
            &account_info,
            account_id,
            document_id,
            children_ids,
            &cache.event_ids_with_flags(EVENT_HAS_ALARMS),
            &cleanup,
            delete_path(&cache, document_id),
            false,
            &mut batch,
        )
        .await
        .caused_by(trc::location!())?;
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear_if_equals(PrincipalField::DefaultCalendarId, document_id);
    clear_folder_aliases(server, &mut batch, account_id, kind, &[document_id]).await?;
    commit(server, account_id, kind, batch, |_| document_id).await
}

pub(super) async fn destroy_address_book(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    document_id: u32,
    contents: FolderContents,
) -> FolderWriteResult {
    let kind = WritableFolder::AddressBook;
    let cache = server
        .fetch_groupware_resources(
            access_token.account_id(),
            account_id,
            kind.sync_collection(),
        )
        .await
        .caused_by(trc::location!())?;
    if !cache.has_container_id(&document_id) {
        return Ok(Err(FolderWriteError::NotFound));
    }
    let Some(archive) = read_container(server, account_id, kind, document_id).await? else {
        return Ok(Err(FolderWriteError::NotFound));
    };
    let address_book = archive
        .to_unarchived::<AddressBook>()
        .caused_by(trc::location!())?;
    if access_token.is_shared(account_id)
        && !address_book
            .inner
            .acls
            .effective_acl(access_token)
            .contains(Acl::Delete)
    {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    if contents == FolderContents::Keep && cache.children_ids(document_id).next().is_some() {
        return Ok(Err(FolderWriteError::HasItems));
    }

    let (children_ids, cleanup) = children_cleanup(
        server,
        access_token,
        account_id,
        &cache,
        document_id,
        Collection::ContactCard,
    )
    .await?;
    let mut batch = BatchBuilder::new();
    DestroyArchive(address_book)
        .delete_with_cards(
            server,
            access_token.changed_by(),
            account_id,
            document_id,
            children_ids,
            &cleanup,
            delete_path(&cache, document_id),
            &mut batch,
        )
        .await
        .caused_by(trc::location!())?;
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear_if_equals(PrincipalField::DefaultAddressBookId, document_id);
    clear_folder_aliases(server, &mut batch, account_id, kind, &[document_id]).await?;
    commit(server, account_id, kind, batch, |_| document_id).await
}

async fn assert_may_create(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    kind: WritableFolder,
) -> trc::Result<Result<(), FolderWriteError>> {
    if access_token.is_shared(account_id) {
        return Ok(Err(FolderWriteError::Forbidden));
    }
    let quota = match kind {
        WritableFolder::Calendar => StorageQuota::MaxCalendars,
        _ => StorageQuota::MaxAddressBooks,
    };
    let cache = server
        .fetch_groupware_resources(
            access_token.account_id(),
            account_id,
            kind.sync_collection(),
        )
        .await
        .caused_by(trc::location!())?;
    let account = server
        .account(account_id)
        .await
        .caused_by(trc::location!())?;
    Ok(
        if server
            .object_quota_usage(&account, quota, || cache.resources.count(true))
            .has_room(0)
        {
            Ok(())
        } else {
            Err(FolderWriteError::OverQuota)
        },
    )
}

fn groupware_name(name: &str) -> Result<(), FolderWriteError> {
    if NAME_LENGTH.contains(&name.len()) {
        Ok(())
    } else if name.is_empty() {
        Err(FolderWriteError::EmptyName)
    } else {
        Err(FolderWriteError::NameTooLong)
    }
}

fn may_read(acl: Bitmap<Acl>) -> bool {
    acl.contains_any([Acl::Read, Acl::ReadItems].into_iter())
}

pub(super) async fn read_container(
    server: &Server,
    account_id: u32,
    kind: WritableFolder,
    document_id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            kind.collection(),
            document_id,
        ))
        .await
        .caused_by(trc::location!())
}

async fn children_cleanup(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    cache: &GroupwareResources,
    document_id: u32,
    collection: Collection,
) -> trc::Result<(Vec<u32>, ContainerCleanup)> {
    let mut children_ids = Vec::new();
    let mut flagged = RoaringBitmap::new();
    for child in cache.children(document_id) {
        let child_id = child.document_id();
        children_ids.push(child_id);
        if !child.resource.metadata_kinds().is_empty() {
            flagged.insert(child_id);
        }
    }
    let cleanup = server
        .preload_container_cleanup(access_token.changed_by(), account_id, collection, &flagged)
        .await
        .caused_by(trc::location!())?;
    Ok((children_ids, cleanup))
}

fn delete_path(cache: &GroupwareResources, document_id: u32) -> Option<String> {
    cache
        .container_resource_path_by_id(document_id)
        .map(|resource| cache.format_resource(resource))
}
