/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ContainerClass, FolderNode, SYNC_ISSUES_FOLDERS, SpecialFolder, WritableFolder,
    tree::{FolderTree, HierarchyVersion, PendingFolder, TreeBuilder},
};
use crate::{
    cache::ExchangeCacheFetch,
    store::{
        FolderKind, FolderRef,
        folder::{FolderStore, VirtualFolderRow},
        object::ExchangeObjectStore,
    },
};
use common::{
    GroupwareResources, MessageStoreCache, Server,
    cache::exchange::{ContainerEntry, ContainerMeta, ExchangeAccountCache, FolderKey},
};
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use groupware::{
    cache::GroupwareCache,
    calendar::{Calendar, SupportedComponent},
    contact::AddressBook,
};
use std::sync::Arc;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, ValueClass, metadata::ExchangeFolder},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
    special_use::SpecialUse,
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

const ROOT_FOLDERS: [SpecialFolder; 7] = [
    SpecialFolder::Views,
    SpecialFolder::CommonViews,
    SpecialFolder::Finder,
    SpecialFolder::Schedule,
    SpecialFolder::Shortcuts,
    SpecialFolder::DeferredAction,
    SpecialFolder::SpoolerQueue,
];
const COMPONENT_EVENT: u8 = 1;
const COMPONENT_TODO: u8 = 1 << 1;
const COMPONENT_JOURNAL: u8 = 1 << 2;
const COMPONENTS: [(SupportedComponent, u8); 3] = [
    (SupportedComponent::VEvent, COMPONENT_EVENT),
    (SupportedComponent::VTodo, COMPONENT_TODO),
    (SupportedComponent::VJournal, COMPONENT_JOURNAL),
];
const MAX_CONTAINER_DEPTH: usize = 32;

struct FolderSources {
    mail: Option<Arc<MessageStoreCache>>,
    calendars: Option<Arc<GroupwareResources>>,
    address_books: Option<Arc<GroupwareResources>>,
}

impl FolderSources {
    async fn fetch(
        server: &Server,
        account_id: u32,
        data_types: Bitmap<DataType>,
    ) -> trc::Result<Self> {
        Ok(FolderSources {
            mail: if data_types.contains(DataType::Email) {
                Some(server.get_cached_messages(account_id).await?)
            } else {
                None
            },
            calendars: if data_types.contains(DataType::CalendarEvent) {
                Some(
                    server
                        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
                        .await?,
                )
            } else {
                None
            },
            address_books: if data_types.contains(DataType::ContactCard) {
                Some(
                    server
                        .fetch_groupware_resources(
                            account_id,
                            account_id,
                            SyncCollection::AddressBook,
                        )
                        .await?,
                )
            } else {
                None
            },
        })
    }

    fn leads(&self, exchange: &ExchangeAccountCache) -> bool {
        let [mail_seen, calendar_seen, address_book_seen, _] = exchange.change_ids;
        self.mail
            .as_ref()
            .is_some_and(|mail| mail.mailboxes.change_id > mail_seen)
            || self
                .calendars
                .as_ref()
                .is_some_and(|calendars| calendars.container_change_id > calendar_seen)
            || self
                .address_books
                .as_ref()
                .is_some_and(|address_books| address_books.container_change_id > address_book_seen)
    }
}

pub trait ExchangeFolders: Sync + Send {
    fn exchange_folder_tree(
        &self,
        account_id: u32,
        data_types: Bitmap<DataType>,
    ) -> impl Future<Output = trc::Result<FolderTree>> + Send;
}

impl ExchangeFolders for Server {
    async fn exchange_folder_tree(
        &self,
        account_id: u32,
        data_types: Bitmap<DataType>,
    ) -> trc::Result<FolderTree> {
        let mut exchange = self.get_cached_exchange(account_id).await?;
        let mut sources = FolderSources::fetch(self, account_id, data_types).await?;
        if sources.leads(&exchange) {
            self.mark_exchange_stale(account_id);
            exchange = self.get_cached_exchange(account_id).await?;
            sources = FolderSources::fetch(self, account_id, data_types).await?;
        }
        let FolderSources {
            mail,
            calendars,
            address_books,
        } = sources;
        let base = exchange.folder_base.first().copied().unwrap_or_default();
        let want_calendars = data_types.contains(DataType::CalendarEvent);
        let want_address_books = data_types.contains(DataType::ContactCard);
        let calendars = calendars.as_ref();
        let address_books = address_books.as_ref();

        let mut version = HierarchyVersion {
            mail: mail.as_ref().map_or(0, |mail| mail.mailboxes.change_id),
            calendar: calendars.map_or(0, |calendars| calendars.container_change_id),
            address_book: address_books
                .map_or(0, |address_books| address_books.container_change_id),
            ..Default::default()
        };
        let mut builder = TreeBuilder::with_capacity(
            32 + mail.as_ref().map_or(0, |mail| mail.mailboxes.items.len()),
        );
        builder.push(PendingFolder {
            node: FolderNode::Special(SpecialFolder::Root),
            parent: None,
            name: super::special_name(SpecialFolder::Root),
            class: SpecialFolder::Root.class(),
            special: Some(SpecialFolder::Root),
            change_id: base,
            search: false,
        });
        builder.push_special(SpecialFolder::IpmSubtree, SpecialFolder::Root, base);
        for folder in ROOT_FOLDERS {
            builder.push_special(folder, SpecialFolder::Root, base);
        }

        if let Some(mail) = &mail {
            let classes = mailbox_classes(self, account_id, &exchange).await?;
            push_mailboxes(&mut builder, &exchange, mail, &classes);
            builder.push_special(SpecialFolder::Outbox, SpecialFolder::IpmSubtree, base);
            let sync_issues = builder.adopt_or_push_special(
                SpecialFolder::SyncIssues,
                FolderNode::Special(SpecialFolder::IpmSubtree),
                base,
            );
            for folder in SYNC_ISSUES_FOLDERS {
                builder.adopt_or_push_special(folder, sync_issues, base);
            }
            if !builder.has_special(SpecialFolder::Notes) {
                builder.push_special(SpecialFolder::Notes, SpecialFolder::IpmSubtree, base);
            }
        }
        let meta = if want_calendars || want_address_books {
            let resident = |wanted: Option<&Arc<GroupwareResources>>, collection| {
                wanted
                    .cloned()
                    .or_else(|| self.cached_groupware_resources(account_id, collection))
            };
            let memo_calendars = resident(calendars, SyncCollection::Calendar);
            let memo_address_books = resident(address_books, SyncCollection::AddressBook);
            Some(
                container_meta(
                    self,
                    account_id,
                    &exchange,
                    memo_calendars.as_deref(),
                    memo_address_books.as_deref(),
                )
                .await?,
            )
        } else {
            None
        };
        let parents = meta.as_deref().map(ContainerParents::new);
        let links = ContainerLinks {
            parents: parents.as_ref(),
            mail: mail.as_deref(),
        };
        if let (Some(calendars), Some(meta)) = (calendars, &meta) {
            let default_id = default_container(
                self,
                account_id,
                PrincipalField::DefaultCalendarId,
                calendars,
            )
            .await?;
            version.default_calendar = default_id;
            push_calendars(&mut builder, &exchange, meta, &links, default_id);
            let base = exchange.folder_base.get(1).copied().unwrap_or(base);
            for folder in [
                SpecialFolder::Calendar,
                SpecialFolder::Tasks,
                SpecialFolder::Journal,
            ] {
                if !builder.has_special(folder) {
                    builder.push_special(folder, SpecialFolder::IpmSubtree, base);
                }
            }
        }
        if let (Some(address_books), Some(meta)) = (address_books, &meta) {
            let default_id = default_container(
                self,
                account_id,
                PrincipalField::DefaultAddressBookId,
                address_books,
            )
            .await?;
            version.default_address_book = default_id;
            push_address_books(&mut builder, &exchange, meta, &links, default_id);
        }

        if mail.is_none() {
            return Ok(builder.build(version));
        }
        self.virtual_folder_rows(account_id, |id, row| {
            let folder = match row {
                VirtualFolderRow::Live(folder) => folder,
                VirtualFolderRow::Deleted { change } => {
                    version.virtual_change = version.virtual_change.max(change);
                    builder.push_virtual_deletion(id, change);
                    return Ok(true);
                }
                VirtualFolderRow::Horizon { change } => {
                    version.virtual_change = version.virtual_change.max(change);
                    version.virtual_horizon = change;
                    return Ok(true);
                }
            };
            version.virtual_change = version.virtual_change.max(folder.change.to_native());
            version.virtual_count = version.virtual_count.saturating_add(1);
            let stored = FolderNode::from_stored(folder.parent.kind, folder.parent.id.to_native());
            let parent = match (stored, folder.search.is_some()) {
                (Some(parent), false) => parent,
                (Some(FolderNode::Special(SpecialFolder::Root)), true) => {
                    FolderNode::Special(SpecialFolder::Root)
                }
                (_, true) => FolderNode::Special(SpecialFolder::Finder),
                (None, false) => return Ok(true),
            };
            let modified = folder.modified.to_native();
            if modified != 0 {
                builder.push_virtual_modified(id, modified);
            }
            let node = FolderNode::Stored(FolderRef {
                kind: FolderKind::Virtual,
                id,
            });
            if let Some(search) = folder.search.as_ref() {
                for scope in search.scope.iter() {
                    if let Some(scope) = FolderNode::from_stored(scope.kind, scope.id.to_native()) {
                        builder.push_search_scope(node, scope);
                    }
                }
            }
            builder.push(PendingFolder {
                node,
                parent: Some(parent),
                name: Arc::from(folder.name.as_str()),
                class: ContainerClass::parse(folder.container_class.as_str()),
                special: None,
                change_id: folder.change.to_native(),
                search: folder.search.is_some(),
            });
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;

        Ok(builder.build(version))
    }
}

fn push_mailboxes(
    builder: &mut TreeBuilder,
    exchange: &ExchangeAccountCache,
    mail: &MessageStoreCache,
    classes: &[(u32, ContainerClass)],
) {
    for mailbox in mail.mailboxes.items.iter() {
        let special = match mailbox.role {
            SpecialUse::Inbox => Some(SpecialFolder::Inbox),
            SpecialUse::Drafts => Some(SpecialFolder::Drafts),
            SpecialUse::Sent => Some(SpecialFolder::SentItems),
            SpecialUse::Trash => Some(SpecialFolder::DeletedItems),
            SpecialUse::Junk => Some(SpecialFolder::JunkEmail),
            SpecialUse::Archive => Some(SpecialFolder::Archive),
            SpecialUse::Memos => Some(SpecialFolder::Notes),
            _ => None,
        }
        .filter(|special| !builder.has_special(*special));
        let class = match classes.binary_search_by_key(&mailbox.document_id, |(id, _)| *id) {
            Ok(pos) => classes
                .get(pos)
                .map_or(ContainerClass::Note, |(_, class)| class.clone()),
            Err(_) if special == Some(SpecialFolder::Notes) => ContainerClass::StickyNote,
            Err(_) => ContainerClass::Note,
        };
        let parent = mailbox.parent_id().map_or(
            FolderNode::Special(SpecialFolder::IpmSubtree),
            |parent_id| {
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id: parent_id,
                })
            },
        );
        builder.push(PendingFolder {
            node: FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id: mailbox.document_id,
            }),
            parent: Some(parent),
            name: mailbox.name.clone(),
            class,
            special,
            change_id: folder_change_id(exchange, FolderKind::Mailbox, mailbox.document_id),
            search: false,
        });
    }
}

async fn mailbox_classes(
    server: &Server,
    account_id: u32,
    exchange: &ExchangeAccountCache,
) -> trc::Result<Vec<(u32, ContainerClass)>> {
    let mut classes = Vec::new();
    let Some(stored) = exchange
        .objects(Collection::Mailbox)
        .filter(|stored| !stored.is_empty())
    else {
        return Ok(classes);
    };
    let key = ContainerClass::property_key();
    server
        .exchange_objects(
            exchange,
            account_id,
            Collection::Mailbox,
            stored,
            |document_id, object| {
                if let Some(class) = object
                    .property(&key)
                    .and_then(ContainerClass::from_property_value)
                    .filter(|class| class.family() == Some(WritableFolder::Mailbox))
                {
                    classes.push((document_id, class));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    classes.sort_unstable_by_key(|(id, _)| *id);
    Ok(classes)
}

async fn container_meta(
    server: &Server,
    account_id: u32,
    exchange: &ExchangeAccountCache,
    calendars: Option<&GroupwareResources>,
    address_books: Option<&GroupwareResources>,
) -> trc::Result<Arc<ContainerMeta>> {
    let memo_key = calendars
        .zip(address_books)
        .map(|(calendars, address_books)| {
            (
                calendars.container_change_id,
                address_books.container_change_id,
            )
        });
    if let Some(meta) = memo_key.and_then(|(calendar_change_id, address_book_change_id)| {
        exchange.containers(calendar_change_id, address_book_change_id)
    }) {
        return Ok(meta);
    }

    let mut entries = Vec::with_capacity(
        calendars.map_or(0, |calendars| calendars.containers().count())
            + address_books.map_or(0, |address_books| address_books.containers().count()),
    );
    let calendar_parents = if calendars.is_some() {
        container_parents(server, account_id, exchange, Collection::Calendar).await?
    } else {
        Vec::new()
    };
    for container in calendars
        .iter()
        .flat_map(|calendars| calendars.containers())
    {
        let id = container.document_id();
        let Some(archive) = read_archive(server, account_id, Collection::Calendar, id).await?
        else {
            continue;
        };
        let calendar = archive
            .unarchive::<Calendar>()
            .caused_by(trc::location!())?;
        let components =
            Bitmap::<SupportedComponent>::from(calendar.supported_components.to_native());
        let name = calendar
            .preferences(account_id)
            .map(|preferences| preferences.name.as_str())
            .filter(|name| !name.is_empty())
            .unwrap_or(calendar.name.as_str());
        entries.push(ContainerEntry {
            kind: FolderKind::Calendar as u8,
            id,
            components: COMPONENTS
                .iter()
                .filter(|(component, _)| components.contains(*component))
                .fold(0, |bits, (_, bit)| bits | bit),
            parent: stored_parent(&calendar_parents, id),
            name: name.into(),
        });
    }
    let address_book_parents = if address_books.is_some() {
        container_parents(server, account_id, exchange, Collection::AddressBook).await?
    } else {
        Vec::new()
    };
    for container in address_books
        .iter()
        .flat_map(|address_books| address_books.containers())
    {
        let id = container.document_id();
        let Some(archive) = read_archive(server, account_id, Collection::AddressBook, id).await?
        else {
            continue;
        };
        let address_book = archive
            .unarchive::<AddressBook>()
            .caused_by(trc::location!())?;
        let name = address_book.preferences(account_id).name.as_str();
        entries.push(ContainerEntry {
            kind: FolderKind::AddressBook as u8,
            id,
            components: 0,
            parent: stored_parent(&address_book_parents, id),
            name: if name.is_empty() {
                address_book.name.as_str()
            } else {
                name
            }
            .into(),
        });
    }
    let (calendar_change_id, address_book_change_id) = memo_key.unwrap_or_default();
    let meta = Arc::new(ContainerMeta {
        calendar_change_id,
        address_book_change_id,
        entries: entries.into_boxed_slice(),
    });
    if memo_key.is_some() {
        exchange.publish_containers(meta.clone());
    }
    Ok(meta)
}

async fn container_parents(
    server: &Server,
    account_id: u32,
    exchange: &ExchangeAccountCache,
    collection: Collection,
) -> trc::Result<Vec<(u32, ExchangeFolder)>> {
    let mut parents = Vec::new();
    let Some(stored) = exchange
        .objects(collection)
        .filter(|stored| !stored.is_empty())
    else {
        return Ok(parents);
    };
    let key = FolderNode::parent_property_key();
    server
        .exchange_objects(
            exchange,
            account_id,
            collection,
            stored,
            |document_id, object| {
                if let Some(parent) = object
                    .property(&key)
                    .and_then(FolderNode::parent_from_property)
                {
                    parents.push((document_id, parent));
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    parents.sort_unstable_by_key(|(id, _)| *id);
    Ok(parents)
}

fn stored_parent(parents: &[(u32, ExchangeFolder)], id: u32) -> ExchangeFolder {
    parents
        .binary_search_by_key(&id, |(id, _)| *id)
        .ok()
        .and_then(|pos| parents.get(pos))
        .map_or(FolderNode::ipm_parent(), |(_, parent)| *parent)
}

struct ContainerParents(Vec<(u8, u32, ExchangeFolder)>);

impl ContainerParents {
    fn new(meta: &ContainerMeta) -> Self {
        let mut parents = Vec::new();
        if meta
            .entries
            .iter()
            .any(|entry| entry.parent != FolderNode::ipm_parent())
        {
            parents.reserve_exact(meta.entries.len());
            parents.extend(
                meta.entries
                    .iter()
                    .map(|entry| (entry.kind, entry.id, entry.parent)),
            );
            parents.sort_unstable_by_key(|&(kind, id, _)| (kind, id));
        }
        ContainerParents(parents)
    }

    fn get(&self, kind: u8, id: u32) -> Option<ExchangeFolder> {
        self.0
            .binary_search_by_key(&(kind, id), |&(kind, id, _)| (kind, id))
            .ok()
            .and_then(|pos| self.0.get(pos))
            .map(|&(_, _, parent)| parent)
    }
}

struct ContainerLinks<'x> {
    parents: Option<&'x ContainerParents>,
    mail: Option<&'x MessageStoreCache>,
}

impl ContainerLinks<'_> {
    fn parent(&self, entry: &ContainerEntry, special: Option<SpecialFolder>) -> FolderNode {
        let ipm = FolderNode::Special(SpecialFolder::IpmSubtree);
        let (Some(parents), None) = (self.parents, special) else {
            return ipm;
        };
        let Some(parent) = FolderNode::from_stored(entry.parent.kind, entry.parent.id) else {
            return ipm;
        };
        let mut current = parent;
        for _ in 0..MAX_CONTAINER_DEPTH {
            let linked = current != parent;
            match current {
                FolderNode::Stored(FolderRef { kind, id })
                    if kind as u8 == entry.kind && id == entry.id =>
                {
                    return ipm;
                }
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id,
                }) => {
                    return if linked
                        || self
                            .mail
                            .is_some_and(|mail| mail.mailbox_by_id(&id).is_some())
                    {
                        parent
                    } else {
                        ipm
                    };
                }
                FolderNode::Stored(FolderRef { kind, id }) if kind as u8 == entry.kind => {
                    match parents
                        .get(entry.kind, id)
                        .and_then(|next| FolderNode::from_stored(next.kind, next.id))
                    {
                        Some(next) => current = next,
                        None if linked => return parent,
                        None => return ipm,
                    }
                }
                FolderNode::Special(SpecialFolder::IpmSubtree) => return parent,
                _ if linked => return parent,
                _ => return ipm,
            }
        }
        ipm
    }
}

async fn read_archive(
    server: &Server,
    account_id: u32,
    collection: Collection,
    id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(account_id, collection, id))
        .await
        .caused_by(trc::location!())
}

fn push_calendars(
    builder: &mut TreeBuilder,
    exchange: &ExchangeAccountCache,
    meta: &ContainerMeta,
    links: &ContainerLinks<'_>,
    default_id: Option<u32>,
) {
    let calendars = meta
        .entries
        .iter()
        .filter(|entry| entry.kind == FolderKind::Calendar as u8);
    let holds_events =
        |entry: &&ContainerEntry| entry.components == 0 || entry.components & COMPONENT_EVENT != 0;
    let default_id = default_id
        .filter(|id| {
            calendars
                .clone()
                .filter(holds_events)
                .any(|entry| entry.id == *id)
        })
        .or_else(|| {
            calendars
                .clone()
                .filter(holds_events)
                .map(|entry| entry.id)
                .min()
        });
    let named_tasks = calendars
        .clone()
        .find(|entry| {
            entry.components == COMPONENT_TODO
                && Some(entry.id) != default_id
                && *entry.name == *SpecialFolder::Tasks.display_name()
        })
        .map(|entry| entry.id);
    for entry in calendars {
        let (class, special) = if Some(entry.id) == default_id {
            (ContainerClass::Appointment, Some(SpecialFolder::Calendar))
        } else if entry.components == COMPONENT_TODO {
            (
                ContainerClass::Task,
                named_tasks
                    .is_none_or(|id| id == entry.id)
                    .then_some(SpecialFolder::Tasks),
            )
        } else if entry.components == COMPONENT_JOURNAL {
            (ContainerClass::Journal, Some(SpecialFolder::Journal))
        } else {
            (ContainerClass::Appointment, None)
        };
        let special = special.filter(|special| !builder.has_special(*special));
        builder.push(PendingFolder {
            node: FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar,
                id: entry.id,
            }),
            parent: Some(links.parent(entry, special)),
            name: Arc::from(
                special
                    .filter(|special| *special == SpecialFolder::Calendar)
                    .map_or(&*entry.name, |special| special.display_name()),
            ),
            class,
            special,
            change_id: folder_change_id(exchange, FolderKind::Calendar, entry.id),
            search: false,
        });
    }
}

fn push_address_books(
    builder: &mut TreeBuilder,
    exchange: &ExchangeAccountCache,
    meta: &ContainerMeta,
    links: &ContainerLinks<'_>,
    default_id: Option<u32>,
) {
    for entry in meta
        .entries
        .iter()
        .filter(|entry| entry.kind == FolderKind::AddressBook as u8)
    {
        let special = (Some(entry.id) == default_id
            && !builder.has_special(SpecialFolder::Contacts))
        .then_some(SpecialFolder::Contacts);
        builder.push(PendingFolder {
            node: FolderNode::Stored(FolderRef {
                kind: FolderKind::AddressBook,
                id: entry.id,
            }),
            parent: Some(links.parent(entry, special)),
            name: Arc::from(special.map_or(&*entry.name, |special| special.display_name())),
            class: ContainerClass::Contact,
            special,
            change_id: folder_change_id(exchange, FolderKind::AddressBook, entry.id),
            search: false,
        });
    }
}

pub(crate) async fn default_container(
    server: &Server,
    account_id: u32,
    field: PrincipalField,
    resources: &GroupwareResources,
) -> trc::Result<Option<u32>> {
    let stored = server
        .store()
        .get_value::<u32>(ValueKey {
            account_id,
            collection: Collection::Principal.into(),
            document_id: 0,
            class: ValueClass::Property(field.into()),
        })
        .await
        .caused_by(trc::location!())?;
    let containers = || {
        resources
            .containers()
            .map(|container| container.document_id())
    };
    Ok(stored
        .filter(|id| containers().any(|container| container == *id))
        .or_else(|| containers().min()))
}

fn folder_change_id(exchange: &ExchangeAccountCache, kind: FolderKind, id: u32) -> u64 {
    exchange
        .folder_change_id(FolderKey {
            kind: kind as u8,
            id,
        })
        .or_else(|| exchange.folder_base.get(kind as usize).copied())
        .unwrap_or_default()
}
