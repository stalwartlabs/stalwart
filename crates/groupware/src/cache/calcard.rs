/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::GroupwareCache;
use crate::{
    DavResourceName, RFC_3986,
    calendar::{
        ArchivedCalendar, ArchivedCalendarEvent, Calendar, CalendarEvent, SCHEDULE_INBOX_ID,
        SCHEDULE_OUTBOX_ID, storage::ItipAutoExpunge,
    },
    contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard},
};
use calcard::common::timezone::Tz;
use common::{
    DavName, DavPath, DavResource, DavResourceMetadata, DavResources, Server,
    TinyCalendarPreferences, auth::AccessToken,
};
use directory::backend::internal::manage::ManageDirectory;
use std::sync::Arc;
use store::ahash::{AHashMap, AHashSet};
use tokio::sync::Semaphore;
use trc::AddContext;
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
};
use utils::map::bitmap::Bitmap;

pub(super) async fn build_calcard_resources(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
    sync_collection: SyncCollection,
    container_collection: Collection,
    item_collection: Collection,
    update_lock: Arc<Semaphore>,
) -> trc::Result<DavResources> {
    let is_calendar = matches!(sync_collection, SyncCollection::Calendar);
    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));
    let mut cache = DavResources {
        base_path: format!(
            "{}/{}/",
            if is_calendar {
                DavResourceName::Cal
            } else {
                DavResourceName::Card
            }
            .base_path(),
            percent_encoding::utf8_percent_encode(&name, RFC_3986),
        ),
        paths: AHashSet::with_capacity(16),
        resources: Vec::with_capacity(16),
        item_change_id: 0,
        container_change_id: 0,
        highest_change_id: 0,
        size: std::mem::size_of::<DavResources>() as u64,
        update_lock,
    };

    let mut is_first_check = true;
    loop {
        let last_change_id = server
            .core
            .storage
            .data
            .get_last_change_id(account_id, sync_collection.into())
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
        cache.item_change_id = last_change_id;
        cache.container_change_id = last_change_id;
        cache.highest_change_id = last_change_id;

        server
            .archives(
                account_id,
                container_collection,
                &(),
                |document_id, archive| {
                    let resource = if is_calendar {
                        resource_from_calendar(archive.unarchive::<Calendar>()?, document_id)
                    } else {
                        resource_from_addressbook(archive.unarchive::<AddressBook>()?, document_id)
                    };
                    let path = DavPath {
                        path: resource.container_name().unwrap().to_string(),
                        parent_id: None,
                        hierarchy_seq: 1,
                        resource_idx: cache.resources.len(),
                    };

                    cache.size += (std::mem::size_of::<DavPath>()
                        + std::mem::size_of::<DavResource>()
                        + (path.path.len()) * 2) as u64;
                    cache.paths.insert(path);
                    cache.resources.push(resource);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if cache.paths.is_empty() {
            if is_first_check {
                if is_calendar {
                    server
                        .create_default_calendar(access_token, account_id, &name)
                        .await?;
                } else {
                    server
                        .create_default_addressbook(access_token, account_id, &name)
                        .await?;
                }
                is_first_check = false;
                continue;
            } else {
                return Ok(cache);
            }
        }

        let parent_range = cache.resources.len();
        server
            .archives(account_id, item_collection, &(), |document_id, archive| {
                let resource = if is_calendar {
                    resource_from_event(archive.unarchive::<CalendarEvent>()?, document_id)
                } else {
                    resource_from_card(archive.unarchive::<ContactCard>()?, document_id)
                };
                let resource_idx = cache.resources.len();

                for name in resource.child_names().unwrap_or_default().iter() {
                    if let Some(parent) =
                        cache.resources.get(..parent_range).and_then(|resources| {
                            resources.iter().find(|r| r.document_id == name.parent_id)
                        })
                    {
                        let path = DavPath {
                            path: format!("{}/{}", parent.container_name().unwrap(), name.name),
                            parent_id: Some(name.parent_id),
                            hierarchy_seq: 0,
                            resource_idx,
                        };

                        cache.size += (std::mem::size_of::<DavPath>()
                            + name.name.len()
                            + path.path.len()) as u64;
                        cache.paths.insert(path);
                    }
                }
                cache.size += std::mem::size_of::<DavResource>() as u64;
                cache.resources.push(resource);

                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;

        return Ok(cache);
    }
}

pub(super) async fn build_scheduling_resources(
    server: &Server,
    account_id: u32,
    update_lock: Arc<Semaphore>,
) -> trc::Result<DavResources> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::CalendarEventNotification.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    let name = server
        .store()
        .get_principal_name(account_id)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_else(|| format!("_{account_id}"));

    let item_ids = server
        .itip_ids(account_id)
        .await
        .caused_by(trc::location!())?;

    let mut cache = DavResources {
        base_path: format!(
            "{}/{}/",
            DavResourceName::Scheduling.base_path(),
            percent_encoding::utf8_percent_encode(&name, RFC_3986),
        ),
        paths: AHashSet::with_capacity((2 + item_ids.len()) as usize),
        resources: Vec::with_capacity((2 + item_ids.len()) as usize),
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        size: std::mem::size_of::<DavResources>() as u64,
        update_lock,
    };

    for (document_id, is_container) in item_ids
        .into_iter()
        .map(|document_id| (document_id, false))
        .chain([(SCHEDULE_INBOX_ID, true), (SCHEDULE_OUTBOX_ID, true)])
    {
        let path = path_from_scheduling(document_id, cache.resources.len(), is_container);
        cache.size += (std::mem::size_of::<DavPath>() + (path.path.len() * 2)) as u64
            + std::mem::size_of::<DavResource>() as u64;
        cache.paths.insert(path);
        cache
            .resources
            .push(resource_from_scheduling(document_id, is_container));
    }

    Ok(cache)
}

pub(super) fn build_simple_hierarchy(cache: &mut DavResources) {
    cache.paths = AHashSet::with_capacity(cache.resources.len());
    let name_idx = cache
        .resources
        .iter()
        .filter_map(|resource| {
            resource
                .container_name()
                .map(|name| (resource.document_id, name))
        })
        .collect::<AHashMap<_, _>>();

    for (resource_idx, resource) in cache.resources.iter().enumerate() {
        match &resource.data {
            DavResourceMetadata::Calendar { name, .. }
            | DavResourceMetadata::AddressBook { name, .. } => {
                let path = DavPath {
                    path: name.to_string(),
                    parent_id: None,
                    hierarchy_seq: 1,
                    resource_idx,
                };
                cache.size +=
                    (std::mem::size_of::<DavPath>() + name.len() + path.path.len()) as u64;
                cache.paths.insert(path);
            }
            DavResourceMetadata::CalendarEvent { names, .. }
            | DavResourceMetadata::ContactCard { names } => {
                for name in names {
                    if let Some(parent_name) = name_idx.get(&name.parent_id) {
                        let path = DavPath {
                            path: format!("{parent_name}/{}", name.name),
                            parent_id: Some(name.parent_id),
                            hierarchy_seq: 0,
                            resource_idx,
                        };
                        cache.size += (std::mem::size_of::<DavPath>()
                            + name.name.len()
                            + path.path.len()) as u64;
                        cache.paths.insert(path);
                    }
                }
            }
            _ => unreachable!(),
        }
        cache.size += std::mem::size_of::<DavResource>() as u64;
    }
}

pub(super) fn resource_from_calendar(calendar: &ArchivedCalendar, document_id: u32) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::Calendar {
            name: calendar.name.to_string(),
            acls: calendar
                .acls
                .iter()
                .map(|acl| AclGrant {
                    account_id: acl.account_id.to_native(),
                    grants: Bitmap::from(&acl.grants),
                })
                .collect(),
            preferences: calendar
                .preferences
                .iter()
                .map(|pref| TinyCalendarPreferences {
                    account_id: pref.account_id.to_native(),
                    flags: pref.flags.to_native(),
                    tz: pref.time_zone.tz().unwrap_or(Tz::UTC),
                })
                .collect(),
        },
    }
}

pub(super) fn resource_from_event(event: &ArchivedCalendarEvent, document_id: u32) -> DavResource {
    let (start, duration) = event.data.event_range().unwrap_or_default();
    DavResource {
        document_id,
        data: DavResourceMetadata::CalendarEvent {
            names: event
                .names
                .iter()
                .map(|name| DavName {
                    name: name.name.to_string(),
                    parent_id: name.parent_id.to_native(),
                })
                .collect(),
            start,
            duration,
        },
    }
}

pub(super) fn resource_from_scheduling(document_id: u32, is_container: bool) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::CalendarEventNotification {
            names: if !is_container {
                [DavName {
                    name: format!("{document_id}.ics"),
                    parent_id: SCHEDULE_INBOX_ID,
                }]
                .into_iter()
                .collect()
            } else {
                Default::default()
            },
        },
    }
}

pub(super) fn path_from_scheduling(
    document_id: u32,
    resource_idx: usize,
    is_container: bool,
) -> DavPath {
    if is_container {
        DavPath {
            path: if document_id == SCHEDULE_INBOX_ID {
                "inbox".to_string()
            } else {
                "outbox".to_string()
            },
            parent_id: None,
            hierarchy_seq: 1,
            resource_idx,
        }
    } else {
        DavPath {
            path: format!("inbox/{document_id}.ics"),
            parent_id: Some(SCHEDULE_INBOX_ID),
            hierarchy_seq: 0,
            resource_idx,
        }
    }
}

pub(super) fn resource_from_addressbook(
    book: &ArchivedAddressBook,
    document_id: u32,
) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::AddressBook {
            name: book.name.to_string(),
            acls: book
                .acls
                .iter()
                .map(|acl| AclGrant {
                    account_id: acl.account_id.to_native(),
                    grants: Bitmap::from(&acl.grants),
                })
                .collect(),
        },
    }
}

pub(super) fn resource_from_card(card: &ArchivedContactCard, document_id: u32) -> DavResource {
    DavResource {
        document_id,
        data: DavResourceMetadata::ContactCard {
            names: card
                .names
                .iter()
                .map(|name| DavName {
                    name: name.name.to_string(),
                    parent_id: name.parent_id.to_native(),
                })
                .collect(),
        },
    }
}
