/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ChunkAccumulator, GroupwareCache};
use crate::{
    DavResourceName,
    calendar::{
        ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarEventNotification, Calendar,
        CalendarEvent, CalendarEventNotification, SCHEDULE_INBOX_ID, SCHEDULE_OUTBOX_ID,
    },
    contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard},
    encode_path_segment,
};
use calcard::common::timezone::Tz;
use common::{
    ArenaRef, DavName, DavPath, GroupwareResource, GroupwareResourceMetadata, GroupwareResources, NO_ID, PathIndex,
    ResourceStore, Server, TinyCalendarPreferences, UpdateLock,
    storage::dav::{CONTAINER_FLAG, ResourceChunkBuilder},
};
use std::sync::Arc;
use store::ahash::AHashMap;
use trc::AddContext;
use types::{
    acl::AclGrant,
    collection::{Collection, SyncCollection},
    field::Field,
};
use utils::map::bitmap::Bitmap;

pub(super) async fn build_calcard_resources(
    server: &Server,
    access_account_id: u32,
    account_id: u32,
    sync_collection: SyncCollection,
    container_collection: Collection,
    item_collection: Collection,
    update_lock: Arc<UpdateLock>,
) -> trc::Result<GroupwareResources> {
    let is_calendar = matches!(sync_collection, SyncCollection::Calendar);
    let owner_account_info = server.account(account_id).await?;
    let access_account_info = if account_id == access_account_id {
        owner_account_info.clone()
    } else {
        server.account(access_account_id).await?
    };
    let base_path =
        DavResourceName::from(sync_collection).account_base_path(owner_account_info.name());

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
        update_lock.set_revision(last_change_id);

        let mut containers = ChunkAccumulator::default();
        server
            .archives(
                account_id,
                container_collection,
                Field::ARCHIVE,
                &(),
                |document_id, archive| {
                    let etag = archive.version.hash().unwrap_or_default();
                    let builder = containers.current();
                    if is_calendar {
                        push_calendar(builder, archive.unarchive::<Calendar>()?, document_id, etag);
                    } else {
                        push_addressbook(
                            builder,
                            archive.unarchive::<AddressBook>()?,
                            document_id,
                            etag,
                        );
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if containers.is_empty() {
            if is_first_check {
                if is_calendar {
                    server
                        .create_default_calendar(&access_account_info, &owner_account_info)
                        .await?;
                } else {
                    server
                        .create_default_addressbook(&access_account_info, &owner_account_info)
                        .await?;
                }
                is_first_check = false;
                continue;
            } else {
                let mut cache = GroupwareResources {
                    base_path,
                    paths: Default::default(),
                    resources: ResourceStore::from_sorted(containers.finish(), Vec::new(), false),
                    item_change_id: last_change_id,
                    container_change_id: last_change_id,
                    highest_change_id: last_change_id,
                    size: 0,
                    update_lock,
                    verification: Default::default(),
                };
                cache.recompute_size();
                return Ok(cache);
            }
        }

        let mut items = ChunkAccumulator::default();
        server
            .archives(
                account_id,
                item_collection,
                Field::ARCHIVE,
                &(),
                |document_id, archive| {
                    let builder = items.current();
                    if is_calendar {
                        push_event(builder, archive.unarchive::<CalendarEvent>()?, document_id);
                    } else {
                        push_card(builder, archive.unarchive::<ContactCard>()?, document_id);
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let resources = ResourceStore::from_sorted(containers.finish(), items.finish(), false);
        let paths = build_calcard_paths(&resources);
        let mut cache = GroupwareResources {
            base_path,
            paths: Arc::new(paths),
            resources,
            item_change_id: last_change_id,
            container_change_id: last_change_id,
            highest_change_id: last_change_id,
            size: 0,
            update_lock,
            verification: Default::default(),
        };
        cache.recompute_size();
        return Ok(cache);
    }
}

pub(super) fn build_calcard_paths(resources: &ResourceStore) -> PathIndex {
    let mut names: AHashMap<u32, String> = AHashMap::with_capacity(16);
    for resource in resources.iter() {
        if resource.is_container()
            && let Some(name) = resource.container_name()
        {
            names.insert(
                resource.document_id(),
                encode_path_segment(name).into_owned(),
            );
        }
    }

    let mut entries: Vec<(String, DavPath)> = Vec::with_capacity(resources.len());
    for resource in resources.iter() {
        if resource.is_container() {
            if let Some(name) = names.get(&resource.document_id()) {
                entries.push((
                    name.clone(),
                    DavPath {
                        path: ArenaRef::default(),
                        parent_id: NO_ID,
                        hierarchy_seq: 1 | CONTAINER_FLAG,
                        document_id: resource.document_id(),
                    },
                ));
            }
        } else {
            for name in resource.child_names() {
                if let Some(parent) = names.get(&name.parent_id) {
                    entries.push((
                        format!(
                            "{parent}/{}",
                            encode_path_segment(resource.child_name_at(name))
                        ),
                        DavPath {
                            path: ArenaRef::default(),
                            parent_id: name.parent_id,
                            hierarchy_seq: 0,
                            document_id: resource.document_id(),
                        },
                    ));
                }
            }
        }
    }

    PathIndex::pack(entries)
}

pub(super) async fn build_scheduling_resources(
    server: &Server,
    account_id: u32,
    update_lock: Arc<UpdateLock>,
) -> trc::Result<GroupwareResources> {
    let last_change_id = server
        .core
        .storage
        .data
        .get_last_change_id(account_id, SyncCollection::CalendarEventNotification.into())
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    let account_info = server.account(account_id).await?;
    update_lock.set_revision(last_change_id);

    let mut containers = ChunkAccumulator::default();
    for document_id in [SCHEDULE_OUTBOX_ID, SCHEDULE_INBOX_ID] {
        push_scheduling_container(containers.current(), document_id);
    }

    let mut items = ChunkAccumulator::default();
    server
        .archives(
            account_id,
            Collection::CalendarEventNotification,
            Field::ARCHIVE,
            &(),
            |document_id, archive| {
                push_scheduling(
                    items.current(),
                    archive.unarchive::<CalendarEventNotification>()?,
                    document_id,
                );
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let resources = ResourceStore::from_sorted(containers.finish(), items.finish(), false);
    let paths = build_scheduling_paths(&resources);
    let mut cache = GroupwareResources {
        base_path: DavResourceName::Scheduling.account_base_path(account_info.name()),
        paths: Arc::new(paths),
        resources,
        item_change_id: last_change_id,
        container_change_id: last_change_id,
        highest_change_id: last_change_id,
        size: 0,
        update_lock,
        verification: Default::default(),
    };
    cache.recompute_size();
    Ok(cache)
}

pub(super) fn build_scheduling_paths(resources: &ResourceStore) -> PathIndex {
    let mut entries: Vec<(String, DavPath)> = Vec::with_capacity(resources.len());
    for resource in resources.iter() {
        if resource.is_container() {
            entries.push((
                if resource.document_id() == SCHEDULE_INBOX_ID {
                    "inbox".to_string()
                } else {
                    "outbox".to_string()
                },
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: NO_ID,
                    hierarchy_seq: 1 | CONTAINER_FLAG,
                    document_id: resource.document_id(),
                },
            ));
        } else {
            entries.push((
                format!("inbox/{}.ics", resource.document_id()),
                DavPath {
                    path: ArenaRef::default(),
                    parent_id: SCHEDULE_INBOX_ID,
                    hierarchy_seq: 0,
                    document_id: resource.document_id(),
                },
            ));
        }
    }
    PathIndex::pack(entries)
}

pub(super) fn push_calendar(
    builder: &mut ResourceChunkBuilder,
    calendar: &ArchivedCalendar,
    document_id: u32,
    etag: u32,
) {
    let name = builder.push_str(calendar.name.as_str());
    let acls = builder.push_acls(
        &calendar
            .acls
            .iter()
            .map(|acl| AclGrant {
                account_id: acl.account_id.to_native(),
                grants: Bitmap::from(&acl.grants),
            })
            .collect::<Vec<_>>(),
    );
    let preferences = builder.push_prefs(
        &calendar
            .preferences
            .iter()
            .map(|pref| TinyCalendarPreferences {
                account_id: pref.account_id.to_native(),
                flags: pref.flags.to_native(),
                tz: pref.time_zone.tz().unwrap_or(Tz::UTC),
            })
            .collect::<Vec<_>>(),
    );
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::Calendar {
            name,
            acls,
            preferences,
            etag,
        },
    });
}

pub(super) fn push_addressbook(
    builder: &mut ResourceChunkBuilder,
    book: &ArchivedAddressBook,
    document_id: u32,
    etag: u32,
) {
    let name = builder.push_str(book.name.as_str());
    let acls = builder.push_acls(
        &book
            .acls
            .iter()
            .map(|acl| AclGrant {
                account_id: acl.account_id.to_native(),
                grants: Bitmap::from(&acl.grants),
            })
            .collect::<Vec<_>>(),
    );
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::AddressBook { name, acls, etag },
    });
}

pub(super) fn push_event(
    builder: &mut ResourceChunkBuilder,
    event: &ArchivedCalendarEvent,
    document_id: u32,
) {
    let created_at = event.created.to_native();
    let names = builder.push_names(
        &event
            .names
            .iter()
            .map(|name| DavName {
                name: name.name.to_string(),
                parent_id: name.parent_id.to_native(),
            })
            .collect::<Vec<_>>(),
    );
    let uid = builder.push_str(truncate_uid(event.uid.as_str()));
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::CalendarEvent {
            names,
            start: event.start.to_native(),
            duration: event.duration.to_native(),
            created_at,
            modified_at: event
                .modified
                .to_native()
                .saturating_sub(created_at)
                .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            uid,
            etag: event.etag.to_native(),
        },
    });
}

pub(super) fn push_card(
    builder: &mut ResourceChunkBuilder,
    card: &ArchivedContactCard,
    document_id: u32,
) {
    let created_at = card.created.to_native();
    let names = builder.push_names(
        &card
            .names
            .iter()
            .map(|name| DavName {
                name: name.name.to_string(),
                parent_id: name.parent_id.to_native(),
            })
            .collect::<Vec<_>>(),
    );
    let uid = builder.push_str(truncate_uid(card.uid.as_str()));
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::ContactCard {
            names,
            created_at,
            modified_at: card
                .modified
                .to_native()
                .saturating_sub(created_at)
                .clamp(i32::MIN as i64, i32::MAX as i64) as i32,
            uid,
            etag: card.etag.to_native(),
        },
    });
}

fn truncate_uid(uid: &str) -> &str {
    if uid.len() <= 255 {
        uid
    } else {
        &uid[..uid.ceil_char_boundary(255)]
    }
}

pub(super) fn push_scheduling(
    builder: &mut ResourceChunkBuilder,
    event: &ArchivedCalendarEventNotification,
    document_id: u32,
) {
    let names = builder.push_names(&[DavName {
        name: format!("{document_id}.ics"),
        parent_id: SCHEDULE_INBOX_ID,
    }]);
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::CalendarEventNotification {
            names,
            created_at: event.created.to_native(),
            event_id: event
                .event_id
                .as_ref()
                .map(|v| v.to_native())
                .unwrap_or(u32::MAX),
            etag: event.etag.to_native(),
        },
    });
}

pub(super) fn push_scheduling_container(builder: &mut ResourceChunkBuilder, document_id: u32) {
    builder.records.push(GroupwareResource {
        document_id,
        data: GroupwareResourceMetadata::CalendarEventNotification {
            names: ArenaRef::default(),
            created_at: 0,
            event_id: u32::MAX,
            etag: 0,
        },
    });
}
