/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderKind, FolderRef, QuotaOwner,
    account::{
        ExchangeAccount, ExchangeAccountStore, ExchangeCounter, MAX_UPDATE_ATTEMPTS,
        bump_objects_epoch, merge_exchange_account,
    },
    account_key, exchange_key, exchange_range, fai_key_tail,
    folder::{
        ArchivedVirtualFolder, FaiMessage, FolderStore, TOMBSTONE_HORIZON_ID, VirtualFolder,
        VirtualFolderNext, VirtualFolderWrite, purge_virtual_tombstones, tombstone_change,
    },
    key_tail,
    object::ExchangeObject,
};
use crate::cache::last_change_ids;
use ahash::AHashMap;
use common::Server;
use store::{
    Deserialize, IterateParams, U16_LEN, U32_LEN, ValueKey,
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, BatchBuilder, ValueClass,
        assert::{AssertValue, ToAssertValue},
        metadata::{ExchangeClass, ExchangeFolder},
    },
};
use trc::AddContext;
use types::collection::Collection;

struct SweepRow {
    collection: Collection,
    document_id: u32,
    class: ExchangeClass,
    size: i64,
    assert: Option<AssertValue>,
    owner: Option<(Collection, u32)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VirtualParent {
    Virtual(u32),
    Stored(Collection, u32),
    Fixed,
}

enum VirtualRoot {
    Stored(Collection, u32),
    Missing,
    Fixed,
}

pub trait ExchangeCleanup: Sync + Send {
    fn purge_exchange_account(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn existing_documents(
        &self,
        account_id: u32,
        collection: Collection,
        candidates: &RoaringBitmap,
    ) -> impl Future<Output = trc::Result<RoaringBitmap>> + Send;
}

impl ExchangeCleanup for Server {
    async fn purge_exchange_account(&self, account_id: u32) -> trc::Result<()> {
        let Some(account) = self.exchange_account(account_id).await? else {
            return Ok(());
        };
        let account = account.deserialize::<ExchangeAccount>()?;
        purge_virtual_tombstones(self, account_id).await?;
        let change_ids = last_change_ids(self, account_id).await?;
        let logs_moved = change_ids != account.swept;
        let owners_moved = logs_moved || account.next_change != account.swept_change;
        let change_mark = account.next_change;
        let is_dead_slot = |slot: u16| {
            slot < account.next_device_slot
                && !account.devices.iter().any(|device| device.slot == slot)
        };

        let mut rows = Vec::new();
        let mut virtual_rows = Vec::new();
        let mut fai_tombstones = Vec::new();
        for class in [ExchangeClass::Object, ExchangeClass::Alias]
            .into_iter()
            .filter(|_| logs_moved)
        {
            let (from, to) = exchange_range(account_id, class);
            self.store()
                .iterate(IterateParams::new(from, to).no_values(), |key, _| {
                    let (collection, document_id) = key_tail(key)?;
                    let collection = Collection::from(collection);
                    rows.push(SweepRow {
                        collection,
                        document_id,
                        class,
                        size: 0,
                        assert: None,
                        owner: Some((collection, document_id)),
                    });
                    Ok(true)
                })
                .await
                .caused_by(trc::location!())?;
        }

        if owners_moved {
            self.store()
                .iterate(
                    IterateParams::new(
                        account_key(account_id, fai(0, 0, 0)),
                        account_key(account_id, fai(u8::MAX, u32::MAX, u32::MAX)),
                    ),
                    |key, value| {
                        let (folder, id) = fai_key_tail(key)?;
                        if let Some(folder_ref) = FolderRef::from_stored(folder) {
                            let archive =
                                <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                            let row = SweepRow {
                                collection: Collection::Principal,
                                document_id: 0,
                                class: ExchangeClass::Fai { folder, id },
                                size: archive.unarchive::<FaiMessage>()?.quota_size(),
                                assert: Some(archive.to_assert_value()),
                                owner: folder_ref
                                    .collection()
                                    .map(|collection| (collection, folder.id)),
                            };
                            if row.owner.is_some() {
                                rows.push(row);
                            } else {
                                virtual_rows.push((folder.id, row));
                            }
                        }
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
            self.store()
                .iterate(
                    IterateParams::new(
                        account_key(account_id, fai_tombstone(0, 0, 0)),
                        account_key(account_id, fai_tombstone(u8::MAX, u32::MAX, u32::MAX)),
                    ),
                    |key, value| {
                        let (folder, id) = fai_key_tail(key)?;
                        fai_tombstones.push((folder, id, tombstone_change(key, value)?));
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }

        self.store()
            .iterate(
                IterateParams::new(
                    account_key(account_id, ExchangeClass::Device { slot: 0 }),
                    account_key(account_id, ExchangeClass::Device { slot: u16::MAX }),
                )
                .no_values(),
                |key, _| {
                    let slot = key
                        .last_chunk::<U16_LEN>()
                        .map(|slot| u16::from_be_bytes(*slot))
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                    if is_dead_slot(slot) {
                        rows.push(SweepRow {
                            collection: Collection::Principal,
                            document_id: 0,
                            class: ExchangeClass::Device { slot },
                            size: 0,
                            assert: None,
                            owner: None,
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        self.store()
            .iterate(
                IterateParams::new(
                    account_key(account_id, device_folder(0, 0, 0)),
                    account_key(account_id, device_folder(u16::MAX, u8::MAX, u32::MAX)),
                )
                .no_values(),
                |key, _| {
                    let (slot, folder) = key
                        .len()
                        .checked_sub(U16_LEN + U32_LEN + 1)
                        .and_then(|start| key.get(start..))
                        .and_then(|tail| tail.split_first_chunk::<U16_LEN>())
                        .and_then(|(slot, rest)| {
                            let (kind, folder) = rest.split_first()?;
                            let folder = folder.first_chunk::<U32_LEN>()?;
                            Some((
                                u16::from_be_bytes(*slot),
                                ExchangeFolder {
                                    kind: *kind,
                                    id: u32::from_be_bytes(*folder),
                                },
                            ))
                        })
                        .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                    let mut row = SweepRow {
                        collection: Collection::Principal,
                        document_id: 0,
                        class: ExchangeClass::DeviceFolder { slot, folder },
                        size: 0,
                        assert: None,
                        owner: None,
                    };
                    if !is_dead_slot(slot) {
                        match FolderRef::from_stored(folder).map(FolderRef::collection) {
                            Some(Some(collection)) if owners_moved => {
                                row.owner = Some((collection, folder.id));
                            }
                            Some(None) if owners_moved => {
                                virtual_rows.push((folder.id, row));
                                return Ok(true);
                            }
                            _ => return Ok(true),
                        }
                    }
                    rows.push(row);
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let mut virtuals = Vec::new();
        if owners_moved {
            self.virtual_folders(account_id, |id, folder| {
                virtuals.push((id, VirtualParent::of(folder)));
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        }

        let roots = virtuals
            .iter()
            .map(|&(id, _)| (id, virtual_root(&virtuals, id)))
            .collect::<Vec<_>>();
        let mut candidates: AHashMap<Collection, RoaringBitmap> = AHashMap::new();
        for (collection, document_id) in rows
            .iter()
            .filter_map(|row| row.owner)
            .chain(roots.iter().filter_map(|(_, root)| match root {
                VirtualRoot::Stored(collection, document_id) => Some((*collection, *document_id)),
                VirtualRoot::Missing | VirtualRoot::Fixed => None,
            }))
            .chain(fai_tombstones.iter().filter_map(|(folder, _, _)| {
                FolderRef::from_stored(*folder)
                    .and_then(FolderRef::collection)
                    .map(|collection| (collection, folder.id))
            }))
        {
            candidates
                .entry(collection)
                .or_default()
                .insert(document_id);
        }
        let mut existing = AHashMap::with_capacity(candidates.len());
        for (collection, documents) in candidates {
            existing.insert(
                collection,
                self.existing_documents(account_id, collection, &documents)
                    .await?,
            );
        }

        let exists = |collection: Collection, document_id: u32| {
            existing
                .get(&collection)
                .is_some_and(|documents| documents.contains(document_id))
        };
        rows.retain(|row| {
            !row.owner
                .is_some_and(|(collection, document_id)| exists(collection, document_id))
        });
        let mut dead_virtuals = roots
            .into_iter()
            .filter_map(|(id, root)| match root {
                VirtualRoot::Missing => Some(id),
                VirtualRoot::Stored(collection, document_id) => {
                    (!exists(collection, document_id)).then_some(id)
                }
                VirtualRoot::Fixed => None,
            })
            .collect::<Vec<_>>();
        let objects = rows.partition_point(|row| row.class == ExchangeClass::Object);
        if let Some(orphans) = rows.get_mut(..objects)
            && !orphans.is_empty()
        {
            let ranges = orphans
                .iter()
                .map(|row| {
                    let key = exchange_key(
                        account_id,
                        row.collection,
                        row.document_id,
                        ExchangeClass::Object,
                    );
                    IterateParams::new(key.clone(), key)
                })
                .collect::<Vec<_>>();
            self.store()
                .iterate_many(ranges, |key, value| {
                    let (collection, document_id) = key_tail(key)?;
                    if let Ok(idx) = orphans
                        .binary_search_by_key(&(collection, document_id), |row| {
                            (u8::from(row.collection), row.document_id)
                        })
                        && let Some(row) = orphans.get_mut(idx)
                    {
                        let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                        row.size = archive.unarchive::<ExchangeObject>()?.quota_size();
                        row.assert = Some(archive.to_assert_value());
                    }
                    Ok(true)
                })
                .await
                .caused_by(trc::location!())?;
        }

        let owner = QuotaOwner::new(
            account_id,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            self.account(account_id)
                .await
                .caused_by(trc::location!())?
                .id_tenant,
            // SPDX-SnippetEnd
        );
        let mut change_mark = Some(change_mark);
        if !dead_virtuals.is_empty()
            && !tombstone_virtuals(self, account_id, owner, &virtuals, &dead_virtuals).await?
        {
            dead_virtuals.clear();
            change_mark = None;
        }
        let virtual_gone = |folder_id: u32| {
            dead_virtuals.binary_search(&folder_id).is_ok()
                || virtuals
                    .binary_search_by_key(&folder_id, |&(id, _)| id)
                    .is_err()
        };
        rows.extend(
            virtual_rows
                .into_iter()
                .filter_map(|(folder_id, row)| virtual_gone(folder_id).then_some(row)),
        );
        let mut batch = BatchBuilder::new();
        let max_history = self.core.email.changes_max_history;
        let mut oldest = Vec::new();
        for tombstones in fai_tombstones.chunk_by(|(a, _, _), (b, _, _)| a == b) {
            let Some(&(folder, _, _)) = tombstones.first() else {
                continue;
            };
            let gone = match FolderRef::from_stored(folder).map(FolderRef::collection) {
                Some(Some(collection)) => !exists(collection, folder.id),
                Some(None) => virtual_gone(folder.id),
                None => false,
            };
            let clear = |&(folder, id, _): &(ExchangeFolder, u32, u64)| SweepRow {
                collection: Collection::Principal,
                document_id: 0,
                class: ExchangeClass::FaiTombstone { folder, id },
                size: 0,
                assert: None,
                owner: None,
            };
            if gone {
                rows.extend(tombstones.iter().map(clear));
                continue;
            }
            let (horizon, deleted) = match tombstones.split_first() {
                Some((&(_, TOMBSTONE_HORIZON_ID, horizon), deleted)) => (horizon, deleted),
                _ => (0, tombstones),
            };
            let Some(excess) = max_history
                .and_then(|max_history| deleted.len().checked_sub(max_history))
                .filter(|excess| *excess > 0)
            else {
                continue;
            };
            oldest.clear();
            oldest.extend(deleted);
            oldest.select_nth_unstable_by_key(excess - 1, |&(_, _, change)| change);
            let purged = oldest.get(..excess).unwrap_or_default();
            let horizon = purged
                .iter()
                .fold(horizon, |horizon, &(_, _, change)| horizon.max(change));
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .set(
                    ExchangeClass::FaiTombstone {
                        folder,
                        id: TOMBSTONE_HORIZON_ID,
                    },
                    horizon.to_be_bytes().to_vec(),
                );
            rows.extend(purged.iter().map(clear));
        }
        let mut refund = 0i64;
        let mut cleared_objects = false;
        for row in rows {
            batch
                .with_account_id(account_id)
                .with_collection(row.collection)
                .with_document(row.document_id);
            if let Some(assert) = row.assert {
                batch.assert_value(row.class, assert);
            }
            batch.clear(row.class);
            refund += row.size;
            cleared_objects |= matches!(row.class, ExchangeClass::Object | ExchangeClass::Alias);
            if batch.is_large_batch()
                && !commit_sweep(self, &mut batch, owner, &mut refund, &mut cleared_objects).await?
            {
                return Ok(());
            }
        }
        if owners_moved && let Some(change_mark) = change_mark {
            merge_exchange_account(&mut batch, account_id, move |account| {
                for (swept, change_id) in account.swept.iter_mut().zip(change_ids) {
                    *swept = (*swept).max(change_id);
                }
                account.swept_change = account.swept_change.max(change_mark);
            });
        }
        if !batch.is_empty() {
            commit_sweep(self, &mut batch, owner, &mut refund, &mut cleared_objects).await?;
        }
        Ok(())
    }

    async fn existing_documents(
        &self,
        account_id: u32,
        collection: Collection,
        candidates: &RoaringBitmap,
    ) -> trc::Result<RoaringBitmap> {
        let mut existing = RoaringBitmap::new();
        if candidates.is_empty() {
            return Ok(existing);
        }
        let ranges = candidates
            .iter()
            .map(|document_id| {
                let key = ValueKey::<ValueClass>::archive(account_id, collection, document_id);
                IterateParams::new(key.clone(), key).no_values()
            })
            .collect::<Vec<_>>();
        self.store()
            .iterate_many(ranges, |key, _| {
                let document_id = key
                    .last_chunk::<U32_LEN>()
                    .map(|id| u32::from_be_bytes(*id))
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                existing.insert(document_id);
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        Ok(existing)
    }
}

async fn commit_sweep(
    server: &Server,
    batch: &mut BatchBuilder,
    owner: QuotaOwner,
    refund: &mut i64,
    cleared_objects: &mut bool,
) -> trc::Result<bool> {
    let refund = std::mem::take(refund);
    if refund != 0 {
        owner.add(batch, -refund);
    }
    if std::mem::take(cleared_objects) {
        bump_objects_epoch(batch, owner.account_id);
    }
    let result = server.store().write_batch(batch).await;
    *batch = BatchBuilder::new();
    match result {
        Ok(_) => Ok(true),
        Err(err) if err.is_assertion_failure() => Ok(false),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

impl VirtualParent {
    fn of(folder: &ArchivedVirtualFolder) -> Self {
        if folder.search.is_some() {
            return VirtualParent::Fixed;
        }
        let parent_id = folder.parent.id.to_native();
        match FolderKind::from_code(folder.parent.kind) {
            Some(FolderKind::Virtual) => VirtualParent::Virtual(parent_id),
            Some(kind) => FolderRef {
                kind,
                id: parent_id,
            }
            .collection()
            .map_or(VirtualParent::Fixed, |collection| {
                VirtualParent::Stored(collection, parent_id)
            }),
            None => VirtualParent::Fixed,
        }
    }
}

async fn tombstone_virtuals(
    server: &Server,
    account_id: u32,
    owner: QuotaOwner,
    virtuals: &[(u32, VirtualParent)],
    dead: &[u32],
) -> trc::Result<bool> {
    for _ in 0..=MAX_UPDATE_ATTEMPTS {
        let ranges = dead
            .iter()
            .map(|&id| {
                let key = account_key(account_id, ExchangeClass::Folder { id });
                IterateParams::new(key.clone(), key)
            })
            .collect::<Vec<_>>();
        let mut previous = Vec::with_capacity(dead.len());
        let mut moved = false;
        server
            .store()
            .iterate_many(ranges, |key, value| {
                let (_, id) = key_tail(key)?;
                let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                let parent = VirtualParent::of(archive.unarchive::<VirtualFolder>()?);
                moved |= virtuals
                    .binary_search_by_key(&id, |&(id, _)| id)
                    .ok()
                    .and_then(|idx| virtuals.get(idx))
                    .is_none_or(|&(_, scanned)| scanned != parent);
                previous.push((id, archive));
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        if moved {
            return Ok(false);
        }
        if previous.is_empty() {
            return Ok(true);
        }
        let reservation = server
            .reserve_exchange_ids(account_id, [(ExchangeCounter::Change, 1)])
            .await?;
        let [change] = reservation.ids();
        let mut batch = BatchBuilder::new();
        let reserved = reservation.seal(&mut batch);
        for (id, previous) in &previous {
            VirtualFolderWrite {
                owner,
                id: *id,
                previous: Some(previous),
                next: VirtualFolderNext::Deleted { change },
                max_size: server.core.exchange.max_object_size,
            }
            .build(&mut batch)?;
        }
        match server.store().write_batch(&mut batch).await {
            Ok(_) => return Ok(true),
            Err(err) if err.is_assertion_failure() => {
                if !reserved.is_stale(server).await? {
                    return Ok(false);
                }
            }
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
    }
    Ok(false)
}

fn virtual_root(folders: &[(u32, VirtualParent)], id: u32) -> VirtualRoot {
    let mut next = id;
    for _ in 0..folders.len() {
        let Ok(idx) = folders.binary_search_by_key(&next, |&(id, _)| id) else {
            return VirtualRoot::Missing;
        };
        match folders.get(idx).map(|&(_, parent)| parent) {
            Some(VirtualParent::Virtual(parent)) => next = parent,
            Some(VirtualParent::Stored(collection, document_id)) => {
                return VirtualRoot::Stored(collection, document_id);
            }
            Some(VirtualParent::Fixed) | None => return VirtualRoot::Fixed,
        }
    }
    VirtualRoot::Fixed
}

const fn fai(kind: u8, folder: u32, id: u32) -> ExchangeClass {
    ExchangeClass::Fai {
        folder: ExchangeFolder { kind, id: folder },
        id,
    }
}

const fn fai_tombstone(kind: u8, folder: u32, id: u32) -> ExchangeClass {
    ExchangeClass::FaiTombstone {
        folder: ExchangeFolder { kind, id: folder },
        id,
    }
}

const fn device_folder(slot: u16, kind: u8, id: u32) -> ExchangeClass {
    ExchangeClass::DeviceFolder {
        slot,
        folder: ExchangeFolder { kind, id },
    }
}
