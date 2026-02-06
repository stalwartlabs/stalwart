/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, ipc::PushNotification};
use std::time::Duration;
use store::{
    IterateParams, Key, LogKey, SUBSPACE_LOGS, U64_LEN,
    write::{AnyClass, AssignedIds, BatchBuilder, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{
    collection::SyncCollection,
    type_state::{DataType, StateChange},
};
use utils::{map::bitmap::Bitmap, snowflake::SnowflakeIdGenerator};

impl Server {
    pub async fn commit_batch(&self, mut builder: BatchBuilder) -> trc::Result<AssignedIds> {
        let mut assigned_ids = AssignedIds::default();
        let mut commit_points = builder.commit_points();

        for commit_point in commit_points.iter() {
            let batch = builder.build_one(commit_point);
            assigned_ids
                .ids
                .extend(self.store().write(batch).await?.ids);
        }

        if let Some(changes) = builder.changes() {
            for (account_id, changed_collections) in changes {
                let mut state_change = StateChange::new(account_id);
                for changed_collection in changed_collections.changed_containers {
                    if let Some(data_type) = DataType::try_from_sync(changed_collection, true) {
                        state_change.set_change(data_type);
                    }
                }
                for changed_collection in changed_collections.changed_items {
                    if let Some(data_type) = DataType::try_from_sync(changed_collection, false) {
                        state_change.set_change(data_type);
                    }
                }
                if state_change.has_changes() {
                    self.broadcast_push_notification(PushNotification::StateChange(
                        state_change.with_change_id(assigned_ids.last_change_id(account_id)?),
                    ))
                    .await;
                }
                if let Some(change_id) = changed_collections.share_notification_id {
                    self.broadcast_push_notification(PushNotification::StateChange(StateChange {
                        account_id,
                        change_id,
                        types: Bitmap::from_iter([DataType::ShareNotification]),
                    }))
                    .await;
                }
            }
        }

        Ok(assigned_ids)
    }

    pub async fn delete_changes(
        &self,
        account_id: u32,
        max_entries: Option<usize>,
        max_duration: Option<Duration>,
    ) -> trc::Result<()> {
        if let Some(max_entries) = max_entries {
            for sync_collection in [
                SyncCollection::Email,
                SyncCollection::Thread,
                SyncCollection::Identity,
                SyncCollection::EmailSubmission,
                SyncCollection::SieveScript,
                SyncCollection::FileNode,
                SyncCollection::AddressBook,
                SyncCollection::Calendar,
                SyncCollection::CalendarEventNotification,
            ] {
                let collection = sync_collection.into();
                let from_key = LogKey {
                    account_id,
                    collection,
                    change_id: 0,
                };
                let to_key = LogKey {
                    account_id,
                    collection,
                    change_id: u64::MAX,
                };

                let mut first_change_id = 0;
                let mut num_changes = 0;

                self.store()
                    .iterate(
                        IterateParams::new(from_key, to_key)
                            .descending()
                            .no_values(),
                        |key, _| {
                            first_change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                            num_changes += 1;

                            Ok(num_changes <= max_entries)
                        },
                    )
                    .await
                    .caused_by(trc::location!())?;

                if num_changes > max_entries {
                    self.store()
                        .delete_range(
                            LogKey {
                                account_id,
                                collection,
                                change_id: 0,
                            },
                            LogKey {
                                account_id,
                                collection,
                                change_id: first_change_id,
                            },
                        )
                        .await
                        .caused_by(trc::location!())?;

                    // Delete vanished items
                    if let Some(vanished_collection) =
                        sync_collection.vanished_collection().map(u8::from)
                    {
                        self.store()
                            .delete_range(
                                LogKey {
                                    account_id,
                                    collection: vanished_collection,
                                    change_id: 0,
                                },
                                LogKey {
                                    account_id,
                                    collection: vanished_collection,
                                    change_id: first_change_id,
                                },
                            )
                            .await
                            .caused_by(trc::location!())?;
                    }

                    // Write truncation entry for cache
                    let mut batch = BatchBuilder::new();
                    batch.with_account_id(account_id).set(
                        ValueClass::Any(AnyClass {
                            subspace: SUBSPACE_LOGS,
                            key: LogKey {
                                account_id,
                                collection,
                                change_id: first_change_id,
                            }
                            .serialize(0),
                        }),
                        Vec::new(),
                    );
                    self.store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
            }
        }

        if let Some(max_duration) = max_duration {
            self.store()
                .delete_range(
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: 0,
                    },
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: SnowflakeIdGenerator::from_duration(max_duration)
                            .unwrap_or_default(),
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }

    #[inline(always)]
    pub fn generate_snowflake_id(&self) -> u64 {
        self.inner.data.jmap_id_gen.generate()
    }
}
