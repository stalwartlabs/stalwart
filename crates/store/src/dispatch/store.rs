/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DocumentSet;
use crate::{
    Deserialize, IterateParams, Key, QueryResult, SUBSPACE_BLOB_EXTRA, SUBSPACE_COUNTER,
    SUBSPACE_INDEXES, SUBSPACE_LOGS, Store, U32_LEN, Value, ValueKey,
    write::{
        AnyClass, AnyKey, AssignedIds, Batch, BatchBuilder, Operation, ReportClass, ValueClass,
        ValueOp,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use compact_str::ToCompactString;
use std::{ops::Range, time::Instant};
use trc::{AddContext, StoreEvent};
use types::collection::Collection;

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_value(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_value(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_value(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_value(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_value(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.get_value(key).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let start_time = Instant::now();
        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.iterate(params, cb).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.iterate(params, cb).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.iterate(params, cb).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.iterate(params, cb).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.iterate(params, cb).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::DataIterate),
            Elapsed = start_time.elapsed(),
        );

        result
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_counter(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_counter(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_counter(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_counter(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_counter(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.get_counter(key).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    #[allow(unreachable_patterns)]
    #[allow(unused_variables)]
    pub async fn sql_query<T: QueryResult + std::fmt::Debug>(
        &self,
        query: &str,
        params: Vec<Value<'_>>,
    ) -> trc::Result<T> {
        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.sql_query(query, &params).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.sql_query(query, &params).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.sql_query(query, &params).await,
            _ => Err(trc::StoreEvent::NotSupported.into_err()),
        };

        trc::event!(
            Store(trc::StoreEvent::SqlQuery),
            Details = query.to_compact_string(),
            Value = params.as_slice(),
            Result = &result,
        );

        result.caused_by(trc::location!())
    }

    pub async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        let start_time = Instant::now();
        let ops = batch.ops.len();

        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.write(batch).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.write(batch).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.write(batch).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.write(batch).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.write(batch).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.write(batch).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        };

        trc::event!(
            Store(StoreEvent::DataWrite),
            Elapsed = start_time.elapsed(),
            Total = ops,
        );

        result
    }

    pub async fn assign_document_ids(
        &self,
        account_id: u32,
        collection: Collection,
        num_ids: u64,
    ) -> trc::Result<u32> {
        // Increment UID next
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(collection)
            .add_and_get(ValueClass::DocumentId, num_ids as i64);
        self.write(batch.build_all()).await.and_then(|v| {
            v.last_counter_id().map(|id| {
                debug_assert!(id >= num_ids as i64, "{} < {}", id, num_ids);
                id as u32
            })
        })
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        // Delete expired reports
        let now = now();
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Tls {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;
        self.delete_range(
            ValueKey::from(ValueClass::Report(ReportClass::Arf { id: 0, expires: 0 })),
            ValueKey::from(ValueClass::Report(ReportClass::Arf {
                id: u64::MAX,
                expires: now,
            })),
        )
        .await
        .caused_by(trc::location!())?;

        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.purge_store().await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.purge_store().await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.purge_store().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.purge_store().await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.purge_store().await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.purge_store().await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_range(from, to).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_range(from, to).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_range(from, to).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.delete_range(from, to).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_documents(
        &self,
        subspace: u8,
        account_id: u32,
        collection: u8,
        collection_offset: Option<usize>,
        document_ids: &impl DocumentSet,
    ) -> trc::Result<()> {
        // Serialize keys
        let (from_key, to_key) = if collection_offset.is_some() {
            (
                KeySerializer::new(U32_LEN + 2)
                    .write(account_id)
                    .write(collection),
                KeySerializer::new(U32_LEN + 2)
                    .write(account_id)
                    .write(collection + 1),
            )
        } else {
            (
                KeySerializer::new(U32_LEN).write(account_id),
                KeySerializer::new(U32_LEN).write(account_id + 1),
            )
        };

        // Find keys to delete
        let mut delete_keys = Vec::new();
        self.iterate(
            IterateParams::new(
                AnyKey {
                    subspace,
                    key: from_key.finalize(),
                },
                AnyKey {
                    subspace,
                    key: to_key.finalize(),
                },
            )
            .no_values(),
            |key, _| {
                if collection_offset.is_none_or(|offset| {
                    key.get(key.len() - U32_LEN - offset).copied() == Some(collection)
                }) {
                    let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                    if document_ids.contains(document_id) {
                        delete_keys.push(key.to_vec());
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

        // Remove keys
        let mut batch = BatchBuilder::new();

        for key in delete_keys {
            if batch.is_large_batch() {
                self.write(std::mem::take(&mut batch).build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            batch.any_op(Operation::Value {
                class: ValueClass::Any(AnyClass { subspace, key }),
                op: ValueOp::Clear,
            });
        }

        if !batch.is_empty() {
            self.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn danger_destroy_account(&self, account_id: u32) -> trc::Result<()> {
        for subspace in [
            SUBSPACE_LOGS,
            SUBSPACE_INDEXES,
            SUBSPACE_COUNTER,
            SUBSPACE_BLOB_EXTRA,
        ] {
            self.delete_range(
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id).finalize(),
                },
                AnyKey {
                    subspace,
                    key: KeySerializer::new(U32_LEN).write(account_id + 1).finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        for (from_class, to_class) in [
            (ValueClass::Acl(account_id), ValueClass::Acl(account_id + 1)),
            (ValueClass::Property(0), ValueClass::Property(0)),
        ] {
            self.delete_range(
                ValueKey {
                    account_id,
                    collection: 0,
                    document_id: 0,
                    class: from_class,
                },
                ValueKey {
                    account_id: account_id + 1,
                    collection: 0,
                    document_id: 0,
                    class: to_class,
                },
            )
            .await
            .caused_by(trc::location!())?;
        }

        Ok(())
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.get_blob(key, range).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.get_blob(key, range).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.get_blob(key, range).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.get_blob(key, range).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.get_blob(key, range).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.get_blob(key, range).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.put_blob(key, data).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.put_blob(key, data).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.put_blob(key, data).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.put_blob(key, data).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.delete_blob(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.delete_blob(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.delete_blob(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.delete_blob(key).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!())
    }
}
