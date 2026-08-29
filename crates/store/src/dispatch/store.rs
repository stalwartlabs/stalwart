/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, IterateParams, Key, QueryResult, Store, Subspace, U32_LEN, Value, ValueKey,
    write::{AnyKey, AssignedIds, Batch, BatchBuilder, ValueClass, key::KeySerializer},
};
use compact_str::ToCompactString;
use std::time::Instant;
use trc::{AddContext, StoreEvent};

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
            Self::Ephemeral(store) => store.get_value(key).await,
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

    pub async fn key_exists(&self, key: impl Key) -> trc::Result<bool> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.key_exists(key).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.key_exists(key).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.key_exists(key).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.key_exists(key).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.key_exists(key).await,
            Self::Ephemeral(store) => store.key_exists(key).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.key_exists(key).await,
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
            Self::Ephemeral(store) => store.iterate(params, cb).await,
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

    pub async fn iterate_many<T: Key>(
        &self,
        ranges: Vec<IterateParams<T>>,
        cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        debug_assert!(ranges.iter().all(|params| {
            params.ascending
                && !params.first
                && params.values == ranges[0].values
                && params.begin.subspace() == ranges[0].begin.subspace()
                && params.end.subspace() == ranges[0].begin.subspace()
        }));
        if ranges.is_empty() {
            return Ok(());
        }
        let start_time = Instant::now();
        let total = ranges.len();

        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.iterate_many(ranges, cb).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.iterate_many(ranges, cb).await,
            Self::Ephemeral(store) => store.iterate_many(ranges, cb).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.iterate_many(ranges, cb).await,
            // SPDX-SnippetEnd
            Self::None => Err(trc::StoreEvent::NotConfigured.into()),
        }
        .caused_by(trc::location!());

        trc::event!(
            Store(StoreEvent::DataIterate),
            Elapsed = start_time.elapsed(),
            Total = total,
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
            Self::Ephemeral(store) => store.get_counter(key).await,
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

    pub async fn write_batch(&self, builder: &mut BatchBuilder) -> trc::Result<AssignedIds> {
        let mut assigned_ids = AssignedIds::default();
        let mut commit_points = builder.commit_points();

        for commit_point in commit_points.iter() {
            let batch = builder.build_one(commit_point);
            self.write(batch, &mut assigned_ids).await?;
        }

        Ok(assigned_ids)
    }

    pub(crate) async fn write(
        &self,
        batch: Batch<'_>,
        assigned_ids: &mut AssignedIds,
    ) -> trc::Result<()> {
        let start_time = Instant::now();
        let ops = batch.ops.len();

        let result = match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "foundation")]
            Self::FoundationDb(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.write(batch, assigned_ids).await,
            #[cfg(feature = "rocks")]
            Self::RocksDb(store) => store.write(batch, assigned_ids).await,
            Self::Ephemeral(store) => store.write(batch, assigned_ids).await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Self::SQLReadReplica(store) => store.write(batch, assigned_ids).await,
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

    pub async fn purge_store(&self) -> trc::Result<()> {
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
            Self::Ephemeral(store) => store.purge_store().await,
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
            Self::Ephemeral(store) => store.delete_range(from, to).await,
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

    pub async fn danger_destroy_account(&self, account_id: u32) -> trc::Result<()> {
        for subspace in [
            Subspace::Logs,
            Subspace::Indexes,
            Subspace::Counter,
            Subspace::Property,
            Subspace::Immutable,
            Subspace::IndexProperty,
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

        self.delete_range(
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Acl(account_id),
            },
            ValueKey {
                account_id: 0,
                collection: 0,
                document_id: 0,
                class: ValueClass::Acl(account_id + 1),
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(())
    }

    pub async fn create_tables(&self) -> trc::Result<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(store) => store.create_tables(),
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(store) => store.create_storage_tables().await,
            #[cfg(feature = "mysql")]
            Self::MySQL(store) => store.create_storage_tables().await,
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(all(feature = "enterprise", any(feature = "postgres", feature = "mysql")))]
            Store::SQLReadReplica(store) => Box::pin(store.primary_store().create_tables()).await,
            // SPDX-SnippetEnd
            _ => Ok(()),
        }
    }
}
