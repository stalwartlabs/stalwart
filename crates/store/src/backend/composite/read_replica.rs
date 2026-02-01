/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::{
    Deserialize, IterateParams, Key, Store, ValueKey,
    search::{IndexDocument, SearchComparator, SearchDocumentId, SearchFilter, SearchQuery},
    write::{AssignedIds, Batch, SearchIndex, ValueClass},
};
use std::{
    future::Future,
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub struct SQLReadReplica {
    primary: Store,
    replicas: Vec<Store>,
    last_used_replica: AtomicUsize,
}

impl SQLReadReplica {
    pub fn open(primary: Store, replicas: Vec<Store>) -> Result<Store, String> {
        Ok(Store::SQLReadReplica(Arc::new(Self {
            primary,
            replicas,
            last_used_replica: AtomicUsize::new(0),
        })))
    }

    async fn run_op<'x, F, T, R>(&'x self, f: F) -> trc::Result<T>
    where
        F: Fn(&'x Store) -> R,
        R: Future<Output = trc::Result<T>>,
        T: 'static,
    {
        let mut last_error = None;
        for store in [
            &self.replicas
                [self.last_used_replica.fetch_add(1, Ordering::Relaxed) % self.replicas.len()],
            &self.primary,
        ] {
            match f(store).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if err.is_assertion_failure() {
                        return Err(err);
                    } else {
                        last_error = Some(err);
                    }
                }
            }
        }

        Err(last_error.unwrap())
    }

    pub async fn get_blob(&self, key: &[u8], range: Range<usize>) -> trc::Result<Option<Vec<u8>>> {
        self.run_op(move |store| {
            let range = range.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_blob(key, range).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_blob(key, range).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.put_blob(key, data).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.put_blob(key, data).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.delete_blob(key).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.delete_blob(key).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        self.run_op(move |store| {
            let key = key.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_value(key).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_value(key).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        let mut last_error = None;
        for store in [
            &self.replicas
                [self.last_used_replica.fetch_add(1, Ordering::Relaxed) % self.replicas.len()],
            &self.primary,
        ] {
            match match store {
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.iterate(params.clone(), &mut cb).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.iterate(params.clone(), &mut cb).await,
                _ => panic!("Invalid store type"),
            } {
                Ok(result) => return Ok(result),
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap())
    }

    pub async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass>> + Sync + Send,
    ) -> trc::Result<i64> {
        let key = key.into();
        self.run_op(move |store| {
            let key = key.clone();

            async move {
                match store {
                    #[cfg(feature = "postgres")]
                    Store::PostgreSQL(store) => store.get_counter(key).await,
                    #[cfg(feature = "mysql")]
                    Store::MySQL(store) => store.get_counter(key).await,
                    _ => panic!("Invalid store type"),
                }
            }
        })
        .await
    }

    pub async fn write(&self, batch: Batch<'_>) -> trc::Result<AssignedIds> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.write(batch).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.write(batch).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.delete_range(from, to).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.delete_range(from, to).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn purge_store(&self) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.purge_store().await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.purge_store().await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.index(documents).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.index(documents).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn unindex(&self, query: SearchQuery) -> trc::Result<u64> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.unindex(query).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.unindex(query).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub async fn query<R: SearchDocumentId>(
        &self,
        index: SearchIndex,
        filters: &[SearchFilter],
        sort: &[SearchComparator],
    ) -> trc::Result<Vec<R>> {
        match &self.primary {
            #[cfg(feature = "postgres")]
            Store::PostgreSQL(store) => store.query(index, filters, sort).await,
            #[cfg(feature = "mysql")]
            Store::MySQL(store) => store.query(index, filters, sort).await,
            _ => panic!("Invalid store type"),
        }
    }

    pub fn primary_store(&self) -> &Store {
        &self.primary
    }

    pub fn into_primary(self) -> Store {
        self.primary
    }
}
