/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(feature = "azure")]
pub mod azure;
pub mod elastic;
pub mod ephemeral;
#[cfg(feature = "foundation")]
pub mod foundationdb;
pub mod fs;
pub mod http;
#[cfg(feature = "keep")]
pub mod keep;
#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/backend/iterate_tests.rs"]
mod iterate_tests;
pub mod local;
pub mod meili;
pub mod memory;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(crate) mod range_batch;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "rocks")]
pub mod rocksdb;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(all(stalwart_tests, any(feature = "postgres", feature = "mysql")))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/backend/sql_fault.rs"]
pub mod sql_fault;
#[cfg(feature = "sqlite")]
pub mod sqlite;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod composite;
// SPDX-SnippetEnd

pub const MAX_TOKEN_LENGTH: usize = (u8::MAX >> 1) as usize;
pub const MAX_TOKEN_MASK: usize = MAX_TOKEN_LENGTH - 1;

#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(crate) fn default_pool_max_connections() -> usize {
    use std::thread::available_parallelism;

    const CONNECTIONS_PER_CORE: usize = 4;
    const MIN_CONNECTIONS: usize = 16;
    const MAX_CONNECTIONS: usize = 32;

    available_parallelism()
        .map_or(MIN_CONNECTIONS, |cores| {
            cores.get().saturating_mul(CONNECTIONS_PER_CORE)
        })
        .clamp(MIN_CONNECTIONS, MAX_CONNECTIONS)
}

#[cfg(any(feature = "rocks", feature = "sqlite"))]
pub(crate) mod worker {
    use rayon::ThreadPool;
    use tokio::{
        runtime::{Handle, RuntimeFlavor},
        sync::{Semaphore, oneshot},
    };

    const MIN_POOL_WORKERS: usize = 4;
    const READ_PERMITS_PER_WORKER: usize = 4;

    #[derive(Clone, Copy)]
    pub(crate) enum Access {
        Read,
        Write,
    }

    pub(crate) struct BlockingPermits {
        reads: Semaphore,
        writes: Semaphore,
    }

    pub(crate) fn pool_workers(configured: Option<u64>) -> usize {
        configured
            .filter(|v| *v > 0)
            .map(|v| v as usize)
            .unwrap_or_else(num_cpus::get)
            .max(MIN_POOL_WORKERS)
    }

    impl BlockingPermits {
        pub(crate) fn new(pool_workers: usize) -> Self {
            Self {
                reads: Semaphore::new(
                    pool_workers
                        .saturating_mul(READ_PERMITS_PER_WORKER)
                        .min(Semaphore::MAX_PERMITS),
                ),
                writes: Semaphore::new(pool_workers.min(Semaphore::MAX_PERMITS)),
            }
        }

        pub(crate) fn block<U, V>(
            &self,
            access: Access,
            f: U,
        ) -> impl Future<Output = trc::Result<V>>
        where
            U: FnMut() -> trc::Result<V> + Send,
            V: Send,
        {
            let permits = match access {
                Access::Read => &self.reads,
                Access::Write => &self.writes,
            };
            async move {
                let _permit = match permits.try_acquire() {
                    Ok(permit) => permit,
                    Err(_) => permits.acquire().await.map_err(|err| {
                        trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)
                    })?,
                };
                block(f)
            }
        }
    }

    pub(crate) async fn spawn<U, V>(pool: &ThreadPool, f: U) -> trc::Result<V>
    where
        U: FnOnce() -> trc::Result<V> + Send + 'static,
        V: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        pool.spawn(move || {
            tx.send(f()).ok();
        });

        match rx.await {
            Ok(result) => result,
            Err(err) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError).reason(err)),
        }
    }

    pub(crate) fn block<U, V>(mut f: U) -> trc::Result<V>
    where
        U: FnMut() -> trc::Result<V> + Send,
        V: Send,
    {
        #[cfg(stalwart_tests)]
        let mut f = super::block_hook::wrap(&mut f);
        match Handle::try_current().map(|handle| handle.runtime_flavor()) {
            Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(&mut f),
            _ => f(),
        }
    }
}

#[cfg(all(stalwart_tests, any(feature = "rocks", feature = "sqlite")))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/backend/block_hook.rs"]
pub mod block_hook;

#[allow(dead_code)]
#[cfg(any(feature = "postgres", feature = "mysql", feature = "sqlite"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueColumn {
    Skip,
    Bytes,
    Counter,
}

#[cfg(any(feature = "postgres", feature = "mysql", feature = "sqlite"))]
impl ValueColumn {
    #[inline]
    pub(crate) fn new(values: bool, subspace: crate::Subspace) -> Self {
        match (values, subspace.shape()) {
            (false, _) => ValueColumn::Skip,
            (true, crate::Shape::Counter) => ValueColumn::Counter,
            (true, _) => ValueColumn::Bytes,
        }
    }

    #[inline]
    pub(crate) fn is_selected(self) -> bool {
        self != ValueColumn::Skip
    }
}

fn deserialize_i64_le(key: &[u8], bytes: &[u8]) -> trc::Result<i64> {
    Ok(i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
        trc::Error::corrupted_key(key, bytes.into(), trc::location!())
    })?))
}
