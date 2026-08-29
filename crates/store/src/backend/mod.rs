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
pub mod meili;
pub mod memory;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "rocks")]
pub mod rocksdb;
#[cfg(feature = "s3")]
pub mod s3;
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

#[cfg(any(feature = "rocks", feature = "sqlite"))]
pub(crate) mod worker {
    use rayon::ThreadPool;
    use tokio::{
        runtime::{Handle, RuntimeFlavor},
        sync::oneshot,
    };

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
        match Handle::try_current().map(|handle| handle.runtime_flavor()) {
            Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(&mut f),
            _ => f(),
        }
    }
}

#[allow(dead_code)]
fn deserialize_i64_le(key: &[u8], bytes: &[u8]) -> trc::Result<i64> {
    Ok(i64::from_le_bytes(bytes[..].try_into().map_err(|_| {
        trc::Error::corrupted_key(key, bytes.into(), trc::location!())
    })?))
}
