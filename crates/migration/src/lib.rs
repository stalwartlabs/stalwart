/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    blob::migrate_blobs_v014,
    queue_v1::{migrate_queue_v011, migrate_queue_v012},
    queue_v2::migrate_queue_v014,
    v011::migrate_v0_11,
    v012::migrate_v0_12,
    v013::migrate_v0_13,
    v014::{SUBSPACE_BITMAP_ID, migrate_principal_v0_14, migrate_v0_14},
};
use common::{DATABASE_SCHEMA_VERSION, Server, manager::boot::DEFAULT_SETTINGS};
use std::time::Duration;
use store::{
    Deserialize, IterateParams, SUBSPACE_PROPERTY, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SUBSPACE_SETTINGS, SerializeInfallible, U32_LEN, Value, ValueKey,
    dispatch::DocumentSet,
    roaring::RoaringBitmap,
    write::{
        AnyClass, AnyKey, BatchBuilder, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use trc::AddContext;
use types::collection::Collection;

pub mod addressbook_v2;
pub mod blob;
pub mod calendar_v2;
pub mod changelog;
pub mod contact_v2;
pub mod email_v1;
pub mod email_v2;
pub mod encryption_v1;
pub mod encryption_v2;
pub mod event_v1;
pub mod event_v2;
pub mod identity_v1;
pub mod mailbox;
pub mod object;
pub mod principal_v1;
pub mod principal_v2;
pub mod push_v1;
pub mod push_v2;
pub mod queue_v1;
pub mod queue_v2;
pub mod report;
pub mod sieve_v1;
pub mod sieve_v2;
pub mod submission;
pub mod tasks_v1;
pub mod tasks_v2;
pub mod threads;
pub mod v011;
pub mod v012;
pub mod v013;
pub mod v014;

const LOCK_WAIT_TIME_ACCOUNT: u64 = 3 * 60;
const LOCK_WAIT_TIME_CORE: u64 = 5 * 60;
const LOCK_RETRY_TIME: Duration = Duration::from_secs(30);

pub async fn try_migrate(server: &Server) -> trc::Result<()> {
    for var in [
        "FORCE_MIGRATE_QUEUE",
        "FORCE_MIGRATE_BLOBS",
        "FORCE_MIGRATE_ACCOUNT",
        "FORCE_MIGRATE",
    ] {
        let Some(version) = std::env::var(var).ok().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        match var {
            "FORCE_MIGRATE_QUEUE" => match version {
                1 => {
                    migrate_queue_v011(server)
                        .await
                        .caused_by(trc::location!())?;
                }
                2 => {
                    migrate_queue_v012(server)
                        .await
                        .caused_by(trc::location!())?;
                }
                4 => {
                    migrate_queue_v014(server)
                        .await
                        .caused_by(trc::location!())?;
                }
                _ => {
                    panic!("Unknown migration queue version: {version}");
                }
            },
            "FORCE_MIGRATE_BLOBS" => {
                migrate_blobs_v014(server)
                    .await
                    .caused_by(trc::location!())?;
            }
            "FORCE_MIGRATE" => match version {
                1 => {
                    migrate_v0_12(server, true)
                        .await
                        .caused_by(trc::location!())?;
                    migrate_v0_13(server).await.caused_by(trc::location!())?;
                    migrate_v0_14(server).await.caused_by(trc::location!())?;
                }
                2 => {
                    migrate_v0_12(server, false)
                        .await
                        .caused_by(trc::location!())?;
                    migrate_v0_13(server).await.caused_by(trc::location!())?;
                    migrate_v0_14(server).await.caused_by(trc::location!())?;
                }
                3 => {
                    migrate_v0_13(server).await.caused_by(trc::location!())?;
                    migrate_v0_14(server).await.caused_by(trc::location!())?;
                }
                4 => {
                    migrate_v0_14(server).await.caused_by(trc::location!())?;
                }
                _ => {
                    panic!("Unknown migration version: {version}");
                }
            },
            "FORCE_MIGRATE_ACCOUNT" => {
                migrate_principal_v0_14(server, version)
                    .await
                    .caused_by(trc::location!())?;
            }
            _ => unreachable!(),
        }

        return Ok(());
    }

    let add_v013_config = match server
        .store()
        .get_value::<u32>(AnyKey {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        })
        .await
        .caused_by(trc::location!())?
    {
        Some(DATABASE_SCHEMA_VERSION) => {
            return Ok(());
        }
        Some(1) => {
            migrate_v0_12(server, true)
                .await
                .caused_by(trc::location!())?;
            migrate_v0_13(server).await.caused_by(trc::location!())?;
            migrate_v0_14(server).await.caused_by(trc::location!())?;
            true
        }
        Some(2) => {
            migrate_v0_12(server, false)
                .await
                .caused_by(trc::location!())?;
            migrate_v0_13(server).await.caused_by(trc::location!())?;
            migrate_v0_14(server).await.caused_by(trc::location!())?;
            true
        }
        Some(3) => {
            migrate_v0_13(server).await.caused_by(trc::location!())?;
            migrate_v0_14(server).await.caused_by(trc::location!())?;
            false
        }
        Some(4) => {
            migrate_v0_14(server).await.caused_by(trc::location!())?;
            false
        }
        Some(version) => {
            panic!(
                "Unknown database schema version, expected {} or below, found {}",
                DATABASE_SCHEMA_VERSION, version
            );
        }
        _ => {
            if !is_new_install(server).await.caused_by(trc::location!())? {
                migrate_v0_11(server).await.caused_by(trc::location!())?;
                true
            } else {
                false
            }
        }
    };

    let mut batch = BatchBuilder::new();
    batch.set(
        ValueClass::Any(AnyClass {
            subspace: SUBSPACE_PROPERTY,
            key: vec![0u8],
        }),
        DATABASE_SCHEMA_VERSION.serialize(),
    );

    if add_v013_config {
        for (key, value) in DEFAULT_SETTINGS {
            if key
                .strip_prefix("queue.")
                .is_some_and(|s| !s.starts_with("limiter.") && !s.starts_with("quota."))
            {
                batch.set(
                    ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_SETTINGS,
                        key: key.as_bytes().to_vec(),
                    }),
                    value.as_bytes().to_vec(),
                );
            }
        }
    }

    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

async fn is_new_install(server: &Server) -> trc::Result<bool> {
    for subspace in [
        SUBSPACE_QUEUE_MESSAGE,
        SUBSPACE_REPORT_IN,
        SUBSPACE_REPORT_OUT,
        SUBSPACE_PROPERTY,
    ] {
        let mut has_data = false;

        server
            .store()
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; 16],
                    },
                )
                .no_values(),
                |_, _| {
                    has_data = true;

                    Ok(false)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if has_data {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn get_properties<U, I>(
    server: &Server,
    account_id: u32,
    collection: Collection,
    iterate: &I,
    property: u8,
) -> trc::Result<Vec<(u32, U)>>
where
    I: DocumentSet + Send + Sync,
    U: Deserialize + 'static,
{
    let collection: u8 = collection.into();
    let expected_results = iterate.len();
    let mut results = Vec::with_capacity(expected_results);

    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(
                ValueKey {
                    account_id,
                    collection,
                    document_id: iterate.min(),
                    class: ValueClass::Property(property),
                },
                ValueKey {
                    account_id,
                    collection,
                    document_id: iterate.max(),
                    class: ValueClass::Property(property),
                },
            ),
            |key, value| {
                let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
                if iterate.contains(document_id) {
                    results.push((document_id, U::deserialize(value)?));
                    Ok(expected_results == 0 || results.len() < expected_results)
                } else {
                    Ok(true)
                }
            },
        )
        .await
        .add_context(|err| {
            err.caused_by(trc::location!())
                .account_id(account_id)
                .collection(collection)
                .id(property.to_string())
        })
        .map(|_| results)
}

pub async fn get_document_ids(
    server: &Server,
    account_id: u32,
    collection: Collection,
) -> trc::Result<Option<RoaringBitmap>> {
    let collection: u8 = collection.into();
    get_bitmap(
        server,
        AnyKey {
            subspace: SUBSPACE_BITMAP_ID,
            key: KeySerializer::new(U32_LEN + 1)
                .write(account_id)
                .write(collection)
                .write(0u32)
                .finalize(),
        },
        AnyKey {
            subspace: SUBSPACE_BITMAP_ID,
            key: KeySerializer::new(U32_LEN + 1)
                .write(account_id)
                .write(collection)
                .write(u32::MAX)
                .finalize(),
        },
    )
    .await
}

pub async fn get_bitmap(
    server: &Server,
    from_key: AnyKey<Vec<u8>>,
    to_key: AnyKey<Vec<u8>>,
) -> trc::Result<Option<RoaringBitmap>> {
    let mut results = RoaringBitmap::new();
    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key).no_values(),
            |key, _| {
                results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| {
            if !results.is_empty() {
                Some(results)
            } else {
                None
            }
        })
}

pub struct LegacyBincode<T: serde::de::DeserializeOwned> {
    pub inner: T,
}

impl<T: serde::de::DeserializeOwned> LegacyBincode<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: serde::de::DeserializeOwned> From<Value<'static>> for LegacyBincode<T> {
    fn from(_: Value<'static>) -> Self {
        unreachable!("From Value called on LegacyBincode<T>")
    }
}

impl<T: serde::de::DeserializeOwned + Sized + Sync + Send> Deserialize for LegacyBincode<T> {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        lz4_flex::decompress_size_prepended(bytes)
            .map_err(|err| {
                trc::StoreEvent::DecompressError
                    .ctx(trc::Key::Value, bytes)
                    .caused_by(trc::location!())
                    .reason(err)
            })
            .and_then(|result| {
                bincode::deserialize(&result).map_err(|err| {
                    trc::StoreEvent::DataCorruption
                        .ctx(trc::Key::Value, bytes)
                        .caused_by(trc::location!())
                        .reason(err)
                })
            })
            .map(|inner| Self { inner })
    }
}
