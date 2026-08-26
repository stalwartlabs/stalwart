/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Core;
use ahash::AHashSet;
use lz4_flex::frame::FrameEncoder;
use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::mpsc::{self, SyncSender},
};
use store::{
    write::{AnyClass, AnyKey, ValueClass, key::SystemKind},
    *,
};
use types::blob_hash::{BLOB_HASH_LEN, BlobHash};
use utils::{UnwrapFailure, codec::leb128::Leb128_};

pub(super) const MAGIC_MARKER: u8 = 123;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub(super) enum Family {
    Data = 0,
    Blob = 2,
    Registry = 3,
    Changelog = 4,
    Queue = 5,
    Report = 6,
    Telemetry = 7,
    Tasks = 8,
}

type TaskHandle = (tokio::task::JoinHandle<()>, std::thread::JoinHandle<()>);

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackupParams {
    dest: PathBuf,
    families: AHashSet<Family>,
}

impl Core {
    pub async fn backup(&self, mut params: BackupParams) {
        if !params.dest.exists() {
            std::fs::create_dir_all(&params.dest).failed("Failed to create backup directory");
        } else if !params.dest.is_dir() {
            eprintln!("Backup destination {:?} is not a directory.", params.dest);
            std::process::exit(1);
        }

        let mut sync_handles = Vec::new();
        let schema_version = self
            .storage
            .data
            .get_value::<u32>(AnyKey {
                subspace: Subspace::System,
                key: vec![SystemKind::SchemaVersion as u8],
            })
            .await
            .failed("Could not retrieve database schema version.")
            .failed("Could not retrieve database schema version.");

        if params.families.is_empty() {
            params.families = [
                Family::Data,
                Family::Registry,
                Family::Blob,
                Family::Changelog,
                Family::Queue,
                Family::Report,
                Family::Telemetry,
                Family::Tasks,
            ]
            .into_iter()
            .collect();
        }

        for subspace in params.families.into_iter().flat_map(|f| f.subspaces()) {
            let (async_handle, sync_handle) = if subspace == Subspace::Blobs {
                self.backup_blobs(&params.dest, subspace, schema_version)
            } else {
                self.backup_subspace(&params.dest, subspace, schema_version)
            };
            async_handle.await.failed("Task failed");
            sync_handles.push(sync_handle);
        }

        for handle in sync_handles {
            handle.join().expect("Failed to join thread");
        }
    }

    fn backup_blobs(&self, dest: &Path, subspace: Subspace, schema_version: u32) -> TaskHandle {
        let store = self.storage.data.clone();
        let blob_store = self.storage.blob.clone();
        let (handle, writer) = spawn_writer(
            dest.join(format!("subspace_{}", subspace.name())),
            subspace,
            schema_version,
        );
        (
            tokio::spawn(async move {
                let mut blobs = Vec::new();
                let mut last_hash = BlobHash::default();
                store
                    .iterate(
                        IterateParams::new(
                            AnyKey {
                                subspace: Subspace::BlobLink,
                                key: vec![0u8],
                            },
                            AnyKey {
                                subspace: Subspace::BlobLink,
                                key: vec![u8::MAX; 32],
                            },
                        )
                        .no_values(),
                        |key, _| {
                            let hash = BlobHash::try_from_hash_slice(
                                key.get(0..BLOB_HASH_LEN).ok_or_else(|| {
                                    trc::Error::corrupted_key(key, None, trc::location!())
                                })?,
                            )
                            .unwrap();

                            if last_hash != hash {
                                blobs.push(hash.clone());
                                last_hash = hash;
                            }

                            Ok(true)
                        },
                    )
                    .await
                    .failed("Failed to iterate over data store");

                for hash in blobs {
                    if let Some(blob) = blob_store
                        .get_blob(hash.as_slice(), 0..usize::MAX)
                        .await
                        .failed("Failed to get blob")
                    {
                        writer
                            .send((hash.as_slice().to_vec(), blob))
                            .failed("Failed to send key");
                    }
                }
            }),
            handle,
        )
    }

    fn backup_subspace(&self, dest: &Path, subspace: Subspace, schema_version: u32) -> TaskHandle {
        let store = self.storage.data.clone();
        let (handle, writer) = spawn_writer(
            dest.join(format!("subspace_{}", subspace.name())),
            subspace,
            schema_version,
        );
        (
            tokio::spawn(async move {
                if !store.is_sql() || !matches!(subspace.shape(), Shape::Counter) {
                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace,
                                    key: vec![0u8],
                                },
                                AnyKey {
                                    subspace,
                                    key: vec![u8::MAX; 32],
                                },
                            )
                            .set_values(!matches!(subspace.shape(), Shape::Presence)),
                            |key, value| {
                                writer
                                    .send((key.to_vec(), value.to_vec()))
                                    .failed("Failed to send key");

                                Ok(true)
                            },
                        )
                        .await
                        .failed("Failed to iterate over data store");
                } else {
                    let mut keys = Vec::with_capacity(128);
                    store
                        .iterate(
                            IterateParams::new(
                                AnyKey {
                                    subspace,
                                    key: vec![0u8],
                                },
                                AnyKey {
                                    subspace,
                                    key: vec![u8::MAX; 32],
                                },
                            )
                            .no_values(),
                            |key, _| {
                                keys.push(key.to_vec());

                                Ok(true)
                            },
                        )
                        .await
                        .failed("Failed to iterate over data store");

                    for key in keys {
                        let counter = store
                            .get_counter(ValueClass::Any(AnyClass {
                                subspace,
                                key: key.clone(),
                            }))
                            .await
                            .failed("Failed to get counter");
                        writer
                            .send((key.to_vec(), (counter as u64).to_le_bytes().to_vec()))
                            .failed("Failed to send key");
                    }
                }
            }),
            handle,
        )
    }
}

#[allow(clippy::type_complexity)]
fn spawn_writer(
    path: PathBuf,
    subspace: Subspace,
    version: u32,
) -> (std::thread::JoinHandle<()>, SyncSender<(Vec<u8>, Vec<u8>)>) {
    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, Vec<u8>)>(10);

    let handle = std::thread::spawn(move || {
        println!("Exporting database to {}.", path.to_str().unwrap());

        let mut file = FrameEncoder::new(BufWriter::new(
            std::fs::File::create(path).failed("Failed to create backup file"),
        ));
        file.write_all(&[MAGIC_MARKER, subspace.byte()])
            .failed("Failed to write version");
        file.write_all(&version.to_le_bytes())
            .failed("Failed to write version");

        while let Ok((key, value)) = rx.recv() {
            key.len()
                .to_leb128_writer(&mut file)
                .failed("Failed to write key value");
            file.write_all(&key).failed("Failed to write key");
            value
                .len()
                .to_leb128_writer(&mut file)
                .failed("Failed to write key value");
            if !value.is_empty() {
                file.write_all(&value).failed("Failed to write key value");
            }
        }

        let mut file = file.finish().failed("Failed to finish backup file");
        file.flush().failed("Failed to flush backup file");
    });

    (handle, tx)
}

impl BackupParams {
    pub fn new(dest: PathBuf) -> Self {
        let mut params = Self {
            dest,
            families: AHashSet::new(),
        };

        if let Ok(families) = std::env::var("EXPORT_TYPES") {
            params.parse_families(&families);
        }

        params
    }

    fn parse_families(&mut self, families: &str) {
        for family in families.split(',') {
            let family = family.trim();
            match Family::parse(family) {
                Ok(family) => {
                    self.families.insert(family);
                }
                Err(err) => {
                    eprintln!("Backup failed: {err}.");
                    std::process::exit(1);
                }
            }
        }
    }
}

pub(super) trait BackupFamily {
    fn family(self) -> Option<Family>;
}

impl BackupFamily for Subspace {
    fn family(self) -> Option<Family> {
        match self {
            Subspace::Acl
            | Subspace::Indexes
            | Subspace::Quota
            | Subspace::Counter
            | Subspace::GlobalCounter
            | Subspace::Property
            | Subspace::Immutable
            | Subspace::IndexProperty
            | Subspace::System => Some(Family::Data),
            Subspace::Blobs | Subspace::BlobLink => Some(Family::Blob),
            Subspace::Registry
            | Subspace::RegistryIndex
            | Subspace::RegistryPrimaryKey
            | Subspace::Directory
            | Subspace::DeletedItems
            | Subspace::SpamSamples => Some(Family::Registry),
            Subspace::Logs => Some(Family::Changelog),
            Subspace::QueueMessage | Subspace::QueueEvent => Some(Family::Queue),
            Subspace::ReportOut | Subspace::ReportIn => Some(Family::Report),
            Subspace::TelemetrySpan | Subspace::TelemetryMetric => Some(Family::Telemetry),
            Subspace::TaskQueue => Some(Family::Tasks),
            Subspace::InMemoryValue
            | Subspace::InMemoryCounter
            | Subspace::SearchTerm
            | Subspace::SearchDocument
            | Subspace::SearchQueue => None,
        }
    }
}

impl Family {
    pub fn subspaces(&self) -> Vec<Subspace> {
        Subspace::ALL
            .iter()
            .copied()
            .filter(|subspace| subspace.family() == Some(*self))
            .collect()
    }

    pub fn parse(family: &str) -> Result<Self, String> {
        match family {
            "data" => Ok(Family::Data),
            "registry" => Ok(Family::Registry),
            "blob" => Ok(Family::Blob),
            "changelog" => Ok(Family::Changelog),
            "queue" => Ok(Family::Queue),
            "report" => Ok(Family::Report),
            "telemetry" => Ok(Family::Telemetry),
            "tasks" => Ok(Family::Tasks),
            _ => Err(format!("Unknown family {}", family)),
        }
    }
}
