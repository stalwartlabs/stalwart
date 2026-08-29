/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::backup::MAGIC_MARKER;
use crate::{Core, DATABASE_SCHEMA_VERSION};
use lz4_flex::frame::FrameDecoder;
use registry::schema::enums::CompressionAlgo;
use std::{
    fs::File,
    io::{BufReader, ErrorKind, Read},
    path::{Path, PathBuf},
};
use store::{
    BlobStore, IterateParams, Shape, Store, Subspace, U32_LEN,
    write::{
        AnyClass, AnyKey, BatchBuilder, ValueClass,
        key::{DeserializeBigEndian, is_node_id_key},
    },
};
use types::{collection::Collection, field::Field};
use utils::{UnwrapFailure, failed};

impl Core {
    pub async fn restore(&self, src: PathBuf) {
        // Backup the core
        let paths = if src.is_dir() {
            let mut paths = Vec::new();
            for entry in std::fs::read_dir(&src).failed("Failed to read directory") {
                let entry = entry.failed("Failed to read entry");
                let path = entry.path();
                if path.is_file() {
                    paths.push(path);
                }
            }
            paths
        } else {
            vec![src]
        };

        let mut conflicts = Vec::new();
        for path in &paths {
            let subspace = KeyValueReader::new(path).subspace;
            if subspace_has_data(&self.storage.data, subspace).await {
                conflicts.push(path.clone());
            }
        }

        if !conflicts.is_empty() {
            eprintln!(
                "Cannot import: the target database already contains data in the key ranges being \
                 imported. This usually means Stalwart was started before the import ran, which \
                 can create duplicate entries. Import into a fresh, empty database and do not \
                 start Stalwart before importing. Conflicting dumps:"
            );
            for path in conflicts {
                eprintln!("  {}", path.display());
            }
            std::process::exit(1);
        }

        let mut tasks = Vec::new();
        for path in paths {
            let storage = self.storage.clone();
            let blob_store = self.storage.blob.clone();
            tasks.push(tokio::spawn(async move {
                restore_file(storage.data, blob_store, &path).await;
            }));
        }

        for task in tasks {
            task.await.failed("Failed to wait for task");
        }
    }
}

async fn subspace_has_data(store: &Store, subspace: Subspace) -> bool {
    let mut has_data = false;
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
                if subspace == Subspace::System && is_node_id_key(key) {
                    Ok(true)
                } else {
                    has_data = true;
                    Ok(false)
                }
            },
        )
        .await
        .failed("Failed to inspect target database");
    has_data
}

async fn restore_file(store: Store, blob_store: BlobStore, path: &Path) {
    println!("Importing database dump from {}.", path.to_str().unwrap());

    let mut reader = KeyValueReader::new(path);
    let mut batch = BatchBuilder::new();

    match reader.subspace {
        Subspace::Blobs => {
            while let Some((key, value)) = reader.next() {
                blob_store
                    .put_blob(&key, &value, CompressionAlgo::Lz4)
                    .await
                    .failed("Failed to write blob");
            }
        }
        subspace if matches!(subspace.shape(), Shape::Counter) => {
            while let Some((key, value)) = reader.next() {
                batch.add(
                    ValueClass::Any(AnyClass {
                        subspace: reader.subspace,
                        key,
                    }),
                    u64::from_le_bytes(
                        value
                            .try_into()
                            .expect("Failed to deserialize counter/quota"),
                    ) as i64,
                );
                if batch.is_large_batch() {
                    store
                        .write_batch(&mut batch)
                        .await
                        .failed("Failed to write batch");
                    batch = BatchBuilder::new();
                }
            }
        }
        Subspace::Indexes => {
            while let Some((key, _)) = reader.next() {
                let account_id = key
                    .as_slice()
                    .deserialize_be_u32(0)
                    .failed("Failed to deserialize account ID");
                let collection = *key.get(U32_LEN).failed("Missing collection byte");
                let field = *key.get(U32_LEN + 1).failed("Missing field byte");
                let value = key
                    .get(U32_LEN + 2..key.len() - U32_LEN)
                    .failed("Missing index key")
                    .to_vec();
                let document_id = key
                    .as_slice()
                    .deserialize_be_u32(key.len() - U32_LEN)
                    .failed("Failed to deserialize document ID");

                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::from(collection))
                    .with_document(document_id)
                    .index(Field::new(field), value);

                if batch.is_large_batch() {
                    store
                        .write_batch(&mut batch)
                        .await
                        .failed("Failed to write batch");
                    batch = BatchBuilder::new();
                }
            }
        }
        _ => {
            while let Some((key, value)) = reader.next() {
                batch.set(
                    ValueClass::Any(AnyClass {
                        subspace: reader.subspace,
                        key,
                    }),
                    value,
                );
                if batch.is_large_batch() {
                    store
                        .write_batch(&mut batch)
                        .await
                        .failed("Failed to write batch");
                    batch = BatchBuilder::new();
                }
            }
        }
    }

    if !batch.is_empty() {
        store
            .write_batch(&mut batch)
            .await
            .failed("Failed to write batch");
    }
}

struct KeyValueReader {
    subspace: Subspace,
    file: FrameDecoder<BufReader<File>>,
}

impl KeyValueReader {
    fn new(path: &Path) -> Self {
        let mut file = FrameDecoder::new(BufReader::new(
            File::open(path).failed("Failed to open file"),
        ));
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf)
            .failed(&format!("Failed to read magic marker from {path:?}"));

        if buf[0] != MAGIC_MARKER {
            failed(&format!("Invalid magic marker in {path:?}"));
        }

        file.read_exact(&mut buf)
            .failed(&format!("Failed to read subspace from {path:?}"));
        let subspace = Subspace::try_from_byte(buf[0])
            .unwrap_or_else(|| failed(&format!("Unknown subspace in {path:?}")));

        let mut buf = [0u8; 4];
        file.read_exact(&mut buf)
            .failed(&format!("Failed to read version from {path:?}"));
        let version = u32::from_le_bytes(buf);

        if version != DATABASE_SCHEMA_VERSION {
            failed(&format!(
                "Invalid database schema version in {path:?}: Expected {DATABASE_SCHEMA_VERSION}, found {version}"
            ));
        }

        Self { file, subspace }
    }

    fn next(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        let size = self.read_size()?;

        let mut key = vec![0; size as usize];
        self.file
            .read_exact(&mut key)
            .failed("Failed to read bytes");
        let value = self.expect_sized_bytes();

        Some((key, value))
    }

    fn read_size(&mut self) -> Option<u32> {
        let mut result = 0;
        let mut buf = [0u8; 1];

        for shift in [0, 7, 14, 21, 28] {
            if let Err(err) = self.file.read_exact(&mut buf) {
                if err.kind() == ErrorKind::UnexpectedEof {
                    return None;
                } else {
                    failed(&format!("Failed to read file: {err:?}"));
                }
            }

            let byte = buf[0];
            if (byte & 0x80) == 0 {
                result |= (byte as u32) << shift;
                return Some(result);
            } else {
                result |= ((byte & 0x7F) as u32) << shift;
            }
        }

        failed("Invalid leb128 sequence")
    }

    fn expect_sized_bytes(&mut self) -> Vec<u8> {
        let len = self.read_size().failed("Missing leb128 value sequence") as usize;
        let mut bytes = vec![0; len];
        self.file
            .read_exact(&mut bytes)
            .failed("Failed to read bytes");
        bytes
    }
}
