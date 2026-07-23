/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::BlobStore;
use registry::schema::structs;
use std::{io::SeekFrom, ops::Range, path::PathBuf, sync::Arc};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use utils::codec::base32_custom::Base32Writer;

pub struct FsStore {
    path: PathBuf,
    hash_levels: usize,
}

impl FsStore {
    pub async fn open(config: structs::FileSystemStore) -> Result<BlobStore, String> {
        let path = PathBuf::from(&config.path);
        if !path.exists() {
            fs::create_dir_all(&path)
                .await
                .map_err(|e| format!("Failed to create directory: {e}"))?;
        }

        Ok(BlobStore::Fs(Arc::new(FsStore {
            path,
            hash_levels: std::cmp::min(config.depth as usize, 5),
        })))
    }

    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        let blob_path = self.build_path(key);
        let blob_size = match fs::metadata(&blob_path).await {
            Ok(m) => m.len() as usize,
            Err(_) => return Ok(None),
        };
        let mut blob = File::open(&blob_path).await.map_err(into_error)?;

        Ok(Some(if range.start != 0 || range.end != usize::MAX {
            let from_offset = if range.start < blob_size {
                range.start
            } else {
                0
            };
            let mut buf = vec![0; (std::cmp::min(range.end, blob_size) - from_offset) as usize];

            if from_offset > 0 {
                blob.seek(SeekFrom::Start(from_offset as u64))
                    .await
                    .map_err(into_error)?;
            }
            blob.read_exact(&mut buf).await.map_err(into_error)?;
            buf
        } else {
            let mut buf = Vec::with_capacity(blob_size as usize);
            blob.read_to_end(&mut buf).await.map_err(into_error)?;
            buf
        }))
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        let blob_path = self.build_path(key);

        if fs::metadata(&blob_path)
            .await
            .map_or(true, |m| m.len() as usize != data.len())
        {
            fs::create_dir_all(blob_path.parent().unwrap())
                .await
                .map_err(into_error)?;
            let mut blob_file = File::create(&blob_path).await.map_err(into_error)?;
            blob_file.write_all(data).await.map_err(into_error)?;
            blob_file.flush().await.map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        let blob_path = self.build_path(key);
        if fs::metadata(&blob_path).await.is_ok() {
            fs::remove_file(&blob_path).await.map_err(into_error)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn build_path(&self, key: &[u8]) -> PathBuf {
        let mut path = self.path.clone();

        for byte in key.iter().take(self.hash_levels) {
            path.push(format!("{:x}", byte));
        }
        path.push(Base32Writer::from_bytes(key).finalize());
        path
    }
}

fn into_error(err: std::io::Error) -> trc::Error {
    trc::StoreEvent::FilesystemError.reason(err)
}
