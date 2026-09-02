/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::SwapKey;
use registry::schema::structs;
use std::path::{Path, PathBuf};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};

const SHARDS: u32 = 256;

pub struct FileSwapStore {
    root: PathBuf,
    max_size: u64,
}

impl FileSwapStore {
    pub async fn open(config: &structs::LocalFileSwap) -> Result<Self, String> {
        let root = PathBuf::from(config.path.as_str());
        if root.as_os_str().is_empty() {
            return Err("No path configured for the local file cache swap tier".to_string());
        }
        create_dir(&root)
            .await
            .map_err(|err| format!("Failed to create cache swap directory {root:?}: {err}"))?;

        let probe = root.join(".stalwart-swap-probe");
        create_file(&probe)
            .await
            .map_err(|err| format!("Cache swap directory {root:?} is not writable: {err}"))?;
        let _ = fs::remove_file(&probe).await;

        remove_stale_temporaries(&root).await;

        Ok(FileSwapStore {
            root,
            max_size: config.max_account_size,
        })
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        let path = self.path(key);
        match fs::metadata(&path).await {
            Ok(metadata) if metadata.len() > self.max_size => {
                trc::event!(
                    Store(trc::StoreEvent::SwapError),
                    AccountId = key.account_id,
                    Collection = key.collection.as_str(),
                    Size = metadata.len(),
                    Limit = self.max_size,
                    Details = "Cache snapshot on disk exceeds the configured maximum size",
                );
                return Ok(None);
            }
            Ok(_) => (),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(into_error(err).caused_by(trc::location!())),
        }

        match fs::read(&path).await {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(into_error(err).caused_by(trc::location!())),
        }
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let path = self.path(key);
        let directory = path.parent().unwrap_or(&self.root);
        if let Err(err) = create_dir(directory).await {
            return Err(into_error(err).caused_by(trc::location!()));
        }

        let temporary = path.with_extension("tmp");
        let result = async {
            let mut file = create_file(&temporary).await?;
            file.write_all(data).await?;
            file.sync_all().await?;
            drop(file);
            fs::rename(&temporary, &path).await
        }
        .await;

        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&temporary).await;
                Err(into_error(err).caused_by(trc::location!()))
            }
        }
    }

    pub async fn remove(&self, key: SwapKey) -> trc::Result<()> {
        match fs::remove_file(self.path(key)).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(into_error(err).caused_by(trc::location!())),
        }
    }

    fn path(&self, key: SwapKey) -> PathBuf {
        let mut path = self.root.join(format!("{:02x}", key.account_id % SHARDS));
        path.push(key.file_name());
        path
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

async fn create_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path).await
}

async fn create_file(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).await
}

async fn remove_stale_temporaries(root: &Path) {
    let mut directories = vec![root.to_path_buf()];

    while let Some(directory) = directories.pop() {
        let Ok(mut entries) = fs::read_dir(&directory).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            match entry.file_type().await {
                Ok(file_type) if file_type.is_dir() => directories.push(path),
                Ok(_) if path.extension().is_some_and(|extension| extension == "tmp") => {
                    let _ = fs::remove_file(&path).await;
                }
                _ => (),
            }
        }
    }
}

fn into_error(err: std::io::Error) -> trc::Error {
    trc::EventType::Store(trc::StoreEvent::SwapError)
        .reason(err)
        .details("Cache swap file error")
}
