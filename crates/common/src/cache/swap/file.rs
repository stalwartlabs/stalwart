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
}

impl FileSwapStore {
    pub async fn open(config: &structs::LocalFileSwap) -> Result<Self, String> {
        let root = PathBuf::from(config.path.as_str());
        if root.as_os_str().is_empty() {
            return Err("No path configured for the local file cache swap tier".to_string());
        }
        fs::create_dir_all(&root)
            .await
            .map_err(|err| format!("Failed to create cache swap directory {root:?}: {err}"))?;

        let probe = root.join(".stalwart-swap-probe");
        fs::write(&probe, b"")
            .await
            .map_err(|err| format!("Cache swap directory {root:?} is not writable: {err}"))?;
        let _ = fs::remove_file(&probe).await;

        Ok(FileSwapStore { root })
    }

    pub async fn load(&self, key: SwapKey) -> trc::Result<Option<Vec<u8>>> {
        match fs::read(self.path(key)).await {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(into_error(err).caused_by(trc::location!())),
        }
    }

    pub async fn store(&self, key: SwapKey, data: &[u8]) -> trc::Result<()> {
        let path = self.path(key);
        let directory = path.parent().unwrap_or(&self.root);
        if let Err(err) = fs::create_dir_all(directory).await {
            return Err(into_error(err).caused_by(trc::location!()));
        }

        let temporary = path.with_extension("tmp");
        let result = async {
            let mut file = File::create(&temporary).await?;
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

fn into_error(err: std::io::Error) -> trc::Error {
    trc::EventType::Store(trc::StoreEvent::SwapError)
        .reason(err)
        .details("Cache swap file error")
}
