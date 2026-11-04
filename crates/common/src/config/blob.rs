/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::{
    schema::{
        enums::CompressionAlgo,
        prelude::ObjectType,
        structs::{Email, FileStorage, SymmetricKey},
    },
    types::id::ObjectId,
};
use std::sync::Arc;
use store::{
    registry::bootstrap::Bootstrap,
    write::blob_codec::{BlobEncryption, BlobKey, BlobKeyring, BlobOpts},
};
use types::id::Id;

#[derive(Clone)]
pub struct BlobConfig {
    pub keys: BlobKeyring,
    pub email: BlobOpts,
    pub file: BlobOpts,
}

impl BlobConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let mut keys = Vec::new();
        for key_obj in bp.list_infallible::<SymmetricKey>().await {
            let object_id = key_obj.id;
            match BlobConfig::load_key(object_id, key_obj.object).await {
                Ok(key) => keys.push(Arc::new(key)),
                Err(err) => bp.build_error(object_id, err),
            }
        }
        let keys = BlobKeyring::new(keys);

        let email = bp.setting_infallible::<Email>().await;
        let file = bp.setting_infallible::<FileStorage>().await;
        let email = BlobOpts::new(
            email.compression_algorithm,
            BlobConfig::resolve_key(bp, &keys, ObjectType::Email, email.blob_encryption_key),
        );
        let file = BlobOpts::new(
            file.compression_algorithm,
            BlobConfig::resolve_key(bp, &keys, ObjectType::FileStorage, file.blob_encryption_key),
        );

        BlobConfig { keys, email, file }
    }

    pub fn is_uncompressed(&self) -> bool {
        self.email.compression == CompressionAlgo::None
            && self.file.compression == CompressionAlgo::None
    }

    async fn load_key(object_id: ObjectId, key: SymmetricKey) -> Result<BlobKey, String> {
        let id = u32::try_from(object_id.id().id())
            .map_err(|_| "Symmetric key identifier exceeds the 32-bit range".to_string())?;
        let secret = key
            .key
            .secret()
            .await
            .map_err(|err| format!("Failed to obtain symmetric key secret: {err}"))?;
        let blob_key = BlobKey::from_base64(id, key.cipher, &secret)
            .map_err(|err| err.message().to_string())?;
        if !key.fingerprint.is_empty() && key.fingerprint != blob_key.fingerprint() {
            return Err(
                "Symmetric key does not match its stored fingerprint; the key file or environment variable may have changed"
                    .to_string(),
            );
        }
        Ok(blob_key)
    }

    fn resolve_key(
        bp: &mut Bootstrap,
        keys: &BlobKeyring,
        object: ObjectType,
        key_id: Option<Id>,
    ) -> BlobEncryption {
        let Some(key_id) = key_id else {
            return BlobEncryption::None;
        };
        let id = u32::try_from(key_id.id()).unwrap_or(u32::MAX);
        match keys.get(id) {
            Some(key) => BlobEncryption::Key(key.clone()),
            None => {
                bp.build_error(
                    object.singleton(),
                    "The configured blob encryption key is not available; new blobs cannot be written until it is fixed",
                );
                BlobEncryption::Unavailable(id)
            }
        }
    }
}
