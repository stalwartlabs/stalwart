/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{ObjectResponse, ValidationResult};
use jmap_proto::error::set::SetError;
use registry::schema::{prelude::Property, structs::SymmetricKey};
use store::write::blob_codec::BlobKey;

pub(crate) async fn validate_symmetric_key(
    key: &mut SymmetricKey,
    old_key: Option<&SymmetricKey>,
) -> ValidationResult {
    if let Some(old_key) = old_key {
        key.fingerprint.clone_from(&old_key.fingerprint);
        return Ok(Ok(ObjectResponse::default()));
    }

    let secret = match key.key.secret().await {
        Ok(secret) => secret,
        Err(err) => {
            return Ok(Err(SetError::invalid_properties()
                .with_property(Property::Key)
                .with_description(format!(
                    "Failed to obtain symmetric key secret: {err}"
                ))));
        }
    };
    match BlobKey::from_base64(0, key.cipher, &secret) {
        Ok(blob_key) => {
            key.fingerprint = blob_key.fingerprint();
            Ok(Ok(ObjectResponse::default()))
        }
        Err(err) => Ok(Err(SetError::invalid_properties()
            .with_property(Property::Key)
            .with_description(err.message()))),
    }
}
