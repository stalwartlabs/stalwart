/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::download::BlobDownload;
use common::{Server, auth::AccessToken};
use directory::Permission;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::copy::{CopyBlobRequest, CopyBlobResponse},
    request::IntoValid,
};
use std::future::Future;
use store::write::{BatchBuilder, BlobLink, BlobOp, now};
use trc::AddContext;
use types::blob::{BlobClass, BlobId};
use utils::map::vec_map::VecMap;

pub trait BlobCopy: Sync + Send {
    fn blob_copy(
        &self,
        request: CopyBlobRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<CopyBlobResponse>> + Send;
}

impl BlobCopy for Server {
    async fn blob_copy(
        &self,
        request: CopyBlobRequest,
        access_token: &AccessToken,
    ) -> trc::Result<CopyBlobResponse> {
        let mut response = CopyBlobResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            copied: VecMap::with_capacity(request.blob_ids.len()),
            not_copied: VecMap::new(),
        };
        let account_id = request.account_id.document_id();

        for blob_id in request.blob_ids.into_valid() {
            if self.has_access_blob(&blob_id, access_token).await? {
                // Enforce quota
                let used = self
                    .core
                    .storage
                    .data
                    .blob_quota(account_id)
                    .await
                    .caused_by(trc::location!())?;

                if ((self.core.jmap.upload_tmp_quota_size > 0
                    && used.bytes >= self.core.jmap.upload_tmp_quota_size)
                    || (self.core.jmap.upload_tmp_quota_amount > 0
                        && used.count + 1 > self.core.jmap.upload_tmp_quota_amount))
                    && !access_token.has_permission(Permission::UnlimitedUploads)
                {
                    response.not_copied.append(
                        blob_id,
                        SetError::over_quota().with_description(format!(
                            "You have exceeded the blob quota of {} files or {} bytes.",
                            self.core.jmap.upload_tmp_quota_amount,
                            self.core.jmap.upload_tmp_quota_size
                        )),
                    );
                    continue;
                }

                let mut batch = BatchBuilder::new();
                let until = now() + self.core.jmap.upload_tmp_ttl;
                batch.with_account_id(account_id).set(
                    BlobOp::Link {
                        hash: blob_id.hash.clone(),
                        to: BlobLink::Temporary { until },
                    },
                    vec![],
                );
                self.store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;

                let dest_blob_id = BlobId {
                    hash: blob_id.hash.clone(),
                    class: BlobClass::Reserved {
                        account_id,
                        expires: until,
                    },
                    section: blob_id.section.clone(),
                };

                response.copied.append(blob_id, dest_blob_id);
            } else {
                response.not_copied.append(
                    blob_id,
                    SetError::new(SetErrorType::BlobNotFound).with_description(
                        "blobId does not exist or not enough permissions to access it.",
                    ),
                );
            }
        }

        Ok(response)
    }
}
