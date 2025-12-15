/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use email::cache::MessageCacheFetch;
use email::cache::email::MessageCacheAccess;
use email::message::metadata::MessageMetadata;
use groupware::cache::GroupwareCache;
use store::ValueKey;
use store::write::{AlignedBytes, Archive};
use std::future::Future;
use trc::AddContext;
use types::acl::Acl;
use types::blob::{BlobClass, BlobId};
use types::collection::{Collection, SyncCollection};
use types::field::EmailField;
use utils::chained_bytes::ChainedBytes;

pub trait BlobDownload: Sync + Send {
    fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<Vec<u8>>>> + Send;

    fn has_access_blob(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl BlobDownload for Server {
    #[allow(clippy::blocks_in_conditions)]
    async fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<Option<Vec<u8>>> {
        if self.has_access_blob(blob_id, access_token).await? {
            if let Some(section) = &blob_id.section {
                self.get_blob_section(&blob_id.hash, section)
                    .await
                    .caused_by(trc::location!())
            } else {
                let blob = self
                    .blob_store()
                    .get_blob(blob_id.hash.as_slice(), 0..usize::MAX)
                    .await
                    .caused_by(trc::location!());
                match (&blob_id.class, blob) {
                    (
                        BlobClass::Linked {
                            account_id,
                            collection,
                            document_id,
                        },
                        Ok(Some(data)),
                    ) if *collection == Collection::Email as u8 => {
                        let Some(archive) = self
                            .store()
                            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                                *account_id,
                                Collection::Email,
                                *document_id,
                                EmailField::Metadata,
                            ))
                            .await
                            .caused_by(trc::location!())?
                        else {
                            return Ok(Some(data));
                        };
                        let metadata = archive
                            .to_unarchived::<MessageMetadata>()
                            .caused_by(trc::location!())?;
                        let body_offset = metadata.inner.blob_body_offset.to_native();
                        if metadata.inner.root_part().offset_body.to_native() != body_offset {
                            let raw_message = ChainedBytes::new(
                                metadata.inner.raw_headers.as_ref(),
                            )
                            .with_last(data.get(body_offset as usize..).unwrap_or_default());
                            Ok(Some(raw_message.to_bytes()))
                        } else {
                            Ok(Some(data))
                        }
                    }
                    (_, blob) => blob,
                }
            }
        } else {
            Ok(None)
        }
    }

    async fn has_access_blob(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<bool> {
        Ok(self
            .store()
            .blob_has_access(&blob_id.hash, &blob_id.class)
            .await
            .caused_by(trc::location!())?
            && match &blob_id.class {
                BlobClass::Linked {
                    account_id,
                    collection,
                    document_id,
                } => {
                    if access_token.is_member(*account_id) {
                        true
                    } else {
                        match Collection::from(*collection) {
                            Collection::Email => self
                                .get_cached_messages(*account_id)
                                .await
                                .caused_by(trc::location!())?
                                .shared_messages(access_token, Acl::ReadItems)
                                .contains(*document_id),
                            collection @ (Collection::FileNode
                            | Collection::ContactCard
                            | Collection::CalendarEvent) => self
                                .fetch_dav_resources(
                                    access_token,
                                    *account_id,
                                    SyncCollection::from(collection),
                                )
                                .await
                                .caused_by(trc::location!())?
                                .shared_items(access_token, [Acl::ReadItems], true)
                                .contains(*document_id),
                            _ => false,
                        }
                    }
                }
                BlobClass::Reserved { account_id, .. } => access_token.is_member(*account_id),
            })
    }
}
