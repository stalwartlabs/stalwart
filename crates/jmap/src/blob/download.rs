/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::embedded::EmbeddedBlobs;
use common::{
    GroupwareResourceRef, GroupwareResources, Server, auth::AccessToken, sharing::EffectiveAcl,
};
use email::cache::MessageCacheFetch;
use email::cache::email::MessageCacheAccess;
use email::cache::mailbox::MailboxCacheAccess;
use email::message::metadata::MetadataRow;
use groupware::cache::GroupwareCache;
use registry::schema::enums::Permission;
use std::future::Future;
use store::ValueKey;
use trc::AddContext;
use types::acl::Acl;
use types::blob::{BlobClass, BlobId};
use types::collection::{Collection, SyncCollection};
use types::field::EmailField;

pub struct DownloadedBlob {
    pub bytes: Vec<u8>,
    pub extra_headers_len: usize,
}

pub trait BlobDownload: Sync + Send {
    fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<Vec<u8>>>> + Send;

    fn blob_download_with_extra(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<DownloadedBlob>>> + Send;

    fn has_access_blob(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl BlobDownload for Server {
    async fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<Option<Vec<u8>>> {
        self.blob_download_with_extra(blob_id, access_token)
            .await
            .map(|blob| blob.map(|blob| blob.bytes))
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn blob_download_with_extra(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<Option<DownloadedBlob>> {
        let plain = |bytes: Option<Vec<u8>>| {
            bytes.map(|bytes| DownloadedBlob {
                bytes,
                extra_headers_len: 0,
            })
        };
        if self.has_access_blob(blob_id, access_token).await? {
            if matches!(blob_id.class, BlobClass::Embedded { .. }) {
                self.embedded_blob(blob_id)
                    .await
                    .caused_by(trc::location!())
                    .map(plain)
            } else if let Some(section) = &blob_id.section {
                self.get_blob_section(&blob_id.hash, section)
                    .await
                    .caused_by(trc::location!())
                    .map(plain)
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
                        let Some(row) = self
                            .store()
                            .get_value::<MetadataRow>(ValueKey::immutable(
                                *account_id,
                                Collection::Email,
                                *document_id,
                                EmailField::Metadata,
                            ))
                            .await
                            .caused_by(trc::location!())?
                        else {
                            return Ok(plain(Some(data)));
                        };
                        let metadata = row.unarchive().caused_by(trc::location!())?;
                        let body_offset = metadata.blob_body_offset();
                        if metadata.headers_len() != body_offset {
                            let headers = row.raw_headers().caused_by(trc::location!())?;
                            let mut bytes = data;
                            bytes.splice(..body_offset.min(bytes.len()), headers.iter().copied());
                            Ok(Some(DownloadedBlob {
                                bytes,
                                extra_headers_len: metadata.extra_headers_len(),
                            }))
                        } else {
                            Ok(plain(Some(data)))
                        }
                    }
                    (_, blob) => blob.map(plain),
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
        if let BlobClass::Embedded {
            account_id,
            collection,
            document_id,
        } = &blob_id.class
        {
            return self
                .has_access_embedded_blob(access_token, *account_id, *collection, *document_id)
                .await;
        }

        Ok(
            (blob_id.class.is_superuser() && access_token.has_permission(Permission::FetchAnyBlob))
                || (self
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
                                    Collection::Email => {
                                        let cache = self
                                            .get_cached_messages(*account_id)
                                            .await
                                            .caused_by(trc::location!())?;
                                        cache.email_by_id(document_id).is_some_and(|message| {
                                            message.mailboxes().iter().any(|mailbox| {
                                                cache
                                                    .mailbox_by_id(&mailbox.mailbox_id)
                                                    .is_some_and(|mailbox| {
                                                        mailbox
                                                            .acls
                                                            .as_slice()
                                                            .effective_acl(access_token)
                                                            .contains(Acl::ReadItems)
                                                    })
                                            })
                                        })
                                    }
                                    Collection::FileNode => self
                                        .fetch_groupware_resources(
                                            access_token.account_id(),
                                            *account_id,
                                            SyncCollection::FileNode,
                                        )
                                        .await
                                        .caused_by(trc::location!())?
                                        .file_acl(access_token, *document_id)
                                        .contains(Acl::ReadItems),
                                    collection @ (Collection::ContactCard
                                    | Collection::CalendarEvent) => {
                                        let resources = self
                                            .fetch_groupware_resources(
                                                access_token.account_id(),
                                                *account_id,
                                                SyncCollection::from(collection),
                                            )
                                            .await
                                            .caused_by(trc::location!())?;
                                        resources.item_by_id(*document_id).is_some_and(|item| {
                                            is_shared_item_readable(&resources, item, access_token)
                                        })
                                    }
                                    _ => false,
                                }
                            }
                        }
                        BlobClass::Reserved { account_id, .. } => {
                            access_token.is_member(*account_id)
                        }
                        BlobClass::Embedded { .. } => false,
                    }),
        )
    }
}

pub(crate) fn is_shared_item_readable(
    resources: &GroupwareResources,
    item: GroupwareResourceRef<'_>,
    access_token: &AccessToken,
) -> bool {
    item.child_names()
        .iter()
        .any(|name| resources.has_access_to_container(access_token, name.parent_id, Acl::ReadItems))
}
