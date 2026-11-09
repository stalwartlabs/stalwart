/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::embedded::EmbeddedBlobs;
use common::{
    GroupwareResourceRef, GroupwareResources, Server, auth::AccessToken, sharing::EffectiveAcl,
    storage::blob::FetchedBlob,
};
use email::cache::MessageCacheFetch;
use email::cache::email::MessageCacheAccess;
use email::cache::mailbox::MailboxCacheAccess;
use email::message::metadata::MetadataRow;
use groupware::cache::GroupwareCache;
use hyper::body::Bytes;
use registry::schema::enums::Permission;
use std::future::Future;
use store::ValueKey;
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use smtp::queue::{Message, spool::SmtpSpool};
// SPDX-SnippetEnd
use trc::AddContext;
use types::acl::Acl;
use types::blob::{BlobClass, BlobId};
use types::collection::{Collection, SyncCollection};
use types::field::EmailField;

pub struct DownloadedBlob {
    pub bytes: FetchedBlob,
    pub extra_headers_len: usize,
}

pub enum BlobContents {
    Plain(FetchedBlob),
    Message {
        headers: Vec<u8>,
        body_offset: usize,
        blob: FetchedBlob,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobAccess {
    Denied,
    Allowed { size: Option<u64> },
}

impl BlobAccess {
    pub fn is_allowed(&self) -> bool {
        matches!(self, BlobAccess::Allowed { .. })
    }
}

impl BlobContents {
    pub fn into_downloaded(self) -> trc::Result<DownloadedBlob> {
        match self {
            BlobContents::Plain(bytes) => Ok(DownloadedBlob {
                bytes,
                extra_headers_len: 0,
            }),
            BlobContents::Message {
                headers,
                body_offset,
                mut blob,
            } => {
                blob.replace_prefix(body_offset, &headers)
                    .caused_by(trc::location!())?;
                Ok(DownloadedBlob {
                    bytes: blob,
                    extra_headers_len: headers.len().saturating_sub(body_offset),
                })
            }
        }
    }

    pub fn into_http_parts(self) -> trc::Result<(Option<Bytes>, Bytes)> {
        match self {
            BlobContents::Plain(bytes) => Ok((None, bytes.into())),
            BlobContents::Message {
                headers,
                body_offset,
                mut blob,
            } => {
                blob.try_reserve_extra(headers.capacity())
                    .caused_by(trc::location!())?;
                let body = Bytes::from(blob);
                let body = body.slice(body_offset.min(body.len())..);
                Ok((Some(headers.into()), body))
            }
        }
    }
}

impl DownloadedBlob {
    pub fn stored_len(&self, blob_id: &BlobId) -> Option<usize> {
        (blob_id.section.is_none() && !matches!(blob_id.class, BlobClass::Embedded { .. }))
            .then(|| self.bytes.len().saturating_sub(self.extra_headers_len))
    }
}

pub trait BlobDownload: Sync + Send {
    fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<FetchedBlob>>> + Send;

    fn blob_download_with_extra(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<DownloadedBlob>>> + Send;

    fn blob_contents(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<Option<BlobContents>>> + Send;

    fn has_access_blob(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<BlobAccess>> + Send;
}

impl BlobDownload for Server {
    async fn blob_download(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<Option<FetchedBlob>> {
        self.blob_download_with_extra(blob_id, access_token)
            .await
            .map(|blob| blob.map(|blob| blob.bytes))
    }

    async fn blob_download_with_extra(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<Option<DownloadedBlob>> {
        self.blob_contents(blob_id, access_token)
            .await?
            .map(BlobContents::into_downloaded)
            .transpose()
    }

    async fn blob_contents(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<Option<BlobContents>> {
        let BlobAccess::Allowed { size } = self.has_access_blob(blob_id, access_token).await?
        else {
            return Ok(None);
        };

        if matches!(blob_id.class, BlobClass::Embedded { .. }) {
            return match self
                .embedded_blob(blob_id)
                .await
                .caused_by(trc::location!())?
            {
                Some(bytes) => self
                    .account_blob(bytes)
                    .map(|blob| Some(BlobContents::Plain(blob))),
                None => Ok(None),
            };
        } else if let Some(section) = &blob_id.section {
            return self
                .fetch_blob_section(&blob_id.hash, section, size)
                .await
                .caused_by(trc::location!())
                .map(|blob| blob.map(BlobContents::Plain));
        }

        let Some(blob) = self
            .fetch_blob(&blob_id.hash, 0..usize::MAX, size)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        if let BlobClass::Linked {
            account_id,
            collection,
            document_id,
        } = &blob_id.class
            && *collection == Collection::Email as u8
            && let Some(row) = self
                .store()
                .get_value::<MetadataRow>(ValueKey::immutable(
                    *account_id,
                    Collection::Email,
                    *document_id,
                    EmailField::Metadata,
                ))
                .await
                .caused_by(trc::location!())?
        {
            let metadata = row.unarchive().caused_by(trc::location!())?;
            let body_offset = metadata.blob_body_offset();
            if metadata.headers_len() != body_offset {
                let headers = row.raw_headers().caused_by(trc::location!())?;
                return Ok(Some(BlobContents::Message {
                    headers: headers.into_owned(),
                    body_offset,
                    blob,
                }));
            }
        }

        Ok(Some(BlobContents::Plain(blob)))
    }

    async fn has_access_blob(
        &self,
        blob_id: &BlobId,
        access_token: &AccessToken,
    ) -> trc::Result<BlobAccess> {
        if let BlobClass::Embedded {
            account_id,
            collection,
            document_id,
        } = &blob_id.class
        {
            return self
                .has_access_embedded_blob(access_token, *account_id, *collection, *document_id)
                .await
                .map(|allowed| {
                    if allowed {
                        BlobAccess::Allowed { size: None }
                    } else {
                        BlobAccess::Denied
                    }
                });
        }

        if blob_id.class.is_superuser() && access_token.has_permission(Permission::FetchAnyBlob) {
            return Ok(BlobAccess::Allowed { size: None });
        }

        let Some(size) = self
            .store()
            .blob_link_size(&blob_id.hash, &blob_id.class)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(BlobAccess::Denied);
        };

        let allowed = match &blob_id.class {
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
                                    cache.mailbox_by_id(&mailbox.mailbox_id).is_some_and(
                                        |mailbox| {
                                            mailbox
                                                .acls
                                                .as_slice()
                                                .effective_acl(access_token)
                                                .contains(Acl::ReadItems)
                                        },
                                    )
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
                        collection @ (Collection::ContactCard | Collection::CalendarEvent) => {
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
            BlobClass::Reserved { account_id, .. } => access_token.is_member(*account_id),
            BlobClass::Embedded { .. } => false,
            BlobClass::Queued { queue_id } => {
                access_token.has_permission(Permission::SysQueuedMessageGet)
                    && is_queued_blob_visible(self, access_token, *queue_id).await?
            }
        };

        Ok(if allowed {
            BlobAccess::Allowed {
                size: Some(size).filter(|size| *size != 0),
            }
        } else {
            BlobAccess::Denied
        })
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
async fn is_queued_blob_visible(
    server: &Server,
    access_token: &AccessToken,
    queue_id: u64,
) -> trc::Result<bool> {
    let Some(tenant_id) = access_token.tenant_id() else {
        return Ok(true);
    };
    match server
        .read_message_archive(queue_id)
        .await
        .caused_by(trc::location!())?
    {
        Some(archive) => Ok(archive
            .unarchive::<Message>()
            .caused_by(trc::location!())?
            .has_tenant(tenant_id)),
        None => Ok(false),
    }
}
// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
async fn is_queued_blob_visible(
    _server: &Server,
    _access_token: &AccessToken,
    _queue_id: u64,
) -> trc::Result<bool> {
    Ok(true)
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
