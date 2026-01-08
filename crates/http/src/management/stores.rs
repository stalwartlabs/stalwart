/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
    auth::AccessToken,
    ipc::{HousekeeperEvent, PurgeType},
    manager::webadmin::Resource,
    storage::index::ObjectIndexBuilder,
    *,
};
use directory::{
    Permission,
    backend::internal::manage::{self, ManageDirectory},
};
use email::{
    cache::MessageCacheFetch,
    message::{
        ingest::EmailIngest,
        metadata::{MessageData, MessageMetadata},
    },
    sieve::SieveScript,
};
use groupware::{
    calendar::{Calendar, CalendarEvent, CalendarEventNotification},
    contact::{AddressBook, ContactCard},
    file::FileNode,
};
use http_proto::{request::decode_path_element, *};
use hyper::Method;
use serde_json::json;
use services::task_manager::index::ReindexIndexTask;
use std::future::Future;
use store::{
    Serialize, ValueKey, rand,
    search::SearchQuery,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, BlobLink, BlobOp, DirectoryClass,
        SearchIndex, ValueClass,
    },
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{EmailField, Field, MailboxField},
};
use utils::url_params::UrlParams;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use super::enterprise::undelete::UndeleteApi;
// SPDX-SnippetEnd

pub trait ManageStore: Sync + Send {
    fn handle_manage_store(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;

    fn housekeeper_request(
        &self,
        event: HousekeeperEvent,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManageStore for Server {
    async fn handle_manage_store(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        body: Option<Vec<u8>>,
        session: &HttpSessionData,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        match (
            path.get(1).copied(),
            path.get(2).copied(),
            path.get(3).copied(),
            req.method(),
        ) {
            (Some("blobs"), Some(blob_hash), _, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::BlobFetch)?;

                let blob_hash = URL_SAFE_NO_PAD
                    .decode(decode_path_element(blob_hash).as_bytes())
                    .map_err(|err| {
                        trc::EventType::Resource(trc::ResourceEvent::BadParameters)
                            .from_base64_error(err)
                    })?;
                let contents = self
                    .core
                    .storage
                    .blob
                    .get_blob(&blob_hash, 0..usize::MAX)
                    .await?
                    .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;
                let params = UrlParams::new(req.uri().query());
                let offset = params.parse("offset").unwrap_or(0);
                let limit = params.parse("limit").unwrap_or(usize::MAX);
                let contents = if offset == 0 && limit == usize::MAX {
                    contents
                } else {
                    contents
                        .get(offset..std::cmp::min(offset + limit, contents.len()))
                        .unwrap_or_default()
                        .to_vec()
                };

                Ok(Resource::new("application/octet-stream", contents).into_http_response())
            }
            (Some("purge"), Some("blob"), _, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeBlobStore)?;

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Blobs {
                    store: self.core.storage.data.clone(),
                    blob_store: self.core.storage.blob.clone(),
                }))
                .await
            }
            (Some("purge"), Some("data"), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeDataStore)?;

                let store = if let Some(id) = id.filter(|id| *id != "default") {
                    if let Some(store) = self.core.storage.stores.get(id) {
                        store.clone()
                    } else {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                } else {
                    self.core.storage.data.clone()
                };

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Data(store)))
                    .await
            }
            (Some("purge"), Some("in-memory"), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeInMemoryStore)?;

                let store = if let Some(id) = id.filter(|id| *id != "default") {
                    if let Some(store) = self.core.storage.lookups.get(id) {
                        store.clone()
                    } else {
                        return Err(trc::ResourceEvent::NotFound.into_err());
                    }
                } else {
                    self.core.storage.lookup.clone()
                };

                let prefix = match path.get(4).copied() {
                    Some("acme") => vec![KV_ACME].into(),
                    Some("oauth") => vec![KV_OAUTH].into(),
                    Some("rate-rcpt") => vec![KV_RATE_LIMIT_RCPT].into(),
                    Some("rate-scan") => vec![KV_RATE_LIMIT_SCAN].into(),
                    Some("rate-loiter") => vec![KV_RATE_LIMIT_LOITER].into(),
                    Some("rate-auth") => vec![KV_RATE_LIMIT_AUTH].into(),
                    Some("rate-smtp") => vec![KV_RATE_LIMIT_SMTP].into(),
                    Some("rate-contact") => vec![KV_RATE_LIMIT_CONTACT].into(),
                    Some("rate-http-authenticated") => {
                        vec![KV_RATE_LIMIT_HTTP_AUTHENTICATED].into()
                    }
                    Some("rate-http-anonymous") => vec![KV_RATE_LIMIT_HTTP_ANONYMOUS].into(),
                    Some("rate-imap") => vec![KV_RATE_LIMIT_IMAP].into(),
                    Some("greylist") => vec![KV_GREYLIST].into(),
                    Some("lock-purge-account") => vec![KV_LOCK_PURGE_ACCOUNT].into(),
                    Some("lock-queue-message") => vec![KV_LOCK_QUEUE_MESSAGE].into(),
                    Some("lock-queue-report") => vec![KV_LOCK_QUEUE_REPORT].into(),
                    Some("lock-email-task") => vec![KV_LOCK_TASK].into(),
                    Some("lock-housekeeper") => vec![KV_LOCK_HOUSEKEEPER].into(),
                    _ => None,
                };

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Lookup {
                    store,
                    prefix,
                }))
                .await
            }
            (Some("purge"), Some("account"), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::PurgeAccount)?;

                let account_id = if let Some(id) = id {
                    self.core
                        .storage
                        .data
                        .get_principal_id(decode_path_element(id).as_ref())
                        .await?
                        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?
                        .into()
                } else {
                    None
                };

                self.housekeeper_request(HousekeeperEvent::Purge(PurgeType::Account {
                    account_id,
                    use_roles: false,
                }))
                .await
            }
            (Some("reindex"), Some(index), id, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::FtsReindex)?;

                let account_id = if let Some(id) = id {
                    self.core
                        .storage
                        .data
                        .get_principal_id(decode_path_element(id).as_ref())
                        .await?
                        .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?
                        .into()
                } else {
                    None
                };
                let tenant_id = access_token.tenant.map(|t| t.id);
                let index = SearchIndex::try_from_str(index).ok_or_else(|| {
                    trc::ResourceEvent::BadParameters.reason("Invalid search index specified")
                })?;

                let jmap = self.clone();
                tokio::spawn(async move {
                    if let Err(err) = jmap.reindex(index, account_id, tenant_id).await {
                        trc::error!(err.details("Failed to reindex FTS"));
                    }
                });

                Ok(JsonResponse::new(json!({
                    "data": (),
                }))
                .into_http_response())
            }
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            (Some("undelete"), _, _, _) => {
                // WARNING: TAMPERING WITH THIS FUNCTION IS STRICTLY PROHIBITED
                // Any attempt to modify, bypass, or disable this license validation mechanism
                // constitutes a severe violation of the Stalwart Enterprise License Agreement.
                // Such actions may result in immediate termination of your license, legal action,
                // and substantial financial penalties. Stalwart Labs LLC actively monitors for
                // unauthorized modifications and will pursue all available legal remedies against
                // violators to the fullest extent of the law, including but not limited to claims
                // for copyright infringement, breach of contract, and fraud.

                // Validate the access token
                access_token.assert_has_permission(Permission::Undelete)?;

                if self.core.is_enterprise_edition() {
                    self.handle_undelete_api_request(req, path, body, session)
                        .await
                } else {
                    Err(manage::enterprise())
                }
            }
            // SPDX-SnippetEnd
            (Some("uids"), Some(account_id), None, &Method::DELETE) => {
                let account_id = self
                    .core
                    .storage
                    .data
                    .get_principal_id(decode_path_element(account_id).as_ref())
                    .await?
                    .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

                let result = reset_imap_uids(self, account_id).await?;

                Ok(JsonResponse::new(json!({
                    "data": result,
                }))
                .into_http_response())
            }
            (Some("quota"), Some(account_id), None, method @ (&Method::GET | &Method::DELETE)) => {
                let account_id = self
                    .core
                    .storage
                    .data
                    .get_principal_id(decode_path_element(account_id).as_ref())
                    .await?
                    .ok_or_else(|| trc::ManageEvent::NotFound.into_err())?;

                if method == Method::DELETE {
                    recalculate_quota(self, account_id).await?;
                }

                let result = self.get_used_quota(account_id).await?;

                Ok(JsonResponse::new(json!({
                    "data": result,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }

    async fn housekeeper_request(&self, event: HousekeeperEvent) -> trc::Result<HttpResponse> {
        self.inner
            .ipc
            .housekeeper_tx
            .send(event)
            .await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .details("Failed to send housekeeper event")
            })?;

        Ok(JsonResponse::new(json!({
            "data": (),
        }))
        .into_http_response())
    }
}

pub async fn recalculate_quota(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut quota = 0;

    for collection in [
        Collection::Email,
        Collection::Calendar,
        Collection::CalendarEvent,
        Collection::CalendarEventNotification,
        Collection::AddressBook,
        Collection::ContactCard,
        Collection::FileNode,
    ] {
        server
            .archives(account_id, collection, &(), |_, archive| {
                match collection {
                    Collection::Email => {
                        quota += archive.unarchive::<MessageData>()?.size.to_native() as i64;
                    }
                    Collection::Calendar => {
                        quota += archive.unarchive::<Calendar>()?.size() as i64;
                    }
                    Collection::CalendarEvent => {
                        quota += archive.unarchive::<CalendarEvent>()?.size() as i64;
                    }
                    Collection::CalendarEventNotification => {
                        quota += archive.unarchive::<CalendarEventNotification>()?.size() as i64;
                    }
                    Collection::AddressBook => {
                        quota += archive.unarchive::<AddressBook>()?.size() as i64;
                    }
                    Collection::ContactCard => {
                        quota += archive.unarchive::<ContactCard>()?.size() as i64;
                    }
                    Collection::FileNode => {
                        quota += archive.unarchive::<FileNode>()?.size() as i64;
                    }
                    _ => {}
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    batch
        .clear(DirectoryClass::UsedQuota(account_id))
        .add(DirectoryClass::UsedQuota(account_id), quota);
    server
        .store()
        .write(batch.build_all())
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

pub async fn destroy_account_blobs(server: &Server, account_id: u32) -> trc::Result<()> {
    let mut delete_keys = Vec::new();
    for (collection, field) in [
        (Collection::Email, u8::from(EmailField::Metadata)),
        (Collection::FileNode, u8::from(Field::ARCHIVE)),
        (Collection::SieveScript, u8::from(Field::ARCHIVE)),
    ] {
        server
            .all_archives(account_id, collection, field, |document_id, archive| {
                match collection {
                    Collection::Email => {
                        let message = archive.unarchive::<MessageMetadata>()?;
                        delete_keys.push((
                            collection,
                            document_id,
                            BlobHash::from(&message.blob_hash),
                        ));
                    }
                    Collection::FileNode => {
                        if let Some(file) = archive.unarchive::<FileNode>()?.file.as_ref() {
                            delete_keys.push((
                                collection,
                                document_id,
                                BlobHash::from(&file.blob_hash),
                            ));
                        }
                    }
                    Collection::SieveScript => {
                        let sieve = archive.unarchive::<SieveScript>()?;
                        delete_keys.push((
                            collection,
                            document_id,
                            BlobHash::from(&sieve.blob_hash),
                        ));
                    }
                    _ => {}
                }
                Ok(())
            })
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    batch.with_account_id(account_id);

    for (collection, document_id, hash) in delete_keys {
        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
            batch.with_account_id(account_id);
        }
        batch
            .with_collection(collection)
            .with_document(document_id)
            .clear(ValueClass::Blob(BlobOp::Link {
                hash,
                to: BlobLink::Document,
            }));
    }

    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(())
}

pub async fn destroy_account_data(
    server: &Server,
    account_id: u32,
    has_data: bool,
) -> trc::Result<()> {
    // Unlink all accounts's blobs
    if has_data {
        destroy_account_blobs(server, account_id).await?;
    }

    // Destroy account data
    server
        .store()
        .danger_destroy_account(account_id)
        .await
        .caused_by(trc::location!())?;

    if has_data {
        // Remove search index
        for index in [
            SearchIndex::Email,
            SearchIndex::Contacts,
            SearchIndex::Calendar,
        ] {
            if let Err(err) = server
                .core
                .storage
                .fts
                .unindex(SearchQuery::new(index).with_account_id(account_id))
                .await
            {
                trc::error!(err.details("Failed to delete FTS index"));
            }
        }
    }

    Ok(())
}

pub async fn reset_imap_uids(server: &Server, account_id: u32) -> trc::Result<(u32, u32)> {
    let mut mailbox_count = 0;
    let mut email_count = 0;

    let cache = server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?;

    for &mailbox_id in cache.mailboxes.index.keys() {
        let mailbox = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Mailbox,
                mailbox_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or_else(|| trc::ImapEvent::Error.into_err().caused_by(trc::location!()))?
            .into_deserialized::<email::mailbox::Mailbox>()
            .caused_by(trc::location!())?;
        let mut new_mailbox = mailbox.inner.clone();
        new_mailbox.uid_validity = rand::random::<u32>();
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Mailbox)
            .with_document(mailbox_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(mailbox)
                    .with_changes(new_mailbox),
            )
            .caused_by(trc::location!())?
            .clear(MailboxField::UidCounter);
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        mailbox_count += 1;
    }

    // Reset all UIDs
    for message_id in cache.emails.items.iter().map(|i| i.document_id) {
        let data = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Email,
                message_id,
            ))
            .await
            .caused_by(trc::location!())?;
        let data_ = if let Some(data) = data {
            data
        } else {
            continue;
        };
        let data = data_
            .to_unarchived::<MessageData>()
            .caused_by(trc::location!())?;
        let mut new_data = data
            .deserialize::<MessageData>()
            .caused_by(trc::location!())?;

        let ids = server
            .assign_email_ids(
                account_id,
                new_data.mailboxes.iter().map(|m| m.mailbox_id),
                false,
            )
            .await
            .caused_by(trc::location!())?;

        for (uid_mailbox, uid) in new_data.mailboxes.iter_mut().zip(ids) {
            uid_mailbox.uid = uid;
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(message_id)
            .assert_value(ValueClass::Property(EmailField::Archive.into()), &data)
            .set(
                EmailField::Archive,
                Archiver::new(new_data)
                    .serialize()
                    .caused_by(trc::location!())?,
            );
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        email_count += 1;
    }

    Ok((mailbox_count, email_count))
}
