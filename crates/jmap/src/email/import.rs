/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{MetadataType, ObjectMetadata},
    blob::download::BlobDownload,
    changes::state::JmapCacheState,
    email::{
        grouped::{GroupedIngest, QueuedEmail},
        ingested_into_object, invalid_keywords,
    },
};
use common::storage::blob::FetchedBlob;
use common::{
    MAX_RECEIVED_AT, Server,
    auth::AccessToken,
    ipc::{EmailPush, PushNotification},
};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::JUNK_ID,
    message::ingest::{group::ThreadKey, recheck::ThreadRecheck},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::import::{ImportEmailRequest, ImportEmailResponse},
    object::email::EmailProperty,
    request::{capability::CapabilityIds, reference::MaybeIdReference},
    types::state::State,
};
use mail_parser::MessageParser;
use std::future::Future;
use types::{acl::Acl, id::Id, keyword::Keyword};
use utils::map::vec_map::VecMap;

pub trait EmailImport: Sync + Send {
    fn email_import(
        &self,
        request: ImportEmailRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<ImportEmailResponse>> + Send;
}

impl EmailImport for Server {
    async fn email_import(
        &self,
        request: ImportEmailRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> trc::Result<ImportEmailResponse> {
        // Validate state
        let account_id = request.account_id.document_id();
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Email);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let cache = self.get_cached_messages(account_id).await?;
        let old_state: State =
            sampled.assert_state(cache.get_state(false), &request.if_in_state)?;
        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            cache.shared_mailboxes(access_token, Acl::AddItems).into()
        } else {
            None
        };

        // Obtain import access token
        let import_access_token = if account_id != access_token.account_id() {
            #[cfg(stalwart_tests)]
            {
                AccessToken::from_id_maybe_invalid(account_id).into()
            }

            #[cfg(not(stalwart_tests))]
            {
                use common::auth::BuildAccessToken;
                use trc::AddContext;
                self.access_token(account_id)
                    .await
                    .caused_by(trc::location!())?
                    .build()
                    .into()
            }
        } else {
            None
        };

        let mut response = ImportEmailResponse {
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state: old_state.into(),
            created: VecMap::with_capacity(request.emails.len()),
            not_created: VecMap::new(),
        };

        let mut grouped = GroupedIngest::new(
            import_access_token.as_ref().unwrap_or(access_token),
            session.session_id,
        );
        let mut last_change_id = None;
        let mut delivered = Vec::with_capacity(request.emails.len());
        let mut recheck = ThreadRecheck::default();
        let grouping = request.emails.len() > 1;
        'outer: for (id, email) in request.emails {
            // Validate mailboxIds
            let mailbox_ids = email
                .mailbox_ids
                .unwrap()
                .into_iter()
                .filter_map(|m| m.try_unwrap().map(|m| m.document_id()))
                .collect::<Vec<_>>();
            if mailbox_ids.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(EmailProperty::MailboxIds)
                        .with_description("Message must belong to at least one mailbox."),
                );
                continue;
            }
            for mailbox_id in &mailbox_ids {
                if !cache.has_mailbox_id(mailbox_id) {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(EmailProperty::MailboxIds)
                            .with_description(format!(
                                "Mailbox {} does not exist.",
                                Id::from(*mailbox_id)
                            )),
                    );
                    continue 'outer;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {}.",
                            Id::from(*mailbox_id)
                        )),
                    );
                    continue 'outer;
                }
            }

            if !email.keywords.iter().all(Keyword::is_jmap_valid) {
                response.not_created.append(id, invalid_keywords());
                continue;
            }

            // Validate per-email limits
            if let Err(err) = self
                .core
                .email
                .limits
                .validate_email(mailbox_ids.len(), &email.keywords)
            {
                response.not_created.append(id, err.into());
                continue;
            }

            let MaybeIdReference::Id(blob_id) = email.blob_id else {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(EmailProperty::BlobId)
                        .with_description("Invalid blob id."),
                );
                continue;
            };

            // Fetch raw message to import
            let blob = match self
                .blob_download_with_extra(&blob_id, access_token)
                .await?
            {
                Some(blob) => blob,
                None => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::BlobNotFound)
                            .with_description(format!("BlobId {} not found.", blob_id)),
                    );
                    continue;
                }
            };

            let is_stored = blob.stored_len(&blob_id) == Some(blob.bytes.len());
            let raw_message = blob.bytes;

            // Import message
            let parsed = MessageParser::new().parse(&raw_message);
            let Some(message) = parsed.filter(|message| message.headers().has_known()) else {
                response.not_created.append(
                    id,
                    SetError::new(SetErrorType::InvalidEmail)
                        .with_description("Blob does not contain a valid RFC 5322 message."),
                );
                continue;
            };
            if let Err(err) = self.core.email.limits.validate_header_section(&message) {
                response.not_created.append(id, err.into());
                continue;
            }
            let received_at = email
                .received_at
                .map(|date| date.timestamp().clamp(0, MAX_RECEIVED_AT as i64) as u64);

            let key = if grouping {
                ThreadKey::new(&message)
            } else {
                ThreadKey::default()
            };
            if grouped.must_flush_before(raw_message.len())
                && let Err(err) = flush(
                    self,
                    &mut grouped,
                    &mut response,
                    &mut recheck,
                    &mut last_change_id,
                    &mut delivered,
                    account_id,
                )
                .await
            {
                recheck.finish(self, session.session_id).await;
                return Err(err);
            }

            let email = QueuedEmail {
                id,
                blob_hash: is_stored.then_some(blob_id.hash),
                train_classifier: email
                    .keywords
                    .iter()
                    .any(|k| matches!(k, Keyword::Junk | Keyword::NotJunk))
                    || mailbox_ids.contains(&JUNK_ID),
                mailbox_ids,
                keywords: email.keywords,
                received_at,
            };
            let result = grouped
                .ingest(self, &email, &raw_message, Some(&message), key)
                .await;
            grouped.queue(email, raw_message, result);
            if let Err(err) = record(
                &mut grouped,
                &mut response,
                &mut recheck,
                &mut last_change_id,
                &mut delivered,
                account_id,
            ) {
                recheck.finish(self, session.session_id).await;
                return Err(err);
            }
        }

        let flushed = flush(
            self,
            &mut grouped,
            &mut response,
            &mut recheck,
            &mut last_change_id,
            &mut delivered,
            account_id,
        )
        .await;
        recheck.finish(self, session.session_id).await;
        flushed?;

        // Update state
        if let Some(change_id) = last_change_id {
            for email_id in delivered {
                self.broadcast_push_notification(PushNotification::EmailPush(EmailPush {
                    account_id,
                    email_id,
                    change_id,
                }))
                .await;
            }

            response.new_state = metadata
                .viewer_change_id(self, account_id)
                .await?
                .state(State::Exact(change_id));
        }

        Ok(response)
    }
}

async fn flush(
    server: &Server,
    grouped: &mut GroupedIngest<'_, FetchedBlob>,
    response: &mut ImportEmailResponse,
    recheck: &mut ThreadRecheck,
    last_change_id: &mut Option<u64>,
    delivered: &mut Vec<u32>,
    account_id: u32,
) -> trc::Result<()> {
    grouped.flush(server).await?;
    record(
        grouped,
        response,
        recheck,
        last_change_id,
        delivered,
        account_id,
    )
}

fn record(
    grouped: &mut GroupedIngest<'_, FetchedBlob>,
    response: &mut ImportEmailResponse,
    recheck: &mut ThreadRecheck,
    last_change_id: &mut Option<u64>,
    delivered: &mut Vec<u32>,
    account_id: u32,
) -> trc::Result<()> {
    for (id, result) in grouped.results.drain(..) {
        match result {
            Ok(mut email) => {
                recheck.push(account_id, &mut email);
                *last_change_id = Some(email.change_id);
                delivered.push(email.document_id);
                response
                    .created
                    .append(id, ingested_into_object(email).into());
            }
            Err(mut err) => match err.as_ref() {
                trc::EventType::Limit(trc::LimitEvent::Quota) => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::OverQuota)
                            .with_description("You have exceeded your account quota."),
                    );
                }
                trc::EventType::MessageIngest(trc::MessageIngestEvent::Error) => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::InvalidEmail).with_description(
                            err.take_value(trc::Key::Reason)
                                .and_then(|v| v.into_string())
                                .unwrap_or_default(),
                        ),
                    );
                }
                _ => return Err(err),
            },
        }
    }
    Ok(())
}
