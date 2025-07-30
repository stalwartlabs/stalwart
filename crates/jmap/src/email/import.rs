/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{blob::download::BlobDownload, changes::state::MessageCacheState};
use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::import::{ImportEmailRequest, ImportEmailResponse},
    types::{acl::Acl, id::Id, property::Property, state::State},
};
use mail_parser::MessageParser;
use std::future::Future;
use utils::map::vec_map::VecMap;

pub trait EmailImport: Sync + Send {
    fn email_import(
        &self,
        request: ImportEmailRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<ImportEmailResponse>> + Send;
}

impl EmailImport for Server {
    async fn email_import(
        &self,
        request: ImportEmailRequest,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<ImportEmailResponse> {
        // Validate state
        let account_id = request.account_id.document_id();
        let cache = self.get_cached_messages(account_id).await?;
        let old_state: State = cache.assert_state(false, &request.if_in_state)?;
        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            cache.shared_mailboxes(access_token, Acl::AddItems).into()
        } else {
            None
        };

        // Obtain import access token
        let import_access_token = if account_id != access_token.primary_id() {
            #[cfg(feature = "test_mode")]
            {
                std::sync::Arc::new(AccessToken::from_id(account_id)).into()
            }

            #[cfg(not(feature = "test_mode"))]
            {
                use trc::AddContext;
                self.get_access_token(account_id)
                    .await
                    .caused_by(trc::location!())?
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
        let can_train_spam = self.email_bayes_can_train(access_token);

        'outer: for (id, email) in request.emails {
            // Validate mailboxIds
            let mailbox_ids = email
                .mailbox_ids
                .unwrap()
                .into_iter()
                .map(|m| m.unwrap().document_id())
                .collect::<Vec<_>>();
            if mailbox_ids.is_empty() {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(Property::MailboxIds)
                        .with_description("Message must belong to at least one mailbox."),
                );
                continue;
            }
            for mailbox_id in &mailbox_ids {
                if !cache.has_mailbox_id(mailbox_id) {
                    response.not_created.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(Property::MailboxIds)
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

            // Fetch raw message to import
            let raw_message = match self.blob_download(&email.blob_id, access_token).await? {
                Some(raw_message) => raw_message,
                None => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::BlobNotFound)
                            .with_description(format!("BlobId {} not found.", email.blob_id)),
                    );
                    continue;
                }
            };

            // Import message
            match self
                .email_ingest(IngestEmail {
                    raw_message: &raw_message,
                    message: MessageParser::new().parse(&raw_message),
                    access_token: import_access_token.as_deref().unwrap_or(access_token),
                    mailbox_ids,
                    keywords: email.keywords,
                    received_at: email.received_at.map(|r| r.into()),
                    source: IngestSource::Jmap,
                    spam_classify: false,
                    spam_train: can_train_spam,
                    session_id: session.session_id,
                })
                .await
            {
                Ok(email) => {
                    response.created.append(id, email.into());
                }
                Err(mut err) => match err.as_ref() {
                    trc::EventType::Limit(trc::LimitEvent::Quota) => {
                        response.not_created.append(
                            id,
                            SetError::new(SetErrorType::OverQuota)
                                .with_description("You have exceeded your disk quota."),
                        );
                    }
                    trc::EventType::MessageIngest(trc::MessageIngestEvent::Error) => {
                        response.not_created.append(
                            id,
                            SetError::new(SetErrorType::InvalidEmail).with_description(
                                err.take_value(trc::Key::Reason)
                                    .and_then(|v| v.into_string())
                                    .unwrap(),
                            ),
                        );
                    }
                    _ => {
                        return Err(err);
                    }
                },
            }
        }

        // Update state
        if !response.created.is_empty() {
            response.new_state = self.get_cached_messages(account_id).await?.get_state(false);
        }

        Ok(response)
    }
}
