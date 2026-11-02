/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{
        MetadataAccess, MetadataPatches, MetadataPreload, MetadataType, MetadataWriter,
        NewMetadata, ObjectMetadata,
    },
    changes::state::JmapCacheState,
    email::{PatchResult, handle_email_patch, ingested_into_object, parse_keywords},
};
use common::{
    MAX_RECEIVED_AT, Server, auth::AccessToken, ipc::PushNotification, sharing::EffectiveAcl,
};
use email::{
    cache::{
        MessageCacheFetch,
        email::{MessageAccess, MessageCacheAccess},
        mailbox::MailboxCacheAccess,
    },
    mailbox::JUNK_ID,
    message::{
        copy::{CopyMessageError, CopySources, EmailCopy},
        ingest::{EmailIngest, SpamSample, SpamSamples},
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse, CopySourceId},
        set::SetRequest,
    },
    object::email::{Email, EmailProperty, EmailValue},
    request::{
        Call, MaybeInvalid, RequestMethod, SetRequestMethod,
        capability::CapabilityIds,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
};
use jmap_tools::{Key, Value};
use std::future::Future;
use store::write::{BatchBuilder, now};
use trc::AddContext;
use types::{
    acl::Acl,
    id::Id,
    type_state::{DataType, StateChange},
};
use utils::map::vec_map::VecMap;

pub trait JmapEmailCopy: Sync + Send {
    fn email_copy<'x>(
        &self,
        request: CopyRequest<'x, Email>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<CopyResponse<Email>>> + Send;
}

impl JmapEmailCopy for Server {
    async fn email_copy<'x>(
        &self,
        request: CopyRequest<'x, Email>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
        using: CapabilityIds,
    ) -> trc::Result<CopyResponse<Email>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Email);
        let sampled = metadata.viewer_change_id(self, account_id).await?;
        let cache = self.get_cached_messages(account_id).await?;
        let old_state = sampled.assert_state(cache.get_state(false), &request.if_in_state)?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
            destroyed: None,
        };

        let from_cache = self
            .get_cached_messages(from_account_id)
            .await
            .caused_by(trc::location!())?;
        let from_access = if access_token.is_member(from_account_id) {
            MessageAccess::All
        } else {
            MessageAccess::Mailboxes(from_cache.shared_mailboxes(access_token, Acl::ReadItems))
        };

        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            cache.shared_mailboxes(access_token, Acl::AddItems).into()
        } else {
            None
        };
        let is_shared = access_token.is_shared(account_id);
        let viewer = metadata.viewer();
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();
        let mut spam_samples = SpamSamples::default();
        let mut last_change_id = None;

        let mut metadata_writer = MetadataWriter::new(metadata, account_id);
        let mut preload = MetadataPreload::default();
        let mut source_ids = Vec::with_capacity(request.create.len());
        for source_id in request
            .create
            .values()
            .filter_map(|create| create.source_id(EmailProperty::Id))
        {
            let document_id = source_id.document_id();
            source_ids.push(document_id);
            let Some(email) = from_cache
                .email_by_jmap_id(source_id)
                .filter(|email| from_access.allows(*email))
            else {
                continue;
            };
            let kinds = from_cache.metadata_kinds(email);
            if viewer.is_some() || !kinds.is_empty() {
                preload.insert_source(document_id, kinds);
            }
        }
        metadata_writer
            .preload(self, from_account_id, preload)
            .await?;
        let mut sources = CopySources::new(from_account_id, source_ids);
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let mut tenant_budget = self
            .tenant_quota_budget(&account)
            .await
            .caused_by(trc::location!())?;
        // SPDX-SnippetEnd

        'create: for (id, mut create) in request.create {
            let from_message_id = match create.take_source_id(EmailProperty::Id) {
                Ok(source_id) => source_id,
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            };
            let metadata_patches =
                match metadata.extract(MetadataPatches::for_create(), &mut create) {
                    Ok(patches) => patches,
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                };
            let mut mailboxes = Vec::new();
            let mut keywords = Vec::new();
            let mut received_at = None;

            for (property, value) in create.into_expanded_object() {
                match (property, value) {
                    (Key::Property(EmailProperty::MailboxIds), Value::Object(ids)) => {
                        mailboxes = ids
                            .into_expanded_boolean_set()
                            .filter_map(|id| {
                                id.try_into_property()?.try_into_id()?.document_id().into()
                            })
                            .collect();
                    }
                    (Key::Property(EmailProperty::Keywords), keywords_ @ Value::Object(_)) => {
                        match parse_keywords(keywords_) {
                            Ok(keywords_) => keywords = keywords_,
                            Err(err) => {
                                response.not_created.append(id, err);
                                continue 'create;
                            }
                        }
                    }
                    (Key::Property(EmailProperty::Pointer(pointer)), value) => {
                        match handle_email_patch(&pointer, value) {
                            PatchResult::SetKeyword(keyword) => {
                                if !keywords.contains(keyword) {
                                    keywords.push(keyword.clone());
                                }
                            }
                            PatchResult::RemoveKeyword(keyword) => {
                                keywords.retain(|k| k != keyword);
                            }
                            PatchResult::AddMailbox(id) => {
                                if !mailboxes.contains(&id) {
                                    mailboxes.push(id);
                                }
                            }
                            PatchResult::RemoveMailbox(id) => {
                                mailboxes.retain(|mid| mid != &id);
                            }
                            PatchResult::Invalid(set_error) => {
                                response.not_created.append(id.clone(), set_error);
                                continue 'create;
                            }
                        }
                    }
                    (
                        Key::Property(EmailProperty::ReceivedAt),
                        Value::Element(EmailValue::Date(value)),
                    ) => {
                        received_at =
                            (value.timestamp().clamp(0, MAX_RECEIVED_AT as i64) as u64).into();
                    }
                    (property, _) => {
                        response.not_created.append(
                            id.clone(),
                            SetError::invalid_properties()
                                .with_property(property.into_owned())
                                .with_description("Invalid property or value.".to_string()),
                        );
                        continue 'create;
                    }
                }
            }

            if !from_cache
                .email_by_jmap_id(from_message_id)
                .is_some_and(|email| from_access.allows(email))
            {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        from_message_id, response.from_account_id
                    )),
                );
                continue 'create;
            }

            // Make sure message belongs to at least one mailbox
            if mailboxes.is_empty() {
                response.not_created.append(
                    id.clone(),
                    SetError::invalid_properties()
                        .with_property(EmailProperty::MailboxIds)
                        .with_description("Message has to belong to at least one mailbox."),
                );
                continue 'create;
            }

            // Verify that the mailboxIds are valid
            for mailbox_id in &mailboxes {
                if !cache.has_mailbox_id(mailbox_id) {
                    response.not_created.append(
                        id.clone(),
                        SetError::invalid_properties()
                            .with_property(EmailProperty::MailboxIds)
                            .with_description(format!("mailboxId {mailbox_id} does not exist.")),
                    );
                    continue 'create;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id.clone(),
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {mailbox_id}."
                        )),
                    );
                    continue 'create;
                }
            }

            // Validate per-email limits
            if let Err(err) = self
                .core
                .email
                .limits
                .validate_email(mailboxes.len(), &keywords)
            {
                response.not_created.append(id.clone(), err.into());
                continue 'create;
            }

            let access = if is_shared && (metadata_patches.is_some() || viewer.is_some()) {
                MetadataAccess::from_container_acls(mailboxes.iter().map(|mailbox_id| {
                    cache
                        .mailbox_by_id(mailbox_id)
                        .map(|mailbox| mailbox.acls.as_slice().effective_acl(access_token))
                        .unwrap_or_default()
                }))
            } else {
                MetadataAccess::FULL
            };
            let ingest_metadata = match metadata_writer
                .prepare_ingest(
                    self,
                    NewMetadata::Copy {
                        patches: metadata_patches,
                        source_id: from_message_id.document_id(),
                    },
                    access,
                )
                .await?
            {
                Ok(metadata) => metadata,
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            };

            // Add response
            let Some(source) = sources
                .take(self, from_message_id.document_id())
                .await
                .caused_by(trc::location!())?
            else {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description("Message not found in account."),
                );
                continue 'create;
            };
            let sample = if mailboxes.contains(&JUNK_ID) && self.core.spam.classifier.is_some() {
                Some(
                    SpamSample::from_metadata(source.metadata(), true)
                        .caused_by(trc::location!())?,
                )
            } else {
                None
            };
            match self
                .copy_message(
                    source,
                    &account,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    &mut tenant_budget,
                    // SPDX-SnippetEnd
                    mailboxes,
                    keywords,
                    received_at.unwrap_or_else(|| {
                        from_cache
                            .email_by_id(&from_message_id.document_id())
                            .map(|v| v.received_at())
                            .unwrap_or_else(now)
                    }),
                    ingest_metadata,
                    session.session_id,
                )
                .await?
            {
                Ok(email) => {
                    last_change_id = Some(email.change_id);
                    if let Some(sample) = sample {
                        spam_samples.add_sample(sample);
                    }

                    response
                        .created
                        .append(id, ingested_into_object(email).into());
                    if on_success_delete {
                        destroy_ids.push(MaybeInvalid::Value(from_message_id));
                    }
                }
                Err(CopyMessageError::OverQuota) => {
                    response.not_created.append(id, SetError::over_quota());
                }
                Err(CopyMessageError::AlreadyExists(existing)) => {
                    let existing_id = self
                        .get_cached_messages(account_id)
                        .await?
                        .email_by_id(&existing)
                        .map_or_else(
                            || Id::from(existing),
                            |email| Id::from_parts(email.thread_id(), existing),
                        );
                    response
                        .not_created
                        .append(id, SetError::already_exists().with_existing_id(existing_id));
                }
            }
        }

        if !spam_samples.is_empty() {
            let mut train_batch = BatchBuilder::new();
            self.add_account_spam_samples(
                &mut train_batch,
                from_account_id,
                spam_samples,
                session.session_id,
            )
            .await
            .caused_by(trc::location!())?;
            if !train_batch.is_empty() {
                self.commit_batch(train_batch)
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        // Update state
        if let Some(change_id) = last_change_id {
            self.broadcast_push_notification(PushNotification::StateChange(
                StateChange::new(account_id)
                    .with_change_id(change_id)
                    .with_change(DataType::EmailDelivery)
                    .with_change(DataType::Email)
                    .with_change(DataType::Mailbox)
                    .with_change(DataType::Thread),
            ))
            .await;
            let sampled = metadata.viewer_change_id(self, account_id).await?;
            response.new_state =
                sampled.state(self.get_cached_messages(account_id).await?.get_state(false));
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::Email, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::Email(Box::new(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                }))),
            }
            .into();
        }

        Ok(response)
    }
}
