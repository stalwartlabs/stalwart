/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{
        ContainerTarget, DetachedMetadata, MetadataAccess, MetadataPatches, MetadataPreload,
        MetadataType, MetadataWriter, ObjectMetadata,
    },
    changes::state::JmapCacheState,
    email::{PatchResult, handle_email_patch, ingested_into_object},
};
use common::{
    MAX_RECEIVED_AT, Server,
    auth::{AccessToken, AccountCache},
    storage::metadata::MetadataLog,
};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    mailbox::JUNK_ID,
    message::{
        copy::{CopyMessageError, CopyMetadata, EmailCopy, SharedCopy},
        ingest::EmailIngest,
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
use std::{future::Future, sync::Arc};
use store::{
    roaring::RoaringBitmap,
    write::{BatchBuilder, now},
};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, metadata::MetadataKinds};
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
        let cache = self.get_cached_messages(account_id).await?;
        let metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Email);
        let old_state = metadata
            .assert_state(
                self,
                account_id,
                cache.get_state(false),
                &request.if_in_state,
            )
            .await?;
        let mut response = CopyResponse {
            from_account_id: request.from_account_id,
            account_id: request.account_id,
            new_state: old_state.clone(),
            old_state,
            created: VecMap::with_capacity(request.create.len()),
            not_created: VecMap::new(),
        };

        let from_cache = self
            .get_cached_messages(from_account_id)
            .await
            .caused_by(trc::location!())?;
        let from_message_ids = if access_token.is_member(from_account_id) {
            from_cache.email_document_ids()
        } else {
            from_cache.shared_messages(access_token, Acl::ReadItems)
        };

        let can_add_mailbox_ids = if access_token.is_shared(account_id) {
            cache.shared_mailboxes(access_token, Acl::AddItems).into()
        } else {
            None
        };
        let is_shared = access_token.is_shared(account_id);
        let mut modifiable_mailbox_ids: Option<RoaringBitmap> = None;
        let mut readable_mailbox_ids: Option<RoaringBitmap> = None;
        let mut owner_account: Option<Arc<AccountCache>> = None;
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();
        let mut train_batch = BatchBuilder::new();
        let mut did_train = false;
        train_batch.with_account_id(from_account_id);

        let mut metadata_writer = MetadataWriter::new(metadata, account_id);
        let mut creates = Vec::with_capacity(request.create.len());
        let mut preload = MetadataPreload::default();
        for (id, mut create) in request.create {
            let source_id = create.take_source_id(EmailProperty::Id);
            let patches = metadata.extract(MetadataPatches::for_create(), &mut create);
            if let (Ok(source_id), Ok(_)) = (&source_id, &patches)
                && from_message_ids.contains(source_id.document_id())
            {
                let document_id = source_id.document_id();
                preload.insert_source(
                    document_id,
                    from_cache
                        .email_by_id(&document_id)
                        .map_or(MetadataKinds::NONE, |email| {
                            from_cache.metadata_kinds(email)
                        }),
                );
            }
            creates.push((id, source_id, create, patches));
        }
        metadata_writer
            .preload(self, from_account_id, preload)
            .await?;

        'create: for (id, source_id, create, patches) in creates {
            let from_message_id = match source_id {
                Ok(source_id) => source_id,
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            };
            let metadata_patches = match patches {
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
                    (Key::Property(EmailProperty::Keywords), Value::Object(keywords_)) => {
                        keywords = keywords_
                            .into_expanded_boolean_set()
                            .filter_map(|id| id.try_into_property()?.try_into_keyword())
                            .collect();
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

            if !from_message_ids.contains(from_message_id.document_id()) {
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

            let access = MetadataAccess {
                may_write_shared: !is_shared
                    || mailboxes.iter().any(|mailbox_id| {
                        modifiable_mailbox_ids
                            .get_or_insert_with(|| {
                                cache.shared_mailboxes(access_token, Acl::ModifyItems)
                            })
                            .contains(*mailbox_id)
                    }),
                may_read: !is_shared
                    || mailboxes.iter().any(|mailbox_id| {
                        readable_mailbox_ids
                            .get_or_insert_with(|| {
                                cache.shared_mailboxes(access_token, Acl::ReadItems)
                            })
                            .contains(*mailbox_id)
                    }),
            };
            let update = match metadata_writer.copy_update(
                metadata_patches,
                from_message_id.document_id(),
                access,
            ) {
                Ok(update) => update,
                Err(err) => {
                    response.not_created.append(id, err);
                    continue 'create;
                }
            };
            let detached = if update.is_empty() {
                DetachedMetadata::default()
            } else {
                let owner = match &owner_account {
                    Some(owner) => Arc::clone(owner),
                    None => Arc::clone(
                        owner_account
                            .insert(self.account(account_id).await.caused_by(trc::location!())?),
                    ),
                };
                match update
                    .prepare_detached(
                        self,
                        ContainerTarget {
                            owner: &owner,
                            viewer_id: access_token.account_id(),
                            collection: Collection::Email,
                            log: MetadataLog::None,
                        },
                    )
                    .await?
                {
                    Ok(detached) => detached,
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                }
            };

            // Add response
            let train_spam = mailboxes.contains(&JUNK_ID);
            match self
                .copy_message(
                    from_account_id,
                    from_message_id.document_id(),
                    account_id,
                    mailboxes,
                    keywords,
                    received_at.unwrap_or_else(|| {
                        from_cache
                            .email_by_id(&from_message_id.document_id())
                            .map(|v| v.received_at())
                            .unwrap_or_else(now)
                    }),
                    CopyMetadata {
                        shared: detached.shared.map_or(SharedCopy::None, SharedCopy::Set),
                        private: detached.private.map(Box::new),
                    },
                    session.session_id,
                )
                .await?
            {
                Ok(email) => {
                    if train_spam {
                        self.add_account_spam_sample(
                            &mut train_batch,
                            from_account_id,
                            from_message_id.document_id(),
                            true,
                            session.session_id,
                        )
                        .await
                        .caused_by(trc::location!())?;
                        train_batch.commit_point();
                        did_train = true;
                    }

                    response
                        .created
                        .append(id, ingested_into_object(email).into());
                }
                Err(err) => {
                    response.not_created.append(
                        id,
                        match err {
                            CopyMessageError::NotFound => SetError::not_found()
                                .with_description("Message not found in account."),
                            CopyMessageError::OverQuota => SetError::over_quota(),
                            CopyMessageError::AlreadyExists(existing) => SetError::already_exists()
                                .with_existing_id(types::id::Id::from(existing)),
                        },
                    );
                }
            }

            // Add to destroy list
            if on_success_delete {
                destroy_ids.push(MaybeInvalid::Value(from_message_id));
            }
        }

        if did_train {
            self.commit_batch(train_batch)
                .await
                .caused_by(trc::location!())?;
        }

        // Update state
        if !response.created.is_empty() {
            response.new_state = metadata
                .state(
                    self,
                    account_id,
                    self.get_cached_messages(account_id).await?.get_state(false),
                )
                .await?;
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
