/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    changes::state::JmapCacheState,
    email::{PatchResult, handle_email_patch, ingested_into_object},
};
use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    message::copy::{CopyMessageError, EmailCopy},
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::SetError,
    method::{
        copy::{CopyRequest, CopyResponse},
        set::SetRequest,
    },
    object::email::{Email, EmailProperty, EmailValue},
    request::{
        Call, IntoValid, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeResultReference,
    },
};
use jmap_tools::{Key, Value};
use std::future::Future;
use trc::AddContext;
use types::acl::Acl;
use utils::map::vec_map::VecMap;

pub trait JmapEmailCopy: Sync + Send {
    fn email_copy<'x>(
        &self,
        request: CopyRequest<'x, Email>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse<Email>>> + Send;
}

impl JmapEmailCopy for Server {
    async fn email_copy<'x>(
        &self,
        request: CopyRequest<'x, Email>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> trc::Result<CopyResponse<Email>> {
        let account_id = request.account_id.document_id();
        let from_account_id = request.from_account_id.document_id();

        if account_id == from_account_id {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("From accountId is equal to fromAccountId"));
        }
        let cache = self.get_cached_messages(account_id).await?;
        let old_state = cache.assert_state(false, &request.if_in_state)?;
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
        let on_success_delete = request.on_success_destroy_original.unwrap_or(false);
        let mut destroy_ids = Vec::new();

        // Obtain quota
        let resource_token = self.get_resource_token(access_token, account_id).await?;

        'create: for (id, create) in request.create.into_valid() {
            let from_message_id = id.document_id();
            if !from_message_ids.contains(from_message_id) {
                response.not_created.append(
                    id,
                    SetError::not_found().with_description(format!(
                        "Item {} not found in account {}.",
                        id, response.from_account_id
                    )),
                );
                continue;
            }

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
                                response.not_created.append(id, set_error);
                                continue 'create;
                            }
                        }
                    }
                    (
                        Key::Property(EmailProperty::ReceivedAt),
                        Value::Element(EmailValue::Date(value)),
                    ) => {
                        received_at = value.into();
                    }
                    (property, _) => {
                        response.not_created.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(property.into_owned())
                                .with_description("Invalid property or value.".to_string()),
                        );
                        continue 'create;
                    }
                }
            }

            // Make sure message belongs to at least one mailbox
            if mailboxes.is_empty() {
                response.not_created.append(
                    id,
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
                        id,
                        SetError::invalid_properties()
                            .with_property(EmailProperty::MailboxIds)
                            .with_description(format!("mailboxId {mailbox_id} does not exist.")),
                    );
                    continue 'create;
                } else if matches!(&can_add_mailbox_ids, Some(ids) if !ids.contains(*mailbox_id)) {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {mailbox_id}."
                        )),
                    );
                    continue 'create;
                }
            }

            // Add response
            match self
                .copy_message(
                    from_account_id,
                    from_message_id,
                    &resource_token,
                    mailboxes,
                    keywords,
                    received_at.map(|dt| dt.timestamp() as u64),
                    session.session_id,
                )
                .await?
            {
                Ok(email) => {
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
                        },
                    );
                }
            }

            // Add to destroy list
            if on_success_delete {
                destroy_ids.push(MaybeInvalid::Value(id));
            }
        }

        // Update state
        if !response.created.is_empty() {
            response.new_state = self.get_cached_messages(account_id).await?.get_state(false);
        }

        // Destroy ids
        if on_success_delete && !destroy_ids.is_empty() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::Email, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::Email(SetRequest {
                    account_id: request.from_account_id,
                    if_in_state: request.destroy_from_if_in_state,
                    create: None,
                    update: None,
                    destroy: MaybeResultReference::Value(destroy_ids).into(),
                    arguments: Default::default(),
                })),
            }
            .into();
        }

        Ok(response)
    }
}
