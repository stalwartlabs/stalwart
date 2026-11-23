/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, network::ServerInstance};
use compact_str::format_compact;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    identity::Identity,
    message::{
        mdn::{MdnMessage, MdnStatus, OriginalMessage, final_recipient_address, validate_mdn},
        metadata::MetadataRow,
    },
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::{
        mdn::{MdnSendRequest, MdnSendResponse},
        set::SetRequest,
    },
    object::{
        email::{EmailProperty, EmailValue},
        mdn::{Mdn, MdnProperty},
    },
    request::{
        Call, MaybeInvalid, RequestMethod, SetRequestMethod,
        method::{MethodFunction, MethodName, MethodObject},
        reference::MaybeIdReference,
    },
};
use jmap_tools::{JsonPointerItem, Key, Value};
use smtp::{
    queue::spool::QueueOutcome,
    reporting::mdn::{MdnOutcome, MdnSender},
};
use std::{future::Future, sync::Arc};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField, id::Id, keyword::Keyword};
use utils::map::vec_map::VecMap;

pub trait JmapMdnSend: Sync + Send {
    fn mdn_send<'x>(
        &self,
        request: MdnSendRequest<'x>,
        instance: &Arc<ServerInstance>,
        session_id: u64,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
    ) -> impl Future<Output = trc::Result<MdnSendResponse>> + Send;
}

impl JmapMdnSend for Server {
    async fn mdn_send<'x>(
        &self,
        request: MdnSendRequest<'x>,
        instance: &Arc<ServerInstance>,
        session_id: u64,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
    ) -> trc::Result<MdnSendResponse> {
        if request.send.len() > self.core.jmap.set_max_objects {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }
        let account_id = request.account_id.document_id();

        let Some(MaybeInvalid::Value(identity_id)) = request.identity_id else {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("Missing or invalid identityId."));
        };
        let Some(identity) = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Identity,
                identity_id.document_id(),
            ))
            .await?
        else {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details("Identity not found."));
        };
        let identity = identity
            .unarchive::<Identity>()
            .caused_by(trc::location!())?;
        let from_address = identity.email.as_str();
        let from_name = Some(identity.name.as_str()).filter(|name| !name.is_empty());

        let updates = request.on_success_update_email;
        if let Some((create_id, _)) = request.send.iter().find(|(create_id, mdn)| {
            !updates.as_ref().is_some_and(|updates| {
                updates.iter().any(|(id, patch)| {
                    let matches_id = match id {
                        MaybeIdReference::Reference(reference) => reference == *create_id,
                        MaybeIdReference::Id(id) => {
                            matches!(mdn.for_email_id, Some(MaybeIdReference::Id(email_id)) if email_id == *id)
                        }
                        MaybeIdReference::Invalid(_) => false,
                    };
                    matches_id && sets_mdn_sent(patch)
                })
            })
        }) {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details(format_compact!(
                    "onSuccessUpdateEmail must set the $mdnsent keyword for {create_id}."
                )));
        }

        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let mut sender = MdnSender::new(
            self.clone(),
            instance.clone(),
            self.account_info(account_id)
                .await
                .caused_by(trc::location!())?,
            from_address,
            session_id,
        );
        let identity_allowed = sender.owns_address(from_address);
        let mut response = MdnSendResponse {
            account_id: request.account_id,
            sent: VecMap::with_capacity(request.send.len()),
            not_sent: VecMap::new(),
        };
        let mut sent_email_ids: Vec<Id> = Vec::with_capacity(request.send.len());

        for (create_id, mut mdn) in request.send {
            if !identity_allowed {
                response.not_sent.append(
                    create_id,
                    SetError::new(SetErrorType::ForbiddenFrom)
                        .with_description("The identity address is not owned by the account."),
                );
                continue;
            }
            let disposition = match validate_mdn(&mdn) {
                Ok(disposition) => disposition,
                Err(err) => {
                    response.not_sent.append(
                        create_id,
                        SetError::invalid_properties()
                            .with_property(err.property)
                            .with_description(err.reason),
                    );
                    continue;
                }
            };
            let Some(MaybeIdReference::Id(email_id)) = mdn.for_email_id else {
                response.not_sent.append(
                    create_id,
                    SetError::invalid_properties()
                        .with_property(MdnProperty::ForEmailId)
                        .with_description("A valid forEmailId is required."),
                );
                continue;
            };
            let Some(message) = cache.email_by_jmap_id(email_id) else {
                response.not_sent.append(
                    create_id,
                    SetError::not_found().with_description("Email not found."),
                );
                continue;
            };
            if cache.has_keyword(message, &Keyword::MdnSent) || sent_email_ids.contains(&email_id) {
                response.not_sent.append(
                    create_id,
                    SetError::new(SetErrorType::MdnAlreadySent)
                        .with_description("The $mdnsent keyword is already set."),
                );
                continue;
            }
            let document_id = message.document_id();

            if let Some(final_recipient) = &mdn.final_recipient
                && !final_recipient_address(final_recipient)
                    .is_some_and(|address| sender.owns_address(&address))
            {
                response.not_sent.append(
                    create_id,
                    SetError::new(SetErrorType::ForbiddenFrom)
                        .with_description("The finalRecipient address is not allowed."),
                );
                continue;
            }

            let Some(row) = self
                .store()
                .get_value::<MetadataRow>(ValueKey::immutable(
                    account_id,
                    Collection::Email,
                    document_id,
                    EmailField::Metadata,
                ))
                .await?
            else {
                response.not_sent.append(
                    create_id,
                    SetError::not_found().with_description("Email not found."),
                );
                continue;
            };
            let metadata = row.unarchive().caused_by(trc::location!())?;
            let raw_headers = row.raw_headers().caused_by(trc::location!())?;
            let mut mdn_request = match MdnStatus::new(metadata, &raw_headers) {
                MdnStatus::Requested(mdn_request) => mdn_request,
                MdnStatus::NotRequested => {
                    response.not_sent.append(
                        create_id,
                        SetError::not_found()
                            .with_description("Email has no Disposition-Notification-To header."),
                    );
                    continue;
                }
                MdnStatus::Report => {
                    response.not_sent.append(
                        create_id,
                        SetError::forbidden()
                            .with_description("MDNs are not sent in response to reports."),
                    );
                    continue;
                }
            };
            if disposition.is_automatic() && !mdn_request.allows_automatic() {
                response.not_sent.append(
                    create_id,
                    SetError::forbidden().with_description(
                        "Automatic MDNs require a single Disposition-Notification-To address matching the Return-Path.",
                    ),
                );
                continue;
            }

            let default_subject = mdn.subject.is_none();
            let default_text_body = mdn.text_body.is_none();
            let default_final_recipient = mdn.final_recipient.is_none();
            mdn_request.apply_defaults(&mut mdn, disposition, from_address);

            let max_size = self.core.email.mail_max_size;
            let original = if mdn.include_original_message {
                if metadata.size() > max_size {
                    response.not_sent.append(
                        create_id,
                        SetError::too_large()
                            .with_description("Original message exceeds the maximum size."),
                    );
                    continue;
                }
                let Some(blob) = self
                    .fetch_blob(
                        &metadata.blob_hash(),
                        0..usize::MAX,
                        Some(metadata.size() as u64),
                    )
                    .await?
                else {
                    response.not_sent.append(
                        create_id,
                        SetError::not_found().with_description("Blob for email not found."),
                    );
                    continue;
                };
                Some(blob)
            } else {
                None
            };

            let raw_message = MdnMessage {
                mdn: &mdn,
                disposition,
                from_name,
                from_address,
                to: &mdn_request.notify,
                original_message: original.as_deref().map(|raw| OriginalMessage {
                    raw,
                    utf8_headers: mdn_request.utf8_headers,
                }),
            }
            .build();
            drop(original);
            let Some(raw_message) = raw_message else {
                response.not_sent.append(
                    create_id,
                    SetError::forbidden().with_description("The MDN could not be built."),
                );
                continue;
            };
            if raw_message.len() > max_size {
                response.not_sent.append(
                    create_id,
                    SetError::too_large().with_description("MDN exceeds the maximum message size."),
                );
                continue;
            }

            match sender
                .send(from_address, &mdn_request.notify, &raw_message)
                .await
            {
                MdnOutcome::Queue(QueueOutcome::Queued) => {
                    sent_email_ids.push(email_id);
                    response.sent.append(
                        create_id,
                        Mdn {
                            subject: mdn.subject.filter(|_| default_subject),
                            text_body: mdn.text_body.filter(|_| default_text_body),
                            final_recipient: mdn
                                .final_recipient
                                .filter(|_| default_final_recipient),
                            original_recipient: mdn.original_recipient,
                            original_message_id: mdn.original_message_id,
                            ..Default::default()
                        },
                    );
                }
                MdnOutcome::RateLimited => {
                    response.not_sent.append(
                        create_id,
                        SetError::new(SetErrorType::RateLimit)
                            .with_description("Too many messages sent, try again later."),
                    );
                }
                MdnOutcome::Queue(QueueOutcome::QuotaExceeded) => {
                    response.not_sent.append(
                        create_id,
                        SetError::over_quota().with_description("Sending quota exceeded."),
                    );
                }
                MdnOutcome::Queue(QueueOutcome::Failed) => {
                    response.not_sent.append(
                        create_id,
                        SetError::forbidden().with_description("The MDN could not be queued."),
                    );
                }
            }
        }

        let update = updates
            .map(|updates| {
                updates
                    .into_iter()
                    .filter_map(|(id, patch)| {
                        let email_id = match id {
                            MaybeIdReference::Reference(reference) => {
                                response.sent.keys().zip(&sent_email_ids).find_map(
                                    |(create_id, id)| (*create_id == reference).then_some(*id),
                                )
                            }
                            MaybeIdReference::Id(id) => sent_email_ids.contains(&id).then_some(id),
                            MaybeIdReference::Invalid(_) => None,
                        }?;
                        Some((MaybeInvalid::Value(email_id), patch))
                    })
                    .collect::<VecMap<_, _>>()
            })
            .filter(|update| !update.is_empty());
        if update.is_some() {
            *next_call = Call {
                id: String::new(),
                name: MethodName::new(MethodObject::Email, MethodFunction::Set),
                method: RequestMethod::Set(SetRequestMethod::Email(Box::new(SetRequest {
                    account_id: request.account_id,
                    if_in_state: None,
                    create: None,
                    update,
                    destroy: None,
                    arguments: Default::default(),
                }))),
            }
            .into();
        }

        Ok(response)
    }
}

fn sets_mdn_sent(patch: &Value<'_, EmailProperty, EmailValue>) -> bool {
    let Value::Object(patch) = patch else {
        return false;
    };
    patch.iter().any(|(key, value)| match (key, value) {
        (Key::Property(EmailProperty::Pointer(pointer)), Value::Bool(true)) => {
            let mut items = pointer.iter();
            matches!(
                (items.next(), items.next(), items.next()),
                (
                    Some(JsonPointerItem::Key(Key::Property(EmailProperty::Keywords))),
                    Some(JsonPointerItem::Key(Key::Property(EmailProperty::Keyword(
                        Keyword::MdnSent
                    )))),
                    None
                )
            )
        }
        (Key::Property(EmailProperty::Keywords), Value::Object(keywords)) => {
            keywords.iter().any(|(keyword, value)| {
                matches!(
                    (keyword, value),
                    (
                        Key::Property(EmailProperty::Keyword(Keyword::MdnSent)),
                        Value::Bool(true)
                    )
                )
            })
        }
        _ => false,
    })
}
