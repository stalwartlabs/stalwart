/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::headers::{BuildHeader, ValueToHeader};
use crate::{
    blob::download::BlobDownload,
    changes::state::JmapCacheState,
    email::{PatchResult, handle_email_patch, ingested_into_object},
};
use common::{
    Server, auth::AccessToken, ipc::PushNotification, storage::index::ObjectIndexBuilder,
};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    mailbox::{JUNK_ID, TRASH_ID, UidMailbox},
    message::{
        delete::EmailDeletion,
        ingest::{EmailIngest, IngestEmail, IngestSource},
        metadata::MessageData,
    },
};
use http_proto::HttpSessionData;
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::email::{Email, EmailProperty, EmailValue},
    references::resolve::ResolveCreatedReference,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{Key, Value};
use mail_builder::{
    MessageBuilder,
    headers::{
        HeaderType, address::Address, content_type::ContentType, date::Date, message_id::MessageId,
        raw::Raw, text::Text,
    },
    mime::{BodyPart, MimePart},
};
use mail_parser::MessageParser;
use std::future::Future;
use std::{borrow::Cow, collections::HashMap};
use store::{
    ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection, VanishedCollection},
    id::Id,
    keyword::{ArchivedKeyword, Keyword},
    type_state::{DataType, StateChange},
};

pub trait EmailSet: Sync + Send {
    fn email_set(
        &self,
        request: SetRequest<'_, Email>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<Email>>> + Send;
}

impl EmailSet for Server {
    async fn email_set(
        &self,
        mut request: SetRequest<'_, Email>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<SetResponse<Email>> {
        // Prepare response
        let account_id = request.account_id.document_id();
        let cache = self.get_cached_messages(account_id).await?;
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(cache.assert_state(false, &request.if_in_state)?);

        // Obtain mailboxIds
        let (can_add_mailbox_ids, can_delete_mailbox_ids, can_modify_mailbox_ids) =
            if access_token.is_shared(account_id) {
                (
                    cache.shared_mailboxes(access_token, Acl::AddItems).into(),
                    cache
                        .shared_mailboxes(access_token, Acl::RemoveItems)
                        .into(),
                    cache
                        .shared_mailboxes(access_token, Acl::ModifyItems)
                        .into(),
                )
            } else {
                (None, None, None)
            };

        // Obtain import access token
        let import_access_token = if account_id != access_token.primary_id() {
            #[cfg(feature = "test_mode")]
            {
                std::sync::Arc::new(AccessToken::from_id(account_id)).into()
            }

            #[cfg(not(feature = "test_mode"))]
            {
                self.get_access_token(account_id)
                    .await
                    .caused_by(trc::location!())?
                    .into()
            }
        } else {
            None
        };

        let mut last_change_id = None;
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Process creates
        'create: for (id, object) in request.unwrap_create() {
            let Value::Object(mut object) = object else {
                continue;
            };

            let has_body_structure =
                object.contains_key(&Key::Property(EmailProperty::BodyStructure));
            let mut builder = MessageBuilder::new();
            let mut mailboxes = Vec::new();
            let mut keywords = Vec::new();
            let mut received_at = None;

            // Parse body values
            let body_values = object
                .remove(&Key::Property(EmailProperty::BodyValues))
                .and_then(|obj| obj.into_object())
                .and_then(|obj| {
                    let mut values = HashMap::with_capacity(obj.len());
                    for (key, value) in obj.into_vec() {
                        let id = key.into_string();
                        if let Value::Object(mut bv) = value {
                            values.insert(
                                id,
                                bv.remove(&Key::Property(EmailProperty::Value))?
                                    .into_string()?,
                            );
                        } else {
                            return None;
                        }
                    }
                    Some(values)
                });
            let mut size_attachments = 0;

            // Parse properties
            for (property, mut value) in object.into_vec() {
                if let Err(err) = response.resolve_self_references(&mut value) {
                    response.not_created.append(id, err);
                    continue 'create;
                };
                let Key::Property(property) = property else {
                    response.invalid_property_create(id, property.into_owned());
                    continue 'create;
                };

                match (property, value) {
                    (EmailProperty::MailboxIds, Value::Object(ids)) => {
                        mailboxes = ids
                            .into_expanded_boolean_set()
                            .filter_map(|id| {
                                id.try_into_property()?.try_into_id()?.document_id().into()
                            })
                            .collect();
                    }
                    (EmailProperty::Keywords, Value::Object(keywords_)) => {
                        keywords = keywords_
                            .into_expanded_boolean_set()
                            .filter_map(|id| id.try_into_property()?.try_into_keyword())
                            .collect();
                    }
                    (EmailProperty::Pointer(pointer), value) => {
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
                        header @ (EmailProperty::MessageId
                        | EmailProperty::InReplyTo
                        | EmailProperty::References),
                        Value::Array(values),
                    ) => {
                        builder = builder.header(
                            header.as_rfc_header(),
                            MessageId {
                                id: values
                                    .into_iter()
                                    .filter_map(|value| value.into_string())
                                    .collect(),
                            },
                        );
                    }

                    (
                        header @ (EmailProperty::Sender
                        | EmailProperty::From
                        | EmailProperty::To
                        | EmailProperty::Cc
                        | EmailProperty::Bcc
                        | EmailProperty::ReplyTo),
                        value,
                    ) => {
                        if let Some(addresses) = value.try_into_address_list() {
                            builder =
                                builder.header(header.as_rfc_header(), Address::List(addresses));
                        } else {
                            response.invalid_property_create(id, header);
                            continue 'create;
                        }
                    }
                    (EmailProperty::Subject, Value::Str(value)) => {
                        builder = builder.subject(value);
                    }

                    (EmailProperty::ReceivedAt, Value::Element(EmailValue::Date(value))) => {
                        received_at = (value.timestamp() as u64).into();
                    }

                    (EmailProperty::SentAt, Value::Element(EmailValue::Date(value))) => {
                        builder = builder.date(Date::new(value.timestamp()));
                    }

                    (
                        property @ (EmailProperty::TextBody
                        | EmailProperty::HtmlBody
                        | EmailProperty::Attachments
                        | EmailProperty::BodyStructure),
                        value,
                    ) => {
                        // Validate request
                        let (values, expected_content_type) = match property {
                            EmailProperty::BodyStructure => (vec![value], None),
                            EmailProperty::TextBody | EmailProperty::HtmlBody
                                if !has_body_structure =>
                            {
                                let values = value.into_array().unwrap_or_default();
                                if values.len() <= 1 {
                                    (
                                        values,
                                        Some(match property {
                                            EmailProperty::TextBody => "text/plain",
                                            EmailProperty::HtmlBody => "text/html",
                                            _ => unreachable!(),
                                        }),
                                    )
                                } else {
                                    response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_property(property)
                                            .with_description("Only one part is allowed."),
                                    );
                                    continue 'create;
                                }
                            }
                            EmailProperty::Attachments if !has_body_structure => {
                                (value.into_array().unwrap_or_default(), None)
                            }
                            _ => {
                                response.not_created.append(
                                    id,
                                    SetError::invalid_properties()
                                        .with_properties([property, EmailProperty::BodyStructure])
                                        .with_description(
                                            "Cannot set both properties on a same request.",
                                        ),
                                );
                                continue 'create;
                            }
                        };

                        // Iterate parts
                        let mut values_stack = Vec::new();
                        let mut values = values.into_iter();
                        let mut parts = Vec::new();
                        loop {
                            while let Some(value) = values.next() {
                                let mut blob_id = None;
                                let mut part_id = None;
                                let mut content_type = None;
                                let mut content_disposition = None;
                                let mut name = None;
                                let mut charset = None;
                                let mut subparts = None;
                                let mut has_size = false;
                                let mut headers: Vec<(Cow<str>, HeaderType)> = Vec::new();

                                if let Some(obj) = value.into_object() {
                                    for (body_property, value) in obj.into_vec() {
                                        let Key::Property(body_property) = body_property else {
                                            continue;
                                        };

                                        match (body_property, value) {
                                            (EmailProperty::Type, Value::Str(value)) => {
                                                content_type = value.into_owned().into();
                                            }
                                            (EmailProperty::PartId, Value::Str(value)) => {
                                                part_id = value.into_owned().into();
                                            }
                                            (
                                                EmailProperty::BlobId,
                                                Value::Element(EmailValue::BlobId(value)),
                                            ) => {
                                                blob_id = value.into();
                                            }
                                            (EmailProperty::Disposition, Value::Str(value)) => {
                                                content_disposition = value.into_owned().into();
                                            }
                                            (EmailProperty::Name, Value::Str(value)) => {
                                                name = value.into_owned().into();
                                            }
                                            (EmailProperty::Charset, Value::Str(value)) => {
                                                charset = value.into_owned().into();
                                            }
                                            (EmailProperty::Language, Value::Array(values)) => {
                                                headers.push((
                                                    "Content-Language".into(),
                                                    Text::new(
                                                        values
                                                            .into_iter()
                                                            .filter_map(|v| v.into_string())
                                                            .fold(
                                                                String::with_capacity(64),
                                                                |mut h, v| {
                                                                    if !h.is_empty() {
                                                                        h.push_str(", ");
                                                                    }
                                                                    h.push_str(&v);
                                                                    h
                                                                },
                                                            ),
                                                    )
                                                    .into(),
                                                ));
                                            }
                                            (EmailProperty::Cid, Value::Str(value)) => {
                                                headers.push((
                                                    "Content-ID".into(),
                                                    MessageId::new(value).into(),
                                                ));
                                            }
                                            (EmailProperty::Location, Value::Str(value)) => {
                                                headers.push((
                                                    "Content-Location".into(),
                                                    Text::new(value).into(),
                                                ));
                                            }
                                            (EmailProperty::Header(header), Value::Str(value))
                                                if !header.header.eq_ignore_ascii_case(
                                                    "content-transfer-encoding",
                                                ) =>
                                            {
                                                headers.push((
                                                    header.header.into(),
                                                    Raw::from(value).into(),
                                                ));
                                            }
                                            (
                                                EmailProperty::Header(header),
                                                Value::Array(values),
                                            ) if !header.header.eq_ignore_ascii_case(
                                                "content-transfer-encoding",
                                            ) =>
                                            {
                                                for value in values {
                                                    if let Some(value) = value.into_string() {
                                                        headers.push((
                                                            header.header.clone().into(),
                                                            Raw::from(value).into(),
                                                        ));
                                                    }
                                                }
                                            }
                                            (EmailProperty::Headers, _) => {
                                                response.not_created.append(
                                                    id,
                                                    SetError::invalid_properties()
                                                        .with_property((
                                                            property,
                                                            EmailProperty::Headers,
                                                        ))
                                                        .with_description(
                                                            "Headers have to be set individually.",
                                                        ),
                                                );
                                                continue 'create;
                                            }
                                            (EmailProperty::Size, _) => {
                                                has_size = true;
                                            }
                                            (EmailProperty::SubParts, Value::Array(values)) => {
                                                subparts = values.into();
                                            }
                                            (body_property, value) if value != Value::Null => {
                                                response.not_created.append(
                                                    id,
                                                    SetError::invalid_properties()
                                                        .with_property((property, body_property))
                                                        .with_description("Cannot set property."),
                                                );
                                                continue 'create;
                                            }
                                            _ => {}
                                        }
                                    }
                                }

                                // Validate content-type
                                let content_type =
                                    content_type.unwrap_or_else(|| "text/plain".to_string());
                                let is_multipart = content_type.starts_with("multipart/");
                                if is_multipart {
                                    if !matches!(property, EmailProperty::BodyStructure) {
                                        response.not_created.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property((property, EmailProperty::Type))
                                                .with_description("Multiparts can only be set with bodyStructure."),
                                        );
                                        continue 'create;
                                    }
                                } else if expected_content_type
                                    .as_ref()
                                    .is_some_and(|v| v != &content_type)
                                {
                                    response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_property((property, EmailProperty::Type))
                                            .with_description(format!(
                                                "Expected one body part of type \"{}\"",
                                                expected_content_type.unwrap()
                                            )),
                                    );
                                    continue 'create;
                                }

                                // Validate partId/blobId
                                match (blob_id.is_some(), part_id.is_some()) {
                                    (true, true) if !is_multipart => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_properties([(property.clone(), EmailProperty::BlobId), (property, EmailProperty::PartId)])
                                            .with_description(
                                                "Cannot specify both \"partId\" and \"blobId\".",
                                            ),
                                    );
                                        continue 'create;
                                    }
                                    (false, false) if !is_multipart => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_description("Expected a \"partId\" or \"blobId\" field in body part."),
                                    );
                                        continue 'create;
                                    }
                                    (false, true) if !is_multipart && has_size => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_property((property, EmailProperty::Size))
                                            .with_description(
                                                "Cannot specify \"size\" when providing a \"partId\".",
                                            ),
                                    );
                                        continue 'create;
                                    }
                                    (true, _) | (_, true) if is_multipart => {
                                        response.not_created.append(
                                        id,
                                        SetError::invalid_properties()
                                            .with_properties([(property.clone(), EmailProperty::BlobId), (property, EmailProperty::PartId)])
                                            .with_description(
                                                "Cannot specify \"partId\" or \"blobId\" in multipart body parts.",
                                            ),
                                    );
                                        continue 'create;
                                    }
                                    _ => (),
                                }

                                // Set Content-Type and Content-Disposition
                                let mut content_type = ContentType::new(content_type);
                                if !is_multipart {
                                    if let Some(charset) = charset {
                                        if part_id.is_none() {
                                            content_type
                                                .attributes
                                                .push(("charset".into(), charset.into()));
                                        } else {
                                            response.not_created.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property((property, EmailProperty::Charset))
                                                .with_description(
                                                    "Cannot specify a character set when providing a \"partId\".",
                                                ),
                                        );
                                            continue 'create;
                                        }
                                    } else if part_id.is_some() {
                                        content_type
                                            .attributes
                                            .push(("charset".into(), "utf-8".into()));
                                    }
                                    match (content_disposition, name) {
                                        (Some(disposition), Some(filename)) => {
                                            headers.push((
                                                "Content-Disposition".into(),
                                                ContentType::new(disposition)
                                                    .attribute("filename", filename)
                                                    .into(),
                                            ));
                                        }
                                        (Some(disposition), None) => {
                                            headers.push((
                                                "Content-Disposition".into(),
                                                ContentType::new(disposition).into(),
                                            ));
                                        }
                                        (None, Some(filename)) => {
                                            content_type
                                                .attributes
                                                .push(("name".into(), filename.into()));
                                        }
                                        (None, None) => (),
                                    };
                                }
                                headers.push(("Content-Type".into(), content_type.into()));

                                // In test, sort headers to avoid randomness
                                #[cfg(feature = "test_mode")]
                                {
                                    headers.sort_unstable_by(|a, b| match a.0.cmp(&b.0) {
                                        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
                                        ord => ord,
                                    });
                                }
                                // Retrieve contents
                                parts.push(MimePart {
                                    headers,
                                    contents: if !is_multipart {
                                        if let Some(blob_id) = blob_id {
                                            match self.blob_download(&blob_id, access_token).await? {
                                                Some(contents) => {
                                                    BodyPart::Binary(contents.into())
                                                }
                                                None => {
                                                    response.not_created.append(
                                                    id,
                                                    SetError::new(SetErrorType::BlobNotFound).with_description(
                                                        format!("blobId {blob_id} does not exist on this server.")
                                                    ),
                                                );
                                                    continue 'create;
                                                }
                                            }
                                        } else if let Some(part_id) = part_id {
                                            if let Some(contents) =
                                                body_values.as_ref().and_then(|bv| bv.get(&part_id))
                                            {
                                                BodyPart::Text(contents.as_ref().into())
                                            } else {
                                                response.not_created.append(
                                                    id,
                                                    SetError::invalid_properties()
                                                        .with_property((property, EmailProperty::PartId))
                                                        .with_description(format!(
                                                        "Missing body value for partId {part_id:?}"
                                                    )),
                                                );
                                                continue 'create;
                                            }
                                        } else {
                                            unreachable!()
                                        }
                                    } else {
                                        BodyPart::Multipart(vec![])
                                    },
                                });

                                // Check attachment sizes
                                if !is_multipart {
                                    size_attachments += parts.last().unwrap().size();
                                    if self.core.jmap.mail_attachments_max_size > 0
                                        && size_attachments
                                            > self.core.jmap.mail_attachments_max_size
                                    {
                                        response.not_created.append(
                                            id,
                                            SetError::invalid_properties()
                                                .with_property(property)
                                                .with_description(format!(
                                                    "Message exceeds maximum size of {} bytes.",
                                                    self.core.jmap.mail_attachments_max_size
                                                )),
                                        );
                                        continue 'create;
                                    }
                                } else if let Some(subparts) = subparts {
                                    values_stack.push((values, parts));
                                    parts = Vec::with_capacity(subparts.len());
                                    values = subparts.into_iter();
                                    continue;
                                }
                            }

                            if let Some((prev_values, mut prev_parts)) = values_stack.pop() {
                                values = prev_values;
                                prev_parts.last_mut().unwrap().contents =
                                    BodyPart::Multipart(parts);
                                parts = prev_parts;
                            } else {
                                break;
                            }
                        }

                        match property {
                            EmailProperty::TextBody => {
                                builder.text_body = parts.pop();
                            }
                            EmailProperty::HtmlBody => {
                                builder.html_body = parts.pop();
                            }
                            EmailProperty::Attachments => {
                                builder.attachments = parts.into();
                            }
                            _ => {
                                builder.body = parts.pop();
                            }
                        }
                    }

                    (EmailProperty::Header(header), value) => {
                        match builder.build_header(header, value) {
                            Ok(builder_) => {
                                builder = builder_;
                            }
                            Err(header) => {
                                response.invalid_property_create(id, EmailProperty::Header(header));
                                continue 'create;
                            }
                        }
                    }

                    (_, Value::Null) => (),

                    (property, _) => {
                        response.invalid_property_create(id, property);
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
                            .with_description(format!(
                                "mailboxId {} does not exist.",
                                Id::from(*mailbox_id)
                            )),
                    );
                    continue 'create;
                } else if can_add_mailbox_ids
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(*mailbox_id))
                {
                    response.not_created.append(
                        id,
                        SetError::forbidden().with_description(format!(
                            "You are not allowed to add messages to mailbox {}.",
                            Id::from(*mailbox_id)
                        )),
                    );
                    continue 'create;
                }
            }

            // Make sure the message is not empty
            if builder.headers.is_empty()
                && builder.body.is_none()
                && builder.html_body.is_none()
                && builder.text_body.is_none()
                && builder.attachments.is_none()
            {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_description("Message has to have at least one header or body part."),
                );
                continue 'create;
            }

            // In test, sort headers to avoid randomness
            #[cfg(feature = "test_mode")]
            {
                builder
                    .headers
                    .sort_unstable_by(|a, b| match a.0.cmp(&b.0) {
                        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
                        ord => ord,
                    });
            }

            // Build message
            let mut raw_message = Vec::with_capacity((4 * size_attachments / 3) + 1024);
            builder.write_to(&mut raw_message).unwrap_or_default();

            // Ingest message
            match self
                .email_ingest(IngestEmail {
                    raw_message: &raw_message,
                    message: MessageParser::new().parse(&raw_message),
                    blob_hash: None,
                    access_token: import_access_token.as_deref().unwrap_or(access_token),
                    mailbox_ids: mailboxes,
                    keywords,
                    received_at,
                    source: IngestSource::Jmap {
                        train_classifier: true,
                    },
                    session_id: session.session_id,
                })
                .await
            {
                Ok(message) => {
                    last_change_id = message.change_id.into();
                    response
                        .created
                        .insert(id, ingested_into_object(message).into());
                }
                Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                    response.not_created.append(
                        id,
                        SetError::new(SetErrorType::OverQuota)
                            .with_description("You have exceeded your disk quota."),
                    );
                }
                Err(err) => return Err(err),
            }
        }

        // Process updates
        let mut batch = BatchBuilder::new();
        let mut changed_mailboxes: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let mut will_update = Vec::with_capacity(request.update.as_ref().map_or(0, |u| u.len()));
        'update: for (id, object) in request.unwrap_update().into_valid() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain message data
            let document_id = id.document_id();
            let data_ = match self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Email,
                    document_id,
                ))
                .await?
            {
                Some(data) => data,
                None => {
                    response.not_updated.append(id, SetError::not_found());
                    continue 'update;
                }
            };
            let data = data_
                .to_unarchived::<MessageData>()
                .caused_by(trc::location!())?;
            let mut new_data = data.inner.to_builder();

            for (property, mut value) in object.into_expanded_object() {
                if let Err(err) = response.resolve_self_references(&mut value) {
                    response.not_updated.append(id, err);
                    continue 'update;
                };

                match (property, value) {
                    (Key::Property(EmailProperty::MailboxIds), Value::Object(ids)) => {
                        new_data.set_mailboxes(
                            ids.into_expanded_boolean_set()
                                .filter_map(|id| {
                                    UidMailbox::new_unassigned(
                                        id.try_into_property()?.try_into_id()?.document_id(),
                                    )
                                    .into()
                                })
                                .collect(),
                        );
                    }
                    (Key::Property(EmailProperty::Keywords), Value::Object(keywords_)) => {
                        new_data.set_keywords(
                            keywords_
                                .into_expanded_boolean_set()
                                .filter_map(|keyword| {
                                    keyword.try_into_property()?.try_into_keyword()
                                })
                                .collect(),
                        );
                    }
                    (Key::Property(EmailProperty::Pointer(pointer)), value) => {
                        match handle_email_patch(&pointer, value) {
                            PatchResult::SetKeyword(keyword) => {
                                new_data.add_keyword(keyword.clone());
                            }
                            PatchResult::RemoveKeyword(keyword) => {
                                new_data.remove_keyword(keyword);
                            }
                            PatchResult::AddMailbox(id) => {
                                new_data.add_mailbox(UidMailbox::new_unassigned(id));
                            }
                            PatchResult::RemoveMailbox(id) => {
                                new_data.remove_mailbox(id);
                            }
                            PatchResult::Invalid(set_error) => {
                                response.not_updated.append(id, set_error);
                                continue 'update;
                            }
                        }
                    }
                    (property, _) => {
                        response.invalid_property_update(id, property.into_owned());
                        continue 'update;
                    }
                }
            }

            let has_keyword_changes = new_data.has_keyword_changes(data.inner);
            let has_mailbox_changes = new_data.has_mailbox_changes(data.inner);
            if !has_keyword_changes && !has_mailbox_changes {
                response.updated.append(id, None);
                continue 'update;
            }

            // Process keywords
            let mut train_spam = None;
            if has_keyword_changes {
                // Verify permissions on shared accounts
                if can_modify_mailbox_ids.as_ref().is_some_and(|ids| {
                    !new_data
                        .mailboxes
                        .iter()
                        .any(|mb| ids.contains(mb.mailbox_id))
                }) {
                    response.not_updated.append(
                        id,
                        SetError::forbidden()
                            .with_description("You are not allowed to modify keywords."),
                    );
                    continue 'update;
                }

                // Process keyword changes
                let mut changed_seen = false;
                for keyword in new_data.added_keywords(data.inner) {
                    match keyword {
                        Keyword::Seen => {
                            changed_seen = true;
                        }
                        Keyword::Junk => {
                            train_spam = Some(true);
                        }
                        Keyword::NotJunk => {
                            train_spam = Some(false);
                        }
                        _ => {}
                    }
                }
                for keyword in new_data.removed_keywords(data.inner) {
                    match keyword {
                        ArchivedKeyword::Seen => {
                            changed_seen = true;
                        }
                        ArchivedKeyword::Junk if train_spam.is_none() => {
                            train_spam = Some(false);
                        }
                        _ => {}
                    }
                }

                // Set all current mailboxes as changed if the Seen tag changed
                if changed_seen {
                    for mailbox_id in new_data.mailboxes.iter() {
                        changed_mailboxes.insert(mailbox_id.mailbox_id, Vec::new());
                    }
                }
            }

            // Process mailboxes
            if has_mailbox_changes {
                // Make sure the message is at least in one mailbox
                if new_data.mailboxes.is_empty() {
                    response.not_updated.append(
                        id,
                        SetError::invalid_properties()
                            .with_property(EmailProperty::MailboxIds)
                            .with_description("Message has to belong to at least one mailbox."),
                    );
                    continue 'update;
                }

                // Make sure all new mailboxIds are valid
                for mailbox_id in new_data.added_mailboxes(data.inner) {
                    if cache.has_mailbox_id(&mailbox_id.mailbox_id) {
                        // Verify permissions on shared accounts
                        if can_add_mailbox_ids
                            .as_ref()
                            .is_none_or(|ids| ids.contains(mailbox_id.mailbox_id))
                        {
                            if mailbox_id.mailbox_id == JUNK_ID {
                                train_spam = Some(true);
                            }

                            changed_mailboxes.insert(mailbox_id.mailbox_id, Vec::new());
                        } else {
                            response.not_updated.append(
                                id,
                                SetError::forbidden().with_description(format!(
                                    "You are not allowed to add messages to mailbox {}.",
                                    Id::from(mailbox_id.mailbox_id)
                                )),
                            );
                            continue 'update;
                        }
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(EmailProperty::MailboxIds)
                                .with_description(format!(
                                    "mailboxId {} does not exist.",
                                    Id::from(mailbox_id.mailbox_id)
                                )),
                        );
                        continue 'update;
                    }
                }

                // Add all removed mailboxes to change list
                for mailbox_id in new_data.removed_mailboxes(data.inner) {
                    // Verify permissions on shared accounts
                    if can_delete_mailbox_ids
                        .as_ref()
                        .is_none_or(|ids| ids.contains(u32::from(mailbox_id.mailbox_id)))
                    {
                        if mailbox_id.mailbox_id == JUNK_ID
                            && !new_data
                                .mailboxes
                                .iter()
                                .any(|mb| mb.mailbox_id == TRASH_ID)
                        {
                            train_spam = Some(false);
                        }

                        changed_mailboxes
                            .entry(mailbox_id.mailbox_id.to_native())
                            .or_default()
                            .push(mailbox_id.uid.to_native());
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(format!(
                                "You are not allowed to delete messages from mailbox {}.",
                                mailbox_id.mailbox_id
                            )),
                        );
                        continue 'update;
                    }
                }

                // Obtain IMAP UIDs for added mailboxes
                let ids = self
                    .assign_email_ids(
                        account_id,
                        new_data
                            .mailboxes
                            .iter()
                            .filter(|m| m.uid == 0)
                            .map(|m| m.mailbox_id),
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?;
                for (uid_mailbox, uid) in new_data
                    .mailboxes
                    .iter_mut()
                    .filter(|m| m.uid == 0)
                    .zip(ids)
                {
                    uid_mailbox.uid = uid;
                }
            }

            // Write changes
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .with_document(document_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_current(data)
                        .with_changes(new_data.seal()),
                )
                .caused_by(trc::location!())?;

            if let Some(train_spam) = train_spam {
                self.add_account_spam_sample(
                    &mut batch,
                    account_id,
                    document_id,
                    train_spam,
                    session.session_id,
                )
                .await
                .caused_by(trc::location!())?;
            }

            batch.commit_point();
            will_update.push(id);
        }

        if !batch.is_empty() {
            // Log mailbox changes
            for (parent_id, deleted_uids) in changed_mailboxes {
                batch.log_container_property_change(SyncCollection::Email, parent_id);
                for deleted_uid in deleted_uids {
                    batch.log_vanished_item(VanishedCollection::Email, (parent_id, deleted_uid));
                }
            }

            match self
                .commit_batch(batch)
                .await
                .and_then(|ids| ids.last_change_id(account_id))
            {
                Ok(change_id) => {
                    last_change_id = change_id.into();

                    // Add to updated list
                    for id in will_update {
                        response.updated.append(id, None);
                    }
                }
                Err(err) if err.is_assertion_failure() => {
                    for id in will_update {
                        response.not_updated.append(
                            id,
                            SetError::forbidden().with_description(
                                "Another process modified this message, please try again.",
                            ),
                        );
                    }
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        // Process deletions
        if !will_destroy.is_empty() {
            let email_ids = cache.email_document_ids();
            let can_destroy_message_ids = if access_token.is_shared(account_id) {
                cache.shared_messages(access_token, Acl::RemoveItems).into()
            } else {
                None
            };
            let mut destroy_ids = RoaringBitmap::new();
            for destroy_id in will_destroy {
                let document_id = destroy_id.document_id();

                if email_ids.contains(document_id) {
                    if !matches!(&can_destroy_message_ids, Some(ids) if !ids.contains(document_id))
                    {
                        destroy_ids.insert(document_id);
                        response.destroyed.push(destroy_id);
                    } else {
                        response.not_destroyed.append(
                            destroy_id,
                            SetError::forbidden()
                                .with_description("You are not allowed to delete this message."),
                        );
                    }
                } else {
                    response
                        .not_destroyed
                        .append(destroy_id, SetError::not_found());
                }
            }

            if !destroy_ids.is_empty() {
                // Batch delete messages
                let mut batch = BatchBuilder::new();
                let not_destroyed = self
                    .emails_delete(
                        account_id,
                        access_token.tenant_id(),
                        &mut batch,
                        destroy_ids,
                    )
                    .await?;
                if !batch.is_empty() {
                    last_change_id = self
                        .commit_batch(batch)
                        .await
                        .and_then(|ids| ids.last_change_id(account_id))
                        .caused_by(trc::location!())?
                        .into();
                    self.notify_task_queue();
                }

                // Mark messages that were not found as not destroyed (this should not occur in practice)
                if !not_destroyed.is_empty() {
                    let mut destroyed = Vec::with_capacity(response.destroyed.len());

                    for destroy_id in response.destroyed {
                        if not_destroyed.contains(destroy_id.document_id()) {
                            response
                                .not_destroyed
                                .append(destroy_id, SetError::not_found());
                        } else {
                            destroyed.push(destroy_id);
                        }
                    }

                    response.destroyed = destroyed;
                }
            }
        }

        // Update state
        if let Some(change_id) = last_change_id {
            if response.updated.is_empty() && response.destroyed.is_empty() {
                // Message ingest does not broadcast state changes
                self.broadcast_push_notification(PushNotification::StateChange(
                    StateChange::new(account_id)
                        .with_change_id(change_id)
                        .with_change(DataType::Email)
                        .with_change(DataType::Mailbox)
                        .with_change(DataType::Thread),
                ))
                .await;
            }

            response.new_state = State::Exact(change_id).into();
        }

        Ok(response)
    }
}
