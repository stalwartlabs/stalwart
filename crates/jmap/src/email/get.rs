/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::JmapCacheState;
use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        body::{ToBodyPart, truncate_html, truncate_plain},
        headers::{HeaderToValue, IntoForm},
        metadata::{
            ArchivedMessageMetadata, ArchivedMessageMetadataContents, ArchivedMessageMetadataPart,
            ArchivedMetadataPartType, MessageMetadata, MetadataHeaderName, PART_ENCODING_PROBLEM,
        },
    },
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::email::{Email, EmailProperty, EmailValue, HeaderForm},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use mail_parser::HeaderValue;
use std::future::Future;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::{AddContext, StoreEvent};
use types::{
    acl::Acl,
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::Collection,
    field::EmailField,
    id::Id,
    keyword::HASATTACHMENT,
};
use utils::chained_bytes::ChainedBytes;

pub trait EmailGet: Sync + Send {
    fn email_get(
        &self,
        request: GetRequest<Email>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Email>>> + Send;
}

impl EmailGet for Server {
    async fn email_get(
        &self,
        mut request: GetRequest<Email>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Email>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            EmailProperty::Id,
            EmailProperty::BlobId,
            EmailProperty::ThreadId,
            EmailProperty::MailboxIds,
            EmailProperty::Keywords,
            EmailProperty::Size,
            EmailProperty::ReceivedAt,
            EmailProperty::MessageId,
            EmailProperty::InReplyTo,
            EmailProperty::References,
            EmailProperty::Sender,
            EmailProperty::From,
            EmailProperty::To,
            EmailProperty::Cc,
            EmailProperty::Bcc,
            EmailProperty::ReplyTo,
            EmailProperty::Subject,
            EmailProperty::SentAt,
            EmailProperty::HasAttachment,
            EmailProperty::Preview,
            EmailProperty::BodyValues,
            EmailProperty::TextBody,
            EmailProperty::HtmlBody,
            EmailProperty::Attachments,
        ]);
        let body_properties = request
            .arguments
            .body_properties
            .map(|v| v.into_valid().collect())
            .unwrap_or_else(|| {
                vec![
                    EmailProperty::PartId,
                    EmailProperty::BlobId,
                    EmailProperty::Size,
                    EmailProperty::Name,
                    EmailProperty::Type,
                    EmailProperty::Charset,
                    EmailProperty::Disposition,
                    EmailProperty::Cid,
                    EmailProperty::Language,
                    EmailProperty::Location,
                ]
            });
        let fetch_text_body_values = request.arguments.fetch_text_body_values.unwrap_or(false);
        let fetch_html_body_values = request.arguments.fetch_html_body_values.unwrap_or(false);
        let fetch_all_body_values = request.arguments.fetch_all_body_values.unwrap_or(false);
        let max_body_value_bytes = request.arguments.max_body_value_bytes.unwrap_or(0);

        let account_id = request.account_id.document_id();
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let message_ids = if access_token.is_member(account_id) {
            cache.email_document_ids()
        } else {
            cache.shared_messages(access_token, Acl::ReadItems)
        };

        let ids = if let Some(ids) = ids {
            ids
        } else {
            cache
                .emails
                .items
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(|item| Id::from_parts(item.thread_id, item.document_id))
                .collect()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        // Check which properties can be answered from the message cache alone
        let mut needs_body = false;
        let mut needs_metadata = false;
        for property in &properties {
            match property {
                EmailProperty::Id
                | EmailProperty::ThreadId
                | EmailProperty::MailboxIds
                | EmailProperty::Keywords
                | EmailProperty::Size
                | EmailProperty::ReceivedAt
                | EmailProperty::HasAttachment => (),
                EmailProperty::BodyValues
                | EmailProperty::TextBody
                | EmailProperty::HtmlBody
                | EmailProperty::Attachments
                | EmailProperty::BodyStructure => {
                    needs_body = true;
                    needs_metadata = true;
                }
                _ => {
                    needs_metadata = true;
                }
            }
        }

        for id in ids {
            // Obtain the email object
            if !message_ids.contains(id.document_id()) {
                response.push_not_found(id);
                continue;
            }

            // Obtain message data
            let data = match cache.email_by_id(&id.document_id()) {
                Some(data) => data,
                None => {
                    response.push_not_found(id);
                    continue;
                }
            };

            // Obtain the message metadata if any of the requested properties need it
            let metadata_;
            let raw_body;
            let message = if needs_metadata {
                metadata_ = match self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::immutable(
                        account_id,
                        Collection::Email,
                        id.document_id(),
                        EmailField::Metadata,
                    ))
                    .await?
                {
                    Some(metadata) => metadata,
                    None => {
                        response.push_not_found(id);
                        continue;
                    }
                };
                let metadata = metadata_
                    .unarchive::<MessageMetadata>()
                    .caused_by(trc::location!())?;

                // Retrieve raw message if needed
                let blob_hash = BlobHash::from(&metadata.blob_hash);
                let mut raw_message = ChainedBytes::new(metadata.raw_headers.as_ref());
                if needs_body {
                    raw_body = self
                        .blob_store()
                        .get_blob(blob_hash.as_slice(), 0..usize::MAX)
                        .await?;

                    if let Some(raw_body) = &raw_body {
                        raw_message.append(
                            raw_body
                                .get(metadata.blob_body_offset.to_native() as usize..)
                                .unwrap_or_default(),
                        );
                    } else {
                        trc::event!(
                            Store(StoreEvent::NotFound),
                            AccountId = account_id,
                            DocumentId = id.document_id(),
                            Collection = Collection::Email,
                            BlobId = blob_hash.to_hex(),
                            Details = "Blob not found.",
                            CausedBy = trc::location!(),
                        );

                        response.push_not_found(id);
                        continue;
                    }
                }

                let contents = &metadata.contents[0];
                let root_part = &contents.parts[0];

                Some(MessageContext {
                    metadata,
                    contents,
                    root_part,
                    raw_message,
                    blob_id: BlobId {
                        hash: blob_hash,
                        class: BlobClass::Linked {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: id.document_id(),
                        },
                        section: None,
                    },
                    blob_body_offset: metadata.blob_body_offset.to_native() as isize
                        - root_part.offset_body.to_native() as isize,
                })
            } else {
                None
            };

            // Prepare response
            let mut email: Map<'_, EmailProperty, EmailValue> =
                Map::with_capacity(properties.len());
            for property in &properties {
                match (property, &message) {
                    (EmailProperty::Id, _) => {
                        email.insert_unchecked(EmailProperty::Id, Id::from(*id));
                    }
                    (EmailProperty::ThreadId, _) => {
                        email.insert_unchecked(EmailProperty::ThreadId, Id::from(id.prefix_id()));
                    }
                    (EmailProperty::MailboxIds, _) => {
                        let mut obj = Map::with_capacity(data.mailboxes.len());
                        for id in data.mailboxes.iter() {
                            debug_assert!(id.uid != 0);
                            obj.insert_unchecked(
                                EmailProperty::IdValue(Id::from(id.mailbox_id)),
                                true,
                            );
                        }

                        email.insert_unchecked(property.clone(), Value::Object(obj));
                    }
                    (EmailProperty::Keywords, _) => {
                        let mut obj = Map::with_capacity(2);
                        for keyword in cache.expand_keywords(data) {
                            obj.insert_unchecked(EmailProperty::Keyword(keyword), true);
                        }
                        email.insert_unchecked(property.clone(), Value::Object(obj));
                    }
                    (EmailProperty::Size, _) => {
                        email.insert_unchecked(EmailProperty::Size, data.size);
                    }
                    (EmailProperty::ReceivedAt, _) => {
                        email.insert_unchecked(
                            EmailProperty::ReceivedAt,
                            EmailValue::Date(UTCDate::from_timestamp(data.received_at as i64)),
                        );
                    }
                    (EmailProperty::HasAttachment, _) => {
                        email.insert_unchecked(
                            EmailProperty::HasAttachment,
                            (data.keywords & 1 << HASATTACHMENT) != 0,
                        );
                    }
                    (EmailProperty::BlobId, Some(message)) => {
                        email.insert_unchecked(EmailProperty::BlobId, message.blob_id.clone());
                    }
                    (EmailProperty::Preview, Some(message)) => {
                        if !message.metadata.preview.is_empty() {
                            email.insert_unchecked(
                                EmailProperty::Preview,
                                message.metadata.preview.to_string(),
                            );
                        }
                    }
                    (EmailProperty::Subject, Some(message)) => {
                        email.insert_unchecked(
                            EmailProperty::Subject,
                            message
                                .root_part
                                .header_value(&MetadataHeaderName::Subject)
                                .map(|value| HeaderValue::from(value).into_form(&HeaderForm::Text))
                                .unwrap_or_default(),
                        );
                    }
                    (EmailProperty::SentAt, Some(message)) => {
                        email.insert_unchecked(
                            EmailProperty::SentAt,
                            message
                                .root_part
                                .header_value(&MetadataHeaderName::Date)
                                .map(|value| HeaderValue::from(value).into_form(&HeaderForm::Date))
                                .unwrap_or_default(),
                        );
                    }
                    (
                        EmailProperty::MessageId
                        | EmailProperty::InReplyTo
                        | EmailProperty::References,
                        Some(message),
                    ) => {
                        email.insert_unchecked(
                            property.clone(),
                            message
                                .root_part
                                .header_value(&match property {
                                    EmailProperty::MessageId => MetadataHeaderName::MessageId,
                                    EmailProperty::InReplyTo => MetadataHeaderName::InReplyTo,
                                    EmailProperty::References => MetadataHeaderName::References,
                                    _ => unreachable!(),
                                })
                                .map(|value| {
                                    HeaderValue::from(value).into_form(&HeaderForm::MessageIds)
                                })
                                .unwrap_or_default(),
                        );
                    }

                    (
                        EmailProperty::Sender
                        | EmailProperty::From
                        | EmailProperty::To
                        | EmailProperty::Cc
                        | EmailProperty::Bcc
                        | EmailProperty::ReplyTo,
                        Some(message),
                    ) => {
                        email.insert_unchecked(
                            property.clone(),
                            message
                                .root_part
                                .header_value(&match property {
                                    EmailProperty::Sender => MetadataHeaderName::Sender,
                                    EmailProperty::From => MetadataHeaderName::From,
                                    EmailProperty::To => MetadataHeaderName::To,
                                    EmailProperty::Cc => MetadataHeaderName::Cc,
                                    EmailProperty::Bcc => MetadataHeaderName::Bcc,
                                    EmailProperty::ReplyTo => MetadataHeaderName::ReplyTo,
                                    _ => unreachable!(),
                                })
                                .map(|value| {
                                    HeaderValue::from(value).into_form(&HeaderForm::Addresses)
                                })
                                .unwrap_or_default(),
                        );
                    }
                    (EmailProperty::Header(_), Some(message)) => {
                        email.insert_unchecked(
                            property.clone(),
                            message
                                .root_part
                                .header_to_value(property, &message.raw_message),
                        );
                    }
                    (EmailProperty::Headers, Some(message)) => {
                        email.insert_unchecked(
                            EmailProperty::Headers,
                            message.root_part.headers_to_value(&message.raw_message),
                        );
                    }
                    (
                        EmailProperty::TextBody
                        | EmailProperty::HtmlBody
                        | EmailProperty::Attachments,
                        Some(message),
                    ) => {
                        let list = match property {
                            EmailProperty::TextBody => &message.contents.text_body,
                            EmailProperty::HtmlBody => &message.contents.html_body,
                            EmailProperty::Attachments => &message.contents.attachments,
                            _ => unreachable!(),
                        }
                        .iter();
                        email.insert_unchecked(
                            property.clone(),
                            list.map(|part_id| {
                                message.contents.to_body_part(
                                    u16::from(part_id) as u32,
                                    &body_properties,
                                    &message.raw_message,
                                    &message.blob_id,
                                    message.blob_body_offset,
                                )
                            })
                            .collect::<Vec<_>>(),
                        );
                    }
                    (EmailProperty::BodyStructure, Some(message)) => {
                        email.insert_unchecked(
                            EmailProperty::BodyStructure,
                            message.contents.to_body_part(
                                0,
                                &body_properties,
                                &message.raw_message,
                                &message.blob_id,
                                message.blob_body_offset,
                            ),
                        );
                    }
                    (EmailProperty::BodyValues, Some(message)) => {
                        let mut body_values = Map::with_capacity(message.contents.parts.len());
                        for (part_id, part) in message.contents.parts.iter().enumerate() {
                            if ((message.contents.is_html_part(part_id as u16)
                                && (fetch_all_body_values || fetch_html_body_values))
                                || (message.contents.is_text_part(part_id as u16)
                                    && (fetch_all_body_values || fetch_text_body_values)))
                                && matches!(
                                    part.body,
                                    ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html
                                )
                            {
                                let contents = part.decode_contents(&message.raw_message);

                                let (is_truncated, value) = match &part.body {
                                    ArchivedMetadataPartType::Text => {
                                        truncate_plain(contents.as_str(), max_body_value_bytes)
                                    }
                                    ArchivedMetadataPartType::Html => {
                                        truncate_html(contents.as_str(), max_body_value_bytes)
                                    }
                                    _ => unreachable!(),
                                };

                                body_values.insert_unchecked(
                                    Key::Owned(part_id.to_string()),
                                    Map::with_capacity(3)
                                        .with_key_value(
                                            EmailProperty::IsEncodingProblem,
                                            (part.flags & PART_ENCODING_PROBLEM) != 0,
                                        )
                                        .with_key_value(EmailProperty::IsTruncated, is_truncated)
                                        .with_key_value(EmailProperty::Value, value),
                                );
                            }
                        }
                        email.insert_unchecked(EmailProperty::BodyValues, body_values);
                    }

                    (_, Some(_)) => {
                        return Err(trc::JmapEvent::InvalidArguments
                            .into_err()
                            .details(format!("Invalid property {property:?}")));
                    }
                    (_, None) => {
                        debug_assert!(
                            false,
                            "Property {property:?} requires metadata but none was fetched."
                        );
                    }
                }
            }
            response.list.push(email.into());
        }

        Ok(response)
    }
}

struct MessageContext<'x> {
    metadata: &'x ArchivedMessageMetadata,
    contents: &'x ArchivedMessageMetadataContents,
    root_part: &'x ArchivedMessageMetadataPart,
    raw_message: ChainedBytes<'x>,
    blob_id: BlobId,
    blob_body_offset: isize,
}
