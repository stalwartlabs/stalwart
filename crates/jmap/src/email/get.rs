/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    body::{ToBodyPart, truncate_html, truncate_plain},
    headers::IntoForm,
};
use crate::{changes::state::JmapCacheState, email::headers::HeaderToValue};
use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::metadata::{ArchivedMetadataPartType, MessageMetadata},
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::email::{Email, EmailProperty, EmailValue, HeaderForm},
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use mail_parser::{ArchivedHeaderName, HeaderValue, core::rkyv::ArchivedGetHeader};
use std::{borrow::Cow, future::Future};
use trc::{AddContext, StoreEvent};
use types::{
    acl::Acl,
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::Collection,
    field::EmailField,
    id::Id,
};

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
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
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
            not_found: vec![],
        };

        // Check if we need to fetch the raw headers or body
        let mut needs_body = false;
        for property in &properties {
            if matches!(
                property,
                EmailProperty::BodyValues
                    | EmailProperty::TextBody
                    | EmailProperty::HtmlBody
                    | EmailProperty::Attachments
                    | EmailProperty::BodyStructure
            ) {
                needs_body = true;
                break;
            }
        }

        for id in ids {
            // Obtain the email object
            if !message_ids.contains(id.document_id()) {
                response.not_found.push(id);
                continue;
            }
            let metadata_ = match self
                .get_archive_by_property(
                    account_id,
                    Collection::Email,
                    id.document_id(),
                    EmailField::Metadata.into(),
                )
                .await?
            {
                Some(metadata) => metadata,
                None => {
                    response.not_found.push(id);
                    continue;
                }
            };
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;

            // Obtain message data
            let data = match cache.email_by_id(&id.document_id()) {
                Some(data) => data,
                None => {
                    response.not_found.push(id);
                    continue;
                }
            };

            // Retrieve raw message if needed
            let blob_hash = BlobHash::from(&metadata.blob_hash);
            let raw_message: Cow<[u8]> = if needs_body {
                if let Some(raw_message) = self
                    .blob_store()
                    .get_blob(blob_hash.as_slice(), 0..usize::MAX)
                    .await?
                {
                    raw_message.into()
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

                    response.not_found.push(id);
                    continue;
                }
            } else {
                metadata.raw_headers.as_slice().into()
            };
            let blob_id = BlobId {
                hash: blob_hash,
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id: id.document_id(),
                },
                section: None,
            };

            // Prepare response
            let mut email: Map<'_, EmailProperty, EmailValue> =
                Map::with_capacity(properties.len());
            let contents = &metadata.contents[0];
            let root_part = &contents.parts[0];
            for property in &properties {
                match property {
                    EmailProperty::Id => {
                        email.insert_unchecked(EmailProperty::Id, Id::from(*id));
                    }
                    EmailProperty::ThreadId => {
                        email.insert_unchecked(EmailProperty::ThreadId, Id::from(id.prefix_id()));
                    }
                    EmailProperty::BlobId => {
                        email.insert_unchecked(EmailProperty::BlobId, blob_id.clone());
                    }
                    EmailProperty::MailboxIds => {
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
                    EmailProperty::Keywords => {
                        let mut obj = Map::with_capacity(2);
                        for keyword in cache.expand_keywords(data) {
                            obj.insert_unchecked(EmailProperty::Keyword(keyword), true);
                        }
                        email.insert_unchecked(property.clone(), Value::Object(obj));
                    }
                    EmailProperty::Size => {
                        email.insert_unchecked(EmailProperty::Size, u32::from(metadata.size));
                    }
                    EmailProperty::ReceivedAt => {
                        email.insert_unchecked(
                            EmailProperty::ReceivedAt,
                            EmailValue::Date(UTCDate::from_timestamp(
                                u64::from(metadata.received_at) as i64,
                            )),
                        );
                    }
                    EmailProperty::Preview => {
                        if !metadata.preview.is_empty() {
                            email.insert_unchecked(
                                EmailProperty::Preview,
                                metadata.preview.to_string(),
                            );
                        }
                    }
                    EmailProperty::HasAttachment => {
                        email.insert_unchecked(
                            EmailProperty::HasAttachment,
                            metadata.has_attachments,
                        );
                    }
                    EmailProperty::Subject => {
                        email.insert_unchecked(
                            EmailProperty::Subject,
                            root_part
                                .headers
                                .header_value(&ArchivedHeaderName::Subject)
                                .map(|value| HeaderValue::from(value).into_form(&HeaderForm::Text))
                                .unwrap_or_default(),
                        );
                    }
                    EmailProperty::SentAt => {
                        email.insert_unchecked(
                            EmailProperty::SentAt,
                            root_part
                                .headers
                                .header_value(&ArchivedHeaderName::Date)
                                .map(|value| HeaderValue::from(value).into_form(&HeaderForm::Date))
                                .unwrap_or_default(),
                        );
                    }
                    EmailProperty::MessageId
                    | EmailProperty::InReplyTo
                    | EmailProperty::References => {
                        email.insert_unchecked(
                            property.clone(),
                            root_part
                                .headers
                                .header_value(&match property {
                                    EmailProperty::MessageId => ArchivedHeaderName::MessageId,
                                    EmailProperty::InReplyTo => ArchivedHeaderName::InReplyTo,
                                    EmailProperty::References => ArchivedHeaderName::References,
                                    _ => unreachable!(),
                                })
                                .map(|value| {
                                    HeaderValue::from(value).into_form(&HeaderForm::MessageIds)
                                })
                                .unwrap_or_default(),
                        );
                    }

                    EmailProperty::Sender
                    | EmailProperty::From
                    | EmailProperty::To
                    | EmailProperty::Cc
                    | EmailProperty::Bcc
                    | EmailProperty::ReplyTo => {
                        email.insert_unchecked(
                            property.clone(),
                            root_part
                                .headers
                                .header_value(&match property {
                                    EmailProperty::Sender => ArchivedHeaderName::Sender,
                                    EmailProperty::From => ArchivedHeaderName::From,
                                    EmailProperty::To => ArchivedHeaderName::To,
                                    EmailProperty::Cc => ArchivedHeaderName::Cc,
                                    EmailProperty::Bcc => ArchivedHeaderName::Bcc,
                                    EmailProperty::ReplyTo => ArchivedHeaderName::ReplyTo,
                                    _ => unreachable!(),
                                })
                                .map(|value| {
                                    HeaderValue::from(value).into_form(&HeaderForm::Addresses)
                                })
                                .unwrap_or_default(),
                        );
                    }
                    EmailProperty::Header(_) => {
                        email.insert_unchecked(
                            property.clone(),
                            root_part.headers.header_to_value(property, &raw_message),
                        );
                    }
                    EmailProperty::Headers => {
                        email.insert_unchecked(
                            EmailProperty::Headers,
                            root_part.headers.headers_to_value(&raw_message),
                        );
                    }
                    EmailProperty::TextBody
                    | EmailProperty::HtmlBody
                    | EmailProperty::Attachments => {
                        let list = match property {
                            EmailProperty::TextBody => &contents.text_body,
                            EmailProperty::HtmlBody => &contents.html_body,
                            EmailProperty::Attachments => &contents.attachments,
                            _ => unreachable!(),
                        }
                        .iter();
                        email.insert_unchecked(
                            property.clone(),
                            list.map(|part_id| {
                                contents.to_body_part(
                                    u16::from(part_id) as u32,
                                    &body_properties,
                                    &raw_message,
                                    &blob_id,
                                )
                            })
                            .collect::<Vec<_>>(),
                        );
                    }
                    EmailProperty::BodyStructure => {
                        email.insert_unchecked(
                            EmailProperty::BodyStructure,
                            contents.to_body_part(0, &body_properties, &raw_message, &blob_id),
                        );
                    }
                    EmailProperty::BodyValues => {
                        let mut body_values = Map::with_capacity(contents.parts.len());
                        for (part_id, part) in contents.parts.iter().enumerate() {
                            if ((contents.is_html_part(part_id as u16)
                                && (fetch_all_body_values || fetch_html_body_values))
                                || (contents.is_text_part(part_id as u16)
                                    && (fetch_all_body_values || fetch_text_body_values)))
                                && matches!(
                                    part.body,
                                    ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html
                                )
                            {
                                let contents = part.decode_contents(&raw_message);

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
                                            part.is_encoding_problem,
                                        )
                                        .with_key_value(EmailProperty::IsTruncated, is_truncated)
                                        .with_key_value(EmailProperty::Value, value),
                                );
                            }
                        }
                        email.insert_unchecked(EmailProperty::BodyValues, body_values);
                    }

                    _ => {
                        return Err(trc::JmapEvent::InvalidArguments
                            .into_err()
                            .details(format!("Invalid property {property:?}")));
                    }
                }
            }
            response.list.push(email.into());
        }

        Ok(response)
    }
}
