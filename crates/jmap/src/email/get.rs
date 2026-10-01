/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::metadata::{MetadataDocuments, MetadataType, ObjectMetadata, select_properties},
    changes::state::{JmapCacheState, MetadataStateManager},
};
use common::{Server, auth::AccessToken};
use compact_str::format_compact;
use email::{
    cache::{
        MessageCacheFetch,
        email::{MessageAccess, MessageCacheAccess},
        mailbox::MailboxCacheAccess,
    },
    message::{
        jmap::{BodyValueOptions, EmailNeeds, EmailRender, HeaderNeeds},
        metadata::{MetadataRow, MetadataStructure},
    },
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse, all_ids},
    object::email::{Email, EmailProperty, EmailValue},
    request::{IntoValid, capability::CapabilityIds},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use store::ValueKey;
use trc::{AddContext, StoreEvent};
use types::{
    acl::Acl,
    blob::{BlobClass, BlobId},
    collection::Collection,
    field::EmailField,
    id::Id,
    keyword::HASATTACHMENT,
};

pub trait EmailGet: Sync + Send {
    fn email_get(
        &self,
        request: GetRequest<Email>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> impl Future<Output = trc::Result<GetResponse<Email>>> + Send;
}

impl EmailGet for Server {
    async fn email_get(
        &self,
        mut request: GetRequest<Email>,
        access_token: &AccessToken,
        using: CapabilityIds,
    ) -> trc::Result<GetResponse<Email>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let is_default = request.properties.is_none();
        let (properties, selection) = select_properties(
            &mut request,
            &[
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
            ],
            using,
        )?;
        let object_metadata = ObjectMetadata::new(self, access_token, using, MetadataType::Email);
        let viewer = object_metadata.viewer();
        let metadata = if is_default {
            None
        } else {
            object_metadata.get(selection)
        };
        let metadata_slots = metadata.as_ref().map_or(0, |get| {
            usize::from(get.wants_shared()) + usize::from(get.wants_private())
        });
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
        let options = BodyValueOptions {
            fetch_text: request.arguments.fetch_text_body_values.unwrap_or(false),
            fetch_html: request.arguments.fetch_html_body_values.unwrap_or(false),
            fetch_all: request.arguments.fetch_all_body_values.unwrap_or(false),
            max_bytes: request.arguments.max_body_value_bytes.unwrap_or(0),
        };
        let mut needs_metadata = false;
        for property in &properties {
            let is_cached = matches!(
                property,
                EmailProperty::Id
                    | EmailProperty::ThreadId
                    | EmailProperty::MailboxIds
                    | EmailProperty::Keywords
                    | EmailProperty::Size
                    | EmailProperty::ReceivedAt
                    | EmailProperty::HasAttachment
            );
            if !is_cached && (!EmailRender::renders(property) || !property.is_allowed_form()) {
                return Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details(format_compact!("Invalid property {property:?}")));
            }
            needs_metadata |= !is_cached;
        }
        if let Some(property) = body_properties
            .iter()
            .find(|property| !property.is_allowed_form())
        {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details(format_compact!("Invalid property {property:?}")));
        }
        let needs = EmailNeeds::new(&properties, &body_properties, &options);
        let header_needs = HeaderNeeds::new(&properties, &body_properties);

        let account_id = request.account_id.document_id();
        let sampled = self
            .viewer_change_id(viewer, account_id, Collection::Email)
            .await?;
        let cache = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let access = if access_token.is_member(account_id) {
            MessageAccess::All
        } else {
            MessageAccess::Mailboxes(cache.shared_mailboxes(access_token, Acl::ReadItems))
        };

        let ids = if let Some(ids) = ids {
            ids
        } else {
            all_ids(
                cache
                    .emails
                    .iter()
                    .filter(|item| access.allows(*item))
                    .map(|item| Id::from_parts(item.thread_id(), item.document_id())),
                self.core.jmap.get_max_objects,
            )?
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: sampled.state(cache.get_state(false)).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };
        let mut metadata_values = match &metadata {
            Some(metadata) => {
                let mut documents = MetadataDocuments::default();
                for document_id in ids.iter().map(Id::document_id) {
                    if let Some(email) = cache
                        .email_by_id(&document_id)
                        .filter(|email| access.allows(*email))
                    {
                        documents.insert(document_id, cache.metadata_kinds(email));
                    }
                }
                Some(
                    object_metadata
                        .load::<EmailProperty, EmailValue>(self, account_id, metadata, &documents)
                        .await?,
                )
            }
            None => None,
        };

        for id in ids {
            // Obtain message data
            let Some(data) = cache
                .email_by_id(&id.document_id())
                .filter(|data| access.allows(*data))
            else {
                response.push_not_found(id);
                continue;
            };

            let metadata_key = ValueKey::immutable(
                account_id,
                Collection::Email,
                id.document_id(),
                EmailField::Metadata,
            );
            let row;
            let structure;
            let raw_headers;
            let mut blob = None;
            let render = if needs_metadata {
                let (metadata, headers) = if needs.headers {
                    let Some(value) = self.store().get_value::<MetadataRow>(metadata_key).await?
                    else {
                        response.push_not_found(id);
                        continue;
                    };
                    row = value;
                    raw_headers = row.raw_headers().caused_by(trc::location!())?;
                    (
                        row.unarchive().caused_by(trc::location!())?,
                        Some(raw_headers.as_ref()),
                    )
                } else {
                    let Some(value) = self
                        .store()
                        .get_value::<MetadataStructure>(metadata_key.clone())
                        .await?
                    else {
                        response.push_not_found(id);
                        continue;
                    };
                    structure = value;
                    let metadata = structure.unarchive().caused_by(trc::location!())?;
                    if needs.headers_for(metadata) {
                        let Some(value) =
                            self.store().get_value::<MetadataRow>(metadata_key).await?
                        else {
                            response.push_not_found(id);
                            continue;
                        };
                        row = value;
                        raw_headers = row.raw_headers().caused_by(trc::location!())?;
                        (
                            row.unarchive().caused_by(trc::location!())?,
                            Some(raw_headers.as_ref()),
                        )
                    } else {
                        (metadata, None)
                    }
                };
                let blob_hash = metadata.blob_hash();
                if needs.blob_for(metadata) {
                    let Some(value) = self
                        .blob_store()
                        .get_blob(blob_hash.as_slice(), 0..usize::MAX)
                        .await?
                    else {
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
                    };
                    blob = Some(value);
                }
                Some((
                    metadata,
                    headers,
                    BlobId {
                        hash: blob_hash,
                        class: BlobClass::Linked {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: id.document_id(),
                        },
                        section: None,
                    },
                ))
            } else {
                None
            };
            let render = render.as_ref().map(|(metadata, headers, blob_id)| {
                EmailRender::new(
                    metadata,
                    *headers,
                    blob.as_deref(),
                    blob_id,
                    &header_needs,
                    &body_properties,
                    &options,
                )
            });

            // Prepare response
            let mut email: Map<'_, EmailProperty, EmailValue> =
                Map::with_capacity(properties.len() + metadata_slots);
            for property in &properties {
                match property {
                    EmailProperty::Id => {
                        email.insert_unchecked(EmailProperty::Id, Id::from(*id));
                    }
                    EmailProperty::ThreadId => {
                        email.insert_unchecked(EmailProperty::ThreadId, Id::from(id.prefix_id()));
                    }
                    EmailProperty::MailboxIds => {
                        let mut obj = Map::with_capacity(data.mailboxes().len());
                        for id in data.mailboxes().iter() {
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
                        email.insert_unchecked(EmailProperty::Size, data.size());
                    }
                    EmailProperty::ReceivedAt => {
                        email.insert_unchecked(
                            EmailProperty::ReceivedAt,
                            EmailValue::Date(UTCDate::from_timestamp(data.received_at() as i64)),
                        );
                    }
                    EmailProperty::HasAttachment => {
                        email.insert_unchecked(
                            EmailProperty::HasAttachment,
                            (data.keywords() & 1 << HASATTACHMENT) != 0,
                        );
                    }
                    _ => {
                        if let Some(value) =
                            render.as_ref().and_then(|render| render.value(property))
                        {
                            email.insert_unchecked(property.clone(), value);
                        }
                    }
                }
            }
            if let Some(metadata_values) = &mut metadata_values {
                metadata_values.insert_into(id.document_id(), &mut email);
            }
            response.list.push(Value::Object(email).into_owned());
        }

        Ok(response)
    }
}
