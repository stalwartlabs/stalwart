/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::download::BlobDownload;
use common::{Server, auth::AccessToken};
use compact_str::format_compact;
use email::message::{
    jmap::{BodyValueOptions, EmailRender, HeaderNeeds},
    metadata::{ArchivedMessageMetadata, ExtraHeaders, MessageMetadata},
};
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::email::{Email, EmailProperty},
    request::{IntoValid, MaybeInvalid, reference::MaybeIdReference},
};
use jmap_tools::{Map, Value};
use mail_parser::MessageParser;
use std::future::Future;
use utils::map::vec_map::VecMap;

pub trait EmailParse: Sync + Send {
    fn email_parse(
        &self,
        request: ParseRequest<Email>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ParseResponse<Email>>> + Send;
}

impl EmailParse for Server {
    async fn email_parse(
        &self,
        request: ParseRequest<Email>,
        access_token: &AccessToken,
    ) -> trc::Result<ParseResponse<Email>> {
        if request.blob_ids.len() > self.core.jmap.mail_parse_max_items {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }
        let properties = request
            .properties
            .map(|v| v.into_valid().collect())
            .unwrap_or_else(|| {
                vec![
                    EmailProperty::BlobId,
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
                ]
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
        if let Some(property) = properties
            .iter()
            .find(|property| {
                !property.is_allowed_form()
                    || !(EmailRender::renders(property)
                        || matches!(
                            property,
                            EmailProperty::Size
                                | EmailProperty::HasAttachment
                                | EmailProperty::Id
                                | EmailProperty::ThreadId
                                | EmailProperty::Keywords
                                | EmailProperty::MailboxIds
                                | EmailProperty::ReceivedAt
                        ))
            })
            .or_else(|| {
                body_properties
                    .iter()
                    .find(|property| !property.is_allowed_form())
            })
        {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details(format_compact!("Invalid property {property:?}")));
        }

        let header_needs = HeaderNeeds::new(&properties, &body_properties);
        let mut response = ParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids {
            let blob_id = match blob_id {
                MaybeIdReference::Id(blob_id) => blob_id,
                MaybeIdReference::Invalid(s) | MaybeIdReference::Reference(s) => {
                    response.not_found.push(MaybeInvalid::Invalid(s));
                    continue;
                }
            };
            // Fetch raw message to parse
            let (raw_message, extra_headers_len) = match self
                .blob_download_with_extra(&blob_id, access_token)
                .await?
            {
                Some(blob) => (blob.bytes, blob.extra_headers_len),
                None => {
                    response.not_found.push(MaybeInvalid::Value(blob_id));
                    continue;
                }
            };
            let message = match MessageParser::new()
                .parse(&raw_message)
                .filter(|message| message.headers().has_known())
            {
                Some(message) => message,
                None => {
                    response.not_parsable.push(blob_id);
                    continue;
                }
            };
            let built =
                MessageMetadata::build(&message, &ExtraHeaders::default(), blob_id.hash.clone());
            let archive =
                rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&built.metadata, Vec::new())
                    .map_err(|err| {
                        trc::StoreEvent::DeserializeError
                            .caused_by(trc::location!())
                            .reason(err)
                    })?;
            let metadata = rkyv::access::<ArchivedMessageMetadata, rkyv::rancor::Error>(&archive)
                .map_err(|err| {
                trc::StoreEvent::DataCorruption
                    .caused_by(trc::location!())
                    .reason(err)
            })?;
            let render = EmailRender::new(
                metadata,
                Some(&built.raw_headers),
                Some(&raw_message),
                &blob_id,
                &header_needs,
                &body_properties,
                &options,
            )
            .with_blob_prefix(extra_headers_len);

            let mut email = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    EmailProperty::Size => Value::Number(raw_message.len().into()),
                    EmailProperty::HasAttachment => Value::Bool(built.has_attachments),
                    EmailProperty::Id
                    | EmailProperty::ThreadId
                    | EmailProperty::Keywords
                    | EmailProperty::MailboxIds
                    | EmailProperty::ReceivedAt => Value::Null,
                    _ => match render.value(property) {
                        Some(value) => value.into_owned(),
                        None => continue,
                    },
                };
                email.insert_unchecked(property.clone(), value);
            }
            response.parsed.append(blob_id, email.into());
        }

        Ok(response)
    }
}
