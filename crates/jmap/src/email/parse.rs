/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    body::{ToBodyPart, TruncateBody},
    headers::HeaderToValue,
};
use crate::blob::download::BlobDownload;
use common::{Server, auth::AccessToken};
use email::message::index::PREVIEW_LENGTH;
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::email::{Email, EmailProperty},
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use mail_parser::{
    MessageParser, PartType, decoders::html::html_to_text, parsers::preview::preview_text,
};
use std::future::Future;
use utils::{chained_bytes::ChainedBytes, map::vec_map::VecMap};

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
        let fetch_text_body_values = request.arguments.fetch_text_body_values.unwrap_or(false);
        let fetch_html_body_values = request.arguments.fetch_html_body_values.unwrap_or(false);
        let fetch_all_body_values = request.arguments.fetch_all_body_values.unwrap_or(false);
        let max_body_value_bytes = request.arguments.max_body_value_bytes.unwrap_or(0);

        let mut response = ParseResponse {
            account_id: request.account_id,
            parsed: VecMap::with_capacity(request.blob_ids.len()),
            not_parsable: vec![],
            not_found: vec![],
        };

        for blob_id in request.blob_ids.into_valid() {
            // Fetch raw message to parse
            let raw_message = match self.blob_download(&blob_id, access_token).await? {
                Some(raw_message) => raw_message,
                None => {
                    response.not_found.push(blob_id);
                    continue;
                }
            };
            let message = if let Some(message) = MessageParser::new().parse(&raw_message) {
                message
            } else {
                response.not_parsable.push(blob_id);
                continue;
            };
            let raw_message = ChainedBytes::new(&raw_message);

            // Prepare response
            let mut email = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    EmailProperty::BlobId => {
                        email.insert_unchecked(EmailProperty::BlobId, blob_id.clone());
                    }

                    EmailProperty::Size => {
                        email.insert_unchecked(
                            EmailProperty::Size,
                            Value::Number(raw_message.len().into()),
                        );
                    }
                    EmailProperty::HasAttachment => {
                        email.insert_unchecked(
                            EmailProperty::HasAttachment,
                            Value::Bool(message.parts.iter().enumerate().any(|(part_id, part)| {
                                let part_id = part_id as u32;
                                match &part.body {
                                    PartType::Html(_) | PartType::Text(_) => {
                                        !message.text_body.contains(&part_id)
                                            && !message.html_body.contains(&part_id)
                                    }
                                    PartType::Binary(_) | PartType::Message(_) => true,
                                    _ => false,
                                }
                            })),
                        );
                    }
                    EmailProperty::Preview => {
                        email.insert_unchecked(
                            EmailProperty::Preview,
                            match message
                                .text_body
                                .first()
                                .or_else(|| message.html_body.first())
                                .and_then(|idx| message.parts.get(*idx as usize))
                                .map(|part| &part.body)
                            {
                                Some(PartType::Text(text)) => {
                                    preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH)
                                        .into()
                                }
                                Some(PartType::Html(html)) => preview_text(
                                    html_to_text(html).replace('\r', "").into(),
                                    PREVIEW_LENGTH,
                                )
                                .into(),
                                _ => Value::Null,
                            },
                        );
                    }
                    EmailProperty::MessageId
                    | EmailProperty::InReplyTo
                    | EmailProperty::References
                    | EmailProperty::Sender
                    | EmailProperty::From
                    | EmailProperty::To
                    | EmailProperty::Cc
                    | EmailProperty::Bcc
                    | EmailProperty::ReplyTo
                    | EmailProperty::Subject
                    | EmailProperty::SentAt
                    | EmailProperty::Header(_) => {
                        email.insert_unchecked(
                            property.clone(),
                            message.parts[0]
                                .headers
                                .header_to_value(property, &raw_message),
                        );
                    }
                    EmailProperty::Headers => {
                        email.insert_unchecked(
                            EmailProperty::Headers,
                            message.parts[0].headers.headers_to_value(&raw_message),
                        );
                    }
                    EmailProperty::TextBody
                    | EmailProperty::HtmlBody
                    | EmailProperty::Attachments => {
                        let list = match property {
                            EmailProperty::TextBody => &message.text_body,
                            EmailProperty::HtmlBody => &message.html_body,
                            EmailProperty::Attachments => &message.attachments,
                            _ => unreachable!(),
                        }
                        .iter();
                        email.insert_unchecked(
                            property.clone(),
                            list.map(|part_id| {
                                message.parts.to_body_part(
                                    *part_id,
                                    &body_properties,
                                    &raw_message,
                                    &blob_id,
                                    0,
                                )
                            })
                            .collect::<Vec<_>>(),
                        );
                    }
                    EmailProperty::BodyStructure => {
                        email.insert_unchecked(
                            EmailProperty::BodyStructure,
                            message.parts.to_body_part(
                                0,
                                &body_properties,
                                &raw_message,
                                &blob_id,
                                0,
                            ),
                        );
                    }
                    EmailProperty::BodyValues => {
                        let mut body_values = Map::with_capacity(message.parts.len());
                        for (part_id, part) in message.parts.iter().enumerate() {
                            let part_id = part_id as u32;
                            if ((message.html_body.contains(&part_id)
                                && (fetch_all_body_values || fetch_html_body_values))
                                || (message.text_body.contains(&part_id)
                                    && (fetch_all_body_values || fetch_text_body_values)))
                                && part.is_text()
                            {
                                let (is_truncated, value) =
                                    part.body.truncate(max_body_value_bytes);
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
                    EmailProperty::Id
                    | EmailProperty::ThreadId
                    | EmailProperty::Keywords
                    | EmailProperty::MailboxIds
                    | EmailProperty::ReceivedAt => {
                        email.insert_unchecked(property.clone(), Value::Null);
                    }

                    _ => {
                        return Err(trc::JmapEvent::InvalidArguments
                            .into_err()
                            .details(format!("Invalid property {property:?}")));
                    }
                }
            }
            response.parsed.append(blob_id, email.into());
        }

        Ok(response)
    }
}
