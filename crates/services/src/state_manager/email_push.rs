/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use aho_corasick::AhoCorasick;
use common::{MessageStoreCache, Server};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        body::ToBodyPart,
        headers::{HeaderToValue, IntoForm},
        messagedata::MessageData,
        metadata::{
            ArchivedMessageMetadataContents, ArchivedMessageMetadataPart, ArchivedMetadataPartType,
            MessageMetadata, MetadataHeaderName,
        },
    },
    push::EmailPush,
};
use jmap_proto::{
    method::query::Filter,
    object::{
        email::{EmailFilter, EmailProperty, EmailValue, HeaderForm},
        push_subscription::EmailPushProperty,
    },
    types::date::UTCDate,
};
use jmap_tools::{Map, Property, Value};
use mail_parser::{HeaderName, HeaderValue};
use std::iter::Peekable;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::Collection,
    field::EmailField,
    id::Id,
    keyword::HASATTACHMENT,
};
use utils::chained_bytes::ChainedBytes;

const BODY_PROPERTIES: &[EmailProperty] = &[
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
];

pub async fn build_email_push_object(
    server: &Server,
    account_id: u32,
    document_id: u32,
    config: &EmailPush,
    max_size: usize,
) -> trc::Result<Option<(Value<'static, EmailProperty, EmailValue>, usize)>> {
    let properties = &config.properties;
    let Some(data) = server
        .store()
        .get_value::<MessageData>(ValueKey::archive(
            account_id,
            Collection::Email,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };

    let Some(metadata_archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::immutable(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let metadata = metadata_archive
        .unarchive::<MessageMetadata>()
        .caused_by(trc::location!())?;
    let (Some(contents), Some(root_part)) = (
        metadata.contents.first(),
        metadata.contents.first().and_then(|c| c.parts.first()),
    ) else {
        return Ok(None);
    };

    let blob_hash = BlobHash::from(&metadata.blob_hash);
    let needs_body = properties.iter().any(|property| {
        matches!(
            property,
            EmailPushProperty::TextBody
                | EmailPushProperty::HtmlBody
                | EmailPushProperty::Attachments
                | EmailPushProperty::BodyStructure
        )
    }) || config.filter.iter().any(|filter| {
        matches!(
            filter,
            Filter::Property(EmailFilter::Body(_) | EmailFilter::Text(_))
        )
    });

    let raw_body;
    let mut raw_message = ChainedBytes::new(metadata.raw_headers.as_ref());
    if needs_body {
        let Some(blob) = server
            .blob_store()
            .get_blob(blob_hash.as_slice(), 0..usize::MAX)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        raw_body = blob;
        raw_message.append(
            raw_body
                .get(metadata.blob_body_offset.to_native() as usize..)
                .unwrap_or_default(),
        );
    }

    if !config.filter.is_empty() {
        let cache = if config.filter.iter().any(|filter| {
            matches!(
                filter,
                Filter::Property(
                    EmailFilter::AllInThreadHaveKeyword(_)
                        | EmailFilter::SomeInThreadHaveKeyword(_)
                        | EmailFilter::NoneInThreadHaveKeyword(_)
                )
            )
        }) {
            Some(
                server
                    .get_cached_messages(account_id)
                    .await
                    .caused_by(trc::location!())?,
            )
        } else {
            None
        };

        if !eval_filter_node(
            &mut config.filter.iter().peekable(),
            &FilterContext {
                data: &data,
                document_id,
                cache: cache.as_deref(),
                contents,
                root_part,
                raw_message: &raw_message,
            },
        )
        .unwrap_or(true)
        {
            return Ok(None);
        }
    }

    let blob_id = BlobId {
        hash: blob_hash,
        class: BlobClass::Linked {
            account_id,
            collection: Collection::Email.into(),
            document_id,
        },
        section: None,
    };
    let blob_body_offset =
        metadata.blob_body_offset.to_native() as isize - root_part.offset_body.to_native() as isize;

    let id = Id::from_parts(data.thread_id, document_id);
    let mut email = Map::with_capacity(properties.len());
    let mut used = 0;

    for property in properties {
        let key = EmailProperty::from(property);
        let value: Value<'static, EmailProperty, EmailValue> = match property {
            EmailPushProperty::Id => id.into(),
            EmailPushProperty::ThreadId => Id::from(id.prefix_id()).into(),
            EmailPushProperty::BlobId => blob_id.clone().into(),
            EmailPushProperty::MailboxIds => {
                let mut mailbox_ids = Map::with_capacity(data.mailboxes.len());
                for mailbox in data.mailboxes.iter() {
                    mailbox_ids.insert_unchecked(
                        EmailProperty::IdValue(Id::from(mailbox.mailbox_id)),
                        true,
                    );
                }
                Value::Object(mailbox_ids)
            }
            EmailPushProperty::Keywords => {
                let mut keywords = Map::with_capacity(2);
                for keyword in data.keywords() {
                    keywords.insert_unchecked(EmailProperty::Keyword(keyword), true);
                }
                Value::Object(keywords)
            }
            EmailPushProperty::Size => data.size.into(),
            EmailPushProperty::ReceivedAt => {
                EmailValue::Date(UTCDate::from_timestamp(data.received_at as i64)).into()
            }
            EmailPushProperty::Preview => {
                if metadata.preview.is_empty() {
                    continue;
                }
                metadata.preview.to_string().into()
            }
            EmailPushProperty::HasAttachment => {
                ((data.keywords & (1 << HASATTACHMENT)) != 0).into()
            }
            EmailPushProperty::Subject
            | EmailPushProperty::SentAt
            | EmailPushProperty::MessageId
            | EmailPushProperty::InReplyTo
            | EmailPushProperty::References
            | EmailPushProperty::Sender
            | EmailPushProperty::From
            | EmailPushProperty::To
            | EmailPushProperty::Cc
            | EmailPushProperty::Bcc
            | EmailPushProperty::ReplyTo => {
                let (header_name, form) = match property {
                    EmailPushProperty::Subject => (MetadataHeaderName::Subject, HeaderForm::Text),
                    EmailPushProperty::SentAt => (MetadataHeaderName::Date, HeaderForm::Date),
                    EmailPushProperty::MessageId => {
                        (MetadataHeaderName::MessageId, HeaderForm::MessageIds)
                    }
                    EmailPushProperty::InReplyTo => {
                        (MetadataHeaderName::InReplyTo, HeaderForm::MessageIds)
                    }
                    EmailPushProperty::References => {
                        (MetadataHeaderName::References, HeaderForm::MessageIds)
                    }
                    EmailPushProperty::Sender => {
                        (MetadataHeaderName::Sender, HeaderForm::Addresses)
                    }
                    EmailPushProperty::From => (MetadataHeaderName::From, HeaderForm::Addresses),
                    EmailPushProperty::To => (MetadataHeaderName::To, HeaderForm::Addresses),
                    EmailPushProperty::Cc => (MetadataHeaderName::Cc, HeaderForm::Addresses),
                    EmailPushProperty::Bcc => (MetadataHeaderName::Bcc, HeaderForm::Addresses),
                    EmailPushProperty::ReplyTo => {
                        (MetadataHeaderName::ReplyTo, HeaderForm::Addresses)
                    }
                    _ => unreachable!(),
                };
                root_part
                    .header_value(&header_name)
                    .map(|value| HeaderValue::from(value).into_form(&form))
                    .unwrap_or_default()
            }
            EmailPushProperty::Header(_) => root_part.header_to_value(&key, &raw_message),
            EmailPushProperty::Headers => root_part.headers_to_value(&raw_message),
            EmailPushProperty::TextBody
            | EmailPushProperty::HtmlBody
            | EmailPushProperty::Attachments => {
                let parts = match property {
                    EmailPushProperty::TextBody => &contents.text_body,
                    EmailPushProperty::HtmlBody => &contents.html_body,
                    EmailPushProperty::Attachments => &contents.attachments,
                    _ => unreachable!(),
                };
                parts
                    .iter()
                    .map(|part_id| {
                        contents.to_body_part(
                            u16::from(part_id) as u32,
                            BODY_PROPERTIES,
                            &raw_message,
                            &blob_id,
                            blob_body_offset,
                        )
                    })
                    .collect::<Vec<_>>()
                    .into()
            }
            EmailPushProperty::BodyStructure => {
                contents.to_body_part(0, BODY_PROPERTIES, &raw_message, &blob_id, blob_body_offset)
            }
            EmailPushProperty::BodyValues => Value::Object(Map::with_capacity(0)),
        };

        let entry_size = key.to_cow().len() + estimate_value_size(&value) + 4;
        if used + entry_size < max_size {
            used += entry_size;
            email.insert_unchecked(key, value);
        }
    }

    Ok(Some((email.into(), used)))
}

fn estimate_value_size(value: &Value<'_, EmailProperty, EmailValue>) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(_) => 5,
        Value::Number(_) => 12,
        Value::Str(text) => text.len() + 2,
        Value::Element(_) => 40,
        Value::Array(values) => {
            2 + values
                .iter()
                .map(|value| estimate_value_size(value) + 1)
                .sum::<usize>()
        }
        Value::Object(map) => {
            2 + map
                .iter()
                .map(|(_, value)| estimate_value_size(value) + 24)
                .sum::<usize>()
        }
    }
}

struct FilterContext<'a> {
    data: &'a MessageData,
    document_id: u32,
    cache: Option<&'a MessageStoreCache>,
    contents: &'a ArchivedMessageMetadataContents,
    root_part: &'a ArchivedMessageMetadataPart,
    raw_message: &'a ChainedBytes<'a>,
}

fn eval_filter_node<'a, I>(tokens: &mut Peekable<I>, context: &FilterContext) -> Option<bool>
where
    I: Iterator<Item = &'a Filter<EmailFilter>>,
{
    match tokens.next()? {
        operator @ (Filter::And | Filter::Or | Filter::Not) => {
            let mut all = true;
            let mut any = false;
            while let Some(token) = tokens.peek() {
                if matches!(token, Filter::Close) {
                    tokens.next();
                    break;
                }
                if let Some(result) = eval_filter_node(tokens, context) {
                    all &= result;
                    any |= result;
                }
            }
            Some(match operator {
                Filter::And => all,
                Filter::Or => any,
                Filter::Not => !any,
                _ => unreachable!(),
            })
        }
        Filter::Property(condition) => Some(eval_filter_condition(condition, context)),
        Filter::Close => None,
    }
}

fn eval_filter_condition(condition: &EmailFilter, context: &FilterContext) -> bool {
    match condition {
        EmailFilter::InMailbox(id) => {
            let mailbox_id = id.document_id();
            context
                .data
                .mailboxes
                .iter()
                .any(|mailbox| mailbox.mailbox_id == mailbox_id)
        }
        EmailFilter::InMailboxOtherThan(ids) => context
            .data
            .mailboxes
            .iter()
            .any(|mailbox| ids.iter().all(|id| id.document_id() != mailbox.mailbox_id)),
        EmailFilter::Before(date) => received_at(context) < date.timestamp(),
        EmailFilter::After(date) => received_at(context) >= date.timestamp(),
        EmailFilter::MinSize(size) => context.data.size >= *size,
        EmailFilter::MaxSize(size) => context.data.size < *size,
        EmailFilter::HasKeyword(keyword) => context.data.has_keyword(keyword),
        EmailFilter::NotKeyword(keyword) => !context.data.has_keyword(keyword),
        EmailFilter::AllInThreadHaveKeyword(keyword) => context.cache.is_some_and(|cache| {
            cache
                .in_thread(context.data.thread_id)
                .all(|message| cache.has_keyword(message, keyword))
        }),
        EmailFilter::SomeInThreadHaveKeyword(keyword) => context.cache.is_some_and(|cache| {
            cache
                .in_thread(context.data.thread_id)
                .any(|message| cache.has_keyword(message, keyword))
        }),
        EmailFilter::NoneInThreadHaveKeyword(keyword) => context.cache.is_some_and(|cache| {
            !cache
                .in_thread(context.data.thread_id)
                .any(|message| cache.has_keyword(message, keyword))
        }),
        EmailFilter::HasAttachment(value) => {
            ((context.data.keywords & (1 << HASATTACHMENT)) != 0) == *value
        }
        EmailFilter::From(text) => ascii_matcher(text).is_some_and(|matcher| {
            header_matches(
                context,
                &MetadataHeaderName::From,
                &HeaderForm::Addresses,
                &matcher,
            )
        }),
        EmailFilter::To(text) => ascii_matcher(text).is_some_and(|matcher| {
            header_matches(
                context,
                &MetadataHeaderName::To,
                &HeaderForm::Addresses,
                &matcher,
            )
        }),
        EmailFilter::Cc(text) => ascii_matcher(text).is_some_and(|matcher| {
            header_matches(
                context,
                &MetadataHeaderName::Cc,
                &HeaderForm::Addresses,
                &matcher,
            )
        }),
        EmailFilter::Bcc(text) => ascii_matcher(text).is_some_and(|matcher| {
            header_matches(
                context,
                &MetadataHeaderName::Bcc,
                &HeaderForm::Addresses,
                &matcher,
            )
        }),
        EmailFilter::Subject(text) => ascii_matcher(text).is_some_and(|matcher| {
            header_matches(
                context,
                &MetadataHeaderName::Subject,
                &HeaderForm::Text,
                &matcher,
            )
        }),
        EmailFilter::Body(text) => {
            ascii_matcher(text).is_some_and(|matcher| body_matches(context, &matcher))
        }
        EmailFilter::Text(text) => ascii_matcher(text).is_some_and(|matcher| {
            header_matches(
                context,
                &MetadataHeaderName::From,
                &HeaderForm::Addresses,
                &matcher,
            ) || header_matches(
                context,
                &MetadataHeaderName::To,
                &HeaderForm::Addresses,
                &matcher,
            ) || header_matches(
                context,
                &MetadataHeaderName::Cc,
                &HeaderForm::Addresses,
                &matcher,
            ) || header_matches(
                context,
                &MetadataHeaderName::Bcc,
                &HeaderForm::Addresses,
                &matcher,
            ) || header_matches(
                context,
                &MetadataHeaderName::Subject,
                &HeaderForm::Text,
                &matcher,
            ) || body_matches(context, &matcher)
        }),
        EmailFilter::Header(parts) => {
            let Some(name) = parts.first() else {
                return false;
            };
            let header_name = MetadataHeaderName::from(
                HeaderName::parse(name.as_str())
                    .unwrap_or_else(|| HeaderName::Other(name.as_str().into())),
            );
            match (context.root_part.header_value(&header_name), parts.get(1)) {
                (Some(value), Some(expected)) => ascii_matcher(expected).is_some_and(|matcher| {
                    value_contains(
                        &HeaderValue::from(value).into_form(&HeaderForm::Raw),
                        &matcher,
                    )
                }),
                (Some(_), None) => true,
                (None, _) => false,
            }
        }
        EmailFilter::SentBefore(date) => {
            sent_at(context).is_some_and(|sent_at| sent_at < date.timestamp())
        }
        EmailFilter::SentAfter(date) => {
            sent_at(context).is_some_and(|sent_at| sent_at >= date.timestamp())
        }
        EmailFilter::InThread(id) => context.data.thread_id == id.document_id(),
        EmailFilter::Id(ids) => ids.iter().any(|id| id.document_id() == context.document_id),
        EmailFilter::_T(_) => false,
    }
}

fn received_at(context: &FilterContext) -> i64 {
    context.data.received_at as i64
}

fn sent_at(context: &FilterContext) -> Option<i64> {
    match context
        .root_part
        .header_value(&MetadataHeaderName::Date)
        .map(HeaderValue::from)
    {
        Some(HeaderValue::DateTime(datetime)) => Some(datetime.to_timestamp()),
        _ => None,
    }
}

fn ascii_matcher(needle: &str) -> Option<AhoCorasick> {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([needle])
        .ok()
}

fn header_matches(
    context: &FilterContext,
    name: &MetadataHeaderName,
    form: &HeaderForm,
    matcher: &AhoCorasick,
) -> bool {
    context
        .root_part
        .header_value(name)
        .is_some_and(|value| value_contains(&HeaderValue::from(value).into_form(form), matcher))
}

fn value_contains(value: &Value<'_, EmailProperty, EmailValue>, matcher: &AhoCorasick) -> bool {
    match value {
        Value::Str(text) => matcher.is_match(text.as_ref()),
        Value::Array(values) => values.iter().any(|value| value_contains(value, matcher)),
        Value::Object(map) => map.iter().any(|(_, value)| value_contains(value, matcher)),
        _ => false,
    }
}

fn body_matches(context: &FilterContext, matcher: &AhoCorasick) -> bool {
    context
        .contents
        .text_body
        .iter()
        .chain(context.contents.html_body.iter())
        .any(|part_id| {
            context
                .contents
                .parts
                .as_ref()
                .get(u16::from(part_id) as usize)
                .is_some_and(|part| {
                    matches!(
                        part.body,
                        ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html
                    ) && matcher.is_match(part.decode_contents(context.raw_message).as_str())
                })
        })
}
