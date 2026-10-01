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
        jmap::{BodyValueOptions, EmailNeeds, EmailRender},
        messagedata::MessageData,
        metadata::{
            AddressHeader, ArchivedMessageMetadata, HeaderList, MetadataRow, MetadataStructure,
            Occurrence, PartSource, RawMessage,
        },
    },
    push::EmailPush,
};
use jmap_proto::{
    method::query::Filter,
    object::{
        email::{EmailFilter, EmailProperty, EmailValue},
        push_subscription::EmailPushProperty,
    },
    types::date::UTCDate,
};
use jmap_tools::{Map, Property, Value};
use mail_parser::HeaderForm;
use std::{borrow::Cow, iter::Peekable};
use store::ValueKey;
use trc::AddContext;
use types::{
    blob::{BlobClass, BlobId},
    collection::Collection,
    field::EmailField,
    id::Id,
    keyword::HASATTACHMENT,
};

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

    let keys = properties
        .iter()
        .map(EmailProperty::from)
        .collect::<Vec<_>>();
    let options = BodyValueOptions::default();
    let needs = EmailNeeds::new(&keys, BODY_PROPERTIES, &options);
    let needs_headers = needs.headers
        || config
            .filter
            .iter()
            .any(|filter| matches!(filter, Filter::Property(EmailFilter::Header(_))));
    let filter_blob = config.filter.iter().any(|filter| {
        matches!(
            filter,
            Filter::Property(EmailFilter::Body(_) | EmailFilter::Text(_))
        )
    });

    let key = ValueKey::immutable(
        account_id,
        Collection::Email,
        document_id,
        EmailField::Metadata,
    );
    let row;
    let structure;
    let raw_headers;
    let (metadata, headers) = if needs_headers {
        let Some(value) = server
            .store()
            .get_value::<MetadataRow>(key)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        row = value;
        raw_headers = row.raw_headers().caused_by(trc::location!())?;
        (
            row.unarchive().caused_by(trc::location!())?,
            Some(raw_headers.as_ref()),
        )
    } else {
        let Some(value) = server
            .store()
            .get_value::<MetadataStructure>(key)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        structure = value;
        (structure.unarchive().caused_by(trc::location!())?, None)
    };

    let blob = if filter_blob || needs.blob {
        let Some(blob) = server
            .blob_store()
            .get_blob(metadata.blob_hash().as_slice(), 0..usize::MAX)
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(None);
        };
        Some(blob)
    } else {
        None
    };

    let blob_id = BlobId::new(
        metadata.blob_hash(),
        BlobClass::Linked {
            account_id,
            collection: Collection::Email.into(),
            document_id,
        },
    );
    let render = EmailRender::new(
        metadata,
        headers,
        blob.as_deref(),
        &blob_id,
        BODY_PROPERTIES,
        &options,
    );

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

        let context = FilterContext {
            data: &data,
            document_id,
            cache: cache.as_deref(),
            meta: metadata,
            headers,
            root_headers: render.root_headers(),
            raw: blob
                .as_deref()
                .map(|blob| metadata.raw_message(headers, blob)),
        };
        if !context
            .eval_node(&mut config.filter.iter().peekable())
            .unwrap_or(true)
        {
            return Ok(None);
        }
    }

    let id = Id::from_parts(data.thread_id, document_id);
    let mut email = Map::with_capacity(properties.len());
    let mut used = 0;

    for (property, key) in properties.iter().zip(keys) {
        let value: Value<'static, EmailProperty, EmailValue> = match property {
            EmailPushProperty::Id => id.into(),
            EmailPushProperty::ThreadId => Id::from(id.prefix_id()).into(),
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
            EmailPushProperty::HasAttachment => {
                ((data.keywords & (1 << HASATTACHMENT)) != 0).into()
            }
            _ => match render.value(&key) {
                Some(value) => value.into_owned(),
                None => continue,
            },
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
    meta: &'a ArchivedMessageMetadata,
    headers: Option<&'a [u8]>,
    root_headers: HeaderList<'a>,
    raw: Option<RawMessage<'a>>,
}

impl FilterContext<'_> {
    fn eval_node<'f, I>(&self, tokens: &mut Peekable<I>) -> Option<bool>
    where
        I: Iterator<Item = &'f Filter<EmailFilter>>,
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
                    if let Some(result) = self.eval_node(tokens) {
                        all &= result;
                        any |= result;
                    }
                }
                Some(match operator {
                    Filter::And => all,
                    Filter::Or => any,
                    _ => !any,
                })
            }
            Filter::Property(condition) => Some(self.eval_condition(condition)),
            Filter::Close => None,
        }
    }

    fn eval_condition(&self, condition: &EmailFilter) -> bool {
        match condition {
            EmailFilter::InMailbox(id) => {
                let mailbox_id = id.document_id();
                self.data
                    .mailboxes
                    .iter()
                    .any(|mailbox| mailbox.mailbox_id == mailbox_id)
            }
            EmailFilter::InMailboxOtherThan(ids) => self
                .data
                .mailboxes
                .iter()
                .any(|mailbox| ids.iter().all(|id| id.document_id() != mailbox.mailbox_id)),
            EmailFilter::Before(date) => self.received_at() < date.timestamp(),
            EmailFilter::After(date) => self.received_at() >= date.timestamp(),
            EmailFilter::MinSize(size) => self.data.size >= *size,
            EmailFilter::MaxSize(size) => self.data.size < *size,
            EmailFilter::HasKeyword(keyword) => self.data.has_keyword(keyword),
            EmailFilter::NotKeyword(keyword) => !self.data.has_keyword(keyword),
            EmailFilter::AllInThreadHaveKeyword(keyword) => self.cache.is_some_and(|cache| {
                cache
                    .in_thread(self.data.thread_id)
                    .all(|message| cache.has_keyword(message, keyword))
            }),
            EmailFilter::SomeInThreadHaveKeyword(keyword) => self.cache.is_some_and(|cache| {
                cache
                    .in_thread(self.data.thread_id)
                    .any(|message| cache.has_keyword(message, keyword))
            }),
            EmailFilter::NoneInThreadHaveKeyword(keyword) => self.cache.is_some_and(|cache| {
                !cache
                    .in_thread(self.data.thread_id)
                    .any(|message| cache.has_keyword(message, keyword))
            }),
            EmailFilter::HasAttachment(value) => {
                ((self.data.keywords & (1 << HASATTACHMENT)) != 0) == *value
            }
            EmailFilter::From(text) => ascii_matcher(text)
                .is_some_and(|matcher| self.address_matches(AddressHeader::From, &matcher)),
            EmailFilter::To(text) => ascii_matcher(text)
                .is_some_and(|matcher| self.address_matches(AddressHeader::To, &matcher)),
            EmailFilter::Cc(text) => ascii_matcher(text)
                .is_some_and(|matcher| self.address_matches(AddressHeader::Cc, &matcher)),
            EmailFilter::Bcc(text) => ascii_matcher(text)
                .is_some_and(|matcher| self.address_matches(AddressHeader::Bcc, &matcher)),
            EmailFilter::Subject(text) => {
                ascii_matcher(text).is_some_and(|matcher| self.subject_matches(&matcher))
            }
            EmailFilter::Body(text) => {
                ascii_matcher(text).is_some_and(|matcher| self.body_matches(&matcher))
            }
            EmailFilter::Text(text) => ascii_matcher(text).is_some_and(|matcher| {
                [
                    AddressHeader::From,
                    AddressHeader::To,
                    AddressHeader::Cc,
                    AddressHeader::Bcc,
                ]
                .into_iter()
                .any(|header| self.address_matches(header, &matcher))
                    || self.subject_matches(&matcher)
                    || self.body_matches(&matcher)
            }),
            EmailFilter::Header(parts) => match parts.first() {
                Some(name) => self.header_matches(name, parts.get(1).map(String::as_str)),
                None => false,
            },
            EmailFilter::SentBefore(date) => self
                .sent_at()
                .is_some_and(|sent_at| sent_at < date.timestamp()),
            EmailFilter::SentAfter(date) => self
                .sent_at()
                .is_some_and(|sent_at| sent_at >= date.timestamp()),
            EmailFilter::InThread(id) => self.data.thread_id == id.document_id(),
            EmailFilter::Id(ids) => ids.iter().any(|id| id.document_id() == self.document_id),
            EmailFilter::_T(_) => false,
        }
    }

    fn received_at(&self) -> i64 {
        self.data.received_at as i64
    }

    fn sent_at(&self) -> Option<i64> {
        self.meta
            .root()
            .envelope()
            .datetime()
            .map(|date| date.to_timestamp())
    }

    fn address_matches(&self, header: AddressHeader, matcher: &AhoCorasick) -> bool {
        self.meta
            .root()
            .envelope()
            .addresses(header, Occurrence::Last)
            .mailboxes()
            .any(|mailbox| {
                mailbox
                    .name
                    .into_iter()
                    .chain(mailbox.address)
                    .any(|text| matcher.is_match(text))
            })
    }

    fn subject_matches(&self, matcher: &AhoCorasick) -> bool {
        self.meta
            .root()
            .envelope()
            .subject()
            .is_some_and(|subject| matcher.is_match(subject))
    }

    fn header_matches(&self, name: &str, expected: Option<&str>) -> bool {
        let Some(headers) = self.headers else {
            return false;
        };
        let Some(header) = self.root_headers.last_named(name, headers) else {
            return false;
        };
        let Some(expected) = expected else {
            return true;
        };
        ascii_matcher(expected).is_some_and(|matcher| {
            header.raw_value(headers).is_some_and(|raw| {
                HeaderForm::Text
                    .parse(raw)
                    .value()
                    .as_text()
                    .is_some_and(|text| matcher.is_match(text))
            })
        })
    }

    fn body_matches(&self, matcher: &AhoCorasick) -> bool {
        let Some(raw) = self.raw else {
            return false;
        };
        let source = PartSource::Raw(raw);
        let root = self.meta.root();
        root.text_body().chain(root.html_body()).any(|part| {
            part.text(&source)
                .is_some_and(|text| matcher.is_match(Cow::as_ref(&text.text)))
        })
    }
}

fn ascii_matcher(needle: &str) -> Option<AhoCorasick> {
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([needle])
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{BODY_PROPERTIES, FilterContext};
    use email::message::{
        jmap::{BodyValueOptions, EmailRender},
        messagedata::MessageData,
        metadata::{ExtraHeaders, MessageMetadata, MetadataRow},
    };
    use jmap_proto::object::email::EmailFilter;
    use mail_parser::MessageParser;
    use store::Deserialize;
    use types::{blob::BlobId, blob_hash::BlobHash};

    #[test]
    fn filters_read_large_header_blocks() {
        let mut raw = String::new();
        for index in 0..16_400 {
            raw.push_str(&format!("X-Junk-{}: v\r\n", index % 97));
        }
        raw.push_str("X-After: marker\r\nTo: ");
        for index in 0..1_100 {
            if index > 0 {
                raw.push_str(",\r\n ");
            }
            raw.push_str(&format!("r{index}@example.com"));
        }
        raw.push_str("\r\nSubject: hello\r\n\r\nbody\r\n");
        let message = MessageParser::new()
            .parse(raw.as_bytes())
            .expect("message parses");
        let built = MessageMetadata::build(&message, &ExtraHeaders::default(), BlobHash::default());
        let row = MetadataRow::deserialize(&built.encode().expect("row encodes")).expect("row");
        let headers = row.raw_headers().expect("headers");
        let meta = row.unarchive().expect("archive");
        let data = MessageData {
            mailboxes: Default::default(),
            keywords: 0,
            keywords_extra: Vec::new(),
            thread_id: 0,
            size: 0,
            received_at: 0,
            sent_at: 0,
            change_id: 0,
        };
        let conditions = [
            (EmailFilter::Header(vec!["X-After".into()]), true),
            (
                EmailFilter::Header(vec!["X-After".into(), "marker".into()]),
                true,
            ),
            (EmailFilter::Header(vec!["X-Junk-1".into()]), true),
            (EmailFilter::Header(vec!["X-Missing".into()]), false),
            (EmailFilter::To("r5@example.com".into()), true),
            (EmailFilter::To("r1099@example.com".into()), true),
            (EmailFilter::To("r1100@example.com".into()), false),
            (EmailFilter::Text("r1099@example.com".into()), true),
            (EmailFilter::Subject("hello".into()), true),
            (EmailFilter::Subject("goodbye".into()), false),
        ];
        let options = BodyValueOptions::default();
        let blob_id = BlobId::default();
        let render = EmailRender::new(
            meta,
            Some(headers.as_ref()),
            Some(raw.as_bytes()),
            &blob_id,
            BODY_PROPERTIES,
            &options,
        );
        let context = FilterContext {
            data: &data,
            document_id: 0,
            cache: None,
            meta,
            headers: Some(headers.as_ref()),
            root_headers: render.root_headers(),
            raw: Some(meta.raw_message(Some(headers.as_ref()), raw.as_bytes())),
        };
        for (condition, expected) in &conditions {
            assert_eq!(
                context.eval_condition(condition),
                *expected,
                "{condition:?}"
            );
        }
    }
}
