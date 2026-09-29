/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod body;
pub mod header;

#[cfg(test)]
mod tests;

use crate::message::metadata::{
    AddressHeader, Addresses, ArchivedMessageMetadata, BodyList, HeaderId, HeaderList,
    HeaderMatcher, HeaderSelection, MessageView, Occurrence, ParsedHeaders, PartHeaders,
    PartSource, PartView, RawMessage, TextItems,
};
use header::{FieldSource, HeaderBytes};
use jmap_proto::{
    object::email::{EmailProperty, EmailValue, HeaderForm},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use std::{borrow::Cow, cell::RefCell};
use store::ahash::AHashMap;
use types::blob::BlobId;

pub type JmapValue<'a> = Value<'a, EmailProperty, EmailValue>;
pub type JmapMap<'a> = Map<'a, EmailProperty, EmailValue>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BodyValueOptions {
    pub fetch_text: bool,
    pub fetch_html: bool,
    pub fetch_all: bool,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmailNeeds {
    pub headers: bool,
    pub blob: bool,
    pub envelope: bool,
    pub fallback: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HeaderNeeds {
    root: HeaderMatcher,
    root_all: bool,
    parts: HeaderMatcher,
    parts_all: bool,
}

pub struct EmailRender<'a, 'p> {
    meta: &'a ArchivedMessageMetadata,
    root: MessageView<'a>,
    root_headers: PartHeaders<'a>,
    truncated: bool,
    part_headers: RefCell<Option<Box<AHashMap<u32, ParsedHeaders>>>>,
    headers: Option<&'a [u8]>,
    raw: Option<RawMessage<'a>>,
    blob_id: &'p BlobId,
    blob_prefix: usize,
    header_needs: &'p HeaderNeeds,
    body_properties: &'p [EmailProperty],
    options: &'p BodyValueOptions,
}

impl BodyValueOptions {
    pub fn fetches_any(&self) -> bool {
        self.fetch_text || self.fetch_html || self.fetch_all
    }
}

impl EmailNeeds {
    pub fn new(
        properties: &[EmailProperty],
        body_properties: &[EmailProperty],
        options: &BodyValueOptions,
    ) -> Self {
        let body_headers = body_properties
            .iter()
            .any(|property| matches!(property, EmailProperty::Header(_) | EmailProperty::Headers));
        let body_fields = body_properties.iter().any(|property| {
            matches!(
                property,
                EmailProperty::Cid | EmailProperty::Location | EmailProperty::Language
            )
        });
        let mut needs = EmailNeeds::default();
        for property in properties {
            if body_fields
                && matches!(
                    property,
                    EmailProperty::TextBody
                        | EmailProperty::HtmlBody
                        | EmailProperty::Attachments
                        | EmailProperty::BodyStructure
                )
            {
                needs.fallback = true;
            }
            match property {
                EmailProperty::Header(_) | EmailProperty::Headers | EmailProperty::References => {
                    needs.headers = true;
                }
                EmailProperty::TextBody
                | EmailProperty::HtmlBody
                | EmailProperty::Attachments
                | EmailProperty::BodyStructure
                    if body_headers =>
                {
                    needs.headers = true;
                    needs.blob = true;
                }
                EmailProperty::BodyValues if options.fetches_any() => {
                    needs.blob = true;
                }
                EmailProperty::Preview => {
                    needs.fallback = true;
                }
                property if EmailRender::envelope_field(property).is_some() => {
                    needs.envelope = true;
                }
                _ => {}
            }
        }
        needs
    }

    pub fn headers_for(&self, meta: &ArchivedMessageMetadata) -> bool {
        self.headers || ((self.envelope || self.fallback) && meta.completeness().is_truncated())
    }

    pub fn blob_for(&self, meta: &ArchivedMessageMetadata) -> bool {
        self.blob || (self.fallback && meta.completeness().is_truncated())
    }
}

impl HeaderNeeds {
    pub fn new(properties: &[EmailProperty], body_properties: &[EmailProperty]) -> Self {
        let mut needs = HeaderNeeds::default();
        for property in properties {
            match property {
                EmailProperty::Headers => needs.root_all = true,
                EmailProperty::Header(header) => needs.root.add_name(&header.header),
                EmailProperty::References => needs.root.add_id(HeaderId::REFERENCES),
                property => {
                    if let Some((id, _)) = EmailRender::envelope_field(property) {
                        needs.root.add_id(id);
                    }
                }
            }
        }
        for property in body_properties {
            match property {
                EmailProperty::Headers => needs.parts_all = true,
                EmailProperty::Header(header) => needs.parts.add_name(&header.header),
                EmailProperty::Cid => needs.parts.add_id(HeaderId::CONTENT_ID),
                EmailProperty::Location => needs.parts.add_id(HeaderId::CONTENT_LOCATION),
                EmailProperty::Language => needs.parts.add_id(HeaderId::CONTENT_LANGUAGE),
                _ => {}
            }
        }
        needs
    }

    pub fn add_root_name(&mut self, name: &str) {
        self.root.add_name(name);
    }

    pub fn add_root_id(&mut self, id: HeaderId) {
        self.root.add_id(id);
    }

    fn root(&self) -> HeaderSelection<'_> {
        if self.root_all {
            HeaderSelection::All
        } else {
            HeaderSelection::Named(&self.root)
        }
    }

    fn parts(&self) -> HeaderSelection<'_> {
        if self.parts_all {
            HeaderSelection::All
        } else {
            HeaderSelection::Named(&self.parts)
        }
    }
}

impl<'a, 'p> EmailRender<'a, 'p> {
    pub fn new(
        meta: &'a ArchivedMessageMetadata,
        headers: Option<&'a [u8]>,
        blob: Option<&'a [u8]>,
        blob_id: &'p BlobId,
        header_needs: &'p HeaderNeeds,
        body_properties: &'p [EmailProperty],
        options: &'p BodyValueOptions,
    ) -> Self {
        let headers = headers.filter(|headers| headers.len() == meta.headers_len());
        let root = meta.root();
        let root_part = root.root_part();
        EmailRender {
            meta,
            root,
            root_headers: headers.map_or(PartHeaders::Stored(root_part.headers()), |headers| {
                root_part.selected_headers(headers, header_needs.root())
            }),
            truncated: meta.completeness().is_truncated(),
            part_headers: RefCell::default(),
            headers,
            raw: blob.map(|blob| meta.raw_message(headers, blob)),
            blob_id,
            blob_prefix: 0,
            header_needs,
            body_properties,
            options,
        }
    }

    pub fn root_headers(&self) -> HeaderList<'_> {
        self.root_headers.list()
    }

    fn with_part_headers<T>(
        &self,
        part: PartView<'a>,
        source: &PartSource<'_>,
        read: impl FnOnce(HeaderList<'_>) -> T,
    ) -> T {
        if !part.is_headers_truncated() {
            return read(part.headers());
        }
        let mut memo = self.part_headers.borrow_mut();
        let memo = memo.get_or_insert_default();
        if !memo.contains_key(&part.id()) {
            let Some(block) = source.get(part.header_range()) else {
                return read(part.headers());
            };
            let parsed = part
                .scan_headers(&block, self.header_needs.parts())
                .collect();
            memo.insert(part.id(), parsed);
        }
        match memo.get(&part.id()) {
            Some(parsed) => read(parsed.list()),
            None => read(part.headers()),
        }
    }

    pub fn with_blob_prefix(mut self, prefix: usize) -> Self {
        self.blob_prefix = prefix;
        self
    }

    pub fn renders(property: &EmailProperty) -> bool {
        matches!(
            property,
            EmailProperty::BlobId
                | EmailProperty::Preview
                | EmailProperty::Subject
                | EmailProperty::SentAt
                | EmailProperty::MessageId
                | EmailProperty::InReplyTo
                | EmailProperty::References
                | EmailProperty::Sender
                | EmailProperty::From
                | EmailProperty::To
                | EmailProperty::Cc
                | EmailProperty::Bcc
                | EmailProperty::ReplyTo
                | EmailProperty::Header(_)
                | EmailProperty::Headers
                | EmailProperty::TextBody
                | EmailProperty::HtmlBody
                | EmailProperty::Attachments
                | EmailProperty::BodyStructure
                | EmailProperty::BodyValues
        )
    }

    fn envelope_field(property: &EmailProperty) -> Option<(HeaderId, HeaderForm)> {
        Some(match property {
            EmailProperty::Subject => (HeaderId::SUBJECT, HeaderForm::Text),
            EmailProperty::SentAt => (HeaderId::DATE, HeaderForm::Date),
            EmailProperty::MessageId => (HeaderId::MESSAGE_ID, HeaderForm::MessageIds),
            EmailProperty::InReplyTo => (HeaderId::IN_REPLY_TO, HeaderForm::MessageIds),
            EmailProperty::Sender => (HeaderId::SENDER, HeaderForm::Addresses),
            EmailProperty::From => (HeaderId::FROM, HeaderForm::Addresses),
            EmailProperty::To => (HeaderId::TO, HeaderForm::Addresses),
            EmailProperty::Cc => (HeaderId::CC, HeaderForm::Addresses),
            EmailProperty::Bcc => (HeaderId::BCC, HeaderForm::Addresses),
            EmailProperty::ReplyTo => (HeaderId::REPLY_TO, HeaderForm::Addresses),
            _ => return None,
        })
    }

    fn envelope_from_headers(&self, property: &EmailProperty) -> Option<JmapValue<'a>> {
        let headers = self.headers?;
        let (id, form) = EmailRender::envelope_field(property)?;
        let value = self
            .root_headers
            .list()
            .last(id)
            .and_then(|header| headers.field(header.value_range()))
            .map_or(Value::Null, |raw| HeaderBytes(raw).jmap_value(form));
        Some(match value {
            Value::Array(items) if items.is_empty() => Value::Null,
            value => value,
        })
    }

    pub fn value(&self, property: &EmailProperty) -> Option<JmapValue<'a>> {
        if self.truncated
            && let Some(value) = self.envelope_from_headers(property)
        {
            return Some(value);
        }
        let envelope = self.root.envelope();
        Some(match property {
            EmailProperty::BlobId => Value::Element(EmailValue::BlobId(self.blob_id.clone())),
            EmailProperty::Preview => match self.meta.stored_preview() {
                Some(preview) => Value::Str(Cow::Borrowed(preview)),
                None => Value::Str(
                    self.fallback_preview()
                        .map_or(Cow::Borrowed(""), Cow::Owned),
                ),
            },
            EmailProperty::Subject => str_value(envelope.subject()),
            EmailProperty::SentAt => envelope
                .datetime()
                .map_or(Value::Null, |date| date_value(&date)),
            EmailProperty::MessageId => envelope.message_id().jmap_ids(),
            EmailProperty::InReplyTo => envelope.in_reply_to().jmap_ids(),
            EmailProperty::References => self.headers.map_or(Value::Null, |headers| {
                self.root_headers
                    .list()
                    .last(HeaderId::REFERENCES)
                    .and_then(|header| headers.field(header.value_range()))
                    .map_or(Value::Null, |raw| HeaderBytes(raw).message_ids())
            }),
            EmailProperty::Sender => envelope
                .addresses(AddressHeader::Sender, Occurrence::Last)
                .jmap_mailboxes(),
            EmailProperty::From => envelope
                .addresses(AddressHeader::From, Occurrence::Last)
                .jmap_mailboxes(),
            EmailProperty::To => envelope
                .addresses(AddressHeader::To, Occurrence::Last)
                .jmap_mailboxes(),
            EmailProperty::Cc => envelope
                .addresses(AddressHeader::Cc, Occurrence::Last)
                .jmap_mailboxes(),
            EmailProperty::Bcc => envelope
                .addresses(AddressHeader::Bcc, Occurrence::Last)
                .jmap_mailboxes(),
            EmailProperty::ReplyTo => envelope
                .addresses(AddressHeader::ReplyTo, Occurrence::Last)
                .jmap_mailboxes(),
            EmailProperty::Header(_) | EmailProperty::Headers => {
                self.headers.map_or(Value::Null, |headers| {
                    self.root_headers.list().jmap_value(property, headers)
                })
            }
            EmailProperty::TextBody => self.body_list_values(BodyList::Text),
            EmailProperty::HtmlBody => self.body_list_values(BodyList::Html),
            EmailProperty::Attachments => self.body_list_values(BodyList::Attachments),
            EmailProperty::BodyStructure => self.body_part(self.root.root_part()),
            EmailProperty::BodyValues => self.body_values(),
            _ => return None,
        })
    }
}

fn str_value(text: Option<&str>) -> JmapValue<'_> {
    text.map_or(Value::Null, |text| Value::Str(Cow::Borrowed(text)))
}

impl<'a> TextItems<'a> {
    pub fn jmap_ids(&self) -> JmapValue<'a> {
        if self.is_empty() {
            Value::Null
        } else {
            Value::Array(
                self.iter()
                    .map(|item| Value::Str(Cow::Borrowed(item)))
                    .collect(),
            )
        }
    }
}

impl<'a> Addresses<'a> {
    pub fn jmap_mailboxes(&self) -> JmapValue<'a> {
        if self.is_empty() {
            return Value::Null;
        }
        Value::Array(
            self.mailboxes()
                .map(|mailbox| {
                    Value::Object(
                        Map::with_capacity(2)
                            .with_key_value(EmailProperty::Name, str_value(mailbox.name))
                            .with_key_value(
                                EmailProperty::Email,
                                Value::Str(Cow::Borrowed(mailbox.address.unwrap_or_default())),
                            ),
                    )
                })
                .collect(),
        )
    }
}

fn date_value<'a>(date: &mail_parser::DateTime) -> JmapValue<'a> {
    Value::Element(EmailValue::Date(UTCDate {
        year: date.year,
        month: date.month,
        day: date.day,
        hour: date.hour,
        minute: date.minute,
        second: date.second,
        tz_before_gmt: date.tz_before_gmt,
        tz_hour: date.tz_hour,
        tz_minute: date.tz_minute,
    }))
}
