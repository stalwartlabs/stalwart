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
    AddressHeader, Addresses, ArchivedMessageMetadata, BodyList, HeaderId, HeaderList, MessageView,
    Occurrence, RawMessage, TextItems,
};
use header::{FieldSource, HeaderBytes};
use jmap_proto::{
    object::email::{EmailProperty, EmailValue},
    types::date::UTCDate,
};
use jmap_tools::{Map, Value};
use std::borrow::Cow;
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
}

pub struct EmailRender<'a, 'p> {
    meta: &'a ArchivedMessageMetadata,
    root: MessageView<'a>,
    headers: Option<&'a [u8]>,
    raw: Option<RawMessage<'a>>,
    blob_id: &'p BlobId,
    blob_prefix: usize,
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
        let mut needs = EmailNeeds::default();
        for property in properties {
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
                _ => {}
            }
        }
        needs
    }
}

impl<'a, 'p> EmailRender<'a, 'p> {
    pub fn new(
        meta: &'a ArchivedMessageMetadata,
        headers: Option<&'a [u8]>,
        blob: Option<&'a [u8]>,
        blob_id: &'p BlobId,
        body_properties: &'p [EmailProperty],
        options: &'p BodyValueOptions,
    ) -> Self {
        let headers = headers.filter(|headers| headers.len() == meta.headers_len());
        EmailRender {
            meta,
            root: meta.root(),
            headers,
            raw: blob.map(|blob| meta.raw_message(headers, blob)),
            blob_id,
            blob_prefix: 0,
            body_properties,
            options,
        }
    }

    pub fn root_headers(&self) -> HeaderList<'a> {
        self.root.root_part().headers()
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

    pub fn value(&self, property: &EmailProperty) -> Option<JmapValue<'a>> {
        let envelope = self.root.envelope();
        Some(match property {
            EmailProperty::BlobId => Value::Element(EmailValue::BlobId(self.blob_id.clone())),
            EmailProperty::Preview => Value::Str(Cow::Borrowed(
                self.meta.stored_preview().unwrap_or_default(),
            )),
            EmailProperty::Subject => str_value(envelope.subject()),
            EmailProperty::SentAt => envelope
                .datetime()
                .map_or(Value::Null, |date| date_value(&date)),
            EmailProperty::MessageId => envelope.message_id().jmap_ids(),
            EmailProperty::InReplyTo => envelope.in_reply_to().jmap_ids(),
            EmailProperty::References => self.headers.map_or(Value::Null, |headers| {
                self.root_headers()
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
                    self.root_headers().jmap_value(property, headers)
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
