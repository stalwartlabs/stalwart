/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{JmapValue, date_value};
use crate::message::metadata::{HeaderId, HeaderList, HeaderView, RawMessage};
use jmap_proto::object::email::{EmailProperty, HeaderForm, HeaderProperty};
use jmap_tools::{Map, Value};
use mail_parser::{AddressList, HeaderForm as ParseForm, HeaderValue, Mailbox, ParsedValue};
use std::{borrow::Cow, ops::Range, str::from_utf8};

pub trait FieldSource<'s>: Copy {
    fn field(self, range: Range<usize>) -> Option<&'s [u8]>;
}

#[derive(Debug, Clone, Copy)]
pub struct HeaderBytes<'s>(pub &'s [u8]);

impl<'s> FieldSource<'s> for &'s [u8] {
    #[inline]
    fn field(self, range: Range<usize>) -> Option<&'s [u8]> {
        self.get(range)
    }
}

impl<'s> FieldSource<'s> for RawMessage<'s> {
    #[inline]
    fn field(self, range: Range<usize>) -> Option<&'s [u8]> {
        self.contiguous(range)
    }
}

impl HeaderList<'_> {
    pub fn jmap_value<'s>(
        &self,
        property: &EmailProperty,
        source: impl FieldSource<'s>,
    ) -> JmapValue<'s> {
        match property {
            EmailProperty::Header(header) => self.jmap_header(header, source),
            EmailProperty::Headers => self.jmap_headers(source),
            _ => Value::Null,
        }
    }

    pub fn jmap_header<'s>(
        &self,
        header: &HeaderProperty,
        source: impl FieldSource<'s>,
    ) -> JmapValue<'s> {
        let id = HeaderId::parse(header.header.as_bytes());
        let name = header.header.as_bytes();
        let lookup = |view: HeaderView<'_>| -> Option<JmapValue<'s>> {
            if id.is_known() {
                (view.id() == id).then(|| {
                    source
                        .field(view.value_range())
                        .map_or(Value::Null, |raw| HeaderBytes(raw).jmap_value(header.form))
                })
            } else if view.id() == HeaderId::OTHER {
                let field = source.field(view.field_range())?;
                view.raw_name_in(field)
                    .eq_ignore_ascii_case(name)
                    .then(|| HeaderBytes(view.raw_value_in(field)).jmap_value(header.form))
            } else {
                None
            }
        };
        if header.all {
            Value::Array(self.iter().filter_map(lookup).collect())
        } else {
            self.iter().rev().find_map(lookup).unwrap_or(Value::Null)
        }
    }

    pub fn jmap_headers<'s>(&self, source: impl FieldSource<'s>) -> JmapValue<'s> {
        Value::Array(
            self.iter()
                .map(|header| {
                    let field = source.field(header.field_range()).unwrap_or_default();
                    Value::Object(
                        Map::with_capacity(2)
                            .with_key_value(
                                EmailProperty::Name,
                                String::from_utf8_lossy(header.raw_name_in(field)),
                            )
                            .with_key_value(
                                EmailProperty::Value,
                                HeaderBytes(header.raw_value_in(field)).raw_text(),
                            ),
                    )
                })
                .collect(),
        )
    }
}

impl<'s> HeaderBytes<'s> {
    pub fn message_ids(self) -> JmapValue<'s> {
        self.ids(ParseForm::MessageIds.parse(self.0).value())
    }

    pub fn jmap_value(self, form: HeaderForm) -> JmapValue<'s> {
        let parse_form = match form {
            HeaderForm::Raw => {
                return Value::Str(self.raw_text());
            }
            HeaderForm::Text => ParseForm::Text,
            HeaderForm::Addresses | HeaderForm::GroupedAddresses | HeaderForm::URLs => {
                ParseForm::Addresses
            }
            HeaderForm::MessageIds => ParseForm::MessageIds,
            HeaderForm::Date => ParseForm::Date,
        };
        self.form(&parse_form.parse(self.0), form)
    }

    pub fn raw_text(self) -> Cow<'s, str> {
        let raw = self.0.trim_ascii_end();
        if raw.contains(&0) {
            let kept: Vec<u8> = raw.iter().copied().filter(|&byte| byte != 0).collect();
            Cow::Owned(
                String::from_utf8(kept)
                    .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
            )
        } else {
            String::from_utf8_lossy(raw)
        }
    }

    fn form(self, parsed: &ParsedValue<'_>, form: HeaderForm) -> JmapValue<'s> {
        match (parsed.value(), form) {
            (HeaderValue::Text(text), HeaderForm::Raw | HeaderForm::Text) => {
                Value::Str(self.borrow(text))
            }
            (HeaderValue::TextList(list), HeaderForm::Raw | HeaderForm::Text) => {
                let mut joined = String::new();
                for (pos, item) in list.iter().enumerate() {
                    if pos > 0 {
                        joined.push_str(", ");
                    }
                    joined.push_str(item);
                }
                Value::Str(Cow::Owned(joined))
            }
            (HeaderValue::Text(text), HeaderForm::MessageIds) => {
                Value::Array(vec![Value::Str(self.borrow(text))])
            }
            (value @ HeaderValue::TextList(_), HeaderForm::MessageIds) => self.ids(value),
            (HeaderValue::DateTime(date), HeaderForm::Date) => date_value(&date),
            (HeaderValue::Address(list), HeaderForm::URLs) if !list.has_groups() => Value::Array(
                list.mailboxes()
                    .filter_map(|mailbox| {
                        mailbox
                            .address()
                            .filter(|address| address.contains(':'))
                            .map(|address| Value::Str(self.borrow(address)))
                    })
                    .collect(),
            ),
            (HeaderValue::Address(list), HeaderForm::Addresses) => Value::Array(
                list.mailboxes()
                    .map(|mailbox| self.mailbox(mailbox))
                    .collect(),
            ),
            (HeaderValue::Address(list), HeaderForm::GroupedAddresses) => self.grouped(list),
            _ => Value::Null,
        }
    }

    fn grouped(self, list: AddressList<'_>) -> JmapValue<'s> {
        let group = |name: JmapValue<'s>, addresses: Vec<JmapValue<'s>>| {
            Value::Object(
                Map::with_capacity(2)
                    .with_key_value(EmailProperty::Name, name)
                    .with_key_value(EmailProperty::Addresses, Value::Array(addresses)),
            )
        };
        if !list.has_groups() {
            return Value::Array(vec![group(
                Value::Null,
                list.mailboxes()
                    .map(|mailbox| self.mailbox(mailbox))
                    .collect(),
            )]);
        }
        Value::Array(
            list.groups()
                .map(|(name, members)| {
                    group(
                        name.map_or(Value::Null, |name| Value::Str(self.borrow(name))),
                        members.map(|mailbox| self.mailbox(mailbox)).collect(),
                    )
                })
                .collect(),
        )
    }

    fn mailbox(self, mailbox: Mailbox<'_>) -> JmapValue<'s> {
        Value::Object(
            Map::with_capacity(2)
                .with_key_value(
                    EmailProperty::Name,
                    mailbox
                        .name()
                        .map_or(Value::Null, |name| Value::Str(self.borrow(name))),
                )
                .with_key_value(
                    EmailProperty::Email,
                    Value::Str(self.borrow(mailbox.address().unwrap_or_default())),
                ),
        )
    }

    fn ids(self, value: HeaderValue<'_>) -> JmapValue<'s> {
        match value {
            HeaderValue::TextList(list) => Value::Array(
                list.iter()
                    .map(|item| Value::Str(self.borrow(item)))
                    .collect(),
            ),
            HeaderValue::Text(text) => Value::Array(vec![Value::Str(self.borrow(text))]),
            _ => Value::Null,
        }
    }

    fn borrow(self, text: &str) -> Cow<'s, str> {
        let start = text.as_ptr().addr();
        let base = self.0.as_ptr().addr();
        start
            .checked_sub(base)
            .and_then(|offset| self.0.get(offset..offset + text.len()))
            .and_then(|bytes| from_utf8(bytes).ok())
            .filter(|borrowed| *borrowed == text)
            .map_or_else(|| Cow::Owned(text.to_owned()), Cow::Borrowed)
    }
}
