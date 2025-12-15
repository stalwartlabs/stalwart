/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::metadata::{ArchivedMessageMetadataPart, ArchivedMetadataHeaderValue};
use jmap_proto::{
    object::email::{EmailProperty, EmailValue, HeaderForm, HeaderProperty},
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use mail_builder::{
    MessageBuilder,
    headers::{
        address::{Address, EmailAddress, GroupedAddresses},
        date::Date,
        message_id::MessageId,
        raw::Raw,
        text::Text,
        url::URL,
    },
};
use mail_parser::{Addr, DateTime, Group, Header, HeaderName, HeaderValue, parsers::MessageStream};
use utils::chained_bytes::ChainedBytes;

pub trait IntoForm {
    fn into_form(self, form: &HeaderForm) -> Value<'static, EmailProperty, EmailValue>;
}

pub trait HeaderToValue {
    fn header_to_value(
        &self,
        property: &EmailProperty,
        raw_message: &ChainedBytes<'_>,
    ) -> Value<'static, EmailProperty, EmailValue>;
    fn headers_to_value(
        &self,
        raw_message: &ChainedBytes<'_>,
    ) -> Value<'static, EmailProperty, EmailValue>;
}

pub trait ValueToHeader<'x> {
    fn try_into_grouped_addresses(self) -> Option<GroupedAddresses<'x>>;
    fn try_into_address_list(self) -> Option<Vec<Address<'x>>>;
    fn try_into_address(self) -> Option<EmailAddress<'x>>;
}

pub trait BuildHeader<'x>: Sized {
    fn build_header(
        self,
        header: HeaderProperty,
        value: Value<'x, EmailProperty, EmailValue>,
    ) -> Result<Self, HeaderProperty>;
}

impl HeaderToValue for Vec<Header<'_>> {
    fn header_to_value(
        &self,
        property: &EmailProperty,
        raw_message: &ChainedBytes<'_>,
    ) -> Value<'static, EmailProperty, EmailValue> {
        let (header_name, form, all) = match property {
            EmailProperty::Header(header) => (
                HeaderName::parse(header.header.as_str())
                    .unwrap_or_else(|| HeaderName::Other(header.header.as_str().into())),
                header.form,
                header.all,
            ),
            EmailProperty::Sender => (HeaderName::Sender, HeaderForm::Addresses, false),
            EmailProperty::From => (HeaderName::From, HeaderForm::Addresses, false),
            EmailProperty::To => (HeaderName::To, HeaderForm::Addresses, false),
            EmailProperty::Cc => (HeaderName::Cc, HeaderForm::Addresses, false),
            EmailProperty::Bcc => (HeaderName::Bcc, HeaderForm::Addresses, false),
            EmailProperty::ReplyTo => (HeaderName::ReplyTo, HeaderForm::Addresses, false),
            EmailProperty::Subject => (HeaderName::Subject, HeaderForm::Text, false),
            EmailProperty::MessageId => (HeaderName::MessageId, HeaderForm::MessageIds, false),
            EmailProperty::InReplyTo => (HeaderName::InReplyTo, HeaderForm::MessageIds, false),
            EmailProperty::References => (HeaderName::References, HeaderForm::MessageIds, false),
            EmailProperty::SentAt => (HeaderName::Date, HeaderForm::Date, false),
            _ => return Value::Null,
        };

        let is_raw = matches!(form, HeaderForm::Raw) || matches!(header_name, HeaderName::Other(_));
        let mut headers = Vec::new();
        let header_name = header_name.as_str();
        for header in self.iter().rev() {
            if header.name.as_str().eq_ignore_ascii_case(header_name) {
                let raw_header;
                let header_value = if is_raw || matches!(header.value, HeaderValue::Empty) {
                    raw_header =
                        raw_message.get(header.offset_start as usize..header.offset_end as usize);

                    if let Some(bytes) = &raw_header {
                        let bytes = bytes.as_ref();
                        match form {
                            HeaderForm::Raw => {
                                HeaderValue::Text(String::from_utf8_lossy(bytes.trim_end()))
                            }
                            HeaderForm::Text => MessageStream::new(bytes).parse_unstructured(),
                            HeaderForm::Addresses
                            | HeaderForm::GroupedAddresses
                            | HeaderForm::URLs => MessageStream::new(bytes).parse_address(),
                            HeaderForm::MessageIds => MessageStream::new(bytes).parse_id(),
                            HeaderForm::Date => MessageStream::new(bytes).parse_date(),
                        }
                    } else {
                        HeaderValue::Empty
                    }
                } else {
                    header.value.clone()
                };
                headers.push(header_value.into_form(&form));
                if !all {
                    break;
                }
            }
        }

        if !all {
            headers.pop().unwrap_or_default()
        } else {
            if headers.len() > 1 {
                headers.reverse();
            }
            Value::Array(headers)
        }
    }

    fn headers_to_value(
        &self,
        raw_message: &ChainedBytes<'_>,
    ) -> Value<'static, EmailProperty, EmailValue> {
        let mut headers = Vec::with_capacity(self.len());
        for header in self.iter() {
            headers.push(Value::Object(
                Map::with_capacity(2)
                    .with_key_value(EmailProperty::Name, header.name().to_string())
                    .with_key_value(
                        EmailProperty::Value,
                        String::from_utf8_lossy(
                            raw_message
                                .get(header.offset_start as usize..header.offset_end as usize)
                                .unwrap_or_default()
                                .as_ref()
                                .trim_end(),
                        )
                        .into_owned(),
                    ),
            ));
        }
        headers.into()
    }
}

impl IntoForm for HeaderValue<'_> {
    fn into_form(self, form: &HeaderForm) -> Value<'static, EmailProperty, EmailValue> {
        match (self, form) {
            (HeaderValue::Text(text), HeaderForm::Raw | HeaderForm::Text) => {
                text.into_owned().into()
            }
            (HeaderValue::TextList(texts), HeaderForm::Raw | HeaderForm::Text) => {
                texts.join(", ").into()
            }
            (HeaderValue::Text(text), HeaderForm::MessageIds) => {
                Value::Array(vec![text.into_owned().into()])
            }
            (HeaderValue::TextList(texts), HeaderForm::MessageIds) => {
                Value::Array(texts.into_iter().map(|t| t.into_owned().into()).collect())
            }
            (HeaderValue::DateTime(datetime), HeaderForm::Date) => from_mail_datetime(datetime),
            (HeaderValue::Address(mail_parser::Address::List(addrlist)), HeaderForm::URLs) => {
                Value::Array(
                    addrlist
                        .into_iter()
                        .filter_map(|addr| match addr {
                            Addr {
                                address: Some(addr),
                                ..
                            } if addr.contains(':') => Some(addr.into_owned().into()),
                            _ => None,
                        })
                        .collect(),
                )
            }
            (HeaderValue::Address(mail_parser::Address::List(addrlist)), HeaderForm::Addresses) => {
                from_mail_addrlist(addrlist)
            }
            (
                HeaderValue::Address(mail_parser::Address::Group(grouplist)),
                HeaderForm::Addresses,
            ) => Value::Array(
                grouplist
                    .into_iter()
                    .flat_map(|group| group.addresses.into_iter().map(from_mail_addr))
                    .collect(),
            ),
            (
                HeaderValue::Address(mail_parser::Address::List(addrlist)),
                HeaderForm::GroupedAddresses,
            ) => Value::Array(vec![
                Map::with_capacity(2)
                    .with_key_value(EmailProperty::Name, Value::Null)
                    .with_key_value(EmailProperty::Addresses, from_mail_addrlist(addrlist))
                    .into(),
            ]),
            (
                HeaderValue::Address(mail_parser::Address::Group(grouplist)),
                HeaderForm::GroupedAddresses,
            ) => Value::Array(
                grouplist
                    .into_iter()
                    .map(from_mail_group)
                    .collect::<Vec<Value<'static, EmailProperty, EmailValue>>>(),
            ),

            _ => Value::Null,
        }
    }
}

impl<'x> ValueToHeader<'x> for Value<'x, EmailProperty, EmailValue> {
    fn try_into_grouped_addresses(self) -> Option<GroupedAddresses<'x>> {
        let mut obj = self.into_object()?;
        Some(GroupedAddresses {
            name: obj
                .remove(&Key::Property(EmailProperty::Name))
                .and_then(|n| n.into_string()),
            addresses: obj
                .remove(&Key::Property(EmailProperty::Addresses))?
                .try_into_address_list()?,
        })
    }

    fn try_into_address_list(self) -> Option<Vec<Address<'x>>> {
        let list = self.into_array()?;
        let mut addresses = Vec::with_capacity(list.len());
        for value in list {
            addresses.push(Address::Address(value.try_into_address()?));
        }
        Some(addresses)
    }

    fn try_into_address(self) -> Option<EmailAddress<'x>> {
        let mut obj = self.into_object()?;
        Some(EmailAddress {
            name: obj
                .remove(&Key::Property(EmailProperty::Name))
                .and_then(|n| n.into_string()),
            email: obj
                .remove(&Key::Property(EmailProperty::Email))?
                .into_string()?,
        })
    }
}

impl<'x> BuildHeader<'x> for MessageBuilder<'x> {
    fn build_header(
        self,
        header: HeaderProperty,
        value: Value<'x, EmailProperty, EmailValue>,
    ) -> Result<Self, HeaderProperty> {
        Ok(match (&header.form, header.all, value) {
            (HeaderForm::Raw, false, Value::Str(value)) => {
                self.header(header.header, Raw::from(value))
            }
            (HeaderForm::Raw, true, Value::Array(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Raw::from(v.into_string()?).into()),
            ),
            (HeaderForm::Date, false, Value::Element(EmailValue::Date(value))) => {
                self.header(header.header, Date::new(value.timestamp()))
            }
            (HeaderForm::Date, true, Value::Array(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Date::new(unwrap_date(v)?.timestamp()).into()),
            ),
            (HeaderForm::Text, false, Value::Str(value)) => {
                self.header(header.header, Text::from(value))
            }
            (HeaderForm::Text, true, Value::Array(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Text::from(v.into_string()?).into()),
            ),
            (HeaderForm::URLs, false, Value::Array(value)) => self.header(
                header.header,
                URL {
                    url: value
                        .into_iter()
                        .filter_map(|v| v.into_string()?.into())
                        .collect(),
                },
            ),
            (HeaderForm::URLs, true, Value::Array(value)) => self.headers(
                header.header,
                value.into_iter().filter_map(|value| {
                    URL {
                        url: value
                            .into_array()?
                            .into_iter()
                            .filter_map(|v| v.into_string()?.into())
                            .collect(),
                    }
                    .into()
                }),
            ),
            (HeaderForm::MessageIds, false, Value::Array(value)) => self.header(
                header.header,
                MessageId {
                    id: value
                        .into_iter()
                        .filter_map(|v| v.into_string()?.into())
                        .collect(),
                },
            ),
            (HeaderForm::MessageIds, true, Value::Array(value)) => self.headers(
                header.header,
                value.into_iter().filter_map(|value| {
                    MessageId {
                        id: value
                            .into_array()?
                            .into_iter()
                            .filter_map(|v| v.into_string()?.into())
                            .collect(),
                    }
                    .into()
                }),
            ),
            (HeaderForm::Addresses, false, Value::Array(value)) => self.header(
                header.header,
                Address::new_list(
                    value
                        .into_iter()
                        .filter_map(|v| Address::Address(v.try_into_address()?).into())
                        .collect(),
                ),
            ),
            (HeaderForm::Addresses, true, Value::Array(value)) => self.headers(
                header.header,
                value
                    .into_iter()
                    .filter_map(|v| Address::new_list(v.try_into_address_list()?).into()),
            ),
            (HeaderForm::GroupedAddresses, false, Value::Array(value)) => self.header(
                header.header,
                Address::new_list(
                    value
                        .into_iter()
                        .filter_map(|v| Address::Group(v.try_into_grouped_addresses()?).into())
                        .collect(),
                ),
            ),
            (HeaderForm::GroupedAddresses, true, Value::Array(value)) => self.headers(
                header.header,
                value.into_iter().filter_map(|v| {
                    Address::new_list(
                        v.into_array()?
                            .into_iter()
                            .filter_map(|v| Address::Group(v.try_into_grouped_addresses()?).into())
                            .collect::<Vec<_>>(),
                    )
                    .into()
                }),
            ),
            _ => {
                return Err(header);
            }
        })
    }
}

impl HeaderToValue for ArchivedMessageMetadataPart {
    fn header_to_value(
        &self,
        property: &EmailProperty,
        raw_message: &ChainedBytes<'_>,
    ) -> Value<'static, EmailProperty, EmailValue> {
        let (header_name, form, all) = match property {
            EmailProperty::Header(header) => (
                HeaderName::parse(header.header.as_str())
                    .unwrap_or_else(|| HeaderName::Other(header.header.as_str().into())),
                header.form,
                header.all,
            ),
            EmailProperty::Sender => (HeaderName::Sender, HeaderForm::Addresses, false),
            EmailProperty::From => (HeaderName::From, HeaderForm::Addresses, false),
            EmailProperty::To => (HeaderName::To, HeaderForm::Addresses, false),
            EmailProperty::Cc => (HeaderName::Cc, HeaderForm::Addresses, false),
            EmailProperty::Bcc => (HeaderName::Bcc, HeaderForm::Addresses, false),
            EmailProperty::ReplyTo => (HeaderName::ReplyTo, HeaderForm::Addresses, false),
            EmailProperty::Subject => (HeaderName::Subject, HeaderForm::Text, false),
            EmailProperty::MessageId => (HeaderName::MessageId, HeaderForm::MessageIds, false),
            EmailProperty::InReplyTo => (HeaderName::InReplyTo, HeaderForm::MessageIds, false),
            EmailProperty::References => (HeaderName::References, HeaderForm::MessageIds, false),
            EmailProperty::SentAt => (HeaderName::Date, HeaderForm::Date, false),
            _ => return Value::Null,
        };

        let is_raw = matches!(form, HeaderForm::Raw) || matches!(header_name, HeaderName::Other(_));
        let mut headers = Vec::new();
        let header_name = header_name.as_str();
        for header in self.headers.iter().rev() {
            if header.name.as_str().eq_ignore_ascii_case(header_name) {
                let raw_header;
                let header_value =
                    if is_raw || matches!(header.value, ArchivedMetadataHeaderValue::Empty) {
                        raw_header = raw_message.get(header.value_range());

                        if let Some(bytes) = &raw_header {
                            let bytes = bytes.as_ref();
                            match form {
                                HeaderForm::Raw => {
                                    HeaderValue::Text(String::from_utf8_lossy(bytes.trim_end()))
                                }
                                HeaderForm::Text => MessageStream::new(bytes).parse_unstructured(),
                                HeaderForm::Addresses
                                | HeaderForm::GroupedAddresses
                                | HeaderForm::URLs => MessageStream::new(bytes).parse_address(),
                                HeaderForm::MessageIds => MessageStream::new(bytes).parse_id(),
                                HeaderForm::Date => MessageStream::new(bytes).parse_date(),
                            }
                        } else {
                            HeaderValue::Empty
                        }
                    } else {
                        HeaderValue::from(&header.value)
                    };
                headers.push(header_value.into_form(&form));
                if !all {
                    break;
                }
            }
        }

        if !all {
            headers.pop().unwrap_or_default()
        } else {
            if headers.len() > 1 {
                headers.reverse();
            }
            Value::Array(headers)
        }
    }

    fn headers_to_value(
        &self,
        raw_message: &ChainedBytes<'_>,
    ) -> Value<'static, EmailProperty, EmailValue> {
        let mut headers = Vec::with_capacity(self.headers.len());
        for header in self.headers.iter() {
            headers.push(Value::Object(
                Map::with_capacity(2)
                    .with_key_value(EmailProperty::Name, header.name.as_str().to_string())
                    .with_key_value(
                        EmailProperty::Value,
                        String::from_utf8_lossy(
                            raw_message
                                .get(header.value_range())
                                .unwrap_or_default()
                                .as_ref()
                                .trim_end(),
                        )
                        .into_owned(),
                    ),
            ));
        }
        headers.into()
    }
}

trait ByteTrim {
    fn trim_end(&self) -> Self;
}

impl ByteTrim for &[u8] {
    fn trim_end(&self) -> Self {
        let mut end = self.len();
        while end > 0 && self[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        &self[..end]
    }
}

#[inline]
pub(crate) fn unwrap_date(value: Value<'_, EmailProperty, EmailValue>) -> Option<UTCDate> {
    match value {
        Value::Element(EmailValue::Date(date)) => Some(date),
        _ => None,
    }
}

fn from_mail_datetime(date: DateTime) -> Value<'static, EmailProperty, EmailValue> {
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

fn from_mail_addr(value: Addr<'_>) -> Value<'static, EmailProperty, EmailValue> {
    Value::Object(
        Map::with_capacity(2)
            .with_key_value(EmailProperty::Name, value.name.map(|v| v.into_owned()))
            .with_key_value(
                EmailProperty::Email,
                value.address.unwrap_or_default().into_owned(),
            ),
    )
}

fn from_mail_group(group: Group<'_>) -> Value<'static, EmailProperty, EmailValue> {
    Value::Object(
        Map::with_capacity(2)
            .with_key_value(EmailProperty::Name, group.name.map(|v| v.into_owned()))
            .with_key_value(
                EmailProperty::Addresses,
                from_mail_addrlist(group.addresses),
            ),
    )
}

fn from_mail_addrlist(addrlist: Vec<Addr<'_>>) -> Value<'static, EmailProperty, EmailValue> {
    Value::Array(
        addrlist
            .into_iter()
            .map(from_mail_addr)
            .collect::<Vec<Value<'static, EmailProperty, EmailValue>>>(),
    )
}
