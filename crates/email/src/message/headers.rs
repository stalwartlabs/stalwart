/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    object::email::{EmailProperty, EmailValue, HeaderForm, HeaderProperty},
    types::date::UTCDate,
};
use jmap_tools::{Key, Value};
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

#[inline]
pub(crate) fn unwrap_date(value: Value<'_, EmailProperty, EmailValue>) -> Option<UTCDate> {
    match value {
        Value::Element(EmailValue::Date(date)) => Some(date),
        _ => None,
    }
}
