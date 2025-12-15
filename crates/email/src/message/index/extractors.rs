/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::{
    ArchivedMessageMetadataContents, ArchivedMessageMetadataPart, ArchivedMetadataHeaderValue,
    MetadataHeaderName, MetadataHeaderValue,
};
use mail_parser::{Addr, Address, Group, HeaderValue};
use nlp::language::Language;
use rkyv::option::ArchivedOption;
use std::borrow::Cow;

impl ArchivedMessageMetadataContents {
    pub fn is_html_part(&self, part_id: u16) -> bool {
        self.html_body.iter().any(|&id| id == part_id)
    }

    pub fn is_text_part(&self, part_id: u16) -> bool {
        self.text_body.iter().any(|&id| id == part_id)
    }
}

impl ArchivedMessageMetadataPart {
    pub fn language(&self) -> Option<Language> {
        self.header_value(&MetadataHeaderName::ContentLanguage)
            .and_then(|v| {
                Language::from_iso_639(v.as_text()?)
                    .unwrap_or(Language::Unknown)
                    .into()
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressElement {
    Name,
    Address,
    GroupName,
}

pub trait VisitText {
    fn visit_addresses(&self, visitor: impl FnMut(AddressElement, &str));
    fn visit_text<'x>(&'x self, visitor: impl FnMut(&'x str));
    fn into_visit_text(self, visitor: impl FnMut(String));
}

impl VisitText for HeaderValue<'_> {
    fn visit_addresses(&self, mut visitor: impl FnMut(AddressElement, &str)) {
        match self {
            HeaderValue::Address(Address::List(addr_list)) => {
                for addr in addr_list {
                    if let Some(name) = &addr.name {
                        visitor(AddressElement::Name, name);
                    }
                    if let Some(addr) = &addr.address {
                        visitor(AddressElement::Address, addr);
                    }
                }
            }
            HeaderValue::Address(Address::Group(groups)) => {
                for group in groups {
                    if let Some(name) = &group.name {
                        visitor(AddressElement::GroupName, name);
                    }

                    for addr in &group.addresses {
                        if let Some(name) = &addr.name {
                            visitor(AddressElement::Name, name);
                        }
                        if let Some(addr) = &addr.address {
                            visitor(AddressElement::Address, addr);
                        }
                    }
                }
            }
            _ => (),
        }
    }

    fn visit_text<'x>(&'x self, mut visitor: impl FnMut(&'x str)) {
        match &self {
            HeaderValue::Text(text) => {
                visitor(text.as_ref());
            }
            HeaderValue::TextList(texts) => {
                for text in texts {
                    visitor(text.as_ref());
                }
            }
            _ => (),
        }
    }

    fn into_visit_text(self, mut visitor: impl FnMut(String)) {
        match self {
            HeaderValue::Text(text) => {
                visitor(text.into_owned());
            }
            HeaderValue::TextList(texts) => {
                for text in texts {
                    visitor(text.into_owned());
                }
            }
            _ => (),
        }
    }
}

pub trait VisitTextArchived {
    fn visit_addresses(&self, visitor: impl FnMut(AddressElement, &str));
    fn visit_text(&self, visitor: impl FnMut(&str));
}

impl VisitTextArchived for MetadataHeaderValue {
    fn visit_addresses(&self, mut visitor: impl FnMut(AddressElement, &str)) {
        match self {
            MetadataHeaderValue::AddressList(addr_list) => {
                for addr in addr_list.iter() {
                    if let Some(name) = &addr.name {
                        visitor(AddressElement::Name, name);
                    }
                    if let Some(addr) = &addr.address {
                        visitor(AddressElement::Address, addr);
                    }
                }
            }
            MetadataHeaderValue::AddressGroup(groups) => {
                for group in groups.iter() {
                    if let Some(name) = &group.name {
                        visitor(AddressElement::GroupName, name);
                    }

                    for addr in group.addresses.iter() {
                        if let Some(name) = &addr.name {
                            visitor(AddressElement::Name, name);
                        }
                        if let Some(addr) = &addr.address {
                            visitor(AddressElement::Address, addr);
                        }
                    }
                }
            }
            _ => (),
        }
    }

    fn visit_text(&self, mut visitor: impl FnMut(&str)) {
        match &self {
            MetadataHeaderValue::Text(text) => {
                visitor(text.as_ref());
            }
            MetadataHeaderValue::TextList(texts) => {
                for text in texts.iter() {
                    visitor(text.as_ref());
                }
            }
            _ => (),
        }
    }
}

impl VisitTextArchived for ArchivedMetadataHeaderValue {
    fn visit_addresses(&self, mut visitor: impl FnMut(AddressElement, &str)) {
        match self {
            ArchivedMetadataHeaderValue::AddressList(addr_list) => {
                for addr in addr_list.iter() {
                    if let ArchivedOption::Some(name) = &addr.name {
                        visitor(AddressElement::Name, name);
                    }
                    if let ArchivedOption::Some(addr) = &addr.address {
                        visitor(AddressElement::Address, addr);
                    }
                }
            }
            ArchivedMetadataHeaderValue::AddressGroup(groups) => {
                for group in groups.iter() {
                    if let ArchivedOption::Some(name) = &group.name {
                        visitor(AddressElement::GroupName, name);
                    }

                    for addr in group.addresses.iter() {
                        if let ArchivedOption::Some(name) = &addr.name {
                            visitor(AddressElement::Name, name);
                        }
                        if let ArchivedOption::Some(addr) = &addr.address {
                            visitor(AddressElement::Address, addr);
                        }
                    }
                }
            }
            _ => (),
        }
    }

    fn visit_text(&self, mut visitor: impl FnMut(&str)) {
        match &self {
            ArchivedMetadataHeaderValue::Text(text) => {
                visitor(text.as_ref());
            }
            ArchivedMetadataHeaderValue::TextList(texts) => {
                for text in texts.iter() {
                    visitor(text.as_ref());
                }
            }
            _ => (),
        }
    }
}

pub trait TrimTextValue {
    fn trim_text(self, length: usize) -> Self;
}

impl TrimTextValue for HeaderValue<'_> {
    fn trim_text(self, length: usize) -> Self {
        match self {
            HeaderValue::Address(Address::List(v)) => {
                HeaderValue::Address(Address::List(v.trim_text(length)))
            }
            HeaderValue::Address(Address::Group(v)) => {
                HeaderValue::Address(Address::Group(v.trim_text(length)))
            }
            HeaderValue::Text(v) => HeaderValue::Text(v.trim_text(length)),
            HeaderValue::TextList(v) => HeaderValue::TextList(v.trim_text(length)),
            v => v,
        }
    }
}

impl TrimTextValue for Addr<'_> {
    fn trim_text(self, length: usize) -> Self {
        Self {
            name: self.name.map(|v| v.trim_text(length)),
            address: self.address.map(|v| v.trim_text(length)),
        }
    }
}

impl TrimTextValue for Group<'_> {
    fn trim_text(self, length: usize) -> Self {
        Self {
            name: self.name.map(|v| v.trim_text(length)),
            addresses: self.addresses.trim_text(length),
        }
    }
}

impl TrimTextValue for &str {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            let mut index = 0;

            for (i, _) in self.char_indices() {
                if i > length {
                    break;
                }
                index = i;
            }

            &self[..index]
        }
    }
}

impl TrimTextValue for Cow<'_, str> {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            let mut result = String::with_capacity(length);
            for (i, c) in self.char_indices() {
                if i > length {
                    break;
                }
                result.push(c);
            }
            result.into()
        }
    }
}

impl<T: TrimTextValue> TrimTextValue for Vec<T> {
    fn trim_text(self, length: usize) -> Self {
        self.into_iter().map(|v| v.trim_text(length)).collect()
    }
}
