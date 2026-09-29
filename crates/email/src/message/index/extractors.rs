/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::PartView;
use mail_parser::{Address, HeaderValue, Mailbox};
use nlp::language::Language;

impl PartView<'_> {
    pub fn language(&self) -> Option<Language> {
        self.content_language()
            .last()
            .map(|language| Language::from_iso_639(language).unwrap_or(Language::Unknown))
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

fn visit_mailbox(mailbox: Mailbox<'_>, visitor: &mut impl FnMut(AddressElement, &str)) {
    if let Some(name) = mailbox.name() {
        visitor(AddressElement::Name, name);
    }
    if let Some(addr) = mailbox.address() {
        visitor(AddressElement::Address, addr);
    }
}

impl VisitText for HeaderValue<'_> {
    fn visit_addresses(&self, mut visitor: impl FnMut(AddressElement, &str)) {
        if let HeaderValue::Address(addresses) = self {
            for address in addresses.iter() {
                match address {
                    Address::Mailbox(mailbox) => visit_mailbox(mailbox, &mut visitor),
                    Address::Group(group) => {
                        if let Some(name) = group.name() {
                            visitor(AddressElement::GroupName, name);
                        }
                        for mailbox in group.mailboxes() {
                            visit_mailbox(mailbox, &mut visitor);
                        }
                    }
                }
            }
        }
    }

    fn visit_text<'x>(&'x self, mut visitor: impl FnMut(&'x str)) {
        match self {
            HeaderValue::Text(text) => {
                visitor(text);
            }
            HeaderValue::TextList(texts) => {
                for text in texts.iter() {
                    visitor(text);
                }
            }
            _ => (),
        }
    }

    fn into_visit_text(self, mut visitor: impl FnMut(String)) {
        self.visit_text(|text| visitor(text.to_string()));
    }
}
