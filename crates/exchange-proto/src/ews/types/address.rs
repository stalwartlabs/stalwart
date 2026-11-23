/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::ItemId,
    value::{EwsValue, T, ews_fields, fields_value},
};
use crate::{
    ews::{
        parser::{Parser, Result},
        schema::MailboxType,
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

ews_fields! {
    pub struct EmailAddress<'x> {
        name: "Name" => Cow<'x, str>,
        email_address: "EmailAddress" => Cow<'x, str>,
        routing_type: "RoutingType" => Cow<'x, str>,
        mailbox_type: "MailboxType" => MailboxType,
        item_id: "ItemId" => Box<ItemId<'x>>,
        original_display_name: "OriginalDisplayName" => Cow<'x, str>,
    }
}

fields_value!(EmailAddress<'x>);

impl EmailAddress<'_> {
    pub fn has_address(&self) -> bool {
        self.email_address
            .as_deref()
            .is_some_and(|address| !address.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SingleRecipient<'x>(pub EmailAddress<'x>);

impl<'x> EwsValue<'x> for SingleRecipient<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut mailbox = EmailAddress::default();
        while let Some(child) = p.child()? {
            if child.local == "Mailbox" {
                p.expect_types(&child)?;
                mailbox = EmailAddress::parse(p, &child.attrs)?;
            } else {
                p.skip()?;
            }
        }
        Ok(SingleRecipient(mailbox))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        if self.0.has_address() {
            w.start(T, local);
            self.0.write(w, "Mailbox");
            w.end(T, local);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Recipients<'x>(pub Vec<EmailAddress<'x>>);

impl<'x> EwsValue<'x> for Recipients<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            if child.local == "Mailbox" {
                p.expect_types(&child)?;
                p.count_id()?;
                list.push(EmailAddress::parse(p, &child.attrs)?);
            } else {
                p.skip()?;
            }
        }
        Ok(Recipients(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        for mailbox in &self.0 {
            mailbox.write(w, "Mailbox");
        }
        w.end(T, local);
    }
}
