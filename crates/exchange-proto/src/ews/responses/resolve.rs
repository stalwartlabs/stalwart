/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Paging, ResponseMessage};
use crate::{
    ews::types::{
        address::EmailAddress,
        ids::AlternateId,
        item::ContactItem,
        value::{EwsValue, M, T},
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Resolution<'x> {
    pub mailbox: EmailAddress<'x>,
    pub contact: Option<Box<ContactItem<'x>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolveNamesMessage<'x> {
    pub paging: Paging,
    pub resolutions: Vec<Resolution<'x>>,
}

impl ResponseMessage for ResolveNamesMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "ResolutionSet");
        self.paging.write_attrs(w);
        for resolution in &self.resolutions {
            w.start(T, "Resolution");
            resolution.mailbox.write(w, "Mailbox");
            if let Some(contact) = &resolution.contact {
                w.start(T, "Contact");
                contact.write_fields(w);
                w.end(T, "Contact");
            }
            w.end(T, "Resolution");
        }
        w.end(M, "ResolutionSet");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExpandDlMessage<'x> {
    pub paging: Paging,
    pub mailboxes: Vec<EmailAddress<'x>>,
}

impl ResponseMessage for ExpandDlMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "DLExpansion");
        self.paging.write_attrs(w);
        for mailbox in &self.mailboxes {
            mailbox.write(w, "Mailbox");
        }
        w.end(M, "DLExpansion");
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConvertIdMessage<'x> {
    pub alternate_id: Option<AlternateId<'x>>,
}

impl ResponseMessage for ConvertIdMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(id) = &self.alternate_id {
            id.write_typed(w, M, "AlternateId");
        }
    }
}
