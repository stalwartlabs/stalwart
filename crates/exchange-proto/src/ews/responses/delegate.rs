/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::{
        schema::DeliverMeetingRequests,
        types::{delegate::DelegateUser, value::M},
    },
    xml::{XmlWrite, XmlWriter},
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DelegateUserMessage<'x> {
    pub user: Option<DelegateUser<'x>>,
}

impl ResponseMessage for DelegateUserMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(user) = &self.user {
            w.start(M, "DelegateUser");
            user.write_children(w);
            w.end(M, "DelegateUser");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliverMeetingRequestsTail(pub DeliverMeetingRequests);

impl XmlWrite for DeliverMeetingRequestsTail {
    fn write(&self, w: &mut XmlWriter<'_>) {
        w.leaf(M, "DeliverMeetingRequests", self.0.as_str());
    }
}
