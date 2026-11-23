/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::types::{
        conversation::Conversation,
        value::{EwsValue, M},
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FindConversationBody<'x> {
    pub conversations: Vec<Conversation<'x>>,
    pub total_conversations_in_view: i32,
    pub indexed_offset: i32,
}

impl ResponseMessage for FindConversationBody<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Conversations");
        for conversation in &self.conversations {
            conversation.write(w, "Conversation");
        }
        w.end(M, "Conversations");
        w.leaf_i64(
            M,
            "TotalConversationsInView",
            i64::from(self.total_conversations_in_view),
        );
        w.leaf_i64(M, "IndexedOffset", i64::from(self.indexed_offset));
    }

    fn write_required(w: &mut XmlWriter<'_>) {
        w.start(M, "Conversations");
        w.end(M, "Conversations");
    }
}
