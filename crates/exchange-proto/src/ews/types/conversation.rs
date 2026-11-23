/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::ItemId,
    value::{DateTime, ItemClasses, List, Strings, XBinary, ews_struct},
};
use crate::ews::schema::Importance;
use std::borrow::Cow;

ews_struct! {
    pub struct ConversationRequest<'x> {
        conversation_id: req "ConversationId" => ItemId<'x>,
        sync_state: opt "SyncState" => XBinary<'x>,
    }
}

ews_struct! {
    pub struct Conversation<'x> {
        conversation_id: req "ConversationId" => ItemId<'x>,
        conversation_topic: req "ConversationTopic" => Cow<'x, str>,
        unique_recipients: req "UniqueRecipients" => Strings<'x>,
        global_unique_recipients: req "GlobalUniqueRecipients" => Strings<'x>,
        unique_unread_senders: req "UniqueUnreadSenders" => Strings<'x>,
        global_unique_unread_senders: req "GlobalUniqueUnreadSenders" => Strings<'x>,
        unique_senders: req "UniqueSenders" => Strings<'x>,
        global_unique_senders: req "GlobalUniqueSenders" => Strings<'x>,
        last_delivery_time: req "LastDeliveryTime" => DateTime,
        global_last_delivery_time: req "GlobalLastDeliveryTime" => DateTime,
        has_attachments: req "HasAttachments" => bool,
        global_has_attachments: req "GlobalHasAttachments" => bool,
        message_count: req "MessageCount" => i32,
        global_message_count: req "GlobalMessageCount" => i32,
        unread_count: req "UnreadCount" => i32,
        global_unread_count: req "GlobalUnreadCount" => i32,
        size: req "Size" => i32,
        global_size: req "GlobalSize" => i32,
        item_classes: req "ItemClasses" => ItemClasses<'x>,
        global_item_classes: req "GlobalItemClasses" => ItemClasses<'x>,
        importance: req "Importance" => Importance,
        global_importance: req "GlobalImportance" => Importance,
        item_ids: req "ItemIds" => List<ItemId<'x>>,
        global_item_ids: req "GlobalItemIds" => List<ItemId<'x>>,
    }
}
