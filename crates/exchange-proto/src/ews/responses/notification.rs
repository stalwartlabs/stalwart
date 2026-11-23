/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMessage;
use crate::{
    ews::{
        schema::ConnectionStatus,
        types::{
            ids::{FolderId, ItemId, SubscriptionId, Watermark},
            value::{DateTime, EwsValue, M, T},
        },
    },
    xml::XmlWriter,
};

#[derive(Debug, Clone, PartialEq)]
pub enum EventObject<'x> {
    Folder(FolderId<'x>),
    Item(ItemId<'x>),
}

impl EventObject<'_> {
    fn write(&self, w: &mut XmlWriter<'_>, folder: &str, item: &str) {
        match self {
            EventObject::Folder(id) => id.write(w, folder),
            EventObject::Item(id) => id.write(w, item),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObjectEvent<'x> {
    pub watermark: Option<Watermark<'x>>,
    pub timestamp: DateTime,
    pub object: EventObject<'x>,
    pub parent_folder_id: FolderId<'x>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MovedEvent<'x> {
    pub event: ObjectEvent<'x>,
    pub old_object: EventObject<'x>,
    pub old_parent_folder_id: FolderId<'x>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event<'x> {
    Status {
        watermark: Option<Watermark<'x>>,
    },
    NewMail(ObjectEvent<'x>),
    Created(ObjectEvent<'x>),
    Deleted(ObjectEvent<'x>),
    Modified {
        event: ObjectEvent<'x>,
        unread_count: Option<i32>,
    },
    Moved(MovedEvent<'x>),
    Copied(MovedEvent<'x>),
    FreeBusyChanged(ObjectEvent<'x>),
}

impl ObjectEvent<'_> {
    fn write_children(&self, w: &mut XmlWriter<'_>) {
        if let Some(watermark) = &self.watermark {
            watermark.write(w, "Watermark");
        }
        self.timestamp.write(w, "TimeStamp");
        self.object.write(w, "FolderId", "ItemId");
        self.parent_folder_id.write(w, "ParentFolderId");
    }
}

impl Event<'_> {
    pub fn element(&self) -> &'static str {
        match self {
            Event::Status { .. } => "StatusEvent",
            Event::NewMail(_) => "NewMailEvent",
            Event::Created(_) => "CreatedEvent",
            Event::Deleted(_) => "DeletedEvent",
            Event::Modified { .. } => "ModifiedEvent",
            Event::Moved(_) => "MovedEvent",
            Event::Copied(_) => "CopiedEvent",
            Event::FreeBusyChanged(_) => "FreeBusyChangedEvent",
        }
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        let element = self.element();
        w.start(T, element);
        match self {
            Event::Status { watermark } => {
                if let Some(watermark) = watermark {
                    watermark.write(w, "Watermark");
                }
            }
            Event::NewMail(event)
            | Event::Created(event)
            | Event::Deleted(event)
            | Event::FreeBusyChanged(event) => event.write_children(w),
            Event::Modified {
                event,
                unread_count,
            } => {
                event.write_children(w);
                if let Some(count) = unread_count {
                    w.leaf_i64(T, "UnreadCount", i64::from(*count));
                }
            }
            Event::Moved(moved) | Event::Copied(moved) => {
                moved.event.write_children(w);
                moved.old_object.write(w, "OldFolderId", "OldItemId");
                moved.old_parent_folder_id.write(w, "OldParentFolderId");
            }
        }
        w.end(T, element);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Notification<'x> {
    pub subscription_id: SubscriptionId<'x>,
    pub previous_watermark: Option<Watermark<'x>>,
    pub more_events: Option<bool>,
    pub events: Vec<Event<'x>>,
}

impl Notification<'_> {
    pub fn write(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "Notification");
        self.subscription_id.write(w, "SubscriptionId");
        if let Some(watermark) = &self.previous_watermark {
            watermark.write(w, "PreviousWatermark");
        }
        if let Some(more) = self.more_events {
            w.leaf_bool(T, "MoreEvents", more);
        }
        for event in &self.events {
            event.write(w);
        }
        w.end(M, "Notification");
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubscribeMessage<'x> {
    pub subscription_id: SubscriptionId<'x>,
    pub watermark: Option<Watermark<'x>>,
}

impl ResponseMessage for SubscribeMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.leaf(M, "SubscriptionId", &self.subscription_id.0);
        if let Some(watermark) = &self.watermark {
            w.leaf(M, "Watermark", &watermark.0);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetEventsMessage<'x> {
    pub notification: Option<Notification<'x>>,
}

impl ResponseMessage for GetEventsMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if let Some(notification) = &self.notification {
            notification.write(w);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GetStreamingEventsMessage<'x> {
    pub notifications: Vec<Notification<'x>>,
    pub error_subscription_ids: Vec<SubscriptionId<'x>>,
    pub connection_status: Option<ConnectionStatus>,
}

impl ResponseMessage for GetStreamingEventsMessage<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        if !self.notifications.is_empty() {
            w.start(M, "Notifications");
            for notification in &self.notifications {
                notification.write(w);
            }
            w.end(M, "Notifications");
        }
        if !self.error_subscription_ids.is_empty() {
            w.start(M, "ErrorSubscriptionIds");
            for id in &self.error_subscription_ids {
                w.leaf(M, "SubscriptionId", &id.0);
            }
            w.end(M, "ErrorSubscriptionIds");
        }
        if let Some(status) = self.connection_status {
            w.leaf(M, "ConnectionStatus", status.as_str());
        }
    }
}
