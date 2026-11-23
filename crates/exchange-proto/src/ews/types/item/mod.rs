/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod attachment;
pub mod calendar;
pub mod contact;
pub mod response;
pub mod task;

use self::{
    attachment::Attachments,
    calendar::{
        CalendarFields, MeetingCancellationFields, MeetingFields, MeetingRequestFields,
        MeetingResponseFields,
    },
    contact::{ContactFields, DistributionListFields},
    response::{ResponseObject, ResponseObjectFields, ResponseObjectKind, ResponseObjectSet},
    task::TaskFields,
};
use crate::{
    common::Guid,
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{IconIndex, Importance, InferenceClassification, Sensitivity},
        types::{
            address::{Recipients, SingleRecipient},
            common::{Body, EffectiveRights, Flag, InternetHeaders, RetentionTag},
            ids::{FolderId, ItemId},
            value::{
                DateTime, EwsValue, List, ListItem, Repeated, Strings, T, XBinary, ews_fields,
                parse_base64,
            },
            xprop::ExtendedProperty,
        },
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimeContent<'x> {
    pub character_set: Option<Cow<'x, str>>,
    pub content: XBinary<'x>,
}

impl<'x> EwsValue<'x> for MimeContent<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let character_set = p.attr(attrs, "CharacterSet")?;
        Ok(MimeContent {
            character_set,
            content: XBinary::Parsed(parse_base64(p)?),
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local)
            .attr_opt("CharacterSet", self.character_set.as_deref());
        self.content.write_content(w);
        w.end(T, local);
    }
}

ews_fields! {
    pub struct ItemFields<'x> {
        mime_content: "MimeContent" => MimeContent<'x>,
        item_id: "ItemId" => ItemId<'x>,
        parent_folder_id: "ParentFolderId" => FolderId<'x>,
        item_class: "ItemClass" => Cow<'x, str>,
        subject: "Subject" => Cow<'x, str>,
        sensitivity: "Sensitivity" => Sensitivity,
        body: "Body" => Body<'x>,
        attachments: "Attachments" => Attachments<'x>,
        date_time_received: "DateTimeReceived" => DateTime,
        size: "Size" => i32,
        categories: "Categories" => Strings<'x>,
        importance: "Importance" => Importance,
        in_reply_to: "InReplyTo" => Cow<'x, str>,
        is_submitted: "IsSubmitted" => bool,
        is_draft: "IsDraft" => bool,
        is_from_me: "IsFromMe" => bool,
        is_resend: "IsResend" => bool,
        is_unmodified: "IsUnmodified" => bool,
        internet_message_headers: "InternetMessageHeaders" => InternetHeaders<'x>,
        date_time_sent: "DateTimeSent" => DateTime,
        date_time_created: "DateTimeCreated" => DateTime,
        response_objects: "ResponseObjects" => ResponseObjectSet,
        reminder_due_by: "ReminderDueBy" => DateTime,
        reminder_is_set: "ReminderIsSet" => bool,
        reminder_next_time: "ReminderNextTime" => DateTime,
        reminder_minutes_before_start: "ReminderMinutesBeforeStart" => i32,
        display_cc: "DisplayCc" => Cow<'x, str>,
        display_to: "DisplayTo" => Cow<'x, str>,
        display_bcc: "DisplayBcc" => Cow<'x, str>,
        has_attachments: "HasAttachments" => bool,
        extended_property: "ExtendedProperty" => Repeated<ExtendedProperty<'x>>,
        culture: "Culture" => Cow<'x, str>,
        effective_rights: "EffectiveRights" => EffectiveRights,
        last_modified_name: "LastModifiedName" => Cow<'x, str>,
        last_modified_time: "LastModifiedTime" => DateTime,
        is_associated: "IsAssociated" => bool,
        web_client_read_form_query_string: "WebClientReadFormQueryString" => Cow<'x, str>,
        web_client_edit_form_query_string: "WebClientEditFormQueryString" => Cow<'x, str>,
        conversation_id: "ConversationId" => ItemId<'x>,
        unique_body: "UniqueBody" => Body<'x>,
        flag: "Flag" => Flag,
        store_entry_id: "StoreEntryId" => XBinary<'x>,
        instance_key: "InstanceKey" => XBinary<'x>,
        normalized_body: "NormalizedBody" => Body<'x>,
        policy_tag: "PolicyTag" => RetentionTag,
        archive_tag: "ArchiveTag" => RetentionTag,
        retention_date: "RetentionDate" => DateTime,
        preview: "Preview" => Cow<'x, str>,
        is_clutter: "IsClutter" => bool,
        block_status: "BlockStatus" => bool,
        has_blocked_images: "HasBlockedImages" => bool,
        text_body: "TextBody" => Body<'x>,
        icon_index: "IconIndex" => IconIndex,
        search_key: "SearchKey" => XBinary<'x>,
        sort_key: "SortKey" => i64,
        hashtags: "Hashtags" => Strings<'x>,
        mentions: "Mentions" => Recipients<'x>,
        mentioned_me: "MentionedMe" => bool,
        pending_social_activity_tag_ids: "PendingSocialActivityTagIds" => Strings<'x>,
        at_all_mention: "AtAllMention" => bool,
        can_delete: "CanDelete" => bool,
        inference_classification: "InferenceClassification" => InferenceClassification,
    }
    skip {
        "EntityExtractionResult", "RightsManagementLicenseData", "PredictedActionReasons",
        "MentionsPreview", "MentionsEx", "AppliedHashtags", "AppliedHashtagsPreview", "Likes",
        "LikesPreview",
    }
}

impl ListItem for Guid {
    const ITEM: &'static str = "MailboxGuid";
}

ews_fields! {
    pub struct MessageFields<'x> {
        sender: "Sender" => SingleRecipient<'x>,
        to_recipients: "ToRecipients" => Recipients<'x>,
        cc_recipients: "CcRecipients" => Recipients<'x>,
        bcc_recipients: "BccRecipients" => Recipients<'x>,
        is_read_receipt_requested: "IsReadReceiptRequested" => bool,
        is_delivery_receipt_requested: "IsDeliveryReceiptRequested" => bool,
        conversation_index: "ConversationIndex" => XBinary<'x>,
        conversation_topic: "ConversationTopic" => Cow<'x, str>,
        from: "From" => SingleRecipient<'x>,
        internet_message_id: "InternetMessageId" => Cow<'x, str>,
        is_read: "IsRead" => bool,
        is_response_requested: "IsResponseRequested" => bool,
        references: "References" => Cow<'x, str>,
        reply_to: "ReplyTo" => Recipients<'x>,
        received_by: "ReceivedBy" => SingleRecipient<'x>,
        received_representing: "ReceivedRepresenting" => SingleRecipient<'x>,
        sender_smtp_address: "SenderSMTPAddress" => Cow<'x, str>,
        mailbox_guids: "MailboxGuids" => List<Guid>,
    }
    skip { "ApprovalRequestData", "VotingInformation", "ReminderMessageData", "MessageSafety" }
}

ews_fields! {
    pub struct PostItemFields<'x> {
        conversation_index: "ConversationIndex" => XBinary<'x>,
        conversation_topic: "ConversationTopic" => Cow<'x, str>,
        from: "From" => SingleRecipient<'x>,
        internet_message_id: "InternetMessageId" => Cow<'x, str>,
        is_read: "IsRead" => bool,
        posted_time: "PostedTime" => DateTime,
        references: "References" => Cow<'x, str>,
        sender: "Sender" => SingleRecipient<'x>,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    SharingMessage,
    RoleMember,
    Network,
    Person,
}

impl ItemKind {
    pub const fn element(self) -> &'static str {
        match self {
            ItemKind::SharingMessage => "SharingMessage",
            ItemKind::RoleMember => "RoleMember",
            ItemKind::Network => "Network",
            ItemKind::Person => "Person",
        }
    }
}

macro_rules! item_payloads {
    ($($name:ident { $($part:ident: $ty:ident),+ $(,)? }),+ $(,)?) => {
        $(
            #[derive(Debug, Clone, PartialEq, Default)]
            pub struct $name<'x> {
                pub item: ItemFields<'x>,
                $(pub $part: $ty<'x>,)+
            }

            impl<'x> $name<'x> {
                fn parse_child(&mut self, p: &mut Parser<'x>, child: &Child<'x>) -> Result<bool> {
                    Ok(self.item.parse_child(p, child)? $(|| self.$part.parse_child(p, child)?)+)
                }

                pub fn write_fields(&self, w: &mut XmlWriter<'_>) {
                    self.item.write_fields(w);
                    $(self.$part.write_fields(w);)+
                }
            }
        )+
    };
}

item_payloads! {
    MessageItem { message: MessageFields },
    CalendarItem { calendar: CalendarFields },
    ContactItem { contact: ContactFields },
    DistributionListItem { list: DistributionListFields },
    MeetingMessageItem { message: MessageFields, meeting: MeetingFields },
    MeetingRequestItem { message: MessageFields, meeting: MeetingFields, request: MeetingRequestFields },
    MeetingResponseItem { message: MessageFields, meeting: MeetingFields, response: MeetingResponseFields },
    MeetingCancellationItem {
        message: MessageFields,
        meeting: MeetingFields,
        cancellation: MeetingCancellationFields,
    },
    TaskItem { task: TaskFields },
    PostItemItem { post: PostItemFields },
}

#[derive(Debug, Clone, PartialEq)]
pub enum Item<'x> {
    Item(Box<ItemFields<'x>>),
    Message(Box<MessageItem<'x>>),
    CalendarItem(Box<CalendarItem<'x>>),
    Contact(Box<ContactItem<'x>>),
    DistributionList(Box<DistributionListItem<'x>>),
    MeetingMessage(Box<MeetingMessageItem<'x>>),
    MeetingRequest(Box<MeetingRequestItem<'x>>),
    MeetingResponse(Box<MeetingResponseItem<'x>>),
    MeetingCancellation(Box<MeetingCancellationItem<'x>>),
    Task(Box<TaskItem<'x>>),
    PostItem(Box<PostItemItem<'x>>),
    ResponseObject(ResponseObjectKind, Box<ResponseObject<'x>>),
    Other(ItemKind, Box<ItemFields<'x>>),
}

const _: () = assert!(size_of::<Item<'static>>() <= 16);

#[derive(Clone, Copy)]
enum ItemElement {
    Item,
    Message,
    CalendarItem,
    Contact,
    DistributionList,
    MeetingMessage,
    MeetingRequest,
    MeetingResponse,
    MeetingCancellation,
    Task,
    PostItem,
    Response(ResponseObjectKind),
    Other(ItemKind),
}

impl ItemElement {
    fn parse(local: &str) -> Option<Self> {
        hashify::map!(local.as_bytes(), ItemElement,
            "Item" => ItemElement::Item,
            "Message" => ItemElement::Message,
            "CalendarItem" => ItemElement::CalendarItem,
            "Contact" => ItemElement::Contact,
            "DistributionList" => ItemElement::DistributionList,
            "MeetingMessage" => ItemElement::MeetingMessage,
            "MeetingRequest" => ItemElement::MeetingRequest,
            "MeetingResponse" => ItemElement::MeetingResponse,
            "MeetingCancellation" => ItemElement::MeetingCancellation,
            "Task" => ItemElement::Task,
            "PostItem" => ItemElement::PostItem,
            "AcceptItem" => ItemElement::Response(ResponseObjectKind::Accept),
            "TentativelyAcceptItem" => ItemElement::Response(ResponseObjectKind::TentativelyAccept),
            "DeclineItem" => ItemElement::Response(ResponseObjectKind::Decline),
            "ReplyToItem" => ItemElement::Response(ResponseObjectKind::ReplyTo),
            "ForwardItem" => ItemElement::Response(ResponseObjectKind::Forward),
            "ReplyAllToItem" => ItemElement::Response(ResponseObjectKind::ReplyAll),
            "CancelCalendarItem" => ItemElement::Response(ResponseObjectKind::CancelCalendarItem),
            "RemoveItem" => ItemElement::Response(ResponseObjectKind::Remove),
            "SuppressReadReceipt" => ItemElement::Response(ResponseObjectKind::SuppressReadReceipt),
            "PostReplyItem" => ItemElement::Response(ResponseObjectKind::PostReply),
            "AcceptSharingInvitation" => ItemElement::Response(ResponseObjectKind::AcceptSharingInvitation),
            "AddItemToMyCalendar" => ItemElement::Response(ResponseObjectKind::AddItemToMyCalendar),
            "ProposeNewTime" => ItemElement::Response(ResponseObjectKind::ProposeNewTime),
            "SharingMessage" => ItemElement::Other(ItemKind::SharingMessage),
            "RoleMember" => ItemElement::Other(ItemKind::RoleMember),
            "Network" => ItemElement::Other(ItemKind::Network),
            "Person" => ItemElement::Other(ItemKind::Person),
        )
        .copied()
    }
}

fn parse_payload<'x, P: Default>(
    p: &mut Parser<'x>,
    parse_child: fn(&mut P, &mut Parser<'x>, &Child<'x>) -> Result<bool>,
) -> Result<Box<P>> {
    let mut payload = Box::<P>::default();
    parse_fields(p, |p, c| parse_child(&mut payload, p, c))?;
    Ok(payload)
}

fn parse_fields<'x>(
    p: &mut Parser<'x>,
    mut field: impl FnMut(&mut Parser<'x>, &Child<'x>) -> Result<bool>,
) -> Result<()> {
    while let Some(child) = p.child()? {
        if !field(p, &child)? {
            p.skip()?;
        }
    }
    Ok(())
}

impl<'x> Item<'x> {
    pub fn parse_child(p: &mut Parser<'x>, child: &Child<'x>) -> Result<Option<Self>> {
        match ItemElement::parse(child.local) {
            Some(element) => {
                p.expect_types(child)?;
                Self::parse_element(p, &child.attrs, element).map(Some)
            }
            None => Ok(None),
        }
    }

    pub(super) fn parse_attached(p: &mut Parser<'x>, child: &Child<'x>) -> Result<Option<Self>> {
        match ItemElement::parse(child.local) {
            Some(ItemElement::Response(_)) | None => Ok(None),
            Some(element) => {
                p.expect_types(child)?;
                Self::parse_element(p, &child.attrs, element).map(Some)
            }
        }
    }

    pub fn parse_list(p: &mut Parser<'x>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(item) => {
                    p.count_id()?;
                    list.push(item);
                }
                None => p.skip()?,
            }
        }
        Ok(list)
    }

    pub fn parse_one(p: &mut Parser<'x>) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(item) if found.is_none() => found = Some(item),
                Some(_) => return Err(p.error(ParseErrorKind::InvalidValue("Item"))),
                None => p.skip()?,
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Item")))
    }

    fn parse_element(p: &mut Parser<'x>, attrs: &Attrs<'x>, element: ItemElement) -> Result<Self> {
        Ok(match element {
            ItemElement::Item => Item::Item(parse_payload(p, ItemFields::parse_child)?),
            ItemElement::Other(kind) => {
                Item::Other(kind, parse_payload(p, ItemFields::parse_child)?)
            }
            ItemElement::Message => Item::Message(parse_payload(p, MessageItem::parse_child)?),
            ItemElement::CalendarItem => {
                Item::CalendarItem(parse_payload(p, CalendarItem::parse_child)?)
            }
            ItemElement::Contact => Item::Contact(parse_payload(p, ContactItem::parse_child)?),
            ItemElement::DistributionList => {
                Item::DistributionList(parse_payload(p, DistributionListItem::parse_child)?)
            }
            ItemElement::Task => Item::Task(parse_payload(p, TaskItem::parse_child)?),
            ItemElement::PostItem => Item::PostItem(parse_payload(p, PostItemItem::parse_child)?),
            ItemElement::MeetingMessage => {
                Item::MeetingMessage(parse_payload(p, MeetingMessageItem::parse_child)?)
            }
            ItemElement::MeetingRequest => {
                Item::MeetingRequest(parse_payload(p, MeetingRequestItem::parse_child)?)
            }
            ItemElement::MeetingResponse => {
                Item::MeetingResponse(parse_payload(p, MeetingResponseItem::parse_child)?)
            }
            ItemElement::MeetingCancellation => {
                Item::MeetingCancellation(parse_payload(p, MeetingCancellationItem::parse_child)?)
            }
            ItemElement::Response(kind) => {
                let mut object = Box::new(ResponseObject {
                    object_name: p.attr(attrs, "ObjectName")?,
                    item: ItemFields::default(),
                    message: MessageFields::default(),
                    extra: ResponseObjectFields::default(),
                });
                let ResponseObject {
                    item,
                    message,
                    extra,
                    ..
                } = &mut *object;
                parse_fields(p, |p, c| {
                    Ok(item.parse_child(p, c)?
                        || message.parse_child(p, c)?
                        || extra.parse_child(p, c)?)
                })?;
                Item::ResponseObject(kind, object)
            }
        })
    }

    pub const fn element(&self) -> &'static str {
        match self {
            Item::Item(_) => "Item",
            Item::Message(..) => "Message",
            Item::CalendarItem(..) => "CalendarItem",
            Item::Contact(..) => "Contact",
            Item::DistributionList(..) => "DistributionList",
            Item::MeetingMessage(..) => "MeetingMessage",
            Item::MeetingRequest(..) => "MeetingRequest",
            Item::MeetingResponse(..) => "MeetingResponse",
            Item::MeetingCancellation(..) => "MeetingCancellation",
            Item::Task(..) => "Task",
            Item::PostItem(..) => "PostItem",
            Item::ResponseObject(kind, _) => kind.element(),
            Item::Other(kind, _) => kind.element(),
        }
    }

    pub fn fields(&self) -> &ItemFields<'x> {
        match self {
            Item::Item(item) | Item::Other(_, item) => item,
            Item::Message(payload) => &payload.item,
            Item::CalendarItem(payload) => &payload.item,
            Item::Contact(payload) => &payload.item,
            Item::DistributionList(payload) => &payload.item,
            Item::MeetingMessage(payload) => &payload.item,
            Item::MeetingRequest(payload) => &payload.item,
            Item::MeetingResponse(payload) => &payload.item,
            Item::MeetingCancellation(payload) => &payload.item,
            Item::Task(payload) => &payload.item,
            Item::PostItem(payload) => &payload.item,
            Item::ResponseObject(_, object) => &object.item,
        }
    }

    pub fn message_fields(&self) -> Option<&MessageFields<'x>> {
        match self {
            Item::Message(payload) => Some(&payload.message),
            Item::MeetingMessage(payload) => Some(&payload.message),
            Item::MeetingRequest(payload) => Some(&payload.message),
            Item::MeetingResponse(payload) => Some(&payload.message),
            Item::MeetingCancellation(payload) => Some(&payload.message),
            _ => None,
        }
    }

    pub fn message_fields_mut(&mut self) -> Option<&mut MessageFields<'x>> {
        match self {
            Item::Message(payload) => Some(&mut payload.message),
            Item::MeetingMessage(payload) => Some(&mut payload.message),
            Item::MeetingRequest(payload) => Some(&mut payload.message),
            Item::MeetingResponse(payload) => Some(&mut payload.message),
            Item::MeetingCancellation(payload) => Some(&mut payload.message),
            _ => None,
        }
    }

    pub fn fields_mut(&mut self) -> &mut ItemFields<'x> {
        match self {
            Item::Item(item) | Item::Other(_, item) => item,
            Item::Message(payload) => &mut payload.item,
            Item::CalendarItem(payload) => &mut payload.item,
            Item::Contact(payload) => &mut payload.item,
            Item::DistributionList(payload) => &mut payload.item,
            Item::MeetingMessage(payload) => &mut payload.item,
            Item::MeetingRequest(payload) => &mut payload.item,
            Item::MeetingResponse(payload) => &mut payload.item,
            Item::MeetingCancellation(payload) => &mut payload.item,
            Item::Task(payload) => &mut payload.item,
            Item::PostItem(payload) => &mut payload.item,
            Item::ResponseObject(_, object) => &mut object.item,
        }
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        let name = self.element();
        w.start(T, name);
        self.write_content(w);
        w.end(T, name);
    }

    pub fn write_untyped(&self, w: &mut XmlWriter<'_>) {
        w.start("", "Item").attr("xsi:type", self.element());
        self.write_content(w);
        w.end("", "Item");
    }

    fn write_content(&self, w: &mut XmlWriter<'_>) {
        match self {
            Item::Item(item) | Item::Other(_, item) => item.write_fields(w),
            Item::Message(payload) => payload.write_fields(w),
            Item::CalendarItem(payload) => payload.write_fields(w),
            Item::Contact(payload) => payload.write_fields(w),
            Item::DistributionList(payload) => payload.write_fields(w),
            Item::MeetingMessage(payload) => payload.write_fields(w),
            Item::MeetingRequest(payload) => payload.write_fields(w),
            Item::MeetingResponse(payload) => payload.write_fields(w),
            Item::MeetingCancellation(payload) => payload.write_fields(w),
            Item::Task(payload) => payload.write_fields(w),
            Item::PostItem(payload) => payload.write_fields(w),
            Item::ResponseObject(_, object) => {
                w.attr_opt("ObjectName", object.object_name.as_deref());
                object.item.write_fields(w);
                object.message.write_fields(w);
                object.extra.write_fields(w);
            }
        }
    }
}
