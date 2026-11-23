/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::ews::{
    schema::{BaseShape, UnindexedField},
    types::{path::Path, shape::ItemShape},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShapeUse {
    Get,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ItemFieldSet(u64);

impl ItemFieldSet {
    pub const ID: u64 = 1;
    pub const PARENT: u64 = 1 << 1;
    pub const CLASS: u64 = 1 << 2;
    pub const SUBJECT: u64 = 1 << 3;
    pub const SENSITIVITY: u64 = 1 << 4;
    pub const BODY: u64 = 1 << 5;
    pub const ATTACHMENTS: u64 = 1 << 6;
    pub const RECEIVED: u64 = 1 << 7;
    pub const SIZE: u64 = 1 << 8;
    pub const CATEGORIES: u64 = 1 << 9;
    pub const IMPORTANCE: u64 = 1 << 10;
    pub const IN_REPLY_TO: u64 = 1 << 11;
    pub const IS_SUBMITTED: u64 = 1 << 12;
    pub const IS_DRAFT: u64 = 1 << 13;
    pub const IS_FROM_ME: u64 = 1 << 14;
    pub const HEADERS: u64 = 1 << 15;
    pub const SENT: u64 = 1 << 16;
    pub const CREATED: u64 = 1 << 17;
    pub const DISPLAY_CC: u64 = 1 << 18;
    pub const DISPLAY_TO: u64 = 1 << 19;
    pub const HAS_ATTACHMENTS: u64 = 1 << 20;
    pub const IS_ASSOCIATED: u64 = 1 << 21;
    pub const LAST_MODIFIED: u64 = 1 << 22;
    pub const CONVERSATION_ID: u64 = 1 << 23;
    pub const FLAG: u64 = 1 << 24;
    pub const PREVIEW: u64 = 1 << 25;
    pub const TEXT_BODY: u64 = 1 << 26;
    pub const SENDER: u64 = 1 << 27;
    pub const TO: u64 = 1 << 28;
    pub const CC: u64 = 1 << 29;
    pub const BCC: u64 = 1 << 30;
    pub const READ_RECEIPT: u64 = 1 << 31;
    pub const DELIVERY_RECEIPT: u64 = 1 << 32;
    pub const TOPIC: u64 = 1 << 33;
    pub const FROM: u64 = 1 << 34;
    pub const MESSAGE_ID: u64 = 1 << 35;
    pub const IS_READ: u64 = 1 << 36;
    pub const REFERENCES: u64 = 1 << 37;
    pub const REPLY_TO: u64 = 1 << 38;
    pub const MIME: u64 = 1 << 39;
    pub const MEETING_START: u64 = 1 << 40;
    pub const MEETING_END: u64 = 1 << 41;
    pub const MEETING_ALL_DAY: u64 = 1 << 42;
    pub const MEETING_LOCATION: u64 = 1 << 43;
    pub const MEETING_UID: u64 = 1 << 44;
    pub const MEETING_EVENT: u64 = 1 << 45;
    pub const MEETING_FREE_BUSY: u64 = 1 << 46;
    pub const MEETING_RECURRENCE_ID: u64 = 1 << 47;
    pub const MEETING_ORIGINAL_START: u64 = 1 << 48;
    pub const CONVERSATION_INDEX: u64 = 1 << 49;
    pub const RECEIVED_REPRESENTING: u64 = 1 << 50;
    pub const RESPONSE_REQUESTED: u64 = 1 << 51;
    pub const MEETING_RESPONSE_REQUESTED: u64 = 1 << 52;
    pub const MEETING_RESPONSE: u64 = 1 << 53;
    pub const MEETING_OUT_OF_DATE: u64 = 1 << 54;
    pub const MEETING_PROCESSED: u64 = 1 << 55;
    pub const MEETING_DELEGATED: u64 = 1 << 56;
    pub const MEETING_REQUEST_TYPE: u64 = 1 << 57;
    pub const RECEIVED_BY: u64 = 1 << 58;
    pub const MEETING_RECURRENCE: u64 = 1 << 59;
    pub const MEETING_MODIFIED: u64 = 1 << 60;
    pub const MEETING_DELETED: u64 = 1 << 61;
    pub const MEETING_SPAN: u64 = Self::MEETING_START
        | Self::MEETING_END
        | Self::MEETING_ALL_DAY
        | Self::MEETING_LOCATION
        | Self::MEETING_FREE_BUSY;
    pub const MEETING_INVITATION: u64 = Self::MEETING_UID
        | Self::MEETING_RECURRENCE_ID
        | Self::MEETING_ORIGINAL_START
        | Self::MEETING_RESPONSE_REQUESTED
        | Self::MEETING_REQUEST_TYPE;
    pub const MEETING_SERIES: u64 =
        Self::MEETING_RECURRENCE | Self::MEETING_MODIFIED | Self::MEETING_DELETED;
    pub const MEETING_EVENT_STATE: u64 = Self::MEETING_RESPONSE | Self::MEETING_OUT_OF_DATE;
    pub const MEETING_LOOKUP: u64 = Self::MEETING_EVENT
        | Self::MEETING_PROCESSED
        | Self::MEETING_EVENT_STATE
        | Self::MEETING_MODIFIED;
    pub const MEETING_REQUEST_ONLY: u64 = Self::MEETING_RESPONSE_REQUESTED
        | Self::MEETING_REQUEST_TYPE
        | Self::MEETING_PROCESSED
        | Self::MEETING_EVENT_STATE
        | Self::MEETING_SERIES;
    pub const MEETING: u64 = Self::MEETING_SPAN
        | Self::MEETING_INVITATION
        | Self::MEETING_SERIES
        | Self::MEETING_LOOKUP
        | Self::MEETING_DELEGATED;

    const DEFAULT: u64 = Self::ID
        | Self::SUBJECT
        | Self::SENSITIVITY
        | Self::BODY
        | Self::CREATED
        | Self::SENT
        | Self::FROM
        | Self::HAS_ATTACHMENTS
        | Self::IS_ASSOCIATED
        | Self::DELIVERY_RECEIPT
        | Self::SIZE
        | Self::IS_READ;
    const ALL: u64 = ((Self::MIME - 1) & !Self::TEXT_BODY & !Self::PREVIEW)
        | Self::MEETING
        | Self::CONVERSATION_INDEX
        | Self::RECEIVED_BY
        | Self::RECEIVED_REPRESENTING
        | Self::RESPONSE_REQUESTED;
    const GET_ONLY: u64 = Self::BODY
        | Self::TEXT_BODY
        | Self::HEADERS
        | Self::MIME
        | Self::ATTACHMENTS
        | Self::MEETING;
    const NEEDS_METADATA: u64 = Self::CLASS
        | Self::SUBJECT
        | Self::BODY
        | Self::ATTACHMENTS
        | Self::IMPORTANCE
        | Self::IN_REPLY_TO
        | Self::IS_FROM_ME
        | Self::HEADERS
        | Self::DISPLAY_CC
        | Self::DISPLAY_TO
        | Self::HAS_ATTACHMENTS
        | Self::PREVIEW
        | Self::TEXT_BODY
        | Self::SENDER
        | Self::TO
        | Self::CC
        | Self::BCC
        | Self::READ_RECEIPT
        | Self::DELIVERY_RECEIPT
        | Self::TOPIC
        | Self::FROM
        | Self::MESSAGE_ID
        | Self::REFERENCES
        | Self::REPLY_TO
        | Self::CONVERSATION_INDEX
        | Self::RECEIVED_BY
        | Self::RECEIVED_REPRESENTING
        | Self::MEETING;
    const NEEDS_TEXT: u64 = Self::BODY | Self::TEXT_BODY;

    pub fn from_shape(shape: &ItemShape<'_>, usage: ShapeUse) -> Self {
        let mut fields = match shape.base {
            BaseShape::IdOnly => Self::ID,
            BaseShape::Default => Self::DEFAULT,
            BaseShape::AllProperties | BaseShape::PcxPeopleSearch => Self::ALL,
        };
        for path in &shape.additional {
            if let Path::Field(field) = path {
                fields |= Self::of_field(*field);
            }
        }
        if shape.include_mime {
            fields |= Self::MIME;
        }
        if usage == ShapeUse::List {
            fields &= !Self::GET_ONLY;
        }
        ItemFieldSet(fields)
    }

    pub const fn id_only() -> Self {
        ItemFieldSet(Self::ID)
    }

    pub const fn mime_only() -> Self {
        ItemFieldSet(Self::MIME)
    }

    pub const fn with_metadata() -> Self {
        ItemFieldSet(Self::ID | Self::SUBJECT)
    }

    pub const fn search_results() -> Self {
        ItemFieldSet(
            Self::ID
                | Self::PARENT
                | Self::CLASS
                | Self::SUBJECT
                | Self::SENSITIVITY
                | Self::RECEIVED
                | Self::SIZE
                | Self::IMPORTANCE
                | Self::IS_DRAFT
                | Self::SENT
                | Self::CREATED
                | Self::DISPLAY_CC
                | Self::DISPLAY_TO
                | Self::HAS_ATTACHMENTS
                | Self::LAST_MODIFIED
                | Self::CONVERSATION_ID
                | Self::PREVIEW
                | Self::SENDER
                | Self::CONVERSATION_INDEX
                | Self::TOPIC
                | Self::FROM
                | Self::IS_READ,
        )
    }

    pub const fn classified() -> Self {
        ItemFieldSet(Self::ID | Self::SUBJECT | Self::CLASS)
    }

    fn of_field(field: UnindexedField) -> u64 {
        match field {
            UnindexedField::ItemItemId => Self::ID,
            UnindexedField::ItemParentFolderId => Self::PARENT,
            UnindexedField::ItemItemClass => Self::CLASS,
            UnindexedField::ItemSubject => Self::SUBJECT,
            UnindexedField::ItemSensitivity => Self::SENSITIVITY,
            UnindexedField::ItemBody => Self::BODY,
            UnindexedField::ItemAttachments => Self::ATTACHMENTS,
            UnindexedField::ItemDateTimeReceived => Self::RECEIVED,
            UnindexedField::ItemSize => Self::SIZE,
            UnindexedField::ItemCategories => Self::CATEGORIES,
            UnindexedField::ItemImportance => Self::IMPORTANCE,
            UnindexedField::ItemInReplyTo => Self::IN_REPLY_TO,
            UnindexedField::ItemIsSubmitted => Self::IS_SUBMITTED,
            UnindexedField::ItemIsDraft => Self::IS_DRAFT,
            UnindexedField::ItemIsFromMe => Self::IS_FROM_ME,
            UnindexedField::ItemInternetMessageHeaders => Self::HEADERS,
            UnindexedField::ItemDateTimeSent => Self::SENT,
            UnindexedField::ItemDateTimeCreated => Self::CREATED,
            UnindexedField::ItemDisplayCc => Self::DISPLAY_CC,
            UnindexedField::ItemDisplayTo => Self::DISPLAY_TO,
            UnindexedField::ItemHasAttachments => Self::HAS_ATTACHMENTS,
            UnindexedField::ItemIsAssociated => Self::IS_ASSOCIATED,
            UnindexedField::ItemLastModifiedTime => Self::LAST_MODIFIED,
            UnindexedField::ItemConversationId => Self::CONVERSATION_ID,
            UnindexedField::ItemFlag => Self::FLAG,
            UnindexedField::ItemPreview => Self::PREVIEW,
            UnindexedField::ItemTextBody => Self::TEXT_BODY,
            UnindexedField::ItemMimeContent => Self::MIME,
            UnindexedField::MessageSender => Self::SENDER,
            UnindexedField::MessageToRecipients => Self::TO,
            UnindexedField::MessageCcRecipients => Self::CC,
            UnindexedField::MessageBccRecipients => Self::BCC,
            UnindexedField::MessageIsReadReceiptRequested => Self::READ_RECEIPT,
            UnindexedField::MessageIsDeliveryReceiptRequested => Self::DELIVERY_RECEIPT,
            UnindexedField::MessageIsResponseRequested => {
                Self::RESPONSE_REQUESTED | Self::MEETING_RESPONSE_REQUESTED
            }
            UnindexedField::MessageConversationTopic => Self::TOPIC,
            UnindexedField::MessageConversationIndex => Self::CONVERSATION_INDEX,
            UnindexedField::MessageFrom => Self::FROM,
            UnindexedField::MessageInternetMessageId => Self::MESSAGE_ID,
            UnindexedField::MessageIsRead => Self::IS_READ,
            UnindexedField::MessageReferences => Self::REFERENCES,
            UnindexedField::MessageReplyTo => Self::REPLY_TO,
            UnindexedField::MessageReceivedBy => Self::RECEIVED_BY,
            UnindexedField::MessageReceivedRepresenting => Self::RECEIVED_REPRESENTING,
            UnindexedField::CalendarStart => Self::MEETING_START,
            UnindexedField::CalendarEnd => Self::MEETING_END,
            UnindexedField::CalendarIsAllDayEvent => Self::MEETING_ALL_DAY,
            UnindexedField::CalendarLocation => Self::MEETING_LOCATION,
            UnindexedField::CalendarUid => Self::MEETING_UID,
            UnindexedField::MeetingAssociatedCalendarItemId => Self::MEETING_EVENT,
            UnindexedField::MeetingRequestIntendedFreeBusyStatus => Self::MEETING_FREE_BUSY,
            UnindexedField::CalendarRecurrenceId => Self::MEETING_RECURRENCE_ID,
            UnindexedField::CalendarOriginalStart => Self::MEETING_ORIGINAL_START,
            UnindexedField::MeetingResponseType => Self::MEETING_RESPONSE,
            UnindexedField::MeetingIsOutOfDate => Self::MEETING_OUT_OF_DATE,
            UnindexedField::MeetingHasBeenProcessed => Self::MEETING_PROCESSED,
            UnindexedField::MeetingIsDelegated => Self::MEETING_DELEGATED,
            UnindexedField::MeetingRequestMeetingRequestType => Self::MEETING_REQUEST_TYPE,
            UnindexedField::CalendarRecurrence => Self::MEETING_RECURRENCE,
            UnindexedField::CalendarModifiedOccurrences => Self::MEETING_MODIFIED,
            UnindexedField::CalendarDeletedOccurrences => Self::MEETING_DELETED,
            _ => 0,
        }
    }

    pub const fn without(self, fields: u64) -> Self {
        ItemFieldSet(self.0 & !fields)
    }

    pub const fn has(self, field: u64) -> bool {
        self.0 & field != 0
    }

    pub const fn needs_metadata(self) -> bool {
        self.has(Self::NEEDS_METADATA)
    }

    pub const fn needs_text(self) -> bool {
        self.has(Self::NEEDS_TEXT)
    }
}
