/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod attach;
pub mod attachment;
pub mod bulk;
pub mod content;
pub mod conversation;
pub mod create;
pub mod edit;
pub mod fields;
pub mod find;
pub mod get;
pub mod props;
pub mod recipients;
pub mod render;
pub mod send;
pub mod sync;
pub mod transfer;
pub mod update;
pub mod write;

use super::context::EwsContext;
use crate::{
    cache::ExchangeCacheFetch,
    folders::{
        FolderNode,
        access::{ItemWrite, ViewRights},
    },
    groupware_write::MeetingReply,
    store::{FolderKind, FolderRef},
};
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    ews::{
        Status,
        schema::ResponseCode,
        types::{
            ids::{AttachmentId, BaseItemId, EwsIdStr, ItemId},
            item::{Item, ItemFields, MessageFields, MessageItem},
        },
    },
    ids::{
        ews::{AttachmentPath, EwsChangeKey, EwsConversationId, EwsObjectId},
        token::ObjectKind,
    },
};
use std::sync::Arc;
use types::type_state::DataType;

const ITEM_NOT_FOUND: &str = "The specified object was not found in the store.";
const ID_MALFORMED: &str = "Id is malformed.";
const ID_EMPTY: &str = "Id must be non-empty.";
const ID_INVALID: &str = "The item id is not valid for this operation.";
const ACCESS_DENIED: &str = "The access token does not grant access to mail.";
const FORBIDDEN: &str = "Access is denied. Check credentials and try again.";
const DUPLICATE: &str = "The item is listed more than once in the request.";
const PROPERTY_SET: &str = "The property cannot be set on this item.";
const EXTENDED_PROPERTY: &str = "The extended property attribute combination is invalid.";
const PROPERTY_APPEND: &str = "The property does not support append.";
const MOVE_COPY_FAILED: &str = "The item cannot be placed in more folders.";
const CONFLICT: &str = "The item changed while it was being saved; retry the request.";
const UNSUPPORTED: &str = "Only MessageDisposition SaveOnly is supported when updating items.";
const STALE: &str = "The change key does not match the current version of the item.";
const NOT_A_MESSAGE: &str = "Only messages can be created.";
const MIME_INVALID: &str = "MimeContent could not be decoded.";
const TOO_LARGE: &str = "The message exceeds the maximum message size.";
const NO_ADDRESS: &str = "A recipient has no email address.";
const INVALID_MAILBOX: &str = "EmailAddress or ItemId must be included in the request.";
const QUOTA: &str = "The mailbox quota is exceeded.";
const UNPARSABLE: &str = "The message could not be parsed.";
const NO_DELETED_ITEMS: &str = "The mailbox has no Deleted Items folder.";
const ATTACHMENT_NOT_FOUND: &str = "The attachment was not found.";
const KEYWORD_LIMIT: &str = "The item would exceed the maximum number of keywords.";
const CATEGORY_INVALID: &str = "A category name cannot be stored.";
const NOT_A_DRAFT: &str = "Attachments can only be changed on draft messages.";
const CONTENT_NOT_DRAFT: &str = "Message content can only be changed on draft messages.";
const NESTED_ATTACHMENT: &str = "Only attachments of the item itself can be deleted.";
const REFERENCE_ATTACHMENT: &str = "Reference attachments are not supported.";
const MISSING_ATTACHED_ITEM: &str = "The item attachment does not contain an item.";
const ATTACHED_ITEM_TYPE: &str = "Only messages can be attached as items.";
const CONTENT_INVALID: &str = "The attachment content could not be decoded.";
const ITEM_SAVE: &str = "The item could not be saved.";
const CONTACT_FOLDER: &str = "Contacts can only be created in contact folders.";
const TASK_FOLDER: &str = "Tasks can only be created in task folders.";
const CALENDAR_FOLDER: &str = "Calendar items can only be created in calendar folders.";
const OBJECT_TYPE_CHANGED: &str = "The item class does not match the item type.";
const GROUPWARE_FOLDER: &str =
    "Contacts, calendar items and tasks can only be placed in folders of their own type.";
const OCCURRENCE_MOVE_COPY: &str =
    "An occurrence cannot be moved or copied; move or copy the recurring master instead.";
const OCCURRENCE_DELETED: &str = "The occurrence was deleted from the recurrence.";
const OCCURRENCE_OUT_OF_RANGE: &str = "The occurrence index is outside the recurrence range.";
const DURATION_TOO_LONG: &str = "The calendar item duration is longer than five years.";
const END_BEFORE_START: &str = "EndDate is earlier than StartDate";
const NOT_OCCURRENCE: &str = "The Id specified does not represent an occurrence.";
const NOT_RECURRING_MASTER: &str = "The specified Id does not represent a recurring master item.";
const INVITATIONS_REQUIRED: &str = "SendMeetingInvitations is required for calendar items.";
const INVITATIONS_OR_CANCELLATIONS_REQUIRED: &str =
    "SendMeetingInvitationsOrCancellations is required for calendar items.";
const CANCELLATIONS_REQUIRED: &str = "SendMeetingCancellations is required for calendar items.";
const INVALID_RECURRENCE: &str = "The recurrence pattern is invalid.";
const UNSUPPORTED_RECURRENCE: &str = "The recurrence pattern is not supported.";
const NO_OCCURRENCE: &str = "The recurrence has no occurrences in the specified range.";
const ORGANIZER_RESPONSE: &str = "The organizer cannot respond to their own meeting.";
const NOT_ORGANIZER: &str = "Only the organizer can cancel the meeting.";
const TOO_MANY_ATTENDEES: &str = "The meeting has too many attendees.";
const DISPOSITION_REQUIRED: &str = "MessageDisposition attribute is required.";
const SAVE_ONLY_CANCEL: &str = "A meeting cancellation must be sent.";
const CANNOT_DELETE: &str = "The access token does not grant permission to delete this item.";
const TOO_MANY_ITEMS: &str = "Too many items are listed for a move or copy between mailboxes.";
const INVALID_CHANGE_KEY: &str = "The change key is invalid.";
const CORRUPT_DATA: &str = "The item data is corrupt and cannot be imported.";
const NOT_STORED: &str = "Occurrences cannot be exported or uploaded; use the recurring master.";
const ASSOCIATED_RECORD: &str = "An associated item can only be uploaded with IsAssociated.";
const ASSOCIATED_ATTACHMENTS: &str = "Associated items cannot have attachments.";
const INVALID_FLAG: &str = "The flag status and dates do not form a valid flag.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MailItem {
    pub mailbox_id: u32,
    pub document_id: u32,
}

pub(crate) struct EmailIds {
    account_id: u32,
    exchange: Arc<ExchangeAccountCache>,
}

impl EmailIds {
    pub async fn load(server: &Server, ctx: &EwsContext) -> trc::Result<Self> {
        let account_id = ctx.account.account_id;
        Ok(EmailIds {
            account_id,
            exchange: server.get_cached_exchange(account_id).await?,
        })
    }

    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    pub fn exchange(&self) -> &ExchangeAccountCache {
        &self.exchange
    }

    pub fn identity(&self, item: MailItem) -> u32 {
        self.exchange.email_item(item.mailbox_id, item.document_id)
    }

    pub fn current(&self, mailbox_id: u32, identity: u32) -> MailItem {
        MailItem {
            mailbox_id,
            document_id: self.exchange.email_document(mailbox_id, identity),
        }
    }

    pub fn item_id(&self, item: MailItem, change_id: u64) -> ItemId<'static> {
        self.identity_item_id(item.mailbox_id, self.identity(item), change_id)
    }

    pub fn identity_item_id(
        &self,
        mailbox_id: u32,
        identity: u32,
        change_id: u64,
    ) -> ItemId<'static> {
        ItemId {
            id: self.encode(mailbox_id, identity),
            change_key: Some(EwsIdStr::Minted(
                EwsChangeKey {
                    kind: ObjectKind::Email,
                    change_id,
                }
                .encode(),
            )),
        }
    }

    pub fn conversation_id(&self, thread: u32) -> ItemId<'static> {
        ItemId {
            id: EwsIdStr::Minted(
                EwsConversationId {
                    account: self.account_id,
                    thread,
                }
                .encode(),
            ),
            change_key: None,
        }
    }

    pub fn decode_conversation(&self, ctx: &EwsContext, id: &ItemId<'_>) -> Result<u32, ItemError> {
        match EwsConversationId::decode(id.id.as_str()).ok_or(ItemError::Malformed)? {
            EwsConversationId { account, thread } if account == self.account_id => {
                mail_allowed(ctx)?;
                Ok(thread)
            }
            _ => Err(ItemError::NotFound),
        }
    }

    pub fn deleted_id(&self, mailbox_id: u32, identity: u32) -> ItemId<'static> {
        ItemId {
            id: self.encode(mailbox_id, identity),
            change_key: None,
        }
    }

    pub fn attachment_id(
        &self,
        item: MailItem,
        fingerprint: u32,
        path: AttachmentPath,
    ) -> AttachmentId<'static> {
        self.identity_attachment_id(item.mailbox_id, self.identity(item), fingerprint, path)
    }

    pub fn identity_attachment_id(
        &self,
        mailbox_id: u32,
        identity: u32,
        fingerprint: u32,
        path: AttachmentPath,
    ) -> AttachmentId<'static> {
        AttachmentId {
            id: EwsIdStr::Minted(
                EwsObjectId::Attachment {
                    account: self.account_id,
                    kind: ObjectKind::Email,
                    container: mailbox_id,
                    id: identity,
                    fingerprint,
                    path,
                }
                .encode(),
            ),
            root_item_id: None,
            root_item_change_key: None,
        }
    }

    pub fn decode(&self, ctx: &EwsContext, id: &BaseItemId<'_>) -> Result<MailItem, ItemError> {
        match id {
            BaseItemId::Item(id) => self.decode_item_id(ctx, id),
            BaseItemId::RecurringMaster { occurrence, .. }
                if matches!(
                    EwsObjectId::decode(occurrence.as_str()),
                    Some(EwsObjectId::Item { .. })
                ) =>
            {
                Err(ItemError::NotOccurrence)
            }
            _ => Err(ItemError::InvalidId),
        }
    }

    pub fn decode_item_id(&self, ctx: &EwsContext, id: &ItemId<'_>) -> Result<MailItem, ItemError> {
        match EwsObjectId::decode(id.id.as_str()).ok_or(ItemError::Malformed)? {
            EwsObjectId::Item {
                account,
                kind: ObjectKind::Email,
                container,
                id,
            } if account == self.account_id => {
                mail_allowed(ctx)?;
                Ok(self.current(container, id))
            }
            EwsObjectId::Item { .. } => Err(ItemError::NotFound),
            _ => Err(ItemError::InvalidId),
        }
    }

    pub fn resolve(
        &self,
        ctx: &EwsContext,
        cache: &MessageStoreCache,
        id: &BaseItemId<'_>,
    ) -> Result<MailItem, ItemError> {
        readable_item(ctx, cache, self.decode(ctx, id)?)
    }

    pub fn resolve_item_id(
        &self,
        ctx: &EwsContext,
        cache: &MessageStoreCache,
        id: &ItemId<'_>,
    ) -> Result<MailItem, ItemError> {
        readable_item(ctx, cache, self.decode_item_id(ctx, id)?)
    }

    fn encode(&self, mailbox_id: u32, identity: u32) -> EwsIdStr<'static> {
        EwsIdStr::Minted(
            EwsObjectId::Item {
                account: self.account_id,
                kind: ObjectKind::Email,
                container: mailbox_id,
                id: identity,
            }
            .encode(),
        )
    }
}

fn readable_item(
    ctx: &EwsContext,
    cache: &MessageStoreCache,
    item: MailItem,
) -> Result<MailItem, ItemError> {
    match cache
        .email_by_id(&item.document_id)
        .filter(|message| message.has_mailbox_id(item.mailbox_id))
    {
        Some(message) => readable_mailbox(
            ctx,
            item,
            message.mailboxes().iter().map(|uid| uid.mailbox_id),
        ),
        None => Err(ItemError::NotFound),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemError {
    AccessDenied,
    Forbidden,
    NotFound,
    InvalidId,
    Malformed,
    IdEmpty,
    Duplicate,
    InvalidPropertySet,
    InvalidExtendedProperty,
    InvalidPropertyAppend,
    MoveCopyFailed,
    Conflict,
    Stale,
    Unsupported,
    NotAMessage,
    MimeInvalid,
    TooLarge,
    NoAddress,
    InvalidMailbox,
    Quota,
    Unparsable,
    KeywordLimit,
    CategoryInvalid,
    NoDeletedItems,
    AttachmentNotFound,
    NotADraft,
    ContentNotDraft,
    NestedAttachment,
    ReferenceAttachment,
    MissingAttachedItem,
    AttachedItemType,
    ContentInvalid,
    ItemSave,
    ContactFolder,
    TaskFolder,
    CalendarFolder,
    GroupwareFolder,
    OccurrenceMoveCopy,
    ObjectTypeChanged,
    OccurrenceDeleted,
    OccurrenceOutOfRange,
    NotRecurringMaster,
    NotOccurrence,
    DurationTooLong,
    EndBeforeStart,
    InvitationsRequired,
    InvitationsOrCancellationsRequired,
    CancellationsRequired,
    InvalidRecurrence,
    UnsupportedRecurrence,
    NoOccurrence,
    OrganizerResponse(MeetingReply),
    NotOrganizer,
    TooManyAttendees,
    DispositionRequired,
    SaveOnlyCancel,
    CannotDelete,
    TooManyItems,
    InvalidChangeKey,
    CorruptData,
    UidConflict,
    NotStored,
    AssociatedRecord,
    AssociatedAttachments,
    InvalidFlag,
}

impl ItemError {
    pub fn status(self) -> Status<'static> {
        match self {
            ItemError::AccessDenied => {
                Status::error(ResponseCode::ErrorAccessDenied, ACCESS_DENIED)
            }
            ItemError::Forbidden => Status::error(ResponseCode::ErrorAccessDenied, FORBIDDEN),
            ItemError::NotFound => Status::error(ResponseCode::ErrorItemNotFound, ITEM_NOT_FOUND),
            ItemError::CannotDelete => {
                Status::error(ResponseCode::ErrorCannotDeleteObject, CANNOT_DELETE)
            }
            ItemError::InvalidId => Status::error(ResponseCode::ErrorInvalidId, ID_INVALID),
            ItemError::Malformed => {
                Status::error(ResponseCode::ErrorInvalidIdMalformed, ID_MALFORMED)
            }
            ItemError::IdEmpty => Status::error(ResponseCode::ErrorInvalidIdEmpty, ID_EMPTY),
            ItemError::Duplicate => Status::error(ResponseCode::ErrorInvalidOperation, DUPLICATE),
            ItemError::InvalidPropertySet => {
                Status::error(ResponseCode::ErrorInvalidPropertySet, PROPERTY_SET)
            }
            ItemError::InvalidExtendedProperty => Status::error(
                ResponseCode::ErrorInvalidExtendedProperty,
                EXTENDED_PROPERTY,
            ),
            ItemError::InvalidPropertyAppend => {
                Status::error(ResponseCode::ErrorInvalidPropertyAppend, PROPERTY_APPEND)
            }
            ItemError::MoveCopyFailed => {
                Status::error(ResponseCode::ErrorMoveCopyFailed, MOVE_COPY_FAILED)
            }
            ItemError::Conflict => {
                Status::error(ResponseCode::ErrorInternalServerTransientError, CONFLICT)
            }
            ItemError::Stale => Status::error(ResponseCode::ErrorIrresolvableConflict, STALE),
            ItemError::Unsupported => {
                Status::error(ResponseCode::ErrorInvalidOperation, UNSUPPORTED)
            }
            ItemError::NotAMessage => {
                Status::error(ResponseCode::ErrorInvalidOperation, NOT_A_MESSAGE)
            }
            ItemError::MimeInvalid => {
                Status::error(ResponseCode::ErrorMimeContentConversionFailed, MIME_INVALID)
            }
            ItemError::TooLarge => Status::error(ResponseCode::ErrorMessageSizeExceeded, TOO_LARGE),
            ItemError::NoAddress => Status::error(ResponseCode::ErrorInvalidRecipients, NO_ADDRESS),
            ItemError::InvalidMailbox => {
                Status::error(ResponseCode::ErrorInvalidMailbox, INVALID_MAILBOX)
            }
            ItemError::Quota => Status::error(ResponseCode::ErrorQuotaExceeded, QUOTA),
            ItemError::Unparsable => {
                Status::error(ResponseCode::ErrorMimeContentConversionFailed, UNPARSABLE)
            }
            ItemError::KeywordLimit => Status::error(ResponseCode::ErrorItemSave, KEYWORD_LIMIT),
            ItemError::CategoryInvalid => {
                Status::error(ResponseCode::ErrorItemSave, CATEGORY_INVALID)
            }
            ItemError::NoDeletedItems => {
                Status::error(ResponseCode::ErrorCannotDeleteObject, NO_DELETED_ITEMS)
            }
            ItemError::AttachmentNotFound => {
                Status::error(ResponseCode::ErrorInvalidAttachmentId, ATTACHMENT_NOT_FOUND)
            }
            ItemError::NotADraft => Status::error(ResponseCode::ErrorInvalidOperation, NOT_A_DRAFT),
            ItemError::ContentNotDraft => {
                Status::error(ResponseCode::ErrorInvalidOperation, CONTENT_NOT_DRAFT)
            }
            ItemError::NestedAttachment => {
                Status::error(ResponseCode::ErrorInvalidOperation, NESTED_ATTACHMENT)
            }
            ItemError::ReferenceAttachment => {
                Status::error(ResponseCode::ErrorInvalidOperation, REFERENCE_ATTACHMENT)
            }
            ItemError::MissingAttachedItem => Status::error(
                ResponseCode::ErrorMissingItemForCreateItemAttachment,
                MISSING_ATTACHED_ITEM,
            ),
            ItemError::AttachedItemType => Status::error(
                ResponseCode::ErrorInvalidItemForOperationCreateItemAttachment,
                ATTACHED_ITEM_TYPE,
            ),
            ItemError::ContentInvalid => {
                Status::error(ResponseCode::ErrorInvalidRequest, CONTENT_INVALID)
            }
            ItemError::ItemSave | ItemError::UidConflict => {
                Status::error(ResponseCode::ErrorItemSave, ITEM_SAVE)
            }
            ItemError::ContactFolder => Status::error(
                ResponseCode::ErrorCannotCreateContactInNonContactFolder,
                CONTACT_FOLDER,
            ),
            ItemError::TaskFolder => Status::error(
                ResponseCode::ErrorCannotCreateTaskInNonTaskFolder,
                TASK_FOLDER,
            ),
            ItemError::CalendarFolder => Status::error(
                ResponseCode::ErrorCannotCreateCalendarItemInNonCalendarFolder,
                CALENDAR_FOLDER,
            ),
            ItemError::ObjectTypeChanged => {
                Status::error(ResponseCode::ErrorObjectTypeChanged, OBJECT_TYPE_CHANGED)
            }
            ItemError::GroupwareFolder => {
                Status::error(ResponseCode::ErrorMoveCopyFailed, GROUPWARE_FOLDER)
            }
            ItemError::OccurrenceMoveCopy => Status::error(
                ResponseCode::ErrorCalendarCannotMoveOrCopyOccurrence,
                OCCURRENCE_MOVE_COPY,
            ),
            ItemError::OccurrenceDeleted => Status::error(
                ResponseCode::ErrorCalendarOccurrenceIsDeletedFromRecurrence,
                OCCURRENCE_DELETED,
            ),
            ItemError::OccurrenceOutOfRange => Status::error(
                ResponseCode::ErrorCalendarOccurrenceIndexIsOutOfRecurrenceRange,
                OCCURRENCE_OUT_OF_RANGE,
            ),
            ItemError::NotRecurringMaster => Status::error(
                ResponseCode::ErrorCalendarCannotUseIdForRecurringMasterId,
                NOT_RECURRING_MASTER,
            ),
            ItemError::NotOccurrence => Status::error(
                ResponseCode::ErrorCalendarCannotUseIdForOccurrenceId,
                NOT_OCCURRENCE,
            ),
            ItemError::EndBeforeStart => Status::error(
                ResponseCode::ErrorCalendarEndDateIsEarlierThanStartDate,
                END_BEFORE_START,
            ),
            ItemError::DurationTooLong => Status::error(
                ResponseCode::ErrorCalendarDurationIsTooLong,
                DURATION_TOO_LONG,
            ),
            ItemError::InvitationsRequired => Status::error(
                ResponseCode::ErrorSendMeetingInvitationsRequired,
                INVITATIONS_REQUIRED,
            ),
            ItemError::InvitationsOrCancellationsRequired => Status::error(
                ResponseCode::ErrorSendMeetingInvitationsOrCancellationsRequired,
                INVITATIONS_OR_CANCELLATIONS_REQUIRED,
            ),
            ItemError::CancellationsRequired => Status::error(
                ResponseCode::ErrorSendMeetingCancellationsRequired,
                CANCELLATIONS_REQUIRED,
            ),
            ItemError::InvalidRecurrence => Status::error(
                ResponseCode::ErrorCalendarInvalidRecurrence,
                INVALID_RECURRENCE,
            ),
            ItemError::UnsupportedRecurrence => Status::error(
                ResponseCode::ErrorUnsupportedRecurrence,
                UNSUPPORTED_RECURRENCE,
            ),
            ItemError::NoOccurrence => {
                Status::error(ResponseCode::ErrorRecurrenceHasNoOccurrence, NO_OCCURRENCE)
            }
            ItemError::OrganizerResponse(response) => Status::error(
                match response {
                    MeetingReply::Accept => ResponseCode::ErrorCalendarIsOrganizerForAccept,
                    MeetingReply::Tentative => ResponseCode::ErrorCalendarIsOrganizerForTentative,
                    MeetingReply::Decline => ResponseCode::ErrorCalendarIsOrganizerForDecline,
                },
                ORGANIZER_RESPONSE,
            ),
            ItemError::NotOrganizer => {
                Status::error(ResponseCode::ErrorCalendarIsNotOrganizer, NOT_ORGANIZER)
            }
            ItemError::TooManyAttendees => {
                Status::error(ResponseCode::ErrorInvalidRecipients, TOO_MANY_ATTENDEES)
            }
            ItemError::DispositionRequired => Status::error(
                ResponseCode::ErrorMessageDispositionRequired,
                DISPOSITION_REQUIRED,
            ),
            ItemError::SaveOnlyCancel => {
                Status::error(ResponseCode::ErrorInvalidOperation, SAVE_ONLY_CANCEL)
            }
            ItemError::TooManyItems => {
                Status::error(ResponseCode::ErrorInvalidOperation, TOO_MANY_ITEMS)
            }
            ItemError::InvalidChangeKey => {
                Status::error(ResponseCode::ErrorInvalidChangeKey, INVALID_CHANGE_KEY)
            }
            ItemError::CorruptData => Status::error(ResponseCode::ErrorCorruptData, CORRUPT_DATA),
            ItemError::NotStored => Status::error(ResponseCode::ErrorInvalidOperation, NOT_STORED),
            ItemError::AssociatedRecord => {
                Status::error(ResponseCode::ErrorInvalidOperation, ASSOCIATED_RECORD)
            }
            ItemError::AssociatedAttachments => {
                Status::error(ResponseCode::ErrorInvalidOperation, ASSOCIATED_ATTACHMENTS)
            }
            ItemError::InvalidFlag => {
                Status::error(ResponseCode::ErrorInvalidArgument, INVALID_FLAG)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailWrite {
    Read,
    Edit,
    ReadState,
    Delete,
    Move,
}

pub(crate) fn writable_mail(
    ctx: &EwsContext,
    cache: &MessageStoreCache,
    item: MailItem,
    write: MailWrite,
) -> Result<MailItem, ItemError> {
    if !ctx.access.is_delegate() {
        return Ok(item);
    }
    let Some(message) = cache
        .email_by_id(&item.document_id)
        .filter(|message| message.has_mailbox_id(item.mailbox_id))
    else {
        return Ok(item);
    };
    let mailboxes = || message.mailboxes().iter().map(|uid| uid.mailbox_id);
    let item = readable_mailbox(ctx, item, mailboxes())?;
    let every = |write| mailboxes().all(|id| may_write_mailbox(ctx, id, write));
    match write {
        MailWrite::Read => Ok(item),
        MailWrite::Edit if every(ItemWrite::Edit) => Ok(item),
        MailWrite::ReadState if every(ItemWrite::ReadState) => Ok(item),
        MailWrite::Edit | MailWrite::ReadState => Err(ItemError::Forbidden),
        MailWrite::Delete | MailWrite::Move
            if may_write_mailbox(ctx, item.mailbox_id, ItemWrite::Delete) =>
        {
            Ok(item)
        }
        MailWrite::Delete => Err(ItemError::CannotDelete),
        MailWrite::Move => Err(ItemError::Forbidden),
    }
}

pub(crate) fn may_write_mailbox(ctx: &EwsContext, mailbox_id: u32, write: ItemWrite) -> bool {
    let node = mailbox_node(mailbox_id);
    ctx.access.of(node).contains(write.needs(node))
}

pub(crate) fn readable_mailbox(
    ctx: &EwsContext,
    item: MailItem,
    mailboxes: impl Iterator<Item = u32>,
) -> Result<MailItem, ItemError> {
    let ViewRights::Delegate(rights) = &ctx.access else {
        return Ok(item);
    };
    let rights_of = |id| rights.of(mailbox_node(id));
    if rights_of(item.mailbox_id).reads_items() {
        return Ok(item);
    }
    let mut visible = false;
    for mailbox_id in mailboxes {
        let rights = rights_of(mailbox_id);
        if rights.reads_items() {
            return Ok(MailItem { mailbox_id, ..item });
        }
        visible |= rights.is_visible();
    }
    Err(if visible {
        ItemError::Forbidden
    } else {
        ItemError::NotFound
    })
}

pub(crate) fn reads_mailbox(access: &ViewRights, mailbox_id: u32) -> bool {
    access.of(mailbox_node(mailbox_id)).reads_items()
}

fn mailbox_node(id: u32) -> FolderNode {
    FolderNode::Stored(FolderRef {
        kind: FolderKind::Mailbox,
        id,
    })
}

pub(crate) fn mail_allowed(ctx: &EwsContext) -> Result<(), ItemError> {
    if ctx.account.data_types.contains(DataType::Email)
        && ctx.account.data_types.contains(DataType::Mailbox)
    {
        Ok(())
    } else {
        Err(ItemError::AccessDenied)
    }
}

pub(crate) fn id_only(id: ItemId<'static>) -> Item<'static> {
    Item::Message(Box::new(MessageItem {
        item: ItemFields {
            item_id: Some(id),
            ..Default::default()
        },
        message: MessageFields::default(),
    }))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/item/tests.rs"]
mod tests;
