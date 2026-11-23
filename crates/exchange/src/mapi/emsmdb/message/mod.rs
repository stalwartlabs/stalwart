/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod attach_row;
mod distlist;
mod early_reply;
pub mod edit;
pub mod fai;
pub mod groupware_import;
pub mod groupware_move;
pub mod groupware_save;
pub mod import;
pub mod load;
mod meeting_copy;
mod meeting_decline;
pub mod object_row;
mod recipient_row;
pub mod save;
pub mod status;
pub mod submit;
pub mod write;

use super::{
    execute::{MailboxView, RopContext, RopError, RopResult},
    folder::stored_mailbox,
    props::{MAX_INLINE_VALUE, PropBag, PropOut},
    staged::{attachment_size, content_size},
    state::{AttachmentObject, MessageObject, RecipientColumns, ServerObject},
    store::StoreGuids,
};
use crate::{
    folders::{FolderNode, SpecialFolder},
    mail::AccountCategories,
    mapi::ids::{IdSpace, MapiId},
    receipt::receipt_pending,
    store::{FolderKind, FolderRef, named::AccountNamedProps},
};
use common::cache::{
    email::MessageRef,
    exchange::{ExchangeAccountCache, Placement},
};
use email::cache::email::MessageCacheAccess;
use exchange_proto::{
    common::{FileTime, UtcSeconds, Utf16Le},
    convert::{
        conversation::ConversationIndex,
        model::{AttachData, Attachment, MessageContent, PropBag as ContentBag},
        tags::{
            message_flags,
            recipient_type::{self, WireType},
        },
    },
    ics::fx::CopyItem,
    ids::{Eid, Gid, mid::ServerIdValue},
    mapi::{
        ErrorCode,
        prop::row::RowValues,
        prop::{
            CodePage, NamedPropMap, OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag, PropType,
            PropValue, tags,
        },
        recipient::{RecipientKind, RecipientRow, flags},
        rop::{
            DecodedRop,
            requests::{OpenAttachment, OpenEmbeddedMessage, OpenMessage, ReadRecipients},
            responses::{
                OpenEmbeddedMessageResponse, OpenMessageResponse, OpenRecipientRow,
                ReadRecipientRow, ReadRecipientsResponse, TypedString,
            },
            views::MapiString,
        },
    },
};
use groupware::cache::GroupwareCache;
use load::embedded;
use object_row::category_keys;
use recipient_row::{RECIPIENT_COLUMNS, RecipientColumnWriter};
use smallvec::SmallVec;
use std::ops::Range;
use trc::AddContext;
use types::collection::{Collection, SyncCollection};
use types::keyword::{DRAFT, FLAGGED, HASATTACHMENT, SEEN};
use types::type_state::DataType;
use write::{NewContent, new_content};

pub const MAX_EMBED_DEPTH: usize = 8;
const MAPI_MESSAGE: i32 = 5;
const MAPI_ATTACH: i32 = 7;
pub const FLAG_STATUS_FLAGGED: i32 = 2;
const FOLLOWUP_ICON_RED: i32 = 6;
const TO_DO_ITEM_FLAGGED: i32 = 0x1;
const TO_DO_RECIPIENT_FLAGGED: i32 = 0x8;
const MEETING_CLASS_PREFIX: &[u8] = b"IPM.Schedule.Meeting.";
const MAX_OPEN_RECIPIENTS: usize = 255;
const MAX_READ_RECIPIENTS: usize = 254;
const OPEN_MODE_CREATE: u8 = 0x02;
const BODY_SOURCES: [PropId; 3] = [
    tags::BODY.id(),
    tags::BODY_HTML.id(),
    tags::RTF_COMPRESSED.id(),
];

struct RecipientText {
    kind: u8,
    display: Range<usize>,
    email: Range<usize>,
    columns: Range<usize>,
}

impl RecipientText {
    fn row<'x>(&self, text: &'x [u8], columns: u16) -> RecipientRow<'x> {
        RecipientRow {
            flags: flags::EMAIL | flags::DISPLAY_NAME | flags::SAME_AS_DISPLAY | flags::UNICODE,
            kind: RecipientKind::Smtp,
            email: utf16_at(text, &self.email),
            display_name: utf16_at(text, &self.display),
            simple_display_name: None,
            transmittable_display_name: None,
            columns: if columns == 0 {
                RowValues::empty()
            } else {
                RowValues::from_encoded(text.get(self.columns.clone()).unwrap_or_default(), columns)
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sending {
    Original,
    Resend,
}

impl Sending {
    fn of(props: &ContentBag) -> Self {
        if object_row::is_resend(props) {
            Sending::Resend
        } else {
            Sending::Original
        }
    }

    fn recipient_type(self, recipient: &ContentBag) -> u8 {
        let kind = match recipient.get(PropKeyRef::Tag(tags::RECIPIENT_TYPE.id()), PropType::I32) {
            Some(OwnedPropValue::I32(kind)) => *kind,
            _ => recipient_type::TO,
        };
        WireType::from_stored(match self {
            Sending::Resend if kind & recipient_type::FLAGS == 0 => recipient_type::P1,
            _ => kind,
        })
        .0
    }
}

fn column_count(columns: &[PropTag]) -> u16 {
    u16::try_from(columns.len()).unwrap_or(u16::MAX)
}

pub(super) fn open_columns(content: &MessageContent) -> RecipientColumns {
    if content.recipients.is_empty() {
        RecipientColumns::Unannounced
    } else {
        RecipientColumns::Fixed
    }
}

fn recipient_texts(
    recipients: &[ContentBag],
    first_row: usize,
    limit: usize,
    columns: &[PropTag],
    code_page: CodePage,
    sending: Sending,
) -> (Vec<u8>, Vec<RecipientText>) {
    let mut text = Vec::new();
    let mut entries = Vec::with_capacity(recipients.len().min(limit));
    let writer = RecipientColumnWriter::new(columns);
    for (order, bag) in (first_row..).zip(recipients.iter().take(limit)) {
        let display = push_utf16(&mut text, unicode(bag, tags::DISPLAY_NAME));
        let email = push_utf16(
            &mut text,
            unicode(bag, tags::SMTP_ADDRESS).or_else(|| unicode(bag, tags::EMAIL_ADDRESS)),
        );
        let start = text.len();
        if !writer.is_empty() {
            writer.write(
                &mut text,
                bag,
                i32::try_from(order).unwrap_or(i32::MAX),
                code_page,
            );
        }
        entries.push(RecipientText {
            columns: start..text.len(),
            kind: sending.recipient_type(bag),
            display,
            email,
        });
    }
    (text, entries)
}

impl RopContext<'_, '_> {
    pub async fn open_message(&mut self, rop: &DecodedRop<'_>, request: &OpenMessage) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let (logon_id, logon) = self
            .state
            .logon_of(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let mailbox_id = logon.mailbox_id;
        let folder = self.folder_id(mailbox_id, request.folder_id).await?;
        let id = MapiId::from_eid(request.message_id)
            .filter(|id| !id.space.is_folder())
            .ok_or(ErrorCode::NOT_FOUND)?;
        let folder = self
            .outbox_mirror(mailbox_id, folder, id)
            .await?
            .map_or(folder, |sent| MapiId::new(IdSpace::Mailbox, sent));
        self.require_folder_items(mailbox_id, folder.counter())
            .await?;
        let id = if self.message_in_folder(mailbox_id, folder, id).await? {
            id
        } else {
            id.from_client_fai().ok_or(ErrorCode::NOT_FOUND)?
        };
        let mut message = MessageObject {
            mailbox_id,
            folder: folder.counter(),
            message: id.counter(),
            code_page: request.code_page_id,
            path: Vec::new(),
            staged: None,
            recipient_columns: RecipientColumns::Unannounced,
        };
        let content = self.message_root(&message).await?;
        message.recipient_columns = open_columns(&content);
        let handle = self
            .state
            .insert(logon_id, ServerObject::Message(Box::new(message)))?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond_open(rop, index, &content, None)
    }

    pub(in crate::mapi::emsmdb) async fn outbox_mirror(
        &mut self,
        mailbox_id: u32,
        folder: MapiId,
        id: MapiId,
    ) -> Result<Option<u32>, RopError> {
        if id.space != IdSpace::Email
            || folder.to_node() != Some(FolderNode::Special(SpecialFolder::Outbox))
        {
            return Ok(None);
        }
        let Some(sent) = self
            .folder_tree(mailbox_id)
            .await?
            .special(SpecialFolder::SentItems)
            .map(|entry| entry.node)
            .and_then(stored_mailbox)
        else {
            return Ok(None);
        };
        let view = self.mailbox(mailbox_id).await?;
        Ok(view
            .exchange
            .resolve_alias(Placement {
                container: sent,
                item: id.id,
            })
            .zip(view.messages.as_ref())
            .and_then(|(document_id, messages)| messages.email_by_id(&document_id))
            .filter(|item| item.has_mailbox_id(sent))
            .map(|_| sent))
    }

    pub(in crate::mapi::emsmdb) async fn message_in_folder(
        &mut self,
        mailbox_id: u32,
        folder: MapiId,
        id: MapiId,
    ) -> Result<bool, RopError> {
        let node = folder.to_node();
        if id.space == IdSpace::Fai {
            return Ok(node.is_some());
        }
        let Some(FolderNode::Stored(FolderRef {
            kind,
            id: container,
        })) = node
        else {
            return Ok(false);
        };
        let (collection, document_id) = match (kind, id.space) {
            (FolderKind::Mailbox, IdSpace::Email) => {
                let mailbox = self.mailbox(mailbox_id).await?;
                let document_id = mailbox.email_document(container, id.id);
                return Ok(mailbox
                    .messages
                    .as_ref()
                    .and_then(|messages| messages.email_by_id(&document_id))
                    .is_some_and(|item| item.has_mailbox_id(container)));
            }
            (FolderKind::Calendar, IdSpace::Event) => (SyncCollection::Calendar, id.id),
            (FolderKind::AddressBook, IdSpace::Contact) => (SyncCollection::AddressBook, id.id),
            (FolderKind::Calendar | FolderKind::AddressBook, IdSpace::Email) => {
                let mailbox = self.mailbox(mailbox_id).await?;
                let Some(stored) = mailbox.stored_item(folder.counter(), id) else {
                    return Ok(false);
                };
                let collection = if kind == FolderKind::Calendar {
                    SyncCollection::Calendar
                } else {
                    SyncCollection::AddressBook
                };
                (collection, stored.id)
            }
            _ => return Ok(false),
        };
        let resources = self
            .request
            .server
            .fetch_groupware_resources(mailbox_id, mailbox_id, collection)
            .await
            .caused_by(trc::location!())?;
        Ok(resources
            .format_resource_path_by_parent(document_id, container)
            .is_some())
    }

    pub async fn open_attachment(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &OpenAttachment,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let message = self.message_object(parent)?;
        let root = self.message_root(&message).await?;
        embedded(&root, &message.path)
            .and_then(|content| attachment_at(content, request.attachment_id))
            .ok_or(ErrorCode::NOT_FOUND)?;
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let handle = self.state.insert(
            logon_id,
            ServerObject::Attachment(Box::new(AttachmentObject {
                message,
                number: request.attachment_id,
            })),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond_empty(rop, index)
    }

    pub async fn open_embedded_message(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &OpenEmbeddedMessage,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let attachment = match self.state.get(parent) {
            Some(ServerObject::Attachment(attachment)) => attachment.as_ref().clone(),
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        if !CodePage::is_known_rop_id(request.code_page_id) {
            return Err(RopError::Code(ErrorCode::UNKNOWN_CODE_PAGE));
        }
        if attachment.message.path.len() >= MAX_EMBED_DEPTH {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        let mut message = attachment.message;
        let create = request.open_mode_flags & OPEN_MODE_CREATE != 0;
        let mut created = false;
        if create {
            let root = self.message_root(&message).await?;
            let item = embedded(&root, &message.path)
                .and_then(|content| attachment_at(content, attachment.number))
                .ok_or(ErrorCode::OBJECT_DELETED)?;
            match item.data {
                AttachData::Embedded(_) | AttachData::Deferred(_) => {}
                AttachData::Bytes(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
                AttachData::None => {
                    message = self.stage_handle(parent).await?;
                    self.copy_child(
                        &message,
                        Some(attachment.number),
                        CopyItem::Embedded(new_content(NewContent::Normal {
                            data_type: DataType::Email,
                        })),
                    )?;
                    created = true;
                }
            }
        }
        message.path.push(attachment.number);
        if let Some(staged) = message.staged.and_then(|id| self.staged().message(id)) {
            if created {
                staged.unsaved_embedded.record(&message.path);
            } else if !create && staged.unsaved_embedded.contains(&message.path) {
                return Err(RopError::Code(ErrorCode::NOT_FOUND));
            }
        }
        message.code_page = request.code_page_id;
        let root = self.message_root(&message).await?;
        let content = embedded(&root, &message.path).ok_or(ErrorCode::NOT_FOUND)?;
        message.recipient_columns = open_columns(content);
        let message_id = Eid::from_le_u64(0);
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let handle = self
            .state
            .insert(logon_id, ServerObject::Message(Box::new(message)))?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond_open(rop, index, content, Some(message_id))
    }

    pub(super) fn set_recipient_columns(
        &mut self,
        handle: super::state::Handle,
        columns: RecipientColumns,
    ) {
        if let Some(ServerObject::Message(message)) = self.state.get_mut(handle) {
            message.recipient_columns = columns;
        }
    }

    pub fn message_object(&self, handle: super::state::Handle) -> Result<MessageObject, RopError> {
        match self.state.get(handle) {
            Some(ServerObject::Message(message)) => Ok(message.without_columns()),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    fn respond_open(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        content: &MessageContent,
        embedded_id: Option<Eid>,
    ) -> RopResult {
        let code_page = self.code_page();
        let code_page_id = code_page.0;
        let columns: &[PropTag] = match open_columns(content) {
            RecipientColumns::Fixed => &RECIPIENT_COLUMNS,
            _ => &[],
        };
        let (text, recipients) = recipient_texts(
            &content.recipients,
            0,
            MAX_OPEN_RECIPIENTS,
            columns,
            code_page,
            Sending::of(&content.props),
        );
        let count = column_count(columns);
        let rows = recipients
            .iter()
            .map(|recipient| OpenRecipientRow {
                recipient_type: recipient.kind,
                code_page_id,
                row: recipient.row(&text, count),
            })
            .collect::<Vec<_>>();
        let body = |count: usize| OpenMessageResponse {
            has_named_properties: true,
            subject_prefix: TypedString::from_text(unicode(&content.props, tags::SUBJECT_PREFIX)),
            normalized_subject: TypedString::from_text(unicode(
                &content.props,
                tags::NORMALIZED_SUBJECT,
            )),
            recipient_count: u16::try_from(content.recipients.len()).unwrap_or(u16::MAX),
            recipient_columns: columns,
            recipient_rows: rows.get(..count).unwrap_or_default(),
        };
        match embedded_id {
            Some(message_id) => self.respond_most(rop, index, rows.len(), |count| {
                OpenEmbeddedMessageResponse {
                    message_id,
                    message: body(count),
                }
            }),
            None => self.respond_most(rop, index, rows.len(), body),
        }
        .map(|_| ())
    }

    pub async fn read_recipients(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &ReadRecipients,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let (message, columns): (MessageObject, SmallVec<[PropTag; 32]>) = match self
            .state
            .get(handle)
        {
            Some(ServerObject::Message(message)) => (
                message.without_columns(),
                match &message.recipient_columns {
                    RecipientColumns::Unannounced => SmallVec::new(),
                    RecipientColumns::Fixed => SmallVec::from_slice(&RECIPIENT_COLUMNS),
                    RecipientColumns::Client(tags) => tags.iter().copied().map(PropTag).collect(),
                },
            ),
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let root = self.message_root(&message).await?;
        let content = embedded(&root, &message.path).ok_or(ErrorCode::OBJECT_DELETED)?;
        let start = usize::try_from(request.row_id).unwrap_or(usize::MAX);
        let recipients = content
            .recipients
            .get(start..)
            .filter(|recipients| !recipients.is_empty())
            .ok_or(ErrorCode::NOT_FOUND)?;
        let code_page = self.code_page();
        let code_page_id = code_page.0;
        let (text, entries) = recipient_texts(
            recipients,
            start,
            MAX_READ_RECIPIENTS,
            &columns,
            code_page,
            Sending::of(&content.props),
        );
        let count = column_count(&columns);
        let rows = (request.row_id..)
            .zip(&entries)
            .map(|(row_id, recipient)| ReadRecipientRow {
                row_id,
                recipient_type: recipient.kind,
                code_page_id,
                row: recipient.row(&text, count),
            })
            .collect::<Vec<_>>();
        self.respond_most(rop, index, rows.len(), |count| ReadRecipientsResponse {
            rows: rows.get(..count).unwrap_or_default(),
        })
        .map(|_| ())
    }

    pub async fn message_props(&mut self, message: &MessageObject) -> Result<PropBag, RopError> {
        let root = self.message_root(message).await?;
        let content = embedded(&root, &message.path).ok_or(ErrorCode::OBJECT_DELETED)?;
        let categories = self.category_source(message)?;
        let mailbox = self.mailbox(message.mailbox_id).await?;
        Ok(message_bag(message, content, &mailbox, categories))
    }

    pub fn category_source(&mut self, message: &MessageObject) -> Result<CategorySource, RopError> {
        Ok(match message.staged {
            Some(_) if self.staged_message(message)?.categories_touched => CategorySource::Staged,
            _ => CategorySource::Stored,
        })
    }

    pub async fn attachment_props(
        &mut self,
        attachment: &AttachmentObject,
    ) -> Result<PropBag, RopError> {
        let root = self.message_root(&attachment.message).await?;
        let item = embedded(&root, &attachment.message.path)
            .and_then(|content| attachment_at(content, attachment.number))
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let mailbox = self.mailbox(attachment.message.mailbox_id).await?;
        let mut bag = PropBag::with_capacity(256);
        push_attachment(&mut bag, attachment.number, item);
        if let AttachData::Bytes(bytes) = &item.data {
            bag.push_binary(tags::ATTACH_DATA_BINARY, bytes);
        }
        push_content(
            &mut bag,
            &item.props,
            &AccountNamedProps::new(&mailbox.exchange),
        );
        Ok(bag)
    }
}

pub fn message_bag(
    message: &MessageObject,
    content: &MessageContent,
    mailbox: &MailboxView,
    categories: CategorySource,
) -> PropBag {
    let guids = StoreGuids::new(mailbox.exchange.store_instance, message.mailbox_id);
    let mut bag = PropBag::with_capacity(1024);
    let mut email = None;
    let mut search_key = None;
    if let (true, Some(id), Some(folder)) = (
        message.path.is_empty(),
        message.id(),
        MapiId::from_counter(message.folder),
    ) {
        let parent_ids = MessageParent::new(&guids, &mailbox.exchange, folder);
        push_message_ids(&mut bag, &guids, &parent_ids, id);
        search_key = Some(guids.gid(id.to_client_message()));
        email = mailbox
            .stored_item(message.folder, id)
            .filter(|stored| stored.space == IdSpace::Email)
            .zip(mailbox.messages.as_ref())
            .and_then(|(stored, messages)| messages.email_by_id(&stored.id));
        if let Some(item) = email {
            push_email_state(&mut bag, item, &mailbox.exchange);
            let notify_read = receipt_pending(item.keywords())
                && matches!(
                    content.props.get(
                        PropKeyRef::Tag(tags::READ_RECEIPT_REQUESTED.id()),
                        PropType::Bool
                    ),
                    Some(OwnedPropValue::Bool(true))
                );
            let resend = object_row::is_resend(&content.props);
            if notify_read || resend {
                let mut flags = email_message_flags(item, &mailbox.exchange);
                if notify_read {
                    flags |= message_flags::NOTIFY_READ;
                }
                if resend {
                    flags |= message_flags::RESEND;
                }
                bag.remove(tags::MESSAGE_FLAGS);
                bag.push_i32(tags::MESSAGE_FLAGS, flags);
            }
        }
    } else {
        let has_attachments = !content.attachments.is_empty();
        bag.push_i32(tags::OBJECT_TYPE, MAPI_MESSAGE);
        bag.push_bool(tags::HAS_ATTACHMENTS, has_attachments);
        if let Some(OwnedPropValue::I32(flags)) = content
            .props
            .get(PropKeyRef::Tag(tags::MESSAGE_FLAGS.id()), PropType::I32)
        {
            let flags = *flags & !message_flags::HAS_ATTACH;
            bag.push_i32(
                tags::MESSAGE_FLAGS,
                if has_attachments {
                    flags | message_flags::HAS_ATTACH
                } else {
                    flags
                },
            );
        }
    }
    if !bag.contains(tags::MESSAGE_FLAGS)
        && content
            .props
            .get(PropKeyRef::Tag(tags::MESSAGE_FLAGS.id()), PropType::I32)
            .is_none()
    {
        bag.push_i32(tags::MESSAGE_FLAGS, default_message_flags(content));
    }
    push_content(
        &mut bag,
        &content.props,
        &AccountNamedProps::new(&mailbox.exchange),
    );
    if email.is_none() && !bag.contains(tags::MESSAGE_SIZE) {
        bag.push_i32(
            tags::MESSAGE_SIZE,
            i32::try_from(content_size(content)).unwrap_or(i32::MAX),
        );
    }
    if email.is_some() {
        normalize_follow_up(&mut bag);
    }
    if let (Some(item), CategorySource::Stored) = (email, categories) {
        push_categories(&mut bag, mailbox, item);
    }
    if let Some(search_key) = search_key
        && !bag.contains(tags::SEARCH_KEY)
    {
        bag.push_binary(tags::SEARCH_KEY, &search_key.to_wire());
    }
    if !bag.contains(tags::CONVERSATION_ID)
        && let Some(OwnedPropValue::Binary(index)) = content.props.get(
            PropKeyRef::Tag(tags::CONVERSATION_INDEX.id()),
            PropType::Binary,
        )
        && let Some(conversation) = index.get(CONVERSATION_GUID)
    {
        bag.push_binary(tags::CONVERSATION_ID, conversation);
    }
    if BODY_SOURCES.iter().any(|id| {
        content
            .props
            .get_any(PropKeyRef::Tag(*id))
            .is_some_and(|value| match value {
                OwnedPropValue::Unicode(text) => !text.is_empty(),
                OwnedPropValue::String8(text) => !text.is_empty(),
                OwnedPropValue::Binary(data) => !data.is_empty(),
                _ => false,
            })
    }) {
        for tag in [tags::BODY, tags::RTF_COMPRESSED] {
            if !bag.contains(tag) {
                bag.push_error(tag, ErrorCode::NOT_ENOUGH_MEMORY);
            }
        }
    }
    push_message_defaults(&mut bag);
    push_display_recipients(&mut bag, &content.recipients);
    if !bag.contains(tags::HAS_NAMED_PROPERTIES) {
        bag.push_bool(tags::HAS_NAMED_PROPERTIES, content.props.has_named());
    }
    bag
}

const DISPLAY_RECIPIENTS: [(PropTag, i32); 3] = [
    (tags::DISPLAY_TO, recipient_type::TO),
    (tags::DISPLAY_CC, recipient_type::CC),
    (tags::DISPLAY_BCC, recipient_type::BCC),
];
const DISPLAY_SEPARATOR: &str = "; ";

fn push_display_recipients(bag: &mut PropBag, recipients: &[ContentBag]) {
    let mut names = String::new();
    for (tag, kind) in DISPLAY_RECIPIENTS {
        names.clear();
        for label in recipients
            .iter()
            .filter(|row| {
                match row.get(PropKeyRef::Tag(tags::RECIPIENT_TYPE.id()), PropType::I32) {
                    Some(OwnedPropValue::I32(value)) => value & recipient_type::MASK == kind,
                    _ => kind == recipient_type::TO,
                }
            })
            .filter_map(|row| {
                [tags::DISPLAY_NAME, tags::SMTP_ADDRESS, tags::EMAIL_ADDRESS]
                    .into_iter()
                    .find_map(|tag| unicode(row, tag).filter(|label| !label.is_empty()))
            })
        {
            if !names.is_empty() {
                names.push_str(DISPLAY_SEPARATOR);
            }
            names.push_str(label);
        }
        bag.remove(tag);
        bag.push_text(tag, &names);
    }
}

const CONVERSATION_GUID: Range<usize> = 6..22;
const IMPORTANCE_NORMAL: i32 = 1;
const SENSITIVITY_NONE: i32 = 0;
const MESSAGE_STATUS_NONE: i32 = 0;
const MESSAGE_DEFAULTS: [(PropTag, i32); 3] = [
    (tags::IMPORTANCE, IMPORTANCE_NORMAL),
    (tags::SENSITIVITY, SENSITIVITY_NONE),
    (tags::MESSAGE_STATUS, MESSAGE_STATUS_NONE),
];

pub fn default_message_flags(content: &MessageContent) -> i32 {
    if content.attachments.is_empty() {
        message_flags::READ
    } else {
        message_flags::HAS_ATTACH | message_flags::READ
    }
}

pub fn push_message_defaults(bag: &mut PropBag) {
    for (tag, value) in MESSAGE_DEFAULTS {
        if !bag.contains(tag) {
            bag.push_i32(tag, value);
        }
    }
}

pub fn push_categories(bag: &mut PropBag, mailbox: &MailboxView, item: MessageRef<'_>) {
    let Some(keywords) = mailbox
        .messages
        .as_ref()
        .map(|messages| messages.custom_keywords(item))
        .filter(|keywords| AccountCategories::any(keywords))
    else {
        return;
    };
    let [name, _] = category_keys();
    let Some(tag) = AccountNamedProps::new(&mailbox.exchange)
        .id(name)
        .map(|id| PropTag::new(id, PropType::MvUnicode))
        .filter(|tag| !bag.contains(*tag))
    else {
        return;
    };
    let names = AccountCategories::new(&mailbox.exchange)
        .resolve(keywords)
        .map(|name| name.into_owned().into_boxed_str())
        .collect();
    bag.push_owned(tag, &OwnedPropValue::MvUnicode(names));
}

pub fn push_attachment(
    bag: &mut PropBag,
    number: u32,
    item: &exchange_proto::convert::model::Attachment,
) {
    bag.push_i32(tags::OBJECT_TYPE, MAPI_ATTACH);
    bag.push_i32(
        tags::ATTACH_NUMBER,
        i32::try_from(number).unwrap_or(i32::MAX),
    );
    bag.push_binary(tags::INSTANCE_KEY, &number.to_le_bytes());
    bag.push_binary(tags::RECORD_KEY, &number.to_le_bytes());
    if let Some(size) = derived_attach_size(item) {
        bag.push_i32(tags::ATTACH_SIZE, size);
    }
}

pub fn derived_attach_size(item: &Attachment) -> Option<i32> {
    if item
        .props
        .get_any(PropKeyRef::Tag(tags::ATTACH_SIZE.id()))
        .is_some()
    {
        return None;
    }
    match item.data {
        AttachData::Deferred(_) => None,
        AttachData::None => Some(
            match item
                .props
                .get_any(PropKeyRef::Tag(tags::ATTACH_DATA_BINARY.id()))
            {
                Some(OwnedPropValue::Binary(bytes)) => {
                    i32::try_from(bytes.len()).unwrap_or(i32::MAX)
                }
                _ => 0,
            },
        ),
        AttachData::Bytes(_) | AttachData::Embedded(_) => {
            Some(i32::try_from(attachment_size(item)).unwrap_or(i32::MAX))
        }
    }
}

pub struct MessageParent {
    id: MapiId,
    key: Gid,
}

impl MessageParent {
    pub fn new(guids: &StoreGuids, exchange: &ExchangeAccountCache, folder: MapiId) -> Self {
        let id = folder.to_client(exchange);
        MessageParent {
            id,
            key: guids.gid(id),
        }
    }

    pub fn server_id(&self) -> Vec<u8> {
        let mut server_id = Vec::new();
        ServerIdValue::Ours {
            fid: self.id.to_eid(),
            mid: Eid::from_wire([0; 8]),
            instance: 0,
        }
        .encode(&mut server_id);
        server_id
    }
}

pub fn push_message_ids(bag: &mut PropBag, guids: &StoreGuids, parent: &MessageParent, id: MapiId) {
    let id = id.to_client_message();
    let eid = id.to_eid();
    let folder = parent.id;
    let folder_eid = folder.to_eid();
    bag.push_i32(tags::OBJECT_TYPE, MAPI_MESSAGE);
    bag.push_i64(tags::MID, i64::from_le_bytes(eid.to_wire()));
    bag.push_i64(tags::FOLDER_ID, i64::from_le_bytes(folder_eid.to_wire()));
    bag.push_i64(
        tags::PARENT_FOLDER_ID,
        i64::from_le_bytes(folder_eid.to_wire()),
    );
    bag.push_entry_id(tags::ENTRY_ID, &guids.message_entry_id(folder, id));
    bag.push_entry_id(tags::PARENT_ENTRY_ID, &guids.folder_entry_id(folder));
    bag.push_binary(tags::SOURCE_KEY, &guids.gid(id).to_wire());
    bag.push_binary(tags::PARENT_SOURCE_KEY, &parent.key.to_wire());
    bag.push_binary(tags::INSTANCE_KEY, &id.counter().to_le_bytes());
}

pub fn email_message_flags(item: MessageRef<'_>, exchange: &ExchangeAccountCache) -> i32 {
    let keywords = item.keywords();
    let mut flags = 0;
    if keywords & (1 << SEEN) != 0 {
        flags |= message_flags::READ | message_flags::EVER_READ;
    }
    if keywords & (1 << DRAFT) != 0 {
        flags |= message_flags::UNSENT;
    } else if !exchange.has_object(Collection::Email, item.document_id()) {
        flags |= message_flags::UNMODIFIED;
    }
    if keywords & (1 << HASATTACHMENT) != 0 {
        flags |= message_flags::HAS_ATTACH;
    }
    flags
}

pub fn push_email_state(bag: &mut PropBag, item: MessageRef<'_>, exchange: &ExchangeAccountCache) {
    let keywords = item.keywords();
    let read = keywords & (1 << SEEN) != 0;
    let has_attach = keywords & (1 << HASATTACHMENT) != 0;
    let flags = email_message_flags(item, exchange);
    let received = FileTime::from_utc(
        UtcSeconds(i64::try_from(item.received_at()).unwrap_or(i64::MAX)),
        0,
    );
    bag.push_i32(tags::MESSAGE_FLAGS, flags);
    bag.push_bool(tags::READ, read);
    if keywords & (1 << FLAGGED) != 0 {
        bag.push_i32(tags::FLAG_STATUS, FLAG_STATUS_FLAGGED);
    }
    bag.push_bool(tags::HAS_ATTACHMENTS, has_attach);
    bag.push_i32(
        tags::MESSAGE_SIZE,
        i32::try_from(item.size()).unwrap_or(i32::MAX),
    );
    bag.push_time(tags::MESSAGE_DELIVERY_TIME, received);
    bag.push_time(tags::CREATION_TIME, received);
    bag.push_time(tags::LAST_MODIFICATION_TIME, received);
}

pub fn normalize_follow_up(bag: &mut PropBag) {
    let to_do = match bag.get(tags::TO_DO_ITEM_FLAGS) {
        Some(PropOut::Value(PropValue::I32(flags))) => Some(flags),
        _ => None,
    };
    let flagged = bag
        .get(tags::FLAG_STATUS)
        .map(|status| matches!(status, PropOut::Value(PropValue::I32(FLAG_STATUS_FLAGGED))));
    match flagged {
        Some(true) => {
            bag.remove(tags::FLAG_COMPLETE_TIME);
            if !bag.contains(tags::FOLLOWUP_ICON) {
                bag.push_i32(tags::FOLLOWUP_ICON, FOLLOWUP_ICON_RED);
            }
            let flags = to_do.unwrap_or_default();
            if flags & (TO_DO_ITEM_FLAGGED | TO_DO_RECIPIENT_FLAGGED) == 0 {
                bag.remove(tags::TO_DO_ITEM_FLAGS);
                bag.push_i32(tags::TO_DO_ITEM_FLAGS, flags | TO_DO_ITEM_FLAGGED);
            }
        }
        Some(false) => {}
        None if is_meeting_related(bag) => {}
        None => {
            bag.remove(tags::FOLLOWUP_ICON);
            if let Some(flags) = to_do.filter(|flags| flags & TO_DO_ITEM_FLAGGED != 0) {
                bag.remove(tags::TO_DO_ITEM_FLAGS);
                if flags != TO_DO_ITEM_FLAGGED {
                    bag.push_i32(tags::TO_DO_ITEM_FLAGS, flags & !TO_DO_ITEM_FLAGGED);
                }
            }
        }
    }
}

fn is_meeting_related(bag: &PropBag) -> bool {
    matches!(
        bag.get(tags::MESSAGE_CLASS),
        Some(PropOut::Text(class)) if class
            .as_bytes()
            .get(..MEETING_CLASS_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(MEETING_CLASS_PREFIX))
    )
}

pub fn fill_conversation_index(content: &mut ContentBag, item: MessageRef<'_>) {
    let id = tags::CONVERSATION_INDEX.id();
    if content.get(PropKeyRef::Tag(id), PropType::Binary).is_none() {
        let delivered = UtcSeconds(i64::try_from(item.received_at()).unwrap_or(i64::MAX));
        content.set(
            PropKey::tag(id),
            OwnedPropValue::Binary(
                ConversationIndex::synthesized(delivered, item.thread_id()).into_bytes(),
            ),
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CategorySource {
    Stored,
    Staged,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ContentScope {
    Object,
    Row,
}

pub fn push_content(bag: &mut PropBag, props: &ContentBag, named: &AccountNamedProps<'_>) {
    push_scoped_content(bag, props, named, ContentScope::Object);
}

pub fn push_scoped_content(
    bag: &mut PropBag,
    props: &ContentBag,
    named: &AccountNamedProps<'_>,
    scope: ContentScope,
) {
    for (key, value) in props.iter() {
        let key = key.as_ref();
        let id = match key {
            PropKeyRef::Tag(id) => Some(id),
            other => named.id(other),
        };
        if let Some(tag) = id.map(|id: PropId| PropTag::new(id, value.ptype()))
            && !bag.contains(tag)
        {
            if scope == ContentScope::Row && exceeds_row(key, value) {
                bag.push_error(tag, ErrorCode::NOT_ENOUGH_MEMORY);
            } else {
                bag.push_owned(tag, value);
            }
        }
    }
}

fn exceeds_row(key: PropKeyRef<'_>, value: &OwnedPropValue) -> bool {
    matches!(key, PropKeyRef::Tag(id) if BODY_SOURCES.contains(&id))
        || value.content_len() > MAX_INLINE_VALUE
}

pub fn row_content(props: ContentBag) -> ContentBag {
    let mut out = ContentBag::new();
    for (key, value) in props.into_entries() {
        let value = row_value(key.as_ref(), value);
        out.set(key, value);
    }
    out
}

pub fn row_value(key: PropKeyRef<'_>, value: OwnedPropValue) -> OwnedPropValue {
    if exceeds_row(key, &value) {
        OwnedPropValue::Error(ErrorCode::NOT_ENOUGH_MEMORY)
    } else {
        value
    }
}

pub fn attachment_number(item: &Attachment) -> Option<u32> {
    match item
        .props
        .get(PropKeyRef::Tag(tags::ATTACH_NUMBER.id()), PropType::I32)
    {
        Some(OwnedPropValue::I32(number)) => u32::try_from(*number).ok(),
        _ => None,
    }
}

pub fn numbered_attachments(content: &MessageContent) -> impl Iterator<Item = (u32, &Attachment)> {
    (0u32..)
        .zip(&content.attachments)
        .map(|(index, item)| (attachment_number(item).unwrap_or(index), item))
}

pub fn attachment_at(content: &MessageContent, number: u32) -> Option<&Attachment> {
    numbered_attachments(content)
        .find(|(candidate, _)| *candidate == number)
        .map(|(_, item)| item)
}

pub fn attachment_mut(content: &mut MessageContent, number: u32) -> Option<&mut Attachment> {
    (0u32..)
        .zip(content.attachments.iter_mut())
        .find(|(index, item)| attachment_number(item).unwrap_or(*index) == number)
        .map(|(_, item)| item)
}

pub fn stamp_attachment_numbers(content: &mut MessageContent) {
    for (index, item) in (0u32..).zip(content.attachments.iter_mut()) {
        if attachment_number(item).is_none() {
            item.props.set(
                PropKey::tag(tags::ATTACH_NUMBER.id()),
                OwnedPropValue::I32(i32::try_from(index).unwrap_or(i32::MAX)),
            );
        }
    }
}

fn unicode(bag: &ContentBag, tag: PropTag) -> Option<&str> {
    match bag.get(PropKeyRef::Tag(tag.id()), PropType::Unicode) {
        Some(OwnedPropValue::Unicode(text)) => Some(text),
        _ => None,
    }
}

fn push_utf16(out: &mut Vec<u8>, text: Option<&str>) -> Range<usize> {
    let start = out.len();
    for unit in text.unwrap_or_default().encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    start..out.len()
}

fn utf16_at<'x>(text: &'x [u8], range: &Range<usize>) -> Option<MapiString<'x>> {
    text.get(range.clone())
        .and_then(Utf16Le::new)
        .map(MapiString::Unicode)
}
