/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    attachment_at, attachment_mut,
    fai::{creation_stamp, fai_data_type},
    numbered_attachments,
    object_row::is_category,
    stamp_attachment_numbers,
};
use crate::{
    folders::FolderNode,
    mapi::{
        emsmdb::{
            access::ItemWrite,
            execute::{RopContext, RopError, RopResult},
            staged::{
                FailedCommit, StagedMessage, StagedObject, TouchedFlags, attachment_size, bag_size,
                content_size, value_size,
            },
            state::{
                AttachmentObject, Handle, MessageObject, RecipientColumns, ServerObject, UNSAVED,
            },
        },
        ids::IdSpace,
        text::decode_text_within,
    },
    store::named::AccountNamedProps,
};
use bytes::Bytes;
use exchange_proto::{
    common::Utf16Le,
    convert::{
        mime::split_subject,
        model::{AttachData, Attachment, MessageContent, PropBag as ContentBag},
        tags::{
            message_flags,
            recipient_type::{self, WireType},
        },
    },
    ics::fx::{Children, CopyItem},
    mapi::{
        ErrorCode,
        prop::{
            CodePage, NamedPropMap, OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag, PropType,
            PropValue, row::RowCell, tags,
        },
        recipient::{RecipientKind, RecipientRow},
        rop::{
            DecodedRop,
            requests::{
                CreateAttachment, CreateMessage, DeleteAttachment, DeleteProperties,
                ModifyRecipients, SaveChangesAttachment, SetProperties,
            },
            responses::{
                CreateAttachmentResponse, CreateMessageResponse, DeletePropertiesResponse,
                PropertyProblem, SetPropertiesResponse,
            },
            views::MapiString,
        },
    },
};
use smallvec::SmallVec;
use std::sync::Arc;
use store::rand;
use types::type_state::DataType;

const FIRST_NAMED_ID: u16 = 0x8000;
const MAX_RECIPIENTS: usize = 0x7FFF;
const MAX_RECIPIENT_COLUMNS: usize = 256;
const ADDRESS_TYPE_EX: &str = "EX";
const ADDRESS_TYPE_SMTP: &str = "SMTP";
const DEFAULT_MESSAGE_CLASS: &str = "IPM.Note";
const SEARCH_KEY_LEN: usize = 16;
const RENDERING_POSITION_NONE: i32 = -1;
const COMPUTED: [PropTag; 16] = [
    tags::MID,
    tags::FOLDER_ID,
    tags::PARENT_FOLDER_ID,
    tags::ENTRY_ID,
    tags::PARENT_ENTRY_ID,
    tags::RECORD_KEY,
    tags::INSTANCE_KEY,
    tags::SOURCE_KEY,
    tags::PARENT_SOURCE_KEY,
    tags::OBJECT_TYPE,
    tags::MESSAGE_SIZE,
    tags::HAS_ATTACHMENTS,
    tags::ATTACH_NUMBER,
    tags::STORE_ENTRY_ID,
    tags::CHANGE_KEY,
    tags::PREDECESSOR_CHANGE_LIST,
];

const READ_ONLY_MESSAGE: [PropTag; 6] = [
    tags::MESSAGE_SIZE,
    tags::HAS_ATTACHMENTS,
    tags::OBJECT_TYPE,
    tags::RECORD_KEY,
    tags::ACCESS,
    tags::ACCESS_LEVEL,
];
const IGNORED_MESSAGE: [PropTag; 2] = [tags::CHANGE_KEY, tags::PREDECESSOR_CHANGE_LIST];
const READ_ONLY_ATTACHMENT: [PropTag; 4] = [
    tags::ATTACH_SIZE,
    tags::OBJECT_TYPE,
    tags::RECORD_KEY,
    tags::ACCESS_LEVEL,
];
const SAVE_MODE_FLAGS: u8 = 0x07;

const RECIPIENT_IDENTITY: [PropTag; 2] = [tags::ENTRY_ID, tags::OBJECT_TYPE];

fn is_read_only_attachment(id: PropId) -> bool {
    READ_ONLY_ATTACHMENT.iter().any(|tag| tag.id() == id)
}

type Edits = SmallVec<[(PropKey, OwnedPropValue); 16]>;

fn collapse_edits(edits: &mut Edits) {
    edits.reverse();
    edits.sort_by(|(a, x), (b, y)| {
        a.as_ref().cmp(&b.as_ref()).then_with(|| {
            x.ptype()
                .storage_class()
                .code()
                .cmp(&y.ptype().storage_class().code())
        })
    });
    edits.dedup_by(|(a, x), (b, y)| {
        a.as_ref() == b.as_ref()
            && x.ptype().storage_class().code() == y.ptype().storage_class().code()
    });
}
type Problems = SmallVec<[PropertyProblem; 8]>;

#[derive(Clone, Copy)]
enum Target {
    Message,
    Attachment(u32),
}

impl Target {
    fn attachment(self) -> Option<u32> {
        match self {
            Target::Message => None,
            Target::Attachment(number) => Some(number),
        }
    }

    fn is_read_only(self, id: PropId) -> bool {
        match self {
            Target::Message => READ_ONLY_MESSAGE.iter().any(|tag| tag.id() == id),
            Target::Attachment(_) => is_read_only_attachment(id),
        }
    }

    fn ignores(self, id: PropId) -> bool {
        matches!(self, Target::Message) && IGNORED_MESSAGE.iter().any(|tag| tag.id() == id)
    }
}

impl RopContext<'_, '_> {
    pub async fn create_message(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &CreateMessage,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        let (logon_id, logon) = self
            .state
            .logon_of(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let mailbox_id = logon.mailbox_id;
        let folder = self.folder_id(mailbox_id, request.folder_id).await?;
        let node = folder.to_node().ok_or(ErrorCode::NOT_FOUND)?;
        self.require_node_write(
            mailbox_id,
            node,
            ItemWrite::of_staged(request.associated_flag, false),
        )
        .await?;
        let data_type = match node {
            FolderNode::Stored(folder) => fai_data_type(folder.kind),
            FolderNode::Special(_) => DataType::Email,
        };
        if !self.types.contains(data_type) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        self.folder_tree(mailbox_id)
            .await?
            .get(node)
            .ok_or(ErrorCode::NOT_FOUND)?;
        let content = if request.associated_flag {
            new_content(NewContent::Associated)
        } else {
            let mut content = new_content(NewContent::Normal { data_type });
            content.props.set(
                PropKey::tag(tags::SEARCH_KEY.id()),
                OwnedPropValue::Binary(Bytes::copy_from_slice(
                    &rand::random::<[u8; SEARCH_KEY_LEN]>(),
                )),
            );
            content
        };
        let id = self.state.allocate_staged();
        let charge = content_size(&content);
        self.staged().insert(
            id,
            StagedObject::Message(Box::new(StagedMessage::new(
                Arc::new(content),
                None,
                request.associated_flag,
            ))),
            charge,
        )?;
        let handle = self.state.insert(
            logon_id,
            ServerObject::Message(Box::new(MessageObject {
                mailbox_id,
                folder: folder.counter(),
                message: UNSAVED,
                code_page: request.code_page_id,
                path: Vec::new(),
                staged: Some(id),
                recipient_columns: RecipientColumns::Unannounced,
            })),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond(rop, index, &CreateMessageResponse { message_id: None })
    }

    pub async fn stage_handle(&mut self, handle: Handle) -> Result<MessageObject, RopError> {
        let mut message = match self.state.get(handle) {
            Some(ServerObject::Message(message)) => message.without_columns(),
            Some(ServerObject::Attachment(attachment)) => attachment.message.without_columns(),
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        if message.staged.is_some() {
            return Ok(message);
        }
        let base = message.id().ok_or(ErrorCode::NOT_FOUND)?;
        if base.space == IdSpace::Email && !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let root = self.message_root(&message).await?;
        let charge = content_size(&root);
        let mut staged = StagedMessage::new(root, Some(base), base.space == IdSpace::Fai);
        if let Some(loaded) = &self.loaded {
            staged.origin = Some(loaded.origin);
            staged.change = loaded.change;
            staged.row = loaded.row;
        }
        let id = self.state.allocate_staged();
        self.staged()
            .insert(id, StagedObject::Message(Box::new(staged)), charge)?;
        self.state
            .attach_staged(message.mailbox_id, message.message, id);
        self.loaded = None;
        message.staged = Some(id);
        Ok(message)
    }

    fn target(&self, handle: Handle) -> Result<Target, RopError> {
        match self.state.get(handle) {
            Some(ServerObject::Message(_)) => Ok(Target::Message),
            Some(ServerObject::Attachment(attachment)) => Ok(Target::Attachment(attachment.number)),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    pub async fn set_item_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetProperties<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let target = self.target(handle)?;
        let message = self.stage_handle(handle).await?;
        let exchange = self.mailbox(message.mailbox_id).await?.exchange;
        let named = AccountNamedProps::new(&exchange);
        let code_page = self.code_page();
        let mut problems = Problems::new();
        let mut edits = Edits::new();
        let mut edited = SmallVec::<[PropId; 16]>::new();
        let mut read_only = SmallVec::<[PropId; 4]>::new();
        for (position, (tag, value)) in request.property_values.iter().enumerate() {
            if target.is_read_only(tag.id()) {
                read_only.push(tag.id());
                continue;
            }
            if target.ignores(tag.id()) {
                continue;
            }
            match item_key(tag, &named).and_then(|key| {
                owned_value(tag, &value, code_page)
                    .and_then(|value| {
                        if is_category(key.as_ref()) {
                            category_value(value, code_page)
                        } else {
                            Some(value)
                        }
                    })
                    .map(|value| (key, value))
                    .ok_or(ErrorCode::INVALID_PARAM)
            }) {
                Ok(edit) => {
                    edits.push(edit);
                    edited.push(tag.id());
                }
                Err(error) => problems.push(PropertyProblem {
                    index: u16::try_from(position).unwrap_or(u16::MAX),
                    tag,
                    error,
                }),
            }
        }
        self.apply_edits(&message, target, edits, &edited)?;
        if !read_only.is_empty() && message.path.is_empty() {
            let staged = self.staged_message(&message)?;
            if staged.import.is_none() {
                for prop in read_only {
                    staged.fail_commit(FailedCommit {
                        code: ErrorCode::ERROR,
                        attachment: target.attachment(),
                        prop,
                    });
                }
            }
        }
        self.respond(
            rop,
            index,
            &SetPropertiesResponse {
                property_problems: &problems,
            },
        )
    }

    pub(in crate::mapi::emsmdb) fn copy_items(
        &mut self,
        message: &MessageObject,
        attachment: Option<u32>,
        items: Vec<CopyItem>,
    ) -> RopResult {
        let code_page = self.code_page();
        let mut edits = Edits::new();
        let mut edited = SmallVec::<[PropId; 16]>::new();
        if attachment.is_none()
            && items
                .iter()
                .any(|item| matches!(item, CopyItem::Attachment(_)))
        {
            stamp_attachment_numbers(self.staged_message(message)?.edit_at(&message.path)?);
        }
        for item in items {
            let CopyItem::Prop(key, value) = item else {
                self.copy_child(message, attachment, item)?;
                continue;
            };
            if let PropKeyRef::Tag(id) = key.as_ref() {
                if id.0 >= FIRST_NAMED_ID
                    || id == tags::ASSOCIATED.id()
                    || COMPUTED.iter().any(|computed| computed.id() == id)
                {
                    continue;
                }
                if id == tags::ATTACH_DATA_BINARY.id()
                    && let Some(number) = attachment
                    && let OwnedPropValue::Binary(bytes) = value
                {
                    self.copy_attach_data(message, number, bytes)?;
                    continue;
                }
                edited.push(id);
            }
            if let Some(value) = copied_value(key.as_ref(), value, code_page) {
                edits.push((key, value));
            }
        }
        if edits.is_empty() && edited.is_empty() {
            return Ok(());
        }
        let target = match attachment {
            Some(number) => Target::Attachment(number),
            None => Target::Message,
        };
        self.apply_edits(message, target, edits, &edited)
    }

    fn copy_attach_data(
        &mut self,
        message: &MessageObject,
        number: u32,
        bytes: Bytes,
    ) -> RopResult {
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        let current = attachment_at(
            self.staged_message(message)?.content_at(&message.path)?,
            number,
        )
        .ok_or(ErrorCode::OBJECT_DELETED)?;
        let removed = attachment_size(current).saturating_sub(bag_size(&current.props));
        let added = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.staged().recharge(id, added, removed)?;
        attachment_mut(
            self.staged_message(message)?.edit_at(&message.path)?,
            number,
        )
        .ok_or(ErrorCode::OBJECT_DELETED)?
        .data = AttachData::Bytes(bytes);
        Ok(())
    }

    pub(in crate::mapi::emsmdb) fn copy_child(
        &mut self,
        message: &MessageObject,
        attachment: Option<u32>,
        item: CopyItem,
    ) -> RopResult {
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        let path = message.path.as_slice();
        match (attachment, item) {
            (None, CopyItem::DeleteChildren(Children::Recipients)) => {
                let staged = self.staged_message(message)?;
                if !staged.content_at(path)?.recipients.is_empty() {
                    staged.edit_at(path)?.recipients.clear();
                }
            }
            (None, CopyItem::DeleteChildren(Children::Attachments)) => {
                let staged = self.staged_message(message)?;
                if !staged.content_at(path)?.attachments.is_empty() {
                    staged.edit_at(path)?.attachments.clear();
                    staged.unsaved_embedded.forget_under(path, None);
                    if path.is_empty() {
                        staged.unsaved.clear();
                        staged.failed.retain(|failure| failure.attachment.is_none());
                    }
                }
            }
            (None, CopyItem::Recipient(bag)) => {
                if self
                    .staged_message(message)?
                    .content_at(path)?
                    .recipients
                    .len()
                    >= MAX_RECIPIENTS
                {
                    return Err(RopError::Code(ErrorCode::TOO_BIG));
                }
                self.staged().charge(id, bag_size(&bag))?;
                self.staged_message(message)?
                    .edit_at(path)?
                    .recipients
                    .push(bag);
            }
            (None, CopyItem::Attachment(mut item)) => {
                item.props
                    .remove_any(PropKeyRef::Tag(tags::ATTACH_SIZE.id()));
                let number_size = value_size(&OwnedPropValue::I32(0));
                self.staged()
                    .charge(id, attachment_size(&item).saturating_add(number_size))?;
                let staged = self.staged_message(message)?;
                let number = next_attachment(staged, path)?;
                item.props.set(
                    PropKey::tag(tags::ATTACH_NUMBER.id()),
                    OwnedPropValue::I32(i32::try_from(number).unwrap_or(i32::MAX)),
                );
                staged.edit_at(path)?.attachments.push(item);
            }
            (Some(number), CopyItem::Embedded(embedded)) => {
                let current =
                    attachment_at(self.staged_message(message)?.content_at(path)?, number)
                        .ok_or(ErrorCode::OBJECT_DELETED)?;
                let removed = attachment_size(current).saturating_sub(bag_size(&current.props));
                self.staged()
                    .recharge(id, content_size(&embedded), removed)?;
                let staged = self.staged_message(message)?;
                attachment_mut(staged.edit_at(path)?, number)
                    .ok_or(ErrorCode::OBJECT_DELETED)?
                    .data = AttachData::Embedded(Box::new(embedded));
                staged.unsaved_embedded.forget_under(path, Some(number));
            }
            _ => return Err(RopError::Code(ErrorCode::RPC_FORMAT)),
        }
        Ok(())
    }

    fn apply_edits(
        &mut self,
        message: &MessageObject,
        target: Target,
        mut edits: Edits,
        edited: &[PropId],
    ) -> RopResult {
        collapse_edits(&mut edits);
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        let path = message.path.as_slice();
        let bag = target_bag(self.staged_message(message)?.content_at(path)?, target)?;
        if matches!(target, Target::Message)
            && let Some(derived) = SubjectEdit::derive(&edits, bag)
        {
            derived.push_into(&mut edits);
        }
        let extra = edits
            .iter()
            .map(|(_, value)| value_size(value))
            .fold(0u64, u64::saturating_add);
        let removed = edits
            .iter()
            .filter_map(|(key, value)| bag.get(key.as_ref(), value.ptype()))
            .map(value_size)
            .fold(0u64, u64::saturating_add);
        self.staged().recharge(id, extra, removed)?;
        let staged = self.staged_message(message)?;
        if path.is_empty() {
            staged.clear_failed(target.attachment(), |prop| edited.contains(&prop));
        }
        match target {
            Target::Message if path.is_empty() => {
                for (key, value) in edits {
                    staged.edit_key(key.as_ref()).props.set(key, value);
                }
            }
            Target::Message => {
                let props = &mut staged.edit_at(path)?.props;
                for (key, value) in edits {
                    props.set(key, value);
                }
            }
            Target::Attachment(number) => {
                let bag = attachment_bag(staged.edit_at(path)?, number)?;
                for (key, value) in edits {
                    bag.set(key, value);
                }
            }
        }
        Ok(())
    }

    pub async fn delete_item_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &DeleteProperties<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let target = self.target(handle)?;
        let message = self.stage_handle(handle).await?;
        let exchange = self.mailbox(message.mailbox_id).await?.exchange;
        let named = AccountNamedProps::new(&exchange);
        let mut problems = Problems::new();
        let mut keys = SmallVec::<[(PropKey, PropType); 16]>::new();
        let mut edited = SmallVec::<[PropId; 16]>::new();
        for (position, tag) in request.property_tags.iter().enumerate() {
            match item_key(tag, &named) {
                Ok(key) => {
                    keys.push((key, tag.ptype()));
                    edited.push(tag.id());
                }
                Err(error) => problems.push(PropertyProblem {
                    index: u16::try_from(position).unwrap_or(u16::MAX),
                    tag,
                    error,
                }),
            }
        }
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        let path = message.path.as_slice();
        let staged = self.staged_message(&message)?;
        let mut removed = 0u64;
        match target {
            Target::Message if !path.is_empty() => {
                let props = &staged.content_at(path)?.props;
                if keys
                    .iter()
                    .any(|(key, ptype)| props.get(key.as_ref(), *ptype).is_some())
                {
                    let props = &mut staged.edit_at(path)?.props;
                    for (key, ptype) in keys {
                        if let Some(value) = props.remove(key.as_ref(), ptype) {
                            removed = removed.saturating_add(value_size(&value));
                        }
                    }
                }
            }
            Target::Message => {
                for (key, ptype) in keys {
                    if (TouchedFlags::is_flag_key(key.as_ref())
                        || is_category(key.as_ref())
                        || staged.content.props.get(key.as_ref(), ptype).is_some())
                        && let Some(value) = staged
                            .edit_key(key.as_ref())
                            .props
                            .remove(key.as_ref(), ptype)
                    {
                        removed = removed.saturating_add(value_size(&value));
                    }
                }
            }
            Target::Attachment(number) => {
                if attachment_at(staged.content_at(path)?, number).is_none() {
                    return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
                }
                let bag = attachment_bag(staged.edit_at(path)?, number)?;
                for (key, ptype) in keys {
                    if let Some(value) = bag.remove(key.as_ref(), ptype) {
                        removed = removed.saturating_add(value_size(&value));
                    }
                }
            }
        }
        if path.is_empty() {
            staged.clear_failed(target.attachment(), |prop| edited.contains(&prop));
        }
        self.staged().recharge(id, 0, removed)?;
        self.respond(
            rop,
            index,
            &DeletePropertiesResponse {
                property_problems: &problems,
            },
        )
    }

    pub async fn modify_recipients(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &ModifyRecipients<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        if !matches!(self.target(handle)?, Target::Message) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        if request.recipient_columns.len() > MAX_RECIPIENT_COLUMNS {
            return Err(RopError::Code(ErrorCode::TOO_BIG));
        }
        self.state
            .check_recipient_columns(handle, request.recipient_columns.len())?;
        let message = self.stage_handle(handle).await?;
        let exchange = self.mailbox(message.mailbox_id).await?.exchange;
        let named = AccountNamedProps::new(&exchange);
        let code_page = self.code_page();
        let columns = request
            .recipient_columns
            .iter()
            .collect::<SmallVec<[PropTag; 32]>>();
        let mut rows = SmallVec::<[(usize, Option<ContentBag>); 8]>::new();
        let mut extra = 0u64;
        for row in request.recipient_rows.iter() {
            let recipient = row
                .recipient(&columns)
                .map_err(|_| ErrorCode::INVALID_PARAM)?;
            let bag = recipient.map(|recipient| {
                recipient_bag(
                    &recipient,
                    WireType(row.recipient_type).kind(),
                    &columns,
                    &named,
                    code_page,
                )
            });
            if let Some(bag) = &bag {
                extra = extra.saturating_add(bag_size(bag));
            }
            rows.push((usize::try_from(row.row_id).unwrap_or(usize::MAX), bag));
        }
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        self.staged().charge(id, extra)?;
        let staged = self.staged_message(&message)?;
        let recipients = &mut staged.edit_at(&message.path)?.recipients;
        for (row, bag) in rows {
            let exists = row < recipients.len();
            match bag {
                Some(mut bag) if exists => {
                    if let Some(slot) = recipients.get_mut(row) {
                        settle_recipient_type(&mut bag, Some(slot));
                        *slot = bag;
                    }
                }
                Some(mut bag) if recipients.len() < MAX_RECIPIENTS => {
                    settle_recipient_type(&mut bag, None);
                    recipients.push(bag);
                }
                Some(_) => return Err(RopError::Code(ErrorCode::TOO_BIG)),
                None if exists => {
                    recipients.remove(row);
                }
                None => {}
            }
        }
        self.set_recipient_columns(
            handle,
            RecipientColumns::Client(columns.iter().map(|tag| tag.0).collect()),
        );
        self.respond_empty(rop, index)
    }

    pub async fn remove_all_recipients(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        if !matches!(self.target(handle)?, Target::Message) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let message = self.stage_handle(handle).await?;
        let staged = self.staged_message(&message)?;
        if !staged.content_at(&message.path)?.recipients.is_empty() {
            staged.edit_at(&message.path)?.recipients.clear();
        }
        self.respond_empty(rop, index)
    }

    pub async fn create_attachment(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &CreateAttachment,
    ) -> RopResult {
        let parent = self.input(rop.header.input_handle)?;
        if !matches!(self.target(parent)?, Target::Message) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let message = self.stage_handle(parent).await?;
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        self.staged()
            .charge(id, value_size(&OwnedPropValue::I32(0)))?;
        let staged = self.staged_message(&message)?;
        stamp_attachment_numbers(staged.edit_at(&message.path)?);
        let number = next_attachment(staged, &message.path)?;
        let content = staged.edit_at(&message.path)?;
        let mut props = ContentBag::new();
        props.set(
            PropKey::tag(tags::ATTACH_NUMBER.id()),
            OwnedPropValue::I32(i32::try_from(number).unwrap_or(i32::MAX)),
        );
        let created = creation_stamp();
        for tag in [tags::CREATION_TIME, tags::LAST_MODIFICATION_TIME] {
            props.set(PropKey::tag(tag.id()), OwnedPropValue::Time(created));
        }
        props.set(
            PropKey::tag(tags::RENDERING_POSITION.id()),
            OwnedPropValue::I32(RENDERING_POSITION_NONE),
        );
        content.attachments.push(Attachment {
            props,
            data: AttachData::None,
        });
        if message.path.is_empty() {
            staged.unsaved.push(number);
        }
        let handle = self.state.insert(
            logon_id,
            ServerObject::Attachment(Box::new(AttachmentObject { message, number })),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond(
            rop,
            index,
            &CreateAttachmentResponse {
                attachment_id: number,
            },
        )
    }

    pub fn save_changes_attachment(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SaveChangesAttachment,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let attachment = match self.state.get(handle) {
            Some(ServerObject::Attachment(attachment)) => attachment.as_ref().clone(),
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        if (request.save_flags & SAVE_MODE_FLAGS).count_ones() > 1 {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        if attachment.message.staged.is_some() && attachment.message.path.is_empty() {
            let staged = self.staged_message(&attachment.message)?;
            if let Some(failure) = staged
                .failed
                .iter()
                .find(|failure| failure.attachment == Some(attachment.number))
            {
                return Err(RopError::Code(failure.code));
            }
            staged.unsaved.retain(|number| *number != attachment.number);
        }
        self.respond_empty(rop, index)
    }

    pub async fn delete_attachment(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &DeleteAttachment,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        if !matches!(self.target(handle)?, Target::Message) {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let message = self.stage_handle(handle).await?;
        let staged = self.staged_message(&message)?;
        let removed = if message.path.is_empty() {
            remove_attachment(staged, request.attachment_id)
        } else {
            remove_embedded_attachment(staged, &message.path, request.attachment_id)?
        };
        if !removed {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        self.respond_empty(rop, index)
    }

    pub fn release_attachment(&mut self, handle: Handle) {
        if let Some(ServerObject::Attachment(attachment)) = self.state.get(handle)
            && let Some(id) = attachment.message.staged
            && attachment.message.path.is_empty()
        {
            let number = attachment.number;
            if let Some(staged) = self.staged().message(id) {
                if staged.unsaved.contains(&number) {
                    remove_attachment(staged, number);
                } else {
                    staged.clear_failed(Some(number), is_read_only_attachment);
                }
            }
        }
    }

    pub fn holds_staged_object(&self, handle: Handle) -> bool {
        match self.state.get(handle) {
            Some(ServerObject::Logon(_)) => true,
            Some(object) => object.staged_ids().next().is_some(),
            None => false,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum NewContent {
    Associated,
    Normal { data_type: DataType },
}

pub(super) fn new_content(kind: NewContent) -> MessageContent {
    let mut content = MessageContent::default();
    let created = creation_stamp();
    for tag in [tags::CREATION_TIME, tags::LAST_MODIFICATION_TIME] {
        content
            .props
            .set(PropKey::tag(tag.id()), OwnedPropValue::Time(created));
    }
    if let NewContent::Normal { data_type } = kind {
        content.props.set(
            PropKey::tag(tags::MESSAGE_FLAGS.id()),
            OwnedPropValue::I32(
                message_flags::READ | message_flags::UNSENT | message_flags::EVER_READ,
            ),
        );
        if data_type == DataType::Email {
            content.props.set(
                PropKey::tag(tags::MESSAGE_CLASS.id()),
                OwnedPropValue::Unicode(DEFAULT_MESSAGE_CLASS.into()),
            );
        }
    }
    content
}

pub fn drop_unsaved_attachments(staged: &mut StagedMessage) {
    while let Some(number) = staged.unsaved.pop() {
        remove_attachment(staged, number);
    }
}

fn remove_attachment(staged: &mut StagedMessage, number: u32) -> bool {
    let Some(position) =
        numbered_attachments(&staged.content).position(|(candidate, _)| candidate == number)
    else {
        return false;
    };
    let content = staged.edit_structure();
    stamp_attachment_numbers(content);
    content.attachments.remove(position);
    staged.unsaved.retain(|unsaved| *unsaved != number);
    staged.unsaved_embedded.forget_under(&[], Some(number));
    staged.clear_failed(Some(number), |_| true);
    true
}

fn remove_embedded_attachment(
    staged: &mut StagedMessage,
    path: &[u32],
    number: u32,
) -> Result<bool, ErrorCode> {
    let Some(position) = numbered_attachments(staged.content_at(path)?)
        .position(|(candidate, _)| candidate == number)
    else {
        return Ok(false);
    };
    let content = staged.edit_at(path)?;
    stamp_attachment_numbers(content);
    content.attachments.remove(position);
    staged.unsaved_embedded.forget_under(path, Some(number));
    Ok(true)
}

fn next_attachment(staged: &mut StagedMessage, path: &[u32]) -> Result<u32, ErrorCode> {
    if path.is_empty() {
        let number = staged.next_attachment;
        staged.next_attachment = number.checked_add(1).ok_or(ErrorCode::TOO_BIG)?;
        return Ok(number);
    }
    numbered_attachments(staged.content_at(path)?).try_fold(0u32, |next, (number, _)| {
        number
            .checked_add(1)
            .map(|after| next.max(after))
            .ok_or(ErrorCode::TOO_BIG)
    })
}

enum SubjectEdit {
    Compose(Box<str>),
    Split {
        prefix: Box<str>,
        normalized: Box<str>,
    },
}

impl SubjectEdit {
    fn derive(edits: &Edits, bag: &ContentBag) -> Option<Self> {
        let mut subject = None;
        let mut prefix = None;
        let mut normalized = None;
        for (key, value) in edits {
            let PropKeyRef::Tag(id) = key.as_ref() else {
                continue;
            };
            let text = match value {
                OwnedPropValue::Unicode(text) => Some(&**text),
                _ => None,
            };
            if id == tags::SUBJECT.id() {
                subject = Some(text);
            } else if id == tags::SUBJECT_PREFIX.id() {
                prefix = Some(text);
            } else if id == tags::NORMALIZED_SUBJECT.id() {
                normalized = Some(text);
            }
        }
        match (subject, prefix, normalized) {
            (Some(subject), None, None) => {
                let (prefix, normalized) = split_subject(subject?);
                (bag.text(tags::SUBJECT_PREFIX.id()).unwrap_or_default() != prefix
                    || bag.text(tags::NORMALIZED_SUBJECT.id()) != Some(normalized))
                .then(|| Self::Split {
                    prefix: prefix.into(),
                    normalized: normalized.into(),
                })
            }
            (Some(_), _, _) | (None, None, None) => None,
            (None, prefix, normalized) => {
                let normalized = match normalized {
                    Some(normalized) => normalized?,
                    None => bag.text(tags::NORMALIZED_SUBJECT.id()).or_else(|| {
                        bag.text(tags::SUBJECT.id())
                            .map(|subject| split_subject(subject).1)
                    })?,
                };
                let prefix = prefix
                    .unwrap_or_else(|| bag.text(tags::SUBJECT_PREFIX.id()))
                    .unwrap_or_default();
                let mut subject = String::with_capacity(prefix.len() + normalized.len());
                subject.push_str(prefix);
                subject.push_str(normalized);
                Some(Self::Compose(subject.into_boxed_str()))
            }
        }
    }

    fn push_into(self, edits: &mut Edits) {
        match self {
            Self::Compose(subject) => edits.push((
                PropKey::tag(tags::SUBJECT.id()),
                OwnedPropValue::Unicode(subject),
            )),
            Self::Split { prefix, normalized } => {
                edits.push((
                    PropKey::tag(tags::SUBJECT_PREFIX.id()),
                    OwnedPropValue::Unicode(prefix),
                ));
                edits.push((
                    PropKey::tag(tags::NORMALIZED_SUBJECT.id()),
                    OwnedPropValue::Unicode(normalized),
                ));
            }
        }
    }
}

fn target_bag(content: &MessageContent, target: Target) -> Result<&ContentBag, RopError> {
    match target {
        Target::Message => Ok(&content.props),
        Target::Attachment(number) => attachment_at(content, number)
            .map(|item| &item.props)
            .ok_or(RopError::Code(ErrorCode::OBJECT_DELETED)),
    }
}

fn attachment_bag(content: &mut MessageContent, number: u32) -> Result<&mut ContentBag, RopError> {
    attachment_mut(content, number)
        .map(|item| &mut item.props)
        .ok_or(RopError::Code(ErrorCode::OBJECT_DELETED))
}

pub fn item_key(tag: PropTag, named: &AccountNamedProps<'_>) -> Result<PropKey, ErrorCode> {
    let id = tag.id();
    if COMPUTED.iter().any(|computed| computed.id() == id) {
        Err(ErrorCode::ACCESS_DENIED)
    } else if id.0 >= FIRST_NAMED_ID {
        named
            .key(id)
            .map(|key| key.to_key())
            .ok_or(ErrorCode::NOT_FOUND)
    } else {
        Ok(PropKey::tag(id))
    }
}

pub fn owned_value(
    tag: PropTag,
    value: &PropValue<'_>,
    code_page: CodePage,
) -> Option<OwnedPropValue> {
    match value {
        PropValue::Unicode(_) | PropValue::String8(_) => {
            let mut text = String::new();
            decode_text_within(value, code_page, usize::MAX, &mut text)
                .then(|| OwnedPropValue::Unicode(text.into_boxed_str()))
        }
        _ if value.ptype().storage_class() != tag.ptype().storage_class() => None,
        _ => Some(value.to_owned_value()),
    }
}

fn copied_value(
    key: PropKeyRef<'_>,
    value: OwnedPropValue,
    code_page: CodePage,
) -> Option<OwnedPropValue> {
    match value {
        value if is_category(key) => category_value(value, code_page),
        OwnedPropValue::String8(bytes) => {
            let mut text = String::new();
            decode_text_within(
                &PropValue::String8(&bytes),
                code_page,
                usize::MAX,
                &mut text,
            )
            .then(|| OwnedPropValue::Unicode(text.into_boxed_str()))
        }
        value => Some(value),
    }
}

fn category_value(value: OwnedPropValue, code_page: CodePage) -> Option<OwnedPropValue> {
    match value {
        OwnedPropValue::MvUnicode(_) => Some(value),
        OwnedPropValue::MvString8(items) => {
            let mut text = String::new();
            items
                .iter()
                .map(|item| {
                    decode_text_within(&PropValue::String8(item), code_page, usize::MAX, &mut text)
                        .then(|| Box::from(text.as_str()))
                })
                .collect::<Option<Box<[Box<str>]>>>()
                .map(OwnedPropValue::MvUnicode)
        }
        _ => None,
    }
}

pub fn stream_value(tag: PropTag, bytes: Vec<u8>, code_page: CodePage) -> Option<OwnedPropValue> {
    match tag.ptype() {
        PropType::Unicode => {
            let even = bytes.get(..bytes.len() & !1).unwrap_or_default();
            owned_value(tag, &PropValue::Unicode(Utf16Le::new(even)?), code_page)
        }
        PropType::String8 => owned_value(tag, &PropValue::String8(&bytes), code_page),
        PropType::Binary => Some(OwnedPropValue::Binary(bytes.into())),
        _ => None,
    }
}

fn settle_recipient_type(bag: &mut ContentBag, previous: Option<&ContentBag>) {
    let key = PropKeyRef::Tag(tags::RECIPIENT_TYPE.id());
    if bag.get(key, PropType::I32).is_some() {
        return;
    }
    let kind = match previous.and_then(|previous| previous.get(key, PropType::I32)) {
        Some(OwnedPropValue::I32(kind)) if kind & recipient_type::MASK != 0 => {
            kind & recipient_type::MASK
        }
        _ => recipient_type::TO,
    };
    bag.set(
        PropKey::tag(tags::RECIPIENT_TYPE.id()),
        OwnedPropValue::I32(kind),
    );
}

fn recipient_bag(
    recipient: &RecipientRow<'_>,
    kind: Option<i32>,
    columns: &[PropTag],
    named: &AccountNamedProps<'_>,
    code_page: CodePage,
) -> ContentBag {
    let mut bag = ContentBag::new();
    let mut text = String::new();
    for (tag, cell) in recipient.columns.iter(columns) {
        let RowCell::Value(value) = cell else {
            continue;
        };
        let key = match tag.id() {
            id if RECIPIENT_IDENTITY.iter().any(|kept| kept.id() == id) => Ok(PropKey::tag(id)),
            _ => item_key(tag, named),
        };
        if let Ok(key) = key
            && let Some(value) = owned_value(tag, &value, code_page)
        {
            bag.set(key, value);
        }
    }
    if let Some(kind) = kind {
        bag.set(
            PropKey::tag(tags::RECIPIENT_TYPE.id()),
            OwnedPropValue::I32(kind),
        );
    }
    for (tag, value) in [
        (tags::DISPLAY_NAME, recipient.display_name),
        (tags::EMAIL_ADDRESS, recipient.email),
    ] {
        if let Some(value) = value
            && map_text(value, code_page, &mut text)
        {
            set_text(&mut bag, tag, &text);
        }
    }
    match &recipient.kind {
        RecipientKind::X500Dn { dn, .. } => {
            set_text(&mut bag, tags::ADDRESS_TYPE, ADDRESS_TYPE_EX);
            if decode_text_within(&PropValue::String8(dn), code_page, usize::MAX, &mut text) {
                set_text(&mut bag, tags::EMAIL_ADDRESS, &text);
            }
        }
        RecipientKind::Smtp => {
            set_text(&mut bag, tags::ADDRESS_TYPE, ADDRESS_TYPE_SMTP);
            if let Some(OwnedPropValue::Unicode(email)) =
                bag.get(PropKeyRef::Tag(tags::EMAIL_ADDRESS.id()), PropType::Unicode)
            {
                let email = email.clone();
                bag.set(
                    PropKey::tag(tags::SMTP_ADDRESS.id()),
                    OwnedPropValue::Unicode(email),
                );
            }
        }
        RecipientKind::NoType {
            address_type: Some(address_type),
        } if decode_text_within(
            &PropValue::String8(address_type),
            code_page,
            usize::MAX,
            &mut text,
        ) =>
        {
            set_text(&mut bag, tags::ADDRESS_TYPE, &text);
        }
        _ => {}
    }
    bag
}

fn map_text(value: MapiString<'_>, code_page: CodePage, out: &mut String) -> bool {
    let value = match value {
        MapiString::Unicode(text) => PropValue::Unicode(text),
        MapiString::String8(bytes) => PropValue::String8(bytes),
    };
    decode_text_within(&value, code_page, usize::MAX, out)
}

fn set_text(bag: &mut ContentBag, tag: PropTag, text: &str) {
    bag.set(PropKey::tag(tag.id()), OwnedPropValue::Unicode(text.into()));
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/write/tests.rs"]
mod tests;
