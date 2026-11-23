/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError, RopResult},
    folder_store::{PropTarget, RowEdit},
    folder_write::{OpenFolder, folder_row_key},
    message::{
        attachment_at, attachment_mut,
        object_row::{encode_property, is_category},
        write::{item_key, stream_value},
    },
    staged::{StagedObject, value_size},
    state::{AttachmentObject, FolderObject, Handle, ServerObject, StreamObject, StreamOwner},
};
use crate::{mapi::ids::MapiId, store::named::AccountNamedProps};
use exchange_proto::{
    convert::model::AttachData,
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropTag, PropType, tags},
        rop::{
            DecodedRop,
            requests::{CopyToStream, OpenStream, SetStreamSize, WriteStream},
            responses::{
                CopyToStreamResponse, OpenStreamResponse, ReadStreamResponse,
                WriteStreamExtendedResponse, WriteStreamResponse,
            },
        },
    },
};
use std::{ops::Range, sync::Arc};

const STREAM_READ_WRITE: u8 = 0x01;
const STREAM_CREATE: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamCommit {
    Commit,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteForm {
    Standard,
    Extended,
}

impl RopContext<'_, '_> {
    pub(super) async fn open_write_stream(
        &mut self,
        rop: &DecodedRop<'_>,
        request: &OpenStream,
    ) -> RopResult {
        let create = match request.open_mode_flags {
            STREAM_READ_WRITE => false,
            STREAM_CREATE => true,
            _ => return Err(RopError::Code(ErrorCode::STREAM_INVALID_PARAM)),
        };
        let parent = self.input(rop.header.input_handle)?;
        let target = match self.state.get(parent) {
            Some(ServerObject::Folder(folder))
                if request.property_tag.ptype() == PropType::Binary =>
            {
                WriteTarget::Folder(*folder)
            }
            Some(ServerObject::Message(_)) => WriteTarget::Message,
            Some(ServerObject::Attachment(attachment)) => {
                WriteTarget::Attachment(attachment.number)
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let owner = match target {
            WriteTarget::Folder(folder) => {
                let open = self.open_folder_at(parent)?;
                if PropTarget::of(open.node).is_none() {
                    return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
                }
                if !self.may_edit_folder_rows(open.mailbox_id) {
                    return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
                }
                self.check_folder_type(open.node)?;
                self.folder_tree(open.mailbox_id)
                    .await?
                    .get(open.node)
                    .ok_or(ErrorCode::OBJECT_DELETED)?;
                let exchange = self.mailbox(open.mailbox_id).await?.exchange;
                folder_row_key(request.property_tag, &AccountNamedProps::new(&exchange))?;
                StreamOwner::Folder(folder)
            }
            WriteTarget::Message => StreamOwner::Message(self.stage_handle(parent).await?),
            WriteTarget::Attachment(number) => StreamOwner::Attachment(AttachmentObject {
                message: self.stage_handle(parent).await?,
                number,
            }),
        };
        let bytes = if create {
            Vec::new()
        } else {
            match self.stream_bytes(&owner, request.property_tag).await {
                Ok(bytes) => bytes,
                Err(RopError::Code(ErrorCode::NOT_FOUND)) => Vec::new(),
                Err(err) => return Err(err),
            }
        };
        let cap = self.staged().message_cap();
        let size = u32::try_from(bytes.len())
            .ok()
            .filter(|size| u64::from(*size) <= cap)
            .ok_or(ErrorCode::TOO_BIG)?;
        let id = self.state.allocate_staged();
        self.staged()
            .insert(id, StagedObject::Stream(bytes), u64::from(size))?;
        let handle = match self.state.insert(
            logon_id,
            ServerObject::Stream(Box::new(StreamObject {
                owner,
                tag: request.property_tag.0,
                size,
                position: 0,
                staged: Some(id),
                dirty: create,
            })),
        ) {
            Ok(handle) => handle,
            Err(code) => {
                self.staged().remove(id);
                return Err(RopError::Code(code));
            }
        };
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        self.respond(rop, index, &OpenStreamResponse { stream_size: size })
    }

    fn writable_stream(&self, handle: Handle) -> Result<(u32, StreamObject), RopError> {
        let stream = self.stream(handle)?;
        let id = stream.staged.ok_or(ErrorCode::STREAM_ACCESS_DENIED)?;
        Ok((id, stream.clone()))
    }

    fn update_stream(&mut self, handle: Handle, size: u32, position: u32) {
        if let Some(ServerObject::Stream(stream)) = self.state.get_mut(handle) {
            stream.size = size;
            stream.position = position;
            stream.dirty = true;
        }
    }

    pub fn write_stream(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &WriteStream<'_>,
        form: WriteForm,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let (id, stream) = self.writable_stream(handle)?;
        let written = u16::try_from(request.data.len()).map_err(|_| ErrorCode::TOO_BIG)?;
        let end = stream
            .position
            .checked_add(u32::from(written))
            .ok_or(ErrorCode::TOO_BIG)?;
        if u64::from(end) > self.staged().message_cap() {
            return Err(RopError::Code(ErrorCode::TOO_BIG));
        }
        match form {
            WriteForm::Standard => self.respond(
                rop,
                index,
                &WriteStreamResponse {
                    written_size: written,
                },
            )?,
            WriteForm::Extended => self.respond(
                rop,
                index,
                &WriteStreamExtendedResponse {
                    written_size: u32::from(written),
                },
            )?,
        }
        self.write_staged(handle, id, &stream, request.data, end)
    }

    pub async fn copy_to_stream(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &CopyToStream,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let source = self.stream(handle)?.clone();
        let dest_handle = self
            .input(request.dest_handle_index)
            .map_err(|_| ErrorCode::DST_NULL_OBJECT)?;
        let (dest_id, dest) = self.writable_stream(dest_handle)?;
        let start = source.position.min(source.size);
        let end = start
            .saturating_add(u32::try_from(request.byte_count).unwrap_or(u32::MAX))
            .min(source.size);
        let data = self.stream_range(handle, &source, start..end).await?;
        let copied = end.saturating_sub(start);
        let dest_end = dest
            .position
            .checked_add(copied)
            .ok_or(ErrorCode::TOO_BIG)?;
        if u64::from(dest_end) > self.staged().message_cap() {
            return Err(RopError::Code(ErrorCode::TOO_BIG));
        }
        self.respond(
            rop,
            index,
            &CopyToStreamResponse {
                read_byte_count: u64::from(copied),
                written_byte_count: u64::from(copied),
            },
        )?;
        self.write_staged(dest_handle, dest_id, &dest, &data, dest_end)?;
        if let Some(ServerObject::Stream(stream)) = self.state.get_mut(handle) {
            stream.position = end;
        }
        Ok(())
    }

    async fn stream_range(
        &mut self,
        handle: Handle,
        stream: &StreamObject,
        range: Range<u32>,
    ) -> Result<Vec<u8>, RopError> {
        let range = usize::try_from(range.start).unwrap_or(usize::MAX)
            ..usize::try_from(range.end).unwrap_or(usize::MAX);
        if let Some(id) = stream.staged {
            return self
                .staged()
                .stream(id)
                .ok_or(ErrorCode::NULL_OBJECT)?
                .get(range)
                .map(<[u8]>::to_vec)
                .ok_or(RopError::Code(ErrorCode::STREAM_SEEK_ERROR));
        }
        let bytes = match self.cached_stream(handle) {
            Some(bytes) => bytes,
            None => {
                let bytes = Arc::new(
                    self.stream_bytes(&stream.owner, PropTag(stream.tag))
                        .await?,
                );
                if u32::try_from(bytes.len()).ok() != Some(stream.size) {
                    return Err(RopError::Code(ErrorCode::OBJECT_DELETED));
                }
                if range.end < bytes.len() && !self.cache_stream(handle, bytes.clone()) {
                    return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
                }
                bytes
            }
        };
        bytes
            .get(range)
            .map(<[u8]>::to_vec)
            .ok_or(RopError::Code(ErrorCode::STREAM_SEEK_ERROR))
    }

    fn write_staged(
        &mut self,
        handle: Handle,
        id: u32,
        stream: &StreamObject,
        data: &[u8],
        end: u32,
    ) -> RopResult {
        let staged = self.staged();
        let current = staged.stream(id).ok_or(ErrorCode::NULL_OBJECT)?.len();
        let grow = usize::try_from(end)
            .unwrap_or(usize::MAX)
            .saturating_sub(current);
        staged.charge(id, u64::try_from(grow).unwrap_or(u64::MAX))?;
        let bytes = staged.stream(id).ok_or(ErrorCode::NULL_OBJECT)?;
        write_at(
            bytes,
            usize::try_from(stream.position).unwrap_or(usize::MAX),
            data,
        );
        self.update_stream(handle, stream.size.max(end), end);
        Ok(())
    }

    pub fn set_stream_size(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetStreamSize,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let (id, stream) = self.writable_stream(handle)?;
        let staged = self.staged();
        let size = u32::try_from(request.stream_size)
            .ok()
            .filter(|size| u64::from(*size) <= staged.message_cap())
            .ok_or(ErrorCode::TOO_BIG)?;
        let current = staged.stream(id).ok_or(ErrorCode::NULL_OBJECT)?.len();
        let target = usize::try_from(size).unwrap_or(usize::MAX);
        staged.charge(
            id,
            u64::try_from(target.saturating_sub(current)).unwrap_or(u64::MAX),
        )?;
        staged
            .stream(id)
            .ok_or(ErrorCode::NULL_OBJECT)?
            .resize(target, 0);
        self.update_stream(handle, size, stream.position);
        self.respond_empty(rop, index)
    }

    pub async fn commit_stream(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        self.writable_stream(handle)?;
        self.commit_staged_stream(handle, StreamCommit::Commit)
            .await?;
        if let Some(ServerObject::Stream(stream)) = self.state.get_mut(handle) {
            stream.dirty = false;
        }
        self.respond_empty(rop, index)
    }

    pub(super) fn read_staged_stream(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        handle: Handle,
        id: u32,
        range: Range<u32>,
    ) -> RopResult {
        let end = range.end;
        let data = self
            .staged()
            .stream(id)
            .ok_or(ErrorCode::NULL_OBJECT)?
            .get(
                usize::try_from(range.start).unwrap_or(usize::MAX)
                    ..usize::try_from(end).unwrap_or(usize::MAX),
            )
            .ok_or(ErrorCode::STREAM_SEEK_ERROR)?
            .to_vec();
        self.respond(rop, index, &ReadStreamResponse { data: &data })?;
        if let Some(ServerObject::Stream(stream)) = self.state.get_mut(handle) {
            stream.position = end;
        }
        Ok(())
    }

    pub async fn commit_staged_stream(
        &mut self,
        handle: Handle,
        mode: StreamCommit,
    ) -> Result<(), RopError> {
        let Some(ServerObject::Stream(stream)) = self.state.get(handle) else {
            return Ok(());
        };
        let Some(id) = stream.staged else {
            return Ok(());
        };
        if mode == StreamCommit::Release && !stream.dirty {
            self.staged().remove(id);
            return Ok(());
        }
        let tag = PropTag(stream.tag);
        let (message, number) = match &stream.owner {
            StreamOwner::Folder(folder) => {
                let folder = *folder;
                return self.commit_folder_stream(id, folder, tag, mode).await;
            }
            StreamOwner::Message(message) => (message.clone(), None),
            StreamOwner::Attachment(attachment) => {
                (attachment.message.clone(), Some(attachment.number))
            }
        };
        let message_id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        let exchange = self.mailbox(message.mailbox_id).await?.exchange;
        let key = item_key(tag, &AccountNamedProps::new(&exchange))?;
        let code_page = self.code_page();
        let staged = self.staged();
        let bytes = match mode {
            StreamCommit::Commit => staged.stream(id).ok_or(ErrorCode::NULL_OBJECT)?.clone(),
            StreamCommit::Release => match staged.remove(id) {
                Some(StagedObject::Stream(bytes)) => bytes,
                _ => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
            },
        };
        let edit = match number {
            Some(number) if tag == tags::ATTACH_DATA_BINARY => {
                StreamEdit::AttachData(number, bytes)
            }
            Some(number) => StreamEdit::AttachProp(
                number,
                stream_value(tag, bytes, code_page).ok_or(ErrorCode::INVALID_PARAM)?,
            ),
            None => StreamEdit::MessageProp(
                stream_value(tag, bytes, code_page)
                    .filter(|_| !is_category(key.as_ref()))
                    .ok_or(ErrorCode::INVALID_PARAM)?,
            ),
        };
        let path = message.path.as_slice();
        let current = self.staged_message(&message)?.content_at(path)?;
        let (added, removed) = match &edit {
            StreamEdit::AttachData(number, bytes) => (
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                match &attachment_at(current, *number)
                    .ok_or(ErrorCode::OBJECT_DELETED)?
                    .data
                {
                    AttachData::Bytes(data) => u64::try_from(data.len()).unwrap_or(u64::MAX),
                    _ => 0,
                },
            ),
            StreamEdit::AttachProp(number, value) => (
                value_size(value),
                attachment_at(current, *number)
                    .ok_or(ErrorCode::OBJECT_DELETED)?
                    .props
                    .get(key.as_ref(), value.ptype())
                    .map_or(0, value_size),
            ),
            StreamEdit::MessageProp(value) => (
                value_size(value),
                current
                    .props
                    .get(key.as_ref(), value.ptype())
                    .map_or(0, value_size),
            ),
        };
        self.staged().recharge(message_id, added, removed)?;
        let target = self.staged_message(&message)?;
        match edit {
            StreamEdit::AttachData(number, bytes) => {
                attachment_mut(target.edit_at(path)?, number)
                    .ok_or(ErrorCode::OBJECT_DELETED)?
                    .data = AttachData::Bytes(bytes.into());
            }
            StreamEdit::AttachProp(number, value) => {
                attachment_mut(target.edit_at(path)?, number)
                    .ok_or(ErrorCode::OBJECT_DELETED)?
                    .props
                    .set(key, value);
            }
            StreamEdit::MessageProp(value) => {
                target
                    .edit_key_at(path, key.as_ref())?
                    .props
                    .set(key, value);
            }
        }
        if path.is_empty() {
            target.clear_failed(number, |prop| prop == tag.id());
        }
        Ok(())
    }

    async fn commit_folder_stream(
        &mut self,
        id: u32,
        folder: FolderObject,
        tag: PropTag,
        mode: StreamCommit,
    ) -> Result<(), RopError> {
        let staged = self.staged();
        let bytes = match mode {
            StreamCommit::Commit => staged.stream(id).ok_or(ErrorCode::NULL_OBJECT)?.clone(),
            StreamCommit::Release => match staged.remove(id) {
                Some(StagedObject::Stream(bytes)) => bytes,
                _ => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
            },
        };
        let open = OpenFolder {
            mailbox_id: folder.mailbox_id,
            node: folder
                .id()
                .and_then(MapiId::to_node)
                .ok_or(ErrorCode::OBJECT_DELETED)?,
        };
        self.check_folder_type(open.node)?;
        self.folder_tree(open.mailbox_id)
            .await?
            .get(open.node)
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let exchange = self.mailbox(open.mailbox_id).await?.exchange;
        let key = folder_row_key(tag, &AccountNamedProps::new(&exchange))?;
        let property = encode_property(key.as_ref(), &OwnedPropValue::Binary(bytes.into()));
        self.edit_owned_folder_row(open, &[RowEdit::Set(property.key, property.value)])
            .await
    }
}

enum WriteTarget {
    Folder(FolderObject),
    Message,
    Attachment(u32),
}

enum StreamEdit {
    AttachData(u32, Vec<u8>),
    AttachProp(u32, OwnedPropValue),
    MessageProp(OwnedPropValue),
}

fn write_at(bytes: &mut Vec<u8>, start: usize, data: &[u8]) {
    if bytes.len() < start {
        bytes.resize(start, 0);
    }
    let tail = bytes.get_mut(start..).unwrap_or_default();
    let overlap = tail.len().min(data.len());
    let (head, rest) = data.split_at(overlap);
    if let Some(target) = tail.get_mut(..overlap) {
        target.copy_from_slice(head);
    }
    bytes.extend_from_slice(rest);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/stream_write/tests.rs"]
mod tests;
