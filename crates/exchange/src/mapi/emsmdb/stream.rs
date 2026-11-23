/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    cache::MAX_CACHE_BYTES,
    execute::{Packing, RopContext, RopError, RopResult},
    message::{attachment_at, load::embedded},
    props::{PropDemand, PropOut},
    staged::FailedCommit,
    state::{AttachmentObject, FolderObject, Handle, ServerObject, StreamObject, StreamOwner},
    stream_write::StreamCommit,
};
use exchange_proto::{
    convert::{
        mime::{BodyKindRequest, BodySelection, select_body},
        model::{AttachData, PropBag as ContentBag},
        rtf::{RtfSource, rtf_compress, rtf_encapsulate},
    },
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropKeyRef, PropTag, PropType, PropValue, tags},
        rop::{
            DecodedRop,
            requests::{OpenStream, ReadStream, SeekStream},
            responses::{
                GetStreamSizeResponse, OpenStreamResponse, ReadStreamResponse, SeekStreamResponse,
            },
        },
    },
};
use std::{ops::Range, sync::Arc};

const STREAM_READ_ONLY: u8 = 0x00;
const SEEK_BEGINNING: u8 = 0x00;
const SEEK_CURRENT: u8 = 0x01;
const SEEK_END: u8 = 0x02;
pub(super) const MAX_READ: u32 = 0xF000;
const MAX_SEEK: i64 = 1 << 31;
const READ_STREAM_OVERHEAD: usize = 8;

impl StreamObject {
    pub fn seek(&self, origin: u8, offset: u64) -> Result<u32, ErrorCode> {
        let base = match origin {
            SEEK_BEGINNING => 0,
            SEEK_CURRENT => i64::from(self.position),
            SEEK_END => i64::from(self.size),
            _ => return Err(ErrorCode::STREAM_INVALID_PARAM),
        };
        base.checked_add(i64::from_le_bytes(offset.to_le_bytes()))
            .filter(|position| *position <= MAX_SEEK)
            .and_then(|position| u32::try_from(position).ok())
            .ok_or(ErrorCode::STREAM_SEEK_ERROR)
    }

    pub fn read_range(&self, want: u32) -> Range<u32> {
        let start = self.position.min(self.size);
        start..start.saturating_add(want.min(MAX_READ)).min(self.size)
    }
}

impl RopContext<'_, '_> {
    pub async fn open_stream(&mut self, rop: &DecodedRop<'_>, request: &OpenStream) -> RopResult {
        if request.open_mode_flags != STREAM_READ_ONLY {
            return self.open_write_stream(rop, request).await;
        }
        let parent = self.input(rop.header.input_handle)?;
        let owner = match self.state.get(parent) {
            Some(ServerObject::Folder(folder))
                if request.property_tag.ptype() == PropType::Binary =>
            {
                StreamOwner::Folder(*folder)
            }
            Some(ServerObject::Message(message)) => StreamOwner::Message(message.without_columns()),
            Some(ServerObject::Attachment(attachment)) => {
                StreamOwner::Attachment(attachment.as_ref().clone())
            }
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let logon_id = self
            .state
            .logon_id(parent)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))?;
        let bytes = self.stream_bytes(&owner, request.property_tag).await?;
        let size = u32::try_from(bytes.len())
            .ok()
            .filter(|size| u64::from(*size) <= MAX_CACHE_BYTES)
            .ok_or(ErrorCode::TOO_BIG)?;
        let handle = self.state.insert(
            logon_id,
            ServerObject::Stream(Box::new(StreamObject {
                owner,
                tag: request.property_tag.0,
                size,
                position: 0,
                staged: None,
                dirty: false,
            })),
        )?;
        let index = request.output_handle_index;
        self.set_output(index, handle)?;
        if size > MAX_READ && !self.cache_stream(handle, Arc::new(bytes)) {
            return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
        }
        let result = self.respond(rop, index, &OpenStreamResponse { stream_size: size });
        if result.is_err() && size > MAX_READ {
            self.forget_stream(handle);
        }
        result
    }

    pub async fn read_stream(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &ReadStream,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let stream = self.stream(handle)?.clone();
        let want = request
            .maximum_byte_count
            .unwrap_or(u32::from(request.byte_count));
        let room = self.writer.remaining().saturating_sub(READ_STREAM_OVERHEAD);
        let range = stream.read_range(want.min(u32::try_from(room).unwrap_or(u32::MAX)));
        if range.is_empty() && stream.read_range(want).end > range.end {
            return Err(RopError::Overflow);
        }
        let read = range.end.saturating_sub(range.start);
        let packing =
            (read > 0 && read < want && range.end < stream.size).then_some(Packing::Bytes(read));
        if let Some(id) = stream.staged {
            self.read_staged_stream(rop, index, handle, id, range)?;
            if let Some(packing) = packing {
                self.packable(packing);
            }
            return Ok(());
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
                if range.end < stream.size && !self.cache_stream(handle, bytes.clone()) {
                    return Err(RopError::Code(ErrorCode::NOT_ENOUGH_MEMORY));
                }
                bytes
            }
        };
        let data = bytes
            .get(range.start as usize..range.end as usize)
            .ok_or(ErrorCode::STREAM_SEEK_ERROR)?;
        self.respond(rop, index, &ReadStreamResponse { data })?;
        if let Some(ServerObject::Stream(stream)) = self.state.get_mut(handle) {
            stream.position = range.end;
        }
        if let Some(packing) = packing {
            self.packable(packing);
        }
        Ok(())
    }

    pub fn seek_stream(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SeekStream,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let position = self.stream(handle)?.seek(request.origin, request.offset)?;
        if let Some(ServerObject::Stream(stream)) = self.state.get_mut(handle) {
            stream.position = position;
        }
        self.respond(
            rop,
            index,
            &SeekStreamResponse {
                new_position: u64::from(position),
            },
        )
    }

    pub fn get_stream_size(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let stream_size = self.stream(handle)?.size;
        self.respond(rop, index, &GetStreamSizeResponse { stream_size })
    }

    pub async fn release_stream(&mut self, handle: Handle) {
        match self.state.get(handle) {
            Some(ServerObject::Stream(stream)) if stream.staged.is_some() => {
                let owner = match &stream.owner {
                    StreamOwner::Folder(folder) => ReleaseOwner::Folder(folder.mailbox_id),
                    StreamOwner::Message(message) => ReleaseOwner::Message(message.staged, None),
                    StreamOwner::Attachment(AttachmentObject { message, number }) => {
                        ReleaseOwner::Message(message.staged, Some(*number))
                    }
                };
                let prop = PropTag(stream.tag).id();
                let code = match self
                    .commit_staged_stream(handle, StreamCommit::Release)
                    .await
                {
                    Ok(()) => return,
                    Err(RopError::Code(code)) => code,
                    Err(RopError::Internal(err)) => {
                        trc::error!(err.details("MAPI stream commit on release failed"));
                        ErrorCode::ERROR
                    }
                    Err(RopError::Overflow) => ErrorCode::ERROR,
                };
                match owner {
                    ReleaseOwner::Folder(mailbox_id) => {
                        if code == ErrorCode::QUOTA_EXCEEDED {
                            trc::event!(
                                Limit(trc::LimitEvent::SizeRequest),
                                AccountId = mailbox_id,
                                Details = "MAPI folder stream dropped on release"
                            );
                        }
                    }
                    ReleaseOwner::Message(owner, attachment) => {
                        if let Some(staged) = owner.and_then(|id| self.staged().message(id)) {
                            staged.fail_commit(FailedCommit {
                                code,
                                attachment,
                                prop,
                            });
                        }
                    }
                }
            }
            Some(ServerObject::Stream(_)) => self.forget_stream(handle),
            _ => {}
        }
    }

    pub(super) fn stream(&self, handle: Handle) -> Result<&StreamObject, RopError> {
        match self.state.get(handle) {
            Some(ServerObject::Stream(stream)) => Ok(stream),
            Some(_) => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        }
    }

    pub(super) async fn stream_bytes(
        &mut self,
        owner: &StreamOwner,
        tag: PropTag,
    ) -> Result<Vec<u8>, RopError> {
        let (message, attachment) = match owner {
            StreamOwner::Folder(folder) => return self.folder_stream_bytes(folder, tag).await,
            StreamOwner::Message(message) => (message, None),
            StreamOwner::Attachment(AttachmentObject { message, number }) => {
                (message, Some(*number))
            }
        };
        let root = self.message_root(message).await?;
        let content = embedded(&root, &message.path).ok_or(ErrorCode::OBJECT_DELETED)?;
        let code_page = self.code_page();
        let props = match attachment {
            None => {
                if tag.id() == tags::RTF_COMPRESSED.id() {
                    return rtf_body(content);
                }
                let want = if tag.id() == tags::BODY.id() {
                    Some(BodyKindRequest::Text)
                } else if tag.id() == tags::BODY_HTML.id() {
                    Some(BodyKindRequest::Html)
                } else {
                    None
                };
                if let Some(want) = want {
                    if tag.ptype() == PropType::Binary
                        && let Some(OwnedPropValue::Binary(bytes)) =
                            content.props.get_any(PropKeyRef::Tag(tag.id()))
                    {
                        return Ok(bytes.to_vec());
                    }
                    return match select_body(content, want) {
                        Some(BodySelection::Text(text) | BodySelection::Html(text)) => {
                            Ok(match tag.ptype() {
                                PropType::String8 => {
                                    let mut out = Vec::with_capacity(text.len());
                                    code_page.narrow_str(&text, usize::MAX, &mut out);
                                    out
                                }
                                PropType::Binary => text.into_owned().into_bytes(),
                                _ => utf16(&text),
                            })
                        }
                        _ => Err(RopError::Code(ErrorCode::NOT_FOUND)),
                    };
                }
                &content.props
            }
            Some(number) => {
                let item = attachment_at(content, number).ok_or(ErrorCode::OBJECT_DELETED)?;
                if tag == tags::ATTACH_DATA_BINARY
                    && let AttachData::Bytes(bytes) = &item.data
                {
                    return Ok(bytes.to_vec());
                }
                &item.props
            }
        };
        value_bytes(props, tag, |text, out| {
            code_page.narrow_str(text, usize::MAX, out)
        })
    }

    async fn folder_stream_bytes(
        &mut self,
        folder: &FolderObject,
        tag: PropTag,
    ) -> Result<Vec<u8>, RopError> {
        let bag = self.folder_props(folder, PropDemand::Tags(&[tag])).await?;
        match bag.get(tag) {
            Some(PropOut::Value(PropValue::Binary(bytes))) => Ok(bytes.to_vec()),
            _ => Err(RopError::Code(ErrorCode::NOT_FOUND)),
        }
    }
}

fn rtf_body(content: &exchange_proto::convert::model::MessageContent) -> Result<Vec<u8>, RopError> {
    let mut rtf = Vec::new();
    match select_body(content, BodyKindRequest::Native) {
        Some(BodySelection::Rtf(compressed)) => return Ok(compressed.to_vec()),
        Some(BodySelection::Html(html)) => rtf_encapsulate(RtfSource::Html(&html), &mut rtf),
        Some(BodySelection::Text(text)) => rtf_encapsulate(RtfSource::Text(&text), &mut rtf),
        None => return Err(RopError::Code(ErrorCode::NOT_FOUND)),
    }
    let mut out = Vec::new();
    rtf_compress(&rtf, &mut out).map_err(|_| ErrorCode::TOO_BIG)?;
    Ok(out)
}

fn value_bytes(
    props: &ContentBag,
    tag: PropTag,
    narrow: impl FnOnce(&str, &mut Vec<u8>),
) -> Result<Vec<u8>, RopError> {
    match props.get_any(PropKeyRef::Tag(tag.id())) {
        Some(OwnedPropValue::Unicode(text)) if tag.ptype() == PropType::String8 => {
            let mut out = Vec::with_capacity(text.len());
            narrow(text, &mut out);
            Ok(out)
        }
        Some(OwnedPropValue::Unicode(text)) => Ok(utf16(text)),
        Some(OwnedPropValue::Binary(bytes)) => Ok(bytes.to_vec()),
        Some(OwnedPropValue::String8(bytes)) => Ok(bytes.to_vec()),
        _ => Err(RopError::Code(ErrorCode::NOT_FOUND)),
    }
}

fn utf16(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(2));
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

enum ReleaseOwner {
    Folder(u32),
    Message(Option<u32>, Option<u32>),
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/stream/tests.rs"]
mod tests;
