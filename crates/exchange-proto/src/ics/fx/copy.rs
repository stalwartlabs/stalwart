/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FxEvent, Marker,
    decoder::unterminated_value,
    meta,
    tags::{MESSAGE_ATTACHMENTS, MESSAGE_RECIPIENTS},
};
use crate::{
    convert::model::{AttachData, Attachment, MessageContent, PropBag},
    mapi::{
        ErrorCode,
        prop::{MvType, OwnedPropValue, PropId, PropKey, PropKeyRef, PropTag, PropType, tags},
    },
};
use bytes::Bytes;
use std::mem;

const ELEMENTS_RESERVE_MAX: usize = 1024;
const VALUE_RESERVE_MAX: usize = 64 * 1024;
const MAX_RECIPIENTS: usize = 0x7FFF;
const MAX_ATTACHMENTS: usize = 0x7FFF;
const ENTRY_CHARGE: usize = 2 * size_of::<(PropKey, OwnedPropValue)>();
const RECIPIENT_CHARGE: usize = 2 * size_of::<PropBag>();
const ATTACHMENT_CHARGE: usize = 2 * size_of::<Attachment>();
const CONTENT_CHARGE: usize = size_of::<MessageContent>();
const ELEMENT_SIZE: usize = size_of::<OwnedPropValue>();

type Entries = Vec<(PropKey, OwnedPropValue)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyError {
    Grammar,
    Recipients,
    Attachments,
    PublicFolder,
}

impl CopyError {
    pub fn error_code(self) -> ErrorCode {
        match self {
            CopyError::Grammar => ErrorCode::RPC_FORMAT,
            CopyError::PublicFolder => ErrorCode::NOT_SUPPORTED,
            CopyError::Recipients => ErrorCode::TOO_BIG,
            CopyError::Attachments => ErrorCode::MAX_ATTACHMENT_EXCEEDED,
        }
    }
}

#[derive(Debug, Default)]
struct Draft {
    props: Entries,
    recipients: Vec<PropBag>,
    attachments: Vec<Attachment>,
}

impl Draft {
    fn finish(self) -> MessageContent {
        MessageContent {
            props: PropBag::from_entries(self.props),
            recipients: self.recipients,
            attachments: self.attachments,
        }
    }
}

#[derive(Debug)]
enum Frame {
    Root,
    Folder(Option<Entries>),
    Message(Draft, MessageKind),
    Recipient(Entries),
    Attachment { props: Entries, data: AttachData },
    Embedded(Draft),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    Normal,
    Associated,
}

#[derive(Debug)]
enum Pending {
    Idle,
    Value {
        key: PropKey,
        ptype: PropType,
        bytes: ValueBuffer,
    },
    Mv {
        key: PropKey,
        mv_type: MvType,
        elements: Vec<OwnedPropValue>,
        heap: usize,
        element: Option<ValueBuffer>,
    },
}

#[derive(Debug)]
struct ValueBuffer {
    bytes: Vec<u8>,
    total: usize,
}

impl ValueBuffer {
    fn new(total_len: u32) -> Self {
        let total = usize::try_from(total_len).unwrap_or(usize::MAX);
        ValueBuffer {
            bytes: Vec::with_capacity(total.min(VALUE_RESERVE_MAX)),
            total,
        }
    }

    fn extend(&mut self, chunk: &[u8]) {
        let needed = self.bytes.len().saturating_add(chunk.len());
        if needed > self.bytes.capacity() {
            let target = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .min(self.total)
                .max(needed);
            self.bytes
                .reserve_exact(target.saturating_sub(self.bytes.len()));
        }
        self.bytes.extend_from_slice(chunk);
    }

    fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
}

impl Pending {
    fn heap_size(&self) -> usize {
        match self {
            Pending::Idle => 0,
            Pending::Value { key, bytes, .. } => key.heap_size().saturating_add(bytes.capacity()),
            Pending::Mv {
                key,
                elements,
                heap,
                element,
                ..
            } => key
                .heap_size()
                .saturating_add(elements.capacity().saturating_mul(ELEMENT_SIZE))
                .saturating_add(*heap)
                .saturating_add(element.as_ref().map_or(0, ValueBuffer::capacity)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyRoot {
    MessageList,
    MessageContent,
    AttachmentContent,
    FolderContent,
    TopFolder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Children {
    Recipients,
    Attachments,
}

#[derive(Debug)]
pub enum CopyItem {
    Prop(PropKey, OwnedPropValue),
    DeleteChildren(Children),
    Recipient(PropBag),
    Attachment(Attachment),
    Embedded(MessageContent),
    Message(MessageContent),
    FaiMessage(MessageContent),
    FolderStart(PropBag),
    FolderEnd,
}

#[derive(Debug)]
pub struct CopyBuilder {
    root: CopyRoot,
    stack: Vec<Frame>,
    pending: Pending,
    built: usize,
    closed: bool,
}

impl CopyBuilder {
    pub fn new(root: CopyRoot) -> Self {
        let stack = match root {
            CopyRoot::MessageContent | CopyRoot::AttachmentContent | CopyRoot::FolderContent => {
                vec![Frame::Root]
            }
            CopyRoot::MessageList | CopyRoot::TopFolder => Vec::new(),
        };
        CopyBuilder {
            root,
            stack,
            pending: Pending::Idle,
            built: 0,
            closed: false,
        }
    }

    pub fn root(&self) -> CopyRoot {
        self.root
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.stack.as_slice(), [] | [Frame::Root]) && matches!(self.pending, Pending::Idle)
    }

    pub fn heap_size(&self) -> usize {
        self.built.saturating_add(self.pending.heap_size())
    }

    pub fn push(&mut self, event: FxEvent<'_>, items: &mut Vec<CopyItem>) -> Result<(), CopyError> {
        match event {
            FxEvent::Marker(marker) => self.marker(marker, items)?,
            FxEvent::Prop { key, value, .. } => {
                self.idle()?;
                self.set(key.to_key(), value.to_owned_value(), items)?;
            }
            FxEvent::ValueStart {
                key,
                ptype,
                total_len,
            } => {
                self.idle()?;
                self.pending = Pending::Value {
                    key: key.to_key(),
                    ptype,
                    bytes: ValueBuffer::new(total_len),
                };
            }
            FxEvent::ValueChunk(chunk) => match &mut self.pending {
                Pending::Value { bytes, .. }
                | Pending::Mv {
                    element: Some(bytes),
                    ..
                } => bytes.extend(chunk),
                _ => return Err(CopyError::Grammar),
            },
            FxEvent::ValueEnd => self.value_end(items)?,
            FxEvent::MvStart {
                key,
                mv_type,
                count,
            } => {
                self.idle()?;
                self.pending = Pending::Mv {
                    key: key.to_key(),
                    mv_type,
                    elements: Vec::with_capacity(reserve(count, ELEMENTS_RESERVE_MAX)),
                    heap: 0,
                    element: None,
                };
            }
            FxEvent::Element(value) => match &mut self.pending {
                Pending::Mv {
                    elements,
                    heap,
                    element: None,
                    ..
                } => {
                    let value = value.to_owned_value();
                    *heap = heap.saturating_add(value.heap_size());
                    elements.push(value);
                }
                _ => return Err(CopyError::Grammar),
            },
            FxEvent::ElementStart { total_len } => match &mut self.pending {
                Pending::Mv { element, .. } if element.is_none() => {
                    *element = Some(ValueBuffer::new(total_len));
                }
                _ => return Err(CopyError::Grammar),
            },
            FxEvent::MvEnd => {
                let Pending::Mv {
                    key,
                    mv_type,
                    elements,
                    element: None,
                    ..
                } = mem::replace(&mut self.pending, Pending::Idle)
                else {
                    return Err(CopyError::Grammar);
                };
                let value = mv_value(mv_type, elements).ok_or(CopyError::Grammar)?;
                self.set(key, value, items)?;
            }
        }
        Ok(())
    }

    fn idle(&self) -> Result<(), CopyError> {
        match self.pending {
            Pending::Idle => Ok(()),
            _ => Err(CopyError::Grammar),
        }
    }

    fn value_end(&mut self, items: &mut Vec<CopyItem>) -> Result<(), CopyError> {
        match &mut self.pending {
            Pending::Mv {
                mv_type,
                elements,
                heap,
                element,
                ..
            } => {
                let bytes = element.take().ok_or(CopyError::Grammar)?;
                let value =
                    owned_value(mv_type.element_type(), bytes.bytes).ok_or(CopyError::Grammar)?;
                *heap = heap.saturating_add(value.heap_size());
                elements.push(value);
                Ok(())
            }
            Pending::Value { .. } => {
                let Pending::Value { key, ptype, bytes } =
                    mem::replace(&mut self.pending, Pending::Idle)
                else {
                    return Err(CopyError::Grammar);
                };
                let value = owned_value(ptype, bytes.bytes).ok_or(CopyError::Grammar)?;
                self.set(key, value, items)
            }
            Pending::Idle => Err(CopyError::Grammar),
        }
    }

    fn emit(&mut self, items: &mut Vec<CopyItem>, item: CopyItem) {
        self.built = 0;
        items.push(item);
    }

    fn at_root(&self, root: CopyRoot) -> bool {
        self.root == root && matches!(self.stack.last(), Some(Frame::Root))
    }

    fn start_folder(&mut self, items: &mut Vec<CopyItem>) {
        if let Some(Frame::Folder(props)) = self.stack.last_mut()
            && let Some(props) = props.take()
        {
            self.emit(items, CopyItem::FolderStart(PropBag::from_entries(props)));
        }
    }

    fn marker(&mut self, marker: Marker, items: &mut Vec<CopyItem>) -> Result<(), CopyError> {
        self.idle()?;
        self.start_folder(items);
        match marker {
            Marker::StartTopFld
                if self.root == CopyRoot::TopFolder && self.stack.is_empty() && !self.closed =>
            {
                self.stack.push(Frame::Folder(Some(Entries::new())));
            }
            Marker::StartSubFld
                if self.at_root(CopyRoot::FolderContent)
                    || matches!(self.stack.last(), Some(Frame::Folder(_))) =>
            {
                self.stack.push(Frame::Folder(Some(Entries::new())));
            }
            Marker::EndFolder => {
                let Some(Frame::Folder(None)) = self.stack.pop() else {
                    return Err(CopyError::Grammar);
                };
                self.closed = self.stack.is_empty();
                self.emit(items, CopyItem::FolderEnd);
            }
            Marker::StartMessage | Marker::StartFaiMsg
                if (self.root == CopyRoot::MessageList && self.stack.is_empty())
                    || self.at_root(CopyRoot::FolderContent)
                    || matches!(self.stack.last(), Some(Frame::Folder(_))) =>
            {
                let kind = if marker == Marker::StartFaiMsg {
                    MessageKind::Associated
                } else {
                    MessageKind::Normal
                };
                self.stack.push(Frame::Message(Draft::default(), kind));
                self.charge(CONTENT_CHARGE);
            }
            Marker::EndMessage => {
                let item = match self.stack.pop() {
                    Some(Frame::Message(draft, MessageKind::Normal)) => {
                        CopyItem::Message(draft.finish())
                    }
                    Some(Frame::Message(draft, MessageKind::Associated)) => {
                        CopyItem::FaiMessage(draft.finish())
                    }
                    _ => return Err(CopyError::Grammar),
                };
                self.emit(items, item);
            }
            Marker::StartRecip => {
                if let Some(draft) = self.draft() {
                    if draft.recipients.len() >= MAX_RECIPIENTS {
                        return Err(CopyError::Recipients);
                    }
                } else if !self.at_root(CopyRoot::MessageContent) {
                    return Err(CopyError::Grammar);
                }
                self.stack.push(Frame::Recipient(Entries::new()));
                self.charge(RECIPIENT_CHARGE);
            }
            Marker::EndToRecip => {
                let Some(Frame::Recipient(props)) = self.stack.pop() else {
                    return Err(CopyError::Grammar);
                };
                let recipient = PropBag::from_entries(props);
                if let Some(draft) = self.draft() {
                    draft.recipients.push(recipient);
                } else if self.at_root(CopyRoot::MessageContent) {
                    self.emit(items, CopyItem::Recipient(recipient));
                } else {
                    return Err(CopyError::Grammar);
                }
            }
            Marker::NewAttach => {
                if let Some(draft) = self.draft() {
                    if draft.attachments.len() >= MAX_ATTACHMENTS {
                        return Err(CopyError::Attachments);
                    }
                } else if !self.at_root(CopyRoot::MessageContent) {
                    return Err(CopyError::Grammar);
                }
                self.stack.push(Frame::Attachment {
                    props: Entries::new(),
                    data: AttachData::None,
                });
                self.charge(ATTACHMENT_CHARGE);
            }
            Marker::EndAttach => {
                let Some(Frame::Attachment { props, data }) = self.stack.pop() else {
                    return Err(CopyError::Grammar);
                };
                let attachment = Attachment {
                    props: PropBag::from_entries(props),
                    data,
                };
                if let Some(draft) = self.draft() {
                    draft.attachments.push(attachment);
                } else if self.at_root(CopyRoot::MessageContent) {
                    self.emit(items, CopyItem::Attachment(attachment));
                } else {
                    return Err(CopyError::Grammar);
                }
            }
            Marker::StartEmbed
                if matches!(
                    self.stack.last(),
                    Some(Frame::Attachment {
                        data: AttachData::None,
                        ..
                    })
                ) || (self.at_root(CopyRoot::AttachmentContent) && !self.closed) =>
            {
                self.stack.push(Frame::Embedded(Draft::default()));
                self.charge(CONTENT_CHARGE);
            }
            Marker::EndEmbed => {
                let Some(Frame::Embedded(draft)) = self.stack.pop() else {
                    return Err(CopyError::Grammar);
                };
                match self.stack.last_mut() {
                    Some(Frame::Attachment { data, .. }) => {
                        *data = AttachData::Embedded(Box::new(draft.finish()));
                    }
                    Some(Frame::Root) => {
                        self.closed = true;
                        self.emit(items, CopyItem::Embedded(draft.finish()));
                    }
                    _ => return Err(CopyError::Grammar),
                }
            }
            _ => return Err(CopyError::Grammar),
        }
        Ok(())
    }

    fn draft(&mut self) -> Option<&mut Draft> {
        match self.stack.last_mut() {
            Some(Frame::Message(draft, _) | Frame::Embedded(draft)) => Some(draft),
            _ => None,
        }
    }

    fn charge(&mut self, size: usize) {
        self.built = self.built.saturating_add(size);
    }

    fn set(
        &mut self,
        key: PropKey,
        value: OwnedPropValue,
        items: &mut Vec<CopyItem>,
    ) -> Result<(), CopyError> {
        let tag = match key.as_ref() {
            PropKeyRef::Tag(id) => Some(id),
            PropKeyRef::Lid { .. } | PropKeyRef::Name { .. } => None,
        };
        match tag.and_then(MetaTag::of) {
            Some(MetaTag::DelProp) => {
                if self.at_root(CopyRoot::MessageContent)
                    && let OwnedPropValue::I32(target) = value
                    && let Some(children) = Children::of(target)
                {
                    self.emit(items, CopyItem::DeleteChildren(children));
                }
                return Ok(());
            }
            Some(MetaTag::Skipped) => return Ok(()),
            Some(MetaTag::PublicFolder) => return Err(CopyError::PublicFolder),
            Some(MetaTag::Rejected) => return Err(CopyError::Grammar),
            None => {}
        }
        let size = ENTRY_CHARGE
            .saturating_add(key.heap_size())
            .saturating_add(value.heap_size());
        match self.stack.last_mut().ok_or(CopyError::Grammar)? {
            Frame::Root => {
                if self.closed {
                    return Err(CopyError::Grammar);
                }
                if self.root == CopyRoot::AttachmentContent && tag == Some(tags::ATTACH_NUMBER.id())
                {
                    return Ok(());
                }
                items.push(CopyItem::Prop(key, value));
                return Ok(());
            }
            Frame::Folder(Some(props)) => props.push((key, value)),
            Frame::Folder(None) => return Err(CopyError::Grammar),
            Frame::Message(draft, kind) => {
                if tag == Some(tags::ASSOCIATED.id()) && matches!(value, OwnedPropValue::Bool(true))
                {
                    *kind = MessageKind::Associated;
                    return Ok(());
                }
                draft.props.push((key, value));
            }
            Frame::Embedded(draft) => draft.props.push((key, value)),
            Frame::Recipient(props) => props.push((key, value)),
            Frame::Attachment { props, data } => match (tag, value) {
                (Some(id), _) if id == tags::ATTACH_NUMBER.id() => return Ok(()),
                (Some(id), OwnedPropValue::Binary(bytes))
                    if id == tags::ATTACH_DATA_BINARY.id() && matches!(data, AttachData::None) =>
                {
                    *data = AttachData::Bytes(bytes);
                }
                (_, value) => props.push((key, value)),
            },
        }
        self.charge(size);
        Ok(())
    }
}

impl Children {
    fn of(tag: i32) -> Option<Self> {
        let tag = PropTag(tag.cast_unsigned());
        if tag == MESSAGE_RECIPIENTS {
            Some(Children::Recipients)
        } else if tag == MESSAGE_ATTACHMENTS {
            Some(Children::Attachments)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetaTag {
    DelProp,
    Skipped,
    PublicFolder,
    Rejected,
}

impl MetaTag {
    fn of(id: PropId) -> Option<Self> {
        if id == meta::FX_DEL_PROP.id() {
            Some(MetaTag::DelProp)
        } else if id == meta::EC_WARNING.id() || id == meta::DN_PREFIX.id() {
            Some(MetaTag::Skipped)
        } else if id == meta::NEW_FX_FOLDER.id() {
            Some(MetaTag::PublicFolder)
        } else if id == meta::INCR_SYNC_GROUP_ID.id()
            || id == meta::INCREMENTAL_SYNC_MESSAGE_PARTIAL.id()
            || id == meta::IDSET_GIVEN.id()
        {
            Some(MetaTag::Rejected)
        } else {
            None
        }
    }
}

fn owned_value(ptype: PropType, bytes: Vec<u8>) -> Option<OwnedPropValue> {
    match ptype {
        PropType::Binary => Some(OwnedPropValue::Binary(Bytes::from(bytes))),
        _ => unterminated_value(ptype, &bytes).map(|value| value.to_owned_value()),
    }
}

fn reserve(len: u32, max: usize) -> usize {
    usize::try_from(len).unwrap_or(max).min(max)
}

macro_rules! collect_mv {
    ($elements:expr, $single:ident, $multi:ident) => {
        OwnedPropValue::$multi(
            $elements
                .into_iter()
                .map(|value| match value {
                    OwnedPropValue::$single(item) => Some(item),
                    _ => None,
                })
                .collect::<Option<_>>()?,
        )
    };
}

fn mv_value(mv_type: MvType, elements: Vec<OwnedPropValue>) -> Option<OwnedPropValue> {
    Some(match mv_type {
        MvType::I16 => collect_mv!(elements, I16, MvI16),
        MvType::I32 => collect_mv!(elements, I32, MvI32),
        MvType::F32 => collect_mv!(elements, F32, MvF32),
        MvType::F64 => collect_mv!(elements, F64, MvF64),
        MvType::Currency => collect_mv!(elements, Currency, MvCurrency),
        MvType::AppTime => collect_mv!(elements, AppTime, MvAppTime),
        MvType::I64 => collect_mv!(elements, I64, MvI64),
        MvType::String8 => collect_mv!(elements, String8, MvString8),
        MvType::Unicode => collect_mv!(elements, Unicode, MvUnicode),
        MvType::Time => collect_mv!(elements, Time, MvTime),
        MvType::Guid => collect_mv!(elements, Guid, MvGuid),
        MvType::Binary => collect_mv!(elements, Binary, MvBinary),
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/ics/fx/copy/tests.rs"]
mod tests;
