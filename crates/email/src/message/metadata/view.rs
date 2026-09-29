/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedAddressEntry, ArchivedAddressField, ArchivedContentTypeEntry, ArchivedEnvelope,
    ArchivedHeaderEntry, ArchivedMessageEntry, ArchivedMessageMetadata, ArchivedMetadataDate,
    ArchivedParamEntry, ArchivedPartEntry, ArchivedPartInfo, ArchivedSpan, ArchivedStr, BlobHash,
    GROUP_BIT, HeaderId, NONE, PartEntry, PartFlags, PartInfo, PartKind, Str, TransferEncoding,
};
use rkyv::{
    option::ArchivedOption,
    primitive::{ArchivedU16, ArchivedU32},
};
use std::{borrow::Cow, iter::from_fn, ops::Range};

const fn le(value: u32) -> ArchivedU32 {
    ArchivedU32::from_native(value)
}

const fn le16(value: u16) -> ArchivedU16 {
    ArchivedU16::from_native(value)
}

const EMPTY_SPAN: ArchivedSpan = ArchivedSpan {
    start: le(0),
    len: le16(0),
};

const ABSENT_SPAN: ArchivedSpan = ArchivedSpan {
    start: le(NONE),
    len: le16(0),
};

const ABSENT_STR: ArchivedStr = ArchivedStr {
    start: le(0),
    len: le16(Str::ABSENT_LEN),
};

const EMPTY_ADDRESSES: ArchivedAddressField = ArchivedAddressField {
    entries: EMPTY_SPAN,
    last: le(0),
};

const NO_CONTENT_TYPE: ArchivedContentTypeEntry = ArchivedContentTypeEntry {
    ctype: ABSENT_STR,
    subtype: ABSENT_STR,
    params: EMPTY_SPAN,
};

static EMPTY_MESSAGE: ArchivedMessageEntry = ArchivedMessageEntry {
    parts: EMPTY_SPAN,
    container: le(NONE),
    source: le(NONE),
    text_body: EMPTY_SPAN,
    html_body: EMPTY_SPAN,
    attachments: EMPTY_SPAN,
    envelope: ArchivedEnvelope {
        date: ArchivedOption::None,
        date_raw: ABSENT_STR,
        subject: ABSENT_STR,
        from: EMPTY_ADDRESSES,
        sender: EMPTY_ADDRESSES,
        reply_to: EMPTY_ADDRESSES,
        to: EMPTY_ADDRESSES,
        cc: EMPTY_ADDRESSES,
        bcc: EMPTY_ADDRESSES,
        in_reply_to: ABSENT_SPAN,
        message_id: ABSENT_SPAN,
    },
};

static EMPTY_PART: ArchivedPartEntry = ArchivedPartEntry {
    offset_header: le(0),
    offset_body: le(0),
    offset_end: le(0),
    message: le(0),
    headers: EMPTY_SPAN,
    children: EMPTY_SPAN,
    decoded_size: le(0),
    lines: le(0),
    content_type: NO_CONTENT_TYPE,
    content_disposition: NO_CONTENT_TYPE,
    content_id: ABSENT_STR,
    content_description: ABSENT_STR,
    content_transfer_encoding: ABSENT_STR,
    content_location: ABSENT_STR,
    content_md5: ABSENT_STR,
    content_language: ABSENT_SPAN,
    info: ArchivedPartInfo(le16(PartEntry::EMPTY.info.0)),
};

impl ArchivedSpan {
    #[inline]
    pub fn range(&self) -> Range<usize> {
        let start = self.start.to_native() as usize;
        start..start.saturating_add(self.len.to_native() as usize)
    }

    #[inline]
    pub fn is_absent(&self) -> bool {
        self.start.to_native() == NONE
    }

    #[inline]
    fn slice<'a, T>(&self, items: &'a [T]) -> &'a [T] {
        items.get(self.range()).unwrap_or_default()
    }
}

impl ArchivedStr {
    #[inline]
    pub fn range(&self) -> Option<Range<usize>> {
        let len = self.len.to_native();
        (len != Str::ABSENT_LEN).then(|| {
            let start = self.start.to_native() as usize;
            start..start + len as usize
        })
    }

    #[inline]
    pub fn get<'a>(&self, pool: &'a str) -> Option<&'a str> {
        pool.get(self.range()?)
    }

    #[inline]
    pub fn bracketed<'a>(&self, pool: &'a str) -> Option<&'a str> {
        let range = self.range()?;
        pool.get(range.start.checked_sub(1)?..range.end + 1)
            .filter(|text| text.starts_with('<') && text.ends_with('>'))
    }
}

impl ArchivedPartInfo {
    #[inline]
    pub fn native(&self) -> PartInfo {
        PartInfo(self.0.to_native())
    }
}

impl TransferEncoding {
    pub fn as_u8(self) -> u8 {
        match self {
            TransferEncoding::None => 0,
            TransferEncoding::QuotedPrintable => 1,
            TransferEncoding::Base64 => 2,
        }
    }
}

impl From<TransferEncoding> for mail_parser::Encoding {
    fn from(value: TransferEncoding) -> Self {
        match value {
            TransferEncoding::None => mail_parser::Encoding::None,
            TransferEncoding::QuotedPrintable => mail_parser::Encoding::QuotedPrintable,
            TransferEncoding::Base64 => mail_parser::Encoding::Base64,
        }
    }
}

#[derive(Clone, Copy)]
pub struct MessageView<'a> {
    meta: &'a ArchivedMessageMetadata,
    id: u32,
    entry: &'a ArchivedMessageEntry,
}

#[derive(Clone, Copy)]
pub struct PartView<'a> {
    meta: &'a ArchivedMessageMetadata,
    id: u32,
    entry: &'a ArchivedPartEntry,
}

#[derive(Clone, Copy)]
pub struct EnvelopeView<'a> {
    meta: &'a ArchivedMessageMetadata,
    entry: &'a ArchivedEnvelope,
}

#[derive(Clone, Copy)]
pub struct Addresses<'a> {
    pool: &'a str,
    entries: &'a [ArchivedAddressEntry],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mailbox<'a> {
    pub name: Option<&'a str>,
    pub address: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub struct Group<'a> {
    pub name: Option<&'a str>,
    pub members: Addresses<'a>,
}

#[derive(Clone, Copy)]
pub enum AddressItem<'a> {
    Mailbox(Mailbox<'a>),
    Group(Group<'a>),
}

#[derive(Clone, Copy)]
pub struct TextItems<'a> {
    pool: &'a str,
    items: &'a [ArchivedStr],
    present: bool,
}

#[derive(Clone, Copy)]
pub struct ContentTypeView<'a> {
    pool: &'a str,
    entry: &'a ArchivedContentTypeEntry,
    params: &'a [ArchivedParamEntry],
}

#[derive(Clone, Copy)]
pub struct HeaderList<'a> {
    entries: &'a [ArchivedHeaderEntry],
}

#[derive(Clone, Copy)]
pub struct HeaderView<'a> {
    entry: &'a ArchivedHeaderEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressHeader {
    From,
    Sender,
    ReplyTo,
    To,
    Cc,
    Bcc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyList {
    Text,
    Html,
    Attachments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occurrence {
    Last,
    All,
}

#[derive(Debug, Clone, Default)]
pub struct HeaderMatcher {
    known: [u64; 4],
    other: Vec<Box<[u8]>>,
}

impl ArchivedMessageMetadata {
    #[inline]
    pub fn pool(&self) -> &str {
        self.strings.as_str()
    }

    pub fn root(&self) -> MessageView<'_> {
        self.message(0).unwrap_or(MessageView {
            meta: self,
            id: 0,
            entry: &EMPTY_MESSAGE,
        })
    }

    #[inline]
    pub fn message(&self, id: u32) -> Option<MessageView<'_>> {
        self.messages.get(id as usize).map(|entry| MessageView {
            meta: self,
            id,
            entry,
        })
    }

    #[inline]
    pub fn part(&self, id: u32) -> Option<PartView<'_>> {
        self.parts.get(id as usize).map(|entry| PartView {
            meta: self,
            id,
            entry,
        })
    }

    #[inline]
    fn part_or_empty(&self, id: u32) -> PartView<'_> {
        PartView {
            meta: self,
            id,
            entry: self.parts.get(id as usize).unwrap_or(&EMPTY_PART),
        }
    }

    pub fn parts(&self) -> impl ExactSizeIterator<Item = PartView<'_>> {
        self.parts.iter().enumerate().map(|(id, entry)| PartView {
            meta: self,
            id: id as u32,
            entry,
        })
    }

    pub fn messages(&self) -> impl ExactSizeIterator<Item = MessageView<'_>> {
        self.messages
            .iter()
            .enumerate()
            .map(|(id, entry)| MessageView {
                meta: self,
                id: id as u32,
                entry,
            })
    }

    pub fn preview(&self) -> &str {
        self.preview.get(self.pool()).unwrap_or_default()
    }

    pub fn stored_preview(&self) -> Option<&str> {
        self.preview.get(self.pool())
    }

    pub fn blob_hash(&self) -> BlobHash {
        BlobHash::from(&self.blob_hash)
    }

    pub fn blob_body_offset(&self) -> usize {
        self.blob_body_offset.to_native() as usize
    }

    pub fn headers_len(&self) -> usize {
        self.parts
            .first()
            .map_or(0, |part| part.offset_body.to_native() as usize)
    }

    pub fn size(&self) -> usize {
        self.parts.first().map_or(0, |part| {
            part.offset_end
                .to_native()
                .saturating_sub(part.offset_header.to_native()) as usize
        })
    }

    pub fn blob_range(&self, range: Range<usize>) -> Option<Range<usize>> {
        let root_body = self.headers_len();
        let base = self.blob_body_offset();
        let start = range.start.checked_add(base)?.checked_sub(root_body)?;
        let end = range.end.checked_add(base)?.checked_sub(root_body)?;
        Some(start..end)
    }

    fn ids(&self, span: &ArchivedSpan) -> impl ExactSizeIterator<Item = PartView<'_>> {
        span.slice(&self.ids)
            .iter()
            .map(move |id| self.part_or_empty(id.to_native()))
    }
}

impl<'a> MessageView<'a> {
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[inline]
    pub fn metadata(&self) -> &'a ArchivedMessageMetadata {
        self.meta
    }

    pub fn root_part(&self) -> PartView<'a> {
        self.meta.part_or_empty(self.entry.parts.start.to_native())
    }

    pub fn parts(&self) -> impl ExactSizeIterator<Item = PartView<'a>> + use<'a> {
        let meta = self.meta;
        let range = self.entry.parts.range();
        let start = range.start as u32;
        let entries = meta.parts.get(range).unwrap_or_default();
        entries
            .iter()
            .enumerate()
            .map(move |(index, entry)| PartView {
                meta,
                id: start + index as u32,
                entry,
            })
    }

    pub fn part_ids(&self) -> Range<u32> {
        let range = self.entry.parts.range();
        range.start as u32..range.end as u32
    }

    pub fn text_body(&self) -> impl ExactSizeIterator<Item = PartView<'a>> + use<'a> {
        self.meta.ids(&self.entry.text_body)
    }

    pub fn html_body(&self) -> impl ExactSizeIterator<Item = PartView<'a>> + use<'a> {
        self.meta.ids(&self.entry.html_body)
    }

    pub fn attachments(&self) -> impl ExactSizeIterator<Item = PartView<'a>> + use<'a> {
        self.meta.ids(&self.entry.attachments)
    }

    pub fn body_list(
        &self,
        list: BodyList,
    ) -> impl ExactSizeIterator<Item = PartView<'a>> + use<'a> {
        self.meta.ids(match list {
            BodyList::Text => &self.entry.text_body,
            BodyList::Html => &self.entry.html_body,
            BodyList::Attachments => &self.entry.attachments,
        })
    }

    pub fn container(&self) -> Option<PartView<'a>> {
        self.meta.part(self.entry.container.to_native())
    }

    pub fn source_part(&self) -> Option<PartView<'a>> {
        let source = self.entry.source.to_native();
        (source != NONE).then(|| self.meta.part(source)).flatten()
    }

    pub fn is_raw_source(&self) -> bool {
        self.entry.source.to_native() == NONE
    }

    #[inline]
    pub fn envelope(&self) -> EnvelopeView<'a> {
        EnvelopeView {
            meta: self.meta,
            entry: &self.entry.envelope,
        }
    }
}

impl<'a> EnvelopeView<'a> {
    pub fn date(&self) -> Option<&'a ArchivedMetadataDate> {
        self.entry.date.as_ref()
    }

    pub fn datetime(&self) -> Option<mail_parser::DateTime> {
        self.date().map(mail_parser::DateTime::from)
    }

    pub fn date_raw(&self) -> Option<&'a str> {
        self.entry.date_raw.get(self.meta.pool())
    }

    pub fn subject(&self) -> Option<&'a str> {
        self.entry.subject.get(self.meta.pool())
    }

    pub fn addresses(&self, header: AddressHeader, occurrence: Occurrence) -> Addresses<'a> {
        let field = match header {
            AddressHeader::From => &self.entry.from,
            AddressHeader::Sender => &self.entry.sender,
            AddressHeader::ReplyTo => &self.entry.reply_to,
            AddressHeader::To => &self.entry.to,
            AddressHeader::Cc => &self.entry.cc,
            AddressHeader::Bcc => &self.entry.bcc,
        };
        let entries = field.entries.slice(&self.meta.addresses);
        let entries = match occurrence {
            Occurrence::All => entries,
            Occurrence::Last => entries
                .get(field.last.to_native() as usize..)
                .unwrap_or_default(),
        };
        Addresses {
            pool: self.meta.pool(),
            entries,
        }
    }

    pub fn in_reply_to(&self) -> TextItems<'a> {
        TextItems::new(self.meta, &self.entry.in_reply_to)
    }

    pub fn message_id(&self) -> TextItems<'a> {
        TextItems::new(self.meta, &self.entry.message_id)
    }
}

impl<'a> Addresses<'a> {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    fn mailbox(&self, entry: &'a ArchivedAddressEntry) -> Mailbox<'a> {
        Mailbox {
            name: entry.name.get(self.pool),
            address: entry.address.get(self.pool),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = AddressItem<'a>> + use<'a> {
        let pool = self.pool;
        let mut rest = self.entries;
        from_fn(move || {
            let (first, tail) = rest.split_first()?;
            let group = first.group.to_native();
            if group & GROUP_BIT != 0 {
                let members = ((group & !GROUP_BIT) as usize).min(tail.len());
                let (members, tail) = tail.split_at(members);
                rest = tail;
                Some(AddressItem::Group(Group {
                    name: first.name.get(pool),
                    members: Addresses {
                        pool,
                        entries: members,
                    },
                }))
            } else {
                rest = tail;
                Some(AddressItem::Mailbox(Mailbox {
                    name: first.name.get(pool),
                    address: first.address.get(pool),
                }))
            }
        })
    }

    pub fn mailboxes(&self) -> impl DoubleEndedIterator<Item = Mailbox<'a>> + use<'a> {
        let this = *self;
        self.entries
            .iter()
            .filter(|entry| entry.group.to_native() & GROUP_BIT == 0)
            .map(move |entry| this.mailbox(entry))
    }

    pub fn first(&self) -> Option<Mailbox<'a>> {
        self.mailboxes().next()
    }

    pub fn has_groups(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.group.to_native() & GROUP_BIT != 0)
    }

    pub fn groups(&self) -> impl Iterator<Item = (Option<&'a str>, Addresses<'a>)> + use<'a> {
        let pool = self.pool;
        let mut rest = self.entries;
        from_fn(move || {
            let (first, tail) = rest.split_first()?;
            let group = first.group.to_native();
            let (name, run, tail) = if group & GROUP_BIT != 0 {
                let members = ((group & !GROUP_BIT) as usize).min(tail.len());
                let (members, tail) = tail.split_at(members);
                (first.name.get(pool), members, tail)
            } else {
                let len = rest
                    .iter()
                    .take_while(|entry| entry.group.to_native() & GROUP_BIT == 0)
                    .count();
                let (run, tail) = rest.split_at(len);
                (None, run, tail)
            };
            rest = tail;
            Some((name, Addresses { pool, entries: run }))
        })
    }

    pub fn has_imap_address(&self) -> bool {
        self.entries.iter().any(|entry| {
            entry.group.to_native() & GROUP_BIT != 0 || entry.address.range().is_some()
        })
    }
}

impl<'a> TextItems<'a> {
    fn new(meta: &'a ArchivedMessageMetadata, span: &ArchivedSpan) -> Self {
        TextItems {
            pool: meta.pool(),
            items: span.slice(&meta.texts),
            present: !span.is_absent(),
        }
    }

    #[inline]
    pub fn is_present(&self) -> bool {
        self.present
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &'a str> + DoubleEndedIterator + use<'a> {
        let pool = self.pool;
        self.items
            .iter()
            .map(move |item| item.get(pool).unwrap_or_default())
    }

    pub fn last(&self) -> Option<&'a str> {
        self.items.last()?.get(self.pool)
    }

    pub fn last_bracketed(&self) -> Option<&'a str> {
        self.items.last()?.bracketed(self.pool)
    }

    pub fn joined_bracketed(&self) -> Option<&'a str> {
        let first = self.items.first()?.range()?;
        let last = self.items.last()?.range()?;
        self.pool
            .get(first.start.checked_sub(1)?..last.end + 1)
            .filter(|text| text.starts_with('<') && text.ends_with('>'))
    }
}

impl<'a> ContentTypeView<'a> {
    pub fn ctype(&self) -> &'a str {
        self.entry.ctype.get(self.pool).unwrap_or_default()
    }

    pub fn subtype(&self) -> Option<&'a str> {
        self.entry.subtype.get(self.pool)
    }

    pub fn mime_type(&self) -> Cow<'a, str> {
        let Some(ctype) = self.entry.ctype.range() else {
            return Cow::Borrowed("");
        };
        match self.entry.subtype.range() {
            None => Cow::Borrowed(self.pool.get(ctype).unwrap_or_default()),
            Some(subtype) if subtype.start == ctype.end + 1 => self
                .pool
                .get(ctype.start..subtype.end)
                .map(Cow::Borrowed)
                .unwrap_or_default(),
            Some(subtype) => Cow::Owned(format!(
                "{}/{}",
                self.pool.get(ctype).unwrap_or_default(),
                self.pool.get(subtype).unwrap_or_default()
            )),
        }
    }

    pub fn attributes(
        &self,
    ) -> impl ExactSizeIterator<Item = (&'a str, &'a str)> + DoubleEndedIterator + use<'a> {
        let pool = self.pool;
        self.params.iter().map(move |param| {
            (
                param.name.get(pool).unwrap_or_default(),
                param.value.get(pool).unwrap_or_default(),
            )
        })
    }

    pub fn has_attributes(&self) -> bool {
        !self.params.is_empty()
    }

    pub fn attribute(&self, name: &str) -> Option<&'a str> {
        self.attributes()
            .find(|(param, _)| *param == name)
            .map(|(_, value)| value)
    }

    pub fn is_inline(&self) -> bool {
        self.ctype().eq_ignore_ascii_case("inline")
    }

    pub fn is_attachment(&self) -> bool {
        self.ctype().eq_ignore_ascii_case("attachment")
    }
}

impl<'a> PartView<'a> {
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[inline]
    pub fn metadata(&self) -> &'a ArchivedMessageMetadata {
        self.meta
    }

    #[inline]
    pub fn kind(&self) -> PartKind {
        self.entry.info.native().kind()
    }

    #[inline]
    pub fn is_multipart(&self) -> bool {
        self.kind() == PartKind::Multipart
    }

    #[inline]
    pub fn is_message(&self) -> bool {
        self.kind() == PartKind::Message
    }

    #[inline]
    pub fn is_text(&self) -> bool {
        matches!(self.kind(), PartKind::Text | PartKind::Html)
    }

    #[inline]
    pub fn encoding(&self) -> TransferEncoding {
        self.entry.info.native().encoding()
    }

    #[inline]
    pub fn flags(&self) -> PartFlags {
        self.entry.info.native().flags()
    }

    pub fn message(&self) -> MessageView<'a> {
        self.meta
            .message(self.entry.message.to_native())
            .unwrap_or(MessageView {
                meta: self.meta,
                id: NONE,
                entry: &EMPTY_MESSAGE,
            })
    }

    pub fn is_message_root(&self) -> bool {
        self.meta
            .messages
            .get(self.entry.message.to_native() as usize)
            .is_some_and(|message| message.parts.start.to_native() == self.id)
    }

    pub fn children(&self) -> impl ExactSizeIterator<Item = PartView<'a>> + use<'a> {
        let span = if self.is_multipart() {
            &self.entry.children
        } else {
            &EMPTY_SPAN
        };
        self.meta.ids(span)
    }

    pub fn child(&self, index: usize) -> Option<PartView<'a>> {
        if self.is_multipart() {
            self.entry
                .children
                .slice(&self.meta.ids)
                .get(index)
                .and_then(|id| self.meta.part(id.to_native()))
        } else {
            None
        }
    }

    pub fn nested(&self) -> Option<MessageView<'a>> {
        if self.is_message() {
            self.meta.message(self.entry.children.start.to_native())
        } else {
            None
        }
    }

    pub fn headers(&self) -> HeaderList<'a> {
        HeaderList {
            entries: self.entry.headers.slice(&self.meta.headers),
        }
    }

    fn content(&self, entry: &'a ArchivedContentTypeEntry) -> Option<ContentTypeView<'a>> {
        entry.ctype.range().map(|_| ContentTypeView {
            pool: self.meta.pool(),
            entry,
            params: entry.params.slice(&self.meta.params),
        })
    }

    pub fn content_type(&self) -> Option<ContentTypeView<'a>> {
        self.content(&self.entry.content_type)
    }

    pub fn content_disposition(&self) -> Option<ContentTypeView<'a>> {
        self.content(&self.entry.content_disposition)
    }

    pub fn content_id(&self) -> Option<&'a str> {
        self.entry.content_id.get(self.meta.pool())
    }

    pub fn content_id_bracketed(&self) -> Option<&'a str> {
        self.entry.content_id.bracketed(self.meta.pool())
    }

    pub fn content_description(&self) -> Option<&'a str> {
        self.entry.content_description.get(self.meta.pool())
    }

    pub fn content_transfer_encoding(&self) -> Option<&'a str> {
        self.entry.content_transfer_encoding.get(self.meta.pool())
    }

    pub fn content_language(&self) -> TextItems<'a> {
        TextItems::new(self.meta, &self.entry.content_language)
    }

    pub fn content_location(&self) -> Option<&'a str> {
        self.entry.content_location.get(self.meta.pool())
    }

    pub fn content_md5(&self) -> Option<&'a str> {
        self.entry.content_md5.get(self.meta.pool())
    }

    pub fn charset(&self) -> Option<&'a str> {
        self.content_type()?.attribute("charset")
    }

    pub fn attachment_name(&self) -> Option<&'a str> {
        self.content_disposition()
            .and_then(|disposition| disposition.attribute("filename"))
            .or_else(|| self.content_type()?.attribute("name"))
    }

    #[inline]
    pub fn decoded_size(&self) -> u32 {
        self.entry.decoded_size.to_native()
    }

    #[inline]
    pub fn lines(&self) -> u32 {
        self.entry.lines.to_native()
    }

    #[inline]
    pub fn offset_header(&self) -> usize {
        self.entry.offset_header.to_native() as usize
    }

    #[inline]
    pub fn offset_body(&self) -> usize {
        self.entry.offset_body.to_native() as usize
    }

    #[inline]
    pub fn offset_end(&self) -> usize {
        self.entry.offset_end.to_native() as usize
    }

    #[inline]
    pub fn header_range(&self) -> Range<usize> {
        self.offset_header()..self.offset_body().max(self.offset_header())
    }

    #[inline]
    pub fn body_range(&self) -> Range<usize> {
        self.offset_body()..self.offset_end().max(self.offset_body())
    }

    #[inline]
    pub fn raw_range(&self) -> Range<usize> {
        self.offset_header()..self.offset_end().max(self.offset_header())
    }
}

impl<'a> HeaderList<'a> {
    #[inline]
    pub(super) fn new(entries: &'a [ArchivedHeaderEntry]) -> Self {
        HeaderList { entries }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(
        &self,
    ) -> impl ExactSizeIterator<Item = HeaderView<'a>> + DoubleEndedIterator + use<'a> {
        self.entries.iter().map(|entry| HeaderView { entry })
    }

    pub fn last(&self, id: HeaderId) -> Option<HeaderView<'a>> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.name.0 == id.0)
            .map(|entry| HeaderView { entry })
    }

    pub fn last_named(&self, name: &str, source: &[u8]) -> Option<HeaderView<'a>> {
        let id = HeaderId::parse(name.as_bytes());
        self.iter().rev().find(|header| {
            if id.is_known() {
                header.id() == id
            } else {
                header.id() == HeaderId::OTHER
                    && header
                        .raw_name(source)
                        .eq_ignore_ascii_case(name.as_bytes())
            }
        })
    }

    pub fn last_parsed<'s>(
        &self,
        id: HeaderId,
        source: &'s [u8],
        form: mail_parser::HeaderForm,
    ) -> Option<mail_parser::ParsedValue<'s>> {
        self.last(id)?.raw_value(source).map(|raw| form.parse(raw))
    }

    pub fn all(&self, id: HeaderId) -> impl DoubleEndedIterator<Item = HeaderView<'a>> + use<'a> {
        self.entries
            .iter()
            .filter(move |entry| entry.name.0 == id.0)
            .map(|entry| HeaderView { entry })
    }
}

impl<'a> HeaderView<'a> {
    #[inline]
    pub(super) fn new(entry: &'a ArchivedHeaderEntry) -> Self {
        HeaderView { entry }
    }

    #[inline]
    pub fn id(&self) -> HeaderId {
        HeaderId(self.entry.name.0)
    }

    #[inline]
    pub fn field_range(&self) -> Range<usize> {
        let start = self.entry.offset_field.to_native() as usize;
        start..(self.entry.offset_end.to_native() as usize).max(start)
    }

    #[inline]
    pub fn value_range(&self) -> Range<usize> {
        let start = self.entry.offset_value.to_native() as usize;
        start..(self.entry.offset_end.to_native() as usize).max(start)
    }

    pub fn raw_name<'r>(&self, source: &'r [u8]) -> &'r [u8] {
        let start = self.entry.offset_field.to_native() as usize;
        let end = (self.entry.offset_value.to_native() as usize).saturating_sub(1);
        source
            .get(start..end.max(start))
            .unwrap_or_default()
            .trim_ascii_end()
    }

    pub fn raw_value<'r>(&self, source: &'r [u8]) -> Option<&'r [u8]> {
        source.get(self.value_range())
    }

    pub fn raw_name_in<'f>(&self, field: &'f [u8]) -> &'f [u8] {
        let name_len = self
            .value_range()
            .start
            .saturating_sub(self.field_range().start)
            .saturating_sub(1);
        field.get(..name_len).unwrap_or_default().trim_ascii_end()
    }

    pub fn raw_value_in<'f>(&self, field: &'f [u8]) -> &'f [u8] {
        let offset = self
            .value_range()
            .start
            .saturating_sub(self.field_range().start);
        field.get(offset..).unwrap_or_default()
    }
}

impl HeaderMatcher {
    pub fn new<'x>(names: impl IntoIterator<Item = &'x str>) -> Self {
        let mut matcher = HeaderMatcher::default();
        for name in names {
            matcher.add_name(name);
        }
        matcher
    }

    pub fn add_name(&mut self, name: &str) {
        let id = HeaderId::parse(name.as_bytes());
        if id.is_known() {
            self.add_id(id);
        } else {
            self.other
                .push(name.as_bytes().to_ascii_lowercase().into_boxed_slice());
        }
    }

    pub fn add_id(&mut self, id: HeaderId) {
        let (word, bit) = id.bit();
        if let Some(slot) = self.known.get_mut(word) {
            *slot |= bit;
        }
    }

    #[inline]
    pub fn matches_id(&self, id: HeaderId) -> bool {
        let (word, bit) = id.bit();
        self.known.get(word).is_some_and(|slot| slot & bit != 0)
    }

    #[inline]
    pub fn matches(&self, header: HeaderView<'_>, source: &[u8]) -> bool {
        let id = header.id();
        if id.is_known() {
            self.matches_id(id)
        } else {
            !self.other.is_empty() && self.matches_other(header.raw_name(source))
        }
    }

    #[inline]
    pub fn matches_other(&self, name: &[u8]) -> bool {
        self.other
            .iter()
            .any(|other| other.eq_ignore_ascii_case(name))
    }

    #[inline]
    pub fn matches_field(&self, header: HeaderView<'_>, field: &[u8]) -> bool {
        let id = header.id();
        if id.is_known() {
            self.matches_id(id)
        } else {
            self.matches_other(header.raw_name_in(field))
        }
    }
}
