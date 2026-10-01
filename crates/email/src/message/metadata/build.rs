/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AddressEntry, AddressField, ArchivedAddressEntry, ArchivedHeaderEntry, ArchivedMessageEntry,
    ArchivedMessageMetadata, ArchivedParamEntry, ArchivedPartEntry, ArchivedStr, ContentTypeEntry,
    Envelope, GROUP_BIT, HeaderEntry, HeaderId, MAX_ADDRESS_ENTRIES, MAX_FIELD_ADDRESSES,
    MAX_HEADER_ENTRIES, MAX_PARAMS, MAX_PART_ENTRIES, MAX_PROTECTED_VALUE_LEN, MAX_TEXT_ITEMS,
    MAX_VALUE_LEN, MessageEntry, MessageMetadata, MetadataDate, NONE, ParamEntry, PartEntry,
    PartFlags, PartInfo, PartKind, Span, Str, TransferEncoding,
};
use crate::message::index::PREVIEW_LENGTH;
use mail_parser::{
    Address, AddressList, ContentType, Encoding, Header, HeaderName, HeaderValue, Message,
    MessagePart, PartKind as ParsedKind, Source,
};
use std::mem::{size_of, take};
use store::{U32_LEN, write::compress::MAX_ARCHIVE_SIZE};
use types::blob_hash::BlobHash;

pub const MAX_POOL_LEN: usize = 4 * 1024 * 1024;

const CONTENT_TYPE_PROTECTED: &[&str] = &["charset", "name"];
const CONTENT_DISPOSITION_PROTECTED: &[&str] = &["filename"];
const PART_PROTECTED_PARAMS: usize =
    CONTENT_TYPE_PROTECTED.len() + CONTENT_DISPOSITION_PROTECTED.len();
const PART_PROTECTED_VALUES: usize = 2 * 2 + 2 * PART_PROTECTED_PARAMS;
const PART_POOL_OVERFLOW: usize = PART_PROTECTED_VALUES * MAX_PROTECTED_VALUE_LEN + 2;
const PART_IDS: usize = 4;
const MAX_STRUCTURE_LEN: usize = size_of::<ArchivedMessageMetadata>()
    + MAX_PART_ENTRIES
        * (size_of::<ArchivedPartEntry>()
            + size_of::<ArchivedMessageEntry>()
            + PART_IDS * U32_LEN
            + PART_PROTECTED_PARAMS * size_of::<ArchivedParamEntry>()
            + PART_POOL_OVERFLOW)
    + MAX_HEADER_ENTRIES * size_of::<ArchivedHeaderEntry>()
    + MAX_ADDRESS_ENTRIES * size_of::<ArchivedAddressEntry>()
    + MAX_TEXT_ITEMS * size_of::<ArchivedStr>()
    + MAX_PARAMS * size_of::<ArchivedParamEntry>()
    + MAX_POOL_LEN;

const _: () = {
    assert!(MAX_VALUE_LEN <= Str::MAX_LEN);
    assert!(MAX_PROTECTED_VALUE_LEN <= MAX_VALUE_LEN);
    assert!(MAX_PART_ENTRIES <= Span::MAX_LEN);
    assert!(MAX_HEADER_ENTRIES <= Span::MAX_LEN);
    assert!(MAX_FIELD_ADDRESSES <= Span::MAX_LEN);
    assert!(MAX_FIELD_ADDRESSES < GROUP_BIT as usize);
    assert!(MAX_TEXT_ITEMS <= Span::MAX_LEN);
    assert!(MAX_PARAMS + CONTENT_TYPE_PROTECTED.len() <= Span::MAX_LEN);
    assert!(MAX_PARAMS + CONTENT_DISPOSITION_PROTECTED.len() <= Span::MAX_LEN);
    assert!(MAX_STRUCTURE_LEN < MAX_ARCHIVE_SIZE);
};

#[derive(Debug, Default, Clone)]
pub struct ExtraHeaders {
    bytes: Vec<u8>,
    fields: Vec<HeaderEntry>,
}

pub struct NewMetadata {
    pub metadata: MessageMetadata,
    pub raw_headers: Vec<u8>,
    pub has_attachments: bool,
}

impl ExtraHeaders {
    pub fn push(&mut self, name: HeaderId, value: &str) -> &mut Self {
        let Some(label) = name.as_str() else {
            return self;
        };
        let offset_field = self.bytes.len() as u32;
        self.bytes.extend_from_slice(label.as_bytes());
        self.bytes.push(b':');
        let offset_value = self.bytes.len() as u32;
        self.bytes.push(b' ');
        self.bytes
            .extend(value.bytes().filter(|&byte| !matches!(byte, b'\r' | b'\n')));
        self.bytes.extend_from_slice(b"\r\n");
        self.fields.push(HeaderEntry {
            name,
            offset_field,
            offset_value,
            offset_end: self.bytes.len() as u32,
        });
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Clone, Copy)]
struct Shift(u32);

impl Shift {
    const NONE: Shift = Shift(0);

    #[inline]
    fn apply(self, offset: u32) -> u32 {
        offset.saturating_add(self.0)
    }
}

#[derive(Default, Clone, Copy)]
struct Occurrences<'m> {
    last: Option<Header<'m>>,
    count: u32,
}

impl<'m> Occurrences<'m> {
    #[inline]
    fn record(&mut self, header: Header<'m>) {
        self.last = Some(header);
        self.count += 1;
    }
}

#[derive(Default)]
struct FieldScan<'m> {
    date: Option<Header<'m>>,
    subject: Option<Header<'m>>,
    in_reply_to: Option<Header<'m>>,
    message_id: Option<Header<'m>>,
    addresses: [Occurrences<'m>; 6],
    content_id: Option<Header<'m>>,
    content_description: Option<Header<'m>>,
    content_transfer_encoding: Option<Header<'m>>,
    content_language: Option<Header<'m>>,
    content_location: Option<Header<'m>>,
    content_md5: Option<Header<'m>>,
}

const ADDRESS_FIELDS: [HeaderName<'static>; 6] = [
    HeaderName::From,
    HeaderName::Sender,
    HeaderName::ReplyTo,
    HeaderName::To,
    HeaderName::Cc,
    HeaderName::Bcc,
];

impl<'m> FieldScan<'m> {
    #[inline]
    fn record(&mut self, header: Header<'m>, name: &HeaderName<'_>, envelope: bool) {
        let slot = match name {
            HeaderName::ContentId => &mut self.content_id,
            HeaderName::ContentDescription => &mut self.content_description,
            HeaderName::ContentTransferEncoding => &mut self.content_transfer_encoding,
            HeaderName::ContentLanguage => &mut self.content_language,
            HeaderName::ContentLocation => &mut self.content_location,
            HeaderName::ContentMd5 => &mut self.content_md5,
            HeaderName::Date if envelope => &mut self.date,
            HeaderName::Subject if envelope => &mut self.subject,
            HeaderName::InReplyTo if envelope => &mut self.in_reply_to,
            HeaderName::MessageId if envelope => &mut self.message_id,
            HeaderName::From if envelope => return self.addresses[0].record(header),
            HeaderName::Sender if envelope => return self.addresses[1].record(header),
            HeaderName::ReplyTo if envelope => return self.addresses[2].record(header),
            HeaderName::To if envelope => return self.addresses[3].record(header),
            HeaderName::Cc if envelope => return self.addresses[4].record(header),
            HeaderName::Bcc if envelope => return self.addresses[5].record(header),
            _ => return,
        };
        *slot = Some(header);
    }
}

struct Builder<'m> {
    metadata: MessageMetadata,
    message: &'m Message<'m>,
    remap: Vec<u32>,
    order: Vec<u32>,
    message_ends: Vec<u32>,
    shift: Shift,
}

impl MessageMetadata {
    pub fn build(message: &Message<'_>, extra: &ExtraHeaders, blob_hash: BlobHash) -> NewMetadata {
        let raw = message.raw();
        let root = message.root().root_part();
        let block = raw.get(..root.offset_body() as usize).unwrap_or_default();
        let mut raw_headers = Vec::with_capacity(extra.len() + block.len());
        raw_headers.extend_from_slice(extra.as_bytes());
        raw_headers.extend_from_slice(block);

        let mut builder = Builder::new(message, extra, block.len());
        builder.metadata.blob_hash = blob_hash;
        builder.metadata.blob_body_offset = root.offset_body();
        builder.metadata.preview = message
            .root()
            .body_preview(PREVIEW_LENGTH)
            .as_deref()
            .map_or(Str::NONE, |preview| builder.push_whole(preview));
        builder.number();
        builder.messages();
        builder.parts(extra);

        debug_assert!(
            builder
                .metadata
                .parts
                .first()
                .is_none_or(|part| part.offset_body as usize == raw_headers.len())
        );

        let has_attachments = builder.has_attachments();
        NewMetadata {
            metadata: builder.metadata,
            raw_headers,
            has_attachments,
        }
    }
}

impl<'m> Builder<'m> {
    fn new(message: &'m Message<'m>, extra: &ExtraHeaders, block_len: usize) -> Self {
        let parts_len = message.parts().len().min(MAX_PART_ENTRIES);
        let messages_len = message.messages().len().min(MAX_PART_ENTRIES);
        Builder {
            metadata: MessageMetadata {
                messages: Vec::with_capacity(messages_len),
                parts: Vec::with_capacity(parts_len),
                headers: Vec::new(),
                ids: Vec::with_capacity(parts_len * 2),
                addresses: Vec::with_capacity(8),
                texts: Vec::with_capacity(8),
                params: Vec::with_capacity(parts_len * 2),
                strings: String::with_capacity(
                    (block_len / 8).min(MAX_POOL_LEN) + PREVIEW_LENGTH + 64,
                ),
                ..Default::default()
            },
            message,
            remap: Vec::new(),
            order: Vec::new(),
            message_ends: Vec::new(),
            shift: Shift(extra.len() as u32),
        }
    }

    fn number(&mut self) {
        let messages_len = self.message.messages().len();
        let parts_len = self.message.parts().len();
        let mut cursor = vec![0u32; messages_len + 1];
        let mut headers_len = 0usize;
        for part in self.message.parts() {
            if let Some(count) = cursor.get_mut(part.message().id() as usize + 1) {
                *count += 1;
            }
            headers_len += part.headers().len();
        }
        let mut total = 0u32;
        for slot in cursor.iter_mut() {
            total += *slot;
            *slot = total;
        }
        self.metadata
            .headers
            .reserve(headers_len.min(MAX_HEADER_ENTRIES) + 2);
        let stored = parts_len.min(MAX_PART_ENTRIES);
        self.remap = vec![NONE; parts_len];
        self.order = vec![NONE; stored];
        for part in self.message.parts() {
            let Some(next) = cursor.get_mut(part.message().id() as usize) else {
                continue;
            };
            let new_id = *next;
            *next += 1;
            if let (Some(remap), Some(order)) = (
                self.remap.get_mut(part.id() as usize),
                self.order.get_mut(new_id as usize),
            ) {
                *remap = new_id;
                *order = part.id();
            }
        }
        cursor.truncate(messages_len);
        self.message_ends = cursor;
    }

    fn has_attachments(&self) -> bool {
        let root = self.message.root();
        root.has_attachments()
            || root.attachments().any(|part| {
                part.is_message()
                    || part.is_content_type("message", "rfc822")
                    || part.is_content_type("message", "global")
            })
    }

    #[inline]
    fn new_id(&self, id: u32) -> u32 {
        self.remap.get(id as usize).copied().unwrap_or(NONE)
    }

    fn messages(&mut self) {
        let stored = self.order.len() as u32;
        let mut start = 0u32;
        let message_ends = take(&mut self.message_ends);
        for (message, end) in self
            .message
            .messages()
            .zip(message_ends.iter())
            .take(MAX_PART_ENTRIES)
        {
            let end = (*end).min(stored).max(start);
            let container = message
                .container()
                .map_or(NONE, |part| self.new_id(part.id()));
            let source = match message.source() {
                Source::Raw => NONE,
                Source::Decoded(part) => self.new_id(part),
            };
            let text_body = self.push_part_ids(message.text_body());
            let html_body = self.push_part_ids(message.html_body());
            let attachments = self.push_part_ids(message.attachments());
            self.metadata.messages.push(MessageEntry {
                parts: Span::between(start, end as usize),
                container,
                source,
                text_body,
                html_body,
                attachments,
                envelope: Envelope::EMPTY,
            });
            start = end;
        }
    }

    fn push_part_ids(&mut self, parts: impl Iterator<Item = MessagePart<'m>>) -> Span {
        let start = self.metadata.ids.len();
        let limit = start + Span::MAX_LEN;
        for part in parts {
            let id = self.new_id(part.id());
            if id != NONE && self.metadata.ids.len() < limit {
                self.metadata.ids.push(id);
            }
        }
        Span::between(start as u32, self.metadata.ids.len())
    }

    fn parts(&mut self, extra: &ExtraHeaders) {
        let order = take(&mut self.order);
        for (new_id, old_id) in order.iter().enumerate() {
            let Some(part) = self.message.part(*old_id) else {
                self.metadata.parts.push(PartEntry::EMPTY);
                continue;
            };
            let message = part.message();
            let message_id = message.id();
            let shift = match message.source() {
                Source::Raw => self.shift,
                Source::Decoded(_) => Shift::NONE,
            };
            let is_message_root = self
                .metadata
                .messages
                .get(message_id as usize)
                .is_some_and(|entry| entry.parts.start as usize == new_id);

            let headers_start = self.metadata.headers.len() as u32;
            let mut scan = FieldScan::default();
            let mut flags = PartFlags::default();
            if new_id == 0 {
                let kept = extra.fields.len().min(MAX_HEADER_ENTRIES);
                self.metadata
                    .headers
                    .extend_from_slice(extra.fields.get(..kept).unwrap_or_default());
            }
            for header in part.headers() {
                let name = header.name();
                scan.record(header, &name, is_message_root);
                if self.metadata.headers.len() < MAX_HEADER_ENTRIES {
                    self.metadata.headers.push(HeaderEntry {
                        name: HeaderId::parse(name.as_str().as_bytes()),
                        offset_field: shift.apply(header.offset_field()),
                        offset_value: shift.apply(header.offset_start()),
                        offset_end: shift.apply(header.offset_end()),
                    });
                }
            }
            let headers = Span::between(headers_start, self.metadata.headers.len());

            if is_message_root {
                let envelope = self.envelope(part, &scan);
                if let Some(entry) = self.metadata.messages.get_mut(message_id as usize) {
                    entry.envelope = envelope;
                }
            }

            let (kind, children) = match part.kind() {
                ParsedKind::Text => (PartKind::Text, Span::EMPTY),
                ParsedKind::Html => (PartKind::Html, Span::EMPTY),
                ParsedKind::Binary => (PartKind::Binary, Span::EMPTY),
                ParsedKind::InlineBinary => (PartKind::InlineBinary, Span::EMPTY),
                ParsedKind::Multipart => (PartKind::Multipart, self.push_part_ids(part.children())),
                ParsedKind::Message(nested) => (
                    PartKind::Message,
                    Span {
                        start: nested.id(),
                        len: 0,
                    },
                ),
            };

            let (decoded_size, lines) = match kind {
                PartKind::Multipart => (0, 0),
                PartKind::Text
                | PartKind::Html
                | PartKind::Binary
                | PartKind::InlineBinary
                | PartKind::Message => (
                    clamp(part.decoded_len()),
                    clamp(bytecount::count(part.raw_body(), b'\n')),
                ),
            };

            if part.in_text_body() {
                flags |= PartFlags::IN_TEXT_BODY;
            }
            if part.in_html_body() {
                flags |= PartFlags::IN_HTML_BODY;
            }
            if part.is_attachment() {
                flags |= PartFlags::ATTACHMENT;
            }
            if !part.has_known_transfer_encoding() {
                flags |= PartFlags::UNKNOWN_TRANSFER_ENCODING;
            }

            let content_type = self.push_content_type(part.content_type(), CONTENT_TYPE_PROTECTED);
            let content_disposition =
                self.push_content_type(part.content_disposition(), CONTENT_DISPOSITION_PROTECTED);
            let content_id = scan
                .content_id
                .and_then(|header| header.value().as_text())
                .map_or(Str::NONE, |id| self.push_bracketed(id));
            let content_description = self.push_text(scan.content_description);
            let content_transfer_encoding = self.push_text(scan.content_transfer_encoding);
            let content_location = self.push_text(scan.content_location);
            let content_md5 = self.push_text(scan.content_md5);
            let content_language = self.push_text_list(scan.content_language, false);

            self.metadata.parts.push(PartEntry {
                offset_header: if new_id == 0 {
                    0
                } else {
                    shift.apply(part.offset_header())
                },
                offset_body: shift.apply(part.offset_body()),
                offset_end: shift.apply(part.offset_end()),
                message: message_id,
                headers,
                children,
                decoded_size,
                lines,
                content_type,
                content_disposition,
                content_id,
                content_description,
                content_transfer_encoding,
                content_location,
                content_md5,
                content_language,
                info: PartInfo::new(
                    kind,
                    match part.encoding() {
                        Encoding::None => TransferEncoding::None,
                        Encoding::QuotedPrintable => TransferEncoding::QuotedPrintable,
                        Encoding::Base64 => TransferEncoding::Base64,
                    },
                    flags,
                ),
            });
        }
        self.order = order;
    }

    fn envelope(&mut self, part: MessagePart<'m>, scan: &FieldScan<'m>) -> Envelope {
        let date = scan
            .date
            .and_then(|header| header.value().as_datetime())
            .map(MetadataDate::from);
        let date_raw = match (scan.date, date) {
            (Some(header), None) => self.push_unfolded(header.raw_value()),
            _ => Str::NONE,
        };
        let subject = scan
            .subject
            .and_then(|header| header.value().as_text())
            .map_or(Str::NONE, |subject| self.push_str(subject));
        let message_id = self.push_ids(scan.message_id);
        let in_reply_to = self.push_ids(scan.in_reply_to);
        let mut envelope = Envelope {
            date,
            date_raw,
            subject,
            in_reply_to,
            message_id,
            ..Envelope::EMPTY
        };
        for (index, (occurrences, name)) in scan.addresses.iter().zip(ADDRESS_FIELDS).enumerate() {
            let field = match occurrences.count {
                0 => AddressField {
                    entries: Span {
                        start: self.metadata.addresses.len() as u32,
                        len: 0,
                    },
                    last: 0,
                },
                1 => self.push_address_field(occurrences.last),
                _ => self.push_address_field(
                    part.headers().iter().filter(|header| header.name() == name),
                ),
            };
            match index {
                0 => envelope.from = field,
                1 => envelope.sender = field,
                2 => envelope.reply_to = field,
                3 => envelope.to = field,
                4 => envelope.cc = field,
                _ => envelope.bcc = field,
            }
        }
        envelope
    }

    fn push_address_field(
        &mut self,
        headers: impl IntoIterator<Item = Header<'m>>,
    ) -> AddressField {
        let start = self.metadata.addresses.len() as u32;
        let limit = MAX_ADDRESS_ENTRIES.min(start as usize + MAX_FIELD_ADDRESSES);
        let mut last = 0;
        for header in headers {
            last = self.metadata.addresses.len() as u32 - start;
            if let Some(list) = header.value().as_address() {
                self.push_address_list(list, limit);
            }
        }
        AddressField {
            entries: Span::between(start, self.metadata.addresses.len()),
            last,
        }
    }

    fn push_address_list(&mut self, list: AddressList<'m>, limit: usize) {
        for item in list.iter() {
            if self.metadata.addresses.len() >= limit {
                return;
            }
            match item {
                Address::Mailbox(mailbox) => {
                    let entry = AddressEntry {
                        name: self.push_opt(mailbox.name()),
                        address: self.push_opt(mailbox.address()),
                        group: 0,
                    };
                    self.metadata.addresses.push(entry);
                }
                Address::Group(group) => {
                    let group_index = self.metadata.addresses.len();
                    let entry = AddressEntry {
                        name: self.push_opt(group.name()),
                        address: Str::NONE,
                        group: GROUP_BIT,
                    };
                    self.metadata.addresses.push(entry);
                    let mut members = 0u16;
                    for mailbox in group.mailboxes() {
                        if self.metadata.addresses.len() >= limit {
                            break;
                        }
                        let entry = AddressEntry {
                            name: self.push_opt(mailbox.name()),
                            address: self.push_opt(mailbox.address()),
                            group: 0,
                        };
                        self.metadata.addresses.push(entry);
                        members += 1;
                    }
                    if let Some(entry) = self.metadata.addresses.get_mut(group_index) {
                        entry.group = GROUP_BIT | members;
                    }
                }
            }
        }
    }

    fn push_text_list(&mut self, header: Option<Header<'m>>, bracketed: bool) -> Span {
        header
            .and_then(|header| self.push_text_items(header, bracketed))
            .unwrap_or(Span::ABSENT)
    }

    fn push_text_items(&mut self, header: Header<'m>, bracketed: bool) -> Option<Span> {
        let start = self.metadata.texts.len() as u32;
        let offered = match header.value() {
            HeaderValue::TextList(list) => {
                for (index, item) in list.iter().enumerate() {
                    if !self.push_item(item, index, bracketed) {
                        break;
                    }
                }
                list.len()
            }
            HeaderValue::Text(item) => {
                self.push_item(item, 0, bracketed);
                1
            }
            _ => return None,
        };
        let stored = self.metadata.texts.len();
        (offered == 0 || stored > start as usize).then(|| Span::between(start, stored))
    }

    fn push_ids(&mut self, header: Option<Header<'m>>) -> Span {
        let Some(header) = header else {
            return Span::ABSENT;
        };
        match header.value() {
            HeaderValue::TextList(_) | HeaderValue::Text(_) => {
                self.push_text_items(header, true).unwrap_or(Span::ABSENT)
            }
            _ => Span {
                start: self.metadata.texts.len() as u32,
                len: 0,
            },
        }
    }

    fn push_unfolded(&mut self, raw: &[u8]) -> Str {
        let text = String::from_utf8_lossy(raw.trim_ascii());
        if text.contains(['\r', '\n']) {
            let unfolded = text.replace(['\r', '\n'], "");
            self.push_str(&unfolded)
        } else {
            self.push_str(&text)
        }
    }

    fn push_item(&mut self, item: &str, index: usize, bracketed: bool) -> bool {
        if self.metadata.texts.len() >= MAX_TEXT_ITEMS {
            return false;
        }
        let text = if bracketed {
            if index > 0 {
                self.push_raw(" ");
            }
            self.push_bracketed(item)
        } else {
            self.push_str(item)
        };
        if text.len == Str::ABSENT_LEN {
            return false;
        }
        self.metadata.texts.push(text);
        true
    }

    fn push_content_type(
        &mut self,
        value: Option<ContentType<'m>>,
        protected: &[&str],
    ) -> ContentTypeEntry {
        let Some(value) = value else {
            return ContentTypeEntry::NONE;
        };
        let ctype = self.push_protected(value.ctype());
        let subtype = value.subtype().map_or(Str::NONE, |subtype| {
            self.metadata.strings.push('/');
            self.push_protected(subtype)
        });
        let start = self.metadata.params.len() as u32;
        let mut stored = 0u32;
        for (name, value) in value.attributes() {
            let slot = protected
                .iter()
                .position(|candidate| *candidate == name)
                .map(|slot| 1u32 << slot)
                .filter(|bit| stored & bit == 0);
            let entry = match slot {
                Some(bit) => {
                    stored |= bit;
                    ParamEntry {
                        name: self.push_protected(name),
                        value: self.push_protected(value),
                    }
                }
                None if self.metadata.params.len() < MAX_PARAMS => ParamEntry {
                    name: self.push_str(name),
                    value: self.push_str(value),
                },
                None => continue,
            };
            self.metadata.params.push(entry);
        }
        ContentTypeEntry {
            ctype,
            subtype,
            params: Span::between(start, self.metadata.params.len()),
        }
    }

    fn push_text(&mut self, header: Option<Header<'m>>) -> Str {
        header
            .and_then(|header| header.value().as_text())
            .map_or(Str::NONE, |text| self.push_str(text))
    }

    fn push_opt(&mut self, text: Option<&str>) -> Str {
        text.map_or(Str::NONE, |text| self.push_str(text))
    }

    fn push_bracketed(&mut self, text: &str) -> Str {
        if self.push_raw("<") {
            let inner = self.push_str(text);
            self.push_raw(">");
            inner
        } else {
            self.push_str(text)
        }
    }

    fn push_raw(&mut self, text: &str) -> bool {
        let fits = self.metadata.strings.len() + text.len() <= MAX_POOL_LEN;
        if fits {
            self.metadata.strings.push_str(text);
        }
        fits
    }

    #[inline]
    fn pool_budget(&self) -> usize {
        MAX_POOL_LEN
            .saturating_sub(self.metadata.strings.len())
            .min(MAX_VALUE_LEN)
    }

    fn push_str(&mut self, text: &str) -> Str {
        self.push_within(text, self.pool_budget())
    }

    fn push_protected(&mut self, text: &str) -> Str {
        self.push_within(text, self.pool_budget().max(MAX_PROTECTED_VALUE_LEN))
    }

    fn push_whole(&mut self, text: &str) -> Str {
        if text.len() <= self.pool_budget() {
            self.push_str(text)
        } else {
            Str::NONE
        }
    }

    fn push_within(&mut self, text: &str, limit: usize) -> Str {
        let kept = floor_str(text, limit.min(Str::MAX_LEN));
        if kept.is_empty() && !text.is_empty() {
            return Str::NONE;
        }
        let start = self.metadata.strings.len() as u32;
        self.metadata.strings.push_str(kept);
        Str::new(start, kept.len())
    }
}

impl PartEntry {
    pub const EMPTY: PartEntry = PartEntry {
        offset_header: 0,
        offset_body: 0,
        offset_end: 0,
        message: 0,
        headers: Span::EMPTY,
        children: Span::EMPTY,
        decoded_size: 0,
        lines: 0,
        content_type: ContentTypeEntry::NONE,
        content_disposition: ContentTypeEntry::NONE,
        content_id: Str::NONE,
        content_description: Str::NONE,
        content_transfer_encoding: Str::NONE,
        content_location: Str::NONE,
        content_md5: Str::NONE,
        content_language: Span::ABSENT,
        info: PartInfo::new(PartKind::Text, TransferEncoding::None, PartFlags(0)),
    };
}

#[inline]
pub(super) fn clamp(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

pub(crate) fn floor_str(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}
