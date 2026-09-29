/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{section::MessageSections, source::DecodedSources};
use email::message::metadata::{
    AddressHeader, AddressItem, Addresses, ArchivedMessageMetadata, ContentTypeView, EnvelopeView,
    HeaderId, HeaderList, HeaderMatcher, HeaderSelection, MAX_NESTING, Mailbox, MessageView,
    Occurrence, PartKind, PartView, RawMessage,
};
use imap_proto::protocol::{
    fetch::{BodyContents, Section},
    push_int, quoted_or_literal_encoded_string, quoted_or_literal_encoded_string_or_nil,
    quoted_or_literal_raw_string, quoted_or_literal_raw_string_or_nil, quoted_rfc2822,
};
use mail_parser::{Address, HeaderForm, ParsedValue};
use utils::chained_bytes::ChainedBytes;

const DUMMY_ADDRESS: Mailbox<'static> = Mailbox {
    name: None,
    address: Some("unknown@localhost"),
};
const DEFAULT_TRANSFER_ENCODING: &str = "7bit";
const DEFAULT_TEXT_SUBTYPE: &str = "plain";
const DEFAULT_MULTIPART_SUBTYPE: &str = "mixed";
const DEFAULT_MESSAGE_SUBTYPE: &str = "rfc822";
const DEFAULT_TEXT_PARAMS: &[u8] = b"(\"charset\" \"us-ascii\")";
const EMPTY_ENVELOPE: &[u8] = b"(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
const EMPTY_BODY: &[u8] = b"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0)";
const EMPTY_BODY_EXTENDED: &[u8] =
    b"(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0 NIL NIL NIL NIL)";
const MESSAGE_FRAME: u32 = u32::MAX;
const NO_PARENT: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary<T> {
    Found(T),
    Missing,
    UnknownCte,
}

impl<T> Binary<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Binary<U> {
        match self {
            Binary::Found(value) => Binary::Found(f(value)),
            Binary::Missing => Binary::Missing,
            Binary::UnknownCte => Binary::UnknownCte,
        }
    }
}

pub trait ImapMetadata {
    fn write_envelope(&self, buf: &mut Vec<u8>, headers: Option<&[u8]>, is_utf8: bool);
    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    );
    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>>;
    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>>;
    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>>;
    fn binary_size(&self, sections: &[u32]) -> Binary<usize>;
}

impl ImapMetadata for ArchivedMessageMetadata {
    fn write_envelope(&self, buf: &mut Vec<u8>, headers: Option<&[u8]>, is_utf8: bool) {
        match headers.filter(|_| self.completeness().is_truncated()) {
            Some(headers) => {
                let selected = self
                    .root()
                    .root_part()
                    .selected_headers(headers, HeaderSelection::ENVELOPE);
                HeaderEnvelope {
                    headers: selected.list(),
                    block: headers,
                }
                .write_imap(buf, is_utf8)
            }
            None => self.root().envelope().write_imap(buf, is_utf8),
        }
    }

    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        self.root().write_structure(buf, is_extended, is_utf8);
    }

    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    ) {
        self.root()
            .write_header_fields(buf, headers, section, matcher);
    }

    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>> {
        self.root().header(raw)
    }

    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>> {
        self.root()
            .body_section(raw, sources, sections, partial, matcher)
    }

    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>> {
        self.root().binary(raw, sources, sections, partial)
    }

    fn binary_size(&self, sections: &[u32]) -> Binary<usize> {
        self.root().binary_size(sections)
    }
}

#[derive(Clone, Copy)]
struct Frame {
    part: u32,
    next: u32,
}

struct FrameStack {
    frames: [Frame; MAX_NESTING],
    len: usize,
}

impl FrameStack {
    fn new() -> Self {
        FrameStack {
            frames: [Frame { part: 0, next: 0 }; MAX_NESTING],
            len: 0,
        }
    }

    fn push(&mut self, frame: Frame) -> bool {
        match self.frames.get_mut(self.len) {
            Some(slot) => {
                *slot = frame;
                self.len += 1;
                true
            }
            None => false,
        }
    }

    fn top(&mut self) -> Option<&mut Frame> {
        self.frames.get_mut(self.len.checked_sub(1)?)
    }

    fn pop(&mut self) -> Option<Frame> {
        let frame = *self.frames.get(self.len.checked_sub(1)?)?;
        self.len -= 1;
        Some(frame)
    }
}

trait StructureWriter {
    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
}

impl StructureWriter for MessageView<'_> {
    fn write_structure(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        let meta = self.metadata();
        let empty_body = if is_extended {
            EMPTY_BODY_EXTENDED
        } else {
            EMPTY_BODY
        };
        let mut stack = FrameStack::new();
        let mut next = Some((self.root_part(), NO_PARENT));

        loop {
            if let Some((part, parent)) = next.take() {
                match part.kind() {
                    PartKind::Multipart => {
                        buf.push(b'(');
                        if stack.push(Frame {
                            part: part.id(),
                            next: 0,
                        }) {
                            continue;
                        }
                        buf.extend_from_slice(empty_body);
                        part.write_multipart_tail(buf, is_extended, is_utf8);
                    }
                    PartKind::Message => {
                        buf.push(b'(');
                        let nested = part.nested();
                        let content_type = part.content_type();
                        part.write_message_head(
                            buf,
                            content_type
                                .as_ref()
                                .and_then(|content_type| content_type.message_subtype())
                                .unwrap_or(DEFAULT_MESSAGE_SUBTYPE),
                            content_type,
                            nested.map(|nested| nested.envelope()),
                            is_utf8,
                        );
                        match nested {
                            Some(nested)
                                if stack.push(Frame {
                                    part: part.id(),
                                    next: MESSAGE_FRAME,
                                }) =>
                            {
                                next = Some((nested.root_part(), NO_PARENT));
                                continue;
                            }
                            _ => {
                                buf.extend_from_slice(empty_body);
                                part.write_message_tail(buf, is_extended, is_utf8);
                            }
                        }
                    }
                    _ => part.write_leaf(buf, parent, empty_body, is_extended, is_utf8),
                }
            }

            let Some(frame) = stack.top() else {
                return;
            };
            let Some(part) = meta.part(frame.part) else {
                stack.pop();
                continue;
            };
            if frame.next != MESSAGE_FRAME
                && let Some(child) = part.child(frame.next as usize)
            {
                frame.next += 1;
                next = Some((child, frame.part));
                continue;
            }
            let has_children = frame.next != 0;
            stack.pop();
            if part.is_message() {
                part.write_message_tail(buf, is_extended, is_utf8);
            } else {
                if !has_children {
                    buf.extend_from_slice(empty_body);
                }
                part.write_multipart_tail(buf, is_extended, is_utf8);
            }
        }
    }
}

trait ImapEnvelope {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ImapEnvelope for EnvelopeView<'_> {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.push(b'(');
        match self.datetime() {
            Some(date) => quoted_rfc2822(buf, &date),
            None => quoted_or_literal_encoded_string_or_nil(buf, self.date_raw(), is_utf8),
        }
        buf.push(b' ');
        quoted_or_literal_encoded_string_or_nil(buf, self.subject(), is_utf8);

        let from = self
            .addresses(AddressHeader::From, Occurrence::All)
            .visible();
        from.write_imap_or(buf, None, is_utf8);
        self.addresses(AddressHeader::Sender, Occurrence::All)
            .visible()
            .or(from)
            .write_imap_or(buf, None, is_utf8);
        self.addresses(AddressHeader::ReplyTo, Occurrence::All)
            .visible()
            .or(from)
            .write_imap_or(buf, None, is_utf8);
        for header in [AddressHeader::To, AddressHeader::Cc, AddressHeader::Bcc] {
            self.addresses(header, Occurrence::All)
                .visible()
                .write_imap_or(buf, Some(b"NIL"), is_utf8);
        }

        let in_reply_to = self.in_reply_to();
        buf.push(b' ');
        quoted_or_literal_raw_string_or_nil(
            buf,
            if in_reply_to.is_present() && in_reply_to.is_empty() {
                Some("")
            } else {
                in_reply_to.joined_bracketed()
            },
            is_utf8,
        );
        let message_id = self.message_id();
        buf.push(b' ');
        quoted_or_literal_raw_string_or_nil(
            buf,
            if message_id.is_present() && message_id.is_empty() {
                Some("")
            } else {
                message_id.last_bracketed()
            },
            is_utf8,
        );
        buf.push(b')');
    }
}

struct HeaderEnvelope<'x> {
    headers: HeaderList<'x>,
    block: &'x [u8],
}

impl HeaderEnvelope<'_> {
    fn raw_value(&self, id: HeaderId) -> Option<&[u8]> {
        self.headers.last(id)?.raw_value(self.block)
    }

    fn addresses(&self, id: HeaderId) -> Vec<ParsedValue<'_>> {
        self.headers
            .all(id)
            .filter_map(|header| header.raw_value(self.block))
            .map(|raw| HeaderForm::Addresses.parse(raw))
            .collect()
    }

    fn write_message_ids(&self, buf: &mut Vec<u8>, id: HeaderId, all: bool, is_utf8: bool) {
        let Some(raw) = self.raw_value(id) else {
            buf.extend_from_slice(b"NIL");
            return;
        };
        let parsed = HeaderForm::MessageIds.parse(raw);
        let value = parsed.value();
        let mut ids = String::new();
        if let Some(list) = value.as_text_list() {
            let skip = if all { 0 } else { list.len().saturating_sub(1) };
            for (pos, item) in list.iter().skip(skip).enumerate() {
                if pos > 0 {
                    ids.push(' ');
                }
                ids.push('<');
                ids.push_str(item);
                ids.push('>');
            }
        }
        quoted_or_literal_raw_string(buf, &ids, is_utf8);
    }
}

impl ImapEnvelope for HeaderEnvelope<'_> {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.push(b'(');
        match self.raw_value(HeaderId::DATE) {
            Some(raw) => match HeaderForm::Date.parse(raw).value().as_datetime() {
                Some(date) => quoted_rfc2822(buf, &date),
                None => {
                    let text = String::from_utf8_lossy(raw.trim_ascii()).replace(['\r', '\n'], "");
                    quoted_or_literal_encoded_string(buf, &text, is_utf8);
                }
            },
            None => buf.extend_from_slice(b"NIL"),
        }
        buf.push(b' ');
        match self.raw_value(HeaderId::SUBJECT) {
            Some(raw) => {
                let parsed = HeaderForm::Text.parse(raw);
                quoted_or_literal_encoded_string_or_nil(buf, parsed.value().as_text(), is_utf8);
            }
            None => buf.extend_from_slice(b"NIL"),
        }

        let from = self.addresses(HeaderId::FROM);
        let from = from.has_imap_address().then_some(from.as_slice());
        for id in [HeaderId::FROM, HeaderId::SENDER, HeaderId::REPLY_TO] {
            buf.push(b' ');
            let values = if id == HeaderId::FROM {
                Vec::new()
            } else {
                self.addresses(id)
            };
            if values.has_imap_address() {
                values.write_imap(buf, is_utf8);
            } else if let Some(from) = from {
                from.write_imap(buf, is_utf8);
            } else {
                buf.push(b'(');
                DUMMY_ADDRESS.write_imap(buf, is_utf8);
                buf.push(b')');
            }
        }
        for id in [HeaderId::TO, HeaderId::CC, HeaderId::BCC] {
            buf.push(b' ');
            let values = self.addresses(id);
            if values.has_imap_address() {
                values.write_imap(buf, is_utf8);
            } else {
                buf.extend_from_slice(b"NIL");
            }
        }

        buf.push(b' ');
        self.write_message_ids(buf, HeaderId::IN_REPLY_TO, true, is_utf8);
        buf.push(b' ');
        self.write_message_ids(buf, HeaderId::MESSAGE_ID, false, is_utf8);
        buf.push(b')');
    }
}

trait ParsedAddresses {
    fn has_imap_address(&self) -> bool;
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ParsedAddresses for [ParsedValue<'_>] {
    fn has_imap_address(&self) -> bool {
        self.iter().any(|value| {
            value.value().as_address().is_some_and(|list| {
                list.iter().any(|item| match item {
                    Address::Mailbox(mailbox) => mailbox.address().is_some(),
                    Address::Group(_) => true,
                })
            })
        })
    }

    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.push(b'(');
        for value in self {
            let Some(list) = value.value().as_address() else {
                continue;
            };
            for item in list.iter() {
                match item {
                    Address::Mailbox(mailbox) => Mailbox {
                        name: mailbox.name(),
                        address: mailbox.address(),
                    }
                    .write_imap(buf, is_utf8),
                    Address::Group(group) => {
                        buf.extend_from_slice(b"(NIL NIL ");
                        match group.name() {
                            Some(name) => quoted_or_literal_encoded_string(buf, name, is_utf8),
                            None => buf.extend_from_slice(b"\"\""),
                        }
                        buf.extend_from_slice(b" NIL)");
                        for mailbox in group.mailboxes() {
                            Mailbox {
                                name: mailbox.name(),
                                address: mailbox.address(),
                            }
                            .write_imap(buf, is_utf8);
                        }
                        buf.extend_from_slice(b"(NIL NIL NIL NIL)");
                    }
                }
            }
        }
        buf.push(b')');
    }
}

trait ImapAddresses: Sized {
    fn visible(self) -> Option<Self>;
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ImapAddresses for Addresses<'_> {
    fn visible(self) -> Option<Self> {
        self.has_imap_address().then_some(self)
    }

    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        buf.push(b'(');
        for item in self.iter() {
            match item {
                AddressItem::Mailbox(mailbox) => mailbox.write_imap(buf, is_utf8),
                AddressItem::Group(group) => {
                    buf.extend_from_slice(b"(NIL NIL ");
                    if let Some(name) = group.name {
                        quoted_or_literal_encoded_string(buf, name, is_utf8);
                    } else {
                        buf.extend_from_slice(b"\"\"");
                    }
                    buf.extend_from_slice(b" NIL)");
                    for mailbox in group.members.mailboxes() {
                        mailbox.write_imap(buf, is_utf8);
                    }
                    buf.extend_from_slice(b"(NIL NIL NIL NIL)");
                }
            }
        }
        buf.push(b')');
    }
}

trait ImapAddressField {
    fn write_imap_or(self, buf: &mut Vec<u8>, fallback: Option<&[u8]>, is_utf8: bool);
}

impl ImapAddressField for Option<Addresses<'_>> {
    fn write_imap_or(self, buf: &mut Vec<u8>, fallback: Option<&[u8]>, is_utf8: bool) {
        buf.push(b' ');
        match (self, fallback) {
            (Some(addresses), _) => addresses.write_imap(buf, is_utf8),
            (None, Some(fallback)) => buf.extend_from_slice(fallback),
            (None, None) => {
                buf.push(b'(');
                DUMMY_ADDRESS.write_imap(buf, is_utf8);
                buf.push(b')');
            }
        }
    }
}

trait ImapMailbox {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool);
}

impl ImapMailbox for Mailbox<'_> {
    fn write_imap(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        let Some(address) = self.address else {
            return;
        };
        buf.push(b'(');
        if let Some(name) = self.name {
            quoted_or_literal_encoded_string(buf, name, is_utf8);
        } else {
            buf.extend_from_slice(b"NIL");
        }

        let addr = if let Some((route, addr)) = address.split_once(':') {
            buf.push(b' ');
            quoted_or_literal_raw_string(buf, route, is_utf8);
            buf.push(b' ');
            addr
        } else {
            buf.extend_from_slice(b" NIL ");
            address
        };

        if let Some((local, host)) = addr.rsplit_once('@') {
            quoted_or_literal_raw_string(buf, local, is_utf8);
            buf.push(b' ');
            quoted_or_literal_raw_string(buf, host, is_utf8);
        } else {
            quoted_or_literal_raw_string(buf, address, is_utf8);
            buf.extend_from_slice(b" \"\"");
        }
        buf.push(b')');
    }
}

trait ImapContentType {
    fn write_parameters(&self, buf: &mut Vec<u8>, is_utf8: bool);
    fn message_subtype(&self) -> Option<&str>;
}

impl ImapContentType for ContentTypeView<'_> {
    fn message_subtype(&self) -> Option<&str> {
        self.subtype().filter(|subtype| {
            self.ctype().eq_ignore_ascii_case("message") && subtype.is_message_subtype()
        })
    }

    fn write_parameters(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        for (pos, (key, value)) in self.attributes().enumerate() {
            if pos > 0 {
                buf.push(b' ');
            }
            quoted_or_literal_raw_string(buf, key, is_utf8);
            buf.push(b' ');
            quoted_or_literal_encoded_string(buf, value, is_utf8);
        }
    }
}

#[derive(Clone, Copy)]
enum LeafMedia<'a> {
    Text {
        subtype: &'a str,
        params: Option<ContentTypeView<'a>>,
    },
    Message {
        subtype: &'a str,
        params: Option<ContentTypeView<'a>>,
    },
    Basic {
        ctype: &'a str,
        subtype: &'a str,
        params: ContentTypeView<'a>,
    },
}

trait ImapPart {
    fn is_digest(&self) -> bool;
    fn leaf_media(&self, parent: u32) -> LeafMedia<'_>;
    fn write_fields(
        &self,
        buf: &mut Vec<u8>,
        params: Option<ContentTypeView<'_>>,
        default_params: &[u8],
        is_utf8: bool,
    );
    fn write_extension(&self, buf: &mut Vec<u8>, is_utf8: bool);
    fn write_leaf(
        &self,
        buf: &mut Vec<u8>,
        parent: u32,
        empty_body: &[u8],
        is_extended: bool,
        is_utf8: bool,
    );
    fn write_message_head(
        &self,
        buf: &mut Vec<u8>,
        subtype: &str,
        params: Option<ContentTypeView<'_>>,
        envelope: Option<EnvelopeView<'_>>,
        is_utf8: bool,
    );
    fn write_message_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
    fn write_multipart_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool);
}

impl ImapPart for PartView<'_> {
    fn is_digest(&self) -> bool {
        self.content_type()
            .and_then(|content_type| content_type.subtype())
            .is_some_and(|subtype| subtype.eq_ignore_ascii_case("digest"))
    }

    fn leaf_media(&self, parent: u32) -> LeafMedia<'_> {
        let Some(content_type) = self.content_type() else {
            return if self
                .metadata()
                .part(parent)
                .is_some_and(|parent| parent.is_digest())
            {
                LeafMedia::Message {
                    subtype: DEFAULT_MESSAGE_SUBTYPE,
                    params: None,
                }
            } else {
                LeafMedia::Text {
                    subtype: DEFAULT_TEXT_SUBTYPE,
                    params: None,
                }
            };
        };
        let ctype = content_type.ctype();
        let Some(subtype) = content_type
            .subtype()
            .filter(|subtype| !subtype.is_empty() && !ctype.is_empty())
        else {
            return LeafMedia::Text {
                subtype: DEFAULT_TEXT_SUBTYPE,
                params: None,
            };
        };
        if ctype.eq_ignore_ascii_case("text") {
            LeafMedia::Text {
                subtype,
                params: Some(content_type),
            }
        } else if ctype.eq_ignore_ascii_case("multipart") {
            LeafMedia::Text {
                subtype: DEFAULT_TEXT_SUBTYPE,
                params: Some(content_type),
            }
        } else if ctype.eq_ignore_ascii_case("message") && subtype.is_message_subtype() {
            LeafMedia::Message {
                subtype,
                params: Some(content_type),
            }
        } else if !ctype.is_media_token() || !subtype.is_media_token() {
            LeafMedia::Text {
                subtype: DEFAULT_TEXT_SUBTYPE,
                params: None,
            }
        } else {
            LeafMedia::Basic {
                ctype,
                subtype,
                params: content_type,
            }
        }
    }

    fn write_fields(
        &self,
        buf: &mut Vec<u8>,
        params: Option<ContentTypeView<'_>>,
        default_params: &[u8],
        is_utf8: bool,
    ) {
        match params.filter(|content_type| content_type.has_attributes()) {
            Some(content_type) => {
                buf.push(b'(');
                content_type.write_parameters(buf, is_utf8);
                buf.push(b')');
            }
            None => buf.extend_from_slice(default_params),
        }
        buf.push(b' ');
        quoted_or_literal_encoded_string_or_nil(buf, self.content_id_bracketed(), is_utf8);
        buf.push(b' ');
        quoted_or_literal_encoded_string_or_nil(buf, self.content_description(), is_utf8);
        buf.push(b' ');
        quoted_or_literal_encoded_string(
            buf,
            self.content_transfer_encoding()
                .unwrap_or(DEFAULT_TRANSFER_ENCODING),
            is_utf8,
        );
        buf.push(b' ');
        push_int(buf, self.body_range().len());
    }

    fn write_extension(&self, buf: &mut Vec<u8>, is_utf8: bool) {
        if let Some(disposition) = self.content_disposition() {
            buf.push(b'(');
            quoted_or_literal_raw_string(buf, disposition.ctype(), is_utf8);
            if disposition.has_attributes() {
                buf.extend_from_slice(b" (");
                disposition.write_parameters(buf, is_utf8);
                buf.extend_from_slice(b"))");
            } else {
                buf.extend_from_slice(b" NIL)");
            }
        } else {
            buf.extend_from_slice(b"NIL");
        }
        let languages = self.content_language();
        match languages.len() {
            0 => buf.extend_from_slice(b" NIL"),
            1 => {
                buf.push(b' ');
                quoted_or_literal_raw_string(
                    buf,
                    languages.iter().next().unwrap_or_default(),
                    is_utf8,
                );
            }
            _ => {
                buf.extend_from_slice(b" (");
                for (pos, language) in languages.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }
                    quoted_or_literal_raw_string(buf, language, is_utf8);
                }
                buf.push(b')');
            }
        }
        buf.push(b' ');
        quoted_or_literal_raw_string_or_nil(buf, self.content_location(), is_utf8);
    }

    fn write_leaf(
        &self,
        buf: &mut Vec<u8>,
        parent: u32,
        empty_body: &[u8],
        is_extended: bool,
        is_utf8: bool,
    ) {
        buf.push(b'(');
        match self.leaf_media(parent) {
            LeafMedia::Text { subtype, params } => {
                buf.extend_from_slice(b"\"text\" ");
                quoted_or_literal_raw_string(buf, subtype, is_utf8);
                buf.push(b' ');
                self.write_fields(buf, params, DEFAULT_TEXT_PARAMS, is_utf8);
                buf.push(b' ');
                push_int(buf, self.lines());
            }
            LeafMedia::Message { subtype, params } => {
                self.write_message_head(buf, subtype, params, None, is_utf8);
                buf.extend_from_slice(empty_body);
                buf.push(b' ');
                push_int(buf, self.lines());
            }
            LeafMedia::Basic {
                ctype,
                subtype,
                params,
            } => {
                quoted_or_literal_raw_string(buf, ctype, is_utf8);
                buf.push(b' ');
                quoted_or_literal_raw_string(buf, subtype, is_utf8);
                buf.push(b' ');
                self.write_fields(buf, Some(params), b"NIL", is_utf8);
            }
        }
        if is_extended {
            buf.push(b' ');
            quoted_or_literal_raw_string_or_nil(buf, self.content_md5(), is_utf8);
            buf.push(b' ');
            self.write_extension(buf, is_utf8);
        }
        buf.push(b')');
    }

    fn write_message_head(
        &self,
        buf: &mut Vec<u8>,
        subtype: &str,
        params: Option<ContentTypeView<'_>>,
        envelope: Option<EnvelopeView<'_>>,
        is_utf8: bool,
    ) {
        buf.extend_from_slice(b"\"message\" ");
        quoted_or_literal_raw_string(buf, subtype, is_utf8);
        buf.push(b' ');
        self.write_fields(buf, params, b"NIL", is_utf8);
        buf.push(b' ');
        match envelope {
            Some(envelope) => envelope.write_imap(buf, is_utf8),
            None => buf.extend_from_slice(EMPTY_ENVELOPE),
        }
        buf.push(b' ');
    }

    fn write_message_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        buf.push(b' ');
        push_int(buf, self.lines());
        if is_extended {
            buf.push(b' ');
            quoted_or_literal_raw_string_or_nil(buf, self.content_md5(), is_utf8);
            buf.push(b' ');
            self.write_extension(buf, is_utf8);
        }
        buf.push(b')');
    }

    fn write_multipart_tail(&self, buf: &mut Vec<u8>, is_extended: bool, is_utf8: bool) {
        let content_type = self.content_type();
        buf.push(b' ');
        quoted_or_literal_raw_string(
            buf,
            content_type
                .and_then(|content_type| content_type.subtype())
                .filter(|subtype| !subtype.is_empty())
                .unwrap_or(DEFAULT_MULTIPART_SUBTYPE),
            is_utf8,
        );
        if is_extended {
            match content_type.filter(|content_type| content_type.has_attributes()) {
                Some(content_type) => {
                    buf.extend_from_slice(b" (");
                    content_type.write_parameters(buf, is_utf8);
                    buf.push(b')');
                }
                None => buf.extend_from_slice(b" NIL"),
            }
            buf.push(b' ');
            self.write_extension(buf, is_utf8);
        }
        buf.push(b')');
    }
}

trait MediaToken {
    fn is_message_subtype(&self) -> bool;
    fn is_media_token(&self) -> bool;
}

impl MediaToken for str {
    fn is_message_subtype(&self) -> bool {
        self.eq_ignore_ascii_case("rfc822") || self.eq_ignore_ascii_case("global")
    }

    fn is_media_token(&self) -> bool {
        !self.is_empty() && !self.contains('\0')
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{Binary, HeaderEnvelope, HeaderSelection, ImapEnvelope, ImapMetadata};
    use crate::op::fetch::source::DecodedSources;
    use email::message::metadata::{
        ExtraHeaders, MAX_VALUE_LEN, MessageMetadata, MetadataRow, MetadataStructure,
    };
    use imap_proto::protocol::fetch::Section;
    use mail_parser::MessageParser;
    use store::Deserialize;
    use types::blob_hash::BlobHash;

    pub(in crate::op::fetch) struct Stored {
        pub(in crate::op::fetch) row: Vec<u8>,
        pub(in crate::op::fetch) blob: Vec<u8>,
    }

    impl Stored {
        pub(in crate::op::fetch) fn new(raw: &str) -> Self {
            Self::with_extra(raw, &ExtraHeaders::default())
        }

        pub(in crate::op::fetch) fn with_extra(raw: &str, extra: &ExtraHeaders) -> Self {
            let blob = raw.as_bytes().to_vec();
            let message = MessageParser::new().parse(&blob).expect("message parses");
            let row = MessageMetadata::build(&message, extra, BlobHash::generate(&blob))
                .encode()
                .expect("row encodes");
            Stored { row, blob }
        }

        pub(in crate::op::fetch) fn row(&self) -> MetadataRow {
            MetadataRow::deserialize(&self.row).expect("row reads")
        }

        pub(in crate::op::fetch) fn structure(&self) -> MetadataStructure {
            MetadataStructure::deserialize(&self.row).expect("structure reads")
        }

        pub(in crate::op::fetch) fn section(
            &self,
            sections: &[Section],
            partial: Option<(u32, u32)>,
        ) -> Option<Vec<u8>> {
            let row = self.row();
            let meta = row.unarchive().expect("unarchives");
            let headers = row.raw_headers().expect("headers");
            meta.body_section(
                meta.raw_message(Some(&headers), &self.blob),
                &mut DecodedSources::default(),
                sections,
                partial,
                None,
            )
            .map(|contents| contents.as_chained().to_vec())
        }

        pub(in crate::op::fetch) fn body_only_section(
            &self,
            sections: &[Section],
            partial: Option<(u32, u32)>,
        ) -> Option<Vec<u8>> {
            let structure = self.structure();
            let meta = structure.unarchive().expect("unarchives");
            meta.body_section(
                meta.raw_message(None, &self.blob),
                &mut DecodedSources::default(),
                sections,
                partial,
                None,
            )
            .map(|contents| contents.as_chained().to_vec())
        }

        pub(in crate::op::fetch) fn header_only_section(
            &self,
            sections: &[Section],
            partial: Option<(u32, u32)>,
        ) -> Option<Vec<u8>> {
            let row = self.row();
            let meta = row.unarchive().expect("unarchives");
            let headers = row.raw_headers().expect("headers");
            meta.body_section(
                meta.raw_message(Some(&headers), &[]),
                &mut DecodedSources::default(),
                sections,
                partial,
                None,
            )
            .map(|contents| contents.as_chained().to_vec())
        }

        pub(in crate::op::fetch) fn binary(
            &self,
            sections: &[u32],
            partial: Option<(u32, u32)>,
        ) -> Binary<Vec<u8>> {
            let structure = self.structure();
            let meta = structure.unarchive().expect("unarchives");
            meta.binary(
                meta.raw_message(None, &self.blob),
                &mut DecodedSources::default(),
                sections,
                partial,
            )
            .map(|contents| contents.as_chained().to_vec())
        }

        pub(in crate::op::fetch) fn binary_with_headers(
            &self,
            sections: &[u32],
            partial: Option<(u32, u32)>,
        ) -> Binary<Vec<u8>> {
            let row = self.row();
            let meta = row.unarchive().expect("unarchives");
            let headers = row.raw_headers().expect("headers");
            meta.binary(
                meta.raw_message(Some(&headers), &self.blob),
                &mut DecodedSources::default(),
                sections,
                partial,
            )
            .map(|contents| contents.as_chained().to_vec())
        }

        pub(in crate::op::fetch) fn binary_size(&self, sections: &[u32]) -> Binary<usize> {
            self.structure()
                .unarchive()
                .expect("unarchives")
                .binary_size(sections)
        }

        fn envelope(&self) -> String {
            let mut buf = Vec::new();
            self.structure()
                .unarchive()
                .expect("unarchives")
                .write_envelope(&mut buf, None, false);
            String::from_utf8(buf).expect("utf-8")
        }

        fn envelope_bytes(&self, is_utf8: bool) -> Vec<u8> {
            let mut buf = Vec::new();
            self.structure()
                .unarchive()
                .expect("unarchives")
                .write_envelope(&mut buf, None, is_utf8);
            buf
        }

        fn envelope_with_headers(&self, is_utf8: bool) -> Vec<u8> {
            let row = self.row();
            let headers = row.raw_headers().expect("headers");
            let mut buf = Vec::new();
            row.unarchive()
                .expect("unarchives")
                .write_envelope(&mut buf, Some(&headers), is_utf8);
            buf
        }

        fn envelope_from_headers(&self, is_utf8: bool) -> Vec<u8> {
            let row = self.row();
            let headers = row.raw_headers().expect("headers");
            let meta = row.unarchive().expect("unarchives");
            let root = meta.root().root_part();
            let selected = root.selected_headers(&headers, HeaderSelection::ENVELOPE);
            let mut buf = Vec::new();
            HeaderEnvelope {
                headers: selected.list(),
                block: &headers,
            }
            .write_imap(&mut buf, is_utf8);
            buf
        }

        fn structure_bytes(&self, is_extended: bool, is_utf8: bool) -> Vec<u8> {
            let mut buf = Vec::new();
            self.structure()
                .unarchive()
                .expect("unarchives")
                .write_structure(&mut buf, is_extended, is_utf8);
            buf
        }

        fn body_structure(&self, is_extended: bool) -> String {
            let mut buf = Vec::new();
            self.structure()
                .unarchive()
                .expect("unarchives")
                .write_structure(&mut buf, is_extended, false);
            String::from_utf8(buf).expect("utf-8")
        }
    }

    #[test]
    fn envelope_distinguishes_absent_empty_and_unparseable_fields() {
        let envelope = |raw: &str| Stored::new(raw).envelope();
        let from = "((NIL NIL \"a\" \"example.com\"))";
        let addresses = format!("{from} {from} {from} ((NIL NIL \"b\" \"example.com\")) NIL NIL");
        assert_eq!(
            envelope("From: a@example.com\r\nTo: b@example.com\r\n\r\nbody\r\n"),
            format!("(NIL NIL {addresses} NIL NIL)")
        );
        assert_eq!(
            envelope(concat!(
                "Date:\r\n",
                "Subject:\r\n",
                "In-Reply-To:\r\n",
                "Message-ID:\r\n",
                "From: a@example.com\r\n",
                "To: b@example.com\r\n\r\nbody\r\n"
            )),
            format!("(\"\" \"\" {addresses} \"\" \"\")")
        );
        assert_eq!(
            envelope(concat!(
                "Date: not a date\r\n",
                "Subject: hello\r\n",
                "In-Reply-To: <a@b> <c@d>\r\n",
                "Message-ID: <e@f>\r\n",
                "From: a@example.com\r\n",
                "To: b@example.com\r\n\r\nbody\r\n"
            )),
            format!("(\"not a date\" \"hello\" {addresses} \"<a@b> <c@d>\" \"<e@f>\")")
        );
        assert_eq!(
            envelope(concat!(
                "Date: Wed, 17 Jul 1996 02:23:25 -0700\r\n",
                "From: a@example.com\r\n",
                "To: b@example.com\r\n\r\nbody\r\n"
            )),
            format!("(\"Wed, 17 Jul 1996 02:23:25 -0700\" NIL {addresses} NIL NIL)")
        );
    }

    #[test]
    fn envelope_writes_groups_and_falls_back_to_from() {
        let envelope = |raw: &str| Stored::new(raw).envelope();
        assert_eq!(
            envelope(concat!(
                "Date: Wed, 17 Jul 1996 02:23:25 +0000\r\n",
                "Subject: Group test\r\n",
                "From: Bill Foobar <foobar@example.com>\r\n",
                "To: Friends and Family: John Doe <jdoe@example.com>, ",
                "Jane Smith <jane.smith@example.com>;\r\n",
                "Message-ID: <B27397-0100000@cac.washington.ed>\r\n",
                "\r\n",
                "body\r\n"
            )),
            concat!(
                "(\"Wed, 17 Jul 1996 02:23:25 +0000\" ",
                "\"Group test\" ",
                "((\"Bill Foobar\" NIL \"foobar\" \"example.com\")) ",
                "((\"Bill Foobar\" NIL \"foobar\" \"example.com\")) ",
                "((\"Bill Foobar\" NIL \"foobar\" \"example.com\")) ",
                "((NIL NIL \"Friends and Family\" NIL)",
                "(\"John Doe\" NIL \"jdoe\" \"example.com\")",
                "(\"Jane Smith\" NIL \"jane.smith\" \"example.com\")",
                "(NIL NIL NIL NIL)) ",
                "NIL NIL NIL \"<B27397-0100000@cac.washington.ed>\")"
            )
        );
        assert_eq!(
            envelope(concat!(
                "From: Terry Gray <gray@cac.washington.edu>\r\n",
                "Sender: sender@example.com\r\n",
                "Reply-To: reply@example.com\r\n",
                "Cc: minutes@CNRI.Reston.VA.US, John Klensin <KLENSIN@MIT.EDU>\r\n",
                "\r\n",
                "body\r\n"
            )),
            concat!(
                "(NIL NIL ",
                "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
                "((NIL NIL \"sender\" \"example.com\")) ",
                "((NIL NIL \"reply\" \"example.com\")) NIL ",
                "((NIL NIL \"minutes\" \"CNRI.Reston.VA.US\")",
                "(\"John Klensin\" NIL \"KLENSIN\" \"MIT.EDU\")) NIL NIL NIL)"
            )
        );
        assert_eq!(
            envelope("Subject: no from\r\n\r\nbody\r\n"),
            concat!(
                "(NIL \"no from\" ",
                "((NIL NIL \"unknown\" \"localhost\")) ",
                "((NIL NIL \"unknown\" \"localhost\")) ",
                "((NIL NIL \"unknown\" \"localhost\")) NIL NIL NIL NIL NIL)"
            )
        );
    }

    #[test]
    fn body_md5_is_content_md5() {
        let stored = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Subject: md5\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain; charset=us-ascii\r\n",
            "Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\n",
            "\r\n",
            "Check Integrity!\r\n",
            "--b\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "AAEC\r\n",
            "--b--\r\n"
        ));
        assert_eq!(
            stored.body_structure(true),
            concat!(
                "((\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 16 0 ",
                "\"Q2hlY2sgSW50ZWdyaXR5IQ==\" NIL NIL NIL)",
                "(\"application\" \"octet-stream\" NIL NIL NIL \"base64\" 4 ",
                "NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"b\") NIL NIL NIL)"
            )
        );
        assert_eq!(
            stored.body_structure(false),
            concat!(
                "((\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 16 0)",
                "(\"application\" \"octet-stream\" NIL NIL NIL \"base64\" 4) \"mixed\")"
            )
        );
    }

    #[test]
    fn message_rfc822_reports_lines() {
        let inner = concat!(
            "From: inner@example.com\r\n",
            "Subject: inner\r\n",
            "\r\n",
            "line 1\r\n",
            "line 2\r\n",
            "line 3\r\n"
        );
        let stored = Stored::new(&format!(
            concat!(
                "From: a@example.com\r\n",
                "Subject: outer\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n",
                "{}"
            ),
            inner
        ));
        let lines = inner.matches('\n').count();
        let structure = stored.body_structure(false);
        assert_eq!(
            structure,
            format!(
                concat!(
                    "(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" {} ",
                    "(NIL \"inner\" ((NIL NIL \"inner\" \"example.com\")) ",
                    "((NIL NIL \"inner\" \"example.com\")) ",
                    "((NIL NIL \"inner\" \"example.com\")) NIL NIL NIL NIL NIL) ",
                    "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 24 3) {})"
                ),
                inner.len(),
                lines
            )
        );
    }

    #[test]
    fn encoding_defaults_to_7bit_for_every_leaf() {
        let stored = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: image/png\r\n",
            "\r\n",
            "PNG\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "Subject: inner\r\n",
            "\r\n",
            "hi\r\n",
            "--b\r\n",
            "Content-Type: application/pdf\r\n",
            "Content-Transfer-Encoding: BASE64\r\n",
            "\r\n",
            "JVBERg==\r\n",
            "--b--\r\n"
        ));
        assert_eq!(
            stored.body_structure(false),
            concat!(
                "((\"image\" \"png\" NIL NIL NIL \"7bit\" 3)",
                "(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 20 ",
                "(NIL \"inner\" ((NIL NIL \"unknown\" \"localhost\")) ",
                "((NIL NIL \"unknown\" \"localhost\")) ",
                "((NIL NIL \"unknown\" \"localhost\")) NIL NIL NIL NIL NIL) ",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 2 0) 2)",
                "(\"application\" \"pdf\" NIL NIL NIL \"BASE64\" 8) \"mixed\")"
            )
        );
    }

    #[test]
    fn bodystructure_writes_ids_parameters_and_extensions() {
        let stored = Stored::new(concat!(
            "From: Terry Gray <gray@cac.washington.edu>\r\n",
            "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: multipart/alternative; boundary=\"alt\"; ",
            "x-param=\"a very special parameter\"\r\n",
            "Content-Language: en-US\r\n",
            "Content-Location: unknown\r\n",
            "\r\n",
            "--alt\r\n",
            "Content-Type: text/plain; charset=UTF-8\r\n",
            "Content-ID: <111@domain.com>\r\n",
            "Content-Description: Text part\r\n",
            "Content-Disposition: inline\r\n",
            "Content-Language: en-US\r\n",
            "Content-Location: right here\r\n",
            "\r\n",
            "text\r\n",
            "--alt\r\n",
            "Content-Type: text/html; charset=UTF-8\r\n",
            "Content-ID: <54535@domain.com>\r\n",
            "Content-Description: HTML part\r\n",
            "Content-Transfer-Encoding: 8bit\r\n",
            "Content-Disposition: attachment; filename=\"myfile.txt\"\r\n",
            "Content-Language: en-US, de-DE\r\n",
            "Content-Location: right there\r\n",
            "\r\n",
            "<p>html</p>\r\n",
            "--alt--\r\n",
            "--outer\r\n",
            "Content-Type: application/msword; name=\"chimichangas.docx\"\r\n",
            "Content-ID: <4444@chimi.changa>\r\n",
            "Content-Description: Chimichangas recipe\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\n",
            "Content-Disposition: attachment; filename=\"chimichangas.docx\"\r\n",
            "Content-Language: en-MX\r\n",
            "Content-Location: secret location\r\n",
            "\r\n",
            "AAEC\r\n",
            "--outer\r\n",
            "Content-Type: message/rfc822\r\n",
            "Content-ID: <abc@123>\r\n",
            "Content-Description: An attached email\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "Subject: Hello world!\r\n",
            "From: Terry Gray <gray@cac.washington.edu>\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>hi</p>\r\n",
            "--outer--\r\n"
        ));
        let nested = concat!(
            "\"message\" \"rfc822\" NIL \"<abc@123>\" \"An attached email\" ",
            "\"quoted-printable\" 103 (NIL \"Hello world!\" ",
            "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
            "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) ",
            "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) NIL NIL NIL NIL NIL) "
        );
        assert_eq!(
            stored.body_structure(false),
            format!(
                concat!(
                    "(((\"text\" \"plain\" (\"charset\" \"UTF-8\") \"<111@domain.com>\" ",
                    "\"Text part\" \"7bit\" 4 0)",
                    "(\"text\" \"html\" (\"charset\" \"UTF-8\") \"<54535@domain.com>\" ",
                    "\"HTML part\" \"8bit\" 11 0) \"alternative\")",
                    "(\"application\" \"msword\" (\"name\" \"chimichangas.docx\") ",
                    "\"<4444@chimi.changa>\" \"Chimichangas recipe\" \"base64\" 4)",
                    "({}(\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 9 0) 4) ",
                    "\"mixed\")"
                ),
                nested
            )
        );
        assert_eq!(
            stored.body_structure(true),
            format!(
                concat!(
                    "(((\"text\" \"plain\" (\"charset\" \"UTF-8\") \"<111@domain.com>\" ",
                    "\"Text part\" \"7bit\" 4 0 NIL (\"inline\" NIL) \"en-US\" \"right here\")",
                    "(\"text\" \"html\" (\"charset\" \"UTF-8\") \"<54535@domain.com>\" ",
                    "\"HTML part\" \"8bit\" 11 0 NIL ",
                    "(\"attachment\" (\"filename\" \"myfile.txt\")) (\"en-US\" \"de-DE\") ",
                    "\"right there\") \"alternative\" ",
                    "(\"boundary\" \"alt\" \"x-param\" \"a very special parameter\") ",
                    "NIL \"en-US\" \"unknown\")",
                    "(\"application\" \"msword\" (\"name\" \"chimichangas.docx\") ",
                    "\"<4444@chimi.changa>\" \"Chimichangas recipe\" \"base64\" 4 ",
                    "\"Q2hlY2sgSW50ZWdyaXR5IQ==\" ",
                    "(\"attachment\" (\"filename\" \"chimichangas.docx\")) \"en-MX\" ",
                    "\"secret location\")",
                    "({}(\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 9 0 ",
                    "NIL NIL NIL NIL) 4 NIL NIL NIL NIL) ",
                    "\"mixed\" (\"boundary\" \"outer\") NIL NIL NIL)"
                ),
                nested
            )
        );
    }

    #[test]
    fn bodystructure_needs_no_blob() {
        const DIGEST_MESSAGES: usize = 200;
        let mut digest = String::from(concat!(
            "From: digest@example.com\r\n",
            "Subject: digest\r\n",
            "Content-Type: multipart/digest; boundary=\"d\"\r\n",
            "\r\n"
        ));
        for index in 0..DIGEST_MESSAGES {
            digest.push_str(&format!(
                "--d\r\n\r\nFrom: m{index}@example.com\r\nSubject: entry {index}\r\n\r\nbody {index}\r\n"
            ));
        }
        digest.push_str("--d--\r\n");
        let encoded = encodify::base64::STANDARD.encode(digest.as_bytes());
        let stored = Stored::new(&format!(
            concat!(
                "From: a@example.com\r\n",
                "Subject: forwarded\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "see attached\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--b\r\n",
                "Content-Type: application/octet-stream\r\n",
                "\r\n",
                "{}\r\n",
                "--b--\r\n"
            ),
            encoded,
            "x".repeat(1024 * 1024)
        ));
        let from_structure = stored.body_structure(true);
        let mut from_row = Vec::new();
        stored
            .row()
            .unarchive()
            .expect("unarchives")
            .write_structure(&mut from_row, true, false);
        assert_eq!(from_structure.as_bytes(), from_row.as_slice());
        for index in 0..DIGEST_MESSAGES {
            assert!(
                from_structure.contains(&format!("\"entry {index}\"")),
                "missing digest entry {index}"
            );
        }
        assert!(from_structure.contains("\"digest\" (\"boundary\" \"d\")"));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Token<'a> {
        Open,
        Close,
        Nil,
        Number,
        Quoted(&'a [u8]),
        Literal(&'a [u8]),
    }

    struct Grammar<'a> {
        bytes: &'a [u8],
        is_utf8: bool,
    }

    impl<'a> Grammar<'a> {
        fn new(bytes: &'a [u8], is_utf8: bool) -> Self {
            Grammar { bytes, is_utf8 }
        }

        fn fail<T>(&self, expected: &str) -> Result<T, String> {
            Err(format!(
                "expected {expected} at {:?}",
                String::from_utf8_lossy(self.bytes.get(..60).unwrap_or(self.bytes))
            ))
        }

        fn token(&mut self) -> Result<Token<'a>, String> {
            if let Some(rest) = self.bytes.strip_prefix(b" ") {
                self.bytes = rest;
            }
            let bytes = self.bytes;
            let (token, rest) = match bytes {
                [b'(', rest @ ..] => (Token::Open, rest),
                [b')', rest @ ..] => (Token::Close, rest),
                [b'N', b'I', b'L', rest @ ..] => (Token::Nil, rest),
                [b'0'..=b'9', ..] => {
                    let len = bytes
                        .iter()
                        .take_while(|byte| byte.is_ascii_digit())
                        .count();
                    (Token::Number, bytes.get(len..).unwrap_or_default())
                }
                [b'"', rest @ ..] => {
                    let mut escaped = false;
                    let mut end = None;
                    for (pos, byte) in rest.iter().enumerate() {
                        if *byte >= 0x80 && !self.is_utf8 {
                            return self.fail("7-bit quoted string");
                        }
                        if matches!(byte, b'\r' | b'\n' | 0) {
                            return self.fail("quoted string without CR, LF or NUL");
                        }
                        match (escaped, byte) {
                            (false, b'\\') => escaped = true,
                            (false, b'"') => {
                                end = Some(pos);
                                break;
                            }
                            (true, b'\\' | b'"') | (false, _) => escaped = false,
                            (true, _) => return self.fail("quoted-specials after a backslash"),
                        }
                    }
                    let Some(end) = end else {
                        return self.fail("closing quote");
                    };
                    let text = rest.get(..end).unwrap_or_default();
                    if std::str::from_utf8(text).is_err() {
                        return self.fail("UTF-8 quoted string");
                    }
                    (Token::Quoted(text), rest.get(end + 1..).unwrap_or_default())
                }
                [b'{', rest @ ..] => {
                    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
                    let len = std::str::from_utf8(rest.get(..digits).unwrap_or_default())
                        .ok()
                        .and_then(|len| len.parse::<usize>().ok());
                    let Some((len, rest)) = len.zip(
                        rest.get(digits..)
                            .and_then(|rest| rest.strip_prefix(b"}\r\n")),
                    ) else {
                        return self.fail("literal");
                    };
                    let Some((text, rest)) = rest.split_at_checked(len) else {
                        return self.fail("literal data");
                    };
                    if text.contains(&0) {
                        return self.fail("literal without NUL");
                    }
                    (Token::Literal(text), rest)
                }
                _ => return self.fail("token"),
            };
            self.bytes = rest;
            Ok(token)
        }

        fn peek(&self) -> Result<Token<'a>, String> {
            Grammar {
                bytes: self.bytes,
                is_utf8: self.is_utf8,
            }
            .token()
        }

        fn expect(&mut self, expected: Token<'_>) -> Result<(), String> {
            if self.token()? == expected {
                Ok(())
            } else {
                self.fail(&format!("{expected:?}"))
            }
        }

        fn string(&mut self) -> Result<&'a [u8], String> {
            match self.token()? {
                Token::Quoted(text) | Token::Literal(text) => Ok(text),
                _ => self.fail("string"),
            }
        }

        fn nstring(&mut self) -> Result<(), String> {
            match self.token()? {
                Token::Quoted(_) | Token::Literal(_) | Token::Nil => Ok(()),
                _ => self.fail("nstring"),
            }
        }

        fn has_more(&self) -> Result<bool, String> {
            Ok(self.peek()? != Token::Close)
        }

        fn number(&mut self) -> Result<(), String> {
            self.expect(Token::Number)
        }

        fn params(&mut self) -> Result<(), String> {
            match self.token()? {
                Token::Nil => Ok(()),
                Token::Open => {
                    self.string()?;
                    self.string()?;
                    while self.peek()? != Token::Close {
                        self.string()?;
                        self.string()?;
                    }
                    self.expect(Token::Close)
                }
                _ => self.fail("body-fld-param"),
            }
        }

        fn address_list(&mut self) -> Result<(), String> {
            match self.token()? {
                Token::Nil => Ok(()),
                Token::Open => {
                    loop {
                        self.expect(Token::Open)?;
                        for _ in 0..4 {
                            self.nstring()?;
                        }
                        self.expect(Token::Close)?;
                        if self.peek()? == Token::Close {
                            break;
                        }
                    }
                    self.expect(Token::Close)
                }
                _ => self.fail("address list"),
            }
        }

        fn envelope(&mut self) -> Result<(), String> {
            self.expect(Token::Open)?;
            self.nstring()?;
            self.nstring()?;
            for _ in 0..6 {
                self.address_list()?;
            }
            self.nstring()?;
            self.nstring()?;
            self.expect(Token::Close)
        }

        fn disposition(&mut self) -> Result<(), String> {
            match self.token()? {
                Token::Nil => Ok(()),
                Token::Open => {
                    self.string()?;
                    self.params()?;
                    self.expect(Token::Close)
                }
                _ => self.fail("body-fld-dsp"),
            }
        }

        fn language(&mut self) -> Result<(), String> {
            match self.token()? {
                Token::Nil | Token::Quoted(_) | Token::Literal(_) => Ok(()),
                Token::Open => {
                    self.string()?;
                    while self.has_more()? {
                        self.string()?;
                    }
                    self.expect(Token::Close)
                }
                _ => self.fail("body-fld-lang"),
            }
        }

        fn body_extension(&mut self) -> Result<(), String> {
            match self.token()? {
                Token::Nil | Token::Number | Token::Quoted(_) | Token::Literal(_) => Ok(()),
                Token::Open => {
                    self.body_extension()?;
                    while self.has_more()? {
                        self.body_extension()?;
                    }
                    self.expect(Token::Close)
                }
                _ => self.fail("body-extension"),
            }
        }

        fn extension_tail(&mut self) -> Result<(), String> {
            if !self.has_more()? {
                return Ok(());
            }
            self.disposition()?;
            if !self.has_more()? {
                return Ok(());
            }
            self.language()?;
            if !self.has_more()? {
                return Ok(());
            }
            self.nstring()?;
            while self.has_more()? {
                self.body_extension()?;
            }
            Ok(())
        }

        fn body(&mut self) -> Result<(), String> {
            self.expect(Token::Open)?;
            match self.peek()? {
                Token::Open => {
                    while self.peek()? == Token::Open {
                        self.body()?;
                    }
                    self.string()?;
                    if self.has_more()? {
                        self.params()?;
                        self.extension_tail()?;
                    }
                }
                Token::Quoted(_) | Token::Literal(_) => {
                    let media = self.token()?;
                    let ctype = self.string_of(media)?.to_ascii_lowercase();
                    let subtype = self.string()?.to_ascii_lowercase();
                    self.params()?;
                    self.nstring()?;
                    self.nstring()?;
                    self.string()?;
                    self.number()?;
                    match (ctype.as_slice(), subtype.as_slice()) {
                        (b"text", _) => {
                            if !matches!(media, Token::Quoted(_)) {
                                return self.fail("media-text as DQUOTE \"TEXT\" DQUOTE");
                            }
                            self.number()?
                        }
                        (b"message", b"rfc822" | b"global") => {
                            if !matches!(media, Token::Quoted(_)) {
                                return self.fail("media-message as DQUOTE \"MESSAGE\" DQUOTE");
                            }
                            self.envelope()?;
                            self.body()?;
                            self.number()?;
                        }
                        _ => (),
                    }
                    if self.has_more()? {
                        self.nstring()?;
                        self.extension_tail()?;
                    }
                }
                _ => return self.fail("body (a multipart needs at least one body)"),
            }
            self.expect(Token::Close)
        }

        fn string_of(&self, token: Token<'a>) -> Result<&'a [u8], String> {
            match token {
                Token::Quoted(text) | Token::Literal(text) => Ok(text),
                _ => self.fail("string"),
            }
        }

        fn check_body(bytes: &[u8], is_utf8: bool) -> Result<(), String> {
            let mut grammar = Grammar::new(bytes, is_utf8);
            grammar.body()?;
            if grammar.bytes.is_empty() {
                Ok(())
            } else {
                grammar.fail("end of body")
            }
        }

        fn check_envelope(bytes: &[u8], is_utf8: bool) -> Result<(), String> {
            let mut grammar = Grammar::new(bytes, is_utf8);
            grammar.envelope()?;
            if grammar.bytes.is_empty() {
                Ok(())
            } else {
                grammar.fail("end of envelope")
            }
        }
    }

    const EDGE_CASES: &[&str] = &[
        concat!(
            "From: digest@example.com\r\n",
            "Content-Type: multipart/digest; boundary=\"d\"\r\n",
            "\r\n",
            "--d\r\n",
            "\r\n",
            "From: m1@example.com\r\n",
            "Subject: entry 1\r\n",
            "\r\n",
            "body 1\r\n",
            "--d\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "--d\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "a note\r\n",
            "--d--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: message/global\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: message/delivery-status\r\n",
            "\r\n",
            "Reporting-MTA: dns; x\r\n",
            "--b\r\n",
            "Content-Type: multipart/alternative; boundary=\"missing\"\r\n",
            "\r\n",
            "no delimiter here\r\n",
            "--b\r\n",
            "Content-Type: image\r\n",
            "\r\n",
            "GIF89a\r\n",
            "--b\r\n",
            "Content-Type: text; charset=utf-8\r\n",
            "\r\n",
            "no subtype\r\n",
            "--b\r\n",
            "Content-Type: multipart; boundary=\"n\"\r\n",
            "\r\n",
            "--n\r\n",
            "\r\n",
            "nested\r\n",
            "--n--\r\n",
            "--b--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"zz\"\r\n",
            "\r\n",
            "no parts here\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: message/delivery-status\r\n",
            "\r\n",
            "Reporting-MTA: dns; x\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"z\"\r\n",
            "\r\n",
            "--z--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"z\"\r\n",
            "\r\n",
            "preamble\r\n",
            "--z--\r\n",
            "epilogue\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"z\"\r\n",
            "\r\n",
            "--z\r\n",
            "--z--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"z\"\r\n",
            "\r\n",
            "--z\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"z\"\r\n",
            "\r\n",
            "--z"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"o\"\r\n",
            "\r\n",
            "--o\r\n",
            "Content-Type: multipart/alternative; boundary=\"z\"\r\n",
            "\r\n",
            "--z--\r\n",
            "--o\r\n",
            "Content-Type: multipart/related; boundary=\"y\"\r\n",
            "\r\n",
            "--y\r\n",
            "--o--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: b@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"z\"\r\n",
            "\r\n",
            "--z--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: s\r\n",
            "Content-Type: te\u{0}xt/pl\u{0}ain\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: s\r\n",
            "Content-Type: text/plain; n\u{0}m=x; name*=utf-8''a%00b\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: s\r\n",
            "Content-Type: application/x\u{0}y; n\u{0}m=\"v\u{0}w\"\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: s\r\n",
            "Content-ID: <a\u{0}b@x>\r\n",
            "Content-Description: d\u{0}e =?utf-8?Q?a=00b?=\r\n",
            "Content-Transfer-Encoding: 7b\u{0}it\r\n",
            "Content-MD5: a\u{0}b\r\n",
            "Content-Disposition: inl\u{0}ine; file\u{0}name=\"a\u{0}b\"\r\n",
            "Content-Language: e\u{0}n\r\n",
            "Content-Location: x\u{0}y\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: s\r\n",
            "Content-Language: e\u{0}n, d\u{0}e\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: s\r\n",
            "Content-Language: e\"n, d\\e\r\n",
            "Content-Location: a\"b\\c\r\n",
            "Content-MD5: a\"b\r\n",
            "Content-Disposition: \"att\\\"ach\"; x=\"a\\\"b\"\r\n",
            "Content-Description: =?utf-8?Q?a=0D=0Ab?=\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"; x\u{0}=\"y\u{0}\"\r\n",
            "Content-Disposition: inl\u{0}ine\r\n",
            "Content-Language: e\u{0}n\r\n",
            "Content-Location: l\u{0}c\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822; x=\"\u{0}\"\r\n",
            "Content-ID: <\u{0}@x>\r\n",
            "Content-MD5: \u{0}\r\n",
            "\r\n",
            "From: \"n\u{0}m\" <m\u{0}@x\u{0}.com>\r\n",
            "Subject: in\u{0}ner\r\n",
            "\r\n",
            "x\r\n",
            "--b--\r\n"
        ),
        concat!(
            "Date: not\u{0}a date\r\n",
            "Subject: a\u{0}b\r\n",
            "From: \"f\u{0}n\" <f\u{0}l@f\u{0}h.com>\r\n",
            "Sender: s\u{0}l@example.com\r\n",
            "Reply-To: r\u{0}l@example.com\r\n",
            "To: \"x\u{0}y\" <l\u{0}p@h\u{0}st.com>, gr\u{0}oup: a\u{0}@b.c;\r\n",
            "Cc: <@r\u{0}oute:c\u{0}c@example.com>\r\n",
            "Bcc: b\u{0}cc@example.com\r\n",
            "In-Reply-To: <c\u{0}d@x>\r\n",
            "Message-ID: <a\u{0}b@example.com>\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: =?utf-8?Q?a=00b?=\r\n",
            "To: =?utf-8?Q?n=00m?= <t@example.com>\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "body\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Message-ID: <a\"b\\c@example.com>\r\n",
            "In-Reply-To: <\"q\"@x>\r\n",
            "To: \"a\\\"b\"@example.com, <\"q\\\\r\"@example.com>\r\n",
            "Cc: J\u{f6}rg <j\u{f6}rg@m\u{fc}nchen.de>\r\n",
            "Bcc: <@route1,@route2:user@example.com>\r\n",
            "Date: caf\u{e9}\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "body\r\n"
        ),
    ];

    const PART_CAP_OVERFLOWS: [usize; 6] = [0, 1, 2, 3, 4, 5];
    const PART_CAP_FILLER: usize = 9_996;
    const TRUNCATING_HEADERS: usize = 16_400;

    fn part_cap_overflow(extra: usize) -> String {
        let mut message = String::from(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"m\"\r\n",
            "\r\n"
        ));
        for _ in 0..PART_CAP_FILLER + extra {
            message.push_str("--m\r\n\r\nx\r\n");
        }
        message.push_str(concat!(
            "--m\r\n",
            "Content-Type: multipart/alternative; boundary=\"n\"\r\n",
            "\r\n",
            "--n\r\n",
            "\r\n",
            "a\r\n",
            "--n\r\n",
            "\r\n",
            "b\r\n",
            "--n--\r\n",
            "--m\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: q@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"q\"\r\n",
            "\r\n",
            "--q\r\n",
            "\r\n",
            "q\r\n",
            "--q--\r\n",
            "--m--\r\n"
        ));
        message
    }

    fn truncated_envelopes() -> Vec<String> {
        let junk = (0..TRUNCATING_HEADERS)
            .map(|index| format!("X-Junk: {index}\r\n"))
            .collect::<String>();
        EDGE_CASES
            .iter()
            .filter(|message| message.contains("Subject") || message.contains("Message-ID"))
            .map(|message| format!("{junk}{message}"))
            .collect()
    }

    fn encoded_nesting(levels: usize) -> String {
        let mut body = String::from("From: z@example.com\r\nSubject: deepest\r\n\r\nbody\r\n");
        for level in 0..levels {
            body = format!(
                concat!(
                    "From: l{}@example.com\r\n",
                    "Content-Type: message/rfc822\r\n",
                    "Content-Transfer-Encoding: base64\r\n",
                    "\r\n",
                    "{}\r\n"
                ),
                level,
                encodify::base64::STANDARD.encode(body.as_bytes())
            );
        }
        body
    }

    fn fixtures() -> Vec<String> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/resources/imap");
        let mut messages = std::fs::read_dir(dir)
            .expect("fixture directory")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|extension| extension == "txt"))
            .map(|path| {
                String::from_utf8_lossy(&std::fs::read(&path).expect("fixture reads")).into_owned()
            })
            .collect::<Vec<_>>();
        assert!(messages.len() > 10);
        messages.extend(EDGE_CASES.iter().map(|message| message.to_string()));
        messages.push(encoded_nesting(5));
        messages.extend(PART_CAP_OVERFLOWS.map(part_cap_overflow));
        messages
    }

    #[test]
    fn every_body_structure_matches_the_rfc_9051_grammar() {
        let truncated = truncated_envelopes();
        assert!(truncated.len() > 5);
        for message in fixtures().into_iter().chain(truncated) {
            let stored = Stored::new(&message);
            for is_utf8 in [false, true] {
                for is_extended in [false, true] {
                    let structure = stored.structure_bytes(is_extended, is_utf8);
                    if let Err(err) = Grammar::check_body(&structure, is_utf8) {
                        panic!(
                            "{err}\nstructure: {}\nmessage: {message:.300}",
                            String::from_utf8_lossy(&structure)
                        );
                    }
                }
                for envelope in [
                    stored.envelope_with_headers(is_utf8),
                    stored.envelope_bytes(is_utf8),
                ] {
                    if let Err(err) = Grammar::check_envelope(&envelope, is_utf8) {
                        panic!(
                            "{err}\nenvelope: {}\nmessage: {message:.300}",
                            String::from_utf8_lossy(&envelope)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn grammar_rejects_zero_child_multiparts_and_nul() {
        for (bytes, is_utf8) in [
            (&b"( \"mixed\")"[..], false),
            (b"( \"mixed\" (\"boundary\" \"z\") NIL NIL NIL)", false),
            (b"()", false),
            (b"(\"te\0xt\" \"plain\" NIL NIL NIL \"7bit\" 6 1)", true),
            (b"(\"text\" {5}\r\npl\0in NIL NIL NIL \"7bit\" 6 1)", true),
            (b"({4}\r\ntext \"plain\" NIL NIL NIL \"7bit\" 6 1)", true),
            (
                b"(\"text\" \"plain\" NIL NIL NIL \"7bit\" 6 1 NIL (\"a\"))",
                true,
            ),
        ] {
            assert!(
                Grammar::check_body(bytes, is_utf8).is_err(),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        assert!(
            Grammar::check_envelope(b"(NIL \"a\0b\" NIL NIL NIL NIL NIL NIL NIL NIL)", true)
                .is_err()
        );
        assert!(
            Grammar::check_body(
                b"((\"text\" \"plain\" NIL NIL NIL \"7bit\" 0 0 NIL (\"inline\" NIL) (\"en\" \"de\") NIL 1 (2 \"x\")) \"mixed\" NIL NIL NIL NIL)",
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn zero_child_multiparts_write_an_empty_body() {
        const EMPTY_TEXT: &str =
            "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0";
        let [
            ..,
            zero_close,
            zero_preamble,
            _,
            open_eof,
            open_eof_without_crlf,
            nested,
            in_rfc,
        ] = EDGE_CASES.get(..11).unwrap_or_default()
        else {
            panic!("edge cases");
        };
        for message in [zero_close, zero_preamble, open_eof, open_eof_without_crlf] {
            let stored = Stored::new(message);
            assert_eq!(
                stored.body_structure(false),
                format!("({EMPTY_TEXT}) \"mixed\")"),
                "{message:?}"
            );
            assert_eq!(
                stored.body_structure(true),
                format!(
                    "({EMPTY_TEXT} NIL NIL NIL NIL) \"mixed\" (\"boundary\" \"z\") NIL NIL NIL)"
                ),
                "{message:?}"
            );
        }
        assert_eq!(
            Stored::new(nested).body_structure(false),
            format!("(({EMPTY_TEXT}) \"alternative\")({EMPTY_TEXT}) \"related\") \"mixed\")")
        );
        assert!(
            Stored::new(in_rfc)
                .body_structure(false)
                .ends_with(&format!(" ({EMPTY_TEXT}) \"mixed\") 4)")),
        );
        let capped = Stored::new(&part_cap_overflow(2)).body_structure(false);
        assert!(
            capped.ends_with(&format!("({EMPTY_TEXT}) \"alternative\") \"mixed\")")),
            "{:?}",
            capped.get(capped.len().saturating_sub(200)..)
        );
    }

    #[test]
    fn nul_octets_never_reach_envelope_or_body_structure() {
        let [
            ..,
            type_nul,
            param_nul,
            basic_nul,
            fields_nul,
            languages_nul,
            _,
            multipart_nul,
            envelope_nul,
            encoded_nul,
            _,
        ] = EDGE_CASES
        else {
            panic!("edge cases");
        };
        for message in [
            type_nul,
            param_nul,
            basic_nul,
            fields_nul,
            languages_nul,
            multipart_nul,
            envelope_nul,
            encoded_nul,
        ] {
            let junk = (0..TRUNCATING_HEADERS)
                .map(|index| format!("X-Junk: {index}\r\n"))
                .collect::<String>();
            for message in [message.to_string(), format!("{junk}{message}")] {
                let stored = Stored::new(&message);
                for is_utf8 in [false, true] {
                    for output in [
                        stored.structure_bytes(false, is_utf8),
                        stored.structure_bytes(true, is_utf8),
                        stored.envelope_bytes(is_utf8),
                        stored.envelope_with_headers(is_utf8),
                    ] {
                        assert!(
                            !output.contains(&0),
                            "{}\nmessage: {message:.200}",
                            String::from_utf8_lossy(&output)
                        );
                    }
                }
            }
        }
        assert_eq!(
            String::from_utf8(Stored::new(envelope_nul).envelope_with_headers(false)),
            Ok(concat!(
                "(\"nota date\" \"ab\" ((\"fn\" NIL \"fl\" \"fh.com\")) ",
                "((NIL NIL \"sl\" \"example.com\")) ((NIL NIL \"rl\" \"example.com\")) ",
                "((\"xy\" NIL \"lp\" \"hst.com\")(NIL NIL \"group\" NIL)(NIL NIL \"a\" \"b.c\")(NIL NIL NIL NIL)) ",
                "((NIL \"@route\" \"cc\" \"example.com\")) ((NIL NIL \"bcc\" \"example.com\")) ",
                "\"<cd@x>\" \"<ab@example.com>\")"
            )
            .to_string())
        );
        assert_eq!(
            Stored::new(type_nul).body_structure(false),
            "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 1)"
        );
    }

    #[test]
    fn leaves_use_declared_types_and_valid_defaults() {
        let [digest, mixed, no_delimiter, delivery_status, ..] = EDGE_CASES else {
            panic!("edge cases");
        };
        assert_eq!(
            Stored::new(digest).body_structure(false),
            concat!(
                "((\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 48 ",
                "(NIL \"entry 1\" ((NIL NIL \"m1\" \"example.com\")) ",
                "((NIL NIL \"m1\" \"example.com\")) ((NIL NIL \"m1\" \"example.com\")) ",
                "NIL NIL NIL NIL NIL) ",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 0) 3)",
                "(\"message\" \"rfc822\" NIL NIL NIL \"base64\" 0 ",
                "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) ",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0) 0)",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 0) ",
                "\"digest\")"
            )
        );
        assert_eq!(
            Stored::new(mixed).body_structure(false),
            concat!(
                "((\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 0 ",
                "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) ",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0) 0)",
                "(\"message\" \"global\" NIL NIL NIL \"base64\" 0 ",
                "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) ",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0) 0)",
                "(\"message\" \"delivery-status\" NIL NIL NIL \"7bit\" 21)",
                "(\"text\" \"plain\" (\"boundary\" \"missing\") NIL NIL \"7bit\" 17 0)",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 0)",
                "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 10 0)",
                "((\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 6 0) ",
                "\"mixed\") \"mixed\")"
            )
        );
        assert_eq!(
            Stored::new(no_delimiter).body_structure(true),
            concat!(
                "(\"text\" \"plain\" (\"boundary\" \"zz\") NIL NIL \"7bit\" 15 1 ",
                "NIL NIL NIL NIL)"
            )
        );
        assert_eq!(
            Stored::new(delivery_status).body_structure(false),
            "(\"message\" \"delivery-status\" NIL NIL NIL \"7bit\" 23)"
        );

        let level = |level: usize, octets: usize| {
            format!(
                concat!(
                    "(\"message\" \"rfc822\" NIL NIL NIL \"base64\" {} ",
                    "(NIL NIL ((NIL NIL \"l{}\" \"example.com\")) ",
                    "((NIL NIL \"l{}\" \"example.com\")) ",
                    "((NIL NIL \"l{}\" \"example.com\")) NIL NIL NIL NIL NIL) "
                ),
                octets, level, level, level
            )
        };
        assert_eq!(
            Stored::new(&encoded_nesting(5)).body_structure(false),
            format!(
                concat!(
                    "{}{}{}",
                    "(\"message\" \"rfc822\" NIL NIL NIL \"base64\" 210 ",
                    "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) ",
                    "(\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 0 0) 1)",
                    " 1) 1) 1)"
                ),
                level(3, 998),
                level(2, 658),
                level(1, 402)
            )
        );
    }

    #[test]
    fn eight_bit_fields_are_literals_without_utf8() {
        let stored = Stored::new(concat!(
            "From: Jos\u{e9} <jos\u{e9}@ex\u{e4}mple.com>\r\n",
            "To: <\"route\"@example.com>, plain@example.com\r\n",
            "Subject: caf\u{e9}\r\n",
            "Message-ID: <\u{e9}t\u{e9}@example.com>\r\n",
            "In-Reply-To: <a@b> <\u{fc}@example.com>\r\n",
            "Content-Type: text/plain; charset=utf-8; na\u{ef}ve=\"caf\u{e9}\"\r\n",
            "Content-MD5: caf\u{e9}\r\n",
            "Content-Disposition: attachment; filename=\"r\u{e9}sum\u{e9}.txt\"\r\n",
            "Content-Language: en, fr-\u{e9}\r\n",
            "Content-Location: caf\u{e9}/menu\r\n",
            "\r\n",
            "x\r\n"
        ));
        for is_utf8 in [false, true] {
            let structure = stored.structure_bytes(true, is_utf8);
            Grammar::check_body(&structure, is_utf8)
                .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(&structure)));
            let envelope = stored.envelope_with_headers(is_utf8);
            Grammar::check_envelope(&envelope, is_utf8)
                .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(&envelope)));
        }
        let structure = String::from_utf8(stored.structure_bytes(true, false)).expect("utf-8");
        for literal in [
            "{5}\r\ncaf\u{e9} ",
            "{5}\r\nfr-\u{e9})",
            "{10}\r\ncaf\u{e9}/menu)",
        ] {
            assert!(structure.contains(literal), "{literal:?} in {structure}");
        }
        let envelope = String::from_utf8(stored.envelope_with_headers(false)).expect("utf-8");
        for literal in [
            "{5}\r\njos\u{e9} {12}\r\nex\u{e4}mple.com)",
            "{19}\r\n<\u{e9}t\u{e9}@example.com>)",
            "{22}\r\n<a@b> <\u{fc}@example.com> ",
        ] {
            assert!(envelope.contains(literal), "{literal:?} in {envelope}");
        }
        let structure = String::from_utf8(stored.structure_bytes(true, true)).expect("utf-8");
        assert!(structure.contains("\"caf\u{e9}\" "), "{structure}");
    }

    #[test]
    fn envelope_falls_back_to_section_b_when_caps_were_hit() {
        let subject = "s".repeat(MAX_VALUE_LEN + 1);
        let to = (0..1_100)
            .map(|index| format!("r{index}@example.com"))
            .collect::<Vec<_>>()
            .join(",\r\n ");
        let stored = Stored::new(&format!(
            concat!(
                "From: a@example.com\r\n",
                "To: {}\r\n",
                "Subject: {}\r\n",
                "Message-ID: <id@example.com>\r\n",
                "\r\n",
                "body\r\n"
            ),
            to, subject
        ));
        let row = stored.row();
        assert!(
            row.unarchive()
                .expect("unarchives")
                .completeness()
                .is_truncated()
        );

        let envelope = String::from_utf8(stored.envelope_with_headers(false)).expect("utf-8");
        Grammar::check_envelope(envelope.as_bytes(), false).expect("valid envelope");
        assert!(envelope.contains(&format!("\"{subject}\"")));
        for index in [0, 1_023, 1_024, 1_099] {
            assert!(
                envelope.contains(&format!("(NIL NIL \"r{index}\" \"example.com\")")),
                "r{index}"
            );
        }
        assert!(envelope.ends_with(" NIL \"<id@example.com>\")"));

        let stored_only = stored.envelope();
        assert!(!stored_only.contains(&format!("\"{subject}\"")));
        assert!(!stored_only.contains("(NIL NIL \"r1099\" \"example.com\")"));
    }

    #[test]
    fn envelope_from_headers_matches_the_stored_envelope() {
        let mut messages = fixtures();
        messages.extend([
            concat!(
                "Date:\r\n",
                "Subject:\r\n",
                "In-Reply-To:\r\n",
                "Message-ID:\r\n",
                "From: a@example.com\r\n",
                "To: b@example.com\r\n\r\nbody\r\n"
            )
            .to_string(),
            concat!(
                "Date: not a date\r\n",
                "Subject: hello\r\n",
                "In-Reply-To: <a@b> <c@d>\r\n",
                "Message-ID: <e@f>\r\n",
                "Message-ID: <g@h>\r\n",
                "From: a@example.com\r\n",
                "From: Second <second@example.com>\r\n",
                "Sender: Friends: ;\r\n",
                "To: Friends and Family: John Doe <jdoe@example.com>;\r\n",
                "Cc: no-at-sign, route@[1.2.3.4]\r\n\r\nbody\r\n"
            )
            .to_string(),
            "Subject: no from\r\n\r\nbody\r\n".to_string(),
        ]);
        for message in messages {
            let stored = Stored::new(&message);
            for is_utf8 in [false, true] {
                let mut expected = Vec::new();
                stored
                    .structure()
                    .unarchive()
                    .expect("unarchives")
                    .write_envelope(&mut expected, None, is_utf8);
                assert_eq!(
                    String::from_utf8_lossy(&stored.envelope_from_headers(is_utf8)),
                    String::from_utf8_lossy(&expected),
                    "{message:.300}"
                );
            }
        }
    }
}
