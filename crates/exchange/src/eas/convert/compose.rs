/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::{
    common::base64::base64_encode_into, convert::conversation::ConversationIndex,
};
use mail_builder::{
    MessageBuilder,
    headers::{address::Address, content_type::ContentType, raw::Raw},
    mime::{BodyPart, MimePart},
};
use mail_parser::{
    MessageParser, MessagePart, MessageRef, PartId, PartKind, PartRole,
    decoders::html::html_to_text,
};
use memchr::memchr2;
use smallvec::SmallVec;
use std::{borrow::Cow, fmt::Write as _, io::Write as _};

const BODY_OPEN: &[u8] = b"<body";
const BODY_CLOSE: &[u8] = b"</body";
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
const DEFAULT_NAME: &str = "attachment";
const MAX_REFERENCES: usize = 32;
const MAX_LINE_LENGTH: usize = 998;
const ENCODING_7BIT: &str = "7bit";
const ENCODING_8BIT: &str = "8bit";
const ENCODING_BINARY: &str = "binary";
const PARAGRAPH: &str = "\r\n\r\n";
const MESSAGE_TYPE_PREFIX: &str = "message/";
const MESSAGE_RFC822: &str = "message/rfc822";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmartMode {
    Reply,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmartOutcome {
    Merged(Vec<u8>),
    Unmerged,
    InvalidClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyThread {
    Linked,
    Unlinked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartFilter {
    All,
    Inline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Related,
    Attached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NewPart<'x> {
    pub(crate) content_type: Cow<'x, str>,
    pub(crate) name: Cow<'x, str>,
    pub(crate) content_id: Option<Cow<'x, str>>,
    pub(crate) content_location: Option<Cow<'x, str>>,
    pub(crate) inline: bool,
    pub(crate) data: Cow<'x, [u8]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum HeaderEdit<T> {
    #[default]
    Keep,
    Remove,
    Set(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewBody<'x> {
    Text(&'x str),
    Html(&'x str),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Overrides<'x> {
    pub(crate) subject: HeaderEdit<&'x str>,
    pub(crate) to: HeaderEdit<Address<'x>>,
    pub(crate) cc: HeaderEdit<Address<'x>>,
    pub(crate) bcc: HeaderEdit<Address<'x>>,
    pub(crate) body: Option<NewBody<'x>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rebuilt {
    pub(crate) raw: Vec<u8>,
    pub(crate) added: SmallVec<[usize; 4]>,
    pub(crate) attachments: usize,
}

pub fn smart_message(client: &[u8], original: &[u8], mode: SmartMode) -> SmartOutcome {
    merge(client, original, mode, ReplyThread::Linked)
}

pub struct SourceThread<'x> {
    pub message_id: Option<&'x str>,
    pub references: Option<&'x [u8]>,
    pub index: Option<ConversationIndex>,
}

pub fn thread_message(client: Vec<u8>, source: &SourceThread<'_>, mode: SmartMode) -> Vec<u8> {
    let Some(parsed) = MessageParser::new().parse_headers(&client) else {
        return client;
    };
    let mut prefix = Vec::new();
    if mode == SmartMode::Reply
        && parsed.in_reply_to().is_none()
        && parsed.references().is_none()
        && let Some(id) = source.message_id
    {
        let _ = write!(prefix, "In-Reply-To: <{id}>\r\nReferences:");
        if let Some(references) = source.references {
            let ids = references
                .split(u8::is_ascii_whitespace)
                .filter(|id| id.first() == Some(&b'<'));
            let skip = ids.clone().count().saturating_sub(MAX_REFERENCES - 1);
            for parent in ids.skip(skip) {
                prefix.push(b' ');
                prefix.extend_from_slice(parent);
            }
        }
        let _ = write!(prefix, " <{id}>\r\n");
    }
    if !parsed.headers().contains("Thread-Index")
        && let Some(index) = &source.index
    {
        prefix.extend_from_slice(b"Thread-Index: ");
        base64_encode_into(index.as_bytes(), &mut prefix);
        prefix.extend_from_slice(b"\r\n");
    }
    if prefix.is_empty() {
        return client;
    }
    prefix.reserve(client.len());
    prefix.extend_from_slice(&client);
    prefix
}

pub fn quote_message(client: &[u8], original: &[u8]) -> SmartOutcome {
    merge(client, original, SmartMode::Reply, ReplyThread::Unlinked)
}

pub fn attach_message(client: &[u8], name: &str, message: &[u8]) -> SmartOutcome {
    let Some(parsed) = MessageParser::new().parse(client) else {
        return SmartOutcome::InvalidClient;
    };
    let client = parsed.root();
    if is_protected(client) {
        return SmartOutcome::Unmerged;
    }
    let attached = [NewPart {
        content_type: Cow::Borrowed(MESSAGE_RFC822),
        name: Cow::Borrowed(name),
        content_id: None,
        content_location: None,
        inline: false,
        data: Cow::Borrowed(message),
    }];
    match rebuild_message(client, &[], &attached, &Overrides::default()) {
        Some(rebuilt) => SmartOutcome::Merged(rebuilt.raw),
        None => SmartOutcome::InvalidClient,
    }
}

fn merge(client: &[u8], original: &[u8], mode: SmartMode, thread: ReplyThread) -> SmartOutcome {
    let parser = MessageParser::new();
    let Some(client) = parser.parse(client) else {
        return SmartOutcome::InvalidClient;
    };
    let client = client.root();
    if is_protected(client) {
        return SmartOutcome::Unmerged;
    }
    let Some(original) = parser.parse(original) else {
        return SmartOutcome::Unmerged;
    };
    let original = original.root();

    let mut builder = copy_headers(client, &Overrides::default());
    if mode == SmartMode::Reply
        && thread == ReplyThread::Linked
        && client.in_reply_to().is_none()
        && client.references().is_none()
        && let Some(threading) = threading(original)
    {
        builder = builder
            .header("In-Reply-To", Raw::new(threading.in_reply_to))
            .header("References", Raw::new(threading.references));
    }

    let mut text = joined(client.text_bodies(), PARAGRAPH);
    let quoted = joined(original.text_bodies(), PARAGRAPH);
    if !quoted.is_empty() {
        if !text.is_empty() {
            text.push_str(PARAGRAPH);
        }
        text.push_str(&quoted);
    }
    builder = builder.text_body(text);

    let mut related = Vec::new();
    let placement = if has_html(client) {
        let mut html = joined(client.html_bodies(), "");
        let mut quoted = String::new();
        for part in original.html_bodies() {
            quoted.push_str(inner_body(&part));
        }
        if !quoted.is_empty() {
            insert_html(&mut html, &quoted);
        }
        related.push(html_part(html));
        Placement::Related
    } else {
        Placement::Attached
    };

    let mut mixed = Vec::new();
    with_parts(&mut related, &mut mixed, client, PartFilter::All, placement);
    match (mode, placement) {
        (SmartMode::Forward, _) => with_parts(
            &mut related,
            &mut mixed,
            original,
            PartFilter::All,
            placement,
        ),
        (SmartMode::Reply, Placement::Related) => with_parts(
            &mut related,
            &mut mixed,
            original,
            PartFilter::Inline,
            placement,
        ),
        (SmartMode::Reply, Placement::Attached) => {}
    }
    set_bodies(&mut builder, related, mixed);
    match builder.write_to_vec() {
        Ok(raw) => SmartOutcome::Merged(raw),
        Err(_) => SmartOutcome::InvalidClient,
    }
}

pub(crate) fn rebuild_message<'x>(
    original: MessageRef<'x>,
    dropped: &[PartId],
    added: &'x [NewPart<'_>],
    overrides: &Overrides<'x>,
) -> Option<Rebuilt> {
    let mut builder = copy_headers(original, overrides);
    if let HeaderEdit::Set(subject) = overrides.subject {
        builder = builder.subject(subject);
    }
    if let HeaderEdit::Set(to) = &overrides.to {
        builder = builder.to(to.clone());
    }
    if let HeaderEdit::Set(cc) = &overrides.cc {
        builder = builder.cc(cc.clone());
    }
    if let HeaderEdit::Set(bcc) = &overrides.bcc {
        builder = builder.bcc(bcc.clone());
    }
    let (text, html) = match overrides.body {
        Some(NewBody::Text(text)) => (Cow::Borrowed(text), None),
        Some(NewBody::Html(html)) => (Cow::Owned(html_to_text(html)), Some(Cow::Borrowed(html))),
        None => (
            Cow::Owned(joined(original.text_bodies(), PARAGRAPH)),
            has_html(original).then(|| Cow::Owned(joined(original.html_bodies(), ""))),
        ),
    };
    builder = builder.text_body(text);
    let mut related = Vec::new();
    let placement = match html {
        Some(html) => {
            related.push(html_part(html));
            Placement::Related
        }
        None => Placement::Attached,
    };
    let mut mixed = Vec::new();
    for part in original.parts() {
        if dropped.contains(&part.id()) {
            continue;
        }
        if let Some(cid) = carried_cid(&part, placement) {
            let target = if cid.is_some() {
                &mut related
            } else {
                &mut mixed
            };
            target.push(mime_part(&part, cid));
        }
    }
    let added_related = added
        .iter()
        .filter(|part| part.is_related(placement))
        .count();
    let mut next_related = related.len().saturating_sub(1);
    let mut next_mixed = next_related + added_related + mixed.len();
    let mut slots = SmallVec::with_capacity(added.len());
    for part in added {
        let (target, next) = if part.is_related(placement) {
            (&mut related, &mut next_related)
        } else {
            (&mut mixed, &mut next_mixed)
        };
        slots.push(*next);
        *next += 1;
        target.push(part.to_mime(placement));
    }
    set_bodies(&mut builder, related, mixed);
    builder.write_to_vec().ok().map(|raw| Rebuilt {
        raw,
        added: slots,
        attachments: next_mixed,
    })
}

impl<T> HeaderEdit<T> {
    fn is_edit(&self) -> bool {
        !matches!(self, HeaderEdit::Keep)
    }
}

impl NewPart<'_> {
    fn is_related(&self, placement: Placement) -> bool {
        self.inline && self.content_id.is_some() && placement == Placement::Related
    }

    fn to_mime(&self, placement: Placement) -> MimePart<'_> {
        let nested = self
            .content_type
            .get(..MESSAGE_TYPE_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(MESSAGE_TYPE_PREFIX));
        let encoding = nested.then(|| nested_encoding(&self.data));
        let mime = MimePart::new(
            ContentType::new(self.content_type.as_ref()),
            BodyPart::Binary(Cow::Borrowed(self.data.as_ref())),
        );
        let mime = match &self.content_id {
            Some(cid) if self.is_related(placement) => {
                inline_part(mime, cid.as_ref(), Some(self.name.as_ref()))
            }
            Some(cid) => mime.attachment(self.name.as_ref()).cid(cid.as_ref()),
            None => mime.attachment(self.name.as_ref()),
        };
        let mime = match &self.content_location {
            Some(location) => mime.location(location.as_ref()),
            None => mime,
        };
        match encoding {
            Some(encoding) => mime.transfer_encoding(encoding),
            None => mime,
        }
    }
}

fn copy_headers<'x>(message: MessageRef<'x>, overrides: &Overrides<'_>) -> MessageBuilder<'x> {
    let mut builder = MessageBuilder::new();
    for header in message.headers().iter() {
        let name = header.raw_name();
        let skipped = hashify::fnc_map_ignore_case!(name.as_bytes(),
            "Content-Type" => { true },
            "Content-Transfer-Encoding" => { true },
            "Content-Disposition" => { true },
            "MIME-Version" => { true },
            "Subject" => { overrides.subject.is_edit() },
            "To" => { overrides.to.is_edit() },
            "Cc" => { overrides.cc.is_edit() },
            "Bcc" => { overrides.bcc.is_edit() },
            _ => false
        );
        if skipped {
            continue;
        }
        let name = hashify::map_ignore_case!(
            name.as_bytes(),
            &str,
            "Message-ID" => "Message-ID",
            "Date" => "Date",
        )
        .copied()
        .unwrap_or(name);
        builder = builder.header(name, Raw::new(unfold(header.raw_value())));
    }
    builder
}

fn has_html(message: MessageRef<'_>) -> bool {
    message
        .html_body()
        .any(|part| matches!(part.kind(), PartKind::Html))
}

fn is_protected(message: MessageRef<'_>) -> bool {
    let Some(ctype) = message.content_type() else {
        return false;
    };
    let subtype = ctype.subtype().unwrap_or_default().as_bytes();
    hashify::fnc_map_ignore_case!(ctype.ctype().as_bytes(),
        "multipart" => { hashify::set_ignore_case!(subtype, "signed", "encrypted") },
        "application" => { hashify::set_ignore_case!(subtype, "pkcs7-mime", "x-pkcs7-mime") },
        _ => false
    )
}

struct Threading {
    in_reply_to: String,
    references: String,
}

fn threading(original: MessageRef<'_>) -> Option<Threading> {
    let id = original.message_id()?;
    let parents = original.references().or_else(|| original.in_reply_to());
    let mut references = String::new();
    if let Some(parents) = parents {
        for parent in parents
            .iter()
            .skip(parents.len().saturating_sub(MAX_REFERENCES - 1))
        {
            let _ = write!(references, "<{parent}> ");
        }
    }
    let _ = write!(references, "<{id}>");
    Some(Threading {
        in_reply_to: format!("<{id}>"),
        references,
    })
}

fn joined<'x>(parts: impl Iterator<Item = Cow<'x, str>>, separator: &str) -> String {
    let mut out = String::new();
    for part in parts {
        if !out.is_empty() {
            out.push_str(separator);
        }
        out.push_str(&part);
    }
    out
}

fn html_part<'x>(html: impl Into<Cow<'x, str>>) -> MimePart<'x> {
    MimePart::new("text/html", BodyPart::Text(html.into()))
}

fn set_bodies<'x>(
    builder: &mut MessageBuilder<'x>,
    mut related: Vec<MimePart<'x>>,
    mixed: Vec<MimePart<'x>>,
) {
    builder.html_body = if related.len() > 1 {
        Some(MimePart::new(
            ContentType::new("multipart/related").attribute("type", "text/html"),
            related,
        ))
    } else {
        related.pop()
    };
    if !mixed.is_empty() {
        builder.attachments = Some(mixed);
    }
}

fn with_parts<'x>(
    related: &mut Vec<MimePart<'x>>,
    mixed: &mut Vec<MimePart<'x>>,
    message: MessageRef<'x>,
    filter: PartFilter,
    placement: Placement,
) {
    for part in message.parts() {
        let Some(cid) = carried_cid(&part, placement) else {
            continue;
        };
        match cid {
            Some(_) => related.push(mime_part(&part, cid)),
            None if filter == PartFilter::All => mixed.push(mime_part(&part, None)),
            None => {}
        }
    }
}

fn carried_cid<'x>(part: &MessagePart<'x>, placement: Placement) -> Option<Option<&'x str>> {
    let inline = match part.role() {
        PartRole::MediaBody => true,
        PartRole::Attachment => part.is_inline(),
        _ => return None,
    };
    Some(
        part.content_id()
            .filter(|_| inline && placement == Placement::Related),
    )
}

fn mime_part<'x>(part: &MessagePart<'x>, cid: Option<&'x str>) -> MimePart<'x> {
    let (content_type, nested) = content_type(part);
    let data = part.decoded();
    let encoding = nested.then(|| nested_encoding(&data));
    let mime = MimePart::new(content_type, BodyPart::Binary(data));
    let mime = match cid {
        Some(cid) => inline_part(mime, cid, part.attachment_name()),
        None => mime.attachment(part.attachment_name().unwrap_or(DEFAULT_NAME)),
    };
    match encoding {
        Some(encoding) => mime.transfer_encoding(encoding),
        None => mime,
    }
}

fn inline_part<'x>(mime: MimePart<'x>, cid: &'x str, name: Option<&'x str>) -> MimePart<'x> {
    let disposition = ContentType::new("inline");
    let disposition = match name {
        Some(name) => disposition.attribute("filename", name),
        None => disposition,
    };
    mime.header("Content-Disposition", disposition).cid(cid)
}

fn content_type<'x>(part: &MessagePart<'x>) -> (ContentType<'x>, bool) {
    let Some(ctype) = part.content_type() else {
        return (ContentType::new(DEFAULT_CONTENT_TYPE), false);
    };
    let name = match ctype.subtype() {
        Some(subtype) => format!("{}/{subtype}", ctype.ctype()),
        None => ctype.ctype().to_string(),
    };
    let mut content_type = ContentType::new(name);
    content_type
        .attributes
        .reserve_exact(ctype.attributes().len());
    for (key, value) in ctype.attributes() {
        content_type = content_type.attribute(key, value);
    }
    (content_type, ctype.ctype().eq_ignore_ascii_case("message"))
}

fn nested_encoding(data: &[u8]) -> &'static str {
    let mut lines = data.split(|&byte| byte == b'\n').peekable();
    while let Some(line) = lines.next() {
        let line = if lines.peek().is_some() {
            match line.strip_suffix(b"\r") {
                Some(line) => line,
                None => return ENCODING_BINARY,
            }
        } else {
            line
        };
        if line.len() > MAX_LINE_LENGTH || memchr2(b'\r', 0, line).is_some() {
            return ENCODING_BINARY;
        }
    }
    if data.is_ascii() {
        ENCODING_7BIT
    } else {
        ENCODING_8BIT
    }
}

fn unfold(value: &[u8]) -> String {
    let value = String::from_utf8_lossy(value);
    let mut out = String::with_capacity(value.len());
    for chunk in value.trim().split(['\r', '\n']) {
        out.push_str(chunk);
    }
    out
}

fn inner_body(html: &str) -> &str {
    let start = find_ignore_case(html.as_bytes(), BODY_OPEN)
        .and_then(|open| {
            html.get(open..)?
                .split_once('>')
                .map(|(_, rest)| html.len() - rest.len())
        })
        .unwrap_or(0);
    let body = html.get(start..).unwrap_or(html);
    match rfind_ignore_case(body.as_bytes(), BODY_CLOSE) {
        Some(end) => body.get(..end).unwrap_or(body),
        None => body,
    }
}

fn insert_html(html: &mut String, quoted: &str) {
    match rfind_ignore_case(html.as_bytes(), BODY_CLOSE) {
        Some(end) => html.insert_str(end, quoted),
        None => html.push_str(quoted),
    }
}

fn find_ignore_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn rfind_ignore_case(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/convert/compose/tests.rs"]
mod tests;
