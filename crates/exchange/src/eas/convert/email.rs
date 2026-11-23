/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    body::{BodyChoice, char_prefix},
    flag::{LastVerb, StoredMail, rendered_flag},
};
use crate::{
    ews::calendar::invitation::{MeetingMethod, meeting_part, within_limit},
    mail::AccountCategories,
};
use calcard::icalendar::ICalendar;
use compact_str::CompactString;
use email::message::metadata::{
    AddressHeader, Addresses, ArchivedMessageMetadata, BodyList, MessageView, Occurrence, PartKind,
    PartView, RawMessage,
};
use exchange_proto::{
    common::time::UtcSeconds,
    convert::{
        conversation::ConversationIndex,
        ical::{
            MeetingRole,
            eas::{MeetingHistory, MeetingKind, meeting_request_to_eas},
            event_meeting_role,
        },
    },
    eas::{
        commands::{
            appdata::{
                Compact, List, Opaque,
                base::{Attachment, AttachmentEntry, Attachments},
                email::{Email, MeetingRequest},
                note::Note,
            },
            find::FindMailProperties,
        },
        tokens::ProtocolVersion,
        types::EasDateTime,
    },
    ids::eas::EasServerId,
};
use smallvec::SmallVec;
use std::{borrow::Cow, fmt::Write};

const MESSAGE_CLASS: &str = "IPM.Note";
pub const MESSAGE_CLASS_NOTE: &str = "IPM.StickyNote";
const MESSAGE_CLASS_SMIME: &str = "IPM.Note.SMIME";
const MESSAGE_CLASS_SMIME_SIGNED: &str = "IPM.Note.SMIME.MultipartSigned";
const MESSAGE_CLASS_MEETING_REQUEST: &str = "IPM.Schedule.Meeting.Request";
const MESSAGE_CLASS_MEETING_CANCELED: &str = "IPM.Schedule.Meeting.Canceled";
const CONTENT_CLASS: &str = "urn:content-classes:message";
const CONTENT_CLASS_MEETING: &str = "urn:content-classes:calendarmessage";
const INTERNET_CPID_UTF8: &str = "65001";
const IMPORTANCE_LOW: u8 = 0;
const IMPORTANCE_NORMAL: u8 = 1;
const IMPORTANCE_HIGH: u8 = 2;
const ATTACHMENT_METHOD_NORMAL: u8 = 1;
const ATTACHMENT_METHOD_EMBEDDED: u8 = 5;
const DEFAULT_ATTACHMENT_NAME: &str = "attachment";
const EML_EXTENSION: &str = ".eml";
pub(crate) const NATIVE_PLAIN: u8 = 1;
const NATIVE_HTML: u8 = 2;
const CONVERSATION_ID_LEN: usize = 16;
const FIND_PREVIEW_CHARS: usize = 255;
const ADDRESS_SEPARATOR: &str = ", ";
const REPLY_TO_SEPARATOR: &str = ";";

#[derive(Debug, Clone, Copy)]
pub struct MailFlags<'a> {
    pub read: bool,
    pub flagged: bool,
    pub answered: bool,
    pub forwarded: bool,
    pub stored: Option<&'a StoredMail>,
    pub categories: &'a [CompactString],
    pub names: AccountCategories<'a>,
}

impl<'a> MailFlags<'a> {
    pub fn apply(&self, email: &mut Email<'a>) {
        email.read = Some(self.read);
        email.flag = Some(rendered_flag(
            self.flagged,
            self.stored.and_then(|stored| stored.flag.as_ref()),
        ));
        let verb = self.stored.and_then(|stored| stored.verb);
        email.last_verb_executed = verb
            .map(|verb| verb.verb)
            .or(if self.answered {
                Some(LastVerb::ReplyToSender)
            } else if self.forwarded {
                Some(LastVerb::Forward)
            } else {
                None
            })
            .map(LastVerb::eas);
        email.last_verb_execution_time = verb.and_then(|verb| verb.time);
        email.categories = Some(self.category_list());
    }

    fn category_list<const ITEM: u16>(&self) -> List<Cow<'a, str>, ITEM> {
        List(self.names.resolve(self.categories).collect())
    }

    pub fn change(&self) -> Email<'a> {
        let mut email = Email::default();
        self.apply(&mut email);
        email
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MeetingPart {
    kind: MeetingKind,
    part_id: u32,
    blob_end: usize,
}

impl MeetingPart {
    pub fn find(meta: &ArchivedMessageMetadata, max_size: usize) -> Option<Self> {
        let (method, part) = meeting_part(meta)?;
        let kind = match method {
            MeetingMethod::Request => MeetingKind::Request,
            MeetingMethod::Cancel => MeetingKind::Cancellation,
            MeetingMethod::Reply => return None,
        };
        if !within_limit(&part, max_size) {
            return None;
        }
        Some(MeetingPart {
            kind,
            part_id: part.id(),
            blob_end: meta.blob_range(part.body_range())?.end,
        })
    }

    pub fn blob_end(&self) -> usize {
        self.blob_end
    }

    pub fn is_request(&self) -> bool {
        self.kind == MeetingKind::Request
    }

    pub fn ical(&self, meta: &ArchivedMessageMetadata, raw: RawMessage<'_>) -> Option<ICalendar> {
        let part = meta.part(self.part_id)?;
        let source = meta.source(part.message(), raw)?;
        let text = part.text(&source)?;
        ICalendar::parse(text.text.as_ref()).ok()
    }

    fn message_class(&self) -> &'static str {
        match self.kind {
            MeetingKind::Request => MESSAGE_CLASS_MEETING_REQUEST,
            MeetingKind::Cancellation => MESSAGE_CLASS_MEETING_CANCELED,
        }
    }
}

pub struct ParsedMeeting {
    pub part: MeetingPart,
    pub ical: ICalendar,
    pub history: MeetingHistory,
    pub(crate) inflated_headers: Option<Vec<u8>>,
}

pub struct MailSource<'a, 'r> {
    pub document_id: u32,
    pub thread_id: u32,
    pub received_at: u64,
    pub meta: &'a ArchivedMessageMetadata,
    pub headers: &'r [u8],
    pub raw: Option<RawMessage<'r>>,
    pub meeting: Option<&'a ParsedMeeting>,
}

impl<'a> MailSource<'a, '_> {
    fn message_class(&self) -> &'static str {
        self.meta
            .root()
            .root_part()
            .content_type()
            .and_then(|content_type| {
                let mime_type = content_type.mime_type();
                hashify::map_ignore_case!(
                    mime_type.as_bytes(),
                    &'static str,
                    "multipart/signed" => MESSAGE_CLASS_SMIME_SIGNED,
                    "application/pkcs7-mime" => MESSAGE_CLASS_SMIME,
                    "application/x-pkcs7-mime" => MESSAGE_CLASS_SMIME,
                )
            })
            .copied()
            .unwrap_or(MESSAGE_CLASS)
    }

    fn meeting(
        &self,
        owner: &[String],
        version: ProtocolVersion,
    ) -> Option<(MeetingPart, Option<MeetingRequest<'static>>)> {
        let meeting = self.meeting?;
        let request = match event_meeting_role(&meeting.ical, owner) {
            MeetingRole::Organizer => None,
            MeetingRole::Attendee | MeetingRole::None => Some(meeting_request_to_eas(
                &meeting.ical,
                meeting.part.kind,
                meeting.history,
                version,
            )?),
        };
        Some((meeting.part, request))
    }

    fn header(&self, name: &str) -> Option<&[u8]> {
        self.meta
            .root()
            .root_part()
            .headers()
            .last_named(name, self.headers)
            .and_then(|header| header.raw_value(self.headers))
            .map(<[u8]>::trim_ascii)
    }

    fn conversation_index(&self) -> Opaque<'static> {
        let index = ConversationIndex::resolve(
            self.header("Thread-Index"),
            UtcSeconds(i64::try_from(self.received_at).unwrap_or(i64::MAX)),
            self.thread_id,
        );
        Opaque(Cow::Owned(index.timestamps()))
    }

    fn importance(&self) -> u8 {
        let value = |name: &str| self.header(name);
        if let Some(importance) = value("Importance").and_then(|value| {
            hashify::map_ignore_case!(
                value,
                u8,
                "low" => IMPORTANCE_LOW,
                "normal" => IMPORTANCE_NORMAL,
                "high" => IMPORTANCE_HIGH,
            )
        }) {
            return *importance;
        }
        match value("X-Priority").and_then(<[u8]>::first) {
            Some(b'1' | b'2') => IMPORTANCE_HIGH,
            Some(b'4' | b'5') => IMPORTANCE_LOW,
            _ => IMPORTANCE_NORMAL,
        }
    }

    pub fn note(&self, flags: MailFlags<'a>, body: &BodyChoice) -> Note<'a> {
        Note {
            subject: self.meta.root().envelope().subject().map(Cow::Borrowed),
            body: body.render(self.meta, self.raw.as_ref()),
            message_class: Some(Cow::Borrowed(MESSAGE_CLASS_NOTE)),
            last_modified_date: Some(Compact(self.received_date())),
            categories: Some(flags.category_list()).filter(|categories| !categories.0.is_empty()),
        }
    }

    fn received_date(&self) -> EasDateTime {
        EasDateTime(
            UtcSeconds(i64::try_from(self.received_at).unwrap_or(i64::MAX)),
            0,
        )
    }

    pub fn find(&self, flags: MailFlags<'a>, draft: bool) -> FindMailProperties<'a> {
        let root = self.meta.root();
        let envelope = root.envelope();
        let preview = char_prefix(self.meta.preview().trim(), FIND_PREVIEW_CHARS);
        FindMailProperties {
            subject: envelope.subject().map(Cow::Borrowed),
            date_received: Some(self.received_date()),
            display_to: display_names(envelope.addresses(AddressHeader::To, Occurrence::Last)),
            display_cc: display_names(envelope.addresses(AddressHeader::Cc, Occurrence::Last)),
            display_bcc: display_names(envelope.addresses(AddressHeader::Bcc, Occurrence::Last)),
            importance: Some(self.importance()),
            read: Some(flags.read),
            is_draft: Some(draft),
            preview: (!preview.is_empty()).then_some(Cow::Borrowed(preview)),
            has_attachments: Some(root.attachments().next().is_some()),
            from: format_addresses(envelope.addresses(AddressHeader::From, Occurrence::Last)),
        }
    }

    pub fn email(
        &self,
        flags: MailFlags<'a>,
        body: Option<&BodyChoice>,
        part: Option<&BodyChoice>,
        owner: &[String],
        version: ProtocolVersion,
    ) -> Email<'a> {
        let meeting = self.meeting(owner, version);
        let calendar_part = meeting.as_ref().map(|(meeting, _)| meeting.part_id);
        let (message_class, content_class, meeting_request) = match meeting {
            Some((meeting, request)) => (meeting.message_class(), CONTENT_CLASS_MEETING, request),
            None => (self.message_class(), CONTENT_CLASS, None),
        };
        let root = self.meta.root();
        let envelope = root.envelope();
        let to = envelope.addresses(AddressHeader::To, Occurrence::Last);
        let subject = envelope.subject();
        let has_html = root.html_body().any(|part| part.kind() == PartKind::Html);
        let (rendered, body_part) =
            BodyChoice::render_with_part(body, part, self.meta, self.raw.as_ref());
        let mut email = Email {
            to: format_addresses(to),
            cc: format_addresses(envelope.addresses(AddressHeader::Cc, Occurrence::Last)),
            from: format_addresses(envelope.addresses(AddressHeader::From, Occurrence::Last)),
            reply_to: format_address_list(
                envelope.addresses(AddressHeader::ReplyTo, Occurrence::Last),
                REPLY_TO_SEPARATOR,
            ),
            subject: subject.map(Cow::Borrowed),
            date_received: Some(self.received_date()),
            display_to: display_names(to),
            thread_topic: subject.map(|subject| Cow::Borrowed(mail_parser::thread_name(subject))),
            importance: Some(self.importance()),
            message_class: Some(Cow::Borrowed(message_class)),
            meeting_request,
            internet_cpid: Some(Cow::Borrowed(INTERNET_CPID_UTF8)),
            content_class: Some(Cow::Borrowed(content_class)),
            native_body_type: Some(if has_html { NATIVE_HTML } else { NATIVE_PLAIN }),
            conversation_id: Some(conversation_id(self.thread_id)),
            conversation_index: Some(self.conversation_index()),
            body: rendered,
            body_part,
            ..Default::default()
        };
        let attachments = listed_attachments(root)
            .filter(|part| Some(part.id()) != calendar_part)
            .map(|part| {
                let file_reference = EasServerId {
                    container: self.document_id,
                    id: part.id(),
                }
                .encode();
                let (display_name, method) = attachment_label(&part);
                AttachmentEntry::Attachment(Attachment {
                    display_name: Some(display_name),
                    file_reference: Some(Cow::Owned(file_reference.as_str().to_string())),
                    method: Some(method),
                    estimated_data_size: Some(part.decoded_size()),
                    content_id: part.content_id().map(Cow::Borrowed),
                    content_location: part.content_location().map(Cow::Borrowed),
                    is_inline: (part.kind() == PartKind::InlineBinary).then_some(true),
                    ..Default::default()
                })
            })
            .collect::<Vec<_>>();
        if !attachments.is_empty() {
            email.attachments = Some(Attachments(attachments));
        }
        flags.apply(&mut email);
        email
    }
}

fn conversation_id(thread_id: u32) -> Opaque<'static> {
    let mut id = vec![0u8; CONVERSATION_ID_LEN];
    if let Some(prefix) = id.first_chunk_mut::<4>() {
        *prefix = thread_id.to_be_bytes();
    }
    Opaque(Cow::Owned(id))
}

pub(crate) fn conversation_thread_id(id: &[u8]) -> Option<u32> {
    let (prefix, padding) = id.split_first_chunk::<4>()?;
    (id.len() == CONVERSATION_ID_LEN && padding.iter().all(|byte| *byte == 0))
        .then(|| u32::from_be_bytes(*prefix))
}

pub(crate) fn listed_attachments<'a>(
    root: MessageView<'a>,
) -> impl Iterator<Item = PartView<'a>> + use<'a> {
    let mut listed: SmallVec<[(u32, BodyList); 8]> = root
        .attachments()
        .map(|part| (part.id(), BodyList::Attachments))
        .chain(root.html_body().map(|part| (part.id(), BodyList::Html)))
        .collect();
    listed.sort_unstable_by_key(|(id, _)| *id);
    let inline = root
        .html_body()
        .map(|part| (part, BodyList::Html))
        .chain(root.text_body().map(|part| (part, BodyList::Text)))
        .filter(move |(part, list)| {
            part.kind() == PartKind::InlineBinary && {
                let id = part.id();
                let start = listed.partition_point(|(listed, _)| *listed < id);
                !listed
                    .get(start..)
                    .unwrap_or_default()
                    .iter()
                    .take_while(|(listed, _)| *listed == id)
                    .any(|(_, owner)| *owner == BodyList::Attachments || *list == BodyList::Text)
            }
        })
        .map(|(part, _)| part);
    root.attachments().chain(inline)
}

fn attachment_label<'a>(part: &PartView<'a>) -> (Cow<'a, str>, u8) {
    let name = part.attachment_name().unwrap_or(DEFAULT_ATTACHMENT_NAME);
    if !part.is_message() && !is_message_type(part) {
        return (Cow::Borrowed(name), ATTACHMENT_METHOD_NORMAL);
    }
    let has_extension = name
        .as_bytes()
        .last_chunk::<{ EML_EXTENSION.len() }>()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(EML_EXTENSION.as_bytes()));
    let label = if has_extension {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("{name}{EML_EXTENSION}"))
    };
    (label, ATTACHMENT_METHOD_EMBEDDED)
}

fn is_message_type(part: &PartView<'_>) -> bool {
    part.content_type().is_some_and(|content_type| {
        content_type.ctype().eq_ignore_ascii_case("message")
            && content_type
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rfc822"))
    })
}

fn format_addresses<'a>(addresses: Addresses<'_>) -> Option<Cow<'a, str>> {
    format_address_list(addresses, ADDRESS_SEPARATOR)
}

fn format_address_list<'a>(addresses: Addresses<'_>, separator: &str) -> Option<Cow<'a, str>> {
    let mut out = String::new();
    for mailbox in addresses.mailboxes() {
        let Some(address) = mailbox.address else {
            continue;
        };
        if !out.is_empty() {
            out.push_str(separator);
        }
        match mailbox.name {
            Some(name) if !name.is_empty() => {
                out.push('"');
                for ch in name.chars().filter(|ch| *ch != '"' && *ch != '\\') {
                    out.push(ch);
                }
                let _ = write!(out, "\" <{address}>");
            }
            _ => {
                let _ = write!(out, "<{address}>");
            }
        }
    }
    (!out.is_empty()).then_some(Cow::Owned(out))
}

fn display_names<'a>(addresses: Addresses<'_>) -> Option<Cow<'a, str>> {
    let mut out = String::new();
    for mailbox in addresses.mailboxes() {
        let Some(name) = mailbox
            .name
            .filter(|name| !name.is_empty())
            .or(mailbox.address)
        else {
            continue;
        };
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(name);
    }
    (!out.is_empty()).then_some(Cow::Owned(out))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/convert/email/tests.rs"]
mod tests;
