/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Write};

use bytes::Bytes;
use mail_parser::{
    AddressList, HeaderName, Headers, MessagePart, MessageRef, PartKind, html_to_text,
};

use super::{
    ends_with_ignore_case,
    mdn::{self, Disposition, Mdn},
    smime::{CONTENT_TYPE, MULTIPART_SIGNED, SMIME_FILE_NAME, SUFFIX_SMIME, SUFFIX_SMIME_SIGNED},
    starts_with_ignore_case,
};
use crate::{
    common::guid::Guid,
    common::time::{FileTime, UtcSeconds},
    convert::{
        ConvertError, MAX_EMBED_DEPTH,
        address::{
            Address, AddressTags, FlatEntryListWriter, SENDER, SENT_REPRESENTING, SmtpRecipient,
            set_address, smtp_recipient,
        },
        context::{AddressResolver, BodyPreference, ConvertOptions, TnefPolicy},
        conversation::ConversationIndex,
        ical::{calendar_part_class, merge_meeting_props},
        model::{AttachData, Attachment, MessageContent, PropBag},
        tags::{
            self, CONTENT_CLASS_NAME, LID_INFO_PATH_FORM_NAME, RECIPIENT_FLAG_SENDABLE,
            attach_flags, attach_method, message_flags, native_body, recipient_type,
        },
        tnef::{tnef_message_props, tnef_to_message_at},
    },
    mapi::prop::{
        OwnedPropValue, PropId, PropKey, PropKeyRef, PropType,
        sets::{PS_INTERNET_HEADERS, PSETID_COMMON},
    },
    mapi::recipient::smtp_search_key,
};

const SMTP: &str = "SMTP";
const DEFAULT_CLASS: &str = "IPM.Note";
const CLASS_SMIME_SIGNED: &str = "IPM.Note.SMIME.MultipartSigned";
const CLASS_SMIME: &str = "IPM.Note.SMIME";
const MEETING_CLASS_PREFIX: &str = "IPM.Schedule.Meeting.";
const CUSTOM_CONTENT_CLASS: &str = "urn:content-class:custom.";
const CLASS_CUSTOM: &str = "IPM.Note.Custom.";
const INFO_PATH_CONTENT_CLASS: &str = "InfoPath.";
const CLASS_INFO_PATH: &str = "IPM.InfoPathForm.";
const VOICE_ATTACHMENT_SUBTYPES: [&str; 4] = ["gsm", "mp3", "wav", "wma"];
const TNEF_STORE_OWNED: [PropId; 3] = [
    tags::CONVERSATION_INDEX,
    tags::CHANGE_KEY,
    tags::PREDECESSOR_CHANGE_LIST,
];
const TNEF_BODY_DERIVED: [PropId; 8] = [
    tags::BODY,
    tags::HTML,
    tags::RTF_COMPRESSED,
    tags::RTF_IN_SYNC,
    tags::NATIVE_BODY,
    tags::INTERNET_CODEPAGE,
    tags::HAS_ATTACHMENTS,
    tags::MESSAGE_FLAGS,
];
const CLASS_NDR: &str = "REPORT.IPM.Note.NDR";
const CLASS_DR: &str = "REPORT.IPM.Note.DR";
const P7M_EXTENSION: &str = ".p7m";
const PKCS7_SIGNATURE: &[u8] = b"pkcs7-signature";
const OCTET_STREAM: &str = "application/octet-stream";
const UTF8_CODE_PAGE: i32 = 65001;
const MAX_PREFIX_CHARS: usize = 3;
const HIDDEN_HEADER_PREFIXES: [&str; 2] = ["x-ms-exchange-organization-", "x-ms-exchange-forest-"];
const ALLOWED_HIDDEN_PREFIX: &str = "x-ms-exchange-organization-auth";

struct Context<'r, 'o> {
    resolver: &'r dyn AddressResolver,
    opts: &'r ConvertOptions<'o>,
    decoded: u64,
}

pub(super) fn message(
    msg: MessageRef<'_>,
    resolver: &dyn AddressResolver,
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    let mut context = Context {
        resolver,
        opts,
        decoded: 0,
    };
    context.message(msg, 0)
}

pub fn is_envelope_key(key: PropKeyRef<'_>) -> bool {
    match key {
        PropKeyRef::Tag(id) => matches!(
            id,
            tags::MESSAGE_CLASS
                | tags::SUBJECT
                | tags::SUBJECT_PREFIX
                | tags::NORMALIZED_SUBJECT
                | tags::CONVERSATION_TOPIC
                | tags::CLIENT_SUBMIT_TIME
                | tags::SENT_REPRESENTING_SMTP_ADDRESS
                | tags::SENT_REPRESENTING_SEARCH_KEY
                | tags::SENT_REPRESENTING_ENTRY_ID
                | tags::SENT_REPRESENTING_NAME
                | tags::SENT_REPRESENTING_ADDRESS_TYPE
                | tags::SENT_REPRESENTING_EMAIL_ADDRESS
                | tags::SENDER_SMTP_ADDRESS
                | tags::SENDER_SEARCH_KEY
                | tags::SENDER_ENTRY_ID
                | tags::SENDER_NAME
                | tags::SENDER_ADDRESS_TYPE
                | tags::SENDER_EMAIL_ADDRESS
                | tags::INTERNET_MESSAGE_ID
                | tags::IN_REPLY_TO_ID
                | tags::INTERNET_REFERENCES
                | tags::IMPORTANCE
                | tags::SENSITIVITY
                | tags::READ_RECEIPT_REQUESTED
                | tags::ORIGINATOR_DELIVERY_REPORT_REQUESTED
                | tags::CONVERSATION_INDEX
                | tags::DISPLAY_TO
                | tags::DISPLAY_CC
                | tags::DISPLAY_BCC
                | tags::TRANSPORT_MESSAGE_HEADERS
                | tags::REPLY_RECIPIENT_ENTRIES
                | tags::REPLY_RECIPIENT_NAMES
                | tags::ORIGINAL_DISPLAY_TO
                | tags::ORIGINAL_DELIVERY_TIME
                | tags::RECEIPT_TIME
                | tags::REPORT_TIME
                | tags::REPORT_TEXT
                | tags::PARENT_KEY
                | tags::ORIGINAL_MESSAGE_ID
        ),
        PropKeyRef::Lid { set, lid } => set == PSETID_COMMON && lid == LID_INFO_PATH_FORM_NAME,
        PropKeyRef::Name { set, name } => {
            set == PS_INTERNET_HEADERS && name.eq_ignore_ascii_case(CONTENT_CLASS_NAME)
        }
    }
}

pub(super) fn envelope(msg: MessageRef<'_>, calendar: Option<&'static str>, bag: &mut PropBag) {
    let headers = msg.headers();
    let content_class = raw_text(headers, CONTENT_CLASS_NAME);
    if let Some(value) = content_class {
        bag.set(
            PropKey::internet_header(CONTENT_CLASS_NAME),
            OwnedPropValue::Unicode(value.into()),
        );
    }
    let mdn = Mdn::find(msg);
    let class = message_class(msg, content_class, mdn.as_ref(), calendar, bag);
    set_string(bag, tags::MESSAGE_CLASS, &class);
    if let Some(subject) = headers.subject() {
        let (prefix, normalized) = split_subject(subject);
        set_string(bag, tags::SUBJECT, subject);
        set_string(bag, tags::SUBJECT_PREFIX, prefix);
        set_string(bag, tags::NORMALIZED_SUBJECT, normalized);
        set_string(bag, tags::CONVERSATION_TOPIC, normalized);
    }
    let sent = headers
        .date()
        .filter(|date| date.is_valid())
        .map(|date| FileTime::from_utc(UtcSeconds(date.to_timestamp()), 0));
    if let Some(sent) = sent {
        set(bag, tags::CLIENT_SUBMIT_TIME, OwnedPropValue::Time(sent));
    }
    let from = headers.from().and_then(|list| list.first());
    let sender = headers.sender().and_then(|list| list.first()).or(from);
    if let Some(address) = from.and_then(mailbox) {
        set_mailbox(
            bag,
            &SENT_REPRESENTING,
            tags::SENT_REPRESENTING_SMTP_ADDRESS,
            tags::SENT_REPRESENTING_SEARCH_KEY,
            address,
        );
    }
    if let Some(address) = sender.and_then(mailbox) {
        set_mailbox(
            bag,
            &SENDER,
            tags::SENDER_SMTP_ADDRESS,
            tags::SENDER_SEARCH_KEY,
            address,
        );
    }
    if let Some(id) = headers.message_id() {
        set_string(bag, tags::INTERNET_MESSAGE_ID, &bracketed(id));
    }
    if let Some(id) = headers.in_reply_to().and_then(|ids| ids.first()) {
        set_string(bag, tags::IN_REPLY_TO_ID, &bracketed(id));
    }
    if let Some(ids) = headers.references().filter(|ids| !ids.is_empty()) {
        let mut joined = String::new();
        for id in ids.iter() {
            if !joined.is_empty() {
                joined.push(' ');
            }
            let _ = write!(joined, "<{id}>");
        }
        set_string(bag, tags::INTERNET_REFERENCES, &joined);
    }
    if let Some(importance) = importance(headers) {
        set(bag, tags::IMPORTANCE, OwnedPropValue::I32(importance));
    }
    if let Some(sensitivity) = raw_text(headers, "Sensitivity").and_then(|value| {
        hashify::map_ignore_case!(value.as_bytes(), i32,
            "personal" => 1,
            "private" => 2,
            "company-confidential" => 3,
        )
        .copied()
    }) {
        set(bag, tags::SENSITIVITY, OwnedPropValue::I32(sensitivity));
    }
    if headers.contains("Disposition-Notification-To") {
        set(
            bag,
            tags::READ_RECEIPT_REQUESTED,
            OwnedPropValue::Bool(true),
        );
    }
    if headers.contains("Return-Receipt-To") {
        set(
            bag,
            tags::ORIGINATOR_DELIVERY_REPORT_REQUESTED,
            OwnedPropValue::Bool(true),
        );
    }
    if let Some(index) = headers
        .all("Thread-Index")
        .last()
        .and_then(|header| ConversationIndex::from_thread_index(header.raw_value().trim_ascii()))
    {
        set(
            bag,
            tags::CONVERSATION_INDEX,
            OwnedPropValue::Binary(index.into_bytes()),
        );
    }
    if let Some(list) = headers.reply_to() {
        set_reply_to(bag, list);
    }
    for (id, list) in [
        (tags::DISPLAY_TO, headers.to()),
        (tags::DISPLAY_CC, headers.cc()),
        (tags::DISPLAY_BCC, headers.bcc()),
    ] {
        if let Some(list) = list {
            set_string(bag, id, &display_list(list));
        }
    }
    if let Some(mdn) = mdn {
        mdn.set_props(bag, sent);
    }
    set_string(
        bag,
        tags::TRANSPORT_MESSAGE_HEADERS,
        &transport_headers(msg),
    );
}

impl Context<'_, '_> {
    fn message(&mut self, msg: MessageRef<'_>, depth: u8) -> Result<MessageContent, ConvertError> {
        let mut content = MessageContent::default();
        envelope(msg, None, &mut content.props);
        if is_meeting_class(&content.props)
            && let Some(calendar) = calendar_part(msg).and_then(|part| part.text())
        {
            merge_meeting_props(&calendar, &mut content.props);
        }
        self.recipients(msg, &mut content.recipients);
        let signing = structure_class(msg, None).unwrap_or(Signing::None);
        if !matches!(signing, Signing::Opaque) {
            self.body(msg, &mut content.props)?;
        }
        let is_smime = self.smime(msg, signing, &mut content)?;
        let is_report = mdn::is_report(msg);
        let mut tnef = None;
        for part in msg
            .attachments()
            .filter(|part| !is_smime && !(is_report && mdn::is_notification(*part)))
        {
            if self.opts.tnef == TnefPolicy::Decode && tnef.is_none() && is_tnef(part) {
                let data = self.decode(part)?;
                match tnef_to_message_at(&data, self.opts, depth) {
                    Ok(decoded) if correlates(msg, &decoded.props) => {
                        tnef = Some(decoded);
                        continue;
                    }
                    _ => {
                        content
                            .attachments
                            .push(self.leaf(part, data, Some(OCTET_STREAM)));
                        continue;
                    }
                }
            }
            let attachment = self.attachment(part, depth)?;
            content.attachments.push(attachment);
        }
        if let Some(decoded) = tnef {
            merge_tnef(&mut content, decoded);
        }
        let has_attachments = !content.attachments.is_empty();
        set(
            &mut content.props,
            tags::HAS_ATTACHMENTS,
            OwnedPropValue::Bool(has_attachments),
        );
        set(
            &mut content.props,
            tags::MESSAGE_FLAGS,
            OwnedPropValue::I32(if has_attachments {
                message_flags::HAS_ATTACH
            } else {
                0
            }),
        );
        Ok(content)
    }

    fn recipients(&self, msg: MessageRef<'_>, rows: &mut Vec<PropBag>) {
        let headers = msg.headers();
        for (kind, list) in [
            (recipient_type::TO, headers.to()),
            (recipient_type::CC, headers.cc()),
            (recipient_type::BCC, headers.bcc()),
        ] {
            let Some(list) = list else {
                continue;
            };
            for mailbox in list.mailboxes() {
                let Some(smtp) = mailbox.address() else {
                    continue;
                };
                let resolved = self.resolver.resolve(smtp);
                let name = mailbox
                    .name()
                    .or(resolved.as_ref().map(|resolved| &*resolved.display_name))
                    .unwrap_or(smtp);
                let display_type = resolved
                    .as_ref()
                    .and_then(|resolved| i32::try_from(resolved.display_type).ok())
                    .unwrap_or(0);
                let row = smtp_recipient(SmtpRecipient {
                    kind,
                    name,
                    smtp,
                    display_type,
                    flags: RECIPIENT_FLAG_SENDABLE,
                });
                rows.push(row);
            }
        }
    }

    fn body(&mut self, msg: MessageRef<'_>, bag: &mut PropBag) -> Result<(), ConvertError> {
        let text = msg
            .text_body()
            .find(|part| matches!(part.kind(), PartKind::Text));
        let html = msg
            .html_body()
            .find(|part| matches!(part.kind(), PartKind::Html));
        let html = match html {
            Some(part) => Some(self.charge_text(part)?),
            None => None,
        };
        let text = match text {
            Some(part) => Some(self.charge_text(part)?),
            None => None,
        };
        let preference = self.opts.body_preference;
        let want_text = preference != BodyPreference::Html || html.is_none();
        let want_html = preference != BodyPreference::Text;
        if want_text {
            match (&text, &html) {
                (Some(text), _) => set_string(bag, tags::BODY, text),
                (None, Some(html)) => set_string(bag, tags::BODY, &html_to_text(html)),
                (None, None) => {}
            }
        }
        if let Some(html) = html.filter(|_| want_html) {
            set(
                bag,
                tags::HTML,
                OwnedPropValue::Binary(Bytes::from(html.into_bytes())),
            );
            set(
                bag,
                tags::INTERNET_CODEPAGE,
                OwnedPropValue::I32(UTF8_CODE_PAGE),
            );
            set(
                bag,
                tags::NATIVE_BODY,
                OwnedPropValue::I32(native_body::HTML),
            );
        } else {
            set(
                bag,
                tags::NATIVE_BODY,
                OwnedPropValue::I32(native_body::PLAIN),
            );
        }
        set(bag, tags::RTF_IN_SYNC, OwnedPropValue::Bool(false));
        Ok(())
    }

    fn smime(
        &mut self,
        msg: MessageRef<'_>,
        signing: Signing,
        content: &mut MessageContent,
    ) -> Result<bool, ConvertError> {
        let root = msg.root_part();
        let content_type = root.headers().get(HeaderName::ContentType);
        match (signing, content_type) {
            (Signing::Clear, Some(header)) => {
                let name = header.raw_name().as_bytes();
                let value = header.raw_value();
                let body = root.raw_body();
                let len = name
                    .len()
                    .saturating_add(value.len())
                    .saturating_add(body.len())
                    .saturating_add(3);
                self.charge(len)?;
                let mut entity = Vec::with_capacity(len);
                entity.extend_from_slice(name);
                entity.push(b':');
                entity.extend_from_slice(value);
                entity.extend_from_slice(if value.ends_with(b"\r\n") {
                    b"\r\n"
                } else {
                    b"\n"
                });
                entity.extend_from_slice(body);
                let mut props = PropBag::new();
                set(
                    &mut props,
                    tags::ATTACH_METHOD,
                    OwnedPropValue::I32(attach_method::BY_VALUE),
                );
                set_string(&mut props, tags::ATTACH_MIME_TAG, MULTIPART_SIGNED);
                for id in [
                    tags::ATTACH_FILENAME,
                    tags::ATTACH_LONG_FILENAME,
                    tags::DISPLAY_NAME,
                ] {
                    set_string(&mut props, id, SMIME_FILE_NAME);
                }
                set(
                    &mut props,
                    tags::ATTACH_SIZE,
                    OwnedPropValue::I32(i32::try_from(entity.len()).unwrap_or(i32::MAX)),
                );
                content.attachments.push(Attachment {
                    props,
                    data: AttachData::Bytes(entity.into()),
                });
                Ok(true)
            }
            (Signing::Opaque, header) => {
                if let Some(header) = header {
                    let raw = String::from_utf8_lossy(header.raw_value());
                    let raw = raw.trim();
                    if !raw.is_empty() {
                        content.props.set(
                            PropKey::internet_header(CONTENT_TYPE),
                            OwnedPropValue::Unicode(raw.into()),
                        );
                    }
                }
                let data = self.decode(root)?;
                content.attachments.push(self.leaf(root, data, None));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn attachment(&mut self, part: MessagePart<'_>, depth: u8) -> Result<Attachment, ConvertError> {
        if let PartKind::Message(nested) = part.kind()
            && depth < MAX_EMBED_DEPTH
        {
            let embedded = self.message(nested, depth.saturating_add(1))?;
            let mut props = PropBag::new();
            set(
                &mut props,
                tags::ATTACH_METHOD,
                OwnedPropValue::I32(attach_method::EMBEDDED_MESSAGE),
            );
            set_string(&mut props, tags::ATTACH_MIME_TAG, "message/rfc822");
            let name = part
                .attachment_name()
                .or_else(|| part.content_description())
                .or_else(|| nested.subject())
                .unwrap_or_default();
            set_string(&mut props, tags::DISPLAY_NAME, name);
            return Ok(Attachment {
                props,
                data: AttachData::Embedded(Box::new(embedded)),
            });
        }
        let data = self.decode(part)?;
        Ok(self.leaf(part, data, None))
    }

    fn leaf(&self, part: MessagePart<'_>, data: Vec<u8>, mime_tag: Option<&str>) -> Attachment {
        let mut props = PropBag::new();
        set(
            &mut props,
            tags::ATTACH_METHOD,
            OwnedPropValue::I32(attach_method::BY_VALUE),
        );
        let name = part
            .attachment_name()
            .or_else(|| part.content_description())
            .map(sanitize_file_name)
            .filter(|name| !name.is_empty());
        if let Some(name) = &name {
            set_string(&mut props, tags::ATTACH_LONG_FILENAME, name);
            set_string(&mut props, tags::ATTACH_FILENAME, name);
            if let Some((_, extension)) = name.rsplit_once('.').filter(|(stem, _)| !stem.is_empty())
            {
                set_string(&mut props, tags::ATTACH_EXTENSION, &format!(".{extension}"));
            }
        }
        let content_type = part.content_type();
        match (mime_tag, content_type) {
            (Some(mime_tag), _) => set_string(&mut props, tags::ATTACH_MIME_TAG, mime_tag),
            (None, Some(ctype)) => {
                let subtype = ctype.subtype().unwrap_or_default();
                let tag = if ctype.ctype().eq_ignore_ascii_case("application")
                    && subtype.eq_ignore_ascii_case("ms-tnef")
                {
                    OCTET_STREAM.to_string()
                } else {
                    format!("{}/{}", ctype.ctype(), subtype).to_ascii_lowercase()
                };
                set_string(&mut props, tags::ATTACH_MIME_TAG, &tag);
                if ctype.ctype().eq_ignore_ascii_case("text")
                    && let Some(charset) = ctype.attribute("charset")
                {
                    set_string(&mut props, tags::TEXT_ATTACHMENT_CHARSET, charset);
                }
            }
            (None, None) => {}
        }
        if let Some(id) = part.content_id() {
            set_string(&mut props, tags::ATTACH_CONTENT_ID, id);
        }
        if let Some(location) = part.content_location() {
            set_string(&mut props, tags::ATTACH_CONTENT_LOCATION, location);
        }
        if is_rendered_inline(part) {
            set(
                &mut props,
                tags::ATTACH_FLAGS,
                OwnedPropValue::I32(attach_flags::RENDERED_IN_BODY),
            );
            set(
                &mut props,
                tags::ATTACHMENT_HIDDEN,
                OwnedPropValue::Bool(true),
            );
        }
        set(
            &mut props,
            tags::ATTACH_SIZE,
            OwnedPropValue::I32(i32::try_from(data.len()).unwrap_or(i32::MAX)),
        );
        Attachment {
            props,
            data: AttachData::Bytes(data.into()),
        }
    }

    fn decode(&mut self, part: MessagePart<'_>) -> Result<Vec<u8>, ConvertError> {
        self.charge(part.decoded_len())?;
        Ok(part.decoded().into_owned())
    }

    fn charge_text(&mut self, part: MessagePart<'_>) -> Result<String, ConvertError> {
        self.charge(part.decoded_len())?;
        Ok(part
            .text()
            .map(|text| text.into_owned())
            .unwrap_or_default())
    }

    fn charge(&mut self, len: usize) -> Result<(), ConvertError> {
        self.decoded = self
            .decoded
            .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        if self.decoded > u64::from(self.opts.max_decoded) {
            Err(ConvertError::TooLarge)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
enum Signing {
    None,
    Opaque,
    Clear,
}

#[derive(Clone, Copy)]
enum ClassRequirement {
    Fax,
    Voice,
}

fn message_class(
    msg: MessageRef<'_>,
    content_class: Option<&str>,
    report: Option<&Mdn<'_>>,
    calendar: Option<&'static str>,
    bag: &mut PropBag,
) -> Cow<'static, str> {
    let signing = match structure_class(msg, report) {
        Ok(signing) => signing,
        Err(report) => return Cow::Borrowed(report),
    };
    let Some(base) = calendar
        .or_else(|| calendar_class(msg))
        .map(Cow::Borrowed)
        .or_else(|| content_class.and_then(|value| content_class_base(msg, value, bag)))
    else {
        return Cow::Borrowed(match signing {
            Signing::None => DEFAULT_CLASS,
            Signing::Opaque => CLASS_SMIME,
            Signing::Clear => CLASS_SMIME_SIGNED,
        });
    };
    match signing {
        Signing::None => base,
        Signing::Opaque => Cow::Owned(format!("{base}{SUFFIX_SMIME}")),
        Signing::Clear => Cow::Owned(format!("{base}{SUFFIX_SMIME_SIGNED}")),
    }
}

fn structure_class(msg: MessageRef<'_>, report: Option<&Mdn<'_>>) -> Result<Signing, &'static str> {
    let root = msg.root_part();
    let Some(ctype) = root.content_type() else {
        return Ok(Signing::None);
    };
    let main = ctype.ctype();
    let subtype = ctype.subtype().unwrap_or_default();
    let multipart = || main.eq_ignore_ascii_case("multipart");
    let application = || main.eq_ignore_ascii_case("application");
    hashify::fnc_map_ignore_case!(subtype.as_bytes(),
        "signed" => {
            if multipart()
                && ctype.attribute("protocol").is_some_and(|protocol| {
                    protocol
                        .as_bytes()
                        .windows(PKCS7_SIGNATURE.len())
                        .any(|window| window.eq_ignore_ascii_case(PKCS7_SIGNATURE))
                })
            {
                return Ok(Signing::Clear);
            }
        },
        "report" => {
            if multipart()
                && let Some(kind) = ctype.attribute("report-type")
            {
                hashify::fnc_map_ignore_case!(kind.as_bytes(),
                    "delivery-status" => {
                        return Err(if report_failed(msg) { CLASS_NDR } else { CLASS_DR });
                    },
                    "disposition-notification" => {
                        return Err(report.map_or(Disposition::Read, Mdn::disposition).class());
                    },
                    _ => {}
                );
            }
        },
        "pkcs7-mime" => {
            if application() {
                return Ok(Signing::Opaque);
            }
        },
        "x-pkcs7-mime" => {
            if application() {
                return Ok(Signing::Opaque);
            }
        },
        "octet-stream" => {
            if application()
                && root
                    .attachment_name()
                    .is_some_and(|name| ends_with_ignore_case(name, P7M_EXTENSION))
            {
                return Ok(Signing::Opaque);
            }
        },
        _ => {}
    );
    Ok(Signing::None)
}

fn content_class_base(
    msg: MessageRef<'_>,
    value: &str,
    bag: &mut PropBag,
) -> Option<Cow<'static, str>> {
    if let Some((class, requirement)) = hashify::map_ignore_case!(value.as_bytes(), (&'static str, ClassRequirement),
        "fax" => ("IPM.Note.Microsoft.Fax", ClassRequirement::Fax),
        "fax-ca" => ("IPM.Note.Microsoft.Fax.CA", ClassRequirement::Fax),
        "missedcall" => ("IPM.Note.Microsoft.Missed.Voice", ClassRequirement::Voice),
        "voice-uc" => ("IPM.Note.Microsoft.Conversation.Voice", ClassRequirement::Voice),
        "voice-ca" => ("IPM.Note.Microsoft.Voicemail.UM.CA", ClassRequirement::Voice),
        "voice" => ("IPM.Note.Microsoft.Voicemail.UM", ClassRequirement::Voice),
    ) {
        return meets(msg, *requirement).then_some(Cow::Borrowed(*class));
    }
    if let Some(custom) =
        strip_prefix_ignore_case(value, CUSTOM_CONTENT_CLASS).filter(|custom| !custom.is_empty())
    {
        return Some(Cow::Owned(format!("{CLASS_CUSTOM}{custom}")));
    }
    let (form, name) = value
        .strip_prefix(INFO_PATH_CONTENT_CLASS)?
        .split_once('.')?;
    if name.is_empty() || Guid::parse_text(form.as_bytes()).is_none() {
        return None;
    }
    bag.set(
        PropKey::lid(PSETID_COMMON, LID_INFO_PATH_FORM_NAME),
        OwnedPropValue::Unicode(name.into()),
    );
    Some(Cow::Owned(format!("{CLASS_INFO_PATH}{form}")))
}

fn meets(msg: MessageRef<'_>, requirement: ClassRequirement) -> bool {
    match requirement {
        ClassRequirement::Fax => {
            let root = msg.root_part();
            let mut children = root.children();
            root.is_content_type("multipart", "mixed")
                && children.len() == 2
                && children
                    .next()
                    .is_some_and(|part| part.is_content_type("text", "html"))
                && children
                    .next()
                    .is_some_and(|part| part.is_content_type("image", "tiff"))
        }
        ClassRequirement::Voice => msg.attachments().all(|part| {
            part.content_type().is_some_and(|ctype| {
                ctype.ctype().eq_ignore_ascii_case("audio")
                    && ctype.subtype().is_some_and(|subtype| {
                        VOICE_ATTACHMENT_SUBTYPES
                            .iter()
                            .any(|allowed| subtype.eq_ignore_ascii_case(allowed))
                    })
            })
        }),
    }
}

fn strip_prefix_ignore_case<'v>(value: &'v str, prefix: &str) -> Option<&'v str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| value.get(prefix.len()..))
        .flatten()
}

fn set_reply_to(bag: &mut PropBag, list: AddressList<'_>) {
    let mut entries = FlatEntryListWriter::new();
    let mut names = String::new();
    for mailbox in list.mailboxes() {
        let Some(email) = mailbox.address() else {
            continue;
        };
        let name = mailbox.name().unwrap_or(email);
        if !entries.push_one_off(name, SMTP, email) {
            continue;
        }
        if !names.is_empty() {
            names.push_str("; ");
        }
        names.push_str(name);
    }
    if let Some(entries) = entries.finish() {
        set(
            bag,
            tags::REPLY_RECIPIENT_ENTRIES,
            OwnedPropValue::Binary(entries),
        );
        set(
            bag,
            tags::REPLY_RECIPIENT_NAMES,
            OwnedPropValue::Unicode(names.into()),
        );
    }
}

fn calendar_part(msg: MessageRef<'_>) -> Option<MessagePart<'_>> {
    msg.parts()
        .find(|part| part.is_content_type("text", "calendar"))
}

fn calendar_class(msg: MessageRef<'_>) -> Option<&'static str> {
    let part = calendar_part(msg)?;
    let method = part.content_type()?.attribute("method")?;
    calendar_part_class(method, part.text().as_deref())
}

fn is_meeting_class(bag: &PropBag) -> bool {
    matches!(
        bag.get_any(PropKeyRef::Tag(tags::MESSAGE_CLASS)),
        Some(OwnedPropValue::Unicode(class)) if starts_with_ignore_case(class, MEETING_CLASS_PREFIX)
    )
}

fn report_failed(msg: MessageRef<'_>) -> bool {
    msg.parts()
        .filter(|part| part.is_content_type("message", "delivery-status"))
        .any(|part| {
            part.decoded()
                .split(|byte| *byte == b'\n')
                .filter_map(|line| line.strip_suffix(b"\r").or(Some(line)))
                .filter_map(|line| {
                    let mut fields = line.splitn(2, |byte| *byte == b':');
                    let name = fields.next()?;
                    let value = fields.next()?;
                    name.trim_ascii()
                        .eq_ignore_ascii_case(b"action")
                        .then_some(value)
                })
                .any(|value| value.trim_ascii().eq_ignore_ascii_case(b"failed"))
        })
}

fn importance(headers: Headers<'_>) -> Option<i32> {
    if let Some(value) = raw_text(headers, "Importance") {
        return hashify::map_ignore_case!(value.as_bytes(), i32,
            "low" => 0,
            "normal" => 1,
            "high" => 2,
        )
        .copied();
    }
    if let Some(value) = raw_text(headers, "Priority") {
        return hashify::map_ignore_case!(value.as_bytes(), i32,
            "non-urgent" => 0,
            "normal" => 1,
            "urgent" => 2,
        )
        .copied();
    }
    if let Some(value) = raw_text(headers, "X-Priority") {
        return match value.bytes().next() {
            Some(b'1' | b'2') => Some(2),
            Some(b'3') => Some(1),
            Some(b'4' | b'5') => Some(0),
            _ => None,
        };
    }
    raw_text(headers, "X-MSMail-Priority").and_then(|value| {
        hashify::map_ignore_case!(value.as_bytes(), i32,
            "low" => 0,
            "normal" => 1,
            "high" => 2,
        )
        .copied()
    })
}

fn raw_text<'m>(headers: Headers<'m>, name: &str) -> Option<&'m str> {
    let header = headers.all(name).next()?;
    std::str::from_utf8(header.raw_value())
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn split_subject(subject: &str) -> (&str, &str) {
    let Some((prefix, rest)) = subject.split_once(':') else {
        return ("", subject);
    };
    let count = prefix.chars().count();
    let valid = (1..=MAX_PREFIX_CHARS).contains(&count)
        && prefix
            .chars()
            .all(|c| !c.is_ascii_digit() && !c.is_whitespace() && c != ':');
    if !valid {
        return ("", subject);
    }
    let normalized = rest.trim_start_matches(' ');
    let prefix_len = subject.len().saturating_sub(normalized.len());
    subject
        .split_at_checked(prefix_len)
        .unwrap_or(("", subject))
}

fn bracketed(id: &str) -> String {
    format!("<{id}>")
}

fn mailbox(mailbox: mail_parser::Mailbox<'_>) -> Option<Address> {
    let email = mailbox.address()?;
    Some(Address {
        name: mailbox.name().unwrap_or(email).into(),
        address_type: SMTP.into(),
        email: email.into(),
    })
}

fn set_mailbox(
    bag: &mut PropBag,
    target: &AddressTags,
    smtp_id: PropId,
    search_key_id: PropId,
    address: Address,
) {
    set(
        bag,
        search_key_id,
        OwnedPropValue::Binary(smtp_search_key(&address.email)),
    );
    set_string(bag, smtp_id, &address.email);
    set_address(bag, target, address);
}

fn display_list(list: AddressList<'_>) -> String {
    let mut out = String::new();
    for mailbox in list.mailboxes() {
        let Some(label) = mailbox.name().or(mailbox.address()) else {
            continue;
        };
        if !out.is_empty() {
            out.push_str("; ");
        }
        out.push_str(label);
    }
    out
}

fn transport_headers(msg: MessageRef<'_>) -> String {
    let mut out = String::new();
    for header in &msg.headers() {
        let name = header.raw_name();
        let starts_with = |prefix: &str| {
            name.as_bytes()
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
        };
        if HIDDEN_HEADER_PREFIXES
            .iter()
            .any(|prefix| starts_with(prefix))
            && !starts_with(ALLOWED_HIDDEN_PREFIX)
        {
            continue;
        }
        out.push_str(name);
        out.push(':');
        out.push_str(&String::from_utf8_lossy(header.raw_value()));
    }
    out
}

fn is_tnef(part: MessagePart<'_>) -> bool {
    part.is_content_type("application", "ms-tnef")
        || part
            .attachment_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("winmail.dat"))
}

pub(super) fn decodes_tnef(msg: MessageRef<'_>) -> bool {
    !matches!(
        structure_class(msg, None),
        Ok(Signing::Clear | Signing::Opaque)
    )
}

pub(super) fn tnef_envelope_props(
    msg: MessageRef<'_>,
    tnef: &[u8],
    max_decoded: u32,
) -> Option<PropBag> {
    let mut props = tnef_message_props(tnef, max_decoded).ok()?;
    if !correlates(msg, &props) {
        return None;
    }
    for id in TNEF_STORE_OWNED.iter().chain(&TNEF_BODY_DERIVED) {
        props.remove_any(PropKeyRef::Tag(*id));
    }
    Some(props)
}

fn correlates(msg: MessageRef<'_>, decoded: &PropBag) -> bool {
    let Some(header) = raw_text(msg.headers(), "X-MS-TNEF-Correlator") else {
        return true;
    };
    match decoded.get(
        PropKey::tag(tags::TNEF_CORRELATION_KEY).as_ref(),
        PropType::Binary,
    ) {
        Some(OwnedPropValue::Binary(key)) => {
            let key = key.strip_suffix(&[0]).unwrap_or(key);
            key == header.as_bytes()
        }
        _ => true,
    }
}

fn merge_tnef(content: &mut MessageContent, decoded: MessageContent) {
    for (key, value) in decoded.props.iter() {
        if !matches!(key.as_ref(), PropKeyRef::Tag(id) if TNEF_STORE_OWNED.contains(&id))
            && content.props.get_any(key.as_ref()).is_none()
        {
            content.props.set(key.clone(), value.clone());
        }
    }
    if content.recipients.is_empty() {
        content.recipients = decoded.recipients;
    }
    content.attachments.extend(decoded.attachments);
}

fn is_rendered_inline(part: MessagePart<'_>) -> bool {
    let referenced_id = part.content_id().is_some() || part.content_location().is_some();
    let in_related = part
        .parent()
        .is_some_and(|parent| parent.is_content_type("multipart", "related"));
    referenced_id
        && in_related
        && part
            .content_type()
            .is_some_and(|ctype| ctype.ctype().eq_ignore_ascii_case("image"))
}

pub(super) fn sanitize_file_name(name: &str) -> String {
    sanitized_file_name(name).collect()
}

pub(super) fn sanitized_file_name(name: &str) -> impl Iterator<Item = char> + '_ {
    name.trim_matches(|c| c == '.' || c == ' ')
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
}

fn set(bag: &mut PropBag, id: PropId, value: OwnedPropValue) {
    bag.set(PropKey::tag(id), value);
}

fn set_string(bag: &mut PropBag, id: PropId, value: &str) {
    bag.set(PropKey::tag(id), OwnedPropValue::Unicode(value.into()));
}
