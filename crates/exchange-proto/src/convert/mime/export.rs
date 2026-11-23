/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use calcard::common::IanaString;
use mail_builder::{
    MessageBuilder,
    headers::{
        address::Address as MimeAddress, content_type::ContentType, date::Date,
        message_id::MessageId, raw::Raw,
    },
    mime::{BodyPart, MimePart},
};
use mail_parser::html_to_text;

use super::{
    CalendarPart,
    body::{Bodies, decode_rtf},
    ends_with_ignore_case,
    mdn::{
        DISPOSITION_NOTIFICATION, DISPOSITION_NOTIFICATION_TYPE, Disposition, MULTIPART_REPORT,
        NotificationFields, REPORT_TYPE,
    },
    media_type,
    smime::{
        CONTENT_TYPE, SMIME_FILE_NAME, SUFFIX_SMIME, SUFFIX_SMIME_SIGNED, clear_signed_entity,
    },
    starts_with_ignore_case,
};
use crate::{
    common::base64::base64_encode_into,
    convert::{
        ConvertError, MAX_EMBED_DEPTH,
        address::FlatEntries,
        context::{AddressResolver, ConvertOptions},
        conversation::ConversationIndex,
        model::{AttachData, Attachment, MessageContent, PropBag},
        tags::{self, CONTENT_CLASS_NAME, attach_flags, attach_method, recipient_type},
    },
    ids::entryid::EntryId,
    mapi::prop::{OwnedPropValue, PropId, PropKey, PropType},
};

const SMTP: &str = "SMTP";
const EX: &str = "EX";
const OCTET_STREAM: &str = "application/octet-stream";
const MESSAGE_RFC822: &str = "message/rfc822";
const CONTENT_DISPOSITION: &str = "Content-Disposition";
const INLINE: &str = "inline";

#[derive(Clone, Copy)]
enum Placement<'c> {
    Attached,
    Inline(&'c str),
}
const SEVEN_BIT: &str = "7bit";
const CID_PREFIX: &str = "cid:";
const NAME_SEPARATOR: char = ';';
const TEXT_CALENDAR: &str = "text/calendar";
const MULTIPART_ALTERNATIVE: &str = "multipart/alternative";
const PREFIX_MEETING: &str = "IPM.Schedule.Meeting.";

type ExportAddress<'c> = (Option<Cow<'c, str>>, Cow<'c, str>);

struct GroupTags {
    name: PropId,
    address_type: PropId,
    email: PropId,
    smtp: PropId,
    entry_id: PropId,
}

const SENT_REPRESENTING: GroupTags = GroupTags {
    name: tags::SENT_REPRESENTING_NAME,
    address_type: tags::SENT_REPRESENTING_ADDRESS_TYPE,
    email: tags::SENT_REPRESENTING_EMAIL_ADDRESS,
    smtp: tags::SENT_REPRESENTING_SMTP_ADDRESS,
    entry_id: tags::SENT_REPRESENTING_ENTRY_ID,
};
const SENDER: GroupTags = GroupTags {
    name: tags::SENDER_NAME,
    address_type: tags::SENDER_ADDRESS_TYPE,
    email: tags::SENDER_EMAIL_ADDRESS,
    smtp: tags::SENDER_SMTP_ADDRESS,
    entry_id: tags::SENDER_ENTRY_ID,
};
const RECIPIENT: GroupTags = GroupTags {
    name: tags::DISPLAY_NAME,
    address_type: tags::ADDRESS_TYPE,
    email: tags::EMAIL_ADDRESS,
    smtp: tags::SMTP_ADDRESS,
    entry_id: tags::ENTRY_ID,
};

#[derive(Clone, Copy)]
enum ClassShape {
    Ordinary,
    ClearSigned,
    Opaque,
    Receipt(Disposition),
    Meeting,
}

impl ClassShape {
    fn of(class: &str) -> Self {
        if ends_with_ignore_case(class, SUFFIX_SMIME_SIGNED) {
            ClassShape::ClearSigned
        } else if ends_with_ignore_case(class, SUFFIX_SMIME) {
            ClassShape::Opaque
        } else if let Some(disposition) = Disposition::from_class(class) {
            ClassShape::Receipt(disposition)
        } else if starts_with_ignore_case(class, PREFIX_MEETING) {
            ClassShape::Meeting
        } else {
            ClassShape::Ordinary
        }
    }
}

struct Exporter<'r, 'o> {
    resolver: &'r dyn AddressResolver,
    opts: &'r ConvertOptions<'o>,
}

pub(super) fn message(
    content: &MessageContent,
    resolver: &dyn AddressResolver,
    opts: &ConvertOptions<'_>,
    calendar: Option<CalendarPart<'_>>,
    out: &mut Vec<u8>,
) -> Result<(), ConvertError> {
    Exporter { resolver, opts }.write(content, 0, calendar, out)
}

impl Exporter<'_, '_> {
    fn write(
        &self,
        content: &MessageContent,
        depth: u8,
        calendar: Option<CalendarPart<'_>>,
        out: &mut Vec<u8>,
    ) -> Result<(), ConvertError> {
        let props = &content.props;
        let mut builder = MessageBuilder::new();
        let from = self.address(props, &SENT_REPRESENTING);
        let sender = self.address(props, &SENDER);
        if let Some((_, from_email)) = &from
            && let Some((name, email)) = &sender
            && !email.eq_ignore_ascii_case(from_email)
        {
            builder = builder.sender(mime_address(name.clone(), email.clone()));
        }
        if let Some((name, email)) = from.or(sender) {
            if bool_prop(props, tags::READ_RECEIPT_REQUESTED) {
                builder = builder.header(
                    "Disposition-Notification-To",
                    mime_address(name.clone(), email.clone()),
                );
            }
            builder = builder.from(mime_address(name, email));
        }
        for (kind, header) in [
            (recipient_type::TO, "To"),
            (recipient_type::CC, "Cc"),
            (recipient_type::BCC, "Bcc"),
        ] {
            let list: Vec<MimeAddress<'_>> = content
                .recipients
                .iter()
                .filter(|row| {
                    int_prop(row, tags::RECIPIENT_TYPE)
                        .is_some_and(|value| value & recipient_type::MASK == kind)
                })
                .filter_map(|row| {
                    self.address(row, &RECIPIENT).or_else(|| {
                        unresolved_recipient(row).map(|email| (None, Cow::Borrowed(email)))
                    })
                })
                .map(|(name, email)| mime_address(name, email))
                .collect();
            if !list.is_empty() {
                builder = builder.header(header, MimeAddress::new_list(list));
            }
        }
        let reply_to = self.reply_to(props);
        if !reply_to.is_empty() {
            builder = builder.reply_to(MimeAddress::new_list(reply_to));
        }
        if let Some(subject) = props.subject() {
            builder = builder.subject(subject);
        }
        if let Some(OwnedPropValue::Time(time)) = props.get(
            PropKey::tag(tags::CLIENT_SUBMIT_TIME).as_ref(),
            PropType::Time,
        ) {
            builder = builder.date(Date::new(time.to_utc().0.0));
        }
        if let Some(id) = props.text(tags::INTERNET_MESSAGE_ID) {
            builder = builder.message_id(unbracket(id));
        }
        if let Some(id) = props.text(tags::IN_REPLY_TO_ID) {
            builder = builder.in_reply_to(unbracket(id));
        }
        if let Some(ids) = props.text(tags::INTERNET_REFERENCES) {
            let ids: Vec<&str> = reference_ids(ids).collect();
            if !ids.is_empty() {
                builder = builder.references(MessageId::from(ids));
            }
        }
        match int_prop(props, tags::IMPORTANCE) {
            Some(0) => builder = builder.header("Importance", Raw::new("Low")),
            Some(2) => builder = builder.header("Importance", Raw::new("High")),
            _ => {}
        }
        let sensitivity = match int_prop(props, tags::SENSITIVITY) {
            Some(1) => Some("Personal"),
            Some(2) => Some("Private"),
            Some(3) => Some("Company-Confidential"),
            _ => None,
        };
        if let Some(sensitivity) = sensitivity {
            builder = builder.header("Sensitivity", Raw::new(sensitivity));
        }
        if let Some(index) = binary_prop(props, tags::CONVERSATION_INDEX)
            .filter(|index| ConversationIndex::is_well_formed(index))
        {
            let mut encoded = Vec::new();
            base64_encode_into(index, &mut encoded);
            builder = builder.header(
                "Thread-Index",
                Raw::new(String::from_utf8_lossy(&encoded).into_owned()),
            );
        }
        if let Some(OwnedPropValue::Unicode(class)) = props.get(
            PropKey::internet_header(CONTENT_CLASS_NAME).as_ref(),
            PropType::Unicode,
        ) && !class.is_empty()
        {
            builder = builder.header(CONTENT_CLASS_NAME, Raw::new(&**class));
        }
        builder = builder.body(self.body(content, depth, calendar)?);
        builder.write_to(out).map_err(|_| ConvertError::Mime)
    }

    fn body<'c>(
        &self,
        content: &'c MessageContent,
        depth: u8,
        calendar: Option<CalendarPart<'c>>,
    ) -> Result<MimePart<'c>, ConvertError> {
        let props = &content.props;
        let shape = ClassShape::of(props.text(tags::MESSAGE_CLASS).unwrap_or_default());
        let entity = match shape {
            ClassShape::ClearSigned => single_entity(content)
                .and_then(|(_, bytes)| clear_signed_entity(bytes))
                .map(|entity| MimePart::raw(BodyPart::Binary(entity))),
            ClassShape::Opaque => single_entity(content)
                .map(|(attachment, bytes)| opaque_entity(props, attachment, bytes)),
            _ => None,
        };
        Ok(match (entity, shape) {
            (Some(entity), _) => entity,
            (None, ClassShape::Receipt(disposition)) => {
                self.receipt(content, depth, disposition)?
            }
            (None, ClassShape::Meeting) => {
                self.body_tree(content, &content.attachments, depth, calendar)?
            }
            (None, _) => self.body_tree(content, &content.attachments, depth, None)?,
        })
    }

    fn receipt<'c>(
        &self,
        content: &'c MessageContent,
        depth: u8,
        disposition: Disposition,
    ) -> Result<MimePart<'c>, ConvertError> {
        let mut parts = Vec::with_capacity(3);
        match content.attachments.as_slice() {
            [original] if is_returned_original(original) => {
                parts.push(self.body_tree(content, &[], depth, None)?);
                parts.push(self.notification(&content.props, disposition));
                parts.push(self.attachment(original, depth, Placement::Attached)?);
            }
            attachments => {
                parts.push(self.body_tree(content, attachments, depth, None)?);
                parts.push(self.notification(&content.props, disposition));
            }
        }
        Ok(MimePart::new(
            ContentType::new(MULTIPART_REPORT).attribute(REPORT_TYPE, DISPOSITION_NOTIFICATION),
            parts,
        ))
    }

    fn notification(&self, props: &PropBag, disposition: Disposition) -> MimePart<'static> {
        let recipient = self
            .address(props, &SENDER)
            .or_else(|| self.address(props, &SENT_REPRESENTING));
        let mut out = Vec::new();
        NotificationFields {
            recipient: recipient
                .as_ref()
                .map(|(name, email)| (name.as_deref(), &**email)),
            disposition,
            parent_key: binary_prop(props, tags::PARENT_KEY),
            original_message_id: props.text(tags::ORIGINAL_MESSAGE_ID),
        }
        .write(&mut out);
        MimePart::new(DISPOSITION_NOTIFICATION_TYPE, BodyPart::Binary(out.into()))
            .transfer_encoding(SEVEN_BIT)
    }

    fn body_tree<'c>(
        &self,
        content: &'c MessageContent,
        attachments: &'c [Attachment],
        depth: u8,
        calendar: Option<CalendarPart<'c>>,
    ) -> Result<MimePart<'c>, ConvertError> {
        let (text, html) = export_bodies(&content.props, self.opts.max_decoded)?;
        let text = match (text, &html) {
            (Some(text), _) => text,
            (None, Some(html)) => Cow::Owned(html_to_text(html)),
            (None, None) => Cow::Borrowed(""),
        };
        let text_part = MimePart::new("text/plain", text);
        let mut inline = Vec::new();
        let mut attached = Vec::new();
        for attachment in attachments {
            match (inline_id(attachment), &html) {
                (Some(id), Some(html)) if references_cid(html, id) => {
                    inline.push(self.attachment(attachment, depth, Placement::Inline(id))?)
                }
                _ => attached.push(self.attachment(attachment, depth, Placement::Attached)?),
            }
        }
        let mut body = match (html, calendar) {
            (None, None) => text_part,
            (html, calendar) => {
                let mut alternative = Vec::with_capacity(3);
                alternative.push(text_part);
                alternative.extend(html.map(|html| MimePart::new("text/html", html)));
                alternative.extend(calendar.map(calendar_part));
                MimePart::new(MULTIPART_ALTERNATIVE, alternative)
            }
        };
        if !inline.is_empty() {
            inline.insert(0, body);
            body = MimePart::new("multipart/related", inline);
        }
        if !attached.is_empty() {
            attached.insert(0, body);
            body = MimePart::new("multipart/mixed", attached);
        }
        Ok(body)
    }

    fn attachment<'c>(
        &self,
        attachment: &'c Attachment,
        depth: u8,
        placement: Placement<'c>,
    ) -> Result<MimePart<'c>, ConvertError> {
        let props = &attachment.props;
        let name = attachment_file_name(props);
        let part = match &attachment.data {
            AttachData::Bytes(bytes) => MimePart::new(
                ContentType::new(mime_tag(props)),
                BodyPart::from(&bytes[..]),
            ),
            AttachData::Embedded(embedded) => {
                if depth >= MAX_EMBED_DEPTH {
                    return Err(ConvertError::TooLarge);
                }
                let mut nested = Vec::new();
                self.write(embedded, depth.saturating_add(1), None, &mut nested)?;
                MimePart::new(MESSAGE_RFC822, BodyPart::from(nested)).transfer_encoding(SEVEN_BIT)
            }
            AttachData::Deferred(_) => return Err(ConvertError::Unsupported),
            AttachData::None => MimePart::new(
                ContentType::new(mime_tag(props)),
                BodyPart::from(binary_prop(props, tags::ATTACH_DATA).unwrap_or_default()),
            ),
        };
        Ok(match (placement, name) {
            (Placement::Inline(id), Some(name)) => part
                .header(
                    CONTENT_DISPOSITION,
                    ContentType::new(INLINE).attribute("filename", name),
                )
                .cid(id),
            (Placement::Inline(id), None) => part.inline().cid(id),
            (Placement::Attached, Some(name)) => part.attachment(name),
            (Placement::Attached, None) => part,
        })
    }

    fn address<'c>(&self, props: &'c PropBag, group: &GroupTags) -> Option<ExportAddress<'c>> {
        let name = props.text(group.name).filter(|name| !name.is_empty());
        if let Some(smtp) = props.text(group.smtp).filter(|smtp| !smtp.is_empty()) {
            return Some((name.map(Cow::Borrowed), Cow::Borrowed(smtp)));
        }
        props
            .text(group.email)
            .filter(|email| !email.is_empty())
            .and_then(|email| {
                let address_type = props.text(group.address_type).unwrap_or(SMTP);
                self.typed_address(name.map(Cow::Borrowed), address_type, Cow::Borrowed(email))
            })
            .or_else(|| {
                binary_prop(props, group.entry_id)
                    .and_then(|entry| self.entry_address(entry, name.map(Cow::Borrowed)))
            })
    }

    fn typed_address<'c>(
        &self,
        name: Option<Cow<'c, str>>,
        address_type: &str,
        email: Cow<'c, str>,
    ) -> Option<ExportAddress<'c>> {
        if address_type.eq_ignore_ascii_case(SMTP) {
            Some((name, email))
        } else if address_type.eq_ignore_ascii_case(EX) {
            self.resolve_dn(name, &email)
        } else {
            None
        }
    }

    fn resolve_dn<'c>(&self, name: Option<Cow<'c, str>>, dn: &str) -> Option<ExportAddress<'c>> {
        let resolved = self.resolver.resolve_dn(dn)?;
        let name = name.unwrap_or_else(|| Cow::Owned(resolved.display_name.into_owned()));
        Some((Some(name), Cow::Owned(resolved.smtp.into_owned())))
    }

    fn reply_to<'c>(&self, props: &'c PropBag) -> Vec<MimeAddress<'c>> {
        let Some(entries) =
            binary_prop(props, tags::REPLY_RECIPIENT_ENTRIES).and_then(FlatEntries::new)
        else {
            return Vec::new();
        };
        let mut names = props
            .text(tags::REPLY_RECIPIENT_NAMES)
            .filter(|names| {
                u32::try_from(names.split(NAME_SEPARATOR).count())
                    .is_ok_and(|count| count == entries.claimed_len())
            })
            .map(|names| names.split(NAME_SEPARATOR));
        entries
            .filter_map(|entry| {
                let name = names
                    .as_mut()
                    .and_then(Iterator::next)
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(Cow::Borrowed);
                let (name, email) = self.entry_address(entry, name)?;
                Some(mime_address(name, email))
            })
            .collect()
    }

    fn entry_address<'c>(
        &self,
        entry: &'c [u8],
        name: Option<Cow<'c, str>>,
    ) -> Option<ExportAddress<'c>> {
        match EntryId::decode(entry).ok()? {
            EntryId::OneOff(id) => {
                let name = name.or(Some(id.display_name).filter(|name| !name.is_empty()));
                self.typed_address(name, &id.address_type, id.email)
            }
            EntryId::AddressBook(id) => self.resolve_dn(name, std::str::from_utf8(&id.dn).ok()?),
            _ => None,
        }
    }
}

fn is_returned_original(attachment: &Attachment) -> bool {
    matches!(attachment.data, AttachData::Embedded(_))
        || attachment
            .props
            .text(tags::ATTACH_MIME_TAG)
            .is_some_and(|tag| {
                hashify::set_ignore_case!(tag.as_bytes(), "message/rfc822", "text/rfc822-headers")
            })
}

fn single_entity(content: &MessageContent) -> Option<(&Attachment, &[u8])> {
    let [attachment] = content.attachments.as_slice() else {
        return None;
    };
    let bytes = match &attachment.data {
        AttachData::Bytes(bytes) => &bytes[..],
        AttachData::None => binary_prop(&attachment.props, tags::ATTACH_DATA)?,
        AttachData::Embedded(_) | AttachData::Deferred(_) => return None,
    };
    Some((attachment, bytes))
}

fn opaque_entity<'c>(
    props: &'c PropBag,
    attachment: &'c Attachment,
    bytes: &'c [u8],
) -> MimePart<'c> {
    let attachment_props = &attachment.props;
    let file_name = attachment_props
        .text(tags::ATTACH_FILENAME)
        .or_else(|| attachment_props.text(tags::ATTACH_LONG_FILENAME))
        .filter(|name| !name.is_empty())
        .unwrap_or(SMIME_FILE_NAME);
    let entity = MimePart::raw(BodyPart::from(bytes));
    let entity = match props.get(
        PropKey::internet_header(CONTENT_TYPE).as_ref(),
        PropType::Unicode,
    ) {
        Some(OwnedPropValue::Unicode(raw)) if !raw.trim().is_empty() => {
            entity.header(CONTENT_TYPE, Raw::new(raw.trim()))
        }
        _ => entity.header(
            CONTENT_TYPE,
            ContentType::new(mime_tag(attachment_props)).attribute("name", file_name),
        ),
    };
    entity.attachment(file_name)
}

fn calendar_part(calendar: CalendarPart<'_>) -> MimePart<'_> {
    MimePart::new(
        ContentType::new(TEXT_CALENDAR)
            .attribute("charset", "utf-8")
            .attribute("method", calendar.method.as_str()),
        calendar.text,
    )
}

fn unresolved_recipient(row: &PropBag) -> Option<&str> {
    if row
        .text(RECIPIENT.email)
        .is_some_and(|email| !email.is_empty())
        || binary_prop(row, RECIPIENT.entry_id).is_some()
    {
        return None;
    }
    let address = row
        .text(RECIPIENT.name)?
        .trim()
        .trim_matches(|ch| matches!(ch, '\'' | '"'))
        .trim();
    let (local, domain) = address.split_once('@')?;
    (!local.is_empty()
        && !local.starts_with('.')
        && !local.ends_with('.')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !address.contains("..")
        && !address.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(
                    byte,
                    b'<' | b'>' | b',' | b';' | b':' | b'"' | b'(' | b')' | b'[' | b']' | b'\\'
                )
        })
        && !domain.contains('@'))
    .then_some(address)
}

fn mime_address<'c>(name: Option<Cow<'c, str>>, email: Cow<'c, str>) -> MimeAddress<'c> {
    MimeAddress::new_address(name, email)
}

fn mime_tag(props: &PropBag) -> &str {
    let Some(tag) = props
        .text(tags::ATTACH_MIME_TAG)
        .filter(|tag| tag.contains('/'))
    else {
        return extension_media_type(props).unwrap_or(OCTET_STREAM);
    };
    let replaced = tag
        .get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("multipart/"))
        || hashify::set_ignore_case!(
            tag.as_bytes(),
            "message/rfc822",
            "application/applefile",
            "application/mac-binhex40",
            "application/ms-tnef",
        );
    if replaced { OCTET_STREAM } else { tag }
}

type ExportBodies<'c> = (Option<Cow<'c, str>>, Option<Cow<'c, str>>);

fn export_bodies(props: &PropBag, max_decoded: u32) -> Result<ExportBodies<'_>, ConvertError> {
    let bodies = Bodies::new(props);
    Ok(match (bodies.text, bodies.has_html(), bodies.rtf) {
        (None, false, Some(rtf)) => decode_rtf(rtf, max_decoded)?,
        (text, _, _) => (text.map(Cow::Borrowed), bodies.html()),
    })
}

pub fn export_html(
    props: &PropBag,
    max_decoded: u32,
) -> Result<Option<Cow<'_, str>>, ConvertError> {
    export_bodies(props, max_decoded).map(|(_, html)| html)
}

pub fn is_inline_part(attachment: &Attachment, html: &str) -> bool {
    inline_id(attachment).is_some_and(|id| references_cid(html, id))
}

fn extension_media_type(props: &PropBag) -> Option<&'static str> {
    if int_prop(props, tags::ATTACH_METHOD) == Some(attach_method::OLE) {
        return None;
    }
    props
        .text(tags::ATTACH_EXTENSION)
        .filter(|extension| !extension.is_empty())
        .or_else(|| {
            attachment_file_name(props)
                .and_then(|name| name.rsplit_once('.'))
                .map(|(_, extension)| extension)
        })
        .and_then(media_type::from_extension)
}

pub(super) fn attachment_file_name(props: &PropBag) -> Option<&str> {
    props
        .text(tags::ATTACH_LONG_FILENAME)
        .or_else(|| props.text(tags::ATTACH_FILENAME))
        .or_else(|| props.text(tags::DISPLAY_NAME))
        .filter(|name| !name.is_empty())
}

pub(super) fn has_inline_id(attachment: &Attachment) -> bool {
    inline_id(attachment).is_some()
}

fn inline_id(attachment: &Attachment) -> Option<&str> {
    let flags = int_prop(&attachment.props, tags::ATTACH_FLAGS)?;
    (flags & attach_flags::RENDERED_IN_BODY != 0)
        .then(|| attachment.props.text(tags::ATTACH_CONTENT_ID))
        .flatten()
        .filter(|id| !id.is_empty())
}

fn references_cid(html: &str, id: &str) -> bool {
    html.match_indices(CID_PREFIX).any(|(start, _)| {
        html.get(start.saturating_add(CID_PREFIX.len())..)
            .and_then(|rest| rest.get(..id.len()))
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(id))
    })
}

pub fn reference_ids(ids: &str) -> impl Iterator<Item = &str> {
    ids.split_ascii_whitespace().map(unbracket)
}

fn unbracket(id: &str) -> &str {
    let id = id.trim();
    id.strip_prefix('<')
        .and_then(|id| id.strip_suffix('>'))
        .unwrap_or(id)
}

fn int_prop(props: &PropBag, id: PropId) -> Option<i32> {
    match props.get(PropKey::tag(id).as_ref(), PropType::I32)? {
        OwnedPropValue::I32(value) => Some(*value),
        _ => None,
    }
}

fn bool_prop(props: &PropBag, id: PropId) -> bool {
    matches!(
        props.get(PropKey::tag(id).as_ref(), PropType::Bool),
        Some(OwnedPropValue::Bool(true))
    )
}

fn binary_prop(props: &PropBag, id: PropId) -> Option<&[u8]> {
    match props.get(PropKey::tag(id).as_ref(), PropType::Binary)? {
        OwnedPropValue::Binary(value) => Some(value),
        _ => None,
    }
}
