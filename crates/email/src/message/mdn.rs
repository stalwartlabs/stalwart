/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::{ArchivedMessageMetadata, HeaderId, view::HeaderList};
use jmap_proto::object::mdn::{
    ActionMode, Disposition, DispositionType, Mdn, MdnProperty, SendingMode,
};
use mail_builder::{
    MessageBuilder,
    headers::{HeaderType, address::Address, content_type::ContentType},
    mime::{BodyPart, MimePart, make_boundary},
};
use mail_parser::{HeaderForm, MessageParser, MessagePart};
use std::{borrow::Cow, fmt::Write};
use utils::{DomainPart, map::vec_map::VecMap, sanitize_email};

pub const MAX_NOTIFY_ADDRESSES: usize = 5;
pub const MAX_FIELD_LEN: usize = 900;
pub const MAX_SUBJECT_LEN: usize = 998;
pub const MAX_TEXT_BODY_LEN: usize = 8192;
pub const MAX_EXTENSION_FIELDS: usize = 32;
pub const MAX_REPORT_FIELDS: usize = 64;
pub const MAX_ERRORS: usize = 16;
const MAX_FIELD_NAME_LEN: usize = 76;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdnStatus {
    NotRequested,
    Report,
    Requested(MdnRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnRequest {
    pub notify: Vec<String>,
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub original_recipient: Option<String>,
    pub return_path: Option<String>,
    pub utf8_headers: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnInvalid {
    pub property: MdnProperty,
    pub reason: &'static str,
}

pub struct MdnMessage<'x> {
    pub mdn: &'x Mdn,
    pub disposition: Disposition,
    pub from_name: Option<&'x str>,
    pub from_address: &'x str,
    pub to: &'x [String],
    pub original_message: Option<OriginalMessage<'x>>,
}

#[derive(Clone, Copy)]
pub struct OriginalMessage<'x> {
    pub raw: &'x [u8],
    pub utf8_headers: bool,
}

impl MdnStatus {
    pub fn new(metadata: &ArchivedMessageMetadata, raw_headers: &[u8]) -> Self {
        let root = metadata.root();
        let part = root.root_part();
        if part.content_type().is_some_and(|ct| {
            ct.ctype().eq_ignore_ascii_case("multipart")
                && ct
                    .subtype()
                    .is_some_and(|subtype| subtype.eq_ignore_ascii_case("report"))
        }) {
            return MdnStatus::Report;
        }

        let headers = part.headers();
        let Some(parsed) = headers.last_parsed(
            HeaderId::DISPOSITION_NOTIFICATION_TO,
            raw_headers,
            HeaderForm::Addresses,
        ) else {
            return MdnStatus::NotRequested;
        };
        let Some(list) = parsed.value().as_address() else {
            return MdnStatus::NotRequested;
        };
        let mut notify = Vec::new();
        for address in list
            .mailboxes()
            .filter_map(|mailbox| mailbox.address().and_then(sanitize_email))
        {
            if !notify.contains(&address) {
                notify.push(address);
                if notify.len() == MAX_NOTIFY_ADDRESSES {
                    break;
                }
            }
        }
        if notify.is_empty() {
            return MdnStatus::NotRequested;
        }

        let envelope = root.envelope();
        MdnStatus::Requested(MdnRequest {
            notify,
            message_id: envelope
                .message_id()
                .last()
                .filter(|id| is_valid_field_value(id))
                .map(|id| format!("<{id}>")),
            subject: envelope.subject().map(str::to_string),
            original_recipient: headers
                .last_parsed(HeaderId::ORIGINAL_RECIPIENT, raw_headers, HeaderForm::Text)
                .and_then(|value| {
                    value
                        .value()
                        .as_text()
                        .map(str::trim)
                        .filter(|text| is_valid_field_value(text))
                        .map(str::to_string)
                }),
            return_path: single_return_path(&headers, raw_headers),
            utf8_headers: !headers.iter().all(|header| {
                raw_headers
                    .get(header.field_range())
                    .is_none_or(<[u8]>::is_ascii)
            }),
        })
    }
}

impl MdnRequest {
    pub fn allows_automatic(&self) -> bool {
        matches!(
            (self.notify.as_slice(), &self.return_path),
            ([notify], Some(return_path)) if notify == return_path
        )
    }

    pub fn apply_defaults(
        &mut self,
        mdn: &mut Mdn,
        disposition: Disposition,
        final_recipient: &str,
    ) {
        if mdn.final_recipient.is_none() {
            mdn.final_recipient = Some(format!("rfc822; {final_recipient}"));
        }
        if mdn.subject.is_none() {
            mdn.subject = Some(default_subject(
                disposition.disposition_type,
                self.subject.as_deref(),
            ));
        }
        if mdn.text_body.is_none() {
            mdn.text_body = Some(default_text(
                disposition.disposition_type,
                self.subject.as_deref(),
            ));
        }
        mdn.original_message_id = self.message_id.take();
        mdn.original_recipient = self.original_recipient.take();
    }
}

impl MdnInvalid {
    fn new(property: MdnProperty, reason: &'static str) -> Self {
        MdnInvalid { property, reason }
    }
}

pub fn validate_mdn(mdn: &Mdn) -> Result<Disposition, MdnInvalid> {
    let Some(disposition) = mdn.disposition else {
        return Err(MdnInvalid::new(
            MdnProperty::Disposition,
            "A valid disposition is required.",
        ));
    };
    for (property, is_set) in [
        (MdnProperty::MdnGateway, mdn.mdn_gateway.is_some()),
        (
            MdnProperty::OriginalRecipient,
            mdn.original_recipient.is_some(),
        ),
        (
            MdnProperty::OriginalMessageId,
            mdn.original_message_id.is_some(),
        ),
        (MdnProperty::Error, mdn.error.is_some()),
    ] {
        if is_set {
            return Err(MdnInvalid::new(property, "Property is server-set."));
        }
    }
    if let Some(subject) = &mdn.subject
        && (subject.len() > MAX_SUBJECT_LEN || subject.contains(['\r', '\n']))
    {
        return Err(MdnInvalid::new(
            MdnProperty::Subject,
            "Subject is too long or contains line breaks.",
        ));
    }
    if mdn
        .text_body
        .as_ref()
        .is_some_and(|text_body| text_body.len() > MAX_TEXT_BODY_LEN)
    {
        return Err(MdnInvalid::new(
            MdnProperty::TextBody,
            "Text body is too long.",
        ));
    }
    for (property, value) in [
        (MdnProperty::ReportingUa, &mdn.reporting_ua),
        (MdnProperty::FinalRecipient, &mdn.final_recipient),
    ] {
        if value
            .as_deref()
            .is_some_and(|value| !is_valid_field_value(value))
        {
            return Err(MdnInvalid::new(property, "Invalid field value."));
        }
    }
    if let Some(fields) = &mdn.extension_fields {
        if fields.len() > MAX_EXTENSION_FIELDS {
            return Err(MdnInvalid::new(
                MdnProperty::ExtensionFields,
                "Too many extension fields.",
            ));
        }
        for (name, value) in fields.iter() {
            if !is_valid_extension_name(name) || !is_valid_field_value(value) {
                return Err(MdnInvalid::new(
                    MdnProperty::ExtensionFields,
                    "Invalid extension field.",
                ));
            }
        }
    }
    Ok(disposition)
}

pub fn final_recipient_address(value: &str) -> Option<String> {
    let (addr_type, address) = value.split_once(';')?;
    if addr_type.trim().eq_ignore_ascii_case("rfc822") {
        sanitize_email(address.trim())
    } else {
        None
    }
}

impl MdnMessage<'_> {
    pub fn build(&self) -> Option<Vec<u8>> {
        let mut report = String::with_capacity(256);
        self.write_report(&mut report);
        let (report_type, report_encoding) = if report.is_ascii() {
            ("message/disposition-notification", "7bit")
        } else {
            ("message/global-disposition-notification", "8bit")
        };

        let mut parts = Vec::with_capacity(3);
        parts.push(MimePart::new(
            ContentType::new("text/plain"),
            BodyPart::Text(Cow::Borrowed(
                self.mdn.text_body.as_deref().unwrap_or_default(),
            )),
        ));
        parts.push(
            MimePart::new(
                ContentType::new(report_type),
                BodyPart::Binary(Cow::Owned(report.into_bytes())),
            )
            .transfer_encoding(report_encoding),
        );
        if let Some(original) = self.original_message {
            let original_type = if original.utf8_headers {
                "message/global"
            } else {
                "message/rfc822"
            };
            let original_encoding = if original.raw.is_ascii() {
                "7bit"
            } else {
                "8bit"
            };
            parts.push(
                MimePart::new(
                    ContentType::new(original_type),
                    BodyPart::Binary(Cow::Borrowed(original.raw)),
                )
                .transfer_encoding(original_encoding),
            );
        }

        let mut builder = MessageBuilder::new()
            .from(match self.from_name {
                Some(name) => Address::from((name, self.from_address)),
                None => Address::from(self.from_address),
            })
            .to(self.to.iter().map(String::as_str).collect::<Vec<_>>())
            .message_id(format!(
                "{}@{}",
                make_boundary("."),
                self.from_address.domain_part()
            ))
            .subject(self.mdn.subject.as_deref().unwrap_or_default());
        if self.disposition.is_automatic() {
            builder = builder.header("Auto-Submitted", HeaderType::Text("auto-replied".into()));
        }
        builder
            .body(MimePart::new(
                ContentType::new("multipart/report")
                    .attribute("report-type", "disposition-notification"),
                BodyPart::Multipart(parts),
            ))
            .write_to_vec()
            .ok()
    }

    fn write_report(&self, out: &mut String) {
        let mdn = self.mdn;
        if let Some(value) = &mdn.reporting_ua {
            let _ = write!(out, "Reporting-UA: {value}\r\n");
        }
        if let Some(value) = &mdn.original_recipient {
            let _ = write!(out, "Original-Recipient: {value}\r\n");
        }
        if let Some(value) = &mdn.final_recipient {
            let _ = write!(out, "Final-Recipient: {value}\r\n");
        }
        if let Some(value) = &mdn.original_message_id {
            let _ = write!(out, "Original-Message-ID: {value}\r\n");
        }
        let _ = write!(
            out,
            "Disposition: {}/{}; {}\r\n",
            self.disposition.action_mode.as_str(),
            self.disposition.sending_mode.as_field(),
            self.disposition.disposition_type.as_str()
        );
        if let Some(fields) = &mdn.extension_fields {
            for (name, value) in fields.iter() {
                let _ = write!(out, "{name}: {value}\r\n");
            }
        }
    }
}

pub fn parse_mdn(raw: &[u8]) -> Option<Mdn> {
    let message = MessageParser::new().parse(raw)?;
    let root = message.root_part();
    if !root.is_content_type("multipart", "report") {
        return None;
    }

    let mut mdn = Mdn {
        subject: message.subject().map(str::to_string),
        ..Default::default()
    };
    let mut has_report = false;
    for part in root.children() {
        if has_report {
            mdn.include_original_message = true;
            break;
        } else if is_report_part(&part) {
            let fields = part.decoded();
            parse_report_fields(&String::from_utf8_lossy(&fields), &mut mdn);
            has_report = true;
        } else if mdn.text_body.is_none() && part.is_content_type("text", "plain") {
            mdn.text_body = part.text().map(Cow::into_owned);
        }
    }

    (has_report && mdn.disposition.is_some()).then_some(mdn)
}

fn is_report_part(part: &MessagePart<'_>) -> bool {
    part.is_content_type("message", "disposition-notification")
        || part.is_content_type("message", "global-disposition-notification")
}

fn parse_report_fields(data: &str, mdn: &mut Mdn) {
    let mut current: Option<(&str, String)> = None;
    let mut count = 0;
    for line in data.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = &mut current
                && value.len() < MAX_FIELD_LEN
            {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = current.take() {
            apply_report_field(mdn, name, value);
        }
        if let Some((name, value)) = line.split_once(':') {
            count += 1;
            if count > MAX_REPORT_FIELDS {
                return;
            }
            current = Some((name.trim(), value.trim().to_string()));
        }
    }
    if let Some((name, value)) = current {
        apply_report_field(mdn, name, value);
    }
}

#[derive(Clone, Copy)]
enum ReportField {
    ReportingUa,
    MdnGateway,
    OriginalRecipient,
    FinalRecipient,
    OriginalMessageId,
    Disposition,
    Error,
    Ignore,
}

fn report_field(name: &str) -> Option<ReportField> {
    hashify::map_ignore_case!(name.as_bytes(), ReportField,
        "Reporting-UA" => ReportField::ReportingUa,
        "MDN-Gateway" => ReportField::MdnGateway,
        "Original-Recipient" => ReportField::OriginalRecipient,
        "Final-Recipient" => ReportField::FinalRecipient,
        "Original-Message-ID" => ReportField::OriginalMessageId,
        "Disposition" => ReportField::Disposition,
        "Error" => ReportField::Error,
        "Failure" => ReportField::Ignore,
        "Warning" => ReportField::Ignore,
    )
    .copied()
}

fn apply_report_field(mdn: &mut Mdn, name: &str, value: String) {
    match report_field(name) {
        Some(ReportField::ReportingUa) => mdn.reporting_ua = Some(value),
        Some(ReportField::MdnGateway) => mdn.mdn_gateway = Some(value),
        Some(ReportField::OriginalRecipient) => mdn.original_recipient = Some(value),
        Some(ReportField::FinalRecipient) => mdn.final_recipient = Some(value),
        Some(ReportField::OriginalMessageId) => mdn.original_message_id = Some(value),
        Some(ReportField::Disposition) => mdn.disposition = parse_disposition(&value),
        Some(ReportField::Error) => {
            let errors = mdn.error.get_or_insert_with(Vec::new);
            if errors.len() < MAX_ERRORS {
                errors.push(value);
            }
        }
        Some(ReportField::Ignore) => {}
        None => {
            if is_valid_extension_name(name) {
                let fields = mdn.extension_fields.get_or_insert_with(VecMap::new);
                if fields.len() < MAX_EXTENSION_FIELDS {
                    fields.append(name.to_string(), value);
                }
            }
        }
    }
}

fn parse_disposition(value: &str) -> Option<Disposition> {
    let value = strip_comments(value);
    let (modes, disposition_type) = value.split_once(';')?;
    let (action_mode, sending_mode) = modes.split_once('/')?;
    let disposition_type = disposition_type
        .split_once('/')
        .map_or(disposition_type, |(disposition_type, _)| disposition_type);
    Some(Disposition {
        action_mode: ActionMode::parse(action_mode.trim())?,
        sending_mode: SendingMode::parse(sending_mode.trim())?,
        disposition_type: DispositionType::parse(disposition_type.trim())?,
    })
}

fn single_return_path(headers: &HeaderList<'_>, raw_headers: &[u8]) -> Option<String> {
    let mut return_paths = headers.all(HeaderId::RETURN_PATH);
    let (Some(header), None) = (return_paths.next(), return_paths.next()) else {
        return None;
    };
    let parsed = HeaderForm::Addresses.parse(header.raw_value(raw_headers)?);
    parsed
        .value()
        .as_address()
        .and_then(|list| list.mailboxes().next())
        .and_then(|mailbox| mailbox.address())
        .and_then(sanitize_email)
}

fn strip_comments(value: &str) -> Cow<'_, str> {
    if !value.contains('(') {
        return Cow::Borrowed(value);
    }
    let mut result = String::with_capacity(value.len());
    let mut depth = 0usize;
    let mut escaped = false;
    for ch in value.chars() {
        if depth > 0 {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
            }
        } else if ch == '(' {
            depth = 1;
        } else {
            result.push(ch);
        }
    }
    Cow::Owned(result)
}

fn default_subject(disposition_type: DispositionType, subject: Option<&str>) -> String {
    let prefix = match disposition_type {
        DispositionType::Displayed => "Read",
        DispositionType::Deleted => "Not read",
        DispositionType::Dispatched => "Dispatched",
        DispositionType::Processed => "Processed",
    };
    match subject {
        Some(subject) => format!("{prefix}: {subject}"),
        None => prefix.to_string(),
    }
}

fn default_text(disposition_type: DispositionType, subject: Option<&str>) -> String {
    let outcome = match disposition_type {
        DispositionType::Displayed => {
            "was displayed to the recipient. This is no guarantee that the message has been read or understood."
        }
        DispositionType::Deleted => "was deleted. The recipient may or may not have seen it.",
        DispositionType::Dispatched => {
            "was dispatched by the recipient without necessarily being displayed."
        }
        DispositionType::Processed => "was processed without being displayed to the recipient.",
    };
    match subject {
        Some(subject) => format!("Your message \"{subject}\" {outcome}\r\n"),
        None => format!("Your message {outcome}\r\n"),
    }
}

fn is_valid_field_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FIELD_LEN
        && !value.chars().any(|ch| ch.is_control() && ch != '\t')
}

fn is_valid_extension_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FIELD_NAME_LEN
        && name
            .bytes()
            .all(|ch| (33..=126).contains(&ch) && ch != b':')
        && report_field(name).is_none()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/message/mdn/tests.rs"]
mod tests;
