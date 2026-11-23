/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::action_editheader::RemoveCrLf;
use crate::{
    Context, Sieve,
    bytecode::{ops, rec::tag},
    runtime::{
        RuntimeError, Variable,
        eval::ValueRef,
        handler::Action,
        message::{
            body::TextForm,
            edits::{BodyEdit, BodyFormat, BodyKind, Edits, TransferEncoding},
            headers::{HeaderRef, ORIGINAL_FROM, ORIGINAL_SUBJECT},
            parts::{PartCursor, ROOT_PART, subtree_end},
        },
    },
};
use mail_parser::{HeaderName, MessageParser, PartKind};
use std::fmt::Write;

#[cfg(not(all(test, stalwart_tests)))]
use crate::runtime::platform;
#[cfg(not(all(test, stalwart_tests)))]
use mail_builder::headers::date::Date;

impl<'x> Context<'x> {
    pub(crate) fn exec_replace(
        &mut self,
        script: &'x Sieve<'x>,
        replace: &ops::Replace,
    ) -> Result<(), RuntimeError> {
        let Some(part) = self.current_part() else {
            return Ok(());
        };
        let part_id = part.id();
        self.edits.hide(part_id + 1..subtree_end(part));
        self.has_changes = true;

        let body = self.eval_value(script, replace.replacement)?.into_string();
        let body = self.intern_cow(body);
        let has_subject = replace.subject.tag != tag::NONE;
        let has_from = replace.from.tag != tag::NONE;

        let (format, encoding, encoded_len) = if replace.mime {
            TransferEncoding::select_entity(body)
        } else {
            let (encoding, encoded_len) = TransferEncoding::select(body);
            (BodyFormat::Content, encoding, encoded_len)
        };
        let previous_size = match self.edits.body(part_id) {
            Some(edited) => edited.encoded_len,
            None => part.raw().len(),
        };
        self.message_size = (self.message_size + encoded_len).saturating_sub(previous_size);

        let mut headers = Vec::new();
        if part_id == ROOT_PART {
            let mut add_date = true;
            let mut add_message_id = true;
            let mut add_mime_version = true;
            let mut has_original_from = false;
            let mut kept_size = 0;
            let previous = self.part_headers(part);
            headers.reserve(previous.size_hint().0 + 7);

            for header in previous {
                let header = match header.name() {
                    HeaderName::Subject if has_subject => {
                        self.renamed_header(header, &ORIGINAL_SUBJECT)
                    }
                    HeaderName::From if has_from => self.renamed_header(header, &ORIGINAL_FROM),
                    HeaderName::From => {
                        has_original_from = true;
                        header
                    }
                    HeaderName::Date => {
                        add_date = false;
                        header
                    }
                    HeaderName::MessageId => {
                        add_message_id = false;
                        header
                    }
                    HeaderName::MimeVersion => {
                        add_mime_version = false;
                        header
                    }
                    name if name.is_content_header() => continue,
                    _ => header,
                };
                kept_size += header.len();
                headers.push(header);
            }
            self.message_size += kept_size;

            let mut add_from = true;
            if let Some(from) = self.eval_opt(script, replace.from)?
                && !from.is_empty()
            {
                let from = self.header_value(from.to_string().as_ref());
                headers.push(self.new_header(HeaderName::From, from));
                add_from = false;
            }
            if add_from && !has_original_from {
                let from = self.alloc_string(self.user_from_field());
                headers.push(self.new_header(HeaderName::From, from));
            }

            if let Some(subject) = self.eval_opt(script, replace.subject)?
                && !subject.is_empty()
            {
                let subject = self.header_value(subject.to_string().as_ref());
                headers.push(self.new_header(HeaderName::Subject, subject));
            }

            if add_date {
                let date = self.alloc_string(self.current_date());
                headers.push(self.new_header(HeaderName::Date, date));
            }

            if add_message_id {
                let message_id = self.alloc_string(self.generate_message_id());
                headers.push(self.new_header(HeaderName::MessageId, message_id));
            }

            if add_mime_version {
                headers.push(self.new_header(HeaderName::MimeVersion, "1.0"));
            }
        }

        if !replace.mime {
            headers.push(self.new_header(HeaderName::ContentType, "text/plain; charset=utf-8"));
        }
        if let Some(cte) = encoding.header_value() {
            headers.push(self.new_header(HeaderName::ContentTransferEncoding, cte));
        }

        self.edits.set_headers(part_id, headers);
        self.set_part_body(
            part_id,
            BodyEdit {
                text: body,
                kind: BodyKind::Text,
                format,
                encoding,
                encoded_len,
            },
        );

        Ok(())
    }

    pub(crate) fn exec_enclose(
        &mut self,
        script: &'x Sieve<'x>,
        enclose: &ops::Enclose,
    ) -> Result<(), RuntimeError> {
        let body = self.eval_value(script, enclose.value)?.into_string();
        let subject = match self.eval_opt(script, enclose.subject)? {
            Some(subject) => subject
                .to_string()
                .as_ref()
                .remove_crlf(self.runtime.max_header_size),
            None => self
                .root_text(&HeaderName::Subject)
                .unwrap_or_default()
                .remove_crlf(self.runtime.max_header_size),
        };

        #[cfg(all(test, stalwart_tests))]
        let boundary = make_test_boundary();
        #[cfg(not(all(test, stalwart_tests)))]
        let boundary = platform::make_boundary();

        let enclosed = self.build_message();
        let mut message = String::with_capacity(512);
        for received in self
            .message
            .root()
            .headers()
            .all(HeaderName::Received)
            .take(self.runtime.max_received_headers)
        {
            let value = received.raw_value();
            message.push_str("Received:");
            message.push_str(&String::from_utf8_lossy(value));
            if !value.ends_with(b"\n") {
                message.push_str("\r\n");
            }
        }
        let _ = write!(
            message,
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\nSubject: {subject}\r\n"
        );

        let mut add_date = true;
        let mut add_message_id = true;
        let mut add_from = true;

        let mut iter = script.recs(enclose.headers)?;
        while let Some(rec) = iter.next() {
            let header = ValueRef::decode(script, rec, &mut iter)?;
            let header = self.eval_value_ref(script, header)?;
            if let Some((mut header_name, mut header_value)) =
                header.to_string().as_ref().split_once(':')
            {
                header_name = header_name.trim();
                header_value = header_value.trim();
                if !header_value.is_empty()
                    && let Some(name) = HeaderName::parse(header_name)
                    && !self.runtime.protected_headers.contains(&name)
                {
                    match &name {
                        HeaderName::Date => add_date = false,
                        HeaderName::From => add_from = false,
                        HeaderName::MessageId => add_message_id = false,
                        _ => (),
                    }
                    let header_value = header_value.remove_crlf(self.runtime.max_header_size);
                    let _ = write!(message, "{header_name}: {header_value}\r\n");
                }
            }
        }

        if add_from {
            let _ = write!(message, "From: {}\r\n", self.user_from_field());
        }
        if add_date {
            let _ = write!(message, "Date: {}\r\n", self.current_date());
        }
        if add_message_id {
            let _ = write!(message, "Message-ID: {}\r\n", self.generate_message_id());
        }
        let _ = write!(
            message,
            "\r\n--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n"
        );

        let mut message = message.into_bytes();
        message.reserve(enclosed.len() + boundary.len() + 8);
        message.extend_from_slice(&enclosed);
        message.extend_from_slice(b"\r\n--");
        message.extend_from_slice(boundary.as_bytes());
        message.extend_from_slice(b"--\r\n");

        if !self.arena.charge(message.len()) {
            return Err(RuntimeError::MemoryLimitReached);
        }
        let message = MessageParser::new()
            .parse_owned(message)
            .unwrap_or_default();
        self.message_size = message.raw().len();
        self.message = self.arena.keep_message(message);
        self.edits = Edits::default();
        self.reset_body_cache();
        self.part = ROOT_PART;
        self.part_iter = PartCursor::default();
        for (part, parts) in &mut self.part_iter_stack {
            *part = ROOT_PART;
            *parts = PartCursor::default();
        }
        self.has_changes = true;

        Ok(())
    }

    pub(crate) fn exec_extracttext(
        &mut self,
        script: &'x Sieve<'x>,
        extract: &ops::ExtractText,
    ) -> Result<(), RuntimeError> {
        let mut value = "";

        if !self.part_iter_stack.is_empty()
            && let Some(part) = self.current_part()
        {
            let text = match self.part_kind(part) {
                PartKind::Text => self.part_text(part, TextForm::Source),
                PartKind::Html => self.part_text(part, TextForm::Plain),
                _ => None,
            };
            if let Some(text) = text {
                value = match extract.first {
                    Some(first) => text
                        .char_indices()
                        .nth(first as usize)
                        .and_then(|(end, _)| text.get(..end))
                        .unwrap_or(text),
                    None => text,
                };
            }

            if !extract.modifiers.is_empty() && !value.is_empty() {
                let modified =
                    self.apply_modifiers(script, extract.modifiers, Variable::borrowed(value))?;
                return self.assign_variable(script, extract.name, modified);
            }
        }

        self.assign_variable(script, extract.name, Variable::borrowed(value))
    }

    fn header_value(&self, value: &str) -> &'x str {
        self.alloc_string(value.remove_crlf(self.runtime.max_header_size))
    }

    fn new_header(&mut self, name: HeaderName<'x>, value: &'x str) -> HeaderRef<'x> {
        let header = self.add_header(name, value);
        self.message_size += header.len();
        header
    }

    fn current_date(&self) -> String {
        #[cfg(not(all(test, stalwart_tests)))]
        {
            Date::new(self.current_time).to_rfc822()
        }
        #[cfg(all(test, stalwart_tests))]
        {
            "Tue, 20 Nov 2022 05:14:20 -0300".to_string()
        }
    }

    fn generate_message_id(&self) -> String {
        #[cfg(not(all(test, stalwart_tests)))]
        {
            let mut header_value = Vec::with_capacity(self.runtime.local_hostname.len() + 64);
            platform::write_message_id(&mut header_value, &self.runtime.local_hostname);
            String::from_utf8(header_value).unwrap_or_default()
        }
        #[cfg(all(test, stalwart_tests))]
        {
            "<auto-generated@message-id>".to_string()
        }
    }

    pub(crate) fn build_message_id(&mut self) -> Option<Action<'x>> {
        if self.has_changes {
            self.last_message_id += 1;
            self.main_message_id = self.last_message_id;
            self.has_changes = false;
            let message = self.build_message();
            Some(Action::CreatedMessage {
                message_id: self.main_message_id,
                message,
            })
        } else {
            None
        }
    }
}

#[cfg(all(test, stalwart_tests))]
thread_local!(static COUNTER: std::cell::Cell<u64>  = 0.into());

#[cfg(all(test, stalwart_tests))]
pub(crate) fn make_test_boundary() -> String {
    format!("boundary_{}", COUNTER.with(|c| { c.replace(c.get() + 1) }))
}

#[cfg(all(test, stalwart_tests))]
pub(crate) fn reset_test_boundary() {
    COUNTER.with(|c| c.replace(0));
}
