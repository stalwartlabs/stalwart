/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::extractors::VisitText,
    metadata::{ArchivedMessageMetadata, HeaderId, HeaderList, HeaderSelection},
};
use mail_parser::{HeaderForm, HeaderName, HeaderValue, Message, thread_name};
use std::borrow::Cow;
use store::xxhash_rust::xxh3::xxh3_128;

#[derive(Debug, Default)]
pub struct ThreadFields<'m> {
    pub subject: &'m str,
    pub message_id: Option<String>,
    pub message_ids: Vec<u128>,
    pub sent_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadSubject<'x> {
    Resolved(&'x str),
    InHeaders,
}

impl<'m> ThreadFields<'m> {
    pub fn scan(message: &'m Message<'_>) -> Self {
        let mut fields = ThreadFields::default();
        let mut date_seen = false;
        for header in message.root_part().headers().iter().rev() {
            let value = header.value();
            match header.name() {
                HeaderName::MessageId => value.visit_text(|id| {
                    if !id.is_empty() {
                        if fields.message_id.is_none() {
                            fields.message_id = id.to_string().into();
                        }
                        fields.message_ids.push(xxh3_128(id.as_bytes()));
                    }
                }),
                HeaderName::InReplyTo | HeaderName::References | HeaderName::ResentMessageId => {
                    value.visit_text(|id| {
                        if !id.is_empty() {
                            fields.message_ids.push(xxh3_128(id.as_bytes()));
                        }
                    });
                }
                HeaderName::Subject if fields.subject.is_empty() => {
                    fields.subject = subject_thread_name(value);
                }
                HeaderName::Date if !date_seen => {
                    date_seen = true;
                    fields.sent_at = value.as_datetime().map(|date| date.to_timestamp());
                }
                _ => (),
            }
        }
        fields.message_ids.sort_unstable();
        fields.message_ids.dedup();
        fields
    }
}

impl ArchivedMessageMetadata {
    pub fn thread_subject(&self) -> ThreadSubject<'_> {
        if self.completeness().is_truncated() {
            return ThreadSubject::InHeaders;
        }
        let root = self.root();
        let name = thread_name(root.envelope().subject().unwrap_or_default());
        if !name.is_empty()
            || root
                .root_part()
                .headers()
                .all(HeaderId::SUBJECT)
                .nth(1)
                .is_none()
        {
            ThreadSubject::Resolved(name)
        } else {
            ThreadSubject::InHeaders
        }
    }

    pub fn thread_subject_in(&self, headers: &[u8]) -> Cow<'_, str> {
        let root = self
            .root()
            .root_part()
            .selected_headers(headers, HeaderSelection::Ids(&[HeaderId::SUBJECT]));
        self.thread_subject_with(root.list(), headers)
    }

    pub fn thread_subject_with(&self, root: HeaderList<'_>, headers: &[u8]) -> Cow<'_, str> {
        if let ThreadSubject::Resolved(name) = self.thread_subject() {
            return Cow::Borrowed(name);
        }
        root.iter()
            .rev()
            .filter(|header| header.id() == HeaderId::SUBJECT)
            .find_map(|header| {
                let parsed = HeaderForm::Text.parse(header.raw_value(headers)?);
                let name = subject_thread_name(parsed.value());
                (!name.is_empty()).then(|| name.to_string())
            })
            .map_or(Cow::Borrowed(""), Cow::Owned)
    }
}

fn subject_thread_name<'x>(value: HeaderValue<'x>) -> &'x str {
    thread_name(match value {
        HeaderValue::Text(text) => text,
        HeaderValue::TextList(list) => list.first().unwrap_or_default(),
        _ => "",
    })
}

#[cfg(test)]
mod tests {
    use super::{ThreadFields, ThreadSubject};
    use crate::message::metadata::{ExtraHeaders, MAX_VALUE_LEN, MessageMetadata, MetadataRow};
    use mail_parser::{MessageParser, thread_name};
    use store::Deserialize;
    use types::blob_hash::BlobHash;

    fn row(raw: &str) -> (MetadataRow, Vec<u8>) {
        let message = MessageParser::new().parse(raw.as_bytes()).expect("parses");
        let built = MessageMetadata::build(
            &message,
            &ExtraHeaders::default(),
            BlobHash::generate(raw.as_bytes()),
        );
        let headers = built.raw_headers.clone();
        let row = MetadataRow::deserialize(&built.encode().expect("encodes")).expect("row");
        (row, headers)
    }

    #[test]
    fn stored_thread_subject_matches_ingest() {
        let long = format!("Re: {}", "t".repeat(MAX_VALUE_LEN + 64));
        for (raw, resolved) in [
            ("Subject: Re: Hello\r\n\r\nbody\r\n".to_string(), true),
            ("Subject:\r\n\r\nbody\r\n".to_string(), true),
            ("From: a@example.com\r\n\r\nbody\r\n".to_string(), true),
            (
                "Subject: Hello\r\nFrom: a@example.com\r\nSubject:\r\n\r\nbody\r\n".to_string(),
                false,
            ),
            (
                "Subject: Hello\r\nSubject: Re: \r\n\r\nbody\r\n".to_string(),
                false,
            ),
            (format!("Subject: {long}\r\n\r\nbody\r\n"), false),
        ] {
            let message = MessageParser::new().parse(raw.as_bytes()).expect("parses");
            let ingest = ThreadFields::scan(&message).subject;
            let (row, headers) = row(&raw);
            let meta = row.unarchive().expect("archive");
            assert_eq!(
                matches!(meta.thread_subject(), ThreadSubject::Resolved(_)),
                resolved,
                "{raw:?}"
            );
            assert_eq!(meta.thread_subject_in(&headers), ingest, "{raw:?}");
        }
        let message = MessageParser::new()
            .parse(&b"Subject: Hello\r\nSubject:\r\n\r\nbody\r\n"[..])
            .expect("parses");
        assert_eq!(ThreadFields::scan(&message).subject, "Hello");
        assert_eq!(thread_name(&long).len(), MAX_VALUE_LEN + 64);
    }

    #[test]
    fn sort_date_is_the_sent_at_date() {
        for raw in [
            "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nDate: Tue, 2 Jan 2024 11:00:00 +0000\r\n\r\nx\r\n",
            "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nDate: not a date\r\n\r\nx\r\n",
            "Date: Tue, 2 Jan 2024 11:00:00 +0000\r\n\r\nx\r\n",
        ] {
            let message = MessageParser::new().parse(raw.as_bytes()).expect("parses");
            let sort = ThreadFields::scan(&message).sent_at;
            let (row, _) = row(raw);
            let meta = row.unarchive().expect("archive");
            let property = meta
                .root()
                .envelope()
                .datetime()
                .map(|date| date.to_timestamp());
            assert_eq!(sort, property, "{raw:?}");
        }
        let message = MessageParser::new()
            .parse(
                &b"Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nDate: Tue, 2 Jan 2024 11:00:00 +0000\r\n\r\nx\r\n"[..],
            )
            .expect("parses");
        assert_eq!(ThreadFields::scan(&message).sent_at, Some(1_704_193_200));
    }
}
