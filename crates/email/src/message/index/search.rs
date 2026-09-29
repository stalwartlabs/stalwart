/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{MAX_MESSAGE_PARTS, attachment::AttachmentText, extractors::VisitText},
    metadata::{
        AddressHeader, AddressItem, Addresses, ArchivedMessageMetadata, EnvelopeView, HeaderId,
        HeaderList, HeaderSelection, Occurrence, PartFlags, PartKind, PartSource, PartView,
    },
};
use common::config::mailstore::email::ExtractLimits;
use mail_parser::{HeaderForm, HeaderValue, html_to_text, thread_name};
use nlp::{
    language::{
        Language,
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
    },
    tokenizers::word::WordTokenizer,
};
use std::{borrow::Cow, str::from_utf8};
use store::{
    ahash::AHashSet,
    backend::MAX_TOKEN_LENGTH,
    search::{EmailSearchField, IndexDocument, SearchField},
    write::SearchIndex,
};

struct DocumentBuilder<'x> {
    document: IndexDocument,
    detector: LanguageDetector,
    attachments: AttachmentText,
    index_fields: &'x AHashSet<SearchField>,
}

impl ArchivedMessageMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn index_document(
        &self,
        account_id: u32,
        document_id: u32,
        headers: &[u8],
        blob: &[u8],
        index_fields: &AHashSet<SearchField>,
        default_language: Language,
        extract_limits: &ExtractLimits,
    ) -> IndexDocument {
        let mut builder = DocumentBuilder {
            document: IndexDocument::new(SearchIndex::Email)
                .with_account_id(account_id)
                .with_document_id(document_id),
            detector: LanguageDetector::new(),
            attachments: AttachmentText::new(extract_limits),
            index_fields,
        };
        let raw = self.raw_message(Some(headers), blob);
        let source = PartSource::Raw(raw);
        let root = self.root();
        let truncated = self.completeness().is_truncated();
        let mut language = Language::Unknown;

        for part in root.parts().take(MAX_MESSAGE_PARTS) {
            let part_language = part.language().unwrap_or(language);
            if part.id() == 0 {
                language = part_language;
                let root_headers = part.selected_headers(headers, builder.root_selection());
                if truncated {
                    builder.index_header_addresses(root_headers.list(), headers);
                } else {
                    builder.index_envelope(root.envelope().addresses_of_interest());
                }
                builder.index_root_headers(root_headers.list(), headers, part_language);
            }

            match part.kind() {
                PartKind::Text | PartKind::Html => {
                    let Some(text) = part.plain_text(&source) else {
                        continue;
                    };
                    let field = if part.flags().contains(PartFlags::IN_TEXT_BODY)
                        || part.flags().contains(PartFlags::IN_HTML_BODY)
                    {
                        EmailSearchField::Body
                    } else {
                        EmailSearchField::Attachment
                    };
                    builder.index_part_text(part, &text, part_language, field);
                }
                PartKind::Binary if builder.is_enabled(EmailSearchField::Attachment) => {
                    builder.attachments.index_binary(
                        part,
                        &source,
                        &mut builder.document,
                        &mut builder.detector,
                        part_language,
                    );
                }
                PartKind::Message if builder.is_enabled(EmailSearchField::Attachment) => {
                    let Some(nested) = part.nested() else {
                        continue;
                    };
                    let nested_language =
                        nested.root_part().language().unwrap_or(Language::Unknown);
                    let nested_source = self.source(nested, raw);
                    let subject = if truncated {
                        nested_source.as_ref().and_then(|source| {
                            nested
                                .root_part()
                                .last_text_in(HeaderId::SUBJECT, source)
                                .map(Cow::Owned)
                        })
                    } else {
                        nested.envelope().subject().map(Cow::Borrowed)
                    };
                    if let Some(subject) = subject {
                        builder.index_text(EmailSearchField::Attachment, &subject, nested_language);
                    }
                    let Some(nested_source) = nested_source else {
                        continue;
                    };
                    for sub_part in nested.parts().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_language);
                        match sub_part.kind() {
                            PartKind::Text | PartKind::Html => {
                                if let Some(text) = sub_part.plain_text(&nested_source) {
                                    builder.index_part_text(
                                        sub_part,
                                        &text,
                                        language,
                                        EmailSearchField::Attachment,
                                    );
                                }
                            }
                            PartKind::Binary => builder.attachments.index_binary(
                                sub_part,
                                &nested_source,
                                &mut builder.document,
                                &mut builder.detector,
                                language,
                            ),
                            _ => (),
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(not(feature = "test_mode"))]
        builder.document.set_unknown_language(
            builder
                .detector
                .most_frequent_language()
                .unwrap_or(default_language),
        );

        #[cfg(feature = "test_mode")]
        builder.document.set_unknown_language(default_language);
        builder.document
    }
}

impl DocumentBuilder<'_> {
    fn is_enabled(&self, field: EmailSearchField) -> bool {
        self.index_fields.is_empty() || self.index_fields.contains(&SearchField::Email(field))
    }

    fn index_text(&mut self, field: EmailSearchField, text: &str, language: Language) {
        if language.is_unknown() {
            self.detector.detect(text, MIN_LANGUAGE_SCORE);
        }
        self.document
            .index_text(SearchField::Email(field), text, language);
    }

    fn index_part_text(
        &mut self,
        part: PartView<'_>,
        text: &str,
        language: Language,
        field: EmailSearchField,
    ) {
        if self.is_enabled(field.clone())
            && !self.attachments.index_rtf(
                part,
                text,
                &mut self.document,
                &mut self.detector,
                language,
                field.clone(),
            )
        {
            self.index_text(field, text, language);
        }
    }

    fn index_envelope<'a>(&mut self, fields: [(EmailSearchField, Addresses<'a>); 4]) {
        for (field, addresses) in fields {
            if self.is_enabled(field.clone()) {
                let search_field = SearchField::Email(field);
                addresses.visit_text(|text| {
                    self.document
                        .index_text(search_field.clone(), text, Language::None);
                });
            }
        }
    }

    fn index_header_addresses(&mut self, list: HeaderList<'_>, headers: &[u8]) {
        for (field, id) in [
            (EmailSearchField::From, HeaderId::FROM),
            (EmailSearchField::To, HeaderId::TO),
            (EmailSearchField::Cc, HeaderId::CC),
            (EmailSearchField::Bcc, HeaderId::BCC),
        ] {
            if !self.is_enabled(field.clone()) {
                continue;
            }
            let search_field = SearchField::Email(field);
            for header in list.all(id) {
                let Some(raw) = headers.get(header.value_range()) else {
                    continue;
                };
                HeaderForm::Addresses
                    .parse(raw)
                    .value()
                    .visit_addresses(|_, text| {
                        self.document
                            .index_text(search_field.clone(), text, Language::None);
                    });
            }
        }
    }

    fn indexes_headers(&self) -> bool {
        #[cfg(not(feature = "test_mode"))]
        let index_headers = self
            .index_fields
            .contains(&SearchField::Email(EmailSearchField::Headers));

        #[cfg(feature = "test_mode")]
        let index_headers = true;

        index_headers
    }

    fn root_selection(&self) -> HeaderSelection<'static> {
        if self.indexes_headers() {
            HeaderSelection::All
        } else {
            HeaderSelection::Ids(&[
                HeaderId::SUBJECT,
                HeaderId::FROM,
                HeaderId::TO,
                HeaderId::CC,
                HeaderId::BCC,
            ])
        }
    }

    fn index_root_headers(&mut self, root: HeaderList<'_>, headers: &[u8], language: Language) {
        let index_headers = self.indexes_headers();
        let index_subject = self.is_enabled(EmailSearchField::Subject);
        for header in root.iter().rev() {
            match header.id() {
                HeaderId::FROM | HeaderId::TO | HeaderId::CC | HeaderId::BCC => {}
                HeaderId::SUBJECT => {
                    if index_subject
                        && let Some(raw) = headers.get(header.value_range())
                        && let Some(subject) = HeaderForm::Text.parse(raw).value().as_text()
                    {
                        self.index_text(EmailSearchField::Subject, thread_name(subject), language);
                    }
                }
                id if index_headers => {
                    let Some(field) = headers.get(header.field_range()) else {
                        continue;
                    };
                    let name = match id.as_str() {
                        Some(name) => Cow::Borrowed(name),
                        None => String::from_utf8_lossy(header.raw_name_in(field)),
                    };
                    let value = id.key_value(header.raw_value_in(field));
                    self.document
                        .insert_key_value(EmailSearchField::Headers, name, value);
                }
                _ => {}
            }
        }
    }
}

impl HeaderId {
    fn key_value_form(self) -> Option<HeaderForm> {
        match self {
            HeaderId::REPLY_TO | HeaderId::SENDER | HeaderId::LIST_ID => {
                Some(HeaderForm::Addresses)
            }
            HeaderId::COMMENTS
            | HeaderId::CONTENT_DESCRIPTION
            | HeaderId::CONTENT_LOCATION
            | HeaderId::CONTENT_TRANSFER_ENCODING => Some(HeaderForm::Text),
            HeaderId::IN_REPLY_TO
            | HeaderId::MESSAGE_ID
            | HeaderId::REFERENCES
            | HeaderId::RESENT_MESSAGE_ID
            | HeaderId::CONTENT_ID => Some(HeaderForm::MessageIds),
            HeaderId::KEYWORDS | HeaderId::CONTENT_LANGUAGE => Some(HeaderForm::CommaList),
            _ => None,
        }
    }

    fn key_value(self, raw: &[u8]) -> String {
        let mut value = String::new();
        let mut push = |text: &str| {
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(text);
        };
        if let Some(form) = self.key_value_form() {
            let parsed = form.parse(raw);
            match parsed.value() {
                parsed @ HeaderValue::Address(_) => {
                    parsed.visit_addresses(|_, text| push(text));
                    return value;
                }
                parsed @ (HeaderValue::Text(_) | HeaderValue::TextList(_)) => {
                    parsed.visit_text(&mut push);
                    return value;
                }
                _ => {}
            }
        }
        for word in WordTokenizer::new(from_utf8(raw).unwrap_or_default(), MAX_TOKEN_LENGTH) {
            push(word.word.as_ref());
        }
        value
    }
}

impl<'a> PartView<'a> {
    fn last_text_in(&self, id: HeaderId, source: &PartSource<'_>) -> Option<String> {
        let ids = [id];
        let headers = self.selected_headers_in(source, HeaderSelection::Ids(&ids));
        let raw = source.get(headers.list().last(id)?.value_range())?;
        HeaderForm::Text
            .parse(&raw)
            .value()
            .as_text()
            .map(str::to_string)
    }

    pub fn plain_text<'x>(&self, source: &PartSource<'x>) -> Option<Cow<'x, str>> {
        let text = self.text(source)?.text;
        Some(if self.kind() == PartKind::Html {
            Cow::Owned(html_to_text(&text))
        } else {
            text
        })
    }
}

impl<'a> Addresses<'a> {
    fn visit_text(&self, mut visitor: impl FnMut(&'a str)) {
        for item in self.iter() {
            match item {
                AddressItem::Mailbox(mailbox) => {
                    mailbox
                        .name
                        .into_iter()
                        .chain(mailbox.address)
                        .for_each(&mut visitor);
                }
                AddressItem::Group(group) => {
                    group.name.into_iter().for_each(&mut visitor);
                    for mailbox in group.members.mailboxes() {
                        mailbox
                            .name
                            .into_iter()
                            .chain(mailbox.address)
                            .for_each(&mut visitor);
                    }
                }
            }
        }
    }
}

impl<'a> EnvelopeView<'a> {
    fn addresses_of_interest(&self) -> [(EmailSearchField, Addresses<'a>); 4] {
        [
            (
                EmailSearchField::From,
                self.addresses(AddressHeader::From, Occurrence::All),
            ),
            (
                EmailSearchField::To,
                self.addresses(AddressHeader::To, Occurrence::All),
            ),
            (
                EmailSearchField::Cc,
                self.addresses(AddressHeader::Cc, Occurrence::All),
            ),
            (
                EmailSearchField::Bcc,
                self.addresses(AddressHeader::Bcc, Occurrence::All),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::message::metadata::{
        Completeness, ExtraHeaders, HeaderId, MAX_FIELD_ADDRESSES, MAX_HEADER_ENTRIES,
        MAX_VALUE_LEN, MessageMetadata, MetadataRow,
    };
    use common::config::mailstore::email::ExtractLimits;
    use mail_parser::MessageParser;
    use nlp::language::Language;
    use store::{
        Deserialize,
        ahash::AHashSet,
        search::{EmailSearchField, IndexDocument, SearchField, SearchValue},
    };
    use types::blob_hash::BlobHash;

    const LIMITS: ExtractLimits = ExtractLimits {
        max_document_size: 64 << 20,
        max_text_size: 4 << 20,
        max_decompressed_size: 256 << 20,
        max_part_size: 64 << 20,
        max_parts: 10_000,
        max_archive_entries: 10_000,
        max_pdf_objects: 1 << 20,
        max_rtf_depth: 256,
    };

    struct Indexed(IndexDocument);

    impl Indexed {
        fn new(raw: &[u8], extra: &ExtraHeaders, fields: &[EmailSearchField]) -> Self {
            let message = MessageParser::new().parse(raw).expect("message parses");
            let row = MessageMetadata::build(&message, extra, BlobHash::generate(raw))
                .encode()
                .expect("row encodes");
            let row = MetadataRow::deserialize(&row).expect("row");
            let headers = row.raw_headers().expect("headers");
            let fields = fields
                .iter()
                .cloned()
                .map(SearchField::Email)
                .collect::<AHashSet<_>>();
            Indexed(row.unarchive().expect("archive").index_document(
                1,
                2,
                &headers,
                raw,
                &fields,
                Language::English,
                &LIMITS,
            ))
        }

        fn text(&self, field: EmailSearchField) -> String {
            self.0
                .fields()
                .filter_map(|(indexed, value)| match (indexed, value) {
                    (SearchField::Email(indexed), SearchValue::Text { value, .. })
                        if *indexed == field =>
                    {
                        Some(value.as_str())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n")
        }

        fn header(&self, name: &str) -> Option<String> {
            self.0
                .fields()
                .find_map(|(indexed, value)| match (indexed, value) {
                    (
                        SearchField::Email(EmailSearchField::Headers),
                        SearchValue::KeyValues(map),
                    ) => map.get(name).cloned(),
                    _ => None,
                })
        }
    }

    #[test]
    fn encoded_nested_message_is_indexed() {
        let nested = concat!(
            "From: Nested Sender <nested@example.com>\r\n",
            "Subject: nested zanzibar report\r\n",
            "Content-Type: multipart/mixed; boundary=\"in\"\r\n",
            "\r\n",
            "--in\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "The quokka lives on Rottnest caf=C3=A9 island\r\n",
            "--in\r\n",
            "Content-Type: text/html\r\n",
            "\r\n",
            "<p>platypus <b>habitat</b></p>\r\n",
            "--in--\r\n",
        );
        let raw = format!(
            concat!(
                "From: Outer <outer@example.com>\r\n",
                "To: Reader <reader@example.com>\r\n",
                "Subject: Fwd: outer subject\r\n",
                "Content-Type: multipart/mixed; boundary=\"out\"\r\n",
                "\r\n",
                "--out\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "outer body wombat\r\n",
                "--out\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}",
                "--out--\r\n",
            ),
            encodify::base64::MIME.encode(nested.as_bytes())
        );
        for extra in [ExtraHeaders::default(), {
            let mut extra = ExtraHeaders::default();
            extra.push(HeaderId::DELIVERED_TO, "reader@example.com");
            extra
        }] {
            let indexed = Indexed::new(raw.as_bytes(), &extra, &[]);
            let attachment = indexed.text(EmailSearchField::Attachment);
            assert!(
                attachment.contains("nested zanzibar report"),
                "{attachment:?}"
            );
            assert!(
                attachment.contains("quokka lives on Rottnest café island"),
                "{attachment:?}"
            );
            assert!(attachment.contains("platypus habitat"), "{attachment:?}");
            let body = indexed.text(EmailSearchField::Body);
            assert!(body.contains("outer body wombat"), "{body:?}");
            assert!(!body.contains("quokka"), "{body:?}");
            assert!(
                indexed
                    .text(EmailSearchField::Subject)
                    .contains("outer subject")
            );
            let from = indexed.text(EmailSearchField::From);
            assert!(
                from.contains("Outer") && from.contains("outer@example.com"),
                "{from:?}"
            );
            assert!(!from.contains("nested@example.com"), "{from:?}");
        }
    }

    #[test]
    fn header_key_values_keep_their_forms() {
        let raw = concat!(
            "From: sender@example.com\r\n",
            "Reply-To: Replies <reply@example.com>, Team: a@example.com;\r\n",
            "Message-ID: <id@example.com>\r\n",
            "Keywords: alpha, beta\r\n",
            "Comments: =?utf-8?q?caf=C3=A9?= talk\r\n",
            "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\n",
            "X-Custom-Header: some-token value!\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Subject: keys\r\n",
            "\r\n",
            "body\r\n",
        );
        let mut extra = ExtraHeaders::default();
        extra.push(HeaderId::X_SPAM_STATUS, "No, reason=card-exists");
        let indexed = Indexed::new(
            raw.as_bytes(),
            &extra,
            &[EmailSearchField::Headers, EmailSearchField::Subject],
        );
        assert_eq!(
            indexed.header("reply-to").as_deref(),
            Some("Replies reply@example.com Team a@example.com")
        );
        assert_eq!(
            indexed.header("message-id").as_deref(),
            Some("id@example.com")
        );
        assert_eq!(indexed.header("keywords").as_deref(), Some("alpha beta"));
        assert_eq!(indexed.header("comments").as_deref(), Some("café talk"));
        assert!(
            indexed
                .header("date")
                .is_some_and(|date| date.contains("2024"))
        );
        assert!(
            indexed
                .header("x-custom-header")
                .is_some_and(|value| value.contains("token") && !value.contains('!'))
        );
        assert!(
            indexed
                .header("x-spam-status")
                .is_some_and(|value| value.contains("card"))
        );
        assert!(indexed.header("from").is_none());
        assert!(indexed.header("subject").is_none());
        assert_eq!(indexed.text(EmailSearchField::Subject), "keys");
        assert!(indexed.text(EmailSearchField::From).is_empty());
    }

    #[test]
    fn truncated_rows_index_from_section_b() {
        let mut raw = String::from("To: ");
        for index in 0..MAX_FIELD_ADDRESSES + 10 {
            if index > 0 {
                raw.push_str(",\r\n ");
            }
            raw.push_str(&format!("r{index}@example.com"));
        }
        raw.push_str("\r\nFrom: Sender <sender@example.com>\r\n");
        for index in 0..MAX_HEADER_ENTRIES {
            raw.push_str(&format!("X-Junk-{}: value\r\n", index % 97));
        }
        let padding = "p".repeat(MAX_VALUE_LEN);
        raw.push_str(&format!(
            concat!(
                "Subject: capybara outer\r\n",
                "X-After: marmoset\r\n",
                "Cc: late@example.com\r\n",
                "Content-Type: multipart/mixed; boundary=\"out\"\r\n",
                "\r\n",
                "--out\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "outer body\r\n",
                "--out\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n",
                "Subject: nested {} okapi\r\n",
                "\r\n",
                "nested body\r\n",
                "--out--\r\n",
            ),
            padding
        ));
        let message = MessageParser::new().parse(raw.as_bytes()).expect("parses");
        let row = MessageMetadata::build(&message, &ExtraHeaders::default(), BlobHash::default())
            .encode()
            .expect("row encodes");
        let row = MetadataRow::deserialize(&row).expect("row");
        assert_eq!(
            row.unarchive().expect("archive").completeness(),
            Completeness::Truncated
        );

        let indexed = Indexed::new(raw.as_bytes(), &ExtraHeaders::default(), &[]);
        let to = indexed.text(EmailSearchField::To);
        assert!(
            to.contains(&format!("r{}@example.com", MAX_FIELD_ADDRESSES + 9)),
            "last To address missing"
        );
        assert!(
            indexed
                .text(EmailSearchField::From)
                .contains("sender@example.com")
        );
        assert!(
            indexed
                .text(EmailSearchField::Cc)
                .contains("late@example.com")
        );
        assert!(
            indexed
                .text(EmailSearchField::Subject)
                .contains("capybara outer")
        );
        assert!(indexed.text(EmailSearchField::Attachment).contains("okapi"));
        let indexed = Indexed::new(
            raw.as_bytes(),
            &ExtraHeaders::default(),
            &[EmailSearchField::Headers],
        );
        assert!(
            indexed
                .header("x-after")
                .is_some_and(|value| value.contains("marmoset"))
        );
    }
}
