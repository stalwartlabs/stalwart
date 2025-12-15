/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{MAX_MESSAGE_PARTS, extractors::VisitTextArchived},
    metadata::{
        ArchivedMessageMetadata, ArchivedMetadataHeaderName, ArchivedMetadataHeaderValue,
        ArchivedMetadataPartType, DecodedPartContent, MESSAGE_RECEIVED_MASK, MetadataHeaderName,
    },
};
use mail_parser::{DateTime, decoders::html::html_to_text, parsers::fields::thread::thread_name};
use nlp::{
    language::{
        Language,
        detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
    },
    tokenizers::word::WordTokenizer,
};
use store::{
    ahash::AHashSet,
    backend::MAX_TOKEN_LENGTH,
    search::{EmailSearchField, IndexDocument, SearchField},
    write::SearchIndex,
};
use utils::chained_bytes::ChainedBytes;

impl ArchivedMessageMetadata {
    pub fn index_document(
        &self,
        account_id: u32,
        document_id: u32,
        raw_message: &[u8],
        index_fields: &AHashSet<SearchField>,
        default_language: Language,
    ) -> IndexDocument {
        let mut detector = LanguageDetector::new();
        let mut language = Language::Unknown;
        let message_contents = &self.contents[0];
        let mut document = IndexDocument::new(SearchIndex::Email)
            .with_account_id(account_id)
            .with_document_id(document_id);

        let raw_message = ChainedBytes::new(self.raw_headers.as_ref()).with_last(
            raw_message
                .get(self.blob_body_offset.to_native() as usize..)
                .unwrap_or_default(),
        );

        if index_fields.is_empty()
            || index_fields.contains(&SearchField::Email(EmailSearchField::ReceivedAt))
        {
            document.index_unsigned(
                SearchField::Email(EmailSearchField::ReceivedAt),
                self.rcvd_attach.to_native() & MESSAGE_RECEIVED_MASK,
            );
        }
        if index_fields.is_empty()
            || index_fields.contains(&SearchField::Email(EmailSearchField::Size))
        {
            document.index_unsigned(
                SearchField::Email(EmailSearchField::Size),
                raw_message.len() as u32,
            );
        }

        for (part_id, part) in message_contents
            .parts
            .iter()
            .take(MAX_MESSAGE_PARTS)
            .enumerate()
        {
            let part_language = part.language().unwrap_or(language);
            if part_id == 0 {
                language = part_language;

                for header in part.headers.iter().rev() {
                    match &header.name {
                        ArchivedMetadataHeaderName::From => {
                            if index_fields.is_empty()
                                || index_fields
                                    .contains(&SearchField::Email(EmailSearchField::From))
                            {
                                header.value.visit_addresses(|_, value| {
                                    document.index_text(
                                        SearchField::Email(EmailSearchField::From),
                                        value,
                                        Language::None,
                                    );
                                });
                            }
                        }
                        ArchivedMetadataHeaderName::To => {
                            if index_fields.is_empty()
                                || index_fields.contains(&SearchField::Email(EmailSearchField::To))
                            {
                                header.value.visit_addresses(|_, value| {
                                    document.index_text(
                                        SearchField::Email(EmailSearchField::To),
                                        value,
                                        Language::None,
                                    );
                                });
                            }
                        }
                        ArchivedMetadataHeaderName::Cc => {
                            if index_fields.is_empty()
                                || index_fields.contains(&SearchField::Email(EmailSearchField::Cc))
                            {
                                header.value.visit_addresses(|_, value| {
                                    document.index_text(
                                        SearchField::Email(EmailSearchField::Cc),
                                        value,
                                        Language::None,
                                    );
                                });
                            }
                        }
                        ArchivedMetadataHeaderName::Bcc => {
                            if index_fields.is_empty()
                                || index_fields.contains(&SearchField::Email(EmailSearchField::Bcc))
                            {
                                header.value.visit_addresses(|_, value| {
                                    document.index_text(
                                        SearchField::Email(EmailSearchField::Bcc),
                                        value,
                                        Language::None,
                                    );
                                });
                            }
                        }
                        ArchivedMetadataHeaderName::Subject => {
                            if (index_fields.is_empty()
                                || index_fields
                                    .contains(&SearchField::Email(EmailSearchField::Subject)))
                                && let Some(subject) = header.value.as_text()
                            {
                                let subject = thread_name(subject);

                                if part_language.is_unknown() {
                                    detector.detect(subject, MIN_LANGUAGE_SCORE);
                                }

                                document.index_text(
                                    SearchField::Email(EmailSearchField::Subject),
                                    subject,
                                    part_language,
                                );
                            }
                        }
                        ArchivedMetadataHeaderName::Date => {
                            if (index_fields.is_empty()
                                || index_fields
                                    .contains(&SearchField::Email(EmailSearchField::SentAt)))
                                && let Some(date) = header.value.as_datetime()
                            {
                                document.index_integer(
                                    SearchField::Email(EmailSearchField::SentAt),
                                    DateTime::from(date).to_timestamp(),
                                );
                            }
                        }
                        _ => {
                            #[cfg(not(feature = "test_mode"))]
                            let index_headers = index_fields
                                .contains(&SearchField::Email(EmailSearchField::Headers));

                            #[cfg(feature = "test_mode")]
                            let index_headers = true;

                            if index_headers {
                                let mut value = String::new();
                                match &header.value {
                                    ArchivedMetadataHeaderValue::AddressList(_)
                                    | ArchivedMetadataHeaderValue::AddressGroup(_) => {
                                        header.value.visit_addresses(|_, addr| {
                                            if !value.is_empty() {
                                                value.push(' ');
                                            }
                                            value.push_str(addr);
                                        });
                                    }
                                    ArchivedMetadataHeaderValue::Text(_)
                                    | ArchivedMetadataHeaderValue::TextList(_) => {
                                        header.value.visit_text(|text| {
                                            if !value.is_empty() {
                                                value.push(' ');
                                            }
                                            value.push_str(text);
                                        });
                                    }
                                    _ => {
                                        if (matches!(
                                            header.value,
                                            ArchivedMetadataHeaderValue::ContentType(_)
                                        ) || matches!(
                                            header.name,
                                            ArchivedMetadataHeaderName::Received
                                        )) && let Some(header) =
                                            raw_message.get(header.value_range())
                                        {
                                            let header = std::str::from_utf8(header.as_ref())
                                                .unwrap_or_default();

                                            for word in WordTokenizer::new(header, MAX_TOKEN_LENGTH)
                                            {
                                                if !value.is_empty() {
                                                    value.push(' ');
                                                }
                                                value.push_str(word.word.as_ref());
                                            }
                                        }
                                    }
                                }

                                document.insert_key_value(
                                    EmailSearchField::Headers,
                                    header.name.as_str(),
                                    value,
                                );
                            }
                        }
                    }
                }
            }

            let part_id = part_id as u16;
            match &part.body {
                ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                    let text = match (part.decode_contents(&raw_message), &part.body) {
                        (DecodedPartContent::Text(text), ArchivedMetadataPartType::Text) => text,
                        (DecodedPartContent::Text(html), ArchivedMetadataPartType::Html) => {
                            html_to_text(html.as_ref()).into()
                        }
                        _ => unreachable!(),
                    };

                    if message_contents.is_html_part(part_id)
                        || message_contents.is_text_part(part_id)
                    {
                        if index_fields.is_empty()
                            || index_fields.contains(&SearchField::Email(EmailSearchField::Body))
                        {
                            if part_language.is_unknown() {
                                detector.detect(text.as_ref(), MIN_LANGUAGE_SCORE);
                            }

                            document.index_text(
                                SearchField::Email(EmailSearchField::Body),
                                text.as_ref(),
                                part_language,
                            );
                        }
                    } else if index_fields.is_empty()
                        || index_fields.contains(&SearchField::Email(EmailSearchField::Attachment))
                    {
                        if part_language.is_unknown() {
                            detector.detect(text.as_ref(), MIN_LANGUAGE_SCORE);
                        }

                        document.index_text(
                            SearchField::Email(EmailSearchField::Attachment),
                            text.as_ref(),
                            part_language,
                        );
                    }
                }
                ArchivedMetadataPartType::Message(nested_message_id)
                    if index_fields.is_empty()
                        || index_fields
                            .contains(&SearchField::Email(EmailSearchField::Attachment)) =>
                {
                    let nested_message = self.message_id(*nested_message_id);
                    let nested_message_language = nested_message
                        .root_part()
                        .language()
                        .unwrap_or(Language::Unknown);
                    if let Some(ArchivedMetadataHeaderValue::Text(subject)) = nested_message
                        .root_part()
                        .header_value(&MetadataHeaderName::Subject)
                    {
                        if nested_message_language.is_unknown() {
                            detector.detect(subject.as_ref(), MIN_LANGUAGE_SCORE);
                        }

                        document.index_text(
                            SearchField::Email(EmailSearchField::Attachment),
                            subject.as_ref(),
                            nested_message_language,
                        );
                    }

                    for sub_part in nested_message.parts.iter().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_message_language);
                        match &sub_part.body {
                            ArchivedMetadataPartType::Text | ArchivedMetadataPartType::Html => {
                                let text = match (
                                    sub_part.decode_contents(&raw_message),
                                    &sub_part.body,
                                ) {
                                    (
                                        DecodedPartContent::Text(text),
                                        ArchivedMetadataPartType::Text,
                                    ) => text,
                                    (
                                        DecodedPartContent::Text(html),
                                        ArchivedMetadataPartType::Html,
                                    ) => html_to_text(html.as_ref()).into(),
                                    _ => unreachable!(),
                                };

                                if language.is_unknown() {
                                    detector.detect(text.as_ref(), MIN_LANGUAGE_SCORE);
                                }

                                document.index_text(
                                    SearchField::Email(EmailSearchField::Attachment),
                                    text.as_ref(),
                                    language,
                                );
                            }
                            _ => (),
                        }
                    }
                }
                _ => {}
            }
        }

        #[cfg(not(feature = "test_mode"))]
        document.set_unknown_language(
            detector
                .most_frequent_language()
                .unwrap_or(default_language),
        );

        #[cfg(feature = "test_mode")]
        document.set_unknown_language(default_language);

        let has_attachment =
            document.has_field(&(SearchField::Email(EmailSearchField::Attachment)));

        document.index_bool(EmailSearchField::HasAttachment, has_attachment);
        document
    }
}
