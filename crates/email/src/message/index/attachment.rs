/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::metadata::{
    ArchivedMessageMetadata, ArchivedMessageMetadataPart, ArchivedMetadataPartType,
    DecodedPartContent, PART_SIZE_MASK,
};
use common::config::mailstore::email::ExtractLimits;
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use store::search::{EmailSearchField, IndexDocument, SearchField};
use text_extract::{Extractor, Format, Hints, Limits};
use utils::chained_bytes::ChainedBytes;

const MESSAGE_TEXT_DOCUMENTS: usize = 2;
const MAX_LANGUAGE_SAMPLE: usize = 64 << 10;

pub(super) struct AttachmentText {
    extractor: Option<Extractor>,
    limits: Limits,
    text: String,
    remaining_text: usize,
    remaining_decompressed: u64,
}

pub fn document_limits(config: &ExtractLimits) -> Limits {
    let defaults = Limits::default();
    Limits {
        max_input_bytes: config.max_document_size,
        max_output_bytes: config.max_text_size,
        max_part_bytes: defaults.max_part_bytes.min(config.max_decompressed_size),
        max_total_bytes: config.max_decompressed_size,
        ..defaults
    }
}

impl ArchivedMessageMetadataPart {
    pub fn extraction_hints(&self) -> Hints<'_> {
        let mut hints = Hints::new();
        if let Some(content_type) = self.content_type() {
            hints = hints.with_media_type_parts(
                content_type.ctype(),
                content_type.subtype().unwrap_or_default(),
            );
        }
        if let Some(name) = self.attachment_name() {
            hints = hints.with_file_name(name);
        }
        hints
    }

    pub fn has_extractable_text(&self) -> bool {
        match self.body {
            ArchivedMetadataPartType::Binary => self.extraction_hints().may_be_supported(),
            ArchivedMetadataPartType::Text => self.is_rtf_text(),
            _ => false,
        }
    }

    fn is_rtf_text(&self) -> bool {
        match self.content_type() {
            Some(content_type) if content_type.ctype().eq_ignore_ascii_case("text") => content_type
                .subtype()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rtf")),
            _ => self.extraction_hints().format() == Some(Format::Rtf),
        }
    }

    fn decoded_size(&self) -> usize {
        (self.flags.to_native() & PART_SIZE_MASK) as usize
    }
}

impl ArchivedMessageMetadata {
    pub fn has_extractable_attachments(&self) -> bool {
        self.contents.iter().any(|contents| {
            contents
                .parts
                .iter()
                .any(ArchivedMessageMetadataPart::has_extractable_text)
        })
    }
}

impl AttachmentText {
    pub(super) fn new(config: &ExtractLimits) -> Self {
        AttachmentText {
            extractor: None,
            limits: document_limits(config),
            text: String::new(),
            remaining_text: config.max_text_size.saturating_mul(MESSAGE_TEXT_DOCUMENTS),
            remaining_decompressed: config.max_decompressed_size,
        }
    }

    pub(super) fn index_binary(
        &mut self,
        part: &ArchivedMessageMetadataPart,
        raw_message: &ChainedBytes<'_>,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
    ) {
        let hints = part.extraction_hints();
        if !hints.may_be_supported()
            || self.remaining_text == 0
            || part.decoded_size() > self.limits.max_input_bytes
        {
            return;
        }
        if let DecodedPartContent::Binary(contents) = part.decode_contents(raw_message)
            && self.extract(&contents, hints)
        {
            self.index(document, detector, language);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn index_rtf(
        &mut self,
        part: &ArchivedMessageMetadataPart,
        contents: &str,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
        field: EmailSearchField,
    ) -> bool {
        if part.is_rtf_text() && self.extract(contents.as_bytes(), part.extraction_hints()) {
            self.index_field(document, detector, language, field);
            true
        } else {
            false
        }
    }

    fn extract(&mut self, contents: &[u8], hints: Hints<'_>) -> bool {
        if self.remaining_text == 0
            || (self.remaining_decompressed == 0 && hints.format() != Some(Format::Rtf))
        {
            return false;
        }
        let defaults = &self.limits;
        let extractor = self
            .extractor
            .get_or_insert_with(|| Extractor::new(defaults.clone()));
        let limits = extractor.limits_mut();
        limits.max_output_bytes = defaults.max_output_bytes.min(self.remaining_text);
        limits.max_total_bytes = defaults.max_total_bytes.min(self.remaining_decompressed);
        self.text.clear();
        let text = &mut self.text;
        match catch_unwind(AssertUnwindSafe(|| {
            extractor.extract(contents, hints, text)
        })) {
            Ok(Ok(extraction)) => {
                self.remaining_text = self.remaining_text.saturating_sub(extraction.bytes_written);
                self.remaining_decompressed = self
                    .remaining_decompressed
                    .saturating_sub(extraction.bytes_decompressed);
                !self.text.is_empty()
            }
            Ok(Err(failure)) => {
                self.remaining_decompressed = self
                    .remaining_decompressed
                    .saturating_sub(failure.bytes_decompressed);
                false
            }
            Err(_) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "Attachment text extraction panicked",
                );
                self.extractor = None;
                self.remaining_text = 0;
                false
            }
        }
    }

    fn index(
        &self,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
    ) {
        self.index_field(document, detector, language, EmailSearchField::Attachment);
    }

    fn index_field(
        &self,
        document: &mut IndexDocument,
        detector: &mut LanguageDetector,
        language: Language,
        field: EmailSearchField,
    ) {
        if language.is_unknown() {
            detector.detect(language_sample(&self.text), MIN_LANGUAGE_SCORE);
        }
        document.index_text(SearchField::Email(field), &self.text, language);
    }
}

fn language_sample(text: &str) -> &str {
    if text.len() <= MAX_LANGUAGE_SAMPLE {
        return text;
    }
    text.get(..text.floor_char_boundary(MAX_LANGUAGE_SAMPLE))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::message::metadata::{
        ArchivedMessageMetadata, MessageMetadata, build_metadata_contents,
    };
    use common::config::mailstore::email::ExtractLimits;
    use mail_builder::MessageBuilder;
    use mail_parser::MessageParser;
    use nlp::language::Language;
    use store::{
        ahash::AHashSet,
        search::{EmailSearchField, IndexDocument, SearchField, SearchValue},
    };
    use types::blob_hash::BlobHash;

    const DOCX: &[u8] =
        include_bytes!("../../../../text-extract/tests/fixtures/real/textutil.docx");
    const DOCX_TYPE: &str =
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

    const LIMITS: ExtractLimits = ExtractLimits {
        max_document_size: 64 << 20,
        max_text_size: 4 << 20,
        max_decompressed_size: 256 << 20,
    };

    fn index_with(raw_message: &[u8], limits: &ExtractLimits) -> (bool, IndexDocument) {
        let message = MessageParser::new()
            .parse(raw_message)
            .unwrap_or_else(|| panic!("message did not parse"));
        let metadata = MessageMetadata {
            contents: build_metadata_contents(message),
            blob_hash: BlobHash::default(),
            blob_body_offset: 0,
            preview: Default::default(),
            raw_headers: Default::default(),
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&metadata)
            .unwrap_or_else(|err| panic!("archive: {err}"));
        let archived = rkyv::access::<ArchivedMessageMetadata, rkyv::rancor::Error>(&bytes)
            .unwrap_or_else(|err| panic!("access: {err}"));
        let document = archived.index_document(
            1,
            2,
            raw_message,
            &AHashSet::default(),
            Language::English,
            limits,
        );
        (archived.has_extractable_attachments(), document)
    }

    fn field_text(document: &IndexDocument, field: EmailSearchField) -> Option<String> {
        document
            .fields()
            .find_map(|(indexed, value)| match (indexed, value) {
                (SearchField::Email(indexed), SearchValue::Text { value, .. })
                    if *indexed == field =>
                {
                    Some(value.clone())
                }
                _ => None,
            })
    }

    fn index(raw_message: &[u8]) -> (bool, Option<String>) {
        let (extractable, document) = index_with(raw_message, &LIMITS);
        (
            extractable,
            field_text(&document, EmailSearchField::Attachment),
        )
    }

    fn message_with_attachment(content_type: &str, name: &str, contents: &str) -> Vec<u8> {
        MessageBuilder::new()
            .from("sender@example.com")
            .to("rcpt@example.com")
            .subject("Notes")
            .text_body("body")
            .attachment(content_type, name, contents)
            .write_to_vec()
            .expect("message builds")
    }

    #[test]
    fn text_plain_named_rtf_is_indexed_as_text() {
        let raw_message =
            message_with_attachment("text/plain", "notes.rtf", "plain meeting notes here");
        let (extractable, attachment) = index(&raw_message);
        assert!(!extractable);
        let attachment = attachment.expect("attachment text indexed");
        assert!(
            attachment.contains("plain meeting notes here"),
            "{attachment:?}"
        );

        let raw_message = message_with_attachment(
            "text/plain",
            "raw.rtf",
            "{\\rtf1\\ansi literal source\\par}",
        );
        let attachment = index(&raw_message).1.expect("attachment text indexed");
        assert!(attachment.contains("rtf1"), "{attachment:?}");
    }

    #[test]
    fn failed_rtf_extraction_falls_back_to_raw_text() {
        let raw_message =
            message_with_attachment("text/rtf", "notes.rtf", "not rtf at all, just words");
        let (extractable, attachment) = index(&raw_message);
        assert!(extractable);
        let attachment = attachment.expect("attachment text indexed");
        assert!(
            attachment.contains("not rtf at all, just words"),
            "{attachment:?}"
        );

        let raw_message = message_with_attachment(
            "text/rtf",
            "big.rtf",
            "{\\rtf1\\ansi oversized document\\par}",
        );
        let (_, document) = index_with(
            &raw_message,
            &ExtractLimits {
                max_document_size: 8,
                ..LIMITS
            },
        );
        let attachment =
            field_text(&document, EmailSearchField::Attachment).expect("attachment text indexed");
        assert!(attachment.contains("oversized document"), "{attachment:?}");
    }

    #[test]
    fn rtf_extraction_indexes_extracted_text_only() {
        let raw_message = message_with_attachment(
            "text/rtf",
            "notes.rtf",
            "{\\rtf1\\ansi caf\\'e9 {\\*\\generator hidden}notes\\par}",
        );
        let (_, document) = index_with(
            &raw_message,
            &ExtractLimits {
                max_decompressed_size: 0,
                ..LIMITS
            },
        );
        let attachment =
            field_text(&document, EmailSearchField::Attachment).expect("attachment text indexed");
        assert!(attachment.contains("caf\u{e9} notes"), "{attachment:?}");
        assert!(
            !attachment.contains("rtf1")
                && !attachment.contains("hidden")
                && !attachment.contains("generator"),
            "{attachment:?}"
        );
        let body = field_text(&document, EmailSearchField::Body).expect("body indexed");
        assert!(
            !body.contains("notes") && !body.contains("rtf1"),
            "{body:?}"
        );
    }

    #[test]
    fn docx_attachment_becomes_searchable_text() {
        let raw_message = MessageBuilder::new()
            .from(("Sender", "sender@example.com"))
            .to("rcpt@example.com")
            .subject("Quarterly report")
            .text_body("See attached")
            .attachment(DOCX_TYPE, "report.docx", DOCX)
            .attachment("image/png", "logo.png", &b"\x89PNG\r\n\x1a\nnot really"[..])
            .write_to_vec()
            .unwrap_or_default();
        let (extractable, attachment) = index(&raw_message);
        assert!(extractable);
        let attachment = attachment.unwrap_or_default();
        assert!(
            attachment.contains("Second paragraph with the word Stalwart."),
            "{attachment:?}"
        );
        assert!(attachment.contains("r\u{e9}sum\u{e9}"));
        assert!(!attachment.contains("PNG"));

        let raw_message = MessageBuilder::new()
            .from("sender@example.com")
            .to("rcpt@example.com")
            .subject("Mislabeled")
            .text_body("See attached")
            .attachment("application/octet-stream", "scan", DOCX)
            .attachment(
                "text/rtf",
                "notes.rtf",
                "{\\rtf1\\ansi caf\\'e9 {\\*\\generator hidden}notes\\par}",
            )
            .write_to_vec()
            .unwrap_or_default();
        let (extractable, attachment) = index(&raw_message);
        assert!(extractable);
        let attachment = attachment.unwrap_or_default();
        assert!(attachment.contains("Stalwart"), "{attachment:?}");
        assert!(attachment.contains("caf\u{e9} notes"), "{attachment:?}");
        assert!(!attachment.contains("rtf1") && !attachment.contains("hidden"));

        let raw_message = MessageBuilder::new()
            .from("sender@example.com")
            .to("rcpt@example.com")
            .subject("No documents")
            .text_body("body")
            .attachment("application/pdf", "file.pdf", &b"%PDF-1.7"[..])
            .write_to_vec()
            .unwrap_or_default();
        assert_eq!(index(&raw_message), (false, None));
    }
}
