/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, config::mailstore::email::ExtractLimits};
use email::message::index::attachment::document_limits;
use groupware::file::{FileNode, content::FileContentKind};
use mail_parser::decoders::html::html_to_text;
use nlp::language::{
    Language,
    detect::{LanguageDetector, MIN_LANGUAGE_SCORE},
};
use std::{
    borrow::Cow,
    panic::{AssertUnwindSafe, catch_unwind},
};
use store::{
    ValueKey,
    search::{FileSearchField, IndexDocument, SearchField},
    write::{Archive, ArchiveBytes, SearchIndex},
};
use trc::AddContext;
use types::collection::Collection;

const HTML_INPUT_FACTOR: usize = 4;

pub(crate) async fn build_file_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let empty_document = || {
        IndexDocument::new(SearchIndex::File)
            .with_account_id(account_id)
            .with_document_id(document_id)
    };
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::File) else {
        return Ok(Some(empty_document()));
    };
    let Some(archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::FileNode,
            document_id,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let node = archive
        .unarchive::<FileNode>()
        .caused_by(trc::location!())?;
    let Some(file) = node.file() else {
        return Ok(None);
    };

    let limits = server.core.email.extract_limits;
    let kind =
        FileContentKind::detect(node.name.as_str(), file.media_type.as_deref()).filter(|_| {
            (index_fields.is_empty()
                || index_fields.contains(&SearchField::File(FileSearchField::Content)))
                && file.size.to_native() as usize <= limits.max_document_size
        });
    let Some(kind) = kind else {
        return Ok(Some(empty_document()));
    };
    let range = match kind {
        FileContentKind::Document => 0..usize::MAX,
        FileContentKind::PlainText => 0..limits.max_text_size,
        FileContentKind::Html => 0..limits.max_text_size.saturating_mul(HTML_INPUT_FACTOR),
    };
    let Some(contents) = server
        .get_blob(file.blob_hash.0.as_slice(), range)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(Some(empty_document()));
    };

    let request = FileIndexRequest {
        account_id,
        document_id,
        file_name: node.name.to_string(),
        media_type: file.media_type.as_deref().map(str::to_string),
        kind,
        contents,
        limits,
        default_language: server.core.email.default_language,
    };
    if kind == FileContentKind::PlainText {
        return Ok(Some(request.build()));
    }
    let document = tokio::task::spawn_blocking(move || request.build())
        .await
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .details("File indexing task failed")
                .caused_by(trc::location!())
        })?;

    Ok(Some(document))
}

struct FileIndexRequest {
    account_id: u32,
    document_id: u32,
    file_name: String,
    media_type: Option<String>,
    kind: FileContentKind,
    contents: Vec<u8>,
    limits: ExtractLimits,
    default_language: Language,
}

impl FileIndexRequest {
    fn build(self) -> IndexDocument {
        let mut document = IndexDocument::new(SearchIndex::File)
            .with_account_id(self.account_id)
            .with_document_id(self.document_id);
        if let Some(text) = self.text() {
            let mut detector = LanguageDetector::new();
            detector.detect(&text, MIN_LANGUAGE_SCORE);
            document.index_text(FileSearchField::Content, &text, Language::Unknown);
            document.set_unknown_language(
                detector
                    .most_frequent_language()
                    .unwrap_or(self.default_language),
            );
        }
        document
    }

    fn text(&self) -> Option<Cow<'_, str>> {
        let max_text_size = self.limits.max_text_size;
        let text = match self.kind {
            FileContentKind::Document => self
                .extract_document()
                .map(Cow::Owned)
                .or_else(|| self.is_rtf().then(|| self.plain_text()))?,
            FileContentKind::Html => Cow::Owned(html_to_text(&lossy_prefix(
                &self.contents,
                max_text_size.saturating_mul(HTML_INPUT_FACTOR),
            ))),
            FileContentKind::PlainText => self.plain_text(),
        };
        let text = match text {
            Cow::Borrowed(text) => {
                Cow::Borrowed(text.get(..text.floor_char_boundary(max_text_size))?)
            }
            Cow::Owned(mut text) => {
                text.truncate(text.floor_char_boundary(max_text_size));
                Cow::Owned(text)
            }
        };
        (!text.trim().is_empty()).then_some(text)
    }

    fn hints(&self) -> text_extract::Hints<'_> {
        let hints = text_extract::Hints::new().with_file_name(&self.file_name);
        match self.media_type.as_deref() {
            Some(media_type) => hints.with_media_type(media_type),
            None => hints,
        }
    }

    fn is_rtf(&self) -> bool {
        self.hints().format() == Some(text_extract::Format::Rtf)
    }

    fn extract_document(&self) -> Option<String> {
        let mut extractor = text_extract::Extractor::new(document_limits(&self.limits));
        let mut text = String::new();
        match catch_unwind(AssertUnwindSafe(|| {
            extractor.extract(&self.contents, self.hints(), &mut text)
        })) {
            Ok(Ok(_)) if !text.trim().is_empty() => Some(text),
            Ok(_) => None,
            Err(_) => {
                trc::event!(
                    Server(trc::ServerEvent::ThreadError),
                    Details = "File text extraction panicked",
                );
                None
            }
        }
    }

    fn plain_text(&self) -> Cow<'_, str> {
        lossy_prefix(&self.contents, self.limits.max_text_size)
    }
}

fn lossy_prefix(contents: &[u8], max_len: usize) -> Cow<'_, str> {
    let bytes = contents
        .get(..contents.len().min(max_len))
        .unwrap_or_default();
    match std::str::from_utf8(bytes) {
        Ok(text) => Cow::Borrowed(text),
        Err(err) if err.error_len().is_none() => bytes
            .get(..err.valid_up_to())
            .and_then(|valid| std::str::from_utf8(valid).ok())
            .map_or(Cow::Borrowed(""), Cow::Borrowed),
        Err(_) => String::from_utf8_lossy(bytes),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/index_queue/file/tests.rs"]
mod tests;
