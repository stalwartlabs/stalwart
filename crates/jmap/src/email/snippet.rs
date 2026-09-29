/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::metadata::{MetadataStructure, PartKind, PartSource},
};
use jmap_proto::{
    method::{
        query::Filter,
        search_snippet::{GetSearchSnippetRequest, GetSearchSnippetResponse, SearchSnippet},
    },
    object::email::EmailFilter,
    request::MaybeInvalid,
};
use nlp::language::{Language, search_snippet::generate_snippet, stemmer::Stemmer};
use std::future::Future;
use store::{ValueKey, backend::MAX_TOKEN_LENGTH};
use trc::AddContext;
use types::{acl::Acl, collection::Collection, field::EmailField};

pub trait EmailSearchSnippet: Sync + Send {
    fn email_search_snippet(
        &self,
        request: GetSearchSnippetRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetSearchSnippetResponse>> + Send;
}

impl EmailSearchSnippet for Server {
    async fn email_search_snippet(
        &self,
        request: GetSearchSnippetRequest,
        access_token: &AccessToken,
    ) -> trc::Result<GetSearchSnippetResponse> {
        let mut filter_stack = vec![];
        let mut include_term = true;
        let mut terms = vec![];
        let mut is_exact = false;
        let mut language = self.core.email.default_language;

        for cond in request.filter {
            match cond {
                Filter::Property(cond) => {
                    if let EmailFilter::Text(text)
                    | EmailFilter::Subject(text)
                    | EmailFilter::Body(text) = cond
                        && include_term
                    {
                        let (text, language_) =
                            Language::detect(text, self.core.email.default_language);
                        language = language_;
                        if (text.starts_with('"') && text.ends_with('"'))
                            || (text.starts_with('\'') && text.ends_with('\''))
                        {
                            for token in language.tokenize_text(&text, MAX_TOKEN_LENGTH) {
                                terms.push(token.word.into_owned());
                            }
                            is_exact = true;
                        } else {
                            for token in Stemmer::new(&text, language, MAX_TOKEN_LENGTH) {
                                terms.push(token.word.into_owned());
                                if let Some(stemmed_word) = token.stemmed_word {
                                    terms.push(stemmed_word.into_owned());
                                }
                            }
                        }
                    }
                }
                Filter::And | Filter::Or => {
                    filter_stack.push(cond);
                }
                Filter::Not => {
                    filter_stack.push(cond);
                    include_term = !include_term;
                }
                Filter::Close => {
                    if matches!(filter_stack.pop(), Some(Filter::Not)) {
                        include_term = !include_term;
                    }
                }
            }
        }
        let account_id = request.account_id.document_id();
        let cached_messages = self
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        let document_ids = if access_token.is_member(account_id) {
            cached_messages.email_document_ids()
        } else {
            cached_messages.shared_messages(access_token, Acl::ReadItems)
        };

        let email_ids = request.email_ids.unwrap();
        let mut response = GetSearchSnippetResponse {
            account_id: request.account_id,
            list: Vec::with_capacity(email_ids.len()),
            not_found: None,
        };
        let mut not_found = Vec::new();

        if email_ids.len() > self.core.jmap.snippet_max_results {
            return Err(trc::JmapEvent::RequestTooLarge.into_err());
        }

        for email_id in email_ids {
            let email_id = match email_id {
                MaybeInvalid::Value(email_id) => email_id,
                invalid => {
                    not_found.push(invalid);
                    continue;
                }
            };
            let document_id = email_id.document_id();
            let mut snippet = SearchSnippet {
                email_id,
                subject: None,
                preview: None,
            };
            if !document_ids.contains(document_id) {
                not_found.push(MaybeInvalid::Value(email_id));
                continue;
            } else if terms.is_empty() {
                response.list.push(snippet);
                continue;
            }
            let structure = match self
                .store()
                .get_value::<MetadataStructure>(ValueKey::immutable(
                    account_id,
                    Collection::Email,
                    document_id,
                    EmailField::Metadata,
                ))
                .await?
            {
                Some(structure) => structure,
                None => {
                    not_found.push(MaybeInvalid::Value(email_id));
                    continue;
                }
            };
            let metadata = structure.unarchive().caused_by(trc::location!())?;
            let root = metadata.root();

            // Add subject snippet
            if let Some(subject) = root
                .envelope()
                .subject()
                .and_then(|subject| generate_snippet(subject, &terms, language, is_exact))
            {
                snippet.subject = subject.into();
            }

            // Download message
            let blob_hash = metadata.blob_hash();
            let Some(raw_body) = self
                .blob_store()
                .get_blob(blob_hash.as_slice(), 0..usize::MAX)
                .await?
            else {
                trc::event!(
                    Store(trc::StoreEvent::NotFound),
                    AccountId = account_id,
                    DocumentId = email_id.document_id(),
                    Collection = Collection::Email,
                    BlobId = blob_hash.as_slice(),
                    Details = "Blob not found.",
                    CausedBy = trc::location!(),
                );

                not_found.push(MaybeInvalid::Value(email_id));
                continue;
            };
            let raw = metadata.raw_message(None, &raw_body);
            let source = PartSource::Raw(raw);

            // Find a matching part
            'outer: for part in root.parts() {
                match part.kind() {
                    PartKind::Text | PartKind::Html => {
                        if let Some(body) = part
                            .plain_text(&source)
                            .and_then(|text| generate_snippet(&text, &terms, language, is_exact))
                        {
                            snippet.preview = body.into();
                            break;
                        }
                    }
                    PartKind::Message => {
                        let Some(nested) = part.nested() else {
                            continue;
                        };
                        let Some(nested_source) = metadata.source(nested, raw) else {
                            continue;
                        };
                        for part in nested.parts().filter(|part| part.is_text()) {
                            if let Some(body) = part.plain_text(&nested_source).and_then(|text| {
                                generate_snippet(&text, &terms, language, is_exact)
                            }) {
                                snippet.preview = body.into();
                                break 'outer;
                            }
                        }
                    }
                    _ => (),
                }
            }

            response.list.push(snippet);
        }

        if !not_found.is_empty() {
            response.not_found = Some(not_found);
        }

        Ok(response)
    }
}
