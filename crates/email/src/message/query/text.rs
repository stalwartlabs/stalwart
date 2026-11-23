/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::index::subject::{search_subject, search_subject_query};
use nlp::{language::Language, tokenizers::word::has_alnum_run};
use std::borrow::Cow;
use store::search::{EmailSearchField, SearchFilter};

const MAX_TEXT_TOKENS: usize = 8;

pub(super) fn strip_subject_prefix(text: &str) -> Cow<'_, str> {
    let trimmed = text.trim();
    let quoted = trimmed
        .chars()
        .next()
        .filter(|quote| matches!(quote, '"' | '\''))
        .and_then(|quote| {
            trimmed
                .strip_prefix(quote)?
                .strip_suffix(quote)
                .map(|inner| (quote, inner))
        });
    match quoted {
        Some((quote, inner)) => match search_subject(inner) {
            Cow::Borrowed(name) if name.is_empty() || name.len() == inner.len() => {
                Cow::Borrowed(text)
            }
            name => Cow::Owned(format!("{quote}{name}{quote}")),
        },
        None => search_subject_query(trimmed),
    }
}

pub(super) fn push_text(filters: &mut Vec<SearchFilter>, text: &str, language: Language) {
    let mut tokens = TextTokens { rest: text }.filter(|token| has_alnum_run(token));
    let Some(first) = tokens.next() else {
        push_text_fields(filters, text, language);
        return;
    };
    let Some(second) = tokens.next() else {
        push_text_fields(filters, first, language);
        return;
    };

    filters.push(SearchFilter::And);
    push_text_fields(filters, first, language);
    push_text_fields(filters, second, language);
    for token in tokens.take(MAX_TEXT_TOKENS - 2) {
        push_text_fields(filters, token, language);
    }
    filters.push(SearchFilter::End);
}

fn push_text_fields(filters: &mut Vec<SearchFilter>, text: &str, language: Language) {
    filters.extend([
        SearchFilter::Or,
        SearchFilter::has_text(EmailSearchField::From, text, Language::None),
        SearchFilter::has_text(EmailSearchField::To, text, Language::None),
        SearchFilter::has_text(EmailSearchField::Cc, text, Language::None),
        SearchFilter::has_text(EmailSearchField::Bcc, text, Language::None),
        SearchFilter::has_text(EmailSearchField::Subject, text, language),
        SearchFilter::has_text(EmailSearchField::Body, text, language),
        SearchFilter::has_text(EmailSearchField::Attachment, text, language),
        SearchFilter::End,
    ]);
}

struct TextTokens<'x> {
    rest: &'x str,
}

impl<'x> Iterator for TextTokens<'x> {
    type Item = &'x str;

    fn next(&mut self) -> Option<&'x str> {
        let text = self.rest.trim_start();
        let quote = text.chars().next()?;
        let (token, rest) = matches!(quote, '"' | '\'')
            .then(|| split_phrase(text, quote))
            .flatten()
            .unwrap_or_else(|| text.split_once(char::is_whitespace).unwrap_or((text, "")));
        self.rest = rest;
        Some(token)
    }
}

fn split_phrase(text: &str, quote: char) -> Option<(&str, &str)> {
    let body = text.strip_prefix(quote)?;
    body.match_indices(quote).find_map(|(pos, _)| {
        let (phrase, rest) = text.split_at_checked(pos + 2)?;
        rest.chars()
            .next()
            .is_none_or(char::is_whitespace)
            .then_some((phrase, rest))
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/email/src/message/query/text/tests.rs"]
mod tests;
