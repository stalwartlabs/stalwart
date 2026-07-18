/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::backend::MAX_TOKEN_LENGTH;
use nlp::{
    language::{Language, stemmer::Stemmer},
    tokenizers::{space::SpaceTokenizer, word::WordTokenizer},
};
use std::borrow::Cow;
use utils::cheeky_hash::CheekyHash;

pub(crate) struct QueryToken<'x> {
    pub word: Cow<'x, str>,
    pub stem: Option<Cow<'x, str>>,
}

pub(crate) fn tokenize<'x>(
    text: &'x str,
    language: Language,
    mut cb: impl FnMut(QueryToken<'x>) -> bool,
) {
    match language {
        Language::None => {
            for word in SpaceTokenizer::new(text, MAX_TOKEN_LENGTH) {
                if !cb(QueryToken {
                    word: word.into(),
                    stem: None,
                }) {
                    return;
                }
            }
        }
        Language::Unknown => {
            for token in WordTokenizer::new(text, MAX_TOKEN_LENGTH) {
                if !cb(QueryToken {
                    word: token.word,
                    stem: None,
                }) {
                    return;
                }
            }
        }
        _ => {
            for token in Stemmer::new(text, language, MAX_TOKEN_LENGTH) {
                if !cb(QueryToken {
                    word: token.word,
                    stem: token.stemmed_word,
                }) {
                    return;
                }
            }
        }
    }
}

pub(crate) fn tokenize_query<'x>(text: &'x str, language: Language) -> Vec<QueryToken<'x>> {
    let mut tokens = Vec::new();
    tokenize(text, language, |token| {
        tokens.push(token);
        true
    });
    tokens
}

pub(crate) fn stem_term(stem: &str) -> CheekyHash {
    let mut buf = String::with_capacity(stem.len() + 1);
    buf.push_str(stem);
    buf.push('*');
    CheekyHash::new(buf.as_bytes())
}

pub(crate) fn key_value_term(key: &str, value: &str) -> CheekyHash {
    let mut buf = String::with_capacity(key.len() + value.len() + 1);
    buf.push_str(key);
    buf.push(' ');
    buf.push_str(value);
    CheekyHash::new(buf.as_bytes())
}

pub(crate) fn integer_term(value: u64) -> CheekyHash {
    CheekyHash::new(value.to_be_bytes())
}
