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

pub(crate) fn stem_term(stem: &str, buf: &mut String) -> CheekyHash {
    buf.clear();
    buf.push_str(stem);
    buf.push('*');
    CheekyHash::new(buf.as_bytes())
}

pub(crate) fn key_value_term(key: &str, value: &str, buf: &mut String) -> CheekyHash {
    buf.clear();
    buf.push_str(key);
    buf.push(' ');
    buf.push_str(value);
    CheekyHash::new(buf.as_bytes())
}

pub(crate) fn integer_term(value: u64) -> CheekyHash {
    CheekyHash::new(&value.to_be_bytes()[std::cmp::min(7, value.leading_zeros() as usize / 8)..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_terms_match_integer_terms() {
        assert_eq!(integer_term(0), CheekyHash::new([0u8]));
        assert_eq!(integer_term(1), CheekyHash::new([1u8]));
    }
}
