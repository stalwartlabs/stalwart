/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{
    Token,
    unicode::{is_alphanumeric, is_uppercase},
};

pub struct WordTokenizer<'x> {
    max_token_length: usize,
    text: &'x str,
    pos: usize,
}

impl WordTokenizer<'_> {
    pub fn new(text: &'_ str, max_token_length: usize) -> WordTokenizer<'_> {
        WordTokenizer {
            max_token_length,
            text,
            pos: 0,
        }
    }
}

pub(super) struct AlnumRun {
    pub start: usize,
    pub end: usize,
    pub resume: usize,
    pub has_upper: bool,
    pub is_ascii: bool,
}

const ASCII_CASE_BIT: u8 = 0x20;

struct WideStop {
    pos: usize,
    len: usize,
    has_upper: bool,
}

#[inline(never)]
fn skip_wide(text: &str, from: usize) -> WideStop {
    for (offset, ch) in text[from..].char_indices() {
        if ch.is_ascii() {
            return WideStop {
                pos: from + offset,
                len: 0,
                has_upper: false,
            };
        }
        if is_alphanumeric(ch) {
            return WideStop {
                pos: from + offset,
                len: ch.len_utf8(),
                has_upper: is_uppercase(ch),
            };
        }
    }
    WideStop {
        pos: text.len(),
        len: 0,
        has_upper: false,
    }
}

#[inline(never)]
fn extend_wide(text: &str, from: usize) -> WideStop {
    let mut has_upper = false;
    for (offset, ch) in text[from..].char_indices() {
        if ch.is_ascii() {
            return WideStop {
                pos: from + offset,
                len: 0,
                has_upper,
            };
        }
        if !is_alphanumeric(ch) {
            return WideStop {
                pos: from + offset,
                len: ch.len_utf8(),
                has_upper,
            };
        }
        has_upper = has_upper || is_uppercase(ch);
    }
    WideStop {
        pos: text.len(),
        len: 0,
        has_upper,
    }
}

pub fn has_alnum_run(text: &str) -> bool {
    next_alnum_run(text, 0).is_some()
}

#[inline(always)]
pub(super) fn next_alnum_run(text: &str, from: usize) -> Option<AlnumRun> {
    let bytes = text.as_bytes();
    let mut pos = from;

    let (start, first_len, first_upper) = 'find: loop {
        match bytes.get(pos) {
            Some(&byte) if byte < 0x80 => {
                if byte.is_ascii_alphanumeric() {
                    break 'find (pos, 0, false);
                }
                pos += 1;
            }
            Some(_) => {
                let hit = skip_wide(text, pos);
                pos = hit.pos;
                if hit.len != 0 {
                    break 'find (pos, hit.len, hit.has_upper);
                }
                if pos == bytes.len() {
                    return None;
                }
            }
            None => return None,
        }
    };

    let mut case_bits = u8::MAX;
    let mut has_upper = first_upper;
    let mut is_ascii = first_len == 0;
    let mut end = start + first_len;
    let resume = 'run: loop {
        while let Some(&byte) = bytes.get(end) {
            if byte >= 0x80 {
                let hit = extend_wide(text, end);
                if hit.pos != end {
                    has_upper |= hit.has_upper;
                    is_ascii = false;
                    end = hit.pos;
                }
                if hit.len != 0 {
                    break 'run end + hit.len;
                }
                continue 'run;
            }
            if !byte.is_ascii_alphanumeric() {
                break 'run end + 1;
            }
            case_bits &= byte;
            end += 1;
        }
        break 'run end;
    };

    Some(AlnumRun {
        start,
        end,
        resume,
        has_upper: has_upper || case_bits & ASCII_CASE_BIT == 0,
        is_ascii,
    })
}

/// Parses indo-european text into lowercase tokens.
impl<'x> Iterator for WordTokenizer<'x> {
    type Item = Token<Cow<'x, str>>;

    fn next(&mut self) -> Option<Self::Item> {
        let text = self.text;
        loop {
            let run = next_alnum_run(text, self.pos)?;
            self.pos = run.resume;

            let token_len = run.end - run.start;
            if token_len <= self.max_token_length {
                let word = &text[run.start..run.end];
                return Some(Token::new(
                    run.start,
                    token_len,
                    if run.has_upper {
                        Cow::Owned(word.to_lowercase())
                    } else {
                        Cow::Borrowed(word)
                    },
                ));
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/nlp/src/tokenizers/word/tests.rs"]
mod tests;
