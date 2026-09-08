/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::Token;

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
        if ch.is_alphanumeric() {
            return WideStop {
                pos: from + offset,
                len: ch.len_utf8(),
                has_upper: ch.is_uppercase(),
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
        if !ch.is_alphanumeric() {
            return WideStop {
                pos: from + offset,
                len: ch.len_utf8(),
                has_upper,
            };
        }
        has_upper = has_upper || ch.is_uppercase();
    }
    WideStop {
        pos: text.len(),
        len: 0,
        has_upper,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_tokenizer_cases() {
        let tokens = WordTokenizer::new("abc Def \u{1c5}x \u{391}\u{3a3} a\u{663} \u{212a}", 40)
            .collect::<Vec<_>>();
        let words = tokens
            .iter()
            .map(|t| (t.word.as_ref(), t.from, t.to))
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            vec![
                ("abc", 0, 3),
                ("def", 4, 7),
                ("\u{1c5}x", 8, 11),
                ("\u{3b1}\u{3c2}", 12, 16),
                ("a\u{663}", 17, 20),
                ("k", 21, 24),
            ]
        );
        assert!(matches!(tokens[0].word, Cow::Borrowed(_)));
        assert!(matches!(tokens[1].word, Cow::Owned(_)));
        assert!(matches!(tokens[2].word, Cow::Borrowed(_)));
        assert!(matches!(tokens[3].word, Cow::Owned(_)));
        assert_eq!(
            WordTokenizer::new("ab abc abcd", 3)
                .map(|t| t.word.into_owned())
                .collect::<Vec<_>>(),
            vec!["ab".to_string(), "abc".to_string()]
        );
        assert_eq!(WordTokenizer::new("", 3).count(), 0);
        assert_eq!(WordTokenizer::new("...", 3).count(), 0);
        assert_eq!(WordTokenizer::new("a", 0).count(), 0);
    }

    #[test]
    fn indo_european_tokenizer() {
        let inputs = [
            (
                "The quick brown fox jumps over the lazy dog",
                vec![
                    Token::new(0, 3, "the".into()),
                    Token::new(4, 5, "quick".into()),
                    Token::new(10, 5, "brown".into()),
                    Token::new(16, 3, "fox".into()),
                    Token::new(20, 5, "jumps".into()),
                    Token::new(26, 4, "over".into()),
                    Token::new(31, 3, "the".into()),
                    Token::new(35, 4, "lazy".into()),
                    Token::new(40, 3, "dog".into()),
                ],
            ),
            (
                "Jovencillo EMPONZOÑADO de whisky: ¡qué figurota exhibe!",
                vec![
                    Token::new(0, 10, "jovencillo".into()),
                    Token::new(11, 12, "emponzoñado".into()),
                    Token::new(24, 2, "de".into()),
                    Token::new(27, 6, "whisky".into()),
                    Token::new(37, 4, "qué".into()),
                    Token::new(42, 8, "figurota".into()),
                    Token::new(51, 6, "exhibe".into()),
                ],
            ),
            (
                "ZWÖLF Boxkämpfer jagten Victor quer über den großen Sylter Deich",
                vec![
                    Token::new(0, 6, "zwölf".into()),
                    Token::new(7, 11, "boxkämpfer".into()),
                    Token::new(19, 6, "jagten".into()),
                    Token::new(26, 6, "victor".into()),
                    Token::new(33, 4, "quer".into()),
                    Token::new(38, 5, "über".into()),
                    Token::new(44, 3, "den".into()),
                    Token::new(48, 7, "großen".into()),
                    Token::new(56, 6, "sylter".into()),
                    Token::new(63, 5, "deich".into()),
                ],
            ),
            (
                "Съешь ещё этих мягких французских булок, да выпей же чаю",
                vec![
                    Token::new(0, 10, "съешь".into()),
                    Token::new(11, 6, "ещё".into()),
                    Token::new(18, 8, "этих".into()),
                    Token::new(27, 12, "мягких".into()),
                    Token::new(40, 22, "французских".into()),
                    Token::new(63, 10, "булок".into()),
                    Token::new(75, 4, "да".into()),
                    Token::new(80, 10, "выпей".into()),
                    Token::new(91, 4, "же".into()),
                    Token::new(96, 6, "чаю".into()),
                ],
            ),
            (
                "Pijamalı hasta yağız şoföre çabucak güvendi",
                vec![
                    Token::new(0, 9, "pijamalı".into()),
                    Token::new(10, 5, "hasta".into()),
                    Token::new(16, 7, "yağız".into()),
                    Token::new(24, 8, "şoföre".into()),
                    Token::new(33, 8, "çabucak".into()),
                    Token::new(42, 8, "güvendi".into()),
                ],
            ),
        ];

        for (input, tokens) in inputs.iter() {
            for (pos, token) in WordTokenizer::new(input, 40).enumerate() {
                assert_eq!(token, tokens[pos]);
            }
        }
    }
}
