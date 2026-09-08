/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::word::next_alnum_run;

pub struct SpaceTokenizer<'x> {
    text: &'x str,
    pos: usize,
    max_token_length: usize,
}

impl SpaceTokenizer<'_> {
    pub fn new(text: &'_ str, max_token_length: usize) -> SpaceTokenizer<'_> {
        SpaceTokenizer {
            text,
            pos: 0,
            max_token_length,
        }
    }
}

#[inline(never)]
fn lowercase_ascii(word: &str) -> String {
    let mut token = String::with_capacity(word.len());
    for &byte in word.as_bytes() {
        token.push(byte.to_ascii_lowercase() as char);
    }
    token
}

#[inline(never)]
fn lowercase_chars(word: &str) -> String {
    let mut token = String::with_capacity(word.len());
    for ch in word.chars() {
        if ch.is_uppercase() {
            token.extend(ch.to_lowercase());
        } else {
            token.push(ch);
        }
    }
    token
}

impl<'x> Iterator for SpaceTokenizer<'x> {
    type Item = Cow<'x, str>;

    fn next(&mut self) -> Option<Self::Item> {
        let text = self.text;
        loop {
            let run = next_alnum_run(text, self.pos)?;
            self.pos = run.resume;
            let word = &text[run.start..run.end];

            if !run.has_upper {
                if word.len() < self.max_token_length {
                    return Some(Cow::Borrowed(word));
                }
            } else if run.is_ascii {
                if word.len() < self.max_token_length {
                    return Some(Cow::Owned(lowercase_ascii(word)));
                }
            } else {
                let token = lowercase_chars(word);
                if token.len() < self.max_token_length {
                    return Some(Cow::Owned(token));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SpaceTokenizer;
    use std::borrow::Cow;

    #[test]
    fn space_tokenizer_cases() {
        let tokens = SpaceTokenizer::new("abc Def \u{1c5}x \u{391}\u{3a3} a\u{663} \u{212a}", 40)
            .collect::<Vec<_>>();
        assert_eq!(
            tokens,
            vec![
                Cow::Borrowed("abc"),
                Cow::Owned::<str>("def".to_string()),
                Cow::Borrowed("\u{1c5}x"),
                Cow::Owned::<str>("\u{3b1}\u{3c3}".to_string()),
                Cow::Borrowed("a\u{663}"),
                Cow::Owned::<str>("k".to_string()),
            ]
        );
        assert!(matches!(tokens[0], Cow::Borrowed(_)));
        assert!(matches!(tokens[1], Cow::Owned(_)));
        assert_eq!(
            SpaceTokenizer::new("ab abc abcd", 3).collect::<Vec<_>>(),
            vec![Cow::Borrowed("ab")]
        );
        assert_eq!(SpaceTokenizer::new("", 3).count(), 0);
        assert_eq!(SpaceTokenizer::new("...", 3).count(), 0);
        assert_eq!(SpaceTokenizer::new("a", 0).count(), 0);
    }
}
