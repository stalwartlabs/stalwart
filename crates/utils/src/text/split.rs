/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{iter::FusedIterator, str::SplitWhitespace};

pub fn split_words(text: &str) -> SplitWords<'_> {
    SplitWords {
        words: if text.is_ascii() {
            Words::Ascii(text)
        } else {
            Words::Unicode(text.split_whitespace())
        },
    }
}

#[derive(Clone)]
pub struct SplitWords<'a> {
    words: Words<'a>,
}

#[derive(Clone)]
enum Words<'a> {
    Ascii(&'a str),
    Unicode(SplitWhitespace<'a>),
}

impl<'a> Iterator for SplitWords<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        match &mut self.words {
            Words::Ascii(rest) => next_ascii_word(rest),
            Words::Unicode(words) => words.find(|word| word.chars().all(char::is_alphanumeric)),
        }
    }
}

impl FusedIterator for SplitWords<'_> {}

fn next_ascii_word<'a>(rest: &mut &'a str) -> Option<&'a str> {
    loop {
        let Some(start) = rest.bytes().position(|byte| !is_ascii_space(byte)) else {
            *rest = "";
            return None;
        };
        let text = rest.get(start..)?;
        let mut valid = true;
        let end = text
            .bytes()
            .position(|byte| {
                let space = is_ascii_space(byte);
                valid &= space || byte.is_ascii_alphanumeric();
                space
            })
            .unwrap_or(text.len());
        let (word, tail) = text.split_at_checked(end)?;
        *rest = tail;
        if valid {
            return Some(word);
        }
    }
}

fn is_ascii_space(byte: u8) -> bool {
    byte == b' ' || byte.wrapping_sub(b'\t') < 5
}

pub fn substring(text: &str, start: usize, len: usize) -> &str {
    let end = start.saturating_add(len);
    let bytes = text.as_bytes();
    if bytes.get(..end).unwrap_or(bytes).is_ascii() {
        return text
            .get(start.min(text.len())..end.min(text.len()))
            .unwrap_or_default();
    }
    let mut chars = text.chars();
    if start > 0 && chars.nth(start - 1).is_none() {
        return "";
    }
    let rest = chars.as_str();
    let Some(last) = len.checked_sub(1) else {
        return "";
    };
    let mut taken = rest.chars();
    if taken.nth(last).is_none() {
        return rest;
    }
    rest.get(..rest.len() - taken.as_str().len())
        .unwrap_or(rest)
}
