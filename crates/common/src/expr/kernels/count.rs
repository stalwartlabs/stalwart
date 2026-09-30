/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::segments::{CHUNK, SHORT_LEN, any_in_chunk, count_in_chunk, find_change};

const PROBE_LEN: usize = 16;

pub fn count_whitespace(text: &str) -> usize {
    if text.is_ascii() {
        count_ascii(text.as_bytes(), is_ascii_space)
    } else {
        text.chars().filter(|c| c.is_whitespace()).count()
    }
}

pub fn count_uppercase(text: &str) -> usize {
    if text.is_ascii() {
        count_ascii(text.as_bytes(), |byte| byte.is_ascii_uppercase())
    } else {
        text.chars()
            .filter(|c| c.is_alphabetic() && c.is_uppercase())
            .count()
    }
}

pub fn count_lowercase(text: &str) -> usize {
    if text.is_ascii() {
        count_ascii(text.as_bytes(), |byte| byte.is_ascii_lowercase())
    } else {
        text.chars()
            .filter(|c| c.is_alphabetic() && c.is_lowercase())
            .count()
    }
}

pub fn count_chars(text: &str) -> usize {
    if text.len() < SHORT_LEN {
        text.chars().count()
    } else {
        count_ascii(text.as_bytes(), is_char_start)
    }
}

pub fn has_digits(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < SHORT_LEN {
        bytes.iter().any(u8::is_ascii_digit)
    } else {
        any_ascii(bytes, |byte| byte.is_ascii_digit())
    }
}

pub fn is_uppercase(text: &str) -> bool {
    is_cased(text, |byte| byte.is_ascii_lowercase(), char::is_uppercase)
}

pub fn is_lowercase(text: &str) -> bool {
    is_cased(text, |byte| byte.is_ascii_uppercase(), char::is_lowercase)
}

fn is_cased(text: &str, ascii_rejects: impl Fn(u8) -> bool, cased: fn(char) -> bool) -> bool {
    let keeps = |c: char| !c.is_alphabetic() || cased(c);
    let mut chars = text.chars();
    while chars.as_str().len() + PROBE_LEN > text.len() {
        match chars.next() {
            Some(c) if !keeps(c) => return false,
            Some(_) => {}
            None => return true,
        }
    }
    find_change(chars.as_str(), ascii_rejects, keeps).is_none()
}

fn count_ascii(bytes: &[u8], matches: impl Fn(u8) -> bool) -> usize {
    bytes
        .chunks(CHUNK)
        .map(|chunk| count_in_chunk(chunk, &matches))
        .sum()
}

fn any_ascii(bytes: &[u8], matches: impl Fn(u8) -> bool) -> bool {
    bytes
        .chunks(CHUNK)
        .any(|chunk| any_in_chunk(chunk, &matches))
}

fn is_ascii_space(byte: u8) -> bool {
    byte == b' ' || byte.wrapping_sub(b'\t') < 5
}

fn is_char_start(byte: u8) -> bool {
    byte & 0xC0 != 0x80
}
