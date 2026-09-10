/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::html::html_to_text;
use sieve::{Context, runtime::Variable};
use std::borrow::Cow;

use super::ApplyString;

pub fn fn_trim<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform_str(|s| s.trim().into())
}

pub fn fn_trim_end<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform_str(|s| s.trim_end().into())
}

pub fn fn_trim_start<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform_str(|s| s.trim_start().into())
}

pub fn fn_len<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    match &v[0] {
        Variable::String(s) => s.len(),
        Variable::Array(a) => a.len(),
        v => v.to_string().len(),
    }
    .into()
}

pub fn fn_to_lowercase<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform(|s| Variable::from(s.to_lowercase()))
}

pub fn fn_to_uppercase<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform(|s| Variable::from(s.to_uppercase()))
}

pub fn fn_is_uppercase<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform(|s| {
        s.chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_uppercase())
            .into()
    })
}

pub fn fn_is_lowercase<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform(|s| {
        s.chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_lowercase())
            .into()
    })
}

pub fn fn_has_digits<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform(|s| s.chars().any(|c| c.is_ascii_digit()).into())
}

pub fn tokenize_words<'x>(v: &Variable<'x>) -> Variable<'x> {
    v.split_str(|text, word| {
        text.split_whitespace()
            .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
            .for_each(word)
    })
}

pub fn fn_count_spaces<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .as_ref()
        .chars()
        .filter(|c| c.is_whitespace())
        .count()
        .into()
}

pub fn fn_count_uppercase<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .as_ref()
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_uppercase())
        .count()
        .into()
}

pub fn fn_count_lowercase<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .as_ref()
        .chars()
        .filter(|c| c.is_alphabetic() && c.is_lowercase())
        .count()
        .into()
}

pub fn fn_count_chars<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string().as_ref().chars().count().into()
}

pub fn fn_eq_ignore_case<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .eq_ignore_ascii_case(v[1].to_string().as_ref())
        .into()
}

pub fn fn_contains<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    match &v[0] {
        Variable::String(s) => s.contains(v[1].to_string().as_ref()),
        Variable::Array(arr) => arr.contains(&v[1]),
        val => val.to_string().contains(v[1].to_string().as_ref()),
    }
    .into()
}

pub fn fn_contains_ignore_case<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let needle = v[1].to_string();
    match &v[0] {
        Variable::String(s) => s.to_lowercase().contains(&needle.to_lowercase()),
        Variable::Array(arr) => arr.iter().any(|v| match v {
            Variable::String(s) => s.eq_ignore_ascii_case(needle.as_ref()),
            _ => false,
        }),
        val => val.to_string().contains(needle.as_ref()),
    }
    .into()
}

pub fn fn_starts_with<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .starts_with(v[1].to_string().as_ref())
        .into()
}

pub fn fn_ends_with<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string().ends_with(v[1].to_string().as_ref()).into()
}

pub fn fn_lines<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    match &v[0] {
        Variable::String(Cow::Borrowed(text)) => text
            .lines()
            .map(Variable::borrowed)
            .collect::<Vec<_>>()
            .into(),
        Variable::String(text) => text
            .lines()
            .map(|line| Variable::from(line.to_string()))
            .collect::<Vec<_>>()
            .into(),
        value => value.clone(),
    }
}

pub fn fn_substring<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let start = v[1].to_usize();
    let len = v[2].to_usize();
    match &v[0] {
        Variable::String(Cow::Borrowed(s)) => Variable::borrowed(char_range(s, start, len)),
        value => value
            .to_string()
            .chars()
            .skip(start)
            .take(len)
            .collect::<String>()
            .into(),
    }
}

fn char_range(s: &str, start: usize, len: usize) -> &str {
    let from = s.char_indices().nth(start).map_or(s.len(), |(at, _)| at);
    let to = s[from..]
        .char_indices()
        .nth(len)
        .map_or(s.len(), |(at, _)| from + at);
    &s[from..to]
}

pub fn fn_strip_prefix<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let prefix = v[1].to_string();
    v[0].transform_str(|s| s.strip_prefix(prefix.as_ref()).unwrap_or_default().into())
}

pub fn fn_strip_suffix<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let suffix = v[1].to_string();
    v[0].transform_str(|s| s.strip_suffix(suffix.as_ref()).unwrap_or_default().into())
}

pub fn fn_split<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let separator = v[1].to_string();
    v[0].split_str(|text, part| text.split(separator.as_ref()).for_each(part))
}

pub fn fn_rsplit<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let separator = v[1].to_string();
    v[0].split_str(|text, part| text.rsplit(separator.as_ref()).for_each(part))
}

pub fn fn_split_n<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let separator = v[1].to_string();
    let limit = v[2].to_integer() as usize;
    v[0].split_str(|text, part| {
        let mut rest = text;
        for _ in 0..limit {
            let Some((head, tail)) = rest.split_once(separator.as_ref()) else {
                break;
            };
            part(head);
            rest = tail;
        }
        part(rest);
    })
}

pub fn fn_split_once<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let separator = v[1].to_string();
    v[0].split_str_once(|text| text.split_once(separator.as_ref()))
}

pub fn fn_rsplit_once<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let separator = v[1].to_string();
    v[0].split_str_once(|text| text.rsplit_once(separator.as_ref()))
}

/**
 * `levenshtein-rs` - levenshtein
 *
 * MIT licensed.
 *
 * Copyright (c) 2016 Titus Wormer <tituswormer@gmail.com>
 */
pub fn fn_levenshtein_distance<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let a = v[0].to_string();
    let b = v[1].to_string();

    levenshtein_distance(a.as_ref(), b.as_ref()).into()
}

pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let mut result = 0;

    /* Shortcut optimizations / degenerate cases. */
    if a == b {
        return result;
    }

    let length_a = a.chars().count();
    let length_b = b.chars().count();

    if length_a == 0 {
        return length_b;
    } else if length_b == 0 {
        return length_a;
    }

    /* Initialize the vector.
     *
     * This is why it’s fast, normally a matrix is used,
     * here we use a single vector. */
    let mut cache: Vec<usize> = (1..).take(length_a).collect();
    let mut distance_a;
    let mut distance_b;

    /* Loop. */
    for (index_b, code_b) in b.chars().enumerate() {
        result = index_b;
        distance_a = index_b;

        for (index_a, code_a) in a.chars().enumerate() {
            distance_b = if code_a == code_b {
                distance_a
            } else {
                distance_a + 1
            };

            distance_a = cache[index_a];

            result = if distance_a > result {
                if distance_b > result {
                    result + 1
                } else {
                    distance_b
                }
            } else if distance_b > distance_a {
                distance_a + 1
            } else {
                distance_b
            };

            cache[index_a] = result;
        }
    }

    result
}

pub fn fn_detect_language<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    whatlang::detect_lang(v[0].to_string().as_ref())
        .map(|l| l.code())
        .unwrap_or("unknown")
        .into()
}

pub fn fn_html_to_text<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    html_to_text(v[0].to_string().as_ref()).into()
}
