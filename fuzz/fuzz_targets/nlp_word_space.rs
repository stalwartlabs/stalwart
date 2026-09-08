/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use nlp::tokenizers::{space::SpaceTokenizer, word::WordTokenizer};

fuzz_target!(|data: &[u8]| {
    let [limit, rest @ ..] = data else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let max_len = match limit % 6 {
        0 => 0,
        1 => 1,
        2 => 8,
        3 => 64,
        4 => 127,
        _ => 255,
    };
    let mut last_to = 0;
    for token in WordTokenizer::new(text, max_len) {
        assert!(token.from >= last_to && token.from < token.to && token.to <= text.len());
        assert!(text.is_char_boundary(token.from) && text.is_char_boundary(token.to));
        assert!(!token.word.is_empty());
        last_to = token.to;
    }
    for word in SpaceTokenizer::new(text, max_len) {
        assert!(!word.is_empty() && word.len() < max_len.max(1) || max_len == 0);
    }
});
