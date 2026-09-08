/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use nlp::tokenizers::types::TypesTokenizer;

fuzz_target!(|data: &[u8]| {
    let [flags, rest @ ..] = data else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let mut last_to = 0;
    for token in TypesTokenizer::new(text)
        .tokenize_urls(flags & 1 != 0)
        .tokenize_urls_without_scheme(flags & 2 != 0)
        .tokenize_emails(flags & 4 != 0)
        .tokenize_numbers(flags & 8 != 0)
    {
        assert!(token.from >= last_to, "tokens moved backwards in {text:?}");
        assert!(token.from < token.to, "empty token in {text:?}");
        assert!(token.to <= text.len(), "token past the end in {text:?}");
        assert!(text.is_char_boundary(token.from) && text.is_char_boundary(token.to));
        last_to = token.to;
    }
});
