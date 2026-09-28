/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use encodify::utf7::IMAP;
use imap_proto::receiver::{ArgumentBytes, Token};
use libfuzzer_sys::fuzz_target;

fn token(text: &str) -> Token {
    Token::Argument(ArgumentBytes::from_slice(text.as_bytes()))
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let decoded = IMAP.lenient().decode(text);
        assert_eq!(
            token(text).unwrap_mailbox_name(false).as_deref(),
            Ok(decoded.as_deref().unwrap_or(text))
        );
        assert_eq!(token(text).unwrap_mailbox_name(true).as_deref(), Ok(text));
        assert_eq!(
            token(text).unwrap_mailbox_name_strict(true).as_deref(),
            Ok(text)
        );

        let encoded = IMAP.encode(text);
        assert!(encoded.is_ascii(), "{text:?} encoded to {encoded:?}");
        assert_eq!(
            token(&encoded).unwrap_mailbox_name_strict(false).as_deref(),
            Ok(text),
            "{text:?} encoded to {encoded:?}"
        );
    }
});
