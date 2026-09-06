/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use imap_proto::utf7::{utf7_decode, utf7_encode, utf7_maybe_decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let encoded = utf7_encode(text);
        assert!(encoded.is_ascii(), "{text:?} encoded to {encoded:?}");
        if text.chars().all(|ch| u32::from(ch) < 0x1_0000) {
            assert_eq!(utf7_decode(&encoded).as_deref(), Some(text));
        }
        let decoded = utf7_decode(text);
        assert_eq!(
            utf7_maybe_decode(text.into(), false).as_str(),
            decoded.as_deref().unwrap_or(text)
        );
        assert_eq!(utf7_maybe_decode(text.into(), true).as_str(), text);
    }
});
