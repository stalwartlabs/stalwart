/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use spam_filter::modules::{
    html::{html_text_body, html_to_tokens},
    pyzor::{html_to_text, pyzor_digest},
};

fuzz_target!(|data: &[u8]| {
    let Ok(html) = std::str::from_utf8(data) else {
        return;
    };
    let tokens = html_to_tokens(html);
    let text = html_text_body(&tokens);
    assert!(text.len() <= html.len() * 4 + 16);
    let stripped = html_to_text(html);
    let digest = pyzor_digest(Vec::new(), stripped.lines());
    assert!(digest.len() <= stripped.len() + 16);
    let _ = pyzor_digest(Vec::new(), html.lines());
});
