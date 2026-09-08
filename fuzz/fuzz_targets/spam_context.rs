/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use common::config::mailstore::spamfilter::{SpamFilterAction, SpamFilterScoreConfig};
use libfuzzer_sys::fuzz_target;
use mail_parser::MessageParser;
use spam_filter::{
    SpamFilterContext, SpamFilterInput, TextPart,
    analysis::{
        date::analyze_date, dmarc::analyze_dmarc, from::analyze_from, headers::analyze_headers,
        html::analyze_html, messageid::analyze_message_id, mime::analyze_mime,
        received::analyze_received, recipient::analyze_recipient, replyto::analyze_reply_to,
        score::finalize, subject::analyze_subject,
    },
    modules::{classifier::Tokens, pyzor::PyzorDigest},
};
use utils::glob::GlobMap;

fuzz_target!(|data: &[u8]| {
    let Some(message) = MessageParser::new().parse(data) else {
        return;
    };
    let mut ctx = SpamFilterContext::new(SpamFilterInput::from_message(&message, 0));
    analyze_headers(&mut ctx);
    analyze_subject(&mut ctx);
    analyze_received(&mut ctx);
    analyze_message_id(&mut ctx);
    analyze_date(&mut ctx);
    analyze_dmarc(&mut ctx);
    analyze_from(&mut ctx);
    analyze_reply_to(&mut ctx);
    analyze_recipient(&mut ctx);
    analyze_html(&mut ctx);
    analyze_mime(&mut ctx, &GlobMap::new());
    let mut scores = GlobMap::new();
    for (idx, tag) in ctx.result.tags.iter().enumerate() {
        scores.insert_entry(tag.clone(), SpamFilterAction::Allow((idx % 5) as f32 - 2.0));
    }
    let thresholds = SpamFilterScoreConfig {
        reject_threshold: 0.0,
        discard_threshold: 0.0,
        spam_threshold: 5.0,
    };
    let _ = finalize(&mut ctx, &scores, &thresholds, None);
    let mut tokens = Tokens::default();
    for (idx, part) in ctx.output.text_parts.iter().enumerate() {
        if !matches!(part, TextPart::None) {
            tokens.insert_text_part(part, idx == 0);
        }
    }
    let _ = message.pyzor_digest(Vec::new());
});
