/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SpamFilterContext,
    analysis::{ExcessEncoding, excess_encoding},
};
use common::{Server, scripts::functions::text::levenshtein_distance};
use mail_parser::HeaderName;
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_SMTPUTF8};
use std::future::Future;
use store::ahash::HashSet;

pub trait SpamFilterAnalyzeRecipient: Sync + Send {
    fn spam_filter_analyze_recipient(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeRecipient for Server {
    async fn spam_filter_analyze_recipient(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut to_raw = b"".as_slice();
        let mut cc_raw = b"".as_slice();
        let mut bcc_raw = b"".as_slice();
        let mut has_list_unsubscribe = false;
        let mut has_list_id = false;

        for header in ctx.input.message.headers() {
            match &header.name {
                HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                    let raw = ctx
                        .input
                        .message
                        .raw_message()
                        .get(header.offset_start as usize..header.offset_end as usize)
                        .unwrap_or_default();
                    match header.name {
                        HeaderName::To => to_raw = raw,
                        HeaderName::Cc => cc_raw = raw,
                        HeaderName::Bcc => bcc_raw = raw,
                        _ => unreachable!(),
                    }
                }
                HeaderName::ListUnsubscribe => {
                    has_list_unsubscribe = true;
                }
                HeaderName::ListId => {
                    has_list_id = true;
                }
                _ => {}
            }
        }

        if to_raw.is_empty() {
            ctx.result.add_tag("MISSING_TO");
        }

        let to_raw_utf8 = std::str::from_utf8(to_raw);
        let cc_raw_utf8 = std::str::from_utf8(cc_raw);
        let bcc_raw_utf8 = std::str::from_utf8(bcc_raw);

        for (raw, raw_utf8, recipients) in [
            (to_raw, &to_raw_utf8, &ctx.output.recipients_to),
            (cc_raw, &cc_raw_utf8, &ctx.output.recipients_cc),
            (bcc_raw, &bcc_raw_utf8, &ctx.output.recipients_bcc),
        ] {
            if !raw.is_empty() {
                // Validate non-ASCII characters in recipient headers
                if !raw.is_ascii() {
                    if (ctx.input.env_from_flags
                        & (MAIL_SMTPUTF8 | MAIL_BODY_8BITMIME | MAIL_BODY_BINARYMIME))
                        == 0
                    {
                        ctx.result.add_tag("TO_NEEDS_ENCODING");
                    }

                    if raw_utf8.is_err() {
                        ctx.result.add_tag("INVALID_TO_8BIT");
                    }
                }

                // Validate unnecessary encoding in recipient headers
                let raw_utf8 = raw_utf8.unwrap_or_default();
                if recipients.iter().all(|rcpt| {
                    rcpt.name.as_ref().is_none_or(|name| name.is_ascii())
                        && rcpt.email.address.is_ascii()
                }) {
                    match excess_encoding(raw_utf8) {
                        ExcessEncoding::QuotedPrintable => {
                            // To header is unnecessarily encoded in quoted-printable
                            ctx.result.add_tag("TO_EXCESS_QP");
                        }
                        ExcessEncoding::Base64 => {
                            // To header is unnecessarily encoded in base64
                            ctx.result.add_tag("TO_EXCESS_BASE64");
                        }
                        ExcessEncoding::None | ExcessEncoding::Other => {}
                    }
                }

                // Check for spaces in recipient addresses
                for token in raw_utf8.split('<') {
                    if let Some((addr, _)) = token.split_once('>')
                        && (addr.starts_with(' ') || addr.ends_with(' '))
                    {
                        ctx.result.add_tag("TO_WRAPPED_IN_SPACES");
                        break;
                    }
                }
            }
        }

        let mut unique_recipients: HashSet<_> = HashSet::with_capacity_and_hasher(
            ctx.output.recipients_to.len()
                + ctx.output.recipients_cc.len()
                + ctx.output.recipients_bcc.len(),
            Default::default(),
        );
        unique_recipients.extend(
            ctx.output
                .all_recipients()
                .filter(|rcpt| !rcpt.email.address.is_empty()),
        );
        let rcpt_count = unique_recipients.len();

        match unique_recipients.len() {
            0 => {
                ctx.result.add_tag("RCPT_COUNT_ZERO");
                return;
            }
            1 => {
                ctx.result.add_tag("RCPT_COUNT_ONE");
            }
            2 => {
                ctx.result.add_tag("RCPT_COUNT_TWO");
            }
            3 => {
                ctx.result.add_tag("RCPT_COUNT_THREE");
            }
            4 | 5 => {
                ctx.result.add_tag("RCPT_COUNT_FIVE");
            }
            6 | 7 => {
                ctx.result.add_tag("RCPT_COUNT_SEVEN");
            }
            8..=12 => {
                ctx.result.add_tag("RCPT_COUNT_TWELVE");
            }
            13.. => {
                ctx.result.add_tag("RCPT_COUNT_GT_50");
            }
        }

        let mut to_dn_eq_addr_count = 0;
        let mut to_dn_count = 0;
        let mut to_match_envrcpt = 0;

        for rcpt in &unique_recipients {
            // Validate name
            if let Some(rcpt_name) = &rcpt.name {
                if *rcpt_name == rcpt.email.address {
                    to_dn_eq_addr_count += 1;
                } else {
                    to_dn_count += 1;
                }
            }

            // Recipient is present in envelope
            if ctx.output.env_to_orig_addr.contains(&rcpt.email) {
                to_match_envrcpt += 1;
            }

            // Check if the local part is present in the subject
            if !rcpt.email.local_part.is_empty() {
                if ctx.output.subject_lc.contains(rcpt.email.address.as_str()) {
                    ctx.result.add_tag("RCPT_IN_SUBJECT");
                } else if rcpt.email.local_part.len() > 3
                    && ctx
                        .output
                        .subject_lc
                        .contains(rcpt.email.local_part.as_str())
                {
                    ctx.result.add_tag("RCPT_LOCAL_IN_SUBJECT");
                }
            }
        }

        if to_dn_count == 0 && to_dn_eq_addr_count == 0 {
            ctx.result.add_tag("TO_DN_NONE");
        } else if to_dn_count == rcpt_count {
            ctx.result.add_tag("TO_DN_ALL");
        } else if to_dn_count > 0 {
            ctx.result.add_tag("TO_DN_SOME");
        }

        if to_dn_eq_addr_count == rcpt_count {
            ctx.result.add_tag("TO_DN_EQ_ADDR_ALL");
        } else if to_dn_eq_addr_count > 0 {
            ctx.result.add_tag("TO_DN_EQ_ADDR_SOME");
        }

        if to_match_envrcpt == rcpt_count {
            ctx.result.add_tag("TO_MATCH_ENVRCPT_ALL");
        } else {
            if to_match_envrcpt > 0 {
                ctx.result.add_tag("TO_MATCH_ENVRCPT_SOME");
            }

            if !has_list_id && !has_list_unsubscribe {
                for env_rcpt in &ctx.output.env_to_orig_addr {
                    if !unique_recipients.iter().any(|rcpt| rcpt.email == *env_rcpt)
                        && env_rcpt != &ctx.output.env_from_addr
                    {
                        ctx.result.add_tag("FORGED_RECIPIENTS");
                        break;
                    }
                }
            }
        }

        // Message from bounce and over 1 recipient
        if rcpt_count > 1 && ctx.output.env_from_postmaster {
            ctx.result.add_tag("RCPT_BOUNCEMOREONE");
        }

        let mut rcpts =
            Vec::with_capacity(ctx.output.recipients_to.len() + ctx.output.recipients_cc.len());
        rcpts.extend(
            ctx.output
                .recipients_to
                .iter()
                .chain(ctx.output.recipients_cc.iter()),
        );

        let mut is_sorted = false;
        if rcpts.len() >= 6
            && rcpts
                .windows(2)
                .all(|pair| pair[0].email.address <= pair[1].email.address)
        {
            // Check if the recipients list is sorted
            ctx.result.add_tag("SORTED_RECIPS");
            is_sorted = true;
        }

        let combinations = rcpts.len() * rcpts.len().saturating_sub(1) / 2;
        if !is_sorted && rcpt_count >= 5 && combinations != 0 {
            // Look for similar recipients
            let mut hits = 0;
            let mut remaining = combinations;
            let is_suspicious = |hits: usize| hits as f64 / combinations as f64 > 0.65;

            'pairs: for i in 0..rcpts.len() {
                for j in i + 1..rcpts.len() {
                    let a = &rcpts[i].email;
                    let b = &rcpts[j].email;

                    if levenshtein_below(&a.local_part, &b.local_part, 3)
                        || (a.domain_part.fqdn != b.domain_part.fqdn
                            && levenshtein_below(&a.domain_part.fqdn, &b.domain_part.fqdn, 4))
                    {
                        hits += 1;
                    }
                    remaining -= 1;

                    if is_suspicious(hits) || !is_suspicious(hits + remaining) {
                        break 'pairs;
                    }
                }
            }

            if is_suspicious(hits) {
                ctx.result.add_tag("SUSPICIOUS_RECIPS");
            }
        }
    }
}

#[inline(always)]
pub(crate) fn levenshtein_below(left: &str, right: &str, limit: usize) -> bool {
    if left.is_ascii() && right.is_ascii() {
        let length_diff = left.len().abs_diff(right.len());
        if length_diff >= limit {
            return false;
        }
        if length_diff == 0 {
            let mismatches = left
                .as_bytes()
                .iter()
                .zip(right.as_bytes())
                .filter(|(a, b)| a != b)
                .count();
            if mismatches < limit {
                return true;
            }
        }
    }

    levenshtein_distance(left, right) < limit
}

#[cfg(test)]
mod tests {
    use super::levenshtein_below;
    use common::scripts::functions::text::levenshtein_distance;

    #[test]
    fn levenshtein_gate_matches_distance() {
        let samples = [
            "",
            "a",
            "ab",
            "abc",
            "abd",
            "abcd",
            "bcd",
            "xyz",
            "john",
            "jon",
            "johnny",
            "jhon",
            "example.com",
            "exampel.com",
            "example.org",
            "\u{e9}cole",
            "ecole",
            "\u{e9}col",
            "\u{c9}cole",
            "日本",
            "日本語",
            "abcdefghij",
            "abcdefghix",
            "jbcdefghij",
        ];
        for left in samples {
            for right in samples {
                for limit in 0..6 {
                    assert_eq!(
                        levenshtein_below(left, right, limit),
                        levenshtein_distance(left, right) < limit,
                        "{left:?} {right:?} {limit}"
                    );
                }
            }
        }
    }
}
