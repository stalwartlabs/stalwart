/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SpamFilterContext,
    analysis::{
        classifier::SpamFilterAnalyzeClassify, date::SpamFilterAnalyzeDate,
        dmarc::SpamFilterAnalyzeDmarc, domain::SpamFilterAnalyzeDomain,
        ehlo::SpamFilterAnalyzeEhlo, from::SpamFilterAnalyzeFrom,
        headers::SpamFilterAnalyzeHeaders, html::SpamFilterAnalyzeHtml, ip::SpamFilterAnalyzeIp,
        messageid::SpamFilterAnalyzeMid, mime::SpamFilterAnalyzeMime,
        pyzor::SpamFilterAnalyzePyzor, received::SpamFilterAnalyzeReceived,
        recipient::SpamFilterAnalyzeRecipient, replyto::SpamFilterAnalyzeReplyTo,
        rules::SpamFilterAnalyzeRules, subject::SpamFilterAnalyzeSubject,
        url::SpamFilterAnalyzeUrl,
    },
};
use common::{
    Server,
    config::mailstore::spamfilter::{ClassifierConfig, SpamFilterAction, SpamFilterScoreConfig},
};
use std::{fmt::Write, future::Future, vec};
use utils::glob::GlobMap;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::analysis::llm::SpamFilterAnalyzeLlm;
// SPDX-SnippetEnd

pub trait SpamFilterAnalyzeScore: Sync + Send {
    fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<SpamFilterScore>> + Send;

    fn spam_filter_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<SpamFilterScore>> + Send;
}

#[derive(Debug, Default)]
pub struct SpamFilterScore {
    pub results: Vec<f32>,
    pub headers: String,
    pub train_spam: Option<bool>,
    pub score: f32,
    pub is_spam: bool,
}

impl SpamFilterAnalyzeScore for Server {
    async fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<SpamFilterScore> {
        finalize(
            ctx,
            &self.core.spam.lists.scores,
            &self.core.spam.scores,
            self.core.spam.classifier.as_ref(),
        )
    }

    async fn spam_filter_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<SpamFilterScore> {
        // IP address analysis
        self.spam_filter_analyze_ip(ctx).await;

        // DMARC/SPF/DKIM/ARC analysis
        self.spam_filter_analyze_dmarc(ctx).await;

        // EHLO hostname analysis
        self.spam_filter_analyze_ehlo(ctx).await;

        // Generic header analysis
        self.spam_filter_analyze_headers(ctx).await;

        // Received headers analysis
        self.spam_filter_analyze_received(ctx).await;

        // Message-ID analysis
        self.spam_filter_analyze_message_id(ctx).await;

        // Date header analysis
        self.spam_filter_analyze_date(ctx).await;

        // Subject analysis
        self.spam_filter_analyze_subject(ctx).await;

        // From and Envelope From analysis
        self.spam_filter_analyze_from(ctx).await;

        // Reply-To analysis
        self.spam_filter_analyze_reply_to(ctx).await;

        // Recipient analysis
        self.spam_filter_analyze_recipient(ctx).await;

        // E-mail and domain analysis
        self.spam_filter_analyze_domain(ctx).await;

        // URL analysis
        self.spam_filter_analyze_url(ctx).await;

        // MIME part analysis
        self.spam_filter_analyze_mime(ctx).await;

        // HTML content analysis
        self.spam_filter_analyze_html(ctx).await;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // LLM classification
        #[cfg(feature = "enterprise")]
        self.spam_filter_analyze_llm(ctx).await;

        // SPDX-SnippetEnd

        // Spam trap
        self.spam_filter_analyze_spam_trap(ctx).await;

        // Pyzor checks
        self.spam_filter_analyze_pyzor(ctx).await;

        // Model classification
        self.spam_filter_analyze_classify(ctx).await;

        // User-defined rules
        self.spam_filter_analyze_rules(ctx).await;

        // Final score calculation
        self.spam_filter_finalize(ctx).await
    }
}

pub fn finalize(
    ctx: &mut SpamFilterContext<'_>,
    scores: &GlobMap<SpamFilterAction<f32>>,
    thresholds: &SpamFilterScoreConfig,
    classifier: Option<&ClassifierConfig>,
) -> SpamFilterAction<SpamFilterScore> {
    // Calculate final score
    let mut results = Vec::with_capacity(ctx.result.tags.len() + 1);
    let mut header_len = 60;
    let mut is_spam_trap = false;
    let mut rbl_count = 0;

    for tag in &ctx.result.tags {
        let score = match scores.get(tag) {
            Some(SpamFilterAction::Allow(score)) => *score,
            Some(SpamFilterAction::Discard) => {
                return SpamFilterAction::Discard;
            }
            Some(SpamFilterAction::Reject) => {
                return SpamFilterAction::Reject;
            }
            None | Some(SpamFilterAction::Disabled) => 0.0,
        };
        if tag == "SPAM_TRAP" {
            is_spam_trap = true;
        } else if score > 1.0 && tag.starts_with("RBL_") {
            rbl_count += 1;
        }
        ctx.result.score += score;
        header_len += tag.len() + 14;
        if score != 0.0 || !tag.starts_with("X_") {
            results.push((tag.as_str(), score));
        }
    }

    let mut final_score = ctx.result.score;
    let mut avg_confidence: f32 = 0.0;
    let mut total_results = 0;
    let mut user_results = vec![ctx.result.score; ctx.input.env_rcpt_rewritten_to.len()];
    if !ctx.result.classifier_confidence.is_empty() {
        for (idx, &confidence) in ctx.result.classifier_confidence.iter().enumerate() {
            if let Some(confidence) = confidence {
                avg_confidence += confidence;
                total_results += 1;

                let user_score = scores
                    .get(confidence.spam_tag())
                    .and_then(|v| v.as_score())
                    .copied()
                    .unwrap_or_default();

                user_results[idx] = ctx.result.score + user_score;
            }
        }

        if total_results > 0 {
            avg_confidence /= total_results as f32;

            let tag = avg_confidence.spam_tag();
            let score = scores
                .get(tag)
                .and_then(|v| v.as_score())
                .copied()
                .unwrap_or_default();
            results.push((tag, score));
            final_score += score;
        }
    }

    if thresholds.reject_threshold > 0.0 && final_score >= thresholds.reject_threshold {
        SpamFilterAction::Reject
    } else if thresholds.discard_threshold > 0.0 && final_score >= thresholds.discard_threshold {
        SpamFilterAction::Discard
    } else {
        let mut headers = String::with_capacity(header_len + 40);
        results.sort_unstable_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .expect("spam filter scores must not be NaN")
                .then_with(|| a.0.cmp(b.0))
        });
        headers.push_str("X-Spam-Result: ");
        for (idx, (tag, score)) in results.into_iter().enumerate() {
            if idx > 0 {
                headers.push_str(",\r\n\t");
            }
            headers.push_str(tag);
            headers.push_str(" (");
            push_two_decimals(&mut headers, score);
            headers.push(')');
        }
        headers.push_str("\r\n");

        if let Some((category, explanation)) = &ctx.result.llm_result {
            headers.push_str("X-Spam-LLM: ");
            headers.push_str(category);
            headers.push_str(" (");
            headers.push_str(explanation);
            headers.push_str(")\r\n");
        }

        let is_spam = final_score >= thresholds.spam_threshold;
        let class = if is_spam { "spam" } else { "ham" };

        headers.push_str("X-Spam-Score: ");
        headers.push_str(class);
        headers.push_str(", score=");
        push_two_decimals(&mut headers, final_score);
        if avg_confidence != 0.0 {
            headers.push_str(", avg_confidence=");
            push_two_decimals(&mut headers, avg_confidence);
        }
        headers.push_str("\r\n");

        // Autolearn SPAM
        let mut train_spam = None;
        if is_spam
            && classifier.is_some_and(|c| {
                (c.auto_learn_spam_trap && is_spam_trap)
                    || (c.auto_learn_spam_rbl_count > 0 && rbl_count >= c.auto_learn_spam_rbl_count)
            })
        {
            train_spam = Some(true);
        }

        SpamFilterAction::Allow(SpamFilterScore {
            results: user_results,
            headers,
            train_spam,
            score: final_score,
            is_spam,
        })
    }
}

#[inline(always)]
pub(crate) fn push_two_decimals(out: &mut String, value: f32) {
    let scaled = (value.abs() as f64) * 100.0;
    if scaled < 1e15 {
        if value.is_sign_negative() {
            out.push('-');
        }
        let scaled = scaled.round_ties_even() as u64;
        let mut buf = [b'0'; 24];
        let mut pos = buf.len();
        let fraction = (scaled % 100) as usize;
        pos -= 1;
        buf[pos] = b'0' + (fraction % 10) as u8;
        pos -= 1;
        buf[pos] = b'0' + (fraction / 10) as u8;
        pos -= 1;
        buf[pos] = b'.';
        let mut integral = scaled / 100;
        loop {
            pos -= 1;
            buf[pos] = b'0' + (integral % 10) as u8;
            integral /= 10;
            if integral == 0 {
                break;
            }
        }
        if let Ok(text) = std::str::from_utf8(&buf[pos..]) {
            out.push_str(text);
        }
    } else {
        push_two_decimals_cold(out, value);
    }
}

#[inline(never)]
fn push_two_decimals_cold(out: &mut String, value: f32) {
    let _ = write!(out, "{value:.2}");
}

pub trait ConfidenceStore {
    fn spam_tag(&self) -> &'static str;
}

impl ConfidenceStore for f32 {
    fn spam_tag(&self) -> &'static str {
        match *self {
            p if p < 0.15 => "PROB_HAM_HIGH",
            p if p < 0.25 => "PROB_HAM_MEDIUM",
            p if p < 0.40 => "PROB_HAM_LOW",
            p if p < 0.60 => "PROB_SPAM_UNCERTAIN",
            p if p < 0.75 => "PROB_SPAM_LOW",
            p if p < 0.85 => "PROB_SPAM_MEDIUM",
            p => {
                if p.is_finite() {
                    "PROB_SPAM_HIGH"
                } else {
                    "PROB_SPAM_UNCERTAIN"
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::push_two_decimals;

    fn formatted(value: f32) -> String {
        let mut out = String::new();
        push_two_decimals(&mut out, value);
        out
    }

    #[test]
    fn two_decimals_match_format() {
        let mut values = vec![
            0.0,
            -0.0,
            0.001,
            -0.001,
            0.005,
            -0.005,
            0.125,
            0.375,
            2.675,
            1.005,
            0.995,
            9.995,
            99.995,
            0.5,
            -1.5,
            1e6,
            1e7,
            1e12,
            9.9e12,
            1e13,
            3.4e38,
            -3.4e38,
            1e-9,
            -1e-9,
            f32::MIN_POSITIVE,
            f32::EPSILON,
            f32::NAN,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ];
        values.extend((-20_000..=20_000).map(|i| i as f32 / 1000.0));
        values.extend((0..5_000).map(|i| i as f32 * 0.005));
        values.extend((0..2_000).map(|i| (i as f32) * 12.345 - 1234.5));
        for value in values {
            assert_eq!(formatted(value), format!("{value:.2}"), "{value:?}");
        }
    }
}
