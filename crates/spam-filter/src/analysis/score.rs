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
use common::{Server, config::spamfilter::SpamFilterAction};
use std::{fmt::Write, future::Future, vec};

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
    pub results: Vec<bool>,
    pub headers: String,
    pub train_spam: Option<bool>,
    pub score: f32,
}

impl SpamFilterAnalyzeScore for Server {
    async fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<SpamFilterScore> {
        // Calculate final score
        let mut results = vec![];
        let mut header_len = 60;
        let mut is_spam_trap = false;
        let mut rbl_count = 0;

        for tag in &ctx.result.tags {
            let score = match self.core.spam.lists.scores.get(tag) {
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
            header_len += tag.len() + 10;
            if score != 0.0 || !tag.starts_with("X_") {
                results.push((tag.as_str(), score));
            }
        }

        let mut final_score = ctx.result.score;
        let mut avg_confidence: f32 = 0.0;
        let mut total_results = 0;
        let mut user_results = vec![
            ctx.result.score >= self.core.spam.scores.spam_threshold;
            ctx.input.env_rcpt_to.len()
        ];
        if !ctx.result.classifier_confidence.is_empty() {
            for (idx, &confidence) in ctx.result.classifier_confidence.iter().enumerate() {
                if let Some(confidence) = confidence {
                    avg_confidence += confidence;
                    total_results += 1;

                    let user_score = self
                        .core
                        .spam
                        .lists
                        .scores
                        .get(confidence.spam_tag())
                        .and_then(|v| v.as_score())
                        .copied()
                        .unwrap_or_default();

                    user_results[idx] =
                        ctx.result.score + user_score >= self.core.spam.scores.spam_threshold;
                }
            }

            if total_results > 0 {
                avg_confidence /= total_results as f32;

                let tag = avg_confidence.spam_tag();
                let score = self
                    .core
                    .spam
                    .lists
                    .scores
                    .get(tag)
                    .and_then(|v| v.as_score())
                    .copied()
                    .unwrap_or_default();
                results.push((tag, score));
                final_score += score;
            }
        }

        if self.core.spam.scores.reject_threshold > 0.0
            && final_score >= self.core.spam.scores.reject_threshold
        {
            SpamFilterAction::Reject
        } else if self.core.spam.scores.discard_threshold > 0.0
            && final_score >= self.core.spam.scores.discard_threshold
        {
            SpamFilterAction::Discard
        } else {
            let mut headers = String::with_capacity(header_len + 40);
            results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap().then_with(|| a.0.cmp(b.0)));
            headers.push_str("X-Spam-Result: ");
            for (idx, (tag, score)) in results.into_iter().enumerate() {
                if idx > 0 {
                    headers.push_str(",\r\n\t");
                }
                let _ = write!(&mut headers, "{} ({:.2})", tag, score);
            }
            headers.push_str("\r\n");

            if let Some((category, explanation)) = &ctx.result.llm_result {
                let _ = write!(&mut headers, "X-Spam-LLM: {category} ({explanation})\r\n",);
            }

            let is_spam = final_score >= self.core.spam.scores.spam_threshold;
            let class = if is_spam { "spam" } else { "ham" };

            if avg_confidence != 0.0 {
                let _ = write!(
                    &mut headers,
                    "X-Spam-Score: {class}, score={final_score:.2}, avg_confidence={avg_confidence:.2}\r\n",
                );
            } else {
                let _ = write!(
                    &mut headers,
                    "X-Spam-Score: {class}, score={final_score:.2}\r\n",
                );
            }

            // Autolearn SPAM
            let mut train_spam = None;
            if is_spam
                && self.core.spam.classifier.as_ref().is_some_and(|c| {
                    (c.auto_learn_spam_trap && is_spam_trap)
                        || (c.auto_learn_spam_rbl_count > 0
                            && rbl_count >= c.auto_learn_spam_rbl_count)
                })
            {
                train_spam = Some(true);
            }

            SpamFilterAction::Allow(SpamFilterScore {
                results: user_results,
                headers,
                train_spam,
                score: final_score,
            })
        }
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
