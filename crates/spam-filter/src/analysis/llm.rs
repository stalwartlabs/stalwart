/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{future::Future, time::Instant};

use common::Server;
use trc::AiEvent;

use crate::{Recipient, SpamFilterContext};

pub trait SpamFilterAnalyzeLlm: Sync + Send {
    fn spam_filter_analyze_llm(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeLlm for Server {
    async fn spam_filter_analyze_llm(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = self
            .core
            .enterprise
            .as_ref()
            .and_then(|c| c.spam_filter_llm.as_ref())
        {
            let time = Instant::now();
            let body = if let Some(body) = ctx.text_body() {
                body
            } else {
                return;
            };

            let prompt = build_prompt(
                &config.prompt,
                &ctx.output.from,
                &ctx.output.recipients_to,
                &ctx.input.env_rcpt_orig_to,
                &ctx.output.subject,
                body,
            );

            match config
                .model
                .send_request(prompt, config.temperature.into())
                .await
            {
                Ok(response) => {
                    trc::event!(
                        Ai(AiEvent::LlmResponse),
                        Id = config.model.id.clone(),
                        Details = response.clone(),
                        Elapsed = time.elapsed(),
                        SpanId = ctx.input.span_id,
                    );

                    let mut category = None;
                    let mut confidence = None;
                    let mut explanation = None;

                    for (idx, value) in response.split(config.separator).enumerate() {
                        let value = value.trim();
                        if !value.is_empty() {
                            if idx == config.index_category {
                                let value = value.to_uppercase();
                                if config.categories.contains(value.as_str()) {
                                    category = Some(value);
                                }
                            } else if config.index_confidence.is_some_and(|i| i == idx) {
                                let value = value.to_uppercase();
                                if config.confidence.contains(value.as_str()) {
                                    confidence = Some(value);
                                }
                            } else if config.index_explanation.is_some_and(|i| i == idx) {
                                let explanation = explanation.get_or_insert_with(|| {
                                    String::with_capacity(std::cmp::min(value.len(), 255))
                                });

                                for value in value.chars() {
                                    if !value.is_whitespace() {
                                        explanation.push(value);
                                    } else {
                                        explanation.push(' ');
                                    }
                                    if explanation.len() == 255 {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    let category = match (category, confidence) {
                        (Some(category), Some(confidence)) => {
                            ctx.result.add_tag(format!("LLM_{category}_{confidence}"));
                            category
                        }
                        (Some(category), None) => {
                            ctx.result.add_tag(format!("LLM_{category}"));
                            category
                        }
                        _ => return,
                    };

                    if let Some(explanation) = explanation {
                        ctx.result.llm_result = Some((category, explanation));
                    }
                }
                Err(err) => {
                    trc::error!(err.span_id(ctx.input.span_id));
                }
            }
        }
    }
}

fn build_prompt(
    prompt: &str,
    from: &Recipient,
    recipients_to: &[Recipient],
    env_rcpt_to: &[&str],
    subject: &str,
    body: &str,
) -> String {
    let mut result = String::with_capacity(prompt.len() + body.len() + subject.len());
    result.push_str(prompt);
    result.push_str("\n\nFrom: ");
    push_recipient(&mut result, from);
    result.push_str("\nTo: ");
    for (idx, rcpt) in recipients_to.iter().take(16).enumerate() {
        if idx > 0 {
            result.push_str(", ");
        }
        push_recipient(&mut result, rcpt);
    }
    result.push_str("\nEnvelope-To: ");
    for (idx, rcpt) in env_rcpt_to.iter().enumerate() {
        if idx > 0 {
            result.push_str(", ");
        }
        result.push_str(rcpt);
    }
    result.push_str("\nSubject: ");
    result.push_str(shorten(subject, 64));
    result.push_str("\n\n");
    result.push_str(shorten(body, 512));
    result
}

fn push_recipient(result: &mut String, rcpt: &Recipient) {
    if let Some(name) = &rcpt.name {
        result.push_str(name);
        result.push_str(" <");
        result.push_str(&rcpt.email.address);
        result.push('>');
    } else {
        result.push_str(&rcpt.email.address);
    }
}

fn shorten(input: &str, mut index: usize) -> &str {
    index = index.min(input.len());
    while !input.is_char_boundary(index) {
        index += 1;
    }
    &input[..index]
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Email, Recipient};

    fn rcpt(name: Option<&str>, address: &str) -> Recipient {
        Recipient {
            email: Email::new(address),
            name: name.map(Into::into),
        }
    }

    #[test]
    fn build_llm_prompt() {
        let prompt = build_prompt(
            "Classify this message.",
            &rcpt(Some("Alice"), "alice@example.com"),
            &[
                rcpt(Some("Bob"), "bob@example.com"),
                rcpt(None, "carol@example.com"),
            ],
            &["dave@example.com", "erin@example.com"],
            "Hello world",
            "This is the body.",
        );

        assert_eq!(
            prompt,
            concat!(
                "Classify this message.\n",
                "\n",
                "From: Alice <alice@example.com>\n",
                "To: Bob <bob@example.com>, carol@example.com\n",
                "Envelope-To: dave@example.com, erin@example.com\n",
                "Subject: Hello world\n",
                "\n",
                "This is the body."
            )
        );
    }

    #[test]
    fn shorten_at_char_boundary() {
        assert_eq!(shorten("hello", 10), "hello");
        assert_eq!(shorten("hello", 3), "hel");
        assert_eq!(shorten("h\u{e9}llo", 2), "h\u{e9}");
    }
}
