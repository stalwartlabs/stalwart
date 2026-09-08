/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::url::UrlParts;
use crate::{
    ContextToken, Email, Hostname, IpParts, Recipient, SpamFilterContext, SpamFilterInput,
    SpamFilterOutput, SpamFilterResult, TextPart,
    modules::html::{html_text_body, html_to_tokens},
};
use common::Server;
use mail_auth::DmarcResult;
use mail_parser::{Addr, Address, HeaderName, PartType, parsers::fields::thread::thread_name};
use nlp::tokenizers::types::{TokenType, TypesTokenizer};
use std::borrow::Cow;

pub trait SpamFilterInit {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x>;
}

const POSTMASTER_ADDRESSES: [&str; 3] = ["postmaster", "mailer-daemon", "root"];
const BYTES_PER_TOKEN: usize = 3;
const MAX_RESERVED_TOKENS: usize = 1 << 16;

impl SpamFilterInit for Server {
    fn spam_filter_init<'x>(&self, input: SpamFilterInput<'x>) -> SpamFilterContext<'x> {
        SpamFilterContext::new(input)
    }
}

impl<'x> SpamFilterContext<'x> {
    pub fn new(mut input: SpamFilterInput<'x>) -> Self {
        let mut subject = "";
        let mut from = None;
        let mut reply_to = None;
        let mut recipients_to = Vec::new();
        let mut recipients_cc = Vec::new();
        let mut recipients_bcc = Vec::new();
        let mut found_spam_status = false;

        for header in input.message.headers() {
            match &header.name {
                HeaderName::To | HeaderName::Cc | HeaderName::Bcc => {
                    let recipients = match &header.name {
                        HeaderName::To => &mut recipients_to,
                        HeaderName::Cc => &mut recipients_cc,
                        _ => &mut recipients_bcc,
                    };
                    match header.value().as_address() {
                        Some(Address::List(list)) => {
                            recipients.reserve(list.len());
                            recipients.extend(list.iter().map(as_recipient));
                        }
                        Some(Address::Group(groups)) => {
                            for group in groups {
                                recipients.reserve(group.addresses.len());
                                recipients.extend(group.addresses.iter().map(as_recipient));
                            }
                        }
                        None => {}
                    }
                }
                HeaderName::ReplyTo => {
                    reply_to = header
                        .value()
                        .as_address()
                        .and_then(|addrs| addrs.first())
                        .and_then(|addr| {
                            Some(Recipient {
                                email: Email::new(addr.address()?),
                                name: addr.name().and_then(trimmed_name),
                            })
                        });
                }
                HeaderName::Subject => {
                    subject = header.value().as_text().unwrap_or_default();
                }
                HeaderName::From => {
                    from = header.value().as_address().and_then(|addrs| addrs.first());
                }
                HeaderName::Other(name)
                    if input.is_train && !found_spam_status && name.eq("X-Spam-Result") =>
                {
                    for token in header
                        .value()
                        .as_text()
                        .unwrap_or_default()
                        .split_ascii_whitespace()
                    {
                        if let Some(dmarc) = token.strip_prefix("DMARC_") {
                            input.dmarc_result = if dmarc == "POLICY_ALLOW" {
                                Some(&DmarcResult::Pass)
                            } else {
                                Some(&DmarcResult::None)
                            };
                        } else if let Some(asn) = token
                            .strip_prefix("SOURCE_ASN_")
                            .and_then(|v| v.parse().ok())
                        {
                            input.asn = Some(asn);
                        }
                    }

                    found_spam_status = true;
                }
                _ => {}
            }
        }

        // Tokenize subject
        let subject_tokens = tokenize(subject, borrowed);

        // Tokenize and convert text parts
        let mut text_parts = Vec::with_capacity(input.message.parts.len());
        let mut text_parts_nested = Vec::new();
        let mut message_stack = Vec::new();
        let mut message_iter = input.message.parts.iter();

        loop {
            while let Some(part) = message_iter.next() {
                let is_main_message = message_stack.is_empty();
                let text_part = match &part.body {
                    PartType::Text(text) => TextPart::Plain {
                        text_body: text.as_ref(),
                        tokens: tokenize(text.as_ref(), borrowed),
                    },
                    PartType::Html(html) => {
                        let html_tokens = html_to_tokens(html);
                        let text_body = html_text_body(&html_tokens);

                        TextPart::Html {
                            tokens: tokenize(&text_body, detached),
                            html_tokens,
                            text_body,
                        }
                    }
                    PartType::Message(message) => {
                        message_stack.push(message_iter);
                        message_iter = message.parts.iter();
                        TextPart::None
                    }
                    _ => TextPart::None,
                };

                if is_main_message {
                    text_parts.push(text_part);
                } else if !matches!(text_part, TextPart::None) {
                    text_parts_nested.push(text_part);
                }
            }

            if let Some(iter) = message_stack.pop() {
                message_iter = iter;
            } else {
                break;
            }
        }
        text_parts.extend(text_parts_nested);

        let subject_thread = thread_name(subject).to_string();
        let env_from_addr = Email::new(input.env_from);
        SpamFilterContext {
            output: SpamFilterOutput {
                ehlo_host: Hostname::new(input.ehlo_domain.unwrap_or("unknown")),
                iprev_ptr: input.iprev_result.and_then(|r| {
                    r.ptr
                        .as_ref()
                        .and_then(|ptr| ptr.first())
                        .map(|ptr| (ptr.strip_suffix('.').unwrap_or(ptr)).to_lowercase())
                }),
                env_from_postmaster: env_from_addr.address.is_empty()
                    || POSTMASTER_ADDRESSES.contains(&env_from_addr.local_part.as_str()),
                env_from_addr,
                env_to_orig_addr: input
                    .env_rcpt_orig_to
                    .iter()
                    .map(|rcpt| Email::new(rcpt))
                    .collect(),
                env_to_rewritten_addr: input
                    .env_rcpt_rewritten_to
                    .iter()
                    .map(|rcpt| Email::new(rcpt))
                    .collect(),
                from: Recipient {
                    email: Email::new(from.and_then(|f| f.address()).unwrap_or_default()),
                    name: from.and_then(|f| f.name()).map(|name| name.to_lowercase()),
                },
                reply_to,
                subject_thread_lc: subject_thread.trim().to_lowercase(),
                subject_thread,
                subject_lc: subject.trim().to_lowercase(),
                subject: subject.to_string(),
                subject_tokens,
                recipients_to,
                recipients_cc,
                recipients_bcc,
                text_parts,
                ips: Default::default(),
                emails: Default::default(),
                urls: Default::default(),
                domains: Default::default(),
            },
            input,
            result: SpamFilterResult::default(),
        }
    }
}

pub(crate) fn tokenize<'a, 'b>(
    text: &'a str,
    into_text: impl Fn(&'a str) -> Cow<'b, str>,
) -> Vec<ContextToken<'b>> {
    let mut tokens = Vec::with_capacity((text.len() / BYTES_PER_TOKEN).min(MAX_RESERVED_TOKENS));
    for token in TypesTokenizer::new(text)
        .tokenize_numbers(false)
        .tokenize_urls(true)
        .tokenize_urls_without_scheme(true)
        .tokenize_emails(true)
    {
        tokens.push(match token.word {
            TokenType::Alphabetic(s) => TokenType::Alphabetic(into_text(s)),
            TokenType::Alphanumeric(s) => TokenType::Alphanumeric(into_text(s)),
            TokenType::Integer(s) => TokenType::Integer(into_text(s)),
            TokenType::Other(s) => TokenType::Other(s),
            TokenType::Punctuation(s) => TokenType::Punctuation(s),
            TokenType::Space => TokenType::Space,
            TokenType::Url(url) => TokenType::Url(Box::new(UrlParts::new(into_text(url)))),
            TokenType::UrlNoHost(s) => TokenType::UrlNoHost(into_text(s)),
            TokenType::UrlNoScheme(s) => {
                TokenType::UrlNoScheme(Box::new(UrlParts::no_scheme(into_text(s))))
            }
            TokenType::IpAddr(i) => TokenType::IpAddr(IpParts::new(i)),
            TokenType::Email(e) => TokenType::Email(Box::new(Email::new(e))),
            TokenType::Float(s) => TokenType::Float(into_text(s)),
        });
    }
    tokens
}

#[inline(always)]
pub(crate) fn borrowed(text: &str) -> Cow<'_, str> {
    Cow::Borrowed(text)
}

#[inline(always)]
pub(crate) fn detached(text: &str) -> Cow<'static, str> {
    Cow::Owned(text.to_string())
}

fn as_recipient(addr: &Addr<'_>) -> Recipient {
    Recipient {
        email: Email::new(addr.address().unwrap_or_default()),
        name: addr.name().and_then(trimmed_name),
    }
}

fn trimmed_name(name: &str) -> Option<String> {
    let name = name.trim();
    if !name.is_empty() {
        Some(name.to_lowercase())
    } else {
        None
    }
}
