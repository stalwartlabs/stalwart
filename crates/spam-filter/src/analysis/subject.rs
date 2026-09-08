/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SpamFilterContext,
    analysis::{ExcessEncoding, excess_encoding},
};
use common::Server;
use mail_parser::HeaderName;
use nlp::tokenizers::types::TokenType;
use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_BODY_BINARYMIME, MAIL_SMTPUTF8};
use std::future::Future;

const CLASS_OTHER: u8 = 0;
const CLASS_SPACE: u8 = 1;
const CLASS_UPPER: u8 = 2;
const CLASS_LOWER: u8 = 3;
const CLASS_CURRENCY: u8 = 4;
const ASCII_CLASS: [u8; 256] = ascii_class_table();

const fn ascii_class_table() -> [u8; 256] {
    let mut table = [CLASS_OTHER; 256];
    table[0x09] = CLASS_SPACE;
    table[0x0a] = CLASS_SPACE;
    table[0x0b] = CLASS_SPACE;
    table[0x0c] = CLASS_SPACE;
    table[0x0d] = CLASS_SPACE;
    table[0x20] = CLASS_SPACE;
    table[b'$' as usize] = CLASS_CURRENCY;
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = CLASS_UPPER;
        byte += 1;
    }
    let mut byte = b'a';
    while byte <= b'z' {
        table[byte as usize] = CLASS_LOWER;
        byte += 1;
    }
    table
}

pub trait SpamFilterAnalyzeSubject: Sync + Send {
    fn spam_filter_analyze_subject(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeSubject for Server {
    async fn spam_filter_analyze_subject(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut subject_raw = b"".as_slice();

        for header in ctx.input.message.headers() {
            if header.name == HeaderName::Subject {
                subject_raw = ctx
                    .input
                    .message
                    .raw_message()
                    .get(header.offset_start as usize..header.offset_end as usize)
                    .unwrap_or_default();
                break;
            }
        }

        if subject_raw.is_empty() {
            // Missing subject header
            ctx.result.add_tag("MISSING_SUBJECT");
            return;
        }

        let mut word_count = 0;
        let mut upper_count = 0;
        let mut lower_count = 0;
        let mut has_currency = false;

        let subject_thread = ctx.output.subject_thread.as_str();
        let is_ascii = subject_thread.is_ascii();

        if is_ascii {
            let mut last_is_space = true;
            for &byte in subject_thread.as_bytes() {
                match ASCII_CLASS[byte as usize] {
                    CLASS_SPACE => {
                        last_is_space = true;
                    }
                    class => {
                        if last_is_space {
                            word_count += 1;
                        }
                        last_is_space = false;
                        match class {
                            CLASS_UPPER => upper_count += 1,
                            CLASS_LOWER => lower_count += 1,
                            CLASS_CURRENCY => has_currency = true,
                            _ => {}
                        }
                    }
                }
            }
        } else {
            let mut last_ch = ' ';
            for ch in subject_thread.chars() {
                if !ch.is_whitespace() {
                    if last_ch.is_whitespace() {
                        word_count += 1;
                    }

                    match ch {
                        '$' | '€' | '£' | '¥' | '₹' | '₽' | '₿' => {
                            has_currency = true;
                        }
                        _ => {
                            if ch.is_alphabetic() {
                                if ch.is_uppercase() {
                                    upper_count += 1;
                                } else {
                                    lower_count += 1;
                                }
                            }
                        }
                    }
                }

                last_ch = ch;
            }
        }

        if has_currency {
            ctx.result.add_tag("SUBJECT_HAS_CURRENCY");
        }

        if ctx.output.subject_lc.is_empty() {
            // Subject is empty
            ctx.result.add_tag("EMPTY_SUBJECT");
        } else if ctx.output.subject.ends_with(' ') {
            // Subject ends with whitespace
            ctx.result.add_tag("SUBJECT_ENDS_SPACES");
        } else if ctx.output.subject
            == "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
        {
            ctx.result.add_tag("GTUBE_TEST");
        }

        if ctx.output.subject_thread.len() >= 10
            && word_count > 1
            && upper_count > 2
            && lower_count == 0
        {
            // Subject contains mostly capital letters
            ctx.result.add_tag("SUBJ_ALL_CAPS");
        }

        for token in &ctx.output.subject_tokens {
            match token {
                TokenType::Url(url) => {
                    // Subject contains URL
                    ctx.result.add_tag("URL_IN_SUBJECT");

                    if let Some(url_parsed) = &url.url_parsed {
                        let host = url_parsed.host.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_SUBJECT");
                                break;
                            }
                        }
                    }
                }
                TokenType::UrlNoScheme(url) => {
                    if let Some(url_parsed) = &url.url_parsed {
                        let host = url_parsed.host.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_SUBJECT");
                                break;
                            }
                        }
                    }
                }
                TokenType::Email(email) => {
                    // Subject contains recipient
                    if ctx.output.env_to_orig_addr.contains(email.as_ref())
                        || ctx.output.all_recipients().any(|r| r.email == **email)
                    {
                        ctx.result.add_tag("RCPT_IN_SUBJECT");
                    } else {
                        let host = email.domain_part.sld_or_default();
                        for rcpt in ctx.output.all_recipients() {
                            if rcpt.email == **email {
                                ctx.result.add_tag("RCPT_IN_SUBJECT");
                                break;
                            } else if rcpt.email.domain_part.sld_or_default() == host {
                                ctx.result.add_tag("RCPT_DOMAIN_IN_SUBJECT");
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Validate encoding
        let subject_raw_utf8 = std::str::from_utf8(subject_raw);
        if !subject_raw.is_ascii() {
            if (ctx.input.env_from_flags
                & (MAIL_SMTPUTF8 | MAIL_BODY_8BITMIME | MAIL_BODY_BINARYMIME))
                == 0
            {
                ctx.result.add_tag("SUBJECT_NEEDS_ENCODING");
            }

            if subject_raw_utf8.is_err() {
                ctx.result.add_tag("INVALID_SUBJECT_8BIT");
            }
        }

        // Validate unnecessary encoding
        if is_ascii {
            match excess_encoding(subject_raw_utf8.unwrap_or_default()) {
                ExcessEncoding::QuotedPrintable => {
                    // Subject header is unnecessarily encoded in quoted-printable
                    ctx.result.add_tag("SUBJ_EXCESS_QP");
                }
                ExcessEncoding::Base64 => {
                    // Subject header is unnecessarily encoded in base64
                    ctx.result.add_tag("SUBJ_EXCESS_BASE64");
                }
                ExcessEncoding::None | ExcessEncoding::Other => {}
            }
        }
    }
}
