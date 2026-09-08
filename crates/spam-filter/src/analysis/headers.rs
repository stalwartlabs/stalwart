/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{SpamFilterContext, analysis::eq_lowercase};
use common::Server;
use mail_parser::HeaderName;
use std::future::Future;
use store::ahash::AHashSet;

const TAG_BYTE: [u8; 256] = tag_byte_table();

const fn tag_byte_table() -> [u8; 256] {
    let mut table = [b' '; 256];
    let mut idx = 0;
    while idx < 256 {
        let byte = idx as u8;
        table[idx] = if byte.is_ascii_digit() || byte.is_ascii_uppercase() {
            byte
        } else if byte.is_ascii_lowercase() {
            byte - 32
        } else if byte == b'-' {
            b'_'
        } else if byte & 0xc0 == 0x80 {
            0
        } else {
            b' '
        };
        idx += 1;
    }
    table
}

pub trait SpamFilterAnalyzeHeaders: Sync + Send {
    fn spam_filter_analyze_headers(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeHeaders for Server {
    async fn spam_filter_analyze_headers(&self, ctx: &mut SpamFilterContext<'_>) {
        let mut list_score = 0.0;
        let mut unique_headers = AHashSet::with_capacity(13);
        let raw_message = ctx.input.message.raw_message();

        for header in ctx.input.message.headers() {
            // Add header exists tag
            ctx.result.add_tag(header_exists_tag(header.name()));

            match &header.name {
                HeaderName::ContentType
                | HeaderName::ContentTransferEncoding
                | HeaderName::Date
                | HeaderName::From
                | HeaderName::Sender
                | HeaderName::To
                | HeaderName::Cc
                | HeaderName::Bcc
                | HeaderName::ReplyTo
                | HeaderName::Subject
                | HeaderName::MessageId
                | HeaderName::References
                | HeaderName::InReplyTo => {
                    if !unique_headers.insert(header.name.clone()) {
                        ctx.result.add_tag("MULTIPLE_UNIQUE_HEADERS");
                    }

                    let mut value = raw_message
                        .get(header.offset_start as usize..)
                        .unwrap_or_default()
                        .iter();
                    loop {
                        match value.next() {
                            Some(b' ' | b'\t') => {
                                break;
                            }
                            Some(b'\r' | b'\n') => {}
                            _ => {
                                ctx.result.add_tag("HEADER_EMPTY_DELIMITER");
                                break;
                            }
                        }
                    }
                }
                HeaderName::ListArchive
                | HeaderName::ListOwner
                | HeaderName::ListHelp
                | HeaderName::ListPost => {
                    list_score += 0.125;
                }
                HeaderName::ListId => {
                    list_score += 0.5125;
                }
                HeaderName::ListSubscribe => {
                    list_score += 0.25;
                }
                HeaderName::ListUnsubscribe => {
                    list_score += 0.25;
                    ctx.result.add_tag("HAS_LIST_UNSUB");
                }
                HeaderName::Other(name) => {
                    if name.eq_ignore_ascii_case("Precedence") {
                        let value = header.value().as_text().unwrap_or_default().trim();

                        if eq_lowercase(value, "bulk") {
                            list_score += 0.25;
                            ctx.result.add_tag("PRECEDENCE_BULK");
                        } else if eq_lowercase(value, "list") {
                            list_score += 0.25;
                        }
                    } else if name.eq_ignore_ascii_case("X-Loop") {
                        list_score += 0.125;
                    } else if name.eq_ignore_ascii_case("X-Priority") {
                        let value = header.value().as_text().unwrap_or_default().trim();

                        match value.parse::<i32>().unwrap_or(i32::MAX) {
                            0 => {
                                ctx.result.add_tag("HAS_X_PRIO_ZERO");
                            }
                            1 => {
                                ctx.result.add_tag("HAS_X_PRIO_ONE");
                            }
                            2 => {
                                ctx.result.add_tag("HAS_X_PRIO_TWO");
                            }
                            3 | 4 => {
                                ctx.result.add_tag("HAS_X_PRIO_THREE");
                            }
                            4..=10000 => {
                                ctx.result.add_tag("HAS_X_PRIO_FIVE");
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if list_score >= 1.0 {
            ctx.result.add_tag("MAILLIST");
        }

        if unique_headers.is_empty() {
            ctx.result.add_tag("MISSING_ESSENTIAL_HEADERS");
        }
    }
}

fn header_exists_tag(name: &str) -> String {
    let mut tag = String::with_capacity(name.len() + 6);
    tag.push_str("X_HDR_");
    for &byte in name.as_bytes() {
        let mapped = TAG_BYTE[byte as usize];
        if mapped != 0 {
            tag.push(mapped as char);
        }
    }
    tag
}
