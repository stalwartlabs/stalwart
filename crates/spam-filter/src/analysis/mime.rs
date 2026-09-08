/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::mime_types::{MimeMatch, mime_match};
use crate::{SpamFilterContext, TextPart, analysis::to_lowercase_cow};
use common::{
    Server,
    scripts::{
        IsMixedCharset,
        functions::{array::cosine_similarity, unicode::CharUtils},
    },
};
use mail_parser::{HeaderName, MimeHeaders, PartType};
use nlp::tokenizers::types::TokenType;
use std::{collections::HashSet, future::Future, vec};

pub trait SpamFilterAnalyzeMime: Sync + Send {
    fn spam_filter_analyze_mime(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeMime for Server {
    async fn spam_filter_analyze_mime(&self, ctx: &mut SpamFilterContext<'_>) {
        let file_extensions = &self.core.spam.lists.file_extensions;

        let mut has_mime_version = false;
        let mut has_ct = false;
        let mut has_cte = false;
        let mut had_cd = false;
        let mut is_plain_text = false;

        for header in ctx.input.message.headers() {
            match &header.name {
                HeaderName::MimeVersion => {
                    if ctx
                        .input
                        .message
                        .raw_message()
                        .get(header.offset_field as usize..header.offset_start as usize - 1)
                        != Some(b"MIME-Version")
                    {
                        ctx.result.add_tag("MV_CASE");
                    }
                    has_mime_version = true;
                }
                HeaderName::ContentType => {
                    has_ct = true;

                    if let Some(ct) = header.value().as_content_type() {
                        if ct.ctype().eq_ignore_ascii_case("multipart")
                            && ct
                                .subtype()
                                .is_some_and(|s| s.eq_ignore_ascii_case("report"))
                            && ct.attribute("report-type").is_some_and(|a| {
                                a.eq_ignore_ascii_case("delivery-status")
                                    || a.eq_ignore_ascii_case("disposition-notification")
                            })
                        {
                            // Message is a DSN
                            ctx.result.add_tag("IS_DSN");
                        }

                        is_plain_text = ct.ctype().eq_ignore_ascii_case("text")
                            && ct
                                .subtype()
                                .unwrap_or_default()
                                .eq_ignore_ascii_case("plain");
                    }
                }
                HeaderName::ContentTransferEncoding => {
                    has_cte = true;
                }
                HeaderName::ContentDisposition => {
                    had_cd = true;
                }
                _ => (),
            }
        }

        if !has_mime_version && (has_ct || has_cte) {
            ctx.result.add_tag("MISSING_MIME_VERSION");
        }
        if has_ct && !is_plain_text && !has_cte && !had_cd && !has_mime_version {
            // Only Content-Type header without other MIME headers
            ctx.result.add_tag("MIME_HEADER_CTYPE_ONLY");
        }
        let raw_message = ctx.input.message.raw_message();

        let mut has_text_part = false;
        let mut is_encrypted = false;
        let mut is_encrypted_smime = false;
        let mut is_encrypted_pgp = false;

        let mut num_parts = 0;
        let mut num_parts_size = 0;

        for (part_id, part) in ctx.input.message.parts.iter().enumerate() {
            let part_id = part_id as u32;
            let mut ct = None;
            let mut cd = None;
            let mut ct_type = "";
            let mut ct_subtype = "";
            let mut cte = "";
            let mut is_attachment = ctx.input.message.attachments.contains(&part_id);
            let mut has_content_id = false;

            for header in part.headers() {
                match &header.name {
                    HeaderName::ContentType => {
                        if let Some(ct_) = header.value().as_content_type() {
                            ct_type = ct_.ctype();
                            ct_subtype = ct_.subtype().unwrap_or_default();
                            ct = Some(ct_);
                        }

                        if ct_type.is_empty() {
                            // Content-Type header can't be parsed
                            ctx.result.add_tag("BROKEN_CONTENT_TYPE");
                        } else if (ct_type.eq_ignore_ascii_case("message")
                            && ct_subtype.eq_ignore_ascii_case("rfc822"))
                            || (ct_type.eq_ignore_ascii_case("text")
                                && ct_subtype.eq_ignore_ascii_case("rfc822-headers"))
                        {
                            // Message has parts
                            ctx.result.add_tag("HAS_MESSAGE_PARTS");
                        }

                        if raw_message
                            .get(header.offset_start as usize..header.offset_end as usize)
                            .and_then(|s| s.trim_ascii_end().last())
                            == Some(&b';')
                        {
                            // Content-Type header ends with a semi-colon
                            ctx.result.add_tag("CT_EXTRA_SEMI");
                        }
                    }
                    HeaderName::ContentTransferEncoding => {
                        cte = header.value().as_text().unwrap_or_default();

                        if cte.as_bytes().iter().any(u8::is_ascii_uppercase) {
                            ctx.result.add_tag("CTE_CASE");
                        }
                    }
                    HeaderName::ContentDisposition => {
                        cd = header.value().as_content_type();
                    }
                    HeaderName::ContentId => {
                        has_content_id = true;
                    }
                    _ => (),
                }
            }

            if ct_type.eq_ignore_ascii_case("multipart") {
                let part_ids = match &part.body {
                    PartType::Multipart(parts) => parts.as_slice(),
                    _ => &[],
                };

                if ct_subtype.eq_ignore_ascii_case("alternative") {
                    let mut has_plain_part = false;
                    let mut has_html_part = false;

                    let mut text_part_words = vec![];
                    let mut text_part_uris = 0;

                    let mut html_part_words = vec![];
                    let mut html_part_uris = 0;

                    for text_part in part_ids
                        .iter()
                        .map(|id| &ctx.output.text_parts[*id as usize])
                    {
                        let (tokens, words, uri_count) = match text_part {
                            TextPart::Plain { tokens, .. } if !has_plain_part => {
                                has_plain_part = true;
                                (tokens, &mut text_part_words, &mut text_part_uris)
                            }
                            TextPart::Html { tokens, .. } if !has_html_part => {
                                has_html_part = true;
                                (tokens, &mut html_part_words, &mut html_part_uris)
                            }
                            _ => continue,
                        };

                        let mut uris = HashSet::new();
                        words.reserve(tokens.len());
                        for token in tokens {
                            match token {
                                TokenType::Alphabetic(v) | TokenType::Alphanumeric(v) => {
                                    words.push(v.as_ref());
                                }
                                TokenType::Url(v) => {
                                    if let Some(host) = v.url_parsed.as_ref().map(|uri| &uri.host) {
                                        uris.insert(host.sld_or_default());
                                    }
                                }
                                _ => (),
                            }
                        }

                        *uri_count = uris.len();
                    }

                    //  Multipart message mostly text/html MIME
                    if has_html_part {
                        if !has_plain_part {
                            ctx.result.add_tag("MIME_MA_MISSING_TEXT");
                        }
                    } else if has_plain_part {
                        ctx.result.add_tag("MIME_MA_MISSING_HTML");
                    }

                    // HTML and text parts are different
                    if has_plain_part
                        && has_html_part
                        && (!text_part_words.is_empty() || !html_part_words.is_empty())
                        && cosine_similarity(&text_part_words, &html_part_words) < 0.95
                    {
                        ctx.result.add_tag("PARTS_DIFFER");
                    }

                    // Odd URI count between parts
                    if text_part_uris != html_part_uris {
                        ctx.result.add_tag("URI_COUNT_ODD");
                    }
                } else if ct_subtype.eq_ignore_ascii_case("mixed") {
                    let mut num_text_parts = 0;
                    let mut has_other_parts = false;

                    for (sub_part_id, sub_part) in part_ids
                        .iter()
                        .map(|id| (*id, &ctx.input.message.parts[*id as usize]))
                    {
                        let ctype = sub_part
                            .content_type()
                            .map(|ct| ct.ctype())
                            .unwrap_or_default();

                        if ctype.eq_ignore_ascii_case("text")
                            && !ctx.input.message.attachments.contains(&sub_part_id)
                        {
                            num_text_parts += 1;
                        } else if !ctype.eq_ignore_ascii_case("multipart") {
                            has_other_parts = true;
                        }
                    }

                    // Found multipart/mixed without non-textual part
                    if !has_other_parts && num_text_parts < 3 {
                        ctx.result.add_tag("CTYPE_MIXED_BOGUS");
                    }
                } else if ct_subtype.eq_ignore_ascii_case("encrypted") {
                    is_encrypted = true;
                }

                continue;
            } else if ct_type.eq_ignore_ascii_case("text") {
                let mut is_7bit = false;
                if cte.is_empty() || cte.eq_ignore_ascii_case("7bit") {
                    if raw_message
                        .get(part.raw_body_offset() as usize..part.raw_end_offset() as usize)
                        .is_some_and(|bytes| !bytes.is_ascii())
                    {
                        // MIME text part claims to be ASCII but isn't
                        ctx.result.add_tag("BAD_CTE_7BIT");
                    }
                    is_7bit = true;
                } else if cte.eq_ignore_ascii_case("base64") {
                    if part.contents().is_ascii() {
                        // Has text part encoded in base64 that does not contain any 8bit characters
                        ctx.result.add_tag("MIME_BASE64_TEXT_BOGUS");
                    } else {
                        // Has text part encoded in base64
                        ctx.result.add_tag("MIME_BASE64_TEXT");
                    }
                }

                if !is_7bit
                    && ct_subtype.eq_ignore_ascii_case("plain")
                    && ct
                        .and_then(|ct| ct.attribute("charset"))
                        .is_none_or(|c| c.is_empty())
                {
                    // Charset header is missing
                    ctx.result.add_tag("MISSING_CHARSET");
                }

                if ctx
                    .output
                    .text_parts
                    .get(part_id as usize)
                    .filter(|_| {
                        ctx.input.message.text_body.contains(&part_id)
                            || ctx.input.message.html_body.contains(&part_id)
                    })
                    .is_some_and(|p| match p {
                        TextPart::Plain { text_body, .. } => text_body.is_mixed_charset(),
                        TextPart::Html { text_body, .. } => text_body.is_mixed_charset(),
                        TextPart::None => false,
                    })
                {
                    // Text part contains multiple scripts
                    ctx.result.add_tag("MIXED_CHARSET");
                }

                has_text_part = true;
            } else if ct_type.eq_ignore_ascii_case("application") {
                if ct_subtype.eq_ignore_ascii_case("pkcs7-mime") {
                    ctx.result.add_tag("ENCRYPTED_SMIME");
                    is_attachment = false;
                    is_encrypted_smime = true;
                } else if ct_subtype.eq_ignore_ascii_case("pkcs7-signature") {
                    ctx.result.add_tag("SIGNED_SMIME");
                    is_attachment = false;
                } else if ct_subtype.eq_ignore_ascii_case("pgp-encrypted") {
                    ctx.result.add_tag("ENCRYPTED_PGP");
                    is_attachment = false;
                    is_encrypted_pgp = true;
                } else if ct_subtype.eq_ignore_ascii_case("pgp-signature") {
                    ctx.result.add_tag("SIGNED_PGP");
                    is_attachment = false;
                } else if ct_subtype.eq_ignore_ascii_case("octet-stream")
                    && !is_encrypted
                    && !has_content_id
                    && cd.is_none_or(|cd| {
                        !cd.c_type.eq_ignore_ascii_case("attachment")
                            && !cd.has_attribute("filename")
                    })
                {
                    ctx.result.add_tag("CTYPE_MISSING_DISPOSITION");
                }
            }

            num_parts += 1;
            num_parts_size += part.len();

            let is_octet_stream = ct_type.eq_ignore_ascii_case("application")
                && ct_subtype.eq_ignore_ascii_case("octet-stream");

            if is_attachment {
                // Has a MIME attachment
                ctx.result.add_tag("HAS_ATTACHMENT");
                if !is_octet_stream && let Some(t) = infer::get(part.contents()) {
                    match mime_match(t.mime_type(), &content_type_full(ct_type, ct_subtype)) {
                        MimeMatch::Equal => {
                            // Known content-type
                            ctx.result.add_tag("MIME_GOOD");
                        }
                        MimeMatch::Mismatch => {
                            // Known bad content-type
                            ctx.result.add_tag("MIME_BAD");
                        }
                        MimeMatch::Compatible => (),
                    }
                }
            }

            // Analyze attachment name
            if let Some(attach_name) = part.attachment_name() {
                if attach_name.chars().any(|c| c.is_obscured()) {
                    // Attachment name contains zero-width space
                    ctx.result.add_tag("MIME_BAD_UNICODE");
                }
                let attach_name = to_lowercase_cow(attach_name.trim());
                if let Some((name, ext)) = attach_name
                    .rsplit_once('.')
                    .and_then(|(name, ext)| Some((name, file_extensions.get(ext)?)))
                {
                    let sub_ext = name
                        .rsplit_once('.')
                        .and_then(|(_, ext)| file_extensions.get(ext));

                    if ext.is_bad {
                        // Attachment has a bad extension
                        if sub_ext.is_some_and(|e| e.is_bad) {
                            ctx.result.add_tag("MIME_DOUBLE_BAD_EXTENSION");
                        } else {
                            ctx.result.add_tag("MIME_BAD_EXTENSION");
                        }
                    }

                    if ext.is_archive && sub_ext.is_some_and(|e| e.is_archive) {
                        // Archive in archive
                        ctx.result.add_tag("MIME_ARCHIVE_IN_ARCHIVE");
                    }

                    if !ext.known_types.is_empty()
                        && !is_octet_stream
                        && !ext
                            .known_types
                            .contains(content_type_full(ct_type, ct_subtype).as_str())
                    {
                        // Invalid attachment mime type
                        ctx.result.add_tag("MIME_BAD_ATTACHMENT");
                    }
                }
            }
        }

        match num_parts_size {
            0 => {
                // Message contains no parts
                ctx.result.add_tag("COMPLETELY_EMPTY");
            }
            1..64 if num_parts == 1 => {
                // Message contains only one short part
                ctx.result.add_tag("SINGLE_SHORT_PART");
            }
            _ => (),
        }

        if has_text_part && (is_encrypted_pgp || is_encrypted_smime) {
            // Message contains both text and encrypted parts
            ctx.result.add_tag("BOGUS_ENCRYPTED_AND_TEXT");
        }
    }
}

fn content_type_full(ct_type: &str, ct_subtype: &str) -> String {
    let mut full = String::with_capacity(ct_type.len() + ct_subtype.len() + 1);
    full.push_str(ct_type);
    full.push('/');
    full.push_str(ct_subtype);
    full.make_ascii_lowercase();
    full
}
