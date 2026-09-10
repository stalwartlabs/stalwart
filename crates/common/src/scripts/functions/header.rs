/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::{HeaderName, HeaderValue, MimeHeaders, parsers::fields::thread::thread_name};
use sieve::{Context, compiler::ReceivedPart, runtime::Variable};

use super::ApplyString;

pub fn fn_received_part<'x>(ctx: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    if let (Ok(part), Some(HeaderValue::Received(rcvd))) = (
        ReceivedPart::try_from(v[1].to_string().as_ref()),
        ctx.message()
            .part(ctx.part())
            .and_then(|p| {
                p.headers
                    .iter()
                    .filter(|h| h.name == HeaderName::Received)
                    .nth((v[0].to_integer() as usize).saturating_sub(1))
            })
            .map(|h| &h.value),
    ) {
        ctx.received_part(&part, rcvd).unwrap_or_default()
    } else {
        Variable::default()
    }
}

pub fn fn_is_encoding_problem<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .map(|p| p.is_encoding_problem)
        .unwrap_or_default()
        .into()
}

pub fn fn_is_attachment<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message().attachments.contains(&ctx.part()).into()
}

pub fn fn_is_body<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    (ctx.message().text_body.contains(&ctx.part()) || ctx.message().html_body.contains(&ctx.part()))
        .into()
}

pub fn fn_attachment_name<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .and_then(|p| p.attachment_name())
        .map(|name| Variable::from(name.to_string()))
        .unwrap_or_default()
}

pub fn fn_mime_part_len<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .map(|p| p.len())
        .unwrap_or_default()
        .into()
}

pub fn fn_thread_name<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].transform_str(|s| thread_name(s).into())
}

pub fn fn_is_header_utf8_valid<'x>(ctx: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .map(|p| {
            let raw = ctx.message().raw_message();
            let mut is_valid = true;
            if let Some(header_name) = HeaderName::parse(v[0].to_string().as_ref()) {
                for header in &p.headers {
                    if header.name == header_name
                        && raw
                            .get(header.offset_start() as usize..header.offset_end() as usize)
                            .and_then(|raw| std::str::from_utf8(raw).ok())
                            .is_none()
                    {
                        is_valid = false;
                        break;
                    }
                }
            } else {
                is_valid = raw
                    .get(p.raw_header_offset() as usize..p.raw_body_offset() as usize)
                    .and_then(|raw| std::str::from_utf8(raw).ok())
                    .is_some();
            }

            Variable::from(is_valid)
        })
        .unwrap_or(Variable::Integer(1))
}
