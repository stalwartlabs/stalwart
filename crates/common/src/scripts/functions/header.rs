/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::{HeaderName, thread_name};
use sieve::{Context, compiler::ReceivedPart, runtime::Variable};

use super::ApplyString;

pub fn fn_received_part<'x>(ctx: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    if let (Ok(part), Some(rcvd)) = (
        ReceivedPart::try_from(v[1].to_string().as_ref()),
        ctx.message()
            .part(ctx.part())
            .and_then(|p| {
                p.headers()
                    .all(HeaderName::Received)
                    .nth((v[0].to_integer() as usize).saturating_sub(1))
            })
            .and_then(|h| h.value().as_received()),
    ) {
        ctx.received_part(&part, rcvd).unwrap_or_default()
    } else {
        Variable::default()
    }
}

pub fn fn_is_encoding_problem<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .map(|p| p.has_problems() || !p.decoded_checked().1.is_empty())
        .unwrap_or_default()
        .into()
}

pub fn fn_is_attachment<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    let part_id = ctx.part();
    ctx.message()
        .attachments()
        .any(|p| p.id() == part_id)
        .into()
}

pub fn fn_is_body<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    let part_id = ctx.part();
    let message = ctx.message();
    message
        .text_body()
        .chain(message.html_body())
        .any(|p| p.id() == part_id)
        .into()
}

pub fn fn_attachment_name<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .and_then(|p| p.attachment_name())
        .map(Variable::from)
        .unwrap_or_default()
}

pub fn fn_mime_part_len<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    ctx.message()
        .part(ctx.part())
        .map(|p| p.decoded_len())
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
            let is_valid = if let Some(header_name) = HeaderName::parse(v[0].to_string().as_ref()) {
                p.headers()
                    .all(header_name)
                    .all(|header| std::str::from_utf8(header.raw_value()).is_ok())
            } else {
                std::str::from_utf8(p.raw_headers()).is_ok()
            };

            Variable::from(is_valid)
        })
        .unwrap_or(Variable::Integer(1))
}
