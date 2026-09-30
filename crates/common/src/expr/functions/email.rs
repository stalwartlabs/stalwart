/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FnCtx, args};
use crate::expr::Variable;

pub(crate) fn fn_is_email<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    let mut last_ch = 0;
    let mut in_quote = false;
    let mut at_count = 0;
    let mut dot_count = 0;
    let mut lp_len = 0;
    let mut value_len = 0;

    for &ch in value.to_str(ctx.arena()).as_bytes() {
        match ch {
            b'0'..=b'9'
            | b'a'..=b'z'
            | b'A'..=b'Z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'/'
            | b'='
            | b'?'
            | b'^'
            | b'_'
            | b'`'
            | b'{'
            | b'|'
            | b'}'
            | b'~'
            | 0x7f..=u8::MAX => {
                value_len += 1;
            }
            b'.' if !in_quote => {
                if last_ch != b'.' && last_ch != b'@' && value_len != 0 {
                    value_len += 1;
                    if at_count == 1 {
                        dot_count += 1;
                    }
                } else {
                    return false.into();
                }
            }
            b'@' if !in_quote => {
                at_count += 1;
                lp_len = value_len;
                value_len = 0;
            }
            b'>' | b':' | b',' | b' ' if in_quote => {
                value_len += 1;
            }
            b'\"' if !in_quote || last_ch != b'\\' => {
                in_quote = !in_quote;
            }
            b'\\' if in_quote && last_ch != b'\\' => (),
            _ => {
                if !in_quote {
                    return false.into();
                }
            }
        }

        last_ch = ch;
    }

    (at_count == 1 && dot_count > 0 && lp_len > 0 && value_len > 0).into()
}

pub(crate) fn fn_email_part<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, part] = args(v);
    let arena = ctx.arena();
    let part = part.to_str(arena);

    value.transform(arena, |s| {
        s.rsplit_once('@')
            .map(|(local, domain)| match part {
                "local" => Variable::String(local.trim()),
                "domain" => Variable::String(domain.trim()),
                _ => Variable::default(),
            })
            .unwrap_or_default()
    })
}
