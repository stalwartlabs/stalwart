/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FnCtx, args};
use crate::expr::Variable;
use mail_auth::dns::ToReverseName;
use registry::types::ipmask::IpAddrOrMask;
use std::{net::IpAddr, str::FromStr};

pub(crate) fn fn_is_empty<'a>(_: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    match value {
        Variable::String(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) | Variable::Constant(_) => false,
        Variable::Array(a) => a.is_empty(),
    }
    .into()
}

pub(crate) fn fn_is_number<'a>(_: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    matches!(value, Variable::Integer(_) | Variable::Float(_)).into()
}

pub(crate) fn fn_bit_and<'a>(_: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [a, b] = args(v);
    match (a.to_integer(), b.to_integer()) {
        (Some(lhs), Some(rhs)) => Variable::Integer(lhs & rhs),
        _ => Variable::Integer(0),
    }
}

fn parse_ip<'a>(ctx: &FnCtx<'a>, value: Variable<'a>) -> Option<IpAddr> {
    value.to_str(ctx.arena()).parse::<IpAddr>().ok()
}

pub(crate) fn fn_is_ip_addr<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    parse_ip(ctx, value).is_some().into()
}

pub(crate) fn fn_is_ipv4_addr<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    parse_ip(ctx, value)
        .is_some_and(|ip| matches!(ip, IpAddr::V4(_)))
        .into()
}

pub(crate) fn fn_is_ipv6_addr<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    parse_ip(ctx, value)
        .is_some_and(|ip| matches!(ip, IpAddr::V6(_)))
        .into()
}

pub(crate) fn fn_is_ip_in_cidr<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, mask] = args(v);
    let Some(ip) = parse_ip(ctx, value) else {
        return false.into();
    };
    IpAddrOrMask::from_str(mask.to_str(ctx.arena()))
        .map(|mask| mask.matches(&ip))
        .unwrap_or(false)
        .into()
}

pub(crate) fn fn_ip_reverse_name<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    match parse_ip(ctx, value) {
        Some(ip) => Variable::String(ctx.arena().alloc_str(&ip.to_reverse_name())),
        None => Variable::default(),
    }
}

pub(crate) fn fn_if_then<'a>(_: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [condition, then, otherwise] = args(v);
    if condition.to_bool() { then } else { otherwise }
}
