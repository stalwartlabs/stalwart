/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, str::FromStr};

use mail_auth::common::resolver::ToReverseName;
use registry::types::ipmask::IpAddrOrMask;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sieve::{Context, runtime::Variable};
use utils::HexEncode;

use super::ApplyString;

pub fn fn_is_empty<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    match &v[0] {
        Variable::String(s) => s.is_empty(),
        Variable::Integer(_) | Variable::Float(_) => false,
        Variable::Array(a) => a.is_empty(),
    }
    .into()
}

pub fn fn_is_number<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    matches!(&v[0], Variable::Integer(_) | Variable::Float(_)).into()
}

pub fn fn_is_ip_addr<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string().parse::<std::net::IpAddr>().is_ok().into()
}

pub fn fn_is_ipv4_addr<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V4(_)))
        .into()
}

pub fn fn_is_ipv6_addr<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| matches!(ip, IpAddr::V6(_)))
        .into()
}

pub fn fn_is_ip_in_cidr<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let Ok(ip) = v[0].to_string().parse::<IpAddr>() else {
        return false.into();
    };
    IpAddrOrMask::from_str(v[1].to_string().as_ref())
        .map(|mask| mask.matches(&ip))
        .unwrap_or(false)
        .into()
}

pub fn fn_ip_reverse_name<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    v[0].to_string()
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_reverse_name())
        .unwrap_or_default()
        .into()
}

pub fn fn_detect_file_type<'x>(ctx: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let as_extension = v[0].to_string() == "ext";
    ctx.message()
        .part(ctx.part())
        .and_then(|p| infer::get(p.contents()))
        .map(|file_type| {
            Variable::borrowed(if as_extension {
                file_type.extension()
            } else {
                file_type.mime_type()
            })
        })
        .unwrap_or_default()
}

pub fn fn_hash<'x>(_: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    use sha1::Digest;
    let hash = v[1].to_string();

    v[0].transform(|value| match hash.as_ref() {
        "md5" => format!("{:x}", md5::compute(value.as_bytes())).into(),
        "sha1" => {
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            hasher.finalize().hex_encode().into()
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            hasher.finalize().hex_encode().into()
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(value.as_bytes());
            hasher.finalize().hex_encode().into()
        }
        _ => Variable::default(),
    })
}

pub fn fn_get_var_names<'x>(ctx: &Context<'x>, _: &[Variable<'x>]) -> Variable<'x> {
    Variable::Array(
        ctx.global_variable_names()
            .map(|v| Variable::from(v.to_uppercase()))
            .collect::<Vec<_>>()
            .into(),
    )
}
