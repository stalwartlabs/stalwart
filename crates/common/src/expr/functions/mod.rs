/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Variable;
use bumpalo::Bump;
use registry::schema::enums::ExpressionVariable;

pub mod array;
pub mod asynch;
pub mod email;
pub mod misc;
pub mod text;

pub trait ResolveVariable: Sync + Send {
    fn resolve_variable<'a>(
        &'a self,
        variable: ExpressionVariable,
        arena: &'a Bump,
    ) -> Variable<'a>;

    fn resolve_global<'a>(&'a self, _: &str, _: &'a Bump) -> Variable<'a> {
        Variable::Integer(0)
    }
}

pub(crate) struct FnCtx<'a> {
    arena: &'a Bump,
}

impl<'a> FnCtx<'a> {
    pub fn new(arena: &'a Bump) -> Self {
        FnCtx { arena }
    }

    pub fn arena(&self) -> &'a Bump {
        self.arena
    }
}

pub(crate) type SyncFn = for<'a> fn(&FnCtx<'a>, &[Variable<'a>]) -> Variable<'a>;

pub(crate) fn args<'a, const N: usize>(v: &[Variable<'a>]) -> [Variable<'a>; N] {
    let mut out = [Variable::default(); N];
    for (slot, value) in out.iter_mut().zip(v) {
        *slot = *value;
    }
    out
}

impl<'a> Variable<'a> {
    pub(crate) fn transform(
        self,
        arena: &'a Bump,
        f: impl Fn(&'a str) -> Variable<'a>,
    ) -> Variable<'a> {
        match self {
            Variable::String(s) => f(s),
            Variable::Array(list) => Variable::Array(
                arena.alloc_slice_fill_iter(list.iter().map(|v| f(v.to_str(arena)))),
            ),
            v => f(v.to_str(arena)),
        }
    }
}

pub(crate) const MAX_SYNC_ARGS: usize = 3;

pub const F_IS_LOCAL_DOMAIN: u32 = 0;
pub const F_IS_LOCAL_ADDRESS: u32 = 1;
pub const F_KEY_GET: u32 = 2;
pub const F_KEY_EXISTS: u32 = 3;
pub const F_KEY_SET: u32 = 4;
pub const F_COUNTER_INCR: u32 = 5;
pub const F_COUNTER_GET: u32 = 6;
pub const F_SQL_QUERY: u32 = 7;
pub const F_DNS_QUERY: u32 = 8;

pub(crate) struct FunctionEntry {
    pub name: &'static str,
    pub id: u32,
    pub num_args: u32,
}

macro_rules! functions {
    (
        sync { $($sync:ident $sync_name:tt $sync_args:tt => $sync_fn:path,)* }
        async { $($async_id:ident $async_name:tt $async_args:tt,)* }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(crate) enum SyncFunction {
            $($sync,)*
        }

        impl SyncFunction {
            const ALL: &[SyncFunction] = &[$(SyncFunction::$sync,)*];

            pub(crate) fn from_id(id: u16) -> Option<Self> {
                Self::ALL.get(usize::from(id)).copied()
            }
        }

        pub(crate) const FUNCTIONS: &[SyncFn] = &[$($sync_fn,)*];

        pub(crate) fn lookup_function(name: &str) -> Option<&'static FunctionEntry> {
            hashify::map!(name.as_bytes(), FunctionEntry,
                $($sync_name => FunctionEntry {
                    name: $sync_name,
                    id: SyncFunction::$sync as u32,
                    num_args: $sync_args,
                },)*
                $($async_name => FunctionEntry {
                    name: $async_name,
                    id: FUNCTIONS.len() as u32 + $async_id,
                    num_args: $async_args,
                },)*
            )
        }
    };
}

functions! {
    sync {
        Count "count" 1 => array::fn_count,
        Sort "sort" 2 => array::fn_sort,
        Dedup "dedup" 1 => array::fn_dedup,
        Winnow "winnow" 1 => array::fn_winnow,
        IsIntersect "is_intersect" 2 => array::fn_is_intersect,
        IsEmail "is_email" 1 => email::fn_is_email,
        EmailPart "email_part" 2 => email::fn_email_part,
        IsEmpty "is_empty" 1 => misc::fn_is_empty,
        IsNumber "is_number" 1 => misc::fn_is_number,
        BitAnd "bit_and" 2 => misc::fn_bit_and,
        IsIpAddr "is_ip_addr" 1 => misc::fn_is_ip_addr,
        IsIpv4Addr "is_ipv4_addr" 1 => misc::fn_is_ipv4_addr,
        IsIpv6Addr "is_ipv6_addr" 1 => misc::fn_is_ipv6_addr,
        IsIpInCidr "is_ip_in_cidr" 2 => misc::fn_is_ip_in_cidr,
        IpReverseName "ip_reverse_name" 1 => misc::fn_ip_reverse_name,
        Trim "trim" 1 => text::fn_trim,
        TrimEnd "trim_end" 1 => text::fn_trim_end,
        TrimStart "trim_start" 1 => text::fn_trim_start,
        Len "len" 1 => text::fn_len,
        ToLowercase "to_lowercase" 1 => text::fn_to_lowercase,
        ToUppercase "to_uppercase" 1 => text::fn_to_uppercase,
        IsUppercase "is_uppercase" 1 => text::fn_is_uppercase,
        IsLowercase "is_lowercase" 1 => text::fn_is_lowercase,
        HasDigits "has_digits" 1 => text::fn_has_digits,
        CountSpaces "count_spaces" 1 => text::fn_count_spaces,
        CountUppercase "count_uppercase" 1 => text::fn_count_uppercase,
        CountLowercase "count_lowercase" 1 => text::fn_count_lowercase,
        CountChars "count_chars" 1 => text::fn_count_chars,
        Contains "contains" 2 => text::fn_contains,
        ContainsIgnoreCase "contains_ignore_case" 2 => text::fn_contains_ignore_case,
        EqIgnoreCase "eq_ignore_case" 2 => text::fn_eq_ignore_case,
        StartsWith "starts_with" 2 => text::fn_starts_with,
        EndsWith "ends_with" 2 => text::fn_ends_with,
        Lines "lines" 1 => text::fn_lines,
        Substring "substring" 3 => text::fn_substring,
        StripPrefix "strip_prefix" 2 => text::fn_strip_prefix,
        StripSuffix "strip_suffix" 2 => text::fn_strip_suffix,
        Split "split" 2 => text::fn_split,
        Rsplit "rsplit" 2 => text::fn_rsplit,
        SplitOnce "split_once" 2 => text::fn_split_once,
        RsplitOnce "rsplit_once" 2 => text::fn_rsplit_once,
        SplitN "split_n" 3 => text::fn_split_n,
        SplitWords "split_words" 1 => text::fn_split_words,
        Hash "hash" 2 => text::fn_hash,
        IfThen "if_then" 3 => misc::fn_if_then,
    }
    async {
        F_IS_LOCAL_DOMAIN "is_local_domain" 1,
        F_IS_LOCAL_ADDRESS "is_local_address" 1,
        F_KEY_GET "key_get" 2,
        F_KEY_EXISTS "key_exists" 2,
        F_KEY_SET "key_set" 3,
        F_COUNTER_INCR "counter_incr" 3,
        F_COUNTER_GET "counter_get" 2,
        F_DNS_QUERY "dns_query" 2,
        F_SQL_QUERY "sql_query" 3,
    }
}

pub(crate) const MAX_ASYNC_ARGS: usize = 3;

pub struct EmptyResolver;

impl ResolveVariable for EmptyResolver {
    fn resolve_variable<'a>(&'a self, _: ExpressionVariable, _: &'a Bump) -> Variable<'a> {
        Variable::Integer(0)
    }
}
