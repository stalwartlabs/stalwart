/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FnCtx, args};
use crate::expr::{Variable, kernels};
use bumpalo::{Bump, collections::Vec as BumpVec};
use memchr::{memchr_iter, memmem};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha512};

const EMPTY_SEPARATOR: &str = "";

fn contains<'a>(haystack: Variable<'a>, needle: Variable<'a>, arena: &'a Bump) -> bool {
    match haystack {
        Variable::String(s) => s.contains(needle.to_str(arena)),
        Variable::Array(items) => items.contains(&needle),
        value => value.to_str(arena).contains(needle.to_str(arena)),
    }
}

pub(crate) fn contains_ignore_case<'a>(
    haystack: Variable<'a>,
    needle: &str,
    arena: &'a Bump,
    in_string: impl FnOnce(&'a str) -> bool,
) -> bool {
    match haystack {
        Variable::String(s) => in_string(s),
        Variable::Array(items) => items
            .iter()
            .any(|item| matches!(item, Variable::String(s) if s.eq_ignore_ascii_case(needle))),
        value => value.to_str(arena).contains(needle),
    }
}

fn collect_strs<'a>(arena: &'a Bump, items: impl Iterator<Item = &'a str>) -> Variable<'a> {
    let mut out = BumpVec::new_in(arena);
    out.extend(items.map(Variable::String));
    Variable::Array(out.into_bump_slice())
}

fn split_capacity(value: &str, separator: &str) -> usize {
    match separator.as_bytes() {
        [] => value.len() + 2,
        [byte] => memchr_iter(*byte, value.as_bytes()).count() + 1,
        needle => memmem::find_iter(value.as_bytes(), needle).count() + 1,
    }
}

fn single_byte(separator: &str) -> Option<char> {
    match separator.as_bytes() {
        [byte] => Some(char::from(*byte)),
        _ => None,
    }
}

fn pair<'a>(arena: &'a Bump, (a, b): (&'a str, &'a str)) -> Variable<'a> {
    Variable::Array(arena.alloc_slice_copy(&[Variable::String(a), Variable::String(b)]))
}

pub(crate) fn fn_trim<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    value.transform(ctx.arena(), |s| Variable::String(s.trim()))
}

pub(crate) fn fn_trim_end<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    value.transform(ctx.arena(), |s| Variable::String(s.trim_end()))
}

pub(crate) fn fn_trim_start<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    value.transform(ctx.arena(), |s| Variable::String(s.trim_start()))
}

pub(crate) fn fn_len<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    match value {
        Variable::String(s) => s.len(),
        Variable::Array(a) => a.len(),
        value => value.to_str(ctx.arena()).len(),
    }
    .into()
}

pub(crate) fn fn_to_lowercase<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    let arena = ctx.arena();
    value.transform(arena, |s| Variable::String(kernels::to_lowercase(s, arena)))
}

pub(crate) fn fn_to_uppercase<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    let arena = ctx.arena();
    value.transform(arena, |s| Variable::String(kernels::to_uppercase(s, arena)))
}

pub(crate) fn fn_is_uppercase<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    value.transform(ctx.arena(), |s| kernels::is_uppercase(s).into())
}

pub(crate) fn fn_is_lowercase<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    value.transform(ctx.arena(), |s| kernels::is_lowercase(s).into())
}

pub(crate) fn fn_has_digits<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    value.transform(ctx.arena(), |s| kernels::has_digits(s).into())
}

pub(crate) fn fn_split_words<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    let arena = ctx.arena();
    collect_strs(arena, kernels::split_words(value.to_str(arena)))
}

pub(crate) fn fn_count_spaces<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    kernels::count_whitespace(value.to_str(ctx.arena())).into()
}

pub(crate) fn fn_count_uppercase<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    kernels::count_uppercase(value.to_str(ctx.arena())).into()
}

pub(crate) fn fn_count_lowercase<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    kernels::count_lowercase(value.to_str(ctx.arena())).into()
}

pub(crate) fn fn_count_chars<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    kernels::count_chars(value.to_str(ctx.arena())).into()
}

pub(crate) fn fn_eq_ignore_case<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [a, b] = args(v);
    let arena = ctx.arena();
    a.to_str(arena).eq_ignore_ascii_case(b.to_str(arena)).into()
}

pub(crate) fn fn_contains<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [haystack, needle] = args(v);
    contains(haystack, needle, ctx.arena()).into()
}

pub(crate) fn fn_contains_ignore_case<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [haystack, needle] = args(v);
    let arena = ctx.arena();
    let needle = needle.to_str(arena);
    contains_ignore_case(haystack, needle, arena, |s| {
        kernels::contains_ignore_case(s, needle)
    })
    .into()
}

pub(crate) fn fn_starts_with<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [a, b] = args(v);
    let arena = ctx.arena();
    a.to_str(arena).starts_with(b.to_str(arena)).into()
}

pub(crate) fn fn_ends_with<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [a, b] = args(v);
    let arena = ctx.arena();
    a.to_str(arena).ends_with(b.to_str(arena)).into()
}

pub(crate) fn fn_lines<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    match value {
        Variable::String(s) => collect_strs(ctx.arena(), s.lines()),
        value => value,
    }
}

pub(crate) fn fn_substring<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, start, count] = args(v);
    Variable::String(kernels::substring(
        value.to_str(ctx.arena()),
        start.to_usize().unwrap_or_default(),
        count.to_usize().unwrap_or_default(),
    ))
}

pub(crate) fn fn_strip_prefix<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, prefix] = args(v);
    let arena = ctx.arena();
    let prefix = prefix.to_str(arena);
    value.transform(arena, |s| {
        s.strip_prefix(prefix)
            .map(Variable::String)
            .unwrap_or_default()
    })
}

pub(crate) fn fn_strip_suffix<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, suffix] = args(v);
    let arena = ctx.arena();
    let suffix = suffix.to_str(arena);
    value.transform(arena, |s| {
        s.strip_suffix(suffix)
            .map(Variable::String)
            .unwrap_or_default()
    })
}

pub(crate) fn fn_split<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, separator] = args(v);
    let arena = ctx.arena();
    let value = value.to_str(arena);
    let separator = separator.to_str(arena);
    let mut out = BumpVec::with_capacity_in(split_capacity(value, separator), arena);
    match single_byte(separator) {
        Some(separator) => out.extend(value.split(separator).map(Variable::String)),
        None => out.extend(value.split(separator).map(Variable::String)),
    }
    Variable::Array(out.into_bump_slice())
}

pub(crate) fn fn_rsplit<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, separator] = args(v);
    let arena = ctx.arena();
    let value = value.to_str(arena);
    let separator = separator.to_str(arena);
    let mut out = BumpVec::with_capacity_in(split_capacity(value, separator), arena);
    match single_byte(separator) {
        Some(separator) => out.extend(value.rsplit(separator).map(Variable::String)),
        None => out.extend(value.rsplit(separator).map(Variable::String)),
    }
    Variable::Array(out.into_bump_slice())
}

pub(crate) fn fn_split_n<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, separator, count] = args(v);
    let arena = ctx.arena();
    let mut rest = value.to_str(arena);
    let separator = separator.to_str(arena);
    let count = count.to_integer().unwrap_or_default() as usize;
    if separator.is_empty() {
        return collect_strs(arena, rest.splitn(count.saturating_add(1), EMPTY_SEPARATOR));
    }

    let mut out = BumpVec::new_in(arena);
    for _ in 0..count {
        match rest.split_once(separator) {
            Some((head, tail)) => {
                out.push(Variable::String(head));
                rest = tail;
            }
            None => break,
        }
    }
    out.push(Variable::String(rest));
    Variable::Array(out.into_bump_slice())
}

pub(crate) fn fn_split_once<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, separator] = args(v);
    let arena = ctx.arena();
    value
        .to_str(arena)
        .split_once(separator.to_str(arena))
        .map(|parts| pair(arena, parts))
        .unwrap_or_default()
}

pub(crate) fn fn_rsplit_once<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, separator] = args(v);
    let arena = ctx.arena();
    value
        .to_str(arena)
        .rsplit_once(separator.to_str(arena))
        .map(|parts| pair(arena, parts))
        .unwrap_or_default()
}

pub(crate) fn fn_hash<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, algorithm] = args(v);
    let arena = ctx.arena();
    let value = value.to_str(arena).as_bytes();

    let hex = |digest: &[u8]| Variable::String(kernels::hex_encode(digest, arena));
    hashify::fnc_map!(algorithm.to_str(arena).as_bytes(),
        "md5" => hex(&md5::compute(value).0),
        "sha1" => hex(&Sha1::digest(value)),
        "sha256" => hex(&Sha256::digest(value)),
        "sha512" => hex(&Sha512::digest(value)),
        _ => Variable::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::functions::SyncFn;

    fn split_n<'a>(
        arena: &'a Bump,
        value: &'a str,
        separator: &'a str,
        count: i64,
    ) -> Vec<&'a str> {
        let ctx = FnCtx::new(arena);
        match fn_split_n(
            &ctx,
            &[
                Variable::String(value),
                Variable::String(separator),
                Variable::Integer(count),
            ],
        ) {
            Variable::Array(items) => items.iter().map(|item| item.to_str(arena)).collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn split_n_empty_separator_follows_std_splitn() {
        let arena = Bump::new();
        for value in ["", "ab", "ünï"] {
            for count in [-1, 0, 1, 2, 3, 100, i64::MAX] {
                let expected = value
                    .splitn((count as usize).saturating_add(1), "")
                    .collect::<Vec<_>>();
                assert_eq!(split_n(&arena, value, "", count), expected);
            }
        }
        assert_eq!(split_n(&arena, "ab", "", -1), ["", "a", "b", ""]);
        assert_eq!(split_n(&arena, "ab", "", 1), ["", "ab"]);
        assert_eq!(split_n(&arena, "a,b,c", ",", -1), ["a", "b", "c"]);
        assert_eq!(split_n(&arena, "a,b,c", ",", 1), ["a", "b,c"]);
    }

    #[test]
    fn split_matches_std() {
        let arena = Bump::new();
        let ctx = FnCtx::new(&arena);
        for value in [
            "",
            "a",
            "a b  c",
            " lead trail ",
            "ünï cödé",
            "a::b::::c",
            "aaaa",
        ] {
            for separator in ["", " ", ":", "::", "aa", "ö", "missing"] {
                let args = [Variable::String(value), Variable::String(separator)];
                for (function, expected) in [
                    (
                        fn_split as SyncFn,
                        value.split(separator).collect::<Vec<_>>(),
                    ),
                    (fn_rsplit, value.rsplit(separator).collect::<Vec<_>>()),
                ] {
                    let Variable::Array(items) = function(&ctx, &args) else {
                        panic!("split returns an array");
                    };
                    let items = items
                        .iter()
                        .map(|item| item.to_str(&arena))
                        .collect::<Vec<_>>();
                    assert_eq!(items, expected, "{value:?} {separator:?}");
                }
            }
        }
    }

    #[test]
    fn case_conversion_borrows_when_unchanged() {
        let arena = Bump::new();
        for text in ["plain ascii", "ünïcödé", "σς"] {
            assert!(std::ptr::eq(kernels::to_lowercase(text, &arena), text));
        }
        for text in ["PLAIN ASCII", "ÜNÏCÖDÉ"] {
            assert!(std::ptr::eq(kernels::to_uppercase(text, &arena), text));
        }
        assert_eq!(arena.allocated_bytes(), 0);
    }

    #[test]
    fn case_conversion_follows_std() {
        let arena = Bump::new();
        for text in [
            "ΟΔΟΣ ΣΊΣΥΦΟΣ",
            "\u{212A}elvin İ",
            "straße ﬁ",
            "ABCDEFGHIJKLMNOPΣ",
            "Plain Ascii Text With Σ",
        ] {
            assert_eq!(kernels::to_lowercase(text, &arena), text.to_lowercase());
            assert_eq!(kernels::to_uppercase(text, &arena), text.to_uppercase());
        }
    }
}
