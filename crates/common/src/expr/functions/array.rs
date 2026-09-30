/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FnCtx, args};
use crate::expr::Variable;
use ahash::RandomState;
use bumpalo::{Bump, collections::Vec as BumpVec};
use std::cmp::Ordering;

const DEDUP_LINEAR_MAX_ITEMS: usize = 32;
const EMPTY_SLOT: u32 = u32::MAX;

pub(crate) fn fn_count<'a>(_: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    match value {
        Variable::Array(a) => a.len(),
        v => usize::from(!v.is_empty()),
    }
    .into()
}

pub(crate) fn fn_sort<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value, ascending] = args(v);
    let arena = ctx.arena();
    let items = arena.alloc_slice_copy(value.into_array(arena));
    let ascending = ascending.to_bool();
    if items.iter().all(|item| matches!(item, Variable::String(_))) {
        if ascending {
            items.sort_unstable_by(|a, b| compare_strings(a, b));
        } else {
            items.sort_unstable_by(|a, b| compare_strings(b, a));
        }
    } else if ascending {
        items.sort_unstable();
    } else {
        items.sort_unstable_by(|a, b| b.cmp(a));
    }
    Variable::Array(items)
}

pub(crate) fn fn_dedup<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    let arena = ctx.arena();
    let items = value.into_array(arena);
    if (DEDUP_LINEAR_MAX_ITEMS + 1..EMPTY_SLOT as usize).contains(&items.len())
        && items.iter().all(|item| matches!(item, Variable::String(_)))
    {
        return Variable::Array(dedup_strings(items, arena));
    }
    let mut result = BumpVec::with_capacity_in(items.len(), arena);
    for item in items {
        if !result.contains(item) {
            result.push(*item);
        }
    }
    Variable::Array(result.into_bump_slice())
}

pub(crate) fn fn_is_intersect<'a>(_: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [a, b] = args(v);
    match (a, b) {
        (Variable::Array(a), Variable::Array(b)) => a.iter().any(|x| b.contains(x)),
        (Variable::Array(a), item) | (item, Variable::Array(a)) => a.contains(&item),
        _ => false,
    }
    .into()
}

pub(crate) fn fn_winnow<'a>(ctx: &FnCtx<'a>, v: &[Variable<'a>]) -> Variable<'a> {
    let [value] = args(v);
    match value {
        Variable::Array(a) => {
            let mut result = BumpVec::with_capacity_in(a.len(), ctx.arena());
            result.extend(a.iter().filter(|i| !i.is_empty()).copied());
            Variable::Array(result.into_bump_slice())
        }
        v => v,
    }
}

fn string_of<'a>(value: &Variable<'a>) -> &'a str {
    match value {
        Variable::String(s) => s,
        _ => "",
    }
}

fn compare_strings(a: &Variable<'_>, b: &Variable<'_>) -> Ordering {
    string_of(a).cmp(string_of(b))
}

fn dedup_strings<'a>(items: &[Variable<'a>], arena: &'a Bump) -> &'a [Variable<'a>] {
    let hasher = RandomState::new();
    let slots = arena.alloc_slice_fill_copy(
        items.len().saturating_mul(2).next_power_of_two(),
        EMPTY_SLOT,
    );
    let mask = slots.len() - 1;
    let mut result = BumpVec::with_capacity_in(items.len(), arena);
    for item in items {
        let text = string_of(item);
        let mut slot = (hasher.hash_one(text) as usize) & mask;
        loop {
            match slots.get(slot).copied() {
                Some(EMPTY_SLOT) => {
                    if let Some(entry) = slots.get_mut(slot) {
                        *entry = result.len() as u32;
                    }
                    result.push(*item);
                    break;
                }
                Some(index) if result.get(index as usize).map(string_of) == Some(text) => break,
                Some(_) => slot = (slot + 1) & mask,
                None => {
                    result.push(*item);
                    break;
                }
            }
        }
    }
    result.into_bump_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_dedup<'a>(items: &[Variable<'a>]) -> Vec<Variable<'a>> {
        let mut result = Vec::new();
        for item in items {
            if !result.contains(item) {
                result.push(*item);
            }
        }
        result
    }

    fn strings(arena: &Bump, count: usize, distinct: usize) -> &[Variable<'_>] {
        arena.alloc_slice_fill_with(count, |index| {
            Variable::String(arena.alloc_str(&format!("item-{}", (index * 7919) % distinct)))
        })
    }

    #[test]
    fn dedup_matches_linear_scan() {
        let arena = Bump::new();
        let ctx = FnCtx::new(&arena);
        for (count, distinct) in [
            (0, 1),
            (5, 3),
            (32, 10),
            (33, 10),
            (40, 40),
            (500, 250),
            (700, 1),
        ] {
            let items = strings(&arena, count, distinct);
            let Variable::Array(result) = fn_dedup(&ctx, &[Variable::Array(items)]) else {
                panic!("dedup returns an array");
            };
            assert_eq!(result, linear_dedup(items).as_slice(), "{count} items");
        }
        let mixed = arena.alloc_slice_fill_with(64, |index| match index % 3 {
            0 => Variable::Integer((index % 5) as i64),
            1 => Variable::String(arena.alloc_str(&(index % 5).to_string())),
            _ => Variable::Float((index % 5) as f64),
        });
        let Variable::Array(result) = fn_dedup(&ctx, &[Variable::Array(mixed)]) else {
            panic!("dedup returns an array");
        };
        assert_eq!(result, linear_dedup(mixed).as_slice());
    }

    #[test]
    fn string_sort_matches_generic_sort() {
        let arena = Bump::new();
        let ctx = FnCtx::new(&arena);
        let items = strings(&arena, 300, 120);
        for ascending in [true, false] {
            let Variable::Array(result) = fn_sort(
                &ctx,
                &[
                    Variable::Array(items),
                    Variable::Integer(i64::from(ascending)),
                ],
            ) else {
                panic!("sort returns an array");
            };
            let mut expected = items.to_vec();
            if ascending {
                expected.sort_unstable();
            } else {
                expected.sort_unstable_by(|a, b| b.cmp(a));
            }
            assert_eq!(result, expected.as_slice());
        }
    }
}
