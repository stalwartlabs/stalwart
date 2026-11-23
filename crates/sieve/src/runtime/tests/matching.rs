/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::glob::CompiledGlob;
use crate::{
    Context, Sieve,
    bytecode::{
        ops::{Match, match_kind},
        rec::{Range, tag},
    },
    compiler::grammar::{Comparator, MatchType, RelationalMatch},
    runtime::{RuntimeError, Variable, eval::ValueRef},
};
use smallvec::SmallVec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pattern {
    Dynamic,
    Glob(u16),
    Regex(u16),
}

#[derive(Debug, Clone)]
pub(crate) struct Key<'x> {
    pub value: Variable<'x>,
    pub pattern: Pattern,
}

pub(crate) type Keys<'x> = SmallVec<[Key<'x>; 4]>;

impl Match {
    #[inline(always)]
    pub(crate) fn match_type(&self) -> MatchType {
        match self.kind {
            match_kind::IS => MatchType::Is,
            match_kind::CONTAINS => MatchType::Contains,
            match_kind::MATCHES => MatchType::Matches(self.arg),
            match_kind::REGEX => MatchType::Regex(self.arg),
            match_kind::VALUE => MatchType::Value(RelationalMatch::from_code(self.arg)),
            match_kind::COUNT => MatchType::Count(RelationalMatch::from_code(self.arg)),
            _ => MatchType::List,
        }
    }

    pub(crate) fn from_match_type(match_type: &MatchType) -> Match {
        match match_type {
            MatchType::Is => Match {
                kind: match_kind::IS,
                arg: 0,
            },
            MatchType::Contains => Match {
                kind: match_kind::CONTAINS,
                arg: 0,
            },
            MatchType::Matches(positions) => Match {
                kind: match_kind::MATCHES,
                arg: *positions,
            },
            MatchType::Regex(positions) => Match {
                kind: match_kind::REGEX,
                arg: *positions,
            },
            MatchType::Value(rel) => Match {
                kind: match_kind::VALUE,
                arg: rel.code(),
            },
            MatchType::Count(rel) => Match {
                kind: match_kind::COUNT,
                arg: rel.code(),
            },
            MatchType::List => Match {
                kind: match_kind::LIST,
                arg: 0,
            },
        }
    }
}

const DYNAMIC_REGEX_CACHE: usize = 32;

use std::borrow::Cow;

impl<'x> Context<'x> {
    pub(crate) fn eval_keys(
        &self,
        script: &'x Sieve<'x>,
        range: Range,
    ) -> Result<Keys<'x>, RuntimeError> {
        let mut result = Keys::with_capacity(range.len as usize);
        let mut iter = script.recs(range)?;
        while let Some(rec) = iter.next() {
            let pattern = match rec.tag {
                tag::TEXT => Pattern::Dynamic,
                tag::GLOB => Pattern::Glob(rec.c),
                tag::REGEX => Pattern::Regex(rec.c),
                _ => {
                    let value = ValueRef::decode(script, rec, &mut iter)?;
                    result.push(Key {
                        value: self.eval_value_ref(script, value)?,
                        pattern: Pattern::Dynamic,
                    });
                    continue;
                }
            };
            result.push(Key {
                value: Variable::borrowed(script.str(rec.str())?),
                pattern,
            });
        }
        Ok(result)
    }

    pub(crate) fn key_matches(
        &self,
        script: &'x Sieve<'x>,
        comparator: &Comparator,
        match_type: &MatchType,
        key: &Key<'x>,
        value: &str,
        captured_values: &mut Vec<(usize, String)>,
    ) -> Result<bool, RuntimeError> {
        Ok(match match_type {
            MatchType::Is => comparator.is(&value, &key.value),
            MatchType::Contains => comparator.contains(value, key.value.to_string().as_ref()),
            MatchType::Value(relation) => comparator.relational(relation, &value, &key.value),
            MatchType::Matches(capture_positions) => self.glob_matches(
                script,
                comparator.is_casemap(),
                key,
                value,
                *capture_positions,
                captured_values,
            )?,
            MatchType::Regex(capture_positions) => {
                self.regex_matches(script, key, value, *capture_positions, captured_values)?
            }
            MatchType::Count(_) | MatchType::List => false,
        })
    }

    pub(crate) fn glob_matches(
        &self,
        script: &'x Sieve<'x>,
        to_lower: bool,
        key: &Key<'x>,
        value: &str,
        capture_positions: u64,
        captured_values: &mut Vec<(usize, String)>,
    ) -> Result<bool, RuntimeError> {
        if let Pattern::Glob(index) = key.pattern {
            let glob = script.glob(index)?;
            Ok(if capture_positions == 0 {
                glob.matches(value)
            } else {
                glob.capture(value, capture_positions, captured_values)
            })
        } else {
            let compiled = CompiledGlob::compile(key.value.to_string().as_ref(), to_lower);
            Ok(if capture_positions == 0 {
                compiled.matches(value)
            } else {
                compiled.capture(value, capture_positions, captured_values)
            })
        }
    }

    pub(crate) fn regex_matches(
        &self,
        script: &'x Sieve<'x>,
        key: &Key<'x>,
        value: &str,
        capture_positions: u64,
        captured_values: &mut Vec<(usize, String)>,
    ) -> Result<bool, RuntimeError> {
        if let Pattern::Regex(slot) = key.pattern {
            let pattern = key.value.to_string();
            let regex = script.regex(slot, pattern.as_ref());
            debug_assert!(regex.is_some(), "Failed to compile regex: {pattern:?}");
            Ok(regex
                .is_some_and(|regex| eval_regex(regex, value, capture_positions, captured_values)))
        } else {
            Ok(self.dynamic_regex_matches(
                key.value.clone().into_string(),
                value,
                capture_positions,
                captured_values,
            ))
        }
    }

    fn dynamic_regex_matches(
        &self,
        pattern: Cow<'x, str>,
        value: &str,
        capture_positions: u64,
        captured_values: &mut Vec<(usize, String)>,
    ) -> bool {
        let mut cache = self.dynamic_regexes.borrow_mut();
        if let Some(regex) = cache.get(pattern.as_ref()) {
            return regex
                .as_ref()
                .is_some_and(|regex| eval_regex(regex, value, capture_positions, captured_values));
        }
        let regex = crate::regex::compile(&pattern);
        let matched = regex
            .as_ref()
            .is_some_and(|regex| eval_regex(regex, value, capture_positions, captured_values));
        if cache.len() < DYNAMIC_REGEX_CACHE {
            cache.insert(self.intern_cow(pattern), regex);
        }
        matched
    }
}

fn eval_regex(
    regex: &fancy_regex::Regex,
    value: &str,
    mut capture_positions: u64,
    captured_values: &mut Vec<(usize, String)>,
) -> bool {
    if capture_positions == 0 {
        regex.is_match(value).unwrap_or_default()
    } else if let Ok(Some(captures)) = regex.captures(value) {
        captured_values.clear();
        while capture_positions != 0 {
            let index = 63 - capture_positions.leading_zeros();
            capture_positions ^= 1 << index;
            if let Some(match_var) = captures.get(index as usize) {
                captured_values.push((index as usize, match_var.as_str().to_string()));
            }
        }
        true
    } else {
        false
    }
}
