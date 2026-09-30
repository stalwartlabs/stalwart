/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bumpalo::Bump;
use regex_automata::{
    Input, MatchKind, meta,
    util::{primitives::NonMaxUsize, syntax},
};
use std::{fmt, sync::Arc};

const NFA_SIZE_LIMIT: usize = 10 * (1 << 20);
const HYBRID_CACHE_CAPACITY: usize = 2 * (1 << 20);

pub type Slot = Option<NonMaxUsize>;

#[derive(Clone)]
pub struct CaptureRegex {
    inner: Arc<CompiledRegex>,
}

struct CompiledRegex {
    regex: meta::Regex,
    pattern: Box<str>,
}

#[derive(Default)]
pub(crate) struct Captures<'s> {
    haystack: &'s str,
    matched: bool,
    slots: Option<(u32, &'s mut [Slot])>,
}

impl CaptureRegex {
    pub fn new(pattern: &str) -> Result<Self, String> {
        meta::Builder::new()
            .configure(
                meta::Config::new()
                    .nfa_size_limit(Some(NFA_SIZE_LIMIT))
                    .hybrid_cache_capacity(HYBRID_CACHE_CAPACITY)
                    .match_kind(MatchKind::LeftmostFirst)
                    .utf8_empty(true),
            )
            .syntax(syntax::Config::new().utf8(true))
            .build(pattern)
            .map(|regex| CaptureRegex {
                inner: Arc::new(CompiledRegex {
                    regex,
                    pattern: pattern.into(),
                }),
            })
            .map_err(|err| {
                let reason = match (err.size_limit(), err.syntax_error()) {
                    (Some(limit), _) => {
                        format!("Compiled regex exceeds size limit of {limit} bytes.")
                    }
                    (None, Some(syntax)) => syntax.to_string(),
                    (None, None) => err.to_string(),
                };
                format!("Invalid regular expression {pattern:?}: {reason}")
            })
    }

    pub fn is_match(&self, haystack: &str) -> bool {
        self.inner.regex.is_match(haystack)
    }

    pub fn slot_len(&self) -> usize {
        self.inner.regex.group_info().slot_len()
    }

    pub fn search(&self, haystack: &str, slots: &mut [Slot]) -> bool {
        self.inner
            .regex
            .search_slots(&Input::new(haystack), slots)
            .is_some()
    }
}

impl fmt::Debug for CaptureRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Regex").field(&self.inner.pattern).finish()
    }
}

impl<'s> Captures<'s> {
    pub(crate) fn read(
        &mut self,
        index: u32,
        regex: &CaptureRegex,
        haystack: &'s str,
        arena: &'s Bump,
    ) -> bool {
        let slots = match &mut self.slots {
            Some((current, slots)) if *current == index => slots,
            slots => {
                &mut slots
                    .insert((index, arena.alloc_slice_fill_copy(regex.slot_len(), None)))
                    .1
            }
        };
        self.matched = regex.search(haystack, slots);
        self.haystack = haystack;
        self.matched
    }

    pub(crate) fn get(&self, group: u32) -> &'s str {
        let Some((_, slots)) = self.slots.as_ref().filter(|_| self.matched) else {
            return "";
        };
        let start = group as usize * 2;
        match slots.get(start..start + 2) {
            Some([Some(start), Some(end)]) => self.haystack.get(start.get()..end.get()),
            _ => None,
        }
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn slots_match_regex_captures() {
        let arena = Bump::new();
        let haystacks = [
            "",
            "john@example.org",
            "Jane.Doe@corp.example.net",
            "Re: Fwd: hello",
            "AW:   ünïcödé",
            "y",
            "xy",
            "İstanbul ü",
            "12.34 and 56.78",
        ];
        for pattern in [
            "^([a-z]+)@(.+)$",
            "^(?i)(re|fwd?|aw):\\s*(.*)$",
            "(x)?y",
            "(ü|Ü|İ)",
            "^$",
            "(\\d+)\\.(\\d+)",
            "([^.]+)\\.(?P<rest>.+)",
        ] {
            let regex = Regex::new(pattern).expect("valid pattern");
            let capture = CaptureRegex::new(pattern).expect("same configuration as regex");
            assert!(
                haystacks
                    .iter()
                    .all(|haystack| capture.is_match(haystack) == regex.is_match(haystack)),
                "{pattern}"
            );
            let mut captures = Captures::default();
            for (index, haystack) in haystacks.iter().enumerate() {
                let expected = regex.captures(haystack);
                assert_eq!(
                    captures.read((index / 3) as u32, &capture, haystack, &arena),
                    expected.is_some(),
                    "{pattern} on {haystack:?}"
                );
                for group in 0..=regex.captures_len() as u32 + 1 {
                    let expected = expected
                        .as_ref()
                        .and_then(|caps| caps.get(group as usize))
                        .map_or("", |m| m.as_str());
                    assert_eq!(
                        captures.get(group),
                        expected,
                        "{pattern} ${group} on {haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn unicode_classes_and_word_boundaries_compile() {
        for (pattern, matching, rejected) in [
            ("\\d+", "\u{663}", "abc"),
            ("\\w+", "\u{fc}", "!?"),
            ("\\s", "a\u{a0}b", "ab"),
            ("(?i)viagra", "Buy VIAGRA", "via gra"),
            ("\\p{Greek}", "\u{3a9}mega", "omega"),
            ("\\bword\\b", "a word.", "\u{fc}word"),
        ] {
            let capture = CaptureRegex::new(pattern).expect("unicode features enabled");
            assert!(capture.is_match(matching), "{pattern} on {matching:?}");
            assert!(!capture.is_match(rejected), "{pattern} on {rejected:?}");
        }
    }

    #[test]
    fn debug_prints_pattern_only() {
        for pattern in ["^([a-z]+)@(.+)$", "(?i)\"quoted\""] {
            assert_eq!(
                format!("{:?}", CaptureRegex::new(pattern).expect("valid pattern")),
                format!("{:?}", Regex::new(pattern).expect("valid pattern"))
            );
        }
    }

    #[test]
    fn errors_match_regex_errors() {
        for pattern in [
            "(",
            "[z-a]",
            "a{4294967295}",
            "\\p{Unknown}",
            "(?P<n>a)(?P<n>b)",
            "\\w{10000}{10000}",
        ] {
            let expected = format!(
                "Invalid regular expression {:?}: {}",
                pattern,
                Regex::new(pattern).expect_err("invalid pattern")
            );
            assert_eq!(
                CaptureRegex::new(pattern).err(),
                Some(expected),
                "{pattern}"
            );
        }
    }
}
