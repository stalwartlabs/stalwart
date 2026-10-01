/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Namespace, request::TextMatch};
use std::{borrow::Cow, convert::identity};
use types::collation::unicode_casemap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum Collation {
    AsciiCasemap,
    Octet,
    UnicodeCasemap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum MatchType {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

impl Collation {
    pub fn default_for(namespace: Namespace) -> Self {
        if namespace == Namespace::CardDav {
            Collation::UnicodeCasemap
        } else {
            Collation::AsciiCasemap
        }
    }

    pub fn try_parse(s: &str) -> Option<Self> {
        hashify::fnc_map!(s.as_bytes(),
            "i;ascii-casemap" => Some(Collation::AsciiCasemap),
            "i;octet" => Some(Collation::Octet),
            "i;unicode-casemap" => Some(Collation::UnicodeCasemap),
            _ => None,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Collation::AsciiCasemap => "i;ascii-casemap",
            Collation::Octet => "i;octet",
            Collation::UnicodeCasemap => "i;unicode-casemap",
        }
    }

    fn prepare<'x>(&self, text: &'x str) -> Cow<'x, str> {
        match self {
            Collation::Octet => Cow::Borrowed(text),
            Collation::AsciiCasemap => {
                if text.bytes().any(|ch| ch.is_ascii_lowercase()) {
                    Cow::Owned(text.to_ascii_uppercase())
                } else {
                    Cow::Borrowed(text)
                }
            }
            Collation::UnicodeCasemap => {
                if text.is_ascii() {
                    Collation::AsciiCasemap.prepare(text)
                } else {
                    let mut folded = String::with_capacity(text.len());
                    unicode_casemap(text, &mut folded);
                    Cow::Owned(folded)
                }
            }
        }
    }
}

impl MatchType {
    pub fn try_parse(s: &str) -> Option<Self> {
        hashify::fnc_map!(s.as_bytes(),
            "equals" => Some(MatchType::Equals),
            "contains" => Some(MatchType::Contains),
            "starts-with" => Some(MatchType::StartsWith),
            "ends-with" => Some(MatchType::EndsWith),
            _ => None,
        )
    }

    fn matches(&self, haystack: &[u8], needle: &[u8], fold: Fold) -> bool {
        match fold {
            Fold::Identity => self.matches_with(haystack, needle, identity, |haystack, needle| {
                memchr::memmem::find(haystack, needle).is_some()
            }),
            Fold::AsciiUppercase => self.matches_with(
                haystack,
                needle,
                |byte| byte.to_ascii_uppercase(),
                ascii_uppercase_contains,
            ),
        }
    }

    fn matches_with(
        &self,
        haystack: &[u8],
        needle: &[u8],
        fold: impl Fn(u8) -> u8,
        prefiltered_contains: impl Fn(&[u8], &[u8]) -> bool,
    ) -> bool {
        let is_equal = |(h, n): (&u8, &u8)| fold(*h) == *n;
        match self {
            MatchType::Equals => {
                haystack.len() == needle.len() && haystack.iter().zip(needle).all(is_equal)
            }
            MatchType::StartsWith => {
                haystack.len() >= needle.len() && haystack.iter().zip(needle).all(is_equal)
            }
            MatchType::EndsWith => {
                haystack.len() >= needle.len()
                    && haystack.iter().rev().zip(needle.iter().rev()).all(is_equal)
            }
            MatchType::Contains if needle.is_empty() => true,
            MatchType::Contains if haystack.len() < PREFILTER_MIN_LEN => haystack
                .windows(needle.len())
                .any(|window| window.iter().zip(needle).all(is_equal)),
            MatchType::Contains => prefiltered_contains(haystack, needle),
        }
    }
}

const PREFILTER_MIN_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fold {
    Identity,
    AsciiUppercase,
}

fn ascii_uppercase_contains(haystack: &[u8], needle: &[u8]) -> bool {
    let Some(first) = needle.first() else {
        return true;
    };
    memchr::memchr2_iter(
        first.to_ascii_uppercase(),
        first.to_ascii_lowercase(),
        haystack,
    )
    .any(|start| {
        haystack
            .get(start..start + needle.len())
            .is_some_and(|window| {
                window
                    .iter()
                    .zip(needle)
                    .all(|(h, n)| h.to_ascii_uppercase() == *n)
            })
    })
}

impl TextMatch {
    pub fn new(value: String, match_type: MatchType, collation: Collation, negate: bool) -> Self {
        TextMatch {
            needle: collation.prepare(&value).into_owned(),
            match_type,
            value,
            collation,
            negate,
        }
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.is_match_with(text, &mut String::new())
    }

    fn is_match_with(&self, text: &str, folded: &mut String) -> bool {
        let needle = self.needle.as_bytes();
        match self.collation {
            Collation::Octet => self
                .match_type
                .matches(text.as_bytes(), needle, Fold::Identity),
            Collation::AsciiCasemap => {
                self.match_type
                    .matches(text.as_bytes(), needle, Fold::AsciiUppercase)
            }
            Collation::UnicodeCasemap if text.is_ascii() => {
                self.needle.is_ascii()
                    && self
                        .match_type
                        .matches(text.as_bytes(), needle, Fold::AsciiUppercase)
            }
            Collation::UnicodeCasemap => {
                folded.clear();
                unicode_casemap(text, folded);
                self.match_type
                    .matches(folded.as_bytes(), needle, Fold::Identity)
            }
        }
    }

    pub fn is_match_any<T: AsRef<str>>(&self, mut values: impl Iterator<Item = T>) -> bool {
        let mut folded = String::new();
        values.any(|value| self.is_match_with(value.as_ref(), &mut folded)) != self.negate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_types_agree_with_a_window_scan() {
        fn reference(
            match_type: MatchType,
            haystack: &[u8],
            needle: &[u8],
            fold: impl Fn(u8) -> u8,
        ) -> bool {
            let is_equal = |(h, n): (&u8, &u8)| fold(*h) == *n;
            match match_type {
                MatchType::Equals => {
                    haystack.len() == needle.len() && haystack.iter().zip(needle).all(is_equal)
                }
                MatchType::StartsWith => {
                    haystack.len() >= needle.len() && haystack.iter().zip(needle).all(is_equal)
                }
                MatchType::EndsWith => {
                    haystack.len() >= needle.len()
                        && haystack.iter().rev().zip(needle.iter().rev()).all(is_equal)
                }
                MatchType::Contains => {
                    needle.is_empty()
                        || haystack
                            .windows(needle.len())
                            .any(|window| window.iter().zip(needle).all(is_equal))
                }
            }
        }

        let alphabet = b"aAbBzZ09 _-\xc3\xa9";
        let mut state = 0x2545_f491_u32;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as usize % bound
        };
        for _ in 0..20_000 {
            let haystack = (0..next(200))
                .map(|_| alphabet[next(alphabet.len())])
                .collect::<Vec<_>>();
            let needle = (0..next(6))
                .map(|_| alphabet[next(alphabet.len())])
                .collect::<Vec<_>>();
            let needle_upper = needle.to_ascii_uppercase();
            for match_type in [
                MatchType::Equals,
                MatchType::Contains,
                MatchType::StartsWith,
                MatchType::EndsWith,
            ] {
                assert_eq!(
                    match_type.matches(&haystack, &needle, Fold::Identity),
                    reference(match_type, &haystack, &needle, identity),
                    "{match_type:?} {haystack:?} {needle:?}"
                );
                for needle in [&needle, &needle_upper] {
                    assert_eq!(
                        match_type.matches(&haystack, needle, Fold::AsciiUppercase),
                        reference(match_type, &haystack, needle, |byte| byte
                            .to_ascii_uppercase()),
                        "{match_type:?} {haystack:?} {needle:?}"
                    );
                }
            }
        }
    }

    fn text_match(value: &str, match_type: MatchType, collation: Collation) -> TextMatch {
        TextMatch::new(value.to_string(), match_type, collation, false)
    }

    #[test]
    fn unicode_casemap_appends_the_prepared_form() {
        for text in [
            "",
            "abc",
            "Doe",
            "Straße",
            "ǆemal",
            "\u{fb01}le",
            "ᾀ",
            "ＡＢＣ",
            "\u{212a}",
        ] {
            let mut folded = String::from("prefix:");
            unicode_casemap(text, &mut folded);
            assert_eq!(
                folded,
                format!("prefix:{}", Collation::UnicodeCasemap.prepare(text)),
                "{text:?}"
            );
        }
    }

    #[test]
    fn octet_is_case_sensitive() {
        let tm = text_match("Doe", MatchType::Contains, Collation::Octet);
        assert!(tm.is_match("John Doe"));
        assert!(!tm.is_match("JOHN DOE"));
    }

    #[test]
    fn ascii_casemap_folds_ascii_only() {
        let tm = text_match("doe", MatchType::Contains, Collation::AsciiCasemap);
        assert!(tm.is_match("John DOE"));
        let tm = text_match("é", MatchType::Equals, Collation::AsciiCasemap);
        assert!(tm.is_match("é"));
        assert!(!tm.is_match("É"));
    }

    #[test]
    fn unicode_casemap_folds_case_and_compatibility_forms() {
        let tm = text_match("é", MatchType::Equals, Collation::UnicodeCasemap);
        assert!(tm.is_match("É"));
        assert!(tm.is_match("e\u{301}"));
        let tm = text_match("ÅNGSTRÖM", MatchType::StartsWith, Collation::UnicodeCasemap);
        assert!(tm.is_match("ångström units"));
        let tm = text_match("doe", MatchType::EndsWith, Collation::UnicodeCasemap);
        assert!(tm.is_match("Jane DOE"));
        assert!(!tm.is_match("Jane Doe Jr"));
        let tm = text_match("ö", MatchType::Contains, Collation::UnicodeCasemap);
        assert!(!tm.is_match("plain ascii"));
    }

    #[test]
    fn unicode_casemap_uses_simple_titlecase() {
        for (needle, haystack, expected) in [
            ("\u{01C6}", "\u{01C4}", true),
            ("\u{01C6}", "\u{01C5}", true),
            ("\u{01C6}", "D\u{017D}", false),
            ("\u{10D0}", "\u{10D0}", true),
            ("\u{10D0}", "\u{1C90}", false),
            ("\u{1FB3}", "\u{1FBC}", true),
            ("\u{1F80}", "\u{1F88}", true),
            ("\u{00DF}", "SS", false),
        ] {
            assert_eq!(
                text_match(needle, MatchType::Equals, Collation::UnicodeCasemap).is_match(haystack),
                expected,
                "{needle:?} {haystack:?}"
            );
        }
    }

    #[test]
    fn match_types() {
        for (match_type, haystack, expected) in [
            (MatchType::Equals, "smith", true),
            (MatchType::Equals, "smithy", false),
            (MatchType::StartsWith, "Smithson", true),
            (MatchType::StartsWith, "Goldsmith", false),
            (MatchType::EndsWith, "Goldsmith", true),
            (MatchType::EndsWith, "Smithson", false),
            (MatchType::Contains, "Goldsmithson", true),
            (MatchType::Contains, "smit", false),
        ] {
            assert_eq!(
                text_match("SMITH", match_type, Collation::AsciiCasemap).is_match(haystack),
                expected,
                "{match_type:?} {haystack}"
            );
        }
    }

    #[test]
    fn negation_applies_to_the_whole_value_set() {
        let tm = TextMatch::new(
            "PERSONAL".to_string(),
            MatchType::Contains,
            Collation::AsciiCasemap,
            true,
        );
        assert!(!tm.is_match_any(["WORK", "PERSONAL"].into_iter()));
        assert!(tm.is_match_any(["WORK"].into_iter()));
        assert!(tm.is_match_any(std::iter::empty::<&str>()));
    }
}
