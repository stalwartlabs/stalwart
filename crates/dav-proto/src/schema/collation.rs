/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Namespace, request::TextMatch};
use std::{borrow::Cow, convert::identity};
use unicode_normalization::UnicodeNormalization;

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

const GREEK_TITLECASE_OFFSET: u32 = 8;

trait SimpleTitlecase {
    fn simple_titlecase(self) -> Self;
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
                    Cow::Owned(text.chars().map(char::simple_titlecase).nfkd().collect())
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

    fn matches(&self, haystack: &[u8], needle: &[u8], fold: impl Fn(u8) -> u8) -> bool {
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
            MatchType::Contains => {
                needle.is_empty()
                    || haystack
                        .windows(needle.len())
                        .any(|window| window.iter().zip(needle).all(is_equal))
            }
        }
    }
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
        let needle = self.needle.as_bytes();
        match self.collation {
            Collation::Octet => self.match_type.matches(text.as_bytes(), needle, identity),
            Collation::AsciiCasemap => self
                .match_type
                .matches(text.as_bytes(), needle, |ch| ch.to_ascii_uppercase()),
            Collation::UnicodeCasemap if text.is_ascii() => {
                self.needle.is_ascii()
                    && self
                        .match_type
                        .matches(text.as_bytes(), needle, |ch| ch.to_ascii_uppercase())
            }
            Collation::UnicodeCasemap => self.match_type.matches(
                Collation::UnicodeCasemap.prepare(text).as_bytes(),
                needle,
                identity,
            ),
        }
    }

    pub fn is_match_any<T: AsRef<str>>(&self, mut values: impl Iterator<Item = T>) -> bool {
        values.any(|value| self.is_match(value.as_ref())) != self.negate
    }
}

impl SimpleTitlecase for char {
    fn simple_titlecase(self) -> Self {
        match self {
            '\u{01C4}'..='\u{01C6}' => '\u{01C5}',
            '\u{01C7}'..='\u{01C9}' => '\u{01C8}',
            '\u{01CA}'..='\u{01CC}' => '\u{01CB}',
            '\u{01F1}'..='\u{01F3}' => '\u{01F2}',
            '\u{10D0}'..='\u{10FA}' | '\u{10FD}'..='\u{10FF}' => self,
            '\u{1F80}'..='\u{1F87}' | '\u{1F90}'..='\u{1F97}' | '\u{1FA0}'..='\u{1FA7}' => {
                char::from_u32(u32::from(self) + GREEK_TITLECASE_OFFSET).unwrap_or(self)
            }
            '\u{1FB3}' => '\u{1FBC}',
            '\u{1FC3}' => '\u{1FCC}',
            '\u{1FF3}' => '\u{1FFC}',
            _ => {
                let mut upper = self.to_uppercase();
                match (upper.next(), upper.next()) {
                    (Some(upper), None) => upper,
                    _ => self,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_match(value: &str, match_type: MatchType, collation: Collation) -> TextMatch {
        TextMatch::new(value.to_string(), match_type, collation, false)
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
