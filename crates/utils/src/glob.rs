/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::text::{ConstNeedle, IgnoreCaseNeedle, lowercase};
use ahash::{AHashMap, AHashSet};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
    Matches(GlobPattern),
    All,
}

#[derive(Debug, Clone)]
pub struct GlobPattern {
    pattern: Vec<PatternChar>,
    to_lower: bool,
    literal: Option<Box<Literal>>,
}

#[derive(Debug, Clone)]
enum Literal {
    Contains(ConstNeedle),
    ContainsIgnoreCase(IgnoreCaseNeedle),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternChar {
    WildcardMany { num: usize, match_pos: usize },
    WildcardSingle { match_pos: usize },
    Char { char: char, match_pos: usize },
}

impl GlobPattern {
    pub fn compile(pattern: &str, to_lower: bool) -> Self {
        let mut chars = Vec::new();
        let mut is_escaped = false;
        let mut str = pattern.chars().peekable();

        while let Some(char) = str.next() {
            match char {
                '*' if !is_escaped => {
                    let mut num = 1;
                    while let Some('*') = str.peek() {
                        num += 1;
                        str.next();
                    }
                    chars.push(PatternChar::WildcardMany { num, match_pos: 0 });
                }
                '?' if !is_escaped => {
                    chars.push(PatternChar::WildcardSingle { match_pos: 0 });
                }
                '\\' if !is_escaped => {
                    is_escaped = true;
                    continue;
                }
                _ => {
                    if is_escaped {
                        is_escaped = false;
                    }
                    if to_lower && char.is_uppercase() {
                        for char in char.to_lowercase() {
                            chars.push(PatternChar::Char { char, match_pos: 0 });
                        }
                    } else {
                        chars.push(PatternChar::Char { char, match_pos: 0 });
                    }
                }
            }
        }

        GlobPattern {
            literal: Literal::classify(&chars, to_lower).map(Box::new),
            pattern: chars,
            to_lower,
        }
    }

    pub fn try_compile(pattern: &str, to_lower: bool) -> Result<Self, String> {
        // Detect if the key is a glob pattern
        let mut last_ch = '\0';
        let mut has_escape = false;
        let mut is_glob = false;
        for ch in pattern.chars() {
            match ch {
                '\\' => {
                    has_escape = true;
                }
                '*' | '?' if last_ch != '\\' => {
                    is_glob = true;
                }
                _ => {}
            }

            last_ch = ch;
        }

        if is_glob {
            Ok(GlobPattern::compile(pattern, to_lower))
        } else {
            Err(if has_escape {
                pattern.replace('\\', "")
            } else {
                pattern.to_string()
            })
        }
    }

    pub fn matches(&self, value: &str) -> bool {
        match self.literal.as_deref() {
            Some(Literal::Contains(needle)) => needle.contains(value),
            Some(Literal::ContainsIgnoreCase(needle)) => needle.contains(value),
            None if !self.to_lower => self.matches_chars(value, identity),
            None if value.is_ascii() => self.matches_chars(value, char::to_ascii_lowercase),
            None => self.matches_chars(&lowercase(value), identity),
        }
    }

    // Credits: Algorithm ported from https://research.swtch.com/glob
    fn matches_chars(&self, value: &str, fold: impl Fn(&char) -> char) -> bool {
        let mut px = 0;
        let mut nx = 0;
        let mut next_px = 0;
        let mut next_nx = 0;

        while px < self.pattern.len() || nx < value.len() {
            let next = value.get(nx..).and_then(|rest| rest.chars().next());
            match self.pattern.get(px) {
                Some(PatternChar::Char { char, .. }) => {
                    if let Some(next) = next.filter(|next| fold(next) == *char) {
                        px += 1;
                        nx += next.len_utf8();
                        continue;
                    }
                }
                Some(PatternChar::WildcardSingle { .. }) => {
                    if let Some(next) = next {
                        px += 1;
                        nx += next.len_utf8();
                        continue;
                    }
                }
                Some(PatternChar::WildcardMany { .. }) => {
                    next_px = px;
                    next_nx = nx + next.map_or(1, char::len_utf8);
                    px += 1;
                    continue;
                }
                None => (),
            }
            if 0 < next_nx && next_nx <= value.len() {
                px = next_px;
                nx = next_nx;
                continue;
            }
            return false;
        }
        true
    }
}

impl Literal {
    fn classify(pattern: &[PatternChar], to_lower: bool) -> Option<Self> {
        let [
            PatternChar::WildcardMany { .. },
            middle @ ..,
            PatternChar::WildcardMany { .. },
        ] = pattern
        else {
            return None;
        };
        let literal = middle
            .iter()
            .map(|item| match item {
                PatternChar::Char { char, .. } => Some(*char),
                _ => None,
            })
            .collect::<Option<String>>()?;
        if !to_lower {
            Some(Literal::Contains(ConstNeedle::new(&literal)))
        } else if literal.is_ascii() {
            Some(Literal::ContainsIgnoreCase(IgnoreCaseNeedle::new(&literal)))
        } else {
            None
        }
    }
}

impl PartialEq for GlobPattern {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.to_lower == other.to_lower
    }
}

impl Eq for GlobPattern {}

fn identity(char: &char) -> char {
    *char
}

#[derive(Debug, Clone, Default)]
pub struct GlobSet {
    entries: AHashSet<String>,
    patterns: Vec<GlobPattern>,
}

#[derive(Debug, Clone)]
pub struct GlobMap<V> {
    entries: AHashMap<String, V>,
    patterns: Vec<(GlobPattern, V)>,
}

impl GlobSet {
    pub fn new() -> Self {
        GlobSet::default()
    }

    pub fn insert_pattern(&mut self, pattern: &str) {
        match GlobPattern::try_compile(pattern, false) {
            Ok(glob) => {
                self.patterns.push(glob);
            }
            Err(entry) => {
                self.entries.insert(entry);
            }
        }
    }

    pub fn insert_entry(&mut self, entry: String) {
        self.entries.insert(entry);
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains(key) || self.patterns.iter().any(|pattern| pattern.matches(key))
    }
}

impl<V> GlobMap<V> {
    pub fn new() -> Self {
        GlobMap {
            entries: AHashMap::new(),
            patterns: Vec::new(),
        }
    }

    pub fn insert_pattern(&mut self, pattern: &str, value: V) {
        match GlobPattern::try_compile(pattern, false) {
            Ok(glob) => {
                self.patterns.push((glob, value));
            }
            Err(entry) => {
                self.entries.insert(entry, value);
            }
        }
    }

    pub fn insert_entry(&mut self, entry: String, value: V) {
        self.entries.insert(entry, value);
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.entries.get(key).or_else(|| {
            self.patterns
                .iter()
                .find_map(|(pattern, value)| pattern.matches(key).then_some(value))
        })
    }
}

impl<V> Default for GlobMap<V> {
    fn default() -> Self {
        GlobMap::new()
    }
}

impl MatchType {
    pub fn parse(value: &str) -> Self {
        if value == "*" {
            MatchType::All
        } else if let Some(value) = value.strip_suffix('*') {
            MatchType::StartsWith(value.to_string())
        } else if let Some(value) = value.strip_prefix('*') {
            MatchType::EndsWith(value.to_string())
        } else if value.contains('*') {
            MatchType::Matches(GlobPattern::compile(value, false))
        } else {
            MatchType::Equal(value.to_string())
        }
    }

    pub fn matches(&self, value: &str) -> bool {
        match self {
            MatchType::Equal(pattern) => value == pattern,
            MatchType::StartsWith(pattern) => value.starts_with(pattern),
            MatchType::EndsWith(pattern) => value.ends_with(pattern),
            MatchType::Matches(pattern) => pattern.matches(value),
            MatchType::All => true,
        }
    }
}

impl<'de> Deserialize<'de> for GlobPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GlobPattern::compile(
            <Cow<&str>>::deserialize(deserializer)?.as_ref(),
            true,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{GlobMap, GlobPattern, GlobSet, Literal, MatchType, PatternChar};

    const PATTERN_FRAGMENTS: &[&str] = &[
        "*", "*", "?", "a", "A", "k", "K", "i", "I", ".", "/", "-", "php", "PHP", "wp-", "..",
        "\\*", "\\?", "é", "É", "ß", "Σ", "σ", "ǅ", "\u{212A}", "İ", "中", "😀",
    ];
    const VALUE_FRAGMENTS: &[&str] = &[
        "a", "A", "b", "k", "K", "i", "I", ".", "/", "-", "*", "?", "php", "PHP", "Php", "wp-",
        "WP-", "..", "/..", "cgi-bin", "é", "É", "ß", "SS", "Σ", "σ", "ς", "ǅ", "ǆ", "\u{212A}",
        "İ", "i\u{307}", "中", "😀", " ",
    ];
    const BAN_PATTERNS: &[&str] = &[
        "*.php*",
        "*.cgi*",
        "*.asp*",
        "*/wp-*",
        "*/php*",
        "*/cgi-bin*",
        "*xmlrpc*",
        "*../*",
        "*/..*",
        "*joomla*",
        "*wordpress*",
        "*drupal*",
    ];
    const PATHS: &[&str] = &[
        "",
        "/",
        "/wp-login.php",
        "/WP-ADMIN/Setup-Config.PHP",
        "/wp-admin/x.php",
        "/.git/config",
        "/cgi-bin/test.cgi",
        "/jmap/unknown",
        "/a/../b",
        "/a/..",
        "/XMLRPC.php",
        "/Joomla/administrator/",
        "/sites/default/DRUPAL",
        "/\u{212A}elvin/.PHP",
        "/İndex.php",
        "/straße/x.asp",
        "/dav/cal/\u{212A}.ics",
    ];

    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound.max(1) as u64) as usize
        }

        fn join(&mut self, fragments: &[&str], max_len: usize) -> String {
            let len = self.below(max_len + 1);
            (0..len)
                .map(|_| fragments.get(self.below(fragments.len())).copied())
                .map(Option::unwrap_or_default)
                .collect()
        }
    }

    fn reference_matches(pattern: &GlobPattern, value: &str) -> bool {
        let value = if pattern.to_lower {
            value.to_lowercase().chars().collect::<Vec<_>>()
        } else {
            value.chars().collect::<Vec<_>>()
        };

        let mut px = 0;
        let mut nx = 0;
        let mut next_px = 0;
        let mut next_nx = 0;

        while px < pattern.pattern.len() || nx < value.len() {
            match pattern.pattern.get(px) {
                Some(PatternChar::Char { char, .. }) => {
                    if matches!(value.get(nx), Some(nc) if nc == char) {
                        px += 1;
                        nx += 1;
                        continue;
                    }
                }
                Some(PatternChar::WildcardSingle { .. }) if nx < value.len() => {
                    px += 1;
                    nx += 1;
                    continue;
                }
                Some(PatternChar::WildcardMany { .. }) => {
                    next_px = px;
                    next_nx = nx + 1;
                    px += 1;
                    continue;
                }
                _ => (),
            }
            if 0 < next_nx && next_nx <= value.len() {
                px = next_px;
                nx = next_nx;
                continue;
            }
            return false;
        }
        true
    }

    fn check(pattern: &str, value: &str) {
        for to_lower in [false, true] {
            let glob = GlobPattern::compile(pattern, to_lower);
            assert_eq!(
                glob.matches(value),
                reference_matches(&glob, value),
                "pattern {pattern:?} value {value:?} to_lower {to_lower}"
            );
        }
    }

    #[test]
    fn matches_reference_on_ban_patterns() {
        for pattern in BAN_PATTERNS {
            let glob = GlobPattern::compile(pattern, true);
            assert!(
                matches!(
                    glob.literal.as_deref(),
                    Some(Literal::ContainsIgnoreCase(_))
                ),
                "{pattern:?}"
            );
            for path in PATHS {
                check(pattern, path);
            }
        }
    }

    #[test]
    fn matches_reference_on_random_input() {
        let mut rng = Rng(0x5EED_0010);
        for _ in 0..4000 {
            let pattern = rng.join(PATTERN_FRAGMENTS, 6);
            for _ in 0..16 {
                check(&pattern, &rng.join(VALUE_FRAGMENTS, 10));
            }
            for path in PATHS {
                check(&pattern, path);
            }
        }
        for fragment in VALUE_FRAGMENTS.iter().chain(PATTERN_FRAGMENTS) {
            for pattern in [
                format!("*{fragment}*"),
                format!("{fragment}*"),
                format!("*{fragment}"),
                format!("?{fragment}?"),
                format!("*{fragment}*{fragment}*"),
            ] {
                for value in VALUE_FRAGMENTS {
                    check(&pattern, value);
                    check(&pattern, &format!("x{value}y"));
                    check(&pattern, &value.repeat(3));
                }
            }
        }
    }

    #[test]
    fn equality_ignores_the_compiled_literal() {
        assert_eq!(
            GlobPattern::compile("*.php*", true),
            GlobPattern::compile("*.PHP*", true)
        );
        assert_ne!(
            GlobPattern::compile("*.php*", true),
            GlobPattern::compile("*.php*", false)
        );
        assert_ne!(
            GlobPattern::compile("*.php*", false),
            GlobPattern::compile("*.PHP*", false)
        );
    }

    #[test]
    fn sets_and_maps_match_patterns() {
        let mut set = GlobSet::new();
        set.insert_pattern("*.exe*");
        set.insert_pattern("exact");
        assert!(set.contains("file.exe.zip"));
        assert!(set.contains("exact"));
        assert!(!set.contains("file.EXE"));
        let mut map = GlobMap::new();
        map.insert_pattern("*spam*", 1);
        map.insert_pattern("a?c", 2);
        assert_eq!(map.get("is-spam-here"), Some(&1));
        assert_eq!(map.get("abc"), Some(&2));
        assert_eq!(map.get("abcd"), None);
        assert!(MatchType::Matches(GlobPattern::compile("*/WP-*", true)).matches("/wp-admin"));
    }
}
