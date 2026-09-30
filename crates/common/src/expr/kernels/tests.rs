/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use bumpalo::Bump;
use std::{fmt::Write, ptr};

const ASCII_FRAGMENTS: &[&str] = &[
    "a",
    "b",
    "e",
    "k",
    "s",
    "z",
    "A",
    "B",
    "E",
    "K",
    "S",
    "Z",
    "i",
    "I",
    "0",
    "7",
    " ",
    " ",
    "\t",
    "\n",
    "\r\n",
    "\x0B",
    "\x0C",
    "\x1C",
    "\x1F",
    "\x00",
    "\x7F",
    ".",
    "@",
    "\"",
    "\\",
    ",",
    ":",
    "-",
    "_",
    "!",
    "?",
    "hello",
    "World",
    "SPAM",
    "Kind",
    "is",
    "undeliverable",
    "info@example.com",
];

const UNICODE_FRAGMENTS: &[&str] = &[
    "é",
    "É",
    "ü",
    "ß",
    "ẞ",
    "Ÿ",
    "Σ",
    "σ",
    "ς",
    "ΑΣ",
    "αΣ",
    "Σα",
    "ΐ",
    "İ",
    "ı",
    "\u{212A}",
    "\u{2126}",
    "\u{212B}",
    "ﬃ",
    "ŉ",
    "ǰ",
    "😀",
    "\u{85}",
    "\u{A0}",
    "\u{1680}",
    "\u{2000}",
    "\u{2028}",
    "\u{3000}",
    "\u{200B}",
    "\u{307}",
    "\u{345}",
    "ǅ",
    "Ⓐ",
    "ª",
    "Ɐ",
    "中",
    "Ж",
    "١",
    "²",
    "Ⅻ",
    "\u{10400}",
    "\u{1E900}",
    "\u{10FFFF}",
    "straße",
    "STRASSE",
    "İstanbul",
    "ΟΔΥΣΣΕΥΣ",
    "\u{212A}elvin",
];

const FIXED_NEEDLES: &[&str] = &[
    "", "k", "K", "i", "I", "ki", "sk", "kelvin", "\u{212A}", "İ", "i\u{307}", "ß", "ss", "σ", "ς",
    "Σ", "é", "É", "straße", "STRASSE", "spam", "world", " ", "@", "ΑΣ", "\u{2126}",
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
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items
            .get(self.below(items.len()))
            .copied()
            .unwrap_or_default()
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

fn random_text(rng: &mut Rng, target_len: usize, unicode_percent: usize) -> String {
    let mut text = String::with_capacity(target_len + 16);
    while text.len() < target_len {
        let fragments = if rng.chance(unicode_percent) {
            UNICODE_FRAGMENTS
        } else {
            ASCII_FRAGMENTS
        };
        text.push_str(rng.pick(fragments));
    }
    text
}

fn samples() -> Vec<String> {
    let mut rng = Rng(0x5EED_0001);
    let mut samples = Vec::new();
    for target_len in (0..300).step_by(3) {
        for unicode_percent in [0, 3, 60] {
            samples.push(random_text(&mut rng, target_len, unicode_percent));
        }
    }
    for prefix_len in [180, 190, 191, 192, 193, 200, 383, 384, 385] {
        for fragment in ["é", "Σ", "İ", "\u{212A}", "😀", "\u{2028}", "\u{85}", "ﬃ"] {
            for filler in ["a", "A", " "] {
                samples.push(format!("{}{fragment}{}", filler.repeat(prefix_len), filler));
            }
        }
    }
    for fragment in UNICODE_FRAGMENTS {
        samples.push(fragment.repeat(97));
        samples.push(format!("{} {fragment}", "Word ".repeat(40)));
    }
    for unicode_percent in [0, 3, 60] {
        samples.push(random_text(&mut rng, 20_000, unicode_percent));
    }
    let variants = samples
        .iter()
        .step_by(3)
        .flat_map(|text| [text.to_lowercase(), text.to_uppercase()])
        .collect::<Vec<_>>();
    samples.extend(variants);
    samples
}

const BOUNDARY_FILLERS: &[&str] = &["a", "A", "7", " ", "é", "É", "ß", "σ", "中"];
const BOUNDARY_FRAGMENTS: &[&str] = &[
    "A", "a", "7", " ", "é", "É", "Σ", "ǅ", "\u{212A}", "😀", "\u{2028}", "ﬃ",
];
const BOUNDARY_POSITIONS: &[usize] = &[
    0, 1, 14, 15, 16, 17, 31, 32, 62, 63, 64, 65, 190, 191, 192, 193, 206, 207, 208, 209, 383, 384,
    385,
];
const BOUNDARY_LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 32, 63, 64, 65, 191, 192, 193, 208, 400];

fn assemble(filler: &str, len: usize, inserts: &[(usize, &str)]) -> String {
    let mut text = String::with_capacity(len * filler.len() + 16);
    for index in 0..=len {
        for (_, fragment) in inserts.iter().filter(|(position, _)| *position == index) {
            text.push_str(fragment);
        }
        if index < len {
            text.push_str(filler);
        }
    }
    text
}

fn boundary_texts() -> Vec<String> {
    let mut texts = Vec::new();
    for filler in BOUNDARY_FILLERS {
        for &len in BOUNDARY_LENGTHS {
            texts.push(assemble(filler, len, &[]));
            for fragment in BOUNDARY_FRAGMENTS {
                for &position in BOUNDARY_POSITIONS
                    .iter()
                    .filter(|&&position| position <= len)
                {
                    texts.push(assemble(filler, len, &[(position, fragment)]));
                }
            }
        }
        for first in ["A", "a", "7"] {
            for second in ["é", "É", "Σ", "\u{212A}", "😀"] {
                for &position in &[0, 15, 16, 100, 191] {
                    for &later in BOUNDARY_POSITIONS.iter().filter(|&&later| later > position) {
                        texts.push(assemble(filler, 400, &[(position, first), (later, second)]));
                    }
                }
            }
        }
    }
    texts
}

fn scalar_values() -> impl Iterator<Item = char> {
    (0..=u32::from(char::MAX)).filter_map(char::from_u32)
}

fn ascii_strings(len: usize) -> impl Iterator<Item = String> {
    (0..128usize.pow(len as u32)).map(move |mut index| {
        let mut text = String::with_capacity(len);
        for _ in 0..len {
            text.push(char::from((index % 128) as u8));
            index /= 128;
        }
        text
    })
}

fn random_slice<'a>(rng: &mut Rng, text: &'a str, max_chars: usize) -> &'a str {
    let boundaries = text
        .char_indices()
        .map(|(index, _)| index)
        .chain([text.len()])
        .collect::<Vec<_>>();
    let start = rng.below(boundaries.len());
    let end = (start + rng.below(max_chars + 1)).min(boundaries.len() - 1);
    match (boundaries.get(start), boundaries.get(end)) {
        (Some(&start), Some(&end)) => text.get(start..end).unwrap_or_default(),
        _ => "",
    }
}

fn scramble_case(rng: &mut Rng, text: &str) -> String {
    match rng.below(4) {
        0 => text.to_lowercase(),
        1 => text.to_uppercase(),
        2 => text
            .chars()
            .map(|c| {
                if rng.chance(50) {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
        _ => text.to_string(),
    }
}

fn describe(text: &str) -> String {
    let preview = text.chars().take(64).collect::<String>();
    format!("{preview:?} (len {})", text.len())
}

mod reference {
    pub fn count_whitespace(text: &str) -> usize {
        text.chars().filter(|c| c.is_whitespace()).count()
    }

    pub fn count_uppercase(text: &str) -> usize {
        text.chars()
            .filter(|c| c.is_alphabetic() && c.is_uppercase())
            .count()
    }

    pub fn count_lowercase(text: &str) -> usize {
        text.chars()
            .filter(|c| c.is_alphabetic() && c.is_lowercase())
            .count()
    }

    pub fn is_uppercase(text: &str) -> bool {
        text.chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_uppercase())
    }

    pub fn is_lowercase(text: &str) -> bool {
        text.chars()
            .filter(|c| c.is_alphabetic())
            .all(|c| c.is_lowercase())
    }

    pub fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
        haystack.to_lowercase().contains(&needle.to_lowercase())
    }

    pub fn split_words(text: &str) -> Vec<&str> {
        text.split_whitespace()
            .filter(|word| word.chars().all(|c| c.is_alphanumeric()))
            .collect()
    }

    pub fn substring(text: &str, start: usize, len: usize) -> String {
        text.chars().skip(start).take(len).collect()
    }
}

fn check_case(text: &str, arena: &mut Bump) {
    arena.reset();
    let expected = text.to_lowercase();
    let lower = to_lowercase(text, arena);
    assert_eq!(lower, expected, "to_lowercase {}", describe(text));
    assert_eq!(
        ptr::eq(lower, text),
        expected == text,
        "to_lowercase borrow {}",
        describe(text)
    );
    let expected = text.to_uppercase();
    let upper = to_uppercase(text, arena);
    assert_eq!(upper, expected, "to_uppercase {}", describe(text));
    assert_eq!(
        ptr::eq(upper, text),
        expected == text,
        "to_uppercase borrow {}",
        describe(text)
    );
}

fn check_counts(text: &str) {
    let context = || describe(text);
    assert_eq!(
        count_whitespace(text),
        reference::count_whitespace(text),
        "{}",
        context()
    );
    assert_eq!(
        count_uppercase(text),
        reference::count_uppercase(text),
        "{}",
        context()
    );
    assert_eq!(
        count_lowercase(text),
        reference::count_lowercase(text),
        "{}",
        context()
    );
    assert_eq!(count_chars(text), text.chars().count(), "{}", context());
    assert_eq!(
        has_digits(text),
        text.chars().any(|c| c.is_ascii_digit()),
        "{}",
        context()
    );
    assert_eq!(
        is_uppercase(text),
        reference::is_uppercase(text),
        "{}",
        context()
    );
    assert_eq!(
        is_lowercase(text),
        reference::is_lowercase(text),
        "{}",
        context()
    );
}

fn check_ignore_case(haystack: &str, needle: &str) {
    let expected = reference::contains_ignore_case(haystack, needle);
    assert_eq!(
        contains_ignore_case(haystack, needle),
        expected,
        "contains_ignore_case {} {needle:?}",
        describe(haystack)
    );
    assert_eq!(
        IgnoreCaseNeedle::new(needle).contains(haystack),
        expected,
        "IgnoreCaseNeedle {} {needle:?}",
        describe(haystack)
    );
}

fn check_const_needle(haystack: &str, needle: &str) {
    let prebuilt = ConstNeedle::new(needle);
    let context = || format!("{} {needle:?}", describe(haystack));
    assert_eq!(prebuilt.as_str(), needle);
    assert_eq!(
        prebuilt.contains(haystack),
        haystack.contains(needle),
        "{}",
        context()
    );
    assert_eq!(
        prebuilt.starts_with(haystack),
        haystack.starts_with(needle),
        "{}",
        context()
    );
    assert_eq!(
        prebuilt.ends_with(haystack),
        haystack.ends_with(needle),
        "{}",
        context()
    );
}

fn check_lossy(bytes: &[u8], arena: &mut Bump) {
    arena.reset();
    let actual = utf8_lossy(bytes, arena);
    assert_eq!(actual, String::from_utf8_lossy(bytes), "{bytes:x?}");
    assert_eq!(
        ptr::eq(actual.as_bytes(), bytes),
        std::str::from_utf8(bytes).is_ok(),
        "utf8_lossy borrow {bytes:x?}"
    );
}

fn check_words(text: &str) {
    assert_eq!(
        split_words(text).collect::<Vec<_>>(),
        reference::split_words(text),
        "split_words {}",
        describe(text)
    );
}

fn check_substring(text: &str, start: usize, len: usize) {
    assert_eq!(
        substring(text, start, len),
        reference::substring(text, start, len),
        "substring {} start {start} len {len}",
        describe(text)
    );
}

#[test]
fn case_matches_std() {
    let mut arena = Bump::new();
    for text in samples() {
        check_case(&text, &mut arena);
    }
    for text in ascii_strings(2) {
        check_case(&text, &mut arena);
    }
    let mut buffer = [0u8; 4];
    let mut text = String::with_capacity(32);
    for c in scalar_values() {
        check_case(c.encode_utf8(&mut buffer), &mut arena);
        for [prefix, suffix] in [["xy", "Σ z"], ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Σ"]] {
            text.clear();
            text.push_str(prefix);
            text.push(c);
            text.push_str(suffix);
            check_case(&text, &mut arena);
        }
    }
}

#[test]
fn case_matches_std_across_boundaries() {
    let mut arena = Bump::new();
    for text in boundary_texts() {
        check_case(&text, &mut arena);
    }
}

#[test]
fn only_kelvin_and_dotted_capital_i_lowercase_to_ascii() {
    let joiners = scalar_values()
        .filter(|c| !c.is_ascii() && c.to_lowercase().any(|lower| lower.is_ascii()))
        .collect::<Vec<_>>();
    assert_eq!(joiners, ['\u{130}', '\u{212A}']);
}

#[test]
fn counts_match_reference() {
    for text in samples() {
        check_counts(&text);
    }
    for text in ascii_strings(2) {
        check_counts(&text);
    }
    let mut buffer = [0u8; 4];
    for c in scalar_values() {
        check_counts(c.encode_utf8(&mut buffer));
    }
    for fragment in UNICODE_FRAGMENTS.iter().chain(ASCII_FRAGMENTS) {
        for times in [1, 63, 64, 65, 191, 192, 193, 255, 256, 400] {
            check_counts(&fragment.repeat(times));
        }
    }
}

#[test]
fn counts_match_reference_across_boundaries() {
    for text in boundary_texts() {
        check_counts(&text);
    }
}

#[test]
fn hex_encode_matches_reference() {
    let mut rng = Rng(0x5EED_0007);
    let mut arena = Bump::new();
    for len in 0..300 {
        arena.reset();
        let bytes = rng.bytes(len);
        let mut expected = String::with_capacity(len * 2);
        for byte in &bytes {
            let _ = write!(expected, "{byte:02x}");
        }
        assert_eq!(hex_encode(&bytes, &arena), expected);
    }
}

#[test]
fn utf8_lossy_matches_std() {
    const INVALID: &[&[u8]] = &[
        b"\x80",
        b"\xC0\x80",
        b"\xC3",
        b"\xE2\x84",
        b"\xED\xA0\x80",
        b"\xF0\x80\x80\x80",
        b"\xF0\x9F\x98",
        b"\xF4\x90\x80\x80",
        b"\xFF",
        b"\xE9",
    ];
    let mut rng = Rng(0x5EED_0008);
    let mut arena = Bump::new();
    for text in samples().iter().step_by(3) {
        let bytes = text.as_bytes();
        check_lossy(bytes, &mut arena);
        let mut corrupted = bytes.to_vec();
        let position = rng.below(corrupted.len() + 1);
        let insertion = INVALID
            .get(rng.below(INVALID.len()))
            .copied()
            .unwrap_or_default();
        corrupted.splice(position..position, insertion.iter().copied());
        check_lossy(&corrupted, &mut arena);
        check_lossy(
            bytes.get(..rng.below(bytes.len() + 1)).unwrap_or_default(),
            &mut arena,
        );
    }
    for len in 0..300 {
        let bytes = rng.bytes(len);
        check_lossy(&bytes, &mut arena);
        let latin1 = bytes.iter().map(|&b| b | 0x40).collect::<Vec<_>>();
        check_lossy(&latin1, &mut arena);
    }
}

#[test]
fn utf8_lossy_matches_std_near_simd_threshold() {
    let mut arena = Bump::new();
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            check_lossy(&[first, second], &mut arena);
        }
    }
    for text in boundary_texts().iter().step_by(7) {
        let bytes = text.as_bytes();
        for len in [15, 16, 17, 62, 63, 64, 65] {
            let prefix = bytes.get(..len).unwrap_or(bytes);
            check_lossy(prefix, &mut arena);
            let mut corrupted = prefix.to_vec();
            corrupted.push(0xC3);
            check_lossy(&corrupted, &mut arena);
        }
    }
}

#[test]
fn ignore_case_matches_reference() {
    let mut rng = Rng(0x5EED_0002);
    for haystack in samples().iter().step_by(2) {
        for needle in FIXED_NEEDLES {
            check_ignore_case(haystack, needle);
        }
        for _ in 0..4 {
            let slice = random_slice(&mut rng, haystack, 12);
            check_ignore_case(haystack, &scramble_case(&mut rng, slice));
        }
    }
    let mut haystack = String::with_capacity(16);
    for c in scalar_values() {
        haystack.clear();
        haystack.push('x');
        haystack.push(c);
        haystack.push('y');
        for needle in ["k", "xky", "i"] {
            check_ignore_case(&haystack, needle);
        }
        check_ignore_case(&haystack, &c.to_uppercase().to_string());
    }
}

const DENSE_EDGE_NEEDLE_LEN: usize = 65;

fn repeat_to(pattern: &str, len: usize) -> String {
    pattern.chars().cycle().take(len).collect()
}

fn edge_positions(edge: usize, needle_len: usize) -> Vec<usize> {
    if needle_len <= DENSE_EDGE_NEEDLE_LEN {
        (edge.saturating_sub(needle_len + 1)..=edge + 1).collect()
    } else {
        [needle_len + 1, needle_len, needle_len - 1, 1, 0]
            .into_iter()
            .map(|back| edge.saturating_sub(back))
            .chain([edge + 1])
            .collect()
    }
}

#[test]
fn ignore_case_matches_reference_across_windows() {
    let mut rng = Rng(0x5EED_0009);
    let needles = [
        "x".to_string(),
        "Viagra".to_string(),
        "x-mailer: phpmailer".to_string(),
        repeat_to("Ab", 64),
        repeat_to("Ab", 65),
        repeat_to("Ab", IgnoreCaseNeedle::SHORT_WINDOW_LEN / 2 + 1),
        repeat_to("Ab", IgnoreCaseNeedle::MAX_WINDOW_NEEDLE_LEN),
        repeat_to("Ab", IgnoreCaseNeedle::MAX_WINDOW_NEEDLE_LEN + 1),
    ];
    for needle in &needles {
        for haystack_len in [
            IgnoreCaseNeedle::LONG_HAYSTACK_LEN - 1,
            IgnoreCaseNeedle::LONG_HAYSTACK_LEN,
            IgnoreCaseNeedle::SHORT_WINDOW_LEN,
            IgnoreCaseNeedle::SHORT_WINDOW_LEN + 1,
            IgnoreCaseNeedle::WINDOW_LEN + 1,
            2 * IgnoreCaseNeedle::WINDOW_LEN + 17,
        ] {
            if needle.len() > haystack_len {
                continue;
            }
            let filler = random_text(&mut rng, haystack_len, 0).replace(
                |c: char| {
                    c.eq_ignore_ascii_case(&'x')
                        || c.eq_ignore_ascii_case(&'v')
                        || c.eq_ignore_ascii_case(&'a')
                },
                ".",
            );
            let filler = filler.get(..haystack_len).unwrap_or(&filler);
            check_ignore_case(filler, needle);
            let window = if haystack_len <= IgnoreCaseNeedle::SHORT_WINDOW_LEN {
                IgnoreCaseNeedle::SHORT_WINDOW_LEN
            } else {
                IgnoreCaseNeedle::WINDOW_LEN
            };
            let step = window.saturating_sub(needle.len() - 1).max(1);
            let mut boundary = 0;
            while boundary <= haystack_len {
                for edge in [boundary, boundary + window] {
                    for position in edge_positions(edge, needle.len()) {
                        let Some((head, tail)) = filler.split_at_checked(position) else {
                            continue;
                        };
                        let Some(tail) = tail.get(needle.len()..) else {
                            continue;
                        };
                        let haystack = format!("{head}{}{tail}", scramble_case(&mut rng, needle));
                        check_ignore_case(&haystack, needle);
                        let split = format!("{head}#{}{tail}", needle.get(1..).unwrap_or_default());
                        check_ignore_case(&split, needle);
                    }
                }
                boundary += step;
            }
        }
    }
}

#[test]
fn ignore_case_long_needles_match_reference() {
    for (haystack_len, needle_len) in [
        (IgnoreCaseNeedle::LONG_HAYSTACK_LEN - 1, 2),
        (IgnoreCaseNeedle::LONG_HAYSTACK_LEN - 1, 100),
        (IgnoreCaseNeedle::LONG_HAYSTACK_LEN - 1, 200),
        (IgnoreCaseNeedle::LONG_HAYSTACK_LEN, 64),
        (IgnoreCaseNeedle::LONG_HAYSTACK_LEN, 65),
        (IgnoreCaseNeedle::SHORT_WINDOW_LEN, 100),
        (
            IgnoreCaseNeedle::SHORT_WINDOW_LEN,
            IgnoreCaseNeedle::SHORT_WINDOW_LEN,
        ),
        (IgnoreCaseNeedle::SHORT_WINDOW_LEN + 1, 1000),
        (
            IgnoreCaseNeedle::WINDOW_LEN + 1,
            IgnoreCaseNeedle::MAX_WINDOW_NEEDLE_LEN,
        ),
        (
            4 * IgnoreCaseNeedle::WINDOW_LEN,
            IgnoreCaseNeedle::MAX_WINDOW_NEEDLE_LEN + 1,
        ),
        (64 * 1024, 10_001),
    ] {
        let filler = "|".repeat(haystack_len);
        let needle = format!("{}e", "|".repeat(needle_len - 1));
        let kelvin_needle = format!("{}k", "|".repeat(needle_len - 1));
        let hit = format!("{}E", "|".repeat(haystack_len - 1));
        let kelvin = format!("{}\u{212A}", "|".repeat(haystack_len - 1));
        for (haystack, needle) in [
            (&filler, &needle),
            (&hit, &needle),
            (&hit, &needle.to_ascii_uppercase()),
            (&filler, &kelvin_needle),
            (&kelvin, &kelvin_needle),
            (&kelvin, &needle),
        ] {
            check_ignore_case(haystack, needle);
        }
    }
}

#[test]
fn ignore_case_long_haystacks_fall_back_on_lowering_chars() {
    let filler = ".".repeat(IgnoreCaseNeedle::WINDOW_LEN + 100);
    for (inserted, needle) in [
        ("\u{212A}", "k"),
        ("\u{212A}elvin", "kelvin"),
        ("x\u{212A}y", "xky"),
        ("\u{130}", "i"),
        ("\u{130}stanbul", "istanbul"),
        ("\u{130}", "i\u{307}"),
    ] {
        for position in [
            0,
            200,
            IgnoreCaseNeedle::SHORT_WINDOW_LEN,
            IgnoreCaseNeedle::WINDOW_LEN - 2,
        ] {
            let (head, tail) = filler.split_at(position);
            let haystack = format!("{head}{inserted}{tail}");
            check_ignore_case(&haystack, needle);
            check_ignore_case(&haystack, &needle.to_uppercase());
        }
    }
}

#[test]
fn ignore_case_matches_reference_across_boundaries() {
    for haystack in boundary_texts().iter().step_by(3) {
        for needle in [
            "a", "k", "7a", "é", "É", "σ", "ς", "Σ", "ǆ", "aé", "ﬃ", "ffi", "😀",
        ] {
            check_ignore_case(haystack, needle);
        }
    }
}

#[test]
fn const_needle_matches_std() {
    let mut rng = Rng(0x5EED_0003);
    for haystack in samples().iter().step_by(4) {
        for needle in FIXED_NEEDLES {
            check_const_needle(haystack, needle);
        }
        for _ in 0..4 {
            let slice = random_slice(&mut rng, haystack, 40);
            check_const_needle(haystack, slice);
            check_const_needle(haystack, &format!("{slice}#"));
        }
    }
}

#[test]
fn const_set_matches_linear_scan() {
    let mut rng = Rng(0x5EED_0004);
    for size in [0, 1, 2, 3, 5, 8, 9, 14, 15, 16, 17, 33, 100] {
        for unicode_percent in [0, 3, 60] {
            let mut items = (0..size)
                .map(|_| {
                    let len = rng.below(20);
                    random_text(&mut rng, len, unicode_percent)
                })
                .collect::<Vec<_>>();
            if let Some(first) = items.first().cloned() {
                items.push(first);
            }
            let set = ConstSet::new(&items);
            let mut probes = items.clone();
            for item in &items {
                probes.push(format!("{item}!"));
                let mut chars = item.chars();
                chars.next_back();
                probes.push(chars.as_str().to_string());
            }
            for _ in 0..40 {
                let len = rng.below(20);
                probes.push(random_text(&mut rng, len, unicode_percent));
            }
            probes.push(String::new());
            for probe in &probes {
                assert_eq!(
                    set.contains(probe),
                    items.contains(probe),
                    "size {size} probe {}",
                    describe(probe)
                );
            }
        }
    }
}

#[test]
fn split_words_matches_reference() {
    for text in samples() {
        check_words(&text);
    }
    let mut text = String::with_capacity(32);
    for c in scalar_values() {
        for [prefix, suffix] in [["a", "b"], ["ab ", " cd"], ["x\u{2028}", "9\u{3000}y z"]] {
            text.clear();
            text.push_str(prefix);
            text.push(c);
            text.push_str(suffix);
            check_words(&text);
        }
    }
    for text in ascii_strings(2) {
        for third in ["a", " ", "\x0B", "-", "Z"] {
            check_words(&format!("{text}{third}"));
        }
    }
}

#[test]
fn substring_matches_reference() {
    let mut rng = Rng(0x5EED_0005);
    for text in samples() {
        let chars = text.chars().count();
        for start in [
            0,
            1,
            chars / 2,
            chars.saturating_sub(1),
            chars,
            chars + 1,
            rng.below(chars + 2),
            usize::MAX,
        ] {
            for len in [0, 1, 2, 5, rng.below(chars + 2), chars, usize::MAX] {
                check_substring(&text, start, len);
            }
        }
    }
    let mut text = String::with_capacity(16);
    for c in scalar_values() {
        text.clear();
        text.push('a');
        text.push(c);
        text.push('b');
        for (start, len) in [
            (0, 1),
            (0, 2),
            (1, 1),
            (1, 2),
            (2, 1),
            (3, 1),
            (0, usize::MAX),
        ] {
            check_substring(&text, start, len);
        }
    }
}
