/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use bumpalo::Bump;
use std::{fmt::Write, ptr};

const FILLERS: &[&str] = &["a", "A", "7", " ", "é", "É", "ß", "σ", "中"];
const FRAGMENTS: &[&str] = &[
    "", "A", "a", "é", "É", "Σ", "ǅ", "İ", "\u{212A}", "😀", "\u{2028}", "ﬃ",
];
const LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 63, 64, 65, 191, 192, 193, 400];

fn scalar_values() -> impl Iterator<Item = char> {
    (0..=u32::from(char::MAX)).filter_map(char::from_u32)
}

fn boundary_texts() -> Vec<String> {
    let mut texts = Vec::new();
    for filler in FILLERS {
        for &len in LENGTHS {
            for fragment in FRAGMENTS {
                for position in [0, 1, len / 2, len.saturating_sub(1), len] {
                    let position = position.min(len);
                    texts.push(format!(
                        "{}{fragment}{}",
                        filler.repeat(position),
                        filler.repeat(len - position)
                    ));
                }
            }
        }
    }
    texts
}

fn check_case(text: &str, arena: &mut Bump) {
    arena.reset();
    let expected = text.to_lowercase();
    let lower = to_lowercase(text, arena);
    assert_eq!(lower, expected, "to_lowercase {text:?}");
    assert_eq!(
        ptr::eq(lower, text),
        expected == text,
        "to_lowercase borrow {text:?}"
    );
    let expected = text.to_uppercase();
    let upper = to_uppercase(text, arena);
    assert_eq!(upper, expected, "to_uppercase {text:?}");
    assert_eq!(
        ptr::eq(upper, text),
        expected == text,
        "to_uppercase borrow {text:?}"
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

#[test]
fn case_wrappers_match_std() {
    let mut arena = Bump::new();
    let mut text = String::with_capacity(32);
    for c in scalar_values() {
        for [prefix, suffix] in [["", ""], ["xy", "Σ z"], ["ABCDEFGHIJKLMNOPQRSTUVWXYZ", "Σ"]] {
            text.clear();
            text.push_str(prefix);
            text.push(c);
            text.push_str(suffix);
            check_case(&text, &mut arena);
        }
    }
    for text in boundary_texts() {
        check_case(&text, &mut arena);
    }
}

#[test]
fn hex_encode_wrapper_matches_reference() {
    let arena = Bump::new();
    for len in 0..300usize {
        let bytes = (0..len)
            .map(|index| (index.wrapping_mul(131) ^ len) as u8)
            .collect::<Vec<_>>();
        let mut expected = String::with_capacity(len * 2);
        for byte in &bytes {
            let _ = write!(expected, "{byte:02x}");
        }
        assert_eq!(hex_encode(&bytes, &arena), expected);
    }
}

#[test]
fn utf8_lossy_wrapper_matches_std() {
    let mut arena = Bump::new();
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            check_lossy(&[first, second], &mut arena);
        }
    }
    for text in boundary_texts().iter().step_by(5) {
        let bytes = text.as_bytes();
        check_lossy(bytes, &mut arena);
        for len in [15, 16, 17, 62, 63, 64, 65, 200] {
            let prefix = bytes.get(..len).unwrap_or(bytes);
            check_lossy(prefix, &mut arena);
            let mut corrupted = prefix.to_vec();
            corrupted.insert(corrupted.len() / 2, 0xC3);
            check_lossy(&corrupted, &mut arena);
            corrupted.push(0xFF);
            check_lossy(&corrupted, &mut arena);
        }
    }
}
