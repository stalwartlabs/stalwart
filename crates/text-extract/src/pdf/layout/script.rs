/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) fn is_space(ch: char) -> bool {
    matches!(
        ch,
        '\t' | '\n'
            | '\u{0B}'
            | '\u{0C}'
            | '\r'
            | ' '
            | '\u{85}'
            | '\u{A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200B}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

pub(crate) fn is_dropped(ch: char) -> bool {
    let code = u32::from(ch);
    ch.is_control()
        || matches!(code, 0xAD | 0xFFFD..=0xFFFF | 0xFDD0..=0xFDEF)
        || matches!(code, 0xE000..=0xF8FF | 0xF_0000..=0x10_FFFF)
}

pub(crate) fn is_unspaced(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x0E00..=0x0EFF
            | 0x0F00..=0x0FFF
            | 0x1000..=0x109F
            | 0x1780..=0x17FF
            | 0x3000..=0x30FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFAFF
            | 0xFF00..=0xFFEF
            | 0x2_0000..=0x3_FFFF
    )
}

pub(crate) fn is_rtl(ch: char) -> bool {
    !ch.is_numeric()
        && matches!(
            u32::from(ch),
            0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFF | 0x1_0800..=0x1_0FFF | 0x1_E800..=0x1_EFFF
        )
}

pub(crate) fn is_combining(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x0300..=0x036F | 0x0591..=0x05BD | 0x05BF..=0x05C7 | 0x0610..=0x061A | 0x064B..=0x065F
            | 0x0670 | 0x06D6..=0x06ED | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF
            | 0xFE20..=0xFE2F
    )
}

pub(crate) fn is_neutral(ch: char) -> bool {
    !ch.is_alphabetic() || is_combining(ch)
}

pub(crate) fn mirror(ch: char) -> char {
    match ch {
        '(' => ')',
        ')' => '(',
        '[' => ']',
        ']' => '[',
        '{' => '}',
        '}' => '{',
        '<' => '>',
        '>' => '<',
        '\u{AB}' => '\u{BB}',
        '\u{BB}' => '\u{AB}',
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert!(is_space('\u{3000}'));
        assert!(!is_space('a'));
        assert!(is_dropped('\u{ad}'));
        assert!(is_dropped('\u{e000}'));
        assert!(is_dropped('\u{1}'));
        assert!(!is_dropped('\u{e9}'));
        assert!(is_unspaced('\u{65e5}'));
        assert!(is_unspaced('\u{30ab}'));
        assert!(is_unspaced('\u{e01}'));
        assert!(!is_unspaced('\u{d55c}'));
        assert!(is_rtl('\u{5d0}'));
        assert!(is_rtl('\u{627}'));
        assert!(!is_rtl('a'));
        assert!(is_neutral('1'));
        assert!(is_neutral(' '));
        assert!(!is_neutral('a'));
        assert_eq!(mirror('('), ')');
    }
}
