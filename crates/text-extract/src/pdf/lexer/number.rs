/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Lexer, Token};

const MAX_REAL: f64 = f32::MAX as f64;
const MAX_FRACTION_DIGITS: usize = 18;
const MAX_EXACT_DIGITS: usize = 15;
const FRACTION_SCALES: [f64; MAX_FRACTION_DIGITS] = {
    let mut scales = [0.0; MAX_FRACTION_DIGITS];
    let mut scale = 1.0;
    let mut index = 0;
    while index < MAX_FRACTION_DIGITS {
        scale /= 10.0;
        scales[index] = scale;
        index += 1;
    }
    scales
};

impl<'a> Lexer<'a> {
    pub(super) fn number(&mut self, start: usize) -> Token<'a> {
        let mut pos = start;
        let mut negative = false;
        while let Some(sign @ (b'+' | b'-')) = self.byte(pos) {
            negative |= sign == b'-';
            pos += 1;
        }
        if pos > start {
            while let Some(b'\r' | b'\n') = self.byte(pos) {
                pos += 1;
            }
        }
        let mut integer = 0u64;
        let mut integer_digits = 0usize;
        let mut fraction = 0f64;
        let mut fraction_digits = 0usize;
        let mut dots = 0u32;
        let mut digits = false;
        for &byte in self.data.get(pos..).unwrap_or_default() {
            let digit = byte.wrapping_sub(b'0');
            if digit < 10 {
                digits = true;
                if dots == 0 {
                    integer = integer.wrapping_mul(10).wrapping_add(u64::from(digit));
                    integer_digits += 1;
                } else if let Some(scale) =
                    FRACTION_SCALES.get(fraction_digits).filter(|_| dots == 1)
                {
                    fraction += f64::from(digit) * scale;
                    fraction_digits += 1;
                }
            } else if byte == b'.' {
                dots += 1;
            } else if byte != b'+' && byte != b'-' {
                break;
            }
            pos += 1;
        }
        if integer_digits > MAX_EXACT_DIGITS {
            return self.wide_number(start);
        }
        self.pos = pos.max(start + 1);
        if !digits {
            return Token::Int(0);
        }
        let integer = integer as i64;
        if dots == 0 {
            return Token::Int(if negative { -integer } else { integer });
        }
        let magnitude = (integer as f64 + fraction).min(MAX_REAL);
        Token::Real(if negative { -magnitude } else { magnitude })
    }

    pub(super) fn wide_number(&mut self, start: usize) -> Token<'a> {
        let mut pos = start;
        let mut negative = false;
        while let Some(sign @ (b'+' | b'-')) = self.byte(pos) {
            negative |= sign == b'-';
            pos += 1;
        }
        if pos > start {
            while let Some(b'\r' | b'\n') = self.byte(pos) {
                pos += 1;
            }
        }
        let mut integer: Option<i64> = Some(0);
        let mut wide = 0f64;
        let mut fraction = 0f64;
        let mut scale = 1f64;
        let mut fraction_digits = 0usize;
        let mut dots = 0u32;
        let mut digits = false;
        while let Some(byte) = self.byte(pos) {
            match byte {
                b'0'..=b'9' => {
                    let digit = byte - b'0';
                    digits = true;
                    if dots == 0 {
                        integer = integer
                            .and_then(|value| value.checked_mul(10))
                            .and_then(|value| value.checked_add(i64::from(digit)));
                        wide = wide * 10.0 + f64::from(digit);
                    } else if dots == 1 && fraction_digits < MAX_FRACTION_DIGITS {
                        scale /= 10.0;
                        fraction += f64::from(digit) * scale;
                        fraction_digits += 1;
                    }
                }
                b'.' => dots += 1,
                b'-' | b'+' => {}
                _ => break,
            }
            pos += 1;
        }
        self.pos = pos.max(start + 1);
        if !digits {
            return Token::Int(0);
        }
        match integer {
            Some(value) if dots == 0 => Token::Int(if negative { -value } else { value }),
            _ => {
                let magnitude = (wide + fraction).min(MAX_REAL);
                Token::Real(if negative { -magnitude } else { magnitude })
            }
        }
    }
}
