/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{NumberFormat, SIGNIFICANT_DIGITS};
use crate::{output::Output, xml::Text};
use memchr::memchr;

const MAX_INTEGER_DIGITS: usize = 15;
const MAX_DIGITS: usize = 40;
const PERCENT_SHIFT: usize = 2;
const ZEROS: &str = "000000000000000000000000000000";

#[derive(Debug, Clone, Copy)]
enum Precision {
    Shortest,
    Fixed(usize),
}

impl Precision {
    fn limit(self, point: usize) -> usize {
        match self {
            Precision::Shortest => usize::MAX,
            Precision::Fixed(decimals) => point + decimals,
        }
    }
}

pub(crate) fn push_exact(text: Text<'_>, format: NumberFormat, out: &mut Output<'_>) -> bool {
    let Some(decimal) = Decimal::parse(text.as_bytes()) else {
        return false;
    };
    match format {
        NumberFormat::General | NumberFormat::Text => decimal.push(text, Precision::Shortest, out),
        NumberFormat::Fixed(decimals) => {
            decimal.push(text, Precision::Fixed(usize::from(decimals)), out)
        }
        NumberFormat::Percent(decimals) => decimal.push_percent(usize::from(decimals), out),
        _ => false,
    }
}

#[inline(always)]
pub(crate) fn push_integer(text: Text<'_>, format: NumberFormat, out: &mut Output<'_>) -> bool {
    let integral = matches!(
        format,
        NumberFormat::General | NumberFormat::Text | NumberFormat::Fixed(0)
    );
    if integral && is_short_integer(text.as_bytes()) {
        text.push(out);
        true
    } else {
        false
    }
}

#[inline(always)]
fn is_short_integer(bytes: &[u8]) -> bool {
    match bytes {
        [b'0'..=b'9'] => true,
        [b'1'..=b'9', rest @ ..] => {
            rest.len() < MAX_INTEGER_DIGITS && rest.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    }
}

struct Decimal<'a> {
    negative: bool,
    integer: &'a [u8],
    fraction: &'a [u8],
}

impl<'a> Decimal<'a> {
    fn parse(raw: &'a [u8]) -> Option<Decimal<'a>> {
        let (negative, unsigned) = match raw.strip_prefix(b"-") {
            Some(unsigned) => (true, unsigned),
            None => (false, raw),
        };
        let (integer, fraction) = match memchr(b'.', unsigned) {
            Some(dot) => (
                unsigned.get(..dot)?,
                unsigned
                    .get(dot + 1..)
                    .filter(|fraction| !fraction.is_empty())?,
            ),
            None => (unsigned, b"".as_slice()),
        };
        let canonical = integer == b"0" || integer.first().is_some_and(|&digit| digit != b'0');
        (canonical
            && integer.len() <= MAX_INTEGER_DIGITS
            && integer.len() + fraction.len() <= MAX_DIGITS
            && integer.iter().all(u8::is_ascii_digit)
            && fraction.iter().all(u8::is_ascii_digit))
        .then_some(Decimal {
            negative,
            integer,
            fraction,
        })
    }

    fn first_significant(&self) -> usize {
        if self.integer == b"0" {
            1 + self
                .fraction
                .iter()
                .take_while(|&&digit| digit == b'0')
                .count()
        } else {
            0
        }
    }

    fn is_zero(&self) -> bool {
        self.integer == b"0" && self.fraction.iter().all(|&digit| digit == b'0')
    }

    fn digit(&self, index: usize) -> Option<u8> {
        match index.checked_sub(self.integer.len()) {
            Some(offset) => self.fraction.get(offset).copied(),
            None => self.integer.get(index).copied(),
        }
    }

    fn push(&self, text: Text<'_>, precision: Precision, out: &mut Output<'_>) -> bool {
        let first = self.first_significant();
        let total = self.integer.len() + self.fraction.len();
        let exact = total.saturating_sub(first) <= SIGNIFICANT_DIGITS
            && !(self.negative && self.is_zero())
            && match precision {
                Precision::Shortest => self.fraction.last() != Some(&b'0'),
                Precision::Fixed(decimals) => self.fraction.len() <= decimals,
            };
        if !exact {
            return self.push_rounded(first, precision, "", out);
        }
        text.push(out);
        if let Precision::Fixed(decimals) = precision
            && decimals > self.fraction.len()
        {
            if self.fraction.is_empty() {
                out.push_str(".");
            }
            out.push_str(ZEROS.get(..decimals - self.fraction.len()).unwrap_or(ZEROS));
        }
        true
    }

    fn push_percent(&self, decimals: usize, out: &mut Output<'_>) -> bool {
        let mut digits = [b'0'; MAX_DIGITS + PERCENT_SHIFT];
        let point = self.integer.len() + PERCENT_SHIFT;
        let (moved, rest) = self
            .fraction
            .split_at(self.fraction.len().min(PERCENT_SHIFT));
        let copied = [
            (0, self.integer),
            (self.integer.len(), moved),
            (point, rest),
        ]
        .into_iter()
        .all(|(at, bytes)| match digits.get_mut(at..at + bytes.len()) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                true
            }
            None => false,
        });
        if !copied {
            return false;
        }
        let leading = digits.get(..point - 1).map_or(0, |head| {
            head.iter().take_while(|&&digit| digit == b'0').count()
        });
        let (Some(integer), Some(fraction)) = (
            digits.get(leading..point),
            digits.get(point..point + rest.len()),
        ) else {
            return false;
        };
        if integer.len() > MAX_INTEGER_DIGITS {
            return false;
        }
        let shifted = Decimal {
            negative: self.negative,
            integer,
            fraction,
        };
        shifted.push_rounded(
            shifted.first_significant(),
            Precision::Fixed(decimals),
            "%",
            out,
        )
    }

    fn push_rounded(
        &self,
        first: usize,
        precision: Precision,
        suffix: &str,
        out: &mut Output<'_>,
    ) -> bool {
        let point = self.integer.len();
        let total = point + self.fraction.len();
        let keep = (first + SIGNIFICANT_DIGITS)
            .min(precision.limit(point))
            .min(total)
            .max(point);
        let mut digits = [b'0'; MAX_DIGITS + 1];
        let (Some(kept), Some(fraction)) =
            (digits.get_mut(1..=keep), self.fraction.get(..keep - point))
        else {
            return false;
        };
        let (integer_slot, fraction_slot) = kept.split_at_mut(point);
        integer_slot.copy_from_slice(self.integer);
        fraction_slot.copy_from_slice(fraction);
        let mut carry = self.digit(keep).is_some_and(|digit| digit >= b'5');
        for slot in kept.iter_mut().rev() {
            if !carry {
                break;
            }
            if *slot == b'9' {
                *slot = b'0';
            } else {
                *slot += 1;
                carry = false;
            }
        }
        let start = if carry {
            if let Some(slot) = digits.first_mut() {
                *slot = b'1';
            }
            0
        } else {
            1
        };
        let (Some(integer), Some(mut fraction)) =
            (digits.get(start..=point), digits.get(point + 1..=keep))
        else {
            return false;
        };
        if matches!(precision, Precision::Shortest) {
            while let [rest @ .., b'0'] = fraction {
                fraction = rest;
            }
        }
        let padding = match precision {
            Precision::Fixed(decimals) => decimals.saturating_sub(fraction.len()),
            Precision::Shortest => 0,
        };
        let negative = self.negative && !integer.iter().chain(fraction).all(|&digit| digit == b'0');
        let mut rendered = [0u8; MAX_DIGITS + 4];
        let mut len = 0;
        let mut append = |bytes: &[u8]| {
            if let Some(slot) = rendered.get_mut(len..len + bytes.len()) {
                slot.copy_from_slice(bytes);
                len += bytes.len();
            }
        };
        if negative {
            append(b"-");
        }
        append(integer);
        if !fraction.is_empty() || padding > 0 {
            append(b".");
            append(fraction);
        }
        match std::str::from_utf8(rendered.get(..len).unwrap_or_default()) {
            Ok(text) => {
                out.push_str(text);
                if padding > 0 {
                    out.push_str(ZEROS.get(..padding).unwrap_or(ZEROS));
                }
                if !suffix.is_empty() {
                    out.push_str(suffix);
                }
                true
            }
            Err(_) => false,
        }
    }
}
