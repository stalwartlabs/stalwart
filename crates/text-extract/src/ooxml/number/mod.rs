/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod decimal;
mod render;
#[cfg(test)]
mod tests;

use crate::{output::Output, xml::Tag};
use memchr::memmem;

pub(crate) use decimal::{push_exact, push_integer};
pub(crate) use render::{push_boolean, push_number};

const SIGNIFICANT_DIGITS: usize = 15;
const MAX_DECIMALS: u8 = 30;
const MAX_VALUE: usize = 64;
const ENCODED_QUOTE: &[u8] = b"quot;";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DateSystem {
    Epoch1900,
    Epoch1904,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NumberFormat {
    #[default]
    General,
    Text,
    Fixed(u8),
    Percent(u8),
    Date,
    DateTime,
    Time,
    ElapsedTime,
}

impl DateSystem {
    pub(crate) fn from_properties(tag: &Tag<'_>) -> Self {
        Self::from_attribute(tag, b"date1904")
    }

    pub(crate) fn from_value(tag: &Tag<'_>) -> Self {
        Self::from_attribute(tag, b"val")
    }

    fn from_attribute(tag: &Tag<'_>, attribute: &[u8]) -> Self {
        let date1904 = tag
            .attributes()
            .any(|(name, value)| name == attribute && hashify::set!(value, b"1", b"true", b"on"));
        if date1904 {
            DateSystem::Epoch1904
        } else {
            DateSystem::Epoch1900
        }
    }
}

impl NumberFormat {
    pub(crate) fn builtin(id: u32) -> NumberFormat {
        match id {
            1 | 3 | 5 | 6 | 37 | 38 | 41 | 42 => NumberFormat::Fixed(0),
            2 | 4 | 7 | 8 | 39 | 40 | 43 | 44 => NumberFormat::Fixed(2),
            9 => NumberFormat::Percent(0),
            10 => NumberFormat::Percent(2),
            14..=17 | 27..=31 | 36 | 50..=58 => NumberFormat::Date,
            18..=21 | 32..=35 | 45 | 47 => NumberFormat::Time,
            22 => NumberFormat::DateTime,
            46 => NumberFormat::ElapsedTime,
            49 => NumberFormat::Text,
            _ => NumberFormat::General,
        }
    }

    pub(crate) fn classify(code: &[u8]) -> NumberFormat {
        let mut tokens = FormatTokens::default();
        let mut rest = code;
        while let Some((&byte, tail)) = rest.split_first() {
            rest = tail;
            match byte {
                b';' => break,
                b'"' => {
                    rest = rest
                        .iter()
                        .position(|&byte| byte == b'"')
                        .and_then(|end| rest.get(end + 1..))
                        .unwrap_or_default();
                }
                b'&' if rest.starts_with(ENCODED_QUOTE) => {
                    let literal = rest.get(ENCODED_QUOTE.len()..).unwrap_or_default();
                    rest = memmem::find(literal, b"&quot;")
                        .and_then(|end| literal.get(end + ENCODED_QUOTE.len() + 1..))
                        .unwrap_or_default();
                }
                b'\\' | b'_' | b'*' => rest = rest.get(1..).unwrap_or_default(),
                b'[' => {
                    let end = rest
                        .iter()
                        .position(|&byte| byte == b']')
                        .unwrap_or(rest.len());
                    let (bracket, tail) = rest.split_at(end);
                    if let Some(first) = bracket.first()
                        && matches!(first.to_ascii_lowercase(), b'h' | b'm' | b's')
                        && bracket.iter().all(|byte| byte.eq_ignore_ascii_case(first))
                    {
                        tokens.elapsed = true;
                        tokens.time = true;
                    }
                    rest = tail.get(1..).unwrap_or_default();
                }
                b'g' | b'G' if starts_with_ignore_case(rest, b"eneral") => {
                    rest = rest.get(6..).unwrap_or_default();
                }
                b'a' | b'A' if starts_with_ignore_case(rest, b"m/p") => {
                    tokens.time = true;
                    rest = rest.get(3..).unwrap_or_default();
                }
                b'y' | b'Y' | b'd' | b'D' => tokens.date = true,
                b'h' | b'H' | b's' | b'S' => tokens.time = true,
                b'm' | b'M' => tokens.month_or_minute = true,
                b'%' => tokens.percent = true,
                b'@' => tokens.text = true,
                b'/' => tokens.fraction = true,
                b'e' | b'E' if matches!(rest.first(), Some(b'+' | b'-')) => {
                    tokens.scientific = true
                }
                b'0' | b'#' | b'?' => {
                    tokens.digits = true;
                    if tokens.in_decimals && !tokens.percent {
                        tokens.decimals = tokens.decimals.saturating_add(1);
                    }
                }
                b'.' => tokens.in_decimals = true,
                _ => {}
            }
        }
        tokens.format()
    }
}

#[derive(Default)]
struct FormatTokens {
    date: bool,
    time: bool,
    month_or_minute: bool,
    elapsed: bool,
    percent: bool,
    text: bool,
    fraction: bool,
    scientific: bool,
    digits: bool,
    in_decimals: bool,
    decimals: u8,
}

impl FormatTokens {
    fn format(&self) -> NumberFormat {
        let date = self.date || (self.month_or_minute && !self.time);
        match (date, self.time) {
            (true, true) => NumberFormat::DateTime,
            (true, false) => NumberFormat::Date,
            (false, true) if self.elapsed => NumberFormat::ElapsedTime,
            (false, true) => NumberFormat::Time,
            (false, false) if self.percent => {
                NumberFormat::Percent(self.decimals.min(MAX_DECIMALS))
            }
            (false, false) if self.text && !self.digits => NumberFormat::Text,
            (false, false) if self.digits && !self.fraction && !self.scientific => {
                NumberFormat::Fixed(self.decimals.min(MAX_DECIMALS))
            }
            (false, false) => NumberFormat::General,
        }
    }
}

fn starts_with_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .get(..needle.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
}

pub(crate) struct ValueBuffer {
    bytes: [u8; MAX_VALUE],
    len: usize,
}

impl Default for ValueBuffer {
    fn default() -> Self {
        ValueBuffer {
            bytes: [0; MAX_VALUE],
            len: 0,
        }
    }
}

impl ValueBuffer {
    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn value(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    #[must_use]
    pub(crate) fn fill(&mut self, text: &[u8]) -> bool {
        let end = self.len + text.len();
        match self.bytes.get_mut(self.len..end) {
            Some(slot) => {
                slot.copy_from_slice(text);
                self.len = end;
                true
            }
            None => false,
        }
    }

    #[must_use]
    pub(crate) fn push(&mut self, text: &[u8], out: &mut Output<'_>) -> bool {
        let end = self.len + text.len();
        match self.bytes.get_mut(self.len..end) {
            Some(slot) => {
                slot.copy_from_slice(text);
                self.len = end;
                true
            }
            None => {
                out.push_utf8(self.value());
                out.push_utf8(text);
                self.len = 0;
                false
            }
        }
    }
}
