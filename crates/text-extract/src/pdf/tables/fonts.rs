/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::encoding::{BaseEncoding, STD_GLYPHS};
use super::font_data::{
    ALIAS_FONTS, ALIAS_NAMES, ALIAS_OFFSETS, DINGBAT_GLYPHS, DINGBAT_WIDTHS, LATIN_GLYPHS,
    LATIN_WIDTHS, SYMBOL_GLYPHS, SYMBOL_WIDTHS, WIDTH_PALETTE,
};
use super::names::NameTable;

static ALIASES: NameTable = NameTable::new(ALIAS_NAMES, &ALIAS_OFFSETS);

const COURIER_WIDTH: u16 = 600;
const SUBSET_TAG_LEN: usize = 7;
const MAX_ALIAS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StandardFont {
    Courier,
    CourierBold,
    CourierOblique,
    CourierBoldOblique,
    Helvetica,
    HelveticaBold,
    HelveticaOblique,
    HelveticaBoldOblique,
    TimesRoman,
    TimesBold,
    TimesItalic,
    TimesBoldItalic,
    Symbol,
    ZapfDingbats,
}

enum Metrics {
    Monospace,
    Latin(usize),
    Symbol,
    Dingbats,
}

impl StandardFont {
    pub(crate) fn from_base_font(name: &[u8]) -> Option<Self> {
        let mut buf = [0u8; MAX_ALIAS];
        let mut len = 0;
        for &byte in strip_subset_tag(name) {
            let normalized = match byte {
                b',' | b'_' => b'-',
                byte if byte.is_ascii_whitespace() => continue,
                byte => byte,
            };
            *buf.get_mut(len)? = normalized;
            len += 1;
        }
        ALIAS_FONTS.get(ALIASES.find(buf.get(..len)?)?).copied()
    }

    pub(crate) fn width(self, glyph_name: &[u8]) -> Option<u16> {
        let (glyphs, widths): (&[u16], &[u8]) = match self.metrics() {
            Metrics::Monospace => return Some(COURIER_WIDTH),
            Metrics::Latin(row) => (&LATIN_GLYPHS, LATIN_WIDTHS.get(row)?),
            Metrics::Symbol => (&SYMBOL_GLYPHS, &SYMBOL_WIDTHS),
            Metrics::Dingbats => (&DINGBAT_GLYPHS, &DINGBAT_WIDTHS),
        };
        let index = u16::try_from(STD_GLYPHS.find(glyph_name)?).ok()?;
        let position = glyphs.binary_search(&index).ok()?;
        WIDTH_PALETTE
            .get(usize::from(*widths.get(position)?))
            .copied()
    }

    pub(crate) fn builtin_encoding(self) -> BaseEncoding {
        match self {
            Self::Symbol => BaseEncoding::Symbol,
            Self::ZapfDingbats => BaseEncoding::ZapfDingbats,
            _ => BaseEncoding::Standard,
        }
    }

    pub(crate) fn is_symbolic(self) -> bool {
        matches!(self, Self::Symbol | Self::ZapfDingbats)
    }

    fn metrics(self) -> Metrics {
        match self {
            Self::Courier | Self::CourierBold | Self::CourierOblique | Self::CourierBoldOblique => {
                Metrics::Monospace
            }
            Self::Helvetica | Self::HelveticaOblique => Metrics::Latin(0),
            Self::HelveticaBold | Self::HelveticaBoldOblique => Metrics::Latin(1),
            Self::TimesRoman => Metrics::Latin(2),
            Self::TimesBold => Metrics::Latin(3),
            Self::TimesItalic => Metrics::Latin(4),
            Self::TimesBoldItalic => Metrics::Latin(5),
            Self::Symbol => Metrics::Symbol,
            Self::ZapfDingbats => Metrics::Dingbats,
        }
    }
}

fn strip_subset_tag(name: &[u8]) -> &[u8] {
    match name.split_at_checked(SUBSET_TAG_LEN) {
        Some((tag, rest))
            if tag.split_last().is_some_and(|(last, head)| {
                *last == b'+' && head.iter().all(u8::is_ascii_uppercase)
            }) =>
        {
            rest
        }
        _ => name,
    }
}
