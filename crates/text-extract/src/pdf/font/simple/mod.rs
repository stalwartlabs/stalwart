/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod encoding;
mod widths;

use self::{
    encoding::{Builtin, Differences, Sources, last_resort},
    widths::{Widths, metric_width, substitute},
};
use super::{
    Metrics, ToUnicode,
    embedded::{ProgramKind, has_program, program},
    program::{BuiltinEncoding, Cff, TrueType},
    unicode::NameResolver,
};
use crate::pdf::{
    document::Document,
    object::{Dict, Object},
    tables::{BaseEncoding, StandardFont},
};
use std::ops::RangeInclusive;

pub(crate) const CODE_COUNT: usize = 256;
const WIDTH_SCALE: f32 = 1000.0;
const DEFAULT_WIDTH: f32 = 500.0;
const SYMBOLIC: i64 = 1 << 2;
const NONSYMBOLIC: i64 = 1 << 5;
const SPACE: u8 = b' ';
const TYPE3_EM_RATIO: RangeInclusive<f64> = 0.2..=1.5;
const TYPE3_EM_FACTOR: f64 = 2.0;
const GBK_FONT_NAMES: &[&[u8]] = &[
    b"\xCB\xCE\xCC\xE5",
    b"\xBA\xDA\xCC\xE5",
    b"\xBF\xAC\xCC\xE5",
    b"\xB7\xC2\xCB\xCE",
    b"\xBF\xAC\xCC\xE5_GB2312",
    b"\xB7\xC2\xCB\xCE_GB2312",
    b"\xC1\xA5\xCA\xE9",
    b"\xD0\xC2\xCB\xCE",
    b"\xB7\xC2\xCB\xCE\xCC\xE5",
    b"\xD0\xA1\xB1\xEA\xCB\xCE",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SimpleKind {
    Type1,
    TrueType,
    Type3,
}

#[derive(Debug, Clone, Copy, Default)]
struct Entry {
    start: u32,
    len: u16,
    width: f32,
}

#[derive(Debug, Clone)]
pub(crate) struct SimpleFont {
    entries: Box<[Entry; CODE_COUNT]>,
    text: String,
}

impl SimpleFont {
    pub(crate) fn carries_gbk(doc: &Document<'_>, dict: Dict<'_>) -> bool {
        let win_ansi = doc
            .get_name(dict, b"Encoding")
            .is_some_and(|name| name.is(b"WinAnsiEncoding"));
        win_ansi
            && !has_program(doc.get_dict(dict, b"FontDescriptor"))
            && doc.get_name(dict, b"BaseFont").is_some_and(|name| {
                let name = name.decoded();
                GBK_FONT_NAMES.iter().any(|known| name.as_ref() == *known)
            })
    }

    pub(crate) fn load(
        doc: &Document<'_>,
        dict: Dict<'_>,
        kind: SimpleKind,
        to_unicode: Option<&ToUnicode>,
        buf: &mut Vec<u8>,
    ) -> (SimpleFont, Metrics) {
        let base_font = doc
            .get_name(dict, b"BaseFont")
            .map(|name| name.decoded().into_owned())
            .unwrap_or_default();
        let descriptor = doc.get_dict(dict, b"FontDescriptor");
        let flags = descriptor
            .and_then(|descriptor| doc.get_int(descriptor, b"Flags"))
            .unwrap_or(0);
        let symbolic = flags & SYMBOLIC != 0 && flags & NONSYMBOLIC == 0;
        let standard = match kind {
            SimpleKind::Type3 => None,
            _ => StandardFont::from_base_font(&base_font),
        };
        let (base, differences) = match doc.dict_get(dict, b"Encoding") {
            Object::Name(name) => (
                BaseEncoding::from_name(&name.decoded()),
                Differences::load(doc, None),
            ),
            Object::Dict(encoding) => (
                doc.get_name(encoding, b"BaseEncoding")
                    .and_then(|name| BaseEncoding::from_name(&name.decoded())),
                Differences::load(doc, doc.get_array(encoding, b"Differences")),
            ),
            _ => (None, Differences::load(doc, None)),
        };
        let zapf = standard == Some(StandardFont::ZapfDingbats)
            || base_font.windows(8).any(|window| window == b"Dingbats");
        let resolver = NameResolver::for_names(zapf, differences.names());
        let fallback = match kind {
            SimpleKind::TrueType => BaseEncoding::WinAnsi,
            _ => BaseEncoding::Standard,
        };
        let wants_program = base.is_none()
            && kind != SimpleKind::Type3
            && to_unicode.is_none()
            && has_program(descriptor);
        let loaded = match descriptor.filter(|_| wants_program) {
            Some(descriptor) => program(doc, descriptor, buf),
            None => None,
        };
        let mut builtin = match loaded {
            Some((ProgramKind::Type1, data)) => {
                BuiltinEncoding::from_type1(data).map_or(Builtin::None, Builtin::from_encoding)
            }
            Some((ProgramKind::Cff, data)) => Cff::parse(data)
                .and_then(|cff| cff.builtin_encoding())
                .map_or(Builtin::None, Builtin::from_encoding),
            Some((ProgramKind::OpenType, data)) => {
                match Cff::parse(data).and_then(|cff| cff.builtin_encoding()) {
                    Some(encoding) => Builtin::from_encoding(encoding),
                    None => TrueType::parse(data)
                        .map_or(Builtin::None, |font| Builtin::TrueType(Box::new(font))),
                }
            }
            Some((ProgramKind::TrueType, data)) if symbolic => TrueType::parse(data)
                .map_or(Builtin::None, |font| Builtin::TrueType(Box::new(font))),
            _ => Builtin::None,
        };
        if matches!(builtin, Builtin::None)
            && base.is_none()
            && let Some(standard) = standard.filter(|standard| standard.is_symbolic())
        {
            builtin = Builtin::Encoding(standard.builtin_encoding());
        }
        let sources = Sources {
            to_unicode,
            differences: &differences,
            base,
            builtin: &builtin,
            fallback,
            resolver,
        };
        let widths = Widths::load(doc, dict, descriptor, kind);
        let metrics_font = standard.unwrap_or_else(|| substitute(&base_font));
        let font = SimpleFont::build(|code, text| {
            sources.text(code, text);
            widths.explicit(code).unwrap_or_else(|| match kind {
                SimpleKind::Type3 => widths.missing.unwrap_or(0.0) * widths.type3_scale,
                _ => {
                    widths.missing.unwrap_or_else(|| {
                        sources
                            .glyph_name(code)
                            .and_then(|name| metric_width(metrics_font, name))
                            .unwrap_or(DEFAULT_WIDTH)
                    }) / WIDTH_SCALE
                }
            })
        });
        let metrics = Metrics {
            em_scale: match kind {
                SimpleKind::Type3 => font.type3_em_scale(widths.type3_em),
                _ => 1.0,
            },
            space_width: font.space_width(),
        };
        (font, metrics)
    }

    pub(crate) fn standard() -> (SimpleFont, Metrics) {
        let encoding = BaseEncoding::WinAnsi;
        let font = SimpleFont::build(|code, text| {
            match encoding.unicode(code) {
                Some(ch) => text.push(ch),
                None => last_resort(code, text),
            }
            encoding
                .glyph_name(code)
                .and_then(|name| metric_width(StandardFont::Helvetica, name.as_bytes()))
                .unwrap_or(DEFAULT_WIDTH)
                / WIDTH_SCALE
        });
        let metrics = Metrics {
            em_scale: 1.0,
            space_width: font.space_width(),
        };
        (font, metrics)
    }

    fn build(mut fill: impl FnMut(u8, &mut String) -> f32) -> SimpleFont {
        let mut font = SimpleFont {
            entries: Box::new([Entry::default(); CODE_COUNT]),
            text: String::new(),
        };
        for (code, entry) in (0..=u8::MAX).zip(font.entries.iter_mut()) {
            let mark = font.text.len();
            let width = fill(code, &mut font.text);
            *entry = Entry {
                start: u32::try_from(mark).unwrap_or(u32::MAX),
                len: u16::try_from(font.text.len() - mark).unwrap_or_default(),
                width,
            };
        }
        font.text.shrink_to_fit();
        font
    }

    fn type3_em_scale(&self, nominal: f64) -> f32 {
        let (sum, count) = self
            .entries
            .iter()
            .filter(|entry| entry.width > 0.0)
            .fold((0f64, 0u32), |(sum, count), entry| {
                (sum + f64::from(entry.width), count + 1)
            });
        if count == 0 || nominal <= 0.0 {
            return nominal.max(f64::MIN_POSITIVE) as f32;
        }
        let average = sum / f64::from(count);
        if TYPE3_EM_RATIO.contains(&(average / nominal)) {
            nominal as f32
        } else {
            (average * TYPE3_EM_FACTOR) as f32
        }
    }

    fn space_width(&self) -> Option<f32> {
        let is_space = |code: u8| self.glyph(code).0 == " ";
        let code = if is_space(SPACE) {
            Some(SPACE)
        } else {
            (0..=u8::MAX).find(|&code| is_space(code))
        };
        code.map(|code| self.glyph(code).1)
            .filter(|width| *width > 0.0)
    }

    #[inline]
    pub(crate) fn glyph(&self, code: u8) -> (&str, f32) {
        match self.entries.get(usize::from(code)) {
            Some(entry) => {
                let start = entry.start as usize;
                (
                    self.text
                        .get(start..start + usize::from(entry.len))
                        .unwrap_or_default(),
                    entry.width,
                )
            }
            None => ("", 0.0),
        }
    }

    pub(crate) fn heap_size(&self) -> usize {
        std::mem::size_of::<[Entry; CODE_COUNT]>() + self.text.capacity()
    }
}
