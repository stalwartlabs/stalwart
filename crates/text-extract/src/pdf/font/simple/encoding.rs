/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CODE_COUNT, SPACE};
use crate::pdf::{
    document::Document,
    font::{
        ToUnicode,
        program::{BuiltinEncoding, CodeNames, TrueType},
        unicode::{NameResolver, Verdict, verdict},
    },
    object::{Array, Object},
    tables::BaseEncoding,
};
use std::ops::RangeInclusive;

const PRINTABLE_ASCII: RangeInclusive<u8> = 0x21..=0x7E;

pub(super) struct Differences {
    names: Vec<u8>,
    spans: Box<[Option<(u32, u16)>; CODE_COUNT]>,
}

pub(super) enum Builtin<'x> {
    None,
    Encoding(BaseEncoding),
    Names(CodeNames<'x>),
    TrueType(Box<TrueType<'x>>),
}

pub(super) struct Sources<'s, 'x> {
    pub(super) to_unicode: Option<&'s ToUnicode>,
    pub(super) differences: &'s Differences,
    pub(super) base: Option<BaseEncoding>,
    pub(super) builtin: &'s Builtin<'x>,
    pub(super) fallback: BaseEncoding,
    pub(super) resolver: NameResolver,
}

impl Differences {
    pub(super) fn load(doc: &Document<'_>, array: Option<Array<'_>>) -> Self {
        let mut differences = Differences {
            names: Vec::new(),
            spans: Box::new([None; CODE_COUNT]),
        };
        let Some(array) = array else {
            return differences;
        };
        let mut code: Option<usize> = None;
        for item in doc.array_iter(array) {
            match item {
                Object::Name(name) => {
                    let Some(current) = code else {
                        continue;
                    };
                    code = Some(current + 1);
                    if name.is(b".notdef") {
                        continue;
                    }
                    let Some(slot) = differences.spans.get_mut(current) else {
                        code = None;
                        continue;
                    };
                    let start = differences.names.len();
                    differences.names.extend(name.bytes());
                    if let (Ok(start), Ok(len)) = (
                        u32::try_from(start),
                        u16::try_from(differences.names.len() - start),
                    ) {
                        *slot = Some((start, len));
                    }
                }
                other => {
                    code = other
                        .as_int()
                        .and_then(|value| usize::try_from(value).ok())
                        .filter(|&value| value < CODE_COUNT);
                }
            }
        }
        differences
    }

    pub(super) fn name(&self, code: u8) -> Option<&[u8]> {
        let (start, len) = (*self.spans.get(usize::from(code))?)?;
        let start = start as usize;
        self.names.get(start..start + usize::from(len))
    }

    pub(super) fn names(&self) -> impl Iterator<Item = &[u8]> + Clone {
        (0..=u8::MAX).filter_map(|code| self.name(code))
    }
}

impl Builtin<'_> {
    pub(super) fn name(&self, code: u8) -> Option<&[u8]> {
        match self {
            Builtin::Encoding(encoding) => encoding.glyph_name(code).map(str::as_bytes),
            Builtin::Names(names) => names.get(code),
            Builtin::TrueType(font) => font.glyph_name(font.symbolic_glyph(code)?),
            Builtin::None => None,
        }
    }
}

impl Sources<'_, '_> {
    pub(super) fn text(&self, code: u8, out: &mut String) {
        let mark = out.len();
        let mut private_use = false;
        if let Some(to_unicode) = self.to_unicode
            && to_unicode.unicode(u32::from(code), out)
        {
            match verdict(out.get(mark..).unwrap_or_default()) {
                Verdict::Accept => return,
                Verdict::Space => {
                    out.truncate(mark);
                    out.push(' ');
                    return;
                }
                Verdict::Reject => out.truncate(mark),
                Verdict::PrivateUse => {
                    out.truncate(mark);
                    private_use = true;
                }
            }
        }
        if let Some(name) = self.differences.name(code) {
            if !self.resolver.resolve(name, out) && !private_use {
                last_resort(code, out);
            }
            return;
        }
        if let Some(ch) = self.base.and_then(|base| base.unicode(code)) {
            out.push(ch);
            return;
        }
        if self.builtin_text(code, out) {
            return;
        }
        if private_use {
            return;
        }
        match self.fallback.unicode(code) {
            Some(ch) => out.push(ch),
            None => last_resort(code, out),
        }
    }

    fn builtin_text(&self, code: u8, out: &mut String) -> bool {
        match self.builtin {
            Builtin::None => false,
            Builtin::Encoding(encoding) => encoding.unicode(code).map(|ch| out.push(ch)).is_some(),
            Builtin::Names(names) => match names.get(code) {
                Some(name) => {
                    if !self.resolver.resolve(name, out) {
                        last_resort(code, out);
                    }
                    true
                }
                None => false,
            },
            Builtin::TrueType(font) => {
                let Some(glyph) = font.symbolic_glyph(code) else {
                    return false;
                };
                if let Some(name) = font.glyph_name(glyph)
                    && self.resolver.resolve(name, out)
                {
                    return true;
                }
                false
            }
        }
    }

    pub(super) fn glyph_name(&self, code: u8) -> Option<&[u8]> {
        self.differences
            .name(code)
            .or_else(|| self.base?.glyph_name(code).map(str::as_bytes))
            .or_else(|| self.builtin.name(code))
            .or_else(|| self.fallback.glyph_name(code).map(str::as_bytes))
    }
}

pub(super) fn last_resort(code: u8, out: &mut String) {
    if PRINTABLE_ASCII.contains(&code) || code == SPACE {
        out.push(char::from(code));
    }
}

impl<'x> Builtin<'x> {
    pub(super) fn from_encoding(encoding: BuiltinEncoding<'x>) -> Self {
        match encoding {
            BuiltinEncoding::Standard => Builtin::Encoding(BaseEncoding::Standard),
            BuiltinEncoding::Expert => Builtin::Encoding(BaseEncoding::Expert),
            BuiltinEncoding::Custom(names) if !names.is_empty() => Builtin::Names(names),
            BuiltinEncoding::Custom(_) => Builtin::None,
        }
    }
}
