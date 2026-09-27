/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod cache;
mod cmap;
mod code;
mod composite;
mod embedded;
mod predefined;
mod program;
mod ranges;
mod simple;
mod unicode;
mod widths;

#[cfg(test)]
mod tests;

pub(crate) use cache::{FontCache, FontId};

use self::{
    cmap::{Cmap, CmapKind},
    composite::CompositeFont,
    simple::{SimpleFont, SimpleKind},
};
use super::{
    document::Document,
    object::{Dict, Object},
    tables::PredefinedCmap,
};

const IDENTITY_PREFIX: &[u8] = b"Identity";
const GBK_CMAP: &[u8] = b"GBK-EUC-H";

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Metrics {
    pub(crate) em_scale: f32,
    pub(crate) space_width: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Glyph {
    pub(crate) len: usize,
    pub(crate) width: f32,
    pub(crate) space_code: bool,
}

#[derive(Debug)]
pub(crate) enum ToUnicode {
    Map(Cmap),
    Identity,
}

#[derive(Debug)]
enum Kind {
    Simple(SimpleFont),
    Composite(Box<CompositeFont>),
}

#[derive(Debug)]
pub(crate) struct Font {
    kind: Kind,
    metrics: Metrics,
    vertical: bool,
}

impl ToUnicode {
    fn load(doc: &Document<'_>, dict: Dict<'_>, buf: &mut Vec<u8>) -> Option<Self> {
        match doc.dict_get(dict, b"ToUnicode") {
            Object::Stream(stream) => {
                let (data, outcome) = doc.stream_bytes(stream, buf);
                if outcome.is_failure() {
                    return None;
                }
                let mut cmap = Cmap::new(CmapKind::ToUnicode);
                cmap.parse(data);
                cmap.finish();
                (!cmap.is_empty()).then_some(ToUnicode::Map(cmap))
            }
            Object::Name(name) if name.raw().starts_with(IDENTITY_PREFIX) => {
                Some(ToUnicode::Identity)
            }
            _ => None,
        }
    }

    pub(crate) fn unicode(&self, code: u32, out: &mut String) -> bool {
        match self {
            ToUnicode::Map(cmap) => cmap.unicode(code, out),
            ToUnicode::Identity => char::from_u32(code).map(|ch| out.push(ch)).is_some(),
        }
    }

    fn heap_size(&self) -> usize {
        match self {
            ToUnicode::Map(cmap) => cmap.heap_size(),
            ToUnicode::Identity => 0,
        }
    }
}

impl Font {
    pub(crate) fn load(doc: &Document<'_>, dict: Dict<'_>, buf: &mut Vec<u8>) -> Self {
        let subtype = doc.get_name(dict, b"Subtype");
        let is = |name: &[u8]| subtype.is_some_and(|subtype| subtype.is(name));
        let to_unicode = ToUnicode::load(doc, dict, buf);
        if is(b"Type0") {
            let (font, metrics, vertical) = CompositeFont::load(doc, dict, to_unicode, buf);
            return Font {
                kind: Kind::Composite(Box::new(font)),
                metrics,
                vertical,
            };
        }
        if to_unicode.is_none()
            && !is(b"Type3")
            && SimpleFont::carries_gbk(doc, dict)
            && let Some(cmap) = PredefinedCmap::from_name(GBK_CMAP)
        {
            let (font, metrics) = CompositeFont::legacy(cmap);
            return Font {
                kind: Kind::Composite(Box::new(font)),
                metrics,
                vertical: false,
            };
        }
        let kind = if is(b"TrueType") {
            SimpleKind::TrueType
        } else if is(b"Type3") {
            SimpleKind::Type3
        } else {
            SimpleKind::Type1
        };
        let (font, metrics) = SimpleFont::load(doc, dict, kind, to_unicode.as_ref(), buf);
        Font {
            kind: Kind::Simple(font),
            metrics,
            vertical: false,
        }
    }

    pub(crate) fn standard() -> Self {
        let (font, metrics) = SimpleFont::standard();
        Font {
            kind: Kind::Simple(font),
            metrics,
            vertical: false,
        }
    }

    #[inline]
    pub(crate) fn metrics(&self) -> Metrics {
        self.metrics
    }

    #[inline]
    pub(crate) fn is_vertical(&self) -> bool {
        self.vertical
    }

    pub(crate) fn heap_size(&self) -> usize {
        std::mem::size_of::<Font>()
            + match &self.kind {
                Kind::Simple(font) => font.heap_size(),
                Kind::Composite(font) => font.heap_size(),
            }
    }

    #[inline]
    pub(crate) fn glyph<'s>(
        &'s self,
        bytes: &[u8],
        scratch: &'s mut String,
    ) -> Option<(Glyph, &'s str)> {
        match &self.kind {
            Kind::Simple(font) => {
                let &code = bytes.first()?;
                let (text, width) = font.glyph(code);
                Some((
                    Glyph {
                        len: 1,
                        width,
                        space_code: code == b' ',
                    },
                    text,
                ))
            }
            Kind::Composite(font) => {
                scratch.clear();
                let glyph = font.glyph(bytes, scratch)?;
                Some((glyph, scratch.as_str()))
            }
        }
    }
}
