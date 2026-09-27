/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cmap::{MAC_ROMAN, PLATFORM_MAC, PLATFORM_WINDOWS, WINDOWS_SYMBOL};
use super::read::ReadBytes;
use super::{Cmap, CmapSubtable, Post, Sfnt};

const MAXP_NUM_GLYPHS: usize = 4;
const GLYPH_SPACE: u32 = 0x1_0000;
const SYMBOL_PAGES: [u32; 4] = [0x0000, 0xF000, 0xF100, 0xF200];
const NO_CODE_POINT: u32 = u32::MAX;

#[derive(Debug, Clone)]
pub(crate) struct TrueType<'x> {
    num_glyphs: Option<u16>,
    #[cfg(test)]
    cmap: Option<Cmap<'x>>,
    unicode: Option<CmapSubtable<'x>>,
    symbol: Option<CmapSubtable<'x>>,
    mac_roman: Option<CmapSubtable<'x>>,
    post: Option<Post<'x>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GlyphUnicodeMap {
    glyphs: Box<[u16]>,
    code_points: Box<[char]>,
}

impl<'x> TrueType<'x> {
    pub(crate) fn parse(data: &'x [u8]) -> Option<Self> {
        let sfnt = Sfnt::parse(data)?;
        let num_glyphs = sfnt
            .table(b"maxp")
            .and_then(|maxp| maxp.be_u16(MAXP_NUM_GLYPHS));
        let cmap = sfnt.table(b"cmap").and_then(Cmap::parse);
        let mut unicode = None;
        let mut symbol = None;
        let mut mac_roman = None;
        if let Some(cmap) = &cmap {
            unicode = cmap.unicode();
            for (platform, encoding, subtable) in cmap.subtables() {
                match (platform, encoding) {
                    (PLATFORM_WINDOWS, WINDOWS_SYMBOL) if symbol.is_none() => {
                        symbol = Some(subtable)
                    }
                    (PLATFORM_MAC, MAC_ROMAN) if mac_roman.is_none() => mac_roman = Some(subtable),
                    _ => {}
                }
            }
        }
        Some(Self {
            num_glyphs,
            #[cfg(test)]
            cmap,
            unicode,
            symbol,
            mac_roman,
            post: sfnt.table(b"post").and_then(Post::parse),
        })
    }

    pub(crate) fn num_glyphs(&self) -> Option<u16> {
        self.num_glyphs
    }

    #[cfg(test)]
    pub(crate) fn cmap(&self) -> Option<&Cmap<'x>> {
        self.cmap.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn unicode_cmap(&self) -> Option<&CmapSubtable<'x>> {
        self.unicode.as_ref()
    }

    pub(crate) fn glyph_name(&self, glyph: u16) -> Option<&'x [u8]> {
        if !self.contains(glyph) {
            return None;
        }
        self.post.as_ref()?.glyph_name(glyph)
    }

    pub(crate) fn symbolic_glyph(&self, code: u8) -> Option<u16> {
        let code = u32::from(code);
        self.symbol
            .as_ref()
            .and_then(|symbol| {
                SYMBOL_PAGES
                    .iter()
                    .find_map(|page| symbol.glyph(page | code))
            })
            .or_else(|| self.mac_roman.as_ref()?.glyph(code))
            .filter(|&glyph| self.contains(glyph))
    }

    pub(crate) fn unicode_map(&self) -> GlyphUnicodeMap {
        let Some(subtable) = &self.unicode else {
            return GlyphUnicodeMap::default();
        };
        let limit = self.num_glyphs.map_or(GLYPH_SPACE, u32::from);
        let mut dense = vec![NO_CODE_POINT; usize::try_from(limit).unwrap_or_default()];
        subtable.for_each_mapping(limit, |code, glyph| {
            if char::from_u32(code).is_none() {
                return;
            }
            if let Some(slot) = dense.get_mut(usize::from(glyph))
                && (*slot == NO_CODE_POINT || rank(code) < rank(*slot))
            {
                *slot = code;
            }
        });
        let mapped = dense.iter().filter(|&&code| code != NO_CODE_POINT).count();
        let mut glyphs = Vec::with_capacity(mapped);
        let mut code_points = Vec::with_capacity(mapped);
        for (glyph, code) in dense.into_iter().enumerate() {
            if let (Ok(glyph), Some(code)) = (u16::try_from(glyph), char::from_u32(code)) {
                glyphs.push(glyph);
                code_points.push(code);
            }
        }
        GlyphUnicodeMap {
            glyphs: glyphs.into_boxed_slice(),
            code_points: code_points.into_boxed_slice(),
        }
    }

    fn contains(&self, glyph: u16) -> bool {
        self.num_glyphs.is_none_or(|count| glyph < count)
    }
}

fn rank(code: u32) -> (bool, u32) {
    let private_use = matches!(code, 0xE000..=0xF8FF | 0xF_0000..);
    (private_use, code)
}

impl GlyphUnicodeMap {
    #[cfg(test)]
    pub(crate) fn get(&self, glyph: u16) -> Option<char> {
        let index = self.glyphs.binary_search(&glyph).ok()?;
        self.code_points.get(index).copied()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.glyphs.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.glyphs.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (u16, char)> + '_ {
        self.glyphs
            .iter()
            .copied()
            .zip(self.code_points.iter().copied())
    }
}
