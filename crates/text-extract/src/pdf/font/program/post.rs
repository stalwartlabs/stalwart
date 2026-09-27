/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::post_data::{MAC_GLYPH_NAMES, MAC_GLYPH_OFFSETS};
use super::read::{NameTable, ReadBytes, Reader};

const VERSION_1: u32 = 0x0001_0000;
const VERSION_2: u32 = 0x0002_0000;
const VERSION_2_5: u32 = 0x0002_5000;
const HEADER_LEN: usize = 32;
const MAC_GLYPH_COUNT: usize = 258;

const MAC_GLYPHS: NameTable = NameTable {
    names: MAC_GLYPH_NAMES,
    offsets: &MAC_GLYPH_OFFSETS,
};

#[derive(Debug, Clone)]
pub(crate) struct Post<'x> {
    names: PostNames<'x>,
}

#[derive(Debug, Clone)]
enum PostNames<'x> {
    Standard,
    Indexed {
        indices: &'x [[u8; 2]],
        strings: &'x [u8],
        offsets: Box<[u32]>,
    },
    Shifted(&'x [u8]),
}

impl<'x> Post<'x> {
    pub(crate) fn parse(data: &'x [u8]) -> Option<Self> {
        let names = match data.be_u32(0)? {
            VERSION_1 => PostNames::Standard,
            VERSION_2 => {
                let mut reader = Reader::at(data, HEADER_LEN)?;
                let count = usize::from(reader.u16()?);
                let (indices, _) = reader.remaining().as_chunks::<2>();
                let indices = indices.get(..count).unwrap_or(indices);
                let strings = reader
                    .remaining()
                    .get(indices.len() * 2..)
                    .unwrap_or_default();
                PostNames::Indexed {
                    indices,
                    strings,
                    offsets: pascal_string_offsets(strings),
                }
            }
            VERSION_2_5 => {
                let mut reader = Reader::at(data, HEADER_LEN)?;
                let count = usize::from(reader.u16()?);
                let offsets = reader.remaining();
                PostNames::Shifted(offsets.get(..count).unwrap_or(offsets))
            }
            _ => return None,
        };
        Some(Self { names })
    }

    pub(crate) fn glyph_name(&self, glyph: u16) -> Option<&'x [u8]> {
        let glyph = usize::from(glyph);
        match &self.names {
            PostNames::Standard => MAC_GLYPHS.get(glyph),
            PostNames::Indexed {
                indices,
                strings,
                offsets,
            } => {
                let index = usize::from(u16::from_be_bytes(*indices.get(glyph)?));
                match index.checked_sub(MAC_GLYPH_COUNT) {
                    None => MAC_GLYPHS.get(index),
                    Some(string) => {
                        let at = usize::try_from(*offsets.get(string)?).ok()?;
                        let (&len, rest) = strings.get(at..)?.split_first()?;
                        rest.get(..usize::from(len))
                    }
                }
            }
            PostNames::Shifted(offsets) => {
                let shift = i8::from_be_bytes([*offsets.get(glyph)?]);
                let index = glyph.checked_add_signed(isize::from(shift))?;
                MAC_GLYPHS.get(index)
            }
        }
    }
}

fn pascal_string_offsets(strings: &[u8]) -> Box<[u32]> {
    let mut offsets = Vec::new();
    let mut at = 0usize;
    while let Some(&len) = strings.get(at) {
        let Ok(offset) = u32::try_from(at) else {
            break;
        };
        offsets.push(offset);
        at += usize::from(len) + 1;
    }
    offsets.into_boxed_slice()
}
