/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    program::{Cff, TrueType},
    unicode::NameResolver,
};
use crate::pdf::{
    decode::DecodeOutcome,
    document::Document,
    object::{Dict, Object},
};

const MAX_GLYPHS: usize = 1 << 16;
const MAX_GLYPH_TEXT: usize = 64;
const TEXT_PER_PROGRAM_BYTE: usize = 2;
const MIN_TEXT_CAP: usize = 64 << 10;
const MAX_TEXT_CAP: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramKind {
    Type1,
    Cff,
    TrueType,
    OpenType,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GidText {
    gids: Vec<u16>,
    spans: Vec<(u32, u16)>,
    text: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) enum CidToGid {
    #[default]
    Identity,
    Table(Box<[u16]>),
    Charset(Box<[(u16, u16)]>),
}

pub(crate) fn has_program(descriptor: Option<Dict<'_>>) -> bool {
    descriptor.is_some_and(|descriptor| {
        [&b"FontFile"[..], b"FontFile2", b"FontFile3"]
            .iter()
            .any(|key| descriptor.contains(key))
    })
}

pub(crate) fn program<'b>(
    doc: &'b Document<'_>,
    descriptor: Dict<'b>,
    buf: &'b mut Vec<u8>,
) -> Option<(ProgramKind, &'b [u8])> {
    let (kind, stream) = [
        (&b"FontFile"[..], ProgramKind::Type1),
        (b"FontFile2", ProgramKind::TrueType),
        (b"FontFile3", ProgramKind::Cff),
    ]
    .into_iter()
    .find_map(|(key, kind)| Some((kind, doc.get_stream(descriptor, key)?)))?;
    let kind = match kind {
        ProgramKind::Cff
            if doc
                .get_name(stream.dict, b"Subtype")
                .is_some_and(|name| name.is(b"OpenType")) =>
        {
            ProgramKind::OpenType
        }
        kind => kind,
    };
    let (data, outcome) = doc.stream_bytes(stream, buf);
    (!outcome.is_failure() && outcome != DecodeOutcome::Image && !data.is_empty())
        .then_some((kind, data))
}

impl GidText {
    pub(crate) fn from_truetype(font: &TrueType<'_>, program_len: usize) -> Self {
        let mut table = GidText::default();
        let map = font.unicode_map();
        let count = font
            .num_glyphs()
            .map_or(MAX_GLYPHS, usize::from)
            .min(MAX_GLYPHS);
        let resolver = NameResolver::default();
        let cap = text_cap(program_len);
        let mut mapped = map.iter().peekable();
        for gid in (0..=u16::MAX).take(count) {
            if table.text.len() >= cap {
                break;
            }
            let mark = table.text.len();
            while mapped.next_if(|(glyph, _)| *glyph < gid).is_some() {}
            if let Some((_, ch)) = mapped.next_if(|(glyph, _)| *glyph == gid) {
                table.text.push(ch);
            } else if let Some(name) = font.glyph_name(gid) {
                resolver.resolve(name, &mut table.text);
            }
            table.close(gid, mark);
        }
        table.text.shrink_to_fit();
        table
    }

    pub(crate) fn from_cff(font: &Cff<'_>, program_len: usize) -> Self {
        let mut table = GidText::default();
        let resolver = NameResolver::default();
        let cap = text_cap(program_len);
        for gid in 0..font.num_glyphs() {
            if table.text.len() >= cap {
                break;
            }
            let mark = table.text.len();
            if let Some(name) = font.glyph_name(gid) {
                resolver.resolve(name, &mut table.text);
            }
            table.close(gid, mark);
        }
        table.text.shrink_to_fit();
        table
    }

    fn close(&mut self, gid: u16, mark: usize) {
        let len = self.text.len() - mark;
        match (u32::try_from(mark), u16::try_from(len)) {
            (Ok(start), Ok(len)) if len > 0 && usize::from(len) <= MAX_GLYPH_TEXT => {
                self.gids.push(gid);
                self.spans.push((start, len));
            }
            _ => self.text.truncate(mark),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.gids.is_empty()
    }

    pub(crate) fn get(&self, gid: u16) -> Option<&str> {
        let index = self.gids.binary_search(&gid).ok()?;
        let &(start, len) = self.spans.get(index)?;
        let start = start as usize;
        self.text.get(start..start + usize::from(len))
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.gids.capacity() * 2 + self.spans.capacity() * 8 + self.text.capacity()
    }
}

fn text_cap(program_len: usize) -> usize {
    program_len
        .saturating_mul(TEXT_PER_PROGRAM_BYTE)
        .clamp(MIN_TEXT_CAP, MAX_TEXT_CAP)
}

impl CidToGid {
    pub(crate) fn load(doc: &Document<'_>, descendant: Dict<'_>, buf: &mut Vec<u8>) -> Self {
        match doc.dict_get(descendant, b"CIDToGIDMap") {
            Object::Stream(stream) => {
                let (data, outcome) = doc.stream_bytes(stream, buf);
                if outcome.is_failure() {
                    return CidToGid::Identity;
                }
                let (pairs, _) = data.as_chunks::<2>();
                CidToGid::Table(
                    pairs
                        .iter()
                        .take(MAX_GLYPHS)
                        .map(|pair| u16::from_be_bytes(*pair))
                        .collect(),
                )
            }
            _ => CidToGid::Identity,
        }
    }

    pub(crate) fn from_charset(font: &Cff<'_>) -> Self {
        let mut pairs: Vec<(u16, u16)> = (0..font.num_glyphs())
            .filter_map(|gid| Some((font.glyph_cid(gid)?, gid)))
            .collect();
        pairs.sort_unstable();
        pairs.dedup_by_key(|(cid, _)| *cid);
        CidToGid::Charset(pairs.into_boxed_slice())
    }

    pub(crate) fn gid(&self, cid: u32) -> Option<u16> {
        match self {
            CidToGid::Identity => u16::try_from(cid).ok(),
            CidToGid::Table(table) => usize::try_from(cid)
                .ok()
                .and_then(|cid| table.get(cid))
                .copied(),
            CidToGid::Charset(pairs) => {
                let cid = u16::try_from(cid).ok()?;
                let index = pairs.binary_search_by_key(&cid, |(key, _)| *key).ok()?;
                pairs.get(index).map(|(_, gid)| *gid)
            }
        }
    }

    pub(crate) fn heap_size(&self) -> usize {
        match self {
            CidToGid::Identity => 0,
            CidToGid::Table(table) => table.len() * 2,
            CidToGid::Charset(pairs) => pairs.len() * 4,
        }
    }
}
