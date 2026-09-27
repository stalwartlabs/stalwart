/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Glyph, Metrics, ToUnicode,
    cmap::{Cmap, CmapKind},
    code::{Code, CodeSplitter},
    embedded::{CidToGid, GidText, ProgramKind, program},
    program::{Cff, TrueType},
    unicode::{Verdict, verdict},
    widths::{CidWidths, VerticalAdvances},
};
use crate::pdf::{
    document::Document,
    object::{Dict, ObjRef, Object, Stream},
    tables::{CidCollection, CmapDecoder, PredefinedCmap},
};

pub(crate) const MAX_USECMAP_DEPTH: usize = 16;
const WIDTH_SCALE: f32 = 1000.0;
const DEFAULT_CODE_LEN: u8 = 2;
const HALF: f32 = 0.5;
const UCS_ORDERING: &[u8] = b"UCS";

#[derive(Debug)]
enum Encoding {
    Identity { vertical: bool },
    Embedded(Box<Cmap>),
    Predefined(PredefinedCmap),
}

#[derive(Debug)]
pub(crate) struct CompositeFont {
    splitter: CodeSplitter,
    encoding: Encoding,
    to_unicode: Option<ToUnicode>,
    collection: Option<CidCollection>,
    ucs: bool,
    gid_text: GidText,
    cid_to_gid: CidToGid,
    widths: CidWidths,
    vertical: Option<VerticalAdvances>,
}

impl Encoding {
    fn load(doc: &Document<'_>, dict: Dict<'_>, buf: &mut Vec<u8>) -> Self {
        match doc.dict_get(dict, b"Encoding") {
            Object::Name(name) => match PredefinedCmap::from_name(&name.decoded()) {
                Some(cmap) if cmap.decoder() == CmapDecoder::Identity => Encoding::Identity {
                    vertical: cmap.is_vertical(),
                },
                Some(cmap) => Encoding::Predefined(cmap),
                None => Encoding::Identity { vertical: false },
            },
            Object::Stream(stream) => Encoding::Embedded(Box::new(embedded(doc, stream, buf))),
            _ => Encoding::Identity { vertical: false },
        }
    }

    fn is_vertical(&self) -> bool {
        match self {
            Encoding::Identity { vertical } => *vertical,
            Encoding::Embedded(cmap) => {
                cmap.is_vertical() || cmap.base().is_some_and(|base| base.is_vertical())
            }
            Encoding::Predefined(cmap) => cmap.is_vertical(),
        }
    }

    fn splitter(&self) -> CodeSplitter {
        match self {
            Encoding::Identity { .. } => CodeSplitter::fixed(DEFAULT_CODE_LEN),
            Encoding::Predefined(cmap) => {
                CodeSplitter::from_ranges(cmap.codespace(), DEFAULT_CODE_LEN)
            }
            Encoding::Embedded(cmap) => {
                let ranges = match cmap.codespace() {
                    [] => cmap.base().map(|base| base.codespace()).unwrap_or_default(),
                    ranges => ranges,
                };
                let fallback = cmap
                    .uniform_source_length()
                    .and_then(|len| u8::try_from(len).ok())
                    .unwrap_or(DEFAULT_CODE_LEN);
                CodeSplitter::from_ranges(ranges, fallback)
            }
        }
    }

    fn cid(&self, code: Code) -> Option<u32> {
        match self {
            Encoding::Identity { .. } => Some(code.value),
            Encoding::Embedded(cmap) => cmap.cid(code.value, usize::from(code.len)).or_else(|| {
                cmap.base()
                    .filter(|base| base.decoder() == CmapDecoder::Identity)
                    .map(|_| code.value)
            }),
            Encoding::Predefined(_) => None,
        }
    }

    fn decoder(&self) -> Option<PredefinedCmap> {
        match self {
            Encoding::Identity { .. } => None,
            Encoding::Embedded(cmap) => cmap.base(),
            Encoding::Predefined(cmap) => Some(*cmap),
        }
        .filter(|cmap| cmap.is_text_encoding())
    }

    fn collection(&self) -> Option<CidCollection> {
        match self {
            Encoding::Identity { .. } => None,
            Encoding::Embedded(cmap) => cmap.base().and_then(|base| base.collection()),
            Encoding::Predefined(cmap) => cmap.collection(),
        }
    }

    fn heap_size(&self) -> usize {
        match self {
            Encoding::Embedded(cmap) => cmap.heap_size(),
            _ => 0,
        }
    }
}

fn embedded(doc: &Document<'_>, stream: Stream<'_>, buf: &mut Vec<u8>) -> Cmap {
    let mut chain: Vec<Stream<'_>> = vec![stream];
    let mut seen: Vec<ObjRef> = vec![stream.id];
    let mut cmap = Cmap::new(CmapKind::Encoding);
    let mut vertical = doc.get_int(stream.dict, b"WMode") == Some(1);
    while chain.len() < MAX_USECMAP_DEPTH {
        let Some(current) = chain.last() else {
            break;
        };
        match doc.dict_get(current.dict, b"UseCMap") {
            Object::Stream(parent) if !seen.contains(&parent.id) => {
                seen.push(parent.id);
                vertical |= doc.get_int(parent.dict, b"WMode") == Some(1);
                chain.push(parent);
            }
            Object::Name(name) => {
                cmap.set_base(PredefinedCmap::from_name(&name.decoded()));
                break;
            }
            _ => break,
        }
    }
    for stream in chain.iter().rev() {
        let (data, outcome) = doc.stream_bytes(*stream, buf);
        if !outcome.is_failure() {
            cmap.parse(data);
        }
    }
    if vertical {
        cmap.set_vertical();
    }
    cmap.finish();
    cmap
}

impl CompositeFont {
    pub(crate) fn load(
        doc: &Document<'_>,
        dict: Dict<'_>,
        to_unicode: Option<ToUnicode>,
        buf: &mut Vec<u8>,
    ) -> (CompositeFont, Metrics, bool) {
        let encoding = Encoding::load(doc, dict, buf);
        let descendant = doc
            .get_array(dict, b"DescendantFonts")
            .and_then(|fonts| doc.array_iter(fonts).next())
            .and_then(|font| font.as_dict())
            .filter(|font| {
                !doc.get_name(*font, b"Subtype")
                    .is_some_and(|subtype| subtype.is(b"Type0"))
            });
        let (widths, collection, ucs) = match descendant {
            Some(descendant) => {
                let (registry, ordering) = doc
                    .get_dict(descendant, b"CIDSystemInfo")
                    .map(|info| {
                        let text = |key: &[u8]| {
                            doc.dict_get(info, key)
                                .as_str()
                                .map(|value| doc.string(value).into_owned())
                                .unwrap_or_default()
                        };
                        (text(b"Registry"), text(b"Ordering"))
                    })
                    .unwrap_or_default();
                (
                    CidWidths::load(doc, descendant),
                    CidCollection::from_ordering(&registry, &ordering),
                    ordering.trim_ascii() == UCS_ORDERING,
                )
            }
            None => (CidWidths::empty(), None, false),
        };
        let vertical = encoding.is_vertical();
        let mut font = CompositeFont {
            splitter: encoding.splitter(),
            collection: collection.or_else(|| encoding.collection()),
            vertical: match (vertical, descendant) {
                (true, Some(descendant)) => Some(VerticalAdvances::load(doc, descendant)),
                (true, None) => Some(VerticalAdvances::empty()),
                _ => None,
            },
            encoding,
            to_unicode,
            ucs,
            gid_text: GidText::default(),
            cid_to_gid: CidToGid::Identity,
            widths,
        };
        if font.to_unicode.is_none()
            && font.encoding.decoder().is_none()
            && let Some(descendant) = descendant
        {
            font.load_program(doc, descendant, buf);
        }
        let metrics = Metrics {
            em_scale: 1.0,
            space_width: font.space_width(),
        };
        (font, metrics, vertical)
    }

    pub(crate) fn legacy(cmap: PredefinedCmap) -> (CompositeFont, Metrics) {
        let encoding = Encoding::Predefined(cmap);
        let font = CompositeFont {
            splitter: encoding.splitter(),
            collection: encoding.collection(),
            vertical: None,
            encoding,
            to_unicode: None,
            ucs: false,
            gid_text: GidText::default(),
            cid_to_gid: CidToGid::Identity,
            widths: CidWidths::empty(),
        };
        let metrics = Metrics {
            em_scale: 1.0,
            space_width: font.space_width(),
        };
        (font, metrics)
    }

    fn load_program(&mut self, doc: &Document<'_>, descendant: Dict<'_>, buf: &mut Vec<u8>) {
        let Some(descriptor) = doc.get_dict(descendant, b"FontDescriptor") else {
            return;
        };
        let mut map = Vec::new();
        let table = CidToGid::load(doc, descendant, &mut map);
        let Some((kind, data)) = program(doc, descriptor, buf) else {
            return;
        };
        match kind {
            ProgramKind::TrueType => {
                if let Some(font) = TrueType::parse(data) {
                    self.gid_text = GidText::from_truetype(&font, data.len());
                    self.cid_to_gid = table;
                }
            }
            ProgramKind::Cff | ProgramKind::OpenType => {
                let cff = Cff::parse(data);
                match &cff {
                    Some(cff) if cff.is_cid() => self.cid_to_gid = CidToGid::from_charset(cff),
                    Some(cff) => self.gid_text = GidText::from_cff(cff, data.len()),
                    None => self.cid_to_gid = table,
                }
                if kind == ProgramKind::OpenType
                    && let Some(font) = TrueType::parse(data)
                {
                    let text = GidText::from_truetype(&font, data.len());
                    if !text.is_empty() {
                        self.gid_text = text;
                    }
                }
            }
            ProgramKind::Type1 => {}
        }
    }

    fn space_width(&self) -> Option<f32> {
        let mut text = String::new();
        let code = Code {
            value: u32::from(b' '),
            len: DEFAULT_CODE_LEN,
            valid: true,
        };
        self.text(code, &mut text);
        (text == " ")
            .then(|| self.width(code, &text) / WIDTH_SCALE)
            .filter(|width| *width > 0.0)
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.encoding.heap_size()
            + self.to_unicode.as_ref().map_or(0, ToUnicode::heap_size)
            + self.gid_text.heap_size()
            + self.cid_to_gid.heap_size()
            + self.widths.heap_size()
            + self
                .vertical
                .as_ref()
                .map_or(0, VerticalAdvances::heap_size)
    }

    pub(crate) fn glyph(&self, bytes: &[u8], out: &mut String) -> Option<Glyph> {
        let code = self.splitter.split(bytes)?;
        if code.valid {
            self.text(code, out);
        }
        let width = match &self.vertical {
            Some(advances) => match self.encoding.cid(code) {
                Some(cid) => advances.advance(cid),
                None => advances.default_advance(),
            },
            None => self.width(code, out),
        };
        Some(Glyph {
            len: usize::from(code.len),
            width: width / WIDTH_SCALE,
            space_code: code.len == 1 && code.value == u32::from(b' '),
        })
    }

    fn width(&self, code: Code, text: &str) -> f32 {
        match self.encoding.cid(code) {
            Some(cid) => self.widths.width(cid),
            None if code.len == 1 || text.chars().all(is_narrow) && !text.is_empty() => {
                self.widths.default_width() * HALF
            }
            None => self.widths.default_width(),
        }
    }

    fn text(&self, code: Code, out: &mut String) {
        let mark = out.len();
        let accept = |out: &mut String| match verdict(out.get(mark..).unwrap_or_default()) {
            Verdict::Accept => true,
            Verdict::Space => {
                out.truncate(mark);
                out.push(' ');
                true
            }
            Verdict::Reject | Verdict::PrivateUse => {
                out.truncate(mark);
                false
            }
        };
        if let Some(to_unicode) = &self.to_unicode
            && to_unicode.unicode(code.value, out)
            && accept(out)
        {
            return;
        }
        let cid = self.encoding.cid(code);
        if cid.is_none()
            && let Some(decoder) = self.encoding.decoder()
            && decoder.decode(code, out)
            && accept(out)
        {
            return;
        }
        let Some(cid) = cid else {
            return;
        };
        if !self.gid_text.is_empty()
            && let Some(text) = self
                .cid_to_gid
                .gid(cid)
                .and_then(|gid| self.gid_text.get(gid))
        {
            out.push_str(text);
            if accept(out) {
                return;
            }
        }
        if let Some(collection) = self.collection
            && collection.unicode(cid, out)
            && accept(out)
        {
            return;
        }
        if self.ucs
            && let Some(ch) = char::from_u32(cid)
        {
            out.push(ch);
            accept(out);
        }
    }
}

fn is_narrow(ch: char) -> bool {
    matches!(u32::from(ch), 0x20..=0x7E | 0xA0..=0x24F | 0xFF61..=0xFF9F)
}
