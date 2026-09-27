/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::super::{BuiltinEncoding, Cff, TrueType};
use super::oracle::{Tally, check_font};

macro_rules! fixture {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!("data/", $name)).as_slice(),
            include_str!(concat!("data/", $name, ".expect")),
        )
    };
}

pub(super) const FIXTURES: [(&str, &[u8], &str); 7] = [
    fixture!("cmr10-type1.t1"),
    fixture!("cmr10-type1c.cff"),
    fixture!("noto-cjk-cid.cff"),
    fixture!("noto-cjk-cid.otf"),
    fixture!("dejavu-latin.ttf"),
    fixture!("dejavu-symbol.ttf"),
    fixture!("dejavu-pair.ttc"),
];

const PFB_ASCII: u8 = 1;
const PFB_BINARY: u8 = 2;
const PFB_EOF: u8 = 3;

fn fixture(name: &str) -> &'static [u8] {
    FIXTURES
        .iter()
        .find(|(file, _, _)| *file == name)
        .map(|(_, data, _)| *data)
        .expect("known fixture")
}

fn pfb_segment(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.extend_from_slice(&[0x80, kind]);
    out.extend_from_slice(&u32::try_from(data.len()).expect("small").to_le_bytes());
    out.extend_from_slice(data);
}

#[test]
fn fixtures_match_fonttools() {
    let mut tally = Tally::default();
    for (file, data, expect) in FIXTURES {
        check_font(&mut tally, file, data, expect);
    }
    tally.report();
    assert_eq!(tally.fonts, FIXTURES.len());
    assert!(tally.checks > 20);
    assert!(tally.failures.is_empty(), "{:?}", tally.samples);
}

#[test]
fn type1_cleartext_encoding() {
    let Some(BuiltinEncoding::Custom(names)) =
        BuiltinEncoding::from_type1(fixture("cmr10-type1.t1"))
    else {
        panic!("custom encoding expected");
    };
    assert_eq!(names.get(11), Some(b"ff".as_slice()));
    assert_eq!(names.get(65), Some(b"A".as_slice()));
    assert_eq!(names.get(1), None);
    assert_eq!(names.iter().count(), 75);
}

#[test]
fn type1_pfb_wrapper() {
    let program = fixture("cmr10-type1.t1");
    let (cleartext, binary) = program.split_at(2587);
    let mut pfb = Vec::new();
    pfb_segment(&mut pfb, PFB_ASCII, cleartext);
    pfb_segment(&mut pfb, PFB_BINARY, binary);
    pfb.extend_from_slice(&[0x80, PFB_EOF]);
    assert_eq!(
        BuiltinEncoding::from_type1(&pfb),
        BuiltinEncoding::from_type1(program)
    );
    let mut binary_first = Vec::new();
    pfb_segment(&mut binary_first, PFB_BINARY, b"dup 1 /bogus put");
    pfb_segment(&mut binary_first, PFB_ASCII, cleartext);
    assert_eq!(
        BuiltinEncoding::from_type1(&binary_first),
        BuiltinEncoding::from_type1(program)
    );
}

#[test]
fn type1c_subset() {
    let cff = Cff::parse(fixture("cmr10-type1c.cff")).expect("valid CFF");
    assert!(!cff.is_cid());
    assert_eq!(cff.num_glyphs(), 41);
    assert_eq!(cff.glyph_name(0), Some(b".notdef".as_slice()));
    assert_eq!(cff.glyph_name(1), Some(b"Gamma".as_slice()));
    assert_eq!(cff.glyph_name(41), None);
    assert_eq!(cff.glyph_cid(1), None);
    let Some(BuiltinEncoding::Custom(names)) = cff.builtin_encoding() else {
        panic!("custom encoding expected");
    };
    assert_eq!(names.get(0), Some(b"Gamma".as_slice()));
    assert_eq!(names.get(10), Some(b"Omega".as_slice()));
    assert_eq!(names.get(19), Some(b"acute".as_slice()));
    assert_eq!(names.get(97), None);
}

#[test]
fn cid_keyed_cff() {
    for file in ["noto-cjk-cid.cff", "noto-cjk-cid.otf"] {
        let cff = Cff::parse(fixture(file)).expect("valid CFF");
        assert!(cff.is_cid());
        assert_eq!(cff.num_glyphs(), 9);
        let ros = cff.ros().expect("ROS");
        assert_eq!(
            (ros.registry, ros.ordering, ros.supplement),
            (b"Adobe".as_slice(), b"Identity".as_slice(), 0)
        );
        assert_eq!(cff.glyph_cid(0), Some(0));
        assert_eq!(cff.glyph_cid(1), Some(1470));
        assert_eq!(cff.glyph_cid(8), Some(58199));
        assert_eq!(cff.glyph_cid(9), None);
        assert_eq!(cff.glyph_name(1), None);
        assert_eq!(cff.builtin_encoding(), None);
    }
    let font = TrueType::parse(fixture("noto-cjk-cid.otf")).expect("valid sfnt");
    assert_eq!(font.unicode_map().get(6), Some('漢'));
}

#[test]
fn truetype_subset() {
    let font = TrueType::parse(fixture("dejavu-latin.ttf")).expect("valid sfnt");
    assert_eq!(font.num_glyphs(), Some(30));
    assert_eq!(font.glyph_name(4), Some(b"H".as_slice()));
    assert_eq!(font.glyph_name(28), Some(b"Euro".as_slice()));
    assert_eq!(font.glyph_name(30), None);
    let unicode = font.unicode_cmap().expect("unicode cmap");
    assert_eq!(unicode.glyph(0x1D400), Some(4));
    assert_eq!(unicode.glyph(u32::from('€')), Some(28));
    assert_eq!(unicode.glyph(u32::from('Z')), None);
    let map = font.unicode_map();
    assert_eq!(map.get(4), Some('H'));
    assert_eq!(map.get(28), Some('€'));
    assert_eq!(map.get(0), None);
    assert_eq!(map.len(), 22);
    assert_eq!(font.symbolic_glyph(b'H'), Some(4));
    let pair = TrueType::parse(fixture("dejavu-pair.ttc")).expect("valid collection");
    assert_eq!(pair.unicode_map(), map);
}

#[test]
fn symbolic_truetype() {
    let font = TrueType::parse(fixture("dejavu-symbol.ttf")).expect("valid sfnt");
    assert_eq!(font.num_glyphs(), Some(7));
    assert!(font.unicode_cmap().is_none());
    assert!(font.unicode_map().is_empty());
    assert_eq!(font.glyph_name(1), None);
    assert_eq!(font.symbolic_glyph(b'1'), Some(1));
    assert_eq!(font.symbolic_glyph(b'A'), Some(4));
    assert_eq!(font.symbolic_glyph(b'C'), Some(6));
    assert_eq!(font.symbolic_glyph(b'Z'), None);
    let big5 = font
        .cmap()
        .and_then(|cmap| cmap.subtable(3, 4))
        .expect("format 2");
    assert_eq!(big5.glyph(0x41), Some(4));
    assert_eq!(big5.glyph(0xA440), Some(5));
    assert_eq!(big5.glyph(0xA441), Some(6));
    assert_eq!(big5.glyph(0xA442), None);
    assert_eq!(big5.glyph(0xA4), None);
}
