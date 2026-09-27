/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::encoding::STD_GLYPHS;
use super::glyphs::{all_names, glyph_index};
use super::{
    BaseEncoding, CodeRadix, GlyphCode, StandardFont, glyph_name_code, glyph_unicode, pdfdoc_char,
    zapf_dingbats_unicode,
};

const ALL_ENCODINGS: [BaseEncoding; 7] = [
    BaseEncoding::Standard,
    BaseEncoding::WinAnsi,
    BaseEncoding::MacRoman,
    BaseEncoding::MacExpert,
    BaseEncoding::Symbol,
    BaseEncoding::ZapfDingbats,
    BaseEncoding::Expert,
];

fn unicode_of(name: &str) -> Option<String> {
    let mut out = String::new();
    glyph_unicode(name.as_bytes(), &mut out).then_some(out)
}

fn dingbat_of(name: &str) -> Option<String> {
    let mut out = String::new();
    zapf_dingbats_unicode(name.as_bytes(), &mut out).then_some(out)
}

#[test]
fn encoding_names() {
    let names: [(&[u8], BaseEncoding); 7] = [
        (b"StandardEncoding", BaseEncoding::Standard),
        (b"WinAnsiEncoding", BaseEncoding::WinAnsi),
        (b"MacRomanEncoding", BaseEncoding::MacRoman),
        (b"MacExpertEncoding", BaseEncoding::MacExpert),
        (b"SymbolSetEncoding", BaseEncoding::Symbol),
        (b"ZapfDingbatsEncoding", BaseEncoding::ZapfDingbats),
        (b"ExpertEncoding", BaseEncoding::Expert),
    ];
    for (name, encoding) in names {
        assert_eq!(BaseEncoding::from_name(name), Some(encoding));
    }
    assert_eq!(BaseEncoding::from_name(b"Identity-H"), None);
}

#[test]
fn encoding_code_points() {
    let cases = [
        (BaseEncoding::Standard, 0x41, Some('A'), Some("A")),
        (
            BaseEncoding::Standard,
            0x27,
            Some('\u{2019}'),
            Some("quoteright"),
        ),
        (
            BaseEncoding::Standard,
            0x60,
            Some('\u{2018}'),
            Some("quoteleft"),
        ),
        (
            BaseEncoding::Standard,
            0xA4,
            Some('\u{2044}'),
            Some("fraction"),
        ),
        (BaseEncoding::Standard, 0xAE, Some('\u{FB01}'), Some("fi")),
        (BaseEncoding::Standard, 0x80, None, None),
        (BaseEncoding::Standard, 0x10, None, None),
        (BaseEncoding::WinAnsi, 0x80, Some('\u{20AC}'), Some("Euro")),
        (
            BaseEncoding::WinAnsi,
            0x7F,
            Some('\u{2022}'),
            Some("bullet"),
        ),
        (
            BaseEncoding::WinAnsi,
            0x81,
            Some('\u{2022}'),
            Some("bullet"),
        ),
        (
            BaseEncoding::WinAnsi,
            0x9D,
            Some('\u{2022}'),
            Some("bullet"),
        ),
        (
            BaseEncoding::WinAnsi,
            0x93,
            Some('\u{201C}'),
            Some("quotedblleft"),
        ),
        (BaseEncoding::WinAnsi, 0xA0, Some(' '), Some("space")),
        (BaseEncoding::WinAnsi, 0xAD, Some('-'), Some("hyphen")),
        (BaseEncoding::WinAnsi, 0xE9, Some('\u{E9}'), Some("eacute")),
        (BaseEncoding::MacRoman, 0x8E, Some('\u{E9}'), Some("eacute")),
        (
            BaseEncoding::MacRoman,
            0xDB,
            Some('\u{A4}'),
            Some("currency"),
        ),
        (BaseEncoding::MacRoman, 0xCA, Some(' '), Some("space")),
        (BaseEncoding::MacRoman, 0xF0, None, None),
        (BaseEncoding::MacRoman, 0xDE, Some('\u{FB01}'), Some("fi")),
        (
            BaseEncoding::MacExpert,
            0x2F,
            Some('\u{2044}'),
            Some("fraction"),
        ),
        (BaseEncoding::MacExpert, 0x56, Some('\u{FB00}'), Some("ff")),
        (BaseEncoding::Expert, 0x2C, Some(','), Some("comma")),
        (BaseEncoding::Symbol, 0x61, Some('\u{3B1}'), Some("alpha")),
        (BaseEncoding::Symbol, 0x41, Some('\u{391}'), Some("Alpha")),
        (BaseEncoding::Symbol, 0xA0, Some('\u{20AC}'), Some("Euro")),
        (
            BaseEncoding::Symbol,
            0x22,
            Some('\u{2200}'),
            Some("universal"),
        ),
        (
            BaseEncoding::ZapfDingbats,
            0x21,
            Some('\u{2701}'),
            Some("a1"),
        ),
        (
            BaseEncoding::ZapfDingbats,
            0x6C,
            Some('\u{25CF}'),
            Some("a71"),
        ),
        (BaseEncoding::ZapfDingbats, 0x20, Some(' '), Some("space")),
    ];
    for (encoding, code, unicode, name) in cases {
        assert_eq!(encoding.unicode(code), unicode, "{encoding:?} {code:#x}");
        if let Some(name) = name {
            assert_eq!(
                encoding.glyph_name(code),
                Some(name),
                "{encoding:?} {code:#x}"
            );
        }
    }
}

#[test]
fn encodings_agree_with_glyph_list() {
    for encoding in ALL_ENCODINGS {
        for code in 0..=u8::MAX {
            let name = encoding.glyph_name(code);
            let unicode = encoding.unicode(code);
            assert_eq!(name.is_some(), unicode.is_some(), "{encoding:?} {code:#x}");
            if let (Some(name), Some(unicode)) = (name, unicode) {
                let mut expected = String::new();
                expected.push(unicode);
                let resolved = match encoding {
                    BaseEncoding::ZapfDingbats => dingbat_of(name),
                    _ => unicode_of(name),
                };
                assert_eq!(resolved, Some(expected), "{encoding:?} {name}");
            }
        }
    }
}

#[test]
fn std_glyphs_resolve() {
    for index in 0..STD_GLYPHS.len() {
        let name = STD_GLYPHS.get(index).unwrap_or_default();
        assert_eq!(glyph_index(name.as_bytes()), None, "{name}");
        let mut out = String::new();
        assert!(zapf_dingbats_unicode(name.as_bytes(), &mut out), "{name}");
        assert_eq!(out.chars().count(), 1, "{name}");
        assert_eq!(STD_GLYPHS.find(name.as_bytes()), Some(index));
    }
}

#[test]
fn glyph_list_roundtrip() {
    let names = all_names();
    assert!(names.len() + STD_GLYPHS.len() > 4500);
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    for (index, name) in names.iter().enumerate() {
        assert_eq!(glyph_index(name.as_bytes()), Some(index), "{name}");
        let mut out = String::new();
        assert!(glyph_unicode(name.as_bytes(), &mut out), "{name}");
        assert!(!out.is_empty(), "{name}");
    }
    assert_eq!(glyph_index(b"Aa"), None);
    assert_eq!(glyph_index(b"zzzzzz"), None);
    assert_eq!(glyph_index(b"0"), None);
}

#[test]
fn glyph_names() {
    let cases = [
        ("A", Some("A")),
        ("Aacute", Some("\u{C1}")),
        ("afii10017", Some("\u{410}")),
        ("afii57636", Some("\u{20AA}")),
        ("uni00410042", Some("AB")),
        ("uni00e9", Some("\u{E9}")),
        ("u1F600", Some("\u{1F600}")),
        ("u00E9", Some("\u{E9}")),
        ("f_f_i", Some("ffi")),
        ("f_f", Some("ff")),
        ("a.sc", Some("a")),
        ("T_h", Some("Th")),
        ("zero.oldstyle", Some("0")),
        ("uni0041.alt", Some("A")),
        ("dalethatafpatah", Some("\u{5D3}\u{5B2}")),
        ("a1", None),
        ("a191", None),
        ("a1_a2", None),
        ("f_a1", None),
        ("parenleftmath", Some("(")),
        ("epsilon1", Some("\u{3B5}")),
        ("angbracketleftbig", Some("\u{2329}")),
        ("summationdisplay", Some("\u{2211}")),
        ("space", Some(" ")),
        ("f_bogus", None),
        ("uniD800", None),
        ("uniDFFF0041", None),
        ("u110000", None),
        ("u1f600", None),
        ("u12", None),
        ("uni004", None),
        (".notdef", None),
        ("", None),
        ("_", None),
        ("bogusname", None),
        ("g0041", None),
        ("cid1234", None),
        ("glyph12", None),
    ];
    for (name, expected) in cases {
        assert_eq!(unicode_of(name).as_deref(), expected, "{name}");
    }
}

#[test]
fn dingbat_names() {
    let cases = [
        ("a1", Some("\u{2701}")),
        ("a191", Some("\u{27BE}")),
        ("a206", Some("\u{2770}")),
        ("a12.alt", Some("\u{261E}")),
        ("space", Some(" ")),
        ("A", Some("A")),
        ("a0", None),
        ("a01", None),
        ("a207", None),
        ("a1000", None),
        ("a", Some("a")),
    ];
    for (name, expected) in cases {
        assert_eq!(dingbat_of(name).as_deref(), expected, "{name}");
    }
}

#[test]
fn glyph_codes() {
    let cases: [(&[u8], CodeRadix, Option<GlyphCode>); 13] = [
        (b"G41", CodeRadix::Decimal, Some(GlyphCode::Code(0x41))),
        (b"g0041", CodeRadix::Decimal, Some(GlyphCode::Code(0x41))),
        (b"c65", CodeRadix::Decimal, Some(GlyphCode::Code(65))),
        (b"C120", CodeRadix::Decimal, Some(GlyphCode::Code(120))),
        (b"c65", CodeRadix::Hex, Some(GlyphCode::Code(0x65))),
        (b"c4F", CodeRadix::Decimal, Some(GlyphCode::NeedsHex)),
        (b"c4F", CodeRadix::Hex, Some(GlyphCode::Code(0x4F))),
        (b"c00", CodeRadix::Decimal, None),
        (b"c12", CodeRadix::Decimal, None),
        (b"c130", CodeRadix::Decimal, None),
        (b"cXY", CodeRadix::Decimal, None),
        (b"G4", CodeRadix::Decimal, None),
        (b"a12", CodeRadix::Decimal, None),
    ];
    for (name, radix, expected) in cases {
        assert_eq!(glyph_name_code(name, radix), expected, "{name:?}");
    }
}

#[test]
fn pdfdoc() {
    let cases = [
        (b'A', Some('A')),
        (b'\n', Some('\n')),
        (0x00, None),
        (0x17, None),
        (0x18, Some('\u{2D8}')),
        (0x1F, Some('\u{2DC}')),
        (0x7F, None),
        (0x80, Some('\u{2022}')),
        (0x8A, Some('\u{2212}')),
        (0x93, Some('\u{FB01}')),
        (0x9E, Some('\u{17E}')),
        (0x9F, None),
        (0xA0, Some('\u{20AC}')),
        (0xE9, Some('\u{E9}')),
        (0xFF, Some('\u{FF}')),
    ];
    for (byte, expected) in cases {
        assert_eq!(pdfdoc_char(byte), expected, "{byte:#x}");
    }
}

#[test]
fn standard_widths() {
    let cases: [(StandardFont, &[u8], Option<u16>); 12] = [
        (StandardFont::Helvetica, b"A", Some(667)),
        (StandardFont::HelveticaOblique, b"A", Some(667)),
        (StandardFont::HelveticaBold, b"A", Some(722)),
        (StandardFont::Courier, b"A", Some(600)),
        (StandardFont::CourierBoldOblique, b"anything", Some(600)),
        (StandardFont::TimesRoman, b"space", Some(250)),
        (StandardFont::TimesBold, b"W", Some(1000)),
        (StandardFont::TimesItalic, b"Euro", Some(500)),
        (StandardFont::TimesBoldItalic, b"alpha", None),
        (StandardFont::Symbol, b"alpha", Some(631)),
        (StandardFont::ZapfDingbats, b"a1", Some(974)),
        (StandardFont::ZapfDingbats, b"A", None),
    ];
    for (font, name, expected) in cases {
        assert_eq!(font.width(name), expected, "{font:?} {name:?}");
    }
}

#[test]
fn standard_font_aliases() {
    let cases: [(&[u8], Option<StandardFont>); 22] = [
        (b"Helvetica", Some(StandardFont::Helvetica)),
        (b"Times-Roman", Some(StandardFont::TimesRoman)),
        (b"ZapfDingbats", Some(StandardFont::ZapfDingbats)),
        (b"Dingbats", Some(StandardFont::ZapfDingbats)),
        (b"Symbol", Some(StandardFont::Symbol)),
        (b"Arial", Some(StandardFont::Helvetica)),
        (b"ArialMT", Some(StandardFont::Helvetica)),
        (b"Arial-BoldMT", Some(StandardFont::HelveticaBold)),
        (b"Arial,Bold", Some(StandardFont::HelveticaBold)),
        (
            b"Arial,BoldItalic",
            Some(StandardFont::HelveticaBoldOblique),
        ),
        (b"Arial-ItalicMT", Some(StandardFont::HelveticaOblique)),
        (
            b"Arial-BoldItalicMT",
            Some(StandardFont::HelveticaBoldOblique),
        ),
        (b"ABCDEF+Arial-BoldMT", Some(StandardFont::HelveticaBold)),
        (b"TimesNewRoman", Some(StandardFont::TimesRoman)),
        (b"TimesNewRomanPS-BoldMT", Some(StandardFont::TimesBold)),
        (b"TimesNewRoman,Italic", Some(StandardFont::TimesItalic)),
        (b"Times New Roman", Some(StandardFont::TimesRoman)),
        (b"CourierNewPSMT", Some(StandardFont::Courier)),
        (b"CourierNew,Bold", Some(StandardFont::CourierBold)),
        (b"Helvetica-Narrow-Bold", Some(StandardFont::HelveticaBold)),
        (b"abcdef+Arial", None),
        (b"Calibri", None),
    ];
    for (name, expected) in cases {
        assert_eq!(StandardFont::from_base_font(name), expected, "{name:?}");
    }
}

#[test]
fn builtin_encodings() {
    assert_eq!(
        StandardFont::Symbol.builtin_encoding(),
        BaseEncoding::Symbol
    );
    assert_eq!(
        StandardFont::ZapfDingbats.builtin_encoding(),
        BaseEncoding::ZapfDingbats
    );
    assert_eq!(
        StandardFont::TimesBold.builtin_encoding(),
        BaseEncoding::Standard
    );
    assert!(StandardFont::Symbol.is_symbolic());
    assert!(StandardFont::ZapfDingbats.is_symbolic());
    assert!(!StandardFont::Courier.is_symbolic());
}
