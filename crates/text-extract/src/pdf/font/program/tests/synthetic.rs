/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use super::super::{BuiltinEncoding, Cff, Cmap, Post, Sfnt, TrueType};

const TIME_BUDGET: Duration = Duration::from_secs(2);

fn u16be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn u32be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn cff_index(items: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    u16be(&mut out, u16::try_from(items.len()).expect("small"));
    if items.is_empty() {
        return out;
    }
    out.push(4);
    let mut offset = 1u32;
    u32be(&mut out, offset);
    for item in items {
        offset += u32::try_from(item.len()).expect("small");
        u32be(&mut out, offset);
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn dict_int(out: &mut Vec<u8>, value: i32) {
    out.push(29);
    out.extend_from_slice(&value.to_be_bytes());
}

struct CffParts<'a> {
    charset: Option<&'a [u8]>,
    charset_offset: i32,
    encoding: Option<&'a [u8]>,
    encoding_offset: i32,
    glyphs: usize,
    ros: bool,
    strings: &'a [&'a [u8]],
}

impl Default for CffParts<'_> {
    fn default() -> Self {
        Self {
            charset: None,
            charset_offset: 0,
            encoding: None,
            encoding_offset: 0,
            glyphs: 4,
            ros: false,
            strings: &[b"custom0", b"custom1"],
        }
    }
}

fn build_cff(parts: &CffParts<'_>) -> Vec<u8> {
    let names = cff_index(&[b"Test"]);
    let strings = cff_index(parts.strings);
    let globals = cff_index(&[]);
    let charstring = [14u8];
    let charstrings = cff_index(&vec![charstring.as_slice(); parts.glyphs]);
    let dict_len = 6 * 3 + if parts.ros { 5 + 5 + 5 + 2 } else { 0 } + 1 + 2;
    let top_len = 2 + 1 + 8 + dict_len;
    let base = 4 + names.len() + top_len + strings.len() + globals.len();
    let charstrings_at = i32::try_from(base).expect("small");
    let charset_at = charstrings_at + i32::try_from(charstrings.len()).expect("small");
    let encoding_at =
        charset_at + i32::try_from(parts.charset.map_or(0, <[u8]>::len)).expect("small");
    let mut dict = Vec::new();
    if parts.ros {
        dict_int(&mut dict, 391);
        dict_int(&mut dict, 392);
        dict_int(&mut dict, 7);
        dict.extend_from_slice(&[12, 30]);
    }
    dict.extend_from_slice(&[30, 0x1a, 0x5f]);
    dict_int(&mut dict, charstrings_at);
    dict.push(17);
    dict_int(
        &mut dict,
        if parts.charset.is_some() {
            charset_at
        } else {
            parts.charset_offset
        },
    );
    dict.push(15);
    dict_int(
        &mut dict,
        if parts.encoding.is_some() {
            encoding_at
        } else {
            parts.encoding_offset
        },
    );
    dict.push(16);
    assert_eq!(dict.len(), dict_len);
    let top = cff_index(&[&dict]);
    assert_eq!(top.len(), top_len);
    let mut out = vec![1, 0, 4, 4];
    for part in [&names, &top, &strings, &globals, &charstrings] {
        out.extend_from_slice(part);
    }
    out.extend_from_slice(parts.charset.unwrap_or_default());
    out.extend_from_slice(parts.encoding.unwrap_or_default());
    out
}

#[test]
fn type1_tokenizer_variants() {
    let program = b"%!FontType1\n% /Encoding 9 array\n/Notice (dup 68 /D put \\) (nested) ) readonly def\n\
        /Encoding 256 array\r\n0 1 255{1 index exch/.notdef put}for\rdup 8#101/A put dup 16#42 /B\tput\n\
        dup  67\n/C put dup 300 /X put dup -1 /Y put dup 36#1Z /Z put dup 99999999999999999999999 /W put\n\
        dup 2#102 /V put dup 70 <4142> put readonly def currentfile eexec dup 69 /E put";
    let Some(BuiltinEncoding::Custom(names)) = BuiltinEncoding::from_type1(program) else {
        panic!("custom encoding expected");
    };
    let got: Vec<_> = names.iter().collect();
    assert_eq!(
        got,
        [
            (65, b"A".as_slice()),
            (66, b"B".as_slice()),
            (67, b"C".as_slice()),
            (71, b"Z".as_slice())
        ]
    );
    assert_eq!(
        BuiltinEncoding::from_type1(b"/FontName /X def /Encoding StandardEncoding def"),
        Some(BuiltinEncoding::Standard)
    );
    assert_eq!(
        BuiltinEncoding::from_type1(b"/Encoding ISOLatin1Encoding def"),
        None
    );
    assert_eq!(
        BuiltinEncoding::from_type1(
            b"/FontName /X def currentfile eexec /Encoding StandardEncoding"
        ),
        None
    );
    assert_eq!(BuiltinEncoding::from_type1(b""), None);
    assert_eq!(
        BuiltinEncoding::from_type1(b"\x80\x01\xff\xff\xff\xff/Encoding StandardEncoding"),
        Some(BuiltinEncoding::Standard)
    );
    assert_eq!(BuiltinEncoding::from_type1(b"\x80\x07"), None);
    let unterminated = BuiltinEncoding::from_type1(b"/Encoding 256 array dup 32 /space put");
    assert!(
        matches!(unterminated, Some(BuiltinEncoding::Custom(names)) if names.get(32) == Some(b"space".as_slice()))
    );
}

#[test]
fn cff_charsets_and_encodings() {
    let charset = [2, 0, 5, 0, 1, 1, 0x87, 0, 0];
    let encoding = [0x81, 2, 65, 1, 97, 0, 1, 200, 1, 0x88];
    let cff_bytes = build_cff(&CffParts {
        charset: Some(&charset),
        encoding: Some(&encoding),
        glyphs: 5,
        ..CffParts::default()
    });
    let cff = Cff::parse(&cff_bytes).expect("valid CFF");
    assert_eq!(cff.num_glyphs(), 5);
    let names: Vec<_> = (0..6).map(|glyph| cff.glyph_name(glyph)).collect();
    assert_eq!(
        names,
        [
            Some(b".notdef".as_slice()),
            Some(b"dollar".as_slice()),
            Some(b"percent".as_slice()),
            Some(b"custom0".as_slice()),
            None,
            None
        ]
    );
    let Some(BuiltinEncoding::Custom(codes)) = cff.builtin_encoding() else {
        panic!("custom encoding expected");
    };
    let got: Vec<_> = codes.iter().collect();
    assert_eq!(
        got,
        [
            (65, b"dollar".as_slice()),
            (66, b"percent".as_slice()),
            (97, b"custom0".as_slice()),
            (200, b"custom1".as_slice())
        ]
    );

    let format0 = [0, 0, 3, 0, 2, 1, 0x87];
    let encoding0 = [0, 3, 0x41, 0x42, 0x43];
    let cff_bytes = build_cff(&CffParts {
        charset: Some(&format0),
        encoding: Some(&encoding0),
        ..CffParts::default()
    });
    let cff = Cff::parse(&cff_bytes).expect("valid CFF");
    assert_eq!(cff.glyph_name(3), Some(b"custom0".as_slice()));
    let Some(BuiltinEncoding::Custom(codes)) = cff.builtin_encoding() else {
        panic!("custom encoding expected");
    };
    assert_eq!(codes.get(0x41), Some(b"quotedbl".as_slice()));
    assert_eq!(codes.get(0x42), Some(b"exclam".as_slice()));

    for (offset, first, encoding) in [
        (0, b"space".as_slice(), BuiltinEncoding::Standard),
        (1, b"space".as_slice(), BuiltinEncoding::Expert),
        (2, b"space".as_slice(), BuiltinEncoding::Standard),
    ] {
        let cff_bytes = build_cff(&CffParts {
            charset_offset: offset,
            encoding_offset: if offset == 1 { 1 } else { 0 },
            ..CffParts::default()
        });
        let cff = Cff::parse(&cff_bytes).expect("valid CFF");
        assert_eq!(cff.glyph_name(1), Some(first));
        assert_eq!(cff.builtin_encoding(), Some(encoding));
    }
    let expert_bytes = build_cff(&CffParts {
        charset_offset: 1,
        ..CffParts::default()
    });
    let expert = Cff::parse(&expert_bytes).expect("valid CFF");
    assert_eq!(expert.glyph_name(2), Some(b"exclamsmall".as_slice()));
    let subset_bytes = build_cff(&CffParts {
        charset_offset: 2,
        ..CffParts::default()
    });
    let subset = Cff::parse(&subset_bytes).expect("valid CFF");
    assert_eq!(subset.glyph_name(2), Some(b"dollaroldstyle".as_slice()));
}

#[test]
fn cff_cid_and_absurd_values() {
    let charset = [2, 0, 100, 0xFF, 0xFF];
    let cff_bytes = build_cff(&CffParts {
        charset: Some(&charset),
        glyphs: 3,
        ros: true,
        ..CffParts::default()
    });
    let cff = Cff::parse(&cff_bytes).expect("valid CFF");
    assert!(cff.is_cid());
    let ros = cff.ros().expect("ROS");
    assert_eq!(
        (ros.registry, ros.ordering, ros.supplement),
        (b"custom0".as_slice(), b"custom1".as_slice(), 7)
    );
    assert_eq!(cff.glyph_cid(2), Some(101));
    assert_eq!(cff.glyph_cid(3), None);
    assert_eq!(cff.glyph_name(2), None);

    let identity_bytes = build_cff(&CffParts {
        ros: true,
        ..CffParts::default()
    });
    let identity = Cff::parse(&identity_bytes).expect("valid CFF");
    assert_eq!(identity.glyph_cid(3), Some(3));

    let mut bad_charstrings = build_cff(&CffParts::default());
    let at = bad_charstrings.len() - 4 * 3 - 2 - 4 * 5 - 1;
    bad_charstrings.truncate(at);
    bad_charstrings.extend_from_slice(&[0xFF, 0xFF, 4, 0, 0, 0, 1]);
    assert!(Cff::parse(&bad_charstrings).is_none());

    let mut huge_index = vec![1, 0, 4, 4, 0xFF, 0xFF, 4];
    huge_index.extend_from_slice(&[0; 32]);
    assert!(Cff::parse(&huge_index).is_none());
    assert!(Cff::parse(&[1, 0, 0xFF, 4]).is_none());
    assert!(Cff::parse(&[2, 0, 5, 4, 0, 0]).is_none());
    assert!(Cff::parse(&[]).is_none());

    let bad_offset_bytes = build_cff(&CffParts {
        charset_offset: i32::MAX,
        ..CffParts::default()
    });
    let bad_offset = Cff::parse(&bad_offset_bytes);
    assert!(bad_offset.is_none());
    let bad_encoding_bytes = build_cff(&CffParts {
        encoding_offset: 1_000_000,
        ..CffParts::default()
    });
    let bad_encoding = Cff::parse(&bad_encoding_bytes).expect("valid CFF");
    assert_eq!(bad_encoding.builtin_encoding(), None);
    let negative_bytes = build_cff(&CffParts {
        encoding_offset: -5,
        ..CffParts::default()
    });
    let negative = Cff::parse(&negative_bytes).expect("valid CFF");
    assert_eq!(negative.glyph_name(1), Some(b"space".as_slice()));
    assert_eq!(negative.builtin_encoding(), None);
}

fn cmap_table(subtables: &[(u16, u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    u16be(&mut out, 0);
    u16be(&mut out, u16::try_from(subtables.len()).expect("small"));
    let mut offset = 4 + 8 * subtables.len();
    for (platform, encoding, data) in subtables {
        u16be(&mut out, *platform);
        u16be(&mut out, *encoding);
        u32be(&mut out, u32::try_from(offset).expect("small"));
        offset += data.len();
    }
    for (_, _, data) in subtables {
        out.extend_from_slice(data);
    }
    out
}

fn format12(groups: &[(u32, u32, u32)], declared: u32) -> Vec<u8> {
    let mut out = Vec::new();
    u16be(&mut out, 12);
    u16be(&mut out, 0);
    u32be(
        &mut out,
        u32::try_from(16 + 12 * groups.len()).expect("small"),
    );
    u32be(&mut out, 0);
    u32be(&mut out, declared);
    for &(start, end, glyph) in groups {
        u32be(&mut out, start);
        u32be(&mut out, end);
        u32be(&mut out, glyph);
    }
    out
}

fn format4(segments: &[(u16, u16, i16, u16)], glyph_ids: &[u16], declared_x2: u16) -> Vec<u8> {
    let mut out = Vec::new();
    u16be(&mut out, 4);
    u16be(&mut out, 0);
    u16be(&mut out, 0);
    u16be(&mut out, declared_x2);
    out.extend_from_slice(&[0; 6]);
    segments
        .iter()
        .for_each(|segment| u16be(&mut out, segment.1));
    u16be(&mut out, 0);
    segments
        .iter()
        .for_each(|segment| u16be(&mut out, segment.0));
    segments
        .iter()
        .for_each(|segment| u16be(&mut out, segment.2.cast_unsigned()));
    segments
        .iter()
        .for_each(|segment| u16be(&mut out, segment.3));
    glyph_ids.iter().for_each(|glyph| u16be(&mut out, *glyph));
    let len = u16::try_from(out.len()).expect("small");
    out.splice(2..4, len.to_be_bytes());
    out
}

#[test]
fn cmap_formats_and_hostile_ranges() {
    let segments = [
        (0x41, 0x43, 0, 4 * 2),
        (0x61, 0x62, -0x60, 0),
        (0x62, 0x64, 10, 0),
        (0xFFFF, 0xFFFF, 1, 0),
    ];
    let table = cmap_table(&[(3, 1, format4(&segments, &[7, 0, 9], 8))]);
    let cmap = Cmap::parse(&table).expect("cmap");
    let subtable = cmap.unicode().expect("unicode");
    let lookups: Vec<_> = (0x40..0x66)
        .filter_map(|code| Some((code, subtable.glyph(code)?)))
        .collect();
    assert_eq!(
        lookups,
        [
            (0x41, 7),
            (0x43, 9),
            (0x61, 1),
            (0x62, 2),
            (0x63, 109),
            (0x64, 110)
        ]
    );
    let mut mappings = Vec::new();
    subtable.for_each_mapping(0x1_0000, |code, glyph| mappings.push((code, glyph)));
    assert_eq!(mappings, lookups);

    let truncated = cmap_table(&[(3, 1, format4(&segments, &[], 0xFFFE))]);
    let subtable = Cmap::parse(&truncated)
        .and_then(|cmap| cmap.unicode())
        .expect("unicode");
    assert_eq!(subtable.glyph(0x41), None);
    subtable.for_each_mapping(0x1_0000, |_, _| {});

    let huge = vec![(0, 0x10_FFFF, 0); 5000];
    let table = cmap_table(&[(3, 10, format12(&huge, u32::MAX))]);
    let started = Instant::now();
    let subtable = Cmap::parse(&table)
        .and_then(|cmap| cmap.unicode())
        .expect("unicode");
    let mut count = 0usize;
    subtable.for_each_mapping(0x1_0000, |_, _| count += 1);
    assert_eq!(count, 0xFFFF);
    assert_eq!(subtable.glyph(0x41), Some(0x41));
    assert_eq!(subtable.glyph(0x10_0000), None);
    assert!(started.elapsed() < TIME_BUDGET);

    let mut sfnt = Vec::new();
    u32be(&mut sfnt, 0x0001_0000);
    u16be(&mut sfnt, 1);
    sfnt.extend_from_slice(&[0; 6]);
    sfnt.extend_from_slice(b"cmap");
    u32be(&mut sfnt, 0);
    u32be(&mut sfnt, 28);
    u32be(&mut sfnt, u32::try_from(table.len()).expect("small"));
    sfnt.extend_from_slice(&table);
    let started = Instant::now();
    let map = TrueType::parse(&sfnt).expect("sfnt").unicode_map();
    assert_eq!(map.len(), 0xFFFF - 0x800);
    assert_eq!(map.get(0x41), Some('A'));
    assert!(started.elapsed() < TIME_BUDGET);

    let preference = cmap_table(&[(
        3,
        10,
        format12(
            &[
                (0x20, 0x20, 3),
                (0xA0, 0xA0, 3),
                (0xE000, 0xE000, 4),
                (0x1_F600, 0x1_F600, 4),
            ],
            4,
        ),
    )]);
    let mut sfnt = Vec::new();
    u32be(&mut sfnt, 0x0001_0000);
    u16be(&mut sfnt, 1);
    sfnt.extend_from_slice(&[0; 6]);
    sfnt.extend_from_slice(b"cmap");
    u32be(&mut sfnt, 0);
    u32be(&mut sfnt, 28);
    u32be(&mut sfnt, u32::try_from(preference.len()).expect("small"));
    sfnt.extend_from_slice(&preference);
    let map = TrueType::parse(&sfnt).expect("sfnt").unicode_map();
    assert_eq!(map.iter().collect::<Vec<_>>(), [(3, ' '), (4, '\u{1F600}')]);

    let mut absurd = Vec::new();
    u16be(&mut absurd, 0);
    u16be(&mut absurd, 0xFFFF);
    absurd.extend_from_slice(&[0, 3, 0, 1, 0xFF, 0xFF, 0xFF, 0xF0]);
    let cmap = Cmap::parse(&absurd).expect("cmap");
    assert!(cmap.unicode().is_none());
    assert_eq!(cmap.subtables().count(), 0);
}

#[test]
fn post_formats() {
    let mut v25 = Vec::new();
    u32be(&mut v25, 0x0002_5000);
    v25.extend_from_slice(&[0; 28]);
    u16be(&mut v25, 4);
    v25.extend_from_slice(&[0, 1, 0x7F, 0x80]);
    let post = Post::parse(&v25).expect("post");
    assert_eq!(post.glyph_name(0), Some(b".notdef".as_slice()));
    assert_eq!(post.glyph_name(1), Some(b"nonmarkingreturn".as_slice()));
    assert_eq!(post.glyph_name(2), Some(b"udieresis".as_slice()));
    assert_eq!(post.glyph_name(3), None);
    assert_eq!(post.glyph_name(4), None);

    let mut v2 = Vec::new();
    u32be(&mut v2, 0x0002_0000);
    v2.extend_from_slice(&[0; 28]);
    u16be(&mut v2, 5);
    for index in [0, 36, 258, 259, 300] {
        u16be(&mut v2, index);
    }
    v2.extend_from_slice(b"\x05alpha\x04beta\x09trunc");
    let post = Post::parse(&v2).expect("post");
    let names: Vec<_> = (0..6).map(|glyph| post.glyph_name(glyph)).collect();
    assert_eq!(
        names,
        [
            Some(b".notdef".as_slice()),
            Some(b"A".as_slice()),
            Some(b"alpha".as_slice()),
            Some(b"beta".as_slice()),
            None,
            None
        ]
    );

    let mut absurd = Vec::new();
    u32be(&mut absurd, 0x0002_0000);
    absurd.extend_from_slice(&[0; 28]);
    u16be(&mut absurd, 0xFFFF);
    absurd.extend_from_slice(&[0xFF, 0xFF]);
    let post = Post::parse(&absurd).expect("post");
    assert_eq!(post.glyph_name(0), None);
    assert_eq!(post.glyph_name(0xFFFF), None);
    assert!(Post::parse(&[0, 3, 0, 0]).is_none());
    assert!(Post::parse(&[0, 1]).is_none());
}

#[test]
fn sfnt_directory_bounds() {
    let mut data = Vec::new();
    u32be(&mut data, 0x0001_0000);
    u16be(&mut data, 0xFFFF);
    data.extend_from_slice(&[0; 6]);
    data.extend_from_slice(b"maxp");
    u32be(&mut data, 0);
    u32be(&mut data, 0xFFFF_FFF0);
    u32be(&mut data, 0xFFFF_FFFF);
    let sfnt = Sfnt::parse(&data).expect("sfnt");
    assert!(sfnt.table(b"maxp").is_none());
    assert!(sfnt.table(b"cmap").is_none());
    let font = TrueType::parse(&data).expect("sfnt");
    assert!(font.num_glyphs().is_none());
    assert!(font.unicode_map().is_empty());

    let mut ttc = b"ttcf\0\x01\0\0\0\0\0\x01".to_vec();
    u32be(&mut ttc, 0xFFFF_FFFF);
    assert!(Sfnt::parse(&ttc).is_none());
    assert!(Sfnt::parse(b"OTTO").is_none());
    assert!(Sfnt::parse(b"wOFF\0\0\0\0\0\0\0\0").is_none());
}
