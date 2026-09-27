/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cid::table_stats;
use super::cid_data::{CNS1_CHECKSUM, GB1_CHECKSUM, JAPAN1_CHECKSUM, KOREA1_CHECKSUM};
use super::{CidCollection, CmapDecoder, PredefinedCmap};

fn cid_text(collection: CidCollection, cid: u32) -> Option<String> {
    let mut out = String::new();
    collection.unicode(cid, &mut out).then_some(out)
}

#[test]
fn cid_orderings() {
    let cases: [(&[u8], &[u8], Option<CidCollection>); 9] = [
        (b"Adobe", b"Japan1", Some(CidCollection::Japan1)),
        (b"Adobe", b"GB1", Some(CidCollection::Gb1)),
        (b"Adobe", b"CNS1", Some(CidCollection::Cns1)),
        (b"Adobe", b"Korea1", Some(CidCollection::Korea1)),
        (b"Adobe ", b" CNS1", Some(CidCollection::Cns1)),
        (b"Adobe", b"Japan2", None),
        (b"Adobe", b"Identity", None),
        (b"Adobe", b"KR", None),
        (b"Foundry", b"GB1", None),
    ];
    for (registry, ordering, expected) in cases {
        assert_eq!(
            CidCollection::from_ordering(registry, ordering),
            expected,
            "{ordering:?}"
        );
    }
}

#[test]
fn cid_unicode() {
    let cases = [
        (CidCollection::Japan1, 0, None),
        (CidCollection::Japan1, 1, Some(" ")),
        (CidCollection::Japan1, 34, Some("A")),
        (CidCollection::Japan1, 230, Some("0")),
        (CidCollection::Japan1, 1000, Some("\u{30EC}")),
        (CidCollection::Japan1, 7641, Some("\u{28CDD}")),
        (CidCollection::Japan1, 23059, Some("\u{32FF}")),
        (CidCollection::Japan1, 23060, None),
        (CidCollection::Japan1, u32::MAX, None),
        (CidCollection::Gb1, 34, Some("A")),
        (CidCollection::Gb1, 1000, Some("\u{62DC}")),
        (CidCollection::Gb1, 22031, Some("\u{90CE}")),
        (CidCollection::Gb1, 22048, Some("\u{20087}")),
        (CidCollection::Gb1, 30283, Some("\u{A4C6}")),
        (CidCollection::Cns1, 124, None),
        (CidCollection::Cns1, 1000, Some("\u{6C57}")),
        (CidCollection::Cns1, 14000, Some("\u{200CC}")),
        (CidCollection::Cns1, 19178, Some("\u{9C47}")),
        (CidCollection::Korea1, 1000, Some("\u{30E3}")),
        (CidCollection::Korea1, 8193, None),
        (CidCollection::Korea1, 8207, Some("((")),
        (CidCollection::Korea1, 18351, Some("\\")),
    ];
    for (collection, cid, expected) in cases {
        assert_eq!(
            cid_text(collection, cid).as_deref(),
            expected,
            "{collection:?} {cid}"
        );
    }
}

const FNV_OFFSET: u64 = 0xCBF29CE484222325;
const FNV_PRIME: u64 = 0x100000001B3;

#[test]
fn cid_tables_match_source() {
    let cases = [
        (CidCollection::Japan1, JAPAN1_CHECKSUM),
        (CidCollection::Gb1, GB1_CHECKSUM),
        (CidCollection::Cns1, CNS1_CHECKSUM),
        (CidCollection::Korea1, KOREA1_CHECKSUM),
    ];
    for (collection, expected) in cases {
        let mut checksum = FNV_OFFSET;
        let mut text = String::new();
        for cid in 0..=u32::from(u16::MAX) {
            text.clear();
            if collection.unicode(cid, &mut text) {
                for byte in cid.to_le_bytes().iter().chain(text.as_bytes()) {
                    checksum = (checksum ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
                }
            }
        }
        assert_eq!(checksum, expected, "{collection:?}");
    }
}

#[test]
fn cid_table_shapes() {
    let cases = [
        (CidCollection::Japan1, 23060),
        (CidCollection::Gb1, 30284),
        (CidCollection::Cns1, 19179),
        (CidCollection::Korea1, 18352),
    ];
    for (collection, cids) in cases {
        let (values, extras, _) = table_stats(collection).unwrap_or_default();
        assert_eq!(values, cids, "{collection:?}");
        let mapped = (0..u32::try_from(cids).unwrap_or_default())
            .filter(|cid| cid_text(collection, *cid).is_some())
            .count();
        assert!(mapped + 300 > cids, "{collection:?} {mapped}");
        assert!(extras < cids / 4, "{collection:?}");
    }
}

#[test]
fn predefined_cmaps() {
    let Some(cmap) = PredefinedCmap::from_name(b"90ms-RKSJ-H") else {
        panic!("90ms-RKSJ-H is predefined");
    };
    assert_eq!(cmap.name(), "90ms-RKSJ-H");
    assert_eq!(cmap.decoder(), CmapDecoder::ShiftJis);
    assert_eq!(cmap.collection(), Some(CidCollection::Japan1));
    assert!(!cmap.is_vertical());
    assert_eq!(cmap.codespace().len(), 4);
    let accepts = |code: &[u8]| cmap.codespace().iter().any(|range| range.contains(code));
    assert!(accepts(&[0x81, 0x40]));
    assert!(accepts(&[0x41]));
    assert!(accepts(&[0xB1]));
    assert!(!accepts(&[0x81, 0x3F]));
    assert!(!accepts(&[0x81]));
    assert!(
        cmap.codespace()
            .iter()
            .any(|range| range.len() == 2 && range.accepts_prefix(&[0x81]))
    );
    assert_eq!(cmap.single_byte(0xA0), Some('\u{FF60}'));
    assert_eq!(cmap.single_byte(0x41), None);

    let expectations: [(&[u8], CmapDecoder, Option<CidCollection>, bool); 12] = [
        (
            b"90ms-RKSJ-V",
            CmapDecoder::ShiftJis,
            Some(CidCollection::Japan1),
            true,
        ),
        (
            b"H",
            CmapDecoder::JisRowCell,
            Some(CidCollection::Japan1),
            false,
        ),
        (
            b"V",
            CmapDecoder::JisRowCell,
            Some(CidCollection::Japan1),
            true,
        ),
        (b"Identity-H", CmapDecoder::Identity, None, false),
        (b"Identity-V", CmapDecoder::Identity, None, true),
        (
            b"UniGB-UTF16-H",
            CmapDecoder::Utf16Be,
            Some(CidCollection::Gb1),
            false,
        ),
        (
            b"UniJIS-UCS2-HW-V",
            CmapDecoder::Utf16Be,
            Some(CidCollection::Japan1),
            true,
        ),
        (
            b"UniKS-UTF8-H",
            CmapDecoder::Utf8,
            Some(CidCollection::Korea1),
            false,
        ),
        (
            b"UniCNS-UTF32-V",
            CmapDecoder::Utf32Be,
            Some(CidCollection::Cns1),
            true,
        ),
        (
            b"GBK2K-H",
            CmapDecoder::Gb18030,
            Some(CidCollection::Gb1),
            false,
        ),
        (
            b"CNS-EUC-V",
            CmapDecoder::EucTw,
            Some(CidCollection::Cns1),
            true,
        ),
        (
            b"KSCms-UHC-HW-H",
            CmapDecoder::EucKr,
            Some(CidCollection::Korea1),
            false,
        ),
    ];
    for (name, decoder, collection, vertical) in expectations {
        let cmap = PredefinedCmap::from_name(name);
        assert_eq!(cmap.map(PredefinedCmap::decoder), Some(decoder), "{name:?}");
        assert_eq!(
            cmap.and_then(PredefinedCmap::collection),
            collection,
            "{name:?}"
        );
        assert_eq!(
            cmap.map(PredefinedCmap::is_vertical),
            Some(vertical),
            "{name:?}"
        );
        assert!(
            cmap.is_some_and(|cmap| !cmap.codespace().is_empty()),
            "{name:?}"
        );
    }
    assert_eq!(PredefinedCmap::from_name(b"Unknown-H"), None);
}

#[test]
fn predefined_codespaces() {
    let cases: [(&[u8], &[u8], bool); 7] = [
        (b"Identity-H", &[0x00, 0x00], true),
        (b"Identity-H", &[0x41], false),
        (b"UniGB-UTF16-H", &[0xD8, 0x00, 0xDC, 0x00], true),
        (b"UniGB-UTF16-H", &[0xD8, 0x00], false),
        (b"CNS-EUC-H", &[0x8E, 0xA1, 0xA1, 0xA1], true),
        (b"H", &[0x21, 0x21], true),
        (b"H", &[0x41], false),
    ];
    for (name, code, expected) in cases {
        let accepted = PredefinedCmap::from_name(name)
            .is_some_and(|cmap| cmap.codespace().iter().any(|range| range.contains(code)));
        assert_eq!(accepted, expected, "{name:?} {code:?}");
    }
}

#[test]
fn mac_single_bytes() {
    let cases: [(&[u8], u8, Option<char>); 8] = [
        (b"GBpc-EUC-H", 0x80, Some('\u{FC}')),
        (b"GBpc-EUC-V", 0xFD, Some('\u{A9}')),
        (b"B5pc-H", 0x80, Some('\\')),
        (b"B5pc-H", 0xFF, Some('\u{2026}')),
        (b"KSCpc-EUC-H", 0x81, Some('\u{20A9}')),
        (b"90pv-RKSJ-H", 0xFE, Some('\u{2122}')),
        (b"83pv-RKSJ-H", 0xB1, None),
        (b"UniJIS-UCS2-H", 0x80, None),
    ];
    for (name, byte, expected) in cases {
        let patched = PredefinedCmap::from_name(name).and_then(|cmap| cmap.single_byte(byte));
        assert_eq!(patched, expected, "{name:?} {byte:#x}");
    }
}
