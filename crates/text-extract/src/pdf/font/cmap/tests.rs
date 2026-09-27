/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;

fn to_unicode(source: &str) -> Cmap {
    let mut cmap = Cmap::new(CmapKind::ToUnicode);
    cmap.parse(source.as_bytes());
    cmap.finish();
    cmap
}

fn text(cmap: &Cmap, code: u32) -> Option<String> {
    let mut out = String::new();
    cmap.unicode(code, &mut out).then_some(out)
}

#[test]
fn bfchar_and_bfrange_forms() {
    let cmap = to_unicode(
        "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n\
         1 begincodespacerange <00> <FF> endcodespacerange\n\
         3 beginbfchar <01> <0041> <02> <D835DC00> <03> /f_i endbfchar\n\
         2 beginbfrange <10> <12> <0061> <20> <22> [<0058> /Y <005A005A>] endbfrange\n\
         1 begincidrange <30> <31> 948 endcidrange\n\
         endcmap CMapName currentdict /CMap defineresource pop end end",
    );
    assert_eq!(text(&cmap, 1).as_deref(), Some("A"));
    assert_eq!(text(&cmap, 2).as_deref(), Some("\u{1d400}"));
    assert_eq!(text(&cmap, 3).as_deref(), Some("fi"));
    assert_eq!(text(&cmap, 0x11).as_deref(), Some("b"));
    assert_eq!(text(&cmap, 0x12).as_deref(), Some("c"));
    assert_eq!(text(&cmap, 0x13), None);
    assert_eq!(text(&cmap, 0x20).as_deref(), Some("X"));
    assert_eq!(text(&cmap, 0x21).as_deref(), Some("Y"));
    assert_eq!(text(&cmap, 0x22).as_deref(), Some("ZZ"));
    assert_eq!(text(&cmap, 0x31).as_deref(), Some("\u{3b5}"));
    assert_eq!(cmap.codespace().len(), 1);
}

#[test]
fn odd_targets_surrogates_and_broken_entries() {
    let cmap = to_unicode(
        "beginbfchar <01> <20> <02> <> <03> <D800> <04> (junk) <05> <0042> endbfchar\n\
         beginbfrange <0010> <0005> <0041> <0100> <0102> <D83DDE00> <0200> <02FF> <FFFF> \
         <0300> <0300> endbfrange",
    );
    assert_eq!(text(&cmap, 1).as_deref(), Some(" "));
    assert_eq!(text(&cmap, 2), None);
    assert_eq!(text(&cmap, 3), None);
    assert_eq!(text(&cmap, 5).as_deref(), Some("B"));
    assert_eq!(text(&cmap, 0x10), None);
    assert_eq!(text(&cmap, 0x101).as_deref(), Some("\u{1f601}"));
    assert_eq!(text(&cmap, 0x200).as_deref(), Some("\u{ffff}"));
    assert_eq!(text(&cmap, 0x201), None);
}

#[test]
fn huge_ranges_stay_unexpanded() {
    let cmap = to_unicode("beginbfrange <00000000> <FFFFFFFF> <0000> endbfrange");
    assert_eq!(cmap.entries.len(), 1);
    assert_eq!(text(&cmap, 0x41).as_deref(), Some("A"));
    assert_eq!(text(&cmap, 0xFFFF_FFFF), None);
    let identity = to_unicode("beginbfrange <0000> <FFFF> <0000> endbfrange");
    assert_eq!(text(&identity, 0x4E2D).as_deref(), Some("\u{4e2d}"));
}

#[test]
fn later_entries_override_earlier_ones() {
    let cmap = to_unicode(
        "beginbfrange <00> <FF> <0041> endbfrange\n\
         beginbfchar <05> <007A> endbfchar\n\
         beginbfrange <10> <20> <0061> endbfrange\n\
         beginbfchar <12> <0030> endbfchar",
    );
    assert_eq!(text(&cmap, 0).as_deref(), Some("A"));
    assert_eq!(text(&cmap, 4).as_deref(), Some("E"));
    assert_eq!(text(&cmap, 5).as_deref(), Some("z"));
    assert_eq!(text(&cmap, 6).as_deref(), Some("G"));
    assert_eq!(text(&cmap, 0x10).as_deref(), Some("a"));
    assert_eq!(text(&cmap, 0x12).as_deref(), Some("0"));
    assert_eq!(text(&cmap, 0x13).as_deref(), Some("d"));
    assert_eq!(text(&cmap, 0x21).as_deref(), Some("b"));
    assert!(cmap.entries.is_disjoint());
}

#[test]
fn many_overlapping_ranges_are_bounded() {
    let mut source = String::from("beginbfrange\n");
    for index in 0..20_000u32 {
        source.push_str(&format!("<0000> <FFFF> <{:04X}>\n", index % 0xFFFF));
    }
    for index in 0..20_000u32 {
        source.push_str(&format!("<{index:04X}> <{index:04X}> <0041>\n"));
    }
    source.push_str("endbfrange");
    let started = std::time::Instant::now();
    let cmap = to_unicode(&source);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(text(&cmap, 5).as_deref(), Some("A"));
    assert!(cmap.entries.len() <= 20_001);
}

#[test]
fn encoding_cmaps_map_codes_to_cids() {
    let mut cmap = Cmap::new(CmapKind::Encoding);
    cmap.parse(
        b"/WMode 1 def /UniJIS-UCS2-H usecmap\n\
          2 begincodespacerange <00> <80> <8140> <9FFC> endcodespacerange\n\
          begincidrange <20> <7E> 1 <8140> <817E> 633 endcidrange\n\
          begincidchar <8150> 7000 endcidchar\n\
          beginbfchar <21> <0100> endbfchar",
    );
    cmap.finish();
    assert!(cmap.is_vertical());
    assert_eq!(cmap.base().map(|base| base.name()), Some("UniJIS-UCS2-H"));
    assert_eq!(cmap.cid(0x20, 1), Some(1));
    assert_eq!(cmap.cid(0x21, 1), Some(0x100));
    assert_eq!(cmap.cid(0x22, 1), Some(3));
    assert_eq!(cmap.cid(0x8141, 2), Some(634));
    assert_eq!(cmap.cid(0x8150, 2), Some(7000));
    assert_eq!(cmap.cid(0x20, 2), None);
    assert_eq!(cmap.codespace().len(), 2);
    assert_eq!(cmap.uniform_source_length(), None);
}

#[test]
fn entry_count_is_capped() {
    let mut source = String::from("beginbfchar\n");
    for index in 0..(MAX_CMAP_ENTRIES as u32 + 10) {
        source.push_str(&format!("<{index:06X}> <0041>\n"));
    }
    let cmap = to_unicode(&source);
    assert_eq!(cmap.entries.len(), MAX_CMAP_ENTRIES);
}
