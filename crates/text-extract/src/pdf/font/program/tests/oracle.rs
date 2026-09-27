/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::{BTreeMap, BTreeSet};

use super::super::{BuiltinEncoding, Cff, CodeNames, TrueType};

#[derive(Default)]
pub(super) struct Tally {
    pub(super) fonts: usize,
    pub(super) checks: usize,
    pub(super) failures: BTreeMap<String, usize>,
    pub(super) samples: Vec<String>,
}

impl Tally {
    fn check(&mut self, ok: bool, category: &str, file: &str, detail: impl FnOnce() -> String) {
        self.checks += 1;
        if !ok {
            *self.failures.entry(category.to_string()).or_default() += 1;
            if self.samples.len() < 60 {
                self.samples
                    .push(format!("{file}: {category}: {}", detail()));
            }
        }
    }
}

type CmapKey = (u16, u16);

#[derive(Default)]
struct Expect {
    num_glyphs: Option<u16>,
    ros: Option<(String, String)>,
    names: BTreeMap<u16, String>,
    cids: BTreeMap<u16, u16>,
    encoding: Option<String>,
    codes: BTreeMap<u8, String>,
    cmaps: Vec<(CmapKey, BTreeSet<(u32, u16)>)>,
    post_format: Option<String>,
    post: BTreeMap<u16, String>,
    cff: Option<Box<Expect>>,
}

fn parse_expect(text: &str) -> Option<Expect> {
    let mut expect = Expect::default();
    let mut cff_lines = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("cff") {
            cff_lines.push_str(rest);
            cff_lines.push('\n');
            continue;
        }
        let mut fields = line.split(' ');
        let key = fields.next()?;
        let mut next = || fields.next().unwrap_or_default();
        match key {
            "error" => return None,
            "numglyphs" => expect.num_glyphs = next().parse().ok(),
            "ros" => expect.ros = Some((next().to_string(), next().to_string())),
            "gname" => {
                let gid = next().parse().ok()?;
                expect.names.insert(gid, next().to_string());
            }
            "cid" => {
                let gid = next().parse().ok()?;
                expect.cids.insert(gid, next().parse().ok()?);
            }
            "enc" => expect.encoding = Some(next().to_string()),
            "code" => {
                let code = next().parse().ok()?;
                expect.codes.insert(code, next().to_string());
            }
            "cmap" => {
                let platform = next().parse().ok()?;
                let encoding = next().parse().ok()?;
                expect.cmaps.push(((platform, encoding), BTreeSet::new()));
            }
            "m" => {
                let code = next().parse().ok()?;
                let gid: u16 = next().parse().ok()?;
                if let Some((_, set)) = expect.cmaps.last_mut()
                    && gid != 0
                {
                    set.insert((code, gid));
                }
            }
            "postformat" => expect.post_format = Some(next().to_string()),
            "post" => {
                let gid = next().parse().ok()?;
                expect.post.insert(gid, next().to_string());
            }
            _ => {}
        }
    }
    if !cff_lines.is_empty() {
        expect.cff = Some(Box::new(parse_expect(&cff_lines)?));
    }
    Some(expect)
}

fn ours_codes(names: &CodeNames<'_>) -> BTreeMap<u8, String> {
    names
        .iter()
        .filter(|(_, name)| *name != b".notdef")
        .map(|(code, name)| (code, String::from_utf8_lossy(name).into_owned()))
        .collect()
}

fn check_encoding(
    tally: &mut Tally,
    file: &str,
    expect: &Expect,
    ours: Option<BuiltinEncoding<'_>>,
) {
    match (expect.encoding.as_deref(), ours) {
        (Some("StandardEncoding"), ours) => tally.check(
            matches!(ours, Some(BuiltinEncoding::Standard)),
            "encoding-standard",
            file,
            || format!("{ours:?}").chars().take(80).collect(),
        ),
        (Some("ExpertEncoding"), ours) => tally.check(
            matches!(ours, Some(BuiltinEncoding::Expert)),
            "encoding-expert",
            file,
            String::new,
        ),
        (_, Some(BuiltinEncoding::Custom(names))) => {
            let mut ours = ours_codes(&names);
            if !expect.codes.contains_key(&0) {
                ours.remove(&0);
            }
            tally.check(ours == expect.codes, "encoding-custom", file, || {
                let missing: Vec<_> = expect
                    .codes
                    .iter()
                    .filter(|(c, n)| ours.get(c) != Some(n))
                    .take(5)
                    .collect();
                let extra: Vec<_> = ours
                    .iter()
                    .filter(|(c, n)| expect.codes.get(c) != Some(n))
                    .take(5)
                    .collect();
                format!(
                    "expected {} got {}; missing {missing:?} extra {extra:?}",
                    expect.codes.len(),
                    ours.len()
                )
            });
        }
        (expected, ours) => tally.check(
            expected == Some("none") && ours.is_none(),
            "encoding-kind",
            file,
            || format!("expected {expected:?} got {:?}", ours.map(|_| "some")),
        ),
    }
}

fn check_cff(tally: &mut Tally, file: &str, expect: &Expect, data: &[u8]) {
    let Some(cff) = Cff::parse(data) else {
        tally.check(false, "cff-parse", file, String::new);
        return;
    };
    tally.check(
        Some(cff.num_glyphs()) == expect.num_glyphs,
        "cff-num-glyphs",
        file,
        || format!("{} vs {:?}", cff.num_glyphs(), expect.num_glyphs),
    );
    tally.check(
        cff.is_cid() == expect.ros.is_some(),
        "cff-is-cid",
        file,
        String::new,
    );
    if let Some((registry, ordering)) = &expect.ros {
        let ros = cff.ros();
        tally.check(
            ros.is_some_and(|ros| {
                ros.registry == registry.as_bytes() && ros.ordering == ordering.as_bytes()
            }),
            "cff-ros",
            file,
            String::new,
        );
        let bad = expect
            .cids
            .iter()
            .filter(|&(&gid, &cid)| cff.glyph_cid(gid) != Some(cid))
            .count();
        tally.check(bad == 0, "cff-cid", file, || format!("{bad} mismatches"));
    } else {
        let bad: Vec<_> = expect
            .names
            .iter()
            .filter(|&(&gid, name)| cff.glyph_name(gid) != Some(name.as_bytes()))
            .take(3)
            .collect();
        tally.check(bad.is_empty(), "cff-glyph-name", file, || {
            format!("{bad:?}")
        });
        check_encoding(tally, file, expect, cff.builtin_encoding());
    }
}

fn check_sfnt(tally: &mut Tally, file: &str, expect: &Expect, data: &[u8]) {
    let Some(font) = TrueType::parse(data) else {
        tally.check(false, "sfnt-parse", file, String::new);
        return;
    };
    tally.check(
        font.num_glyphs() == expect.num_glyphs,
        "num-glyphs",
        file,
        String::new,
    );
    let limit = expect.num_glyphs.map_or(0x1_0000, u32::from);
    let mut seen = BTreeSet::new();
    for ((platform, encoding), expected) in &expect.cmaps {
        if !seen.insert((*platform, *encoding)) {
            continue;
        }
        let Some(subtable) = font
            .cmap()
            .and_then(|cmap| cmap.subtable(*platform, *encoding))
        else {
            tally.check(false, "cmap-missing", file, || {
                format!("{platform},{encoding}")
            });
            continue;
        };
        let bad: Vec<_> = expected
            .iter()
            .filter(|&&(code, gid)| subtable.glyph(code) != Some(gid))
            .take(3)
            .collect();
        tally.check(bad.is_empty(), "cmap-lookup", file, || {
            format!("{platform},{encoding} {bad:?}")
        });
        let mut ours = BTreeSet::new();
        subtable.for_each_mapping(limit, |code, gid| {
            ours.insert((code, gid));
        });
        let expected_in_range: BTreeSet<_> = expected
            .iter()
            .copied()
            .filter(|&(_, gid)| u32::from(gid) < limit)
            .collect();
        tally.check(ours == expected_in_range, "cmap-enumerate", file, || {
            let missing: Vec<_> = expected_in_range.difference(&ours).take(3).collect();
            let extra: Vec<_> = ours.difference(&expected_in_range).take(3).collect();
            format!("{platform},{encoding} missing {missing:?} extra {extra:?}")
        });
    }
    let map = font.unicode_map();
    if let Some(unicode) = font.unicode_cmap() {
        let bad = map
            .iter()
            .filter(|&(gid, ch)| {
                unicode.glyph(u32::from(ch)) != Some(gid) || u32::from(gid) >= limit
            })
            .count();
        tally.check(bad == 0, "unicode-map", file, || {
            format!("{bad} inconsistent")
        });
    }
    if matches!(expect.post_format.as_deref(), Some("1.0" | "2.0")) {
        let bad: Vec<_> = expect
            .post
            .iter()
            .filter(|(_, name)| !name.contains('#'))
            .filter(|&(&gid, name)| font.glyph_name(gid) != Some(name.as_bytes()))
            .take(3)
            .collect();
        tally.check(bad.is_empty(), "post-name", file, || format!("{bad:?}"));
    }
    if let Some(cff) = &expect.cff {
        check_cff(tally, file, cff, data);
    }
}

pub(super) fn check_font(tally: &mut Tally, file: &str, data: &[u8], expect: &str) {
    let Some(expect) = parse_expect(expect) else {
        return;
    };
    tally.fonts += 1;
    match file.rsplit_once('.').map(|(_, ext)| ext) {
        Some("t1") => check_encoding(tally, file, &expect, BuiltinEncoding::from_type1(data)),
        Some("cff" | "cidcff") => check_cff(tally, file, &expect, data),
        _ => check_sfnt(tally, file, &expect, data),
    }
}

impl Tally {
    pub(super) fn report(&self) {
        println!("fonts {} checks {}", self.fonts, self.checks);
        for (category, count) in &self.failures {
            println!("FAIL {category}: {count}");
        }
        for sample in &self.samples {
            println!("  {sample}");
        }
    }
}
