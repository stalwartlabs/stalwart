/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use super::super::{BuiltinEncoding, Cff, TrueType};
use super::hostile::{PER_INPUT_BUDGET, SEED, XorShift, exercise, mutate};
use super::oracle::{Tally, check_font};

const CORPUS_ENV: &str = "FONT_CORPUS";
const PERF_ENV: &str = "FONT_PERF";
const PERF_ROUNDS: u32 = 20;
const CUTS_PER_FONT: usize = 64;
const MUTATIONS_PER_FONT: usize = 200;

#[test]
#[ignore]
fn compare_with_fonttools() {
    let Ok(dir) = std::env::var(CORPUS_ENV) else {
        return;
    };
    let mut tally = Tally::default();
    let mut entries: Vec<_> = fs::read_dir(Path::new(&dir))
        .expect("corpus directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext != "expect" && ext != "tsv")
        })
        .collect();
    entries.sort();
    for path in entries {
        let mut expect_path = path.clone().into_os_string();
        expect_path.push(".expect");
        let Ok(expect) = fs::read_to_string(&expect_path) else {
            continue;
        };
        let data = fs::read(&path).expect("font file");
        let file = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        check_font(&mut tally, file, &data, &expect);
    }
    tally.report();
}

fn time_per_round(mut round: impl FnMut() -> usize) -> (Duration, usize) {
    let started = Instant::now();
    let work = (0..PERF_ROUNDS).map(|_| round()).sum();
    (started.elapsed() / PERF_ROUNDS, work)
}

#[test]
#[ignore]
fn parse_time() {
    let Ok(paths) = std::env::var(PERF_ENV) else {
        return;
    };
    for path in paths.split(',') {
        let data = fs::read(path).expect("font file");
        let (type1, _) =
            time_per_round(|| usize::from(BuiltinEncoding::from_type1(&data).is_some()));
        let (sfnt_parse, _) = time_per_round(|| usize::from(TrueType::parse(&data).is_some()));
        let (unicode_map, mapped) =
            time_per_round(|| TrueType::parse(&data).map_or(0, |font| font.unicode_map().len()));
        let (post_names, named) = time_per_round(|| {
            TrueType::parse(&data).map_or(0, |font| {
                (0..font.num_glyphs().unwrap_or(0))
                    .filter_map(|glyph| font.glyph_name(glyph))
                    .count()
            })
        });
        let (cff, cff_glyphs) = time_per_round(|| {
            Cff::parse(&data).map_or(0, |cff| {
                (0..cff.num_glyphs())
                    .filter(|&glyph| {
                        cff.glyph_name(glyph).is_some() || cff.glyph_cid(glyph).is_some()
                    })
                    .count()
            })
        });
        println!(
            "{path}: {} bytes; type1 {type1:?}; sfnt {sfnt_parse:?}; +unicode map {unicode_map:?} ({} glyphs); +post names {post_names:?} ({}); cff all glyphs {cff:?} ({})",
            data.len(),
            mapped / PERF_ROUNDS as usize,
            named / PERF_ROUNDS as usize,
            cff_glyphs / PERF_ROUNDS as usize
        );
    }
}

#[test]
#[ignore]
fn corpus_truncations_and_mutations() {
    let Ok(dir) = std::env::var(CORPUS_ENV) else {
        return;
    };
    let mut rng = XorShift(SEED);
    let mut buffer = Vec::new();
    let mut slowest = (Duration::ZERO, String::new());
    let mut inputs = 0usize;
    for path in fs::read_dir(Path::new(&dir))
        .expect("corpus directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
    {
        if path
            .extension()
            .is_some_and(|ext| ext == "expect" || ext == "tsv")
        {
            continue;
        }
        let data = fs::read(&path).expect("font file");
        for round in 0..CUTS_PER_FONT + MUTATIONS_PER_FONT {
            buffer.clear();
            if round < CUTS_PER_FONT {
                buffer.extend_from_slice(data.get(..rng.below(data.len())).unwrap_or_default());
            } else {
                buffer.extend_from_slice(&data);
                mutate(&mut rng, &mut buffer);
            }
            let started = Instant::now();
            exercise(&buffer);
            let elapsed = started.elapsed();
            inputs += 1;
            if elapsed > slowest.0 {
                slowest = (elapsed, path.display().to_string());
            }
        }
    }
    println!("{inputs} inputs, slowest {:?} ({})", slowest.0, slowest.1);
    assert!(slowest.0 < PER_INPUT_BUDGET);
}
