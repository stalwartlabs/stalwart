/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{budget, walk_with};
use crate::{
    Limits,
    pdf::{
        document::{DocScratch, Document},
        pages::{Pages, Visited},
    },
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn corpus_index(root: &Path) -> HashMap<PathBuf, usize> {
    let mut index = HashMap::new();
    for candidate in [root.join("INDEX.tsv"), root.join("bench/INDEX.tsv")] {
        let Ok(text) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        let base = candidate
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        for line in text.lines().skip(1) {
            let mut fields = line.split('\t');
            if let (Some(name), _, Some(pages)) = (fields.next(), fields.next(), fields.next())
                && let Ok(pages) = pages.parse()
            {
                index.insert(base.join(name), pages);
            }
        }
    }
    index
}

fn collect_pdfs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_pdfs(&path, out);
        } else if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
        {
            out.push(path);
        }
    }
}

#[test]
#[ignore]
fn corpus_stats() {
    let Some(roots) = std::env::var_os("PDF_CORPUS_DIR") else {
        return;
    };
    let roots: Vec<PathBuf> = std::env::split_paths(&roots).collect();
    let mut files = Vec::new();
    let mut expected = HashMap::new();
    for root in &roots {
        collect_pdfs(root, &mut files);
        expected.extend(corpus_index(root));
    }
    files.sort();
    let limits = Limits::default();
    let mut times = Vec::with_capacity(files.len());
    let (mut failures, mut mismatches, mut panics, mut repaired, mut decode_failures) =
        (0usize, 0usize, 0usize, 0usize, 0usize);
    println!("file\tsize\tpages\texpected\trepaired\tstreams\tfailures\tdecoded\tms\tresult");
    for path in &files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        let started = Instant::now();
        let outcome = std::panic::catch_unwind(|| walk_with(&data, &limits));
        let elapsed = started.elapsed();
        times.push((elapsed, path.clone()));
        let expected_pages = expected.get(path).copied();
        let line = match outcome {
            Err(_) => {
                panics += 1;
                "PANIC".to_string()
            }
            Ok(Err(error)) => {
                failures += 1;
                format!("{error:?}")
            }
            Ok(Ok(walk)) => {
                repaired += usize::from(walk.repaired);
                decode_failures += walk.failures;
                if expected_pages.is_some_and(|pages| pages != walk.pages) {
                    mismatches += 1;
                }
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\tok",
                    walk.pages,
                    expected_pages.map_or("-".to_string(), |pages| pages.to_string()),
                    walk.repaired,
                    walk.streams,
                    walk.failures,
                    walk.decoded
                )
            }
        };
        println!(
            "{}\t{}\t{line}\t{:.1}",
            path.display(),
            data.len(),
            elapsed.as_secs_f64() * 1000.0
        );
    }
    times.sort();
    let total: Duration = times.iter().map(|(time, _)| *time).sum();
    let p95 = times
        .get(times.len() * 95 / 100)
        .map_or(Duration::ZERO, |(time, _)| *time);
    println!(
        "SUMMARY files={} open_failures={failures} panics={panics} page_mismatches={mismatches} repaired={repaired} decode_failures={decode_failures} total_ms={:.1} p95_ms={:.2}",
        files.len(),
        total.as_secs_f64() * 1000.0,
        p95.as_secs_f64() * 1000.0
    );
    for (time, path) in times.iter().rev().take(10) {
        println!(
            "SLOW {:.1}ms {}",
            time.as_secs_f64() * 1000.0,
            path.display()
        );
    }
}

#[test]
#[ignore]
fn inspect_file() {
    let Some(path) = std::env::var_os("PDF_INSPECT") else {
        return;
    };
    let data = std::fs::read(path).unwrap_or_default();
    let mut scratch = DocScratch::default();
    let mut visited = Visited::default();
    let document = match Document::open(&data, &mut scratch, budget(&Limits::default()), 1 << 20) {
        Ok(document) => document,
        Err(failure) => {
            println!("open failed: {failure:?}");
            return;
        }
    };
    println!("repaired after open: {}", document.repaired());
    println!(
        "catalog: {:?}",
        document
            .catalog()
            .map(|catalog| String::from_utf8_lossy(catalog.body()).into_owned())
    );
    for page in Pages::new(&document, &mut visited) {
        let mut contents = Vec::new();
        let (data, outcome) = page.contents(&document, &mut contents);
        println!("page {:?} {outcome:?} {} bytes", page.id, data.len());
    }
    println!(
        "repaired: {} decoded: {}",
        document.repaired(),
        document.used_bytes()
    );
}
