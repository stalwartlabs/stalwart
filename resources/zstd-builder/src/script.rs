use std::path::Path;

use common::scripts::{functions::register_functions_untrusted, plugins::RegisterSievePlugins};
use email::sieve::{SieveScript, VacationResponse};
use sieve::Compiler;
use types::blob_hash::BlobHash;

use crate::{
    corpus::{Corpus, Rng, Stats, archive, collect_files, normalize_crlf},
    testsuite,
};

pub fn build(dir: &Path, stats: &mut Stats) -> std::io::Result<Corpus> {
    let files = collect_files(dir, &["sieve", "svtest"])?;
    let mut corpus = Corpus::new();

    let mut functions = register_functions_untrusted().register_plugins_untrusted();
    let compiler = Compiler::new()
        .with_max_script_size(102400)
        .with_max_string_size(4096)
        .with_max_variable_name_size(32)
        .with_max_nested_blocks(15)
        .with_max_nested_tests(15)
        .with_max_nested_foreverypart(3)
        .with_max_match_variables(30)
        .with_max_local_variables(128)
        .with_max_header_size(1024)
        .with_max_includes(3)
        .with_no_capability_check(true)
        .register_functions(&mut functions);

    for (index, path) in files.iter().enumerate() {
        let Ok(raw) = std::fs::read(path) else {
            stats.skipped += 1;
            continue;
        };
        let Ok(source) = std::str::from_utf8(&raw) else {
            stats.skipped += 1;
            continue;
        };
        let converted = testsuite::to_sieve(source);
        let is_testsuite = converted != source;
        let raw = normalize_crlf(converted.as_bytes());

        let script = match compiler.compile(&raw) {
            Ok(script) => script,
            Err(err) => {
                if stats.skipped < 5 {
                    eprintln!("skipped {}: {err}", path.display());
                }
                stats.skipped += 1;
                continue;
            }
        };

        let mut rng = Rng::new(index as u64 + 1);
        let name_len = rng.range(4, 20);
        let sample = archive(&SieveScript {
            name: rng.token(name_len),
            blob_hash: BlobHash::generate(&raw),
            size: raw.len() as u32,
            vacation_response: rng.chance(10).then(|| vacation(&mut rng)),
            script: Box::new(script),
        });

        if is_testsuite {
            corpus.push_train_only(sample);
        } else {
            corpus.push_both(sample);
        }
        stats.read += 1;
    }

    Ok(corpus)
}

fn vacation(rng: &mut Rng) -> VacationResponse {
    let subject_len = rng.range(10, 40);
    let text_len = rng.range(60, 400);
    let from_date = 1_750_000_000 + rng.below(86400 * 365) as u64;

    VacationResponse {
        from_date: Some(from_date),
        to_date: Some(from_date + rng.range(86400, 86400 * 21) as u64),
        subject: Some(rng.token(subject_len)),
        text_body: Some(rng.token(text_len)),
        html_body: rng.chance(50).then(|| {
            let body_len = rng.range(60, 400);
            format!(
                "<html><head></head><body><div dir=\"ltr\"><p>{}</p></div></body></html>",
                rng.token(body_len)
            )
        }),
    }
}
