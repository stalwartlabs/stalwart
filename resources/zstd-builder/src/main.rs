mod calendar;
mod constants;
mod contact;
mod corpus;
mod metadata;
mod script;
mod testsuite;
mod synthetic;
mod train;
mod vacation;

use std::path::{Path, PathBuf};

use corpus::{Corpus, Stats};
use train::{CANDIDATE_SIZES, Candidate, MIN_DICTIONARY_SIZE, evaluate, split, sweep, verify};

const DEFAULT_COMMON_SAMPLES: usize = 24000;

struct Options {
    dictionary: String,
    input: Option<PathBuf>,
    output: PathBuf,
    size: Option<usize>,
    samples: usize,
    keep_text: bool,
    core_only: bool,
    force: bool,
    fraction: usize,
}

fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(err) => {
            eprintln!("{err}\n");
            usage();
            std::process::exit(1);
        }
    };

    let mut stats = Stats {
        read: 0,
        skipped: 0,
    };
    let corpus = match options.dictionary.as_str() {
        "common" => synthetic::build(options.samples, &mut stats),
        "calendar" => read(
            &options,
            "ics",
            calendar::build(input(&options), options.keep_text, &mut stats),
        ),
        "contact" => read(
            &options,
            "vcf",
            contact::build(input(&options), options.keep_text, &mut stats),
        ),
        "sieve" => read(
            &options,
            "sieve",
            script::build(input(&options), &mut stats),
        ),
        "email" => read(
            &options,
            "eml or mbox",
            metadata::build(input(&options), &mut stats),
        ),
        other => {
            eprintln!("unknown dictionary: {other}\n");
            usage();
            std::process::exit(1);
        }
    };

    stats.report(&options.dictionary);
    if corpus.is_empty() || corpus.len() < 32 {
        eprintln!("refusing to train on {} samples", corpus.len());
        std::process::exit(1);
    }

    let total: usize = corpus.real.iter().map(Vec::len).sum();
    let mut sizes: Vec<usize> = corpus.real.iter().map(Vec::len).collect();
    sizes.sort_unstable();
    let at = |p: f64| sizes[((sizes.len() - 1) as f64 * p) as usize];
    println!(
        "corpus    : {} archives, {total} bytes, mean {} bytes",
        corpus.len(),
        total / corpus.len()
    );
    println!(
        "sizes     : p10 {} p50 {} p90 {} p99 {} max {}",
        at(0.10),
        at(0.50),
        at(0.90),
        at(0.99),
        sizes[sizes.len() - 1]
    );

    let typical = at(0.90);
    let train_only = if options.core_only {
        0
    } else {
        corpus.train_only.len()
    };
    let split = split(corpus, options.core_only);
    println!(
        "split     : {} training ({train_only} training only, {}% used), {} held out\n",
        split.train.len(),
        options.fraction,
        split.dev.len()
    );

    let baseline = evaluate(None, &split.dev, typical);
    println!(
        "{:>9}  {:>13}  {:>10}  {:>12}  {:>10}",
        "size", "typical", "all bytes", "mean stored", "compressed"
    );
    println!(
        "{:>9}  {:>12.2}%  {:>9.2}%  {:>10} B  {:>9}",
        "none",
        baseline.typical_ratio(),
        baseline.ratio(),
        baseline.mean_stored(),
        baseline.compressed_values
    );

    let sizes = options.size.map_or(CANDIDATE_SIZES.to_vec(), |size| vec![size]);
    let (candidates, knee) = sweep(&split, &sizes, typical, options.fraction);
    if candidates.is_empty() {
        eprintln!("no candidate could be trained");
        std::process::exit(1);
    }

    for (index, candidate) in candidates.iter().enumerate() {
        println!(
            "{:>8}K  {:>12.2}%  {:>9.2}%  {:>10} B  {:>9}{}",
            candidate.size / 1024,
            candidate.score.typical_ratio(),
            candidate.score.ratio(),
            candidate.score.mean_stored(),
            candidate.score.compressed_values,
            if index == knee { "  <- knee" } else { "" }
        );
    }

    let chosen = &candidates[knee];
    finish(chosen, &split.dev, &options.output, options.force);
}

fn finish(candidate: &Candidate, dev: &[Vec<u8>], output: &Path, force: bool) {
    let id = match verify(&candidate.dict, dev) {
        Ok(id) => id,
        Err(err) => {
            eprintln!("\nverification failed: {err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = check_siblings(output, &candidate.dict, id, force) {
        eprintln!("\n{err}");
        std::process::exit(1);
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }
    std::fs::write(output, &candidate.dict).expect("write dictionary");

    println!(
        "\nwrote     : {} ({} bytes, id {id})",
        output.display(),
        candidate.dict.len()
    );
    println!(
        "verified  : {} held out archives round tripped byte identical",
        dev.len()
    );
}

fn shipped_dictionary(path: &Path) -> Option<(u32, Vec<u8>)> {
    let bytes = std::fs::read(path).ok()?;
    let id = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
    (u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?) == 0xEC30A437 && id != 0)
        .then_some((id, bytes))
}

fn check_siblings(output: &Path, dict: &[u8], id: u32, force: bool) -> Result<(), String> {
    if let Some((existing, bytes)) = shipped_dictionary(output)
        && bytes != dict
        && !force
    {
        return Err(format!(
            "{} already holds dictionary {existing}; overwriting it makes every value written \n             with that identifier undecodable. Write a new version alongside it, or pass --force.",
            output.display()
        ));
    }

    let Some(directory) = output.parent() else {
        return Ok(());
    };
    for entry in std::fs::read_dir(directory).into_iter().flatten().flatten() {
        let path = entry.path();
        if path == output || path.extension().is_none_or(|ext| ext != "dict") {
            continue;
        }
        if let Some((other, bytes)) = shipped_dictionary(&path)
            && other == id
            && bytes != dict
        {
            return Err(format!(
                "identifier {id} is already used by {}; two dictionaries sharing one are \n                 indistinguishable to the decoder. Retrain with a different corpus or size.",
                path.display()
            ));
        }
    }
    Ok(())
}

fn input(options: &Options) -> &Path {
    options.input.as_deref().unwrap_or_else(|| {
        eprintln!("{} requires an input directory\n", options.dictionary);
        usage();
        std::process::exit(1)
    })
}

fn read(options: &Options, kind: &str, result: std::io::Result<Corpus>) -> Corpus {
    match result {
        Ok(corpus) => corpus,
        Err(err) => {
            eprintln!(
                "failed to read {kind} samples from {}: {err}",
                input(options).display()
            );
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let dictionary = args.next().ok_or("no dictionary named")?;
    if dictionary == "-h" || dictionary == "--help" {
        usage();
        std::process::exit(0);
    }

    let mut options = Options {
        output: PathBuf::from(format!("../zstd/{dictionary}-v1.dict")),
        dictionary,
        input: None,
        size: None,
        samples: DEFAULT_COMMON_SAMPLES,
        keep_text: false,
        core_only: false,
        force: false,
        fraction: 100,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                options.output = args.next().ok_or("--out needs a path")?.into();
            }
            "--size" => {
                let size: usize = args
                    .next()
                    .ok_or("--size needs a byte count")?
                    .parse()
                    .map_err(|_| "--size is not a number")?;
                if size < MIN_DICTIONARY_SIZE {
                    return Err(format!("--size must be at least {MIN_DICTIONARY_SIZE} bytes"));
                }
                options.size = Some(size);
            }
            "--samples" => {
                options.samples = args
                    .next()
                    .ok_or("--samples needs a count")?
                    .parse()
                    .map_err(|_| "--samples is not a number")?;
            }
            "--keep-text" => options.keep_text = true,
            "--core-only" => options.core_only = true,
            "--force" => options.force = true,
            "--train-fraction" => {
                let fraction: usize = args
                    .next()
                    .ok_or("--train-fraction needs a percentage")?
                    .parse()
                    .map_err(|_| "--train-fraction is not a number")?;
                if !(1..=100).contains(&fraction) {
                    return Err("--train-fraction must be between 1 and 100".to_string());
                }
                options.fraction = fraction;
            }
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other if options.input.is_none() => options.input = Some(other.into()),
            other => return Err(format!("unexpected argument: {other}")),
        }
    }

    Ok(options)
}

fn usage() {
    eprintln!(
        "usage: zstd-builder <dictionary> [input-dir] [options]

dictionaries:
  common     synthetic archives for Mailbox, Identity, EmailSubmission, PushSubscriptions,
             ParticipantIdentities, Calendar, AddressBook, FileNode and the SMTP queue Message
  calendar   CalendarEvent and CalendarEventNotification, from a directory of .ics files
  contact    ContactCard, from a directory of .vcf files
  sieve      SieveScript, from a directory of .sieve and .svtest files
  email      MessageMetadata, from a directory of .eml files or mbox archives

options:
  --out <path>      where to write the dictionary (default ../zstd/<dictionary>-v1.dict)
  --size <bytes>    train one size instead of sweeping
  --samples <n>     synthetic archives to generate (common only, default {DEFAULT_COMMON_SAMPLES})
  --keep-text       train on sample free text instead of neutralising it (calendar, contact)
  --core-only       drop the training only material, leaving the held out set unchanged
  --force           overwrite an existing dictionary that carries a different identifier
  --train-fraction <percent>
                    train on a slice of the training set, to check whether the corpus
                    has saturated; the held out set is unaffected"
    );
}
