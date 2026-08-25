use std::path::Path;

use email::message::metadata::ArchivedMessageMetadata;
use mail_parser::MessageParser;
use nlp::language::Language;
use store::{
    ahash::{AHashMap, AHashSet},
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, FileSearchField, IndexDocument,
        SearchField,
    },
    write::{SearchIndex, serialize::rkyv_unarchive},
};
use utils::cheeky_hash::CheekyHash;

use crate::{
    corpus::{Corpus, Rng, Stats, archive, collect_files, normalize_crlf},
    metadata::{split_mbox, unescape_mbox, with_ingest_headers},
};

const MIN_WORD_LEN: usize = 2;
const WORDS_PER_LANGUAGE: usize = 50000;
const SYNTHETIC_SEED: u64 = 0x7e12_d0c5;
const MIN_COVERAGE_WORDS: usize = 1500;
const MAX_COVERAGE_WORDS: usize = 50000;
const COVERAGE_WORDS_PER_DOCUMENT: usize = 160;

const TLDS: [&str; 12] = [
    "com", "net", "org", "io", "de", "fr", "es", "it", "nl", "se", "jp", "br",
];

const HEADER_NAMES: [&str; 16] = [
    "received",
    "date",
    "message-id",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "return-path",
    "delivered-to",
    "list-id",
    "list-unsubscribe",
    "user-agent",
    "x-mailer",
    "references",
    "in-reply-to",
    "reply-to",
    "precedence",
];

const HEADER_VALUES: [&str; 16] = [
    "from mail example com by mx example org with esmtps id",
    "mon jan 2006 15 04 05 0000",
    "abcdef0123456789 mail example com",
    "1 0",
    "text plain charset utf 8",
    "quoted printable",
    "bounces list example org",
    "user example com",
    "announce list example org",
    "mailto unsubscribe example org",
    "mozilla thunderbird 128 0",
    "microsoft outlook 16 0",
    "cafe0123 mail example com",
    "beef4567 mail example com",
    "no reply example com",
    "bulk",
];

const MEDIA_NAMES: [&str; 10] = [
    "report", "invoice", "agenda", "minutes", "budget", "photo", "contract", "receipt", "draft",
    "notes",
];

const FILE_EXTENSIONS: [&str; 10] = [
    "pdf", "docx", "xlsx", "png", "jpg", "txt", "csv", "zip", "odt", "pptx",
];

const CONTACT_KINDS: [&str; 4] = ["individual", "group", "org", "location"];

const DEFAULT_LANGUAGE_SHARE: u32 = 10;

fn language_share(language: Language) -> u32 {
    match language {
        Language::English => 5000,
        Language::Spanish => 620,
        Language::German => 560,
        Language::Russian => 550,
        Language::French => 450,
        Language::Japanese => 400,
        Language::Portuguese => 350,
        Language::Mandarin => 300,
        Language::Italian => 250,
        Language::Dutch => 200,
        Language::Turkish => 190,
        Language::Polish => 160,
        Language::Persian => 150,
        Language::Vietnamese => 130,
        Language::Arabic => 120,
        Language::Korean => 100,
        Language::Indonesian => 80,
        Language::Czech => 70,
        Language::Ukrainian => 60,
        Language::Hindi => 55,
        Language::Greek => 50,
        Language::Swedish => 50,
        Language::Danish => 45,
        Language::Romanian => 45,
        Language::Hungarian => 40,
        Language::Hebrew => 40,
        Language::Finnish => 35,
        Language::Thai => 35,
        Language::Slovak => 30,
        Language::Bulgarian => 30,
        Language::Serbian => 30,
        Language::Croatian => 25,
        Language::Bokmal => 25,
        Language::Catalan => 20,
        Language::Lithuanian => 20,
        Language::Slovene => 20,
        Language::Latvian => 15,
        Language::Estonian => 15,
        _ => DEFAULT_LANGUAGE_SHARE,
    }
}

struct LanguageWords {
    language: Language,
    words: Vec<Box<str>>,
    cumulative: Vec<u64>,
}

pub struct Vocabulary {
    languages: Vec<LanguageWords>,
}

impl LanguageWords {
    fn pick(&self, rng: &mut Rng) -> &str {
        let total = *self.cumulative.last().unwrap();
        let target = rng.next_u64() % total;
        let index = self.cumulative.partition_point(|sum| *sum <= target);
        &self.words[index.min(self.words.len() - 1)]
    }

    fn words(&self, rng: &mut Rng, count: usize, out: &mut String) {
        for index in 0..count {
            if index > 0 {
                out.push(if index % 12 == 11 { '.' } else { ' ' });
                if index % 12 == 11 {
                    out.push(' ');
                }
            }
            out.push_str(self.pick(rng));
        }
    }

    fn phrase(&self, rng: &mut Rng, from: usize, to: usize) -> String {
        let count = rng.range(from, to);
        let mut out = String::new();
        self.words(rng, count, &mut out);
        out
    }

    fn body(&self, rng: &mut Rng) -> String {
        let count = body_length(rng);
        let mut out = String::new();
        self.words(rng, count, &mut out);
        out
    }

    fn address(&self, rng: &mut Rng) -> String {
        let local = if rng.chance(60) {
            format!("{}.{}", self.pick(rng), self.pick(rng))
        } else {
            self.pick(rng).to_string()
        };
        format!(
            "{local}@{}.{}",
            self.pick(rng),
            TLDS[rng.below(TLDS.len())]
        )
    }

    fn addresses(&self, rng: &mut Rng, from: usize, to: usize) -> String {
        let count = rng.range(from, to);
        let mut out = String::new();
        for index in 0..count {
            if index > 0 {
                out.push(' ');
            }
            out.push_str(&format!(
                "{} {} {}",
                self.pick(rng),
                self.pick(rng),
                self.address(rng)
            ));
        }
        out
    }
}

impl Vocabulary {
    pub fn load(dir: &Path, stats: &mut Stats) -> std::io::Result<Self> {
        let mut merged: Vec<(Language, AHashMap<Box<str>, u64>)> = Vec::new();

        for path in collect_files(dir, &["txt"])? {
            let Some(code) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let Some(language) = Language::from_iso_639(code) else {
                stats.skipped += 1;
                continue;
            };
            let Ok(contents) = std::fs::read_to_string(&path) else {
                stats.skipped += 1;
                continue;
            };

            let counts = match merged.iter_mut().find(|(known, _)| *known == language) {
                Some((_, counts)) => counts,
                None => {
                    merged.push((language, AHashMap::new()));
                    &mut merged.last_mut().unwrap().1
                }
            };

            let mut rank = 0u64;
            for line in contents.lines() {
                let (word, count) = match line.split_once(' ') {
                    Some((word, count)) => (word, count.trim().parse::<u64>().unwrap_or(1)),
                    None => (line.trim(), 1),
                };
                if !is_indexable(word) {
                    continue;
                }
                rank += 1;
                if rank > WORDS_PER_LANGUAGE as u64 {
                    break;
                }
                *counts.entry(word.into()).or_default() += count.max(1);
            }
        }

        let mut languages = Vec::with_capacity(merged.len());
        for (language, counts) in merged {
            if counts.len() < 256 {
                stats.skipped += 1;
                continue;
            }

            let mut ranked = counts.into_iter().collect::<Vec<_>>();
            ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            ranked.truncate(WORDS_PER_LANGUAGE);

            let mut words = Vec::with_capacity(ranked.len());
            let mut cumulative = Vec::with_capacity(ranked.len());
            let mut total = 0u64;
            for (word, count) in ranked {
                total += count;
                words.push(word);
                cumulative.push(total);
            }

            stats.read += words.len();
            languages.push(LanguageWords {
                language,
                words,
                cumulative,
            });
        }

        languages.sort_unstable_by_key(|entry| entry.language as usize);
        Ok(Vocabulary { languages })
    }

    pub fn is_empty(&self) -> bool {
        self.languages.is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "{} languages, {} words",
            self.languages.len(),
            self.languages
                .iter()
                .map(|entry| entry.words.len())
                .sum::<usize>()
        )
    }

    fn documents(&self, samples: usize, corpus: &mut Corpus) -> Vec<(Language, usize, usize)> {
        let mut rng = Rng::new(SYNTHETIC_SEED);
        let total: u64 = self
            .languages
            .iter()
            .map(|entry| language_share(entry.language) as u64)
            .sum();
        let highest = self
            .languages
            .iter()
            .map(|entry| language_share(entry.language))
            .max()
            .unwrap_or(1) as u64;
        let mut report = Vec::with_capacity(self.languages.len());

        for entry in &self.languages {
            let share = language_share(entry.language) as u64;

            let covered = ((MAX_COVERAGE_WORDS as u64 * share / highest.max(1)) as usize)
                .max(MIN_COVERAGE_WORDS)
                .min(entry.words.len());
            for chunk in entry.words[..covered].chunks(COVERAGE_WORDS_PER_DOCUMENT) {
                corpus.push_train_only(coverage_document(entry, chunk));
            }

            let sampled = ((samples as u64 * share / total.max(1)) as usize).max(1);
            for index in 0..sampled {
                let document_id = index as u32;
                let sample = match index % 10 {
                    0 | 1 => contact_document(entry, &mut rng, document_id),
                    2 => calendar_document(entry, &mut rng, document_id),
                    3 => file_document(entry, &mut rng, document_id),
                    _ => email_document(entry, &mut rng, document_id),
                };
                corpus.push_train_only(sample);
            }

            report.push((entry.language, covered, sampled));
        }

        report.sort_unstable_by_key(|(_, _, sampled)| std::cmp::Reverse(*sampled));
        report
    }
}

fn coverage_document(entry: &LanguageWords, words: &[Box<str>]) -> Vec<u8> {
    let mut text = String::new();
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(word);
    }

    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(1)
        .with_document_id(0);
    document.index_text(EmailSearchField::Body, &text, entry.language);
    document.into_term_document(0)
}

fn is_indexable(word: &str) -> bool {
    (MIN_WORD_LEN..=CheekyHash::HASH_SIZE).contains(&word.len())
        && word
            .chars()
            .all(|ch| ch.is_alphanumeric() && !ch.is_uppercase())
}

fn body_length(rng: &mut Rng) -> usize {
    match rng.below(100) {
        0..=29 => rng.range(15, 80),
        30..=69 => rng.range(80, 350),
        70..=92 => rng.range(350, 1200),
        _ => rng.range(1200, 4000),
    }
}

fn email_document(entry: &LanguageWords, rng: &mut Rng, document_id: u32) -> Vec<u8> {
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(1)
        .with_document_id(document_id);

    document.index_text(
        EmailSearchField::From,
        &entry.addresses(rng, 1, 1),
        Language::None,
    );
    document.index_text(
        EmailSearchField::To,
        &entry.addresses(rng, 1, 4),
        Language::None,
    );
    if rng.chance(25) {
        document.index_text(
            EmailSearchField::Cc,
            &entry.addresses(rng, 1, 3),
            Language::None,
        );
    }
    document.index_text(
        EmailSearchField::Subject,
        &entry.phrase(rng, 2, 12),
        entry.language,
    );
    document.index_text(
        EmailSearchField::Body,
        &entry.body(rng),
        entry.language,
    );
    if rng.chance(20) {
        document.index_text(
            EmailSearchField::Attachment,
            &entry.phrase(rng, 50, 900),
            entry.language,
        );
    }

    for (name, value) in HEADER_NAMES.iter().zip(HEADER_VALUES.iter()) {
        if rng.chance(70) {
            document.insert_key_value(EmailSearchField::Headers, name, value);
        }
    }
    document.insert_key_value(
        EmailSearchField::Headers,
        "subject",
        entry.phrase(rng, 2, 12),
    );

    document.into_term_document(document_id)
}

fn contact_document(entry: &LanguageWords, rng: &mut Rng, document_id: u32) -> Vec<u8> {
    let mut document = IndexDocument::new(SearchIndex::Contacts)
        .with_account_id(1)
        .with_document_id(document_id);

    document.index_text(
        ContactSearchField::Name,
        &entry.phrase(rng, 2, 4),
        Language::None,
    );
    if rng.chance(30) {
        document.index_text(
            ContactSearchField::Nickname,
            entry.pick(rng),
            Language::None,
        );
    }
    if rng.chance(55) {
        document.index_text(
            ContactSearchField::Organization,
            &entry.phrase(rng, 1, 4),
            Language::None,
        );
    }
    document.index_text(
        ContactSearchField::Email,
        &entry.address(rng),
        Language::None,
    );
    if rng.chance(60) {
        document.index_text(
            ContactSearchField::Phone,
            &format!("+{} {} {}", rng.range(1, 99), rng.below(1000), rng.below(10000)),
            Language::None,
        );
    }
    if rng.chance(45) {
        document.index_text(
            ContactSearchField::Address,
            &entry.phrase(rng, 3, 9),
            Language::None,
        );
    }
    if rng.chance(20) {
        document.index_text(
            ContactSearchField::Note,
            &entry.phrase(rng, 5, 60),
            entry.language,
        );
    }
    document.index_keyword(
        ContactSearchField::Kind,
        CONTACT_KINDS[rng.below(CONTACT_KINDS.len())],
    );

    document.into_term_document(document_id)
}

fn calendar_document(entry: &LanguageWords, rng: &mut Rng, document_id: u32) -> Vec<u8> {
    let mut document = IndexDocument::new(SearchIndex::Calendar)
        .with_account_id(1)
        .with_document_id(document_id);

    document.index_text(
        CalendarSearchField::Title,
        &entry.phrase(rng, 2, 9),
        entry.language,
    );
    if rng.chance(60) {
        document.index_text(
            CalendarSearchField::Description,
            &entry.phrase(rng, 5, 120),
            entry.language,
        );
    }
    if rng.chance(50) {
        document.index_text(
            CalendarSearchField::Location,
            &entry.phrase(rng, 1, 6),
            Language::None,
        );
    }
    document.index_text(
        CalendarSearchField::Owner,
        &entry.address(rng),
        Language::None,
    );
    document.index_text(
        CalendarSearchField::Attendee,
        &entry.addresses(rng, 1, 8),
        Language::None,
    );

    document.into_term_document(document_id)
}

fn file_document(entry: &LanguageWords, rng: &mut Rng, document_id: u32) -> Vec<u8> {
    let mut document = IndexDocument::new(SearchIndex::File)
        .with_account_id(1)
        .with_document_id(document_id);

    document.index_text(
        FileSearchField::Name,
        &format!(
            "{} {}.{}",
            MEDIA_NAMES[rng.below(MEDIA_NAMES.len())],
            entry.pick(rng),
            FILE_EXTENSIONS[rng.below(FILE_EXTENSIONS.len())]
        ),
        Language::None,
    );
    if rng.chance(70) {
        document.index_text(
            FileSearchField::Content,
            &entry.body(rng),
            entry.language,
        );
    }

    document.into_term_document(document_id)
}

pub fn build(
    dir: &Path,
    vocabulary: &Vocabulary,
    samples: usize,
    train_on_messages: bool,
    stats: &mut Stats,
) -> std::io::Result<Corpus> {
    let mut corpus = Corpus::new();
    let parser = MessageParser::new();
    let index_fields = AHashSet::new();
    let mut document_id = 0u32;

    for path in collect_files(dir, &[])? {
        let Ok(raw) = std::fs::read(path) else {
            stats.skipped += 1;
            continue;
        };

        for message in split_mbox(&raw) {
            let message = with_ingest_headers(&normalize_crlf(&unescape_mbox(message)));
            let Some(metadata) = crate::metadata::metadata(&parser, &message) else {
                stats.skipped += 1;
                continue;
            };
            let bytes = archive(&metadata);
            let Ok(metadata) = rkyv_unarchive::<email::message::metadata::MessageMetadata>(&bytes)
            else {
                stats.skipped += 1;
                continue;
            };

            let sample = term_document(metadata, &message, &index_fields, document_id);
            document_id = document_id.wrapping_add(1);
            if sample.is_empty() {
                stats.skipped += 1;
                continue;
            }

            if train_on_messages {
                corpus.push_both(sample);
            } else {
                corpus.push_dev_only(sample);
            }
            stats.read += 1;
        }
    }

    let report = vocabulary.documents(samples, &mut corpus);
    println!("weighting :");
    for (language, covered, sampled) in report.iter().take(12) {
        println!("            {language:?} {covered} words covered, {sampled} documents");
    }
    if report.len() > 12 {
        let (words, documents) = report[12..]
            .iter()
            .fold((0, 0), |(words, documents), (_, covered, sampled)| {
                (words + covered, documents + sampled)
            });
        println!(
            "            {} more languages, {words} words covered, {documents} documents",
            report.len() - 12
        );
    }

    Ok(corpus)
}

fn term_document(
    metadata: &ArchivedMessageMetadata,
    raw_message: &[u8],
    index_fields: &AHashSet<SearchField>,
    document_id: u32,
) -> Vec<u8> {
    metadata
        .index_document(1, document_id, raw_message, index_fields, Language::Unknown)
        .into_term_document(document_id)
}
