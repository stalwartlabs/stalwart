use std::path::Path;

use email::message::metadata::{ExtraHeaders, HeaderId, MessageMetadata, NewMetadata};
use mail_parser::MessageParser;
use types::blob_hash::BlobHash;

use crate::corpus::{Corpus, Stats, collect_files, normalize_crlf};

const INGEST_HEADERS: &str = "Return-Path: <>\r\n";
const DELIVERED_TO: &str = "<recipient@example.org>";
const SPAM_STATUS: &str = "No";

pub fn build(dir: &Path, stats: &mut Stats) -> std::io::Result<Corpus> {
    let files = collect_files(dir, &["eml", "mbox", "msg", "txt"])?;
    let mut corpus = Corpus::new();
    let parser = MessageParser::new();

    for path in &files {
        let Ok(raw) = std::fs::read(path) else {
            stats.skipped += 1;
            continue;
        };

        for message in split_mbox(&raw) {
            let message = with_ingest_headers(&normalize_crlf(&unescape_mbox(message)));
            let Some(metadata) = metadata(&parser, &message) else {
                stats.skipped += 1;
                continue;
            };
            corpus.push_both(metadata.raw_headers);
            stats.read += 1;
        }
    }

    Ok(corpus)
}

pub fn unescape_mbox(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        let mut line = line;
        while line.len() > 1 && line[0] == b'>' && line[1] == b'>' {
            line = &line[1..];
        }
        if line.starts_with(b">From ") {
            out.extend_from_slice(&line[1..]);
        } else {
            out.extend_from_slice(line);
        }
    }
    out
}

pub fn with_ingest_headers(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + INGEST_HEADERS.len());
    out.extend_from_slice(INGEST_HEADERS.as_bytes());
    out.extend_from_slice(raw);
    out
}

pub fn split_mbox(raw: &[u8]) -> Vec<&[u8]> {
    if !raw.starts_with(b"From ") {
        return vec![raw];
    }

    let mut messages = Vec::new();
    let mut start = None;
    let mut offset = 0;

    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"From ") {
            if let Some(start) = start.take()
                && offset > start
            {
                messages.push(&raw[start..offset]);
            }
            start = Some(offset + line.len());
        }
        offset += line.len();
    }
    if let Some(start) = start
        && offset > start
    {
        messages.push(&raw[start..offset]);
    }

    messages
}

pub fn metadata(parser: &MessageParser, raw: &[u8]) -> Option<NewMetadata> {
    let message = parser.parse(raw)?;
    let mut extra = ExtraHeaders::default();
    extra
        .push(HeaderId::DELIVERED_TO, DELIVERED_TO)
        .push(HeaderId::X_SPAM_STATUS, SPAM_STATUS);
    Some(MessageMetadata::build(
        &message,
        &extra,
        BlobHash::generate(raw),
    ))
}
