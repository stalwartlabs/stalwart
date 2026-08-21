use std::path::Path;

use email::message::{index::PREVIEW_LENGTH, metadata::MessageMetadata};
use mail_parser::{
    MessageParser, PartType, decoders::html::html_to_text, parsers::preview::preview_text,
};
use types::blob_hash::BlobHash;

use crate::corpus::{Corpus, Stats, archive, collect_files, normalize_crlf};

const MAX_MESSAGE_PARTS: usize = 1000;

const INGEST_HEADERS: &str = concat!(
    "Return-Path: <>\r\n",
    "Delivered-To: <recipient@example.org>\r\n",
    "X-Spam-Status: No\r\n",
);

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
            corpus.push_both(archive(&metadata));
            stats.read += 1;
        }
    }

    Ok(corpus)
}

fn unescape_mbox(raw: &[u8]) -> Vec<u8> {
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

fn with_ingest_headers(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + INGEST_HEADERS.len());
    out.extend_from_slice(INGEST_HEADERS.as_bytes());
    out.extend_from_slice(raw);
    out
}

fn split_mbox(raw: &[u8]) -> Vec<&[u8]> {
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

fn metadata(parser: &MessageParser, raw: &[u8]) -> Option<MessageMetadata> {
    let message = parser.parse(raw)?;
    if message.parts.is_empty() {
        return None;
    }

    let preview_part_id = message
        .text_body
        .first()
        .or_else(|| message.html_body.first())
        .copied()
        .unwrap_or(u32::MAX);
    let mut preview = None;

    for (part_id, part) in message.parts.iter().take(MAX_MESSAGE_PARTS).enumerate() {
        if part_id as u32 != preview_part_id {
            continue;
        }
        match &part.body {
            PartType::Text(text) => {
                preview = preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
            }
            PartType::Html(html) => {
                let text = html_to_text(html);
                preview = preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
            }
            _ => {}
        }
    }

    let root_part = message.root_part();
    let blob_body_offset = root_part.offset_body;
    let raw_headers = raw
        .get(root_part.offset_header as usize..root_part.offset_body as usize)
        .unwrap_or_default()
        .to_vec();

    Some(MessageMetadata {
        preview: preview.unwrap_or_default().into_owned().into_boxed_str(),
        raw_headers: raw_headers.into_boxed_slice(),
        contents: email::message::metadata::build_metadata_contents(message),
        blob_hash: BlobHash::generate(raw),
        blob_body_offset,
    })
}
