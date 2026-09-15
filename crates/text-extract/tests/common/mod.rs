/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![allow(dead_code)]

use flate2::{Compress, Compression, Crc, FlushCompress};
use std::path::Path;
use text_extract::{Error, Extraction, Hints, Limits};

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATED: u16 = 8;
pub const METHOD_LZMA: u16 = 14;

pub const W_NS: &str = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"";
pub const MC_NS: &str = "xmlns:mc=\"http://schemas.openxmlformats.org/markup-compatibility/2006\"";

pub fn fixture(path: &str) -> Vec<u8> {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    std::fs::read(&full).unwrap_or_else(|err| panic!("fixture {}: {err}", full.display()))
}

pub fn run(data: &[u8]) -> (Result<Extraction, Error>, String) {
    run_with(data, Hints::new(), &Limits::default())
}

pub fn run_with(
    data: &[u8],
    hints: Hints<'_>,
    limits: &Limits,
) -> (Result<Extraction, Error>, String) {
    let mut out = String::new();
    let result =
        text_extract::extract(data, hints, limits, &mut out).map_err(|failure| failure.error);
    (result, out)
}

pub fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut compressor = Compress::new(Compression::default(), false);
    let mut out = Vec::with_capacity(data.len() / 2 + 1024);
    loop {
        let consumed = compressor.total_in() as usize;
        if out.capacity() - out.len() < 1024 {
            out.reserve(out.capacity());
        }
        let status = compressor
            .compress_vec(
                data.get(consumed..).unwrap_or_default(),
                &mut out,
                FlushCompress::Finish,
            )
            .unwrap_or_else(|err| panic!("deflate: {err}"));
        if status == flate2::Status::StreamEnd {
            return out;
        }
    }
}

fn full_flush_block(data: &[u8]) -> Vec<u8> {
    let mut compressor = Compress::new(Compression::best(), false);
    let mut out = Vec::with_capacity(data.len() + 1024);
    compressor
        .compress_vec(data, &mut out, FlushCompress::Full)
        .unwrap_or_else(|err| panic!("deflate block: {err}"));
    assert_eq!(compressor.total_in() as usize, data.len());
    out
}

pub struct Bomb {
    pub compressed: Vec<u8>,
    pub uncompressed_size: u64,
    pub crc: u32,
}

pub fn deflate_bomb(header: &[u8], chunk: &[u8], repeats: usize, trailer: &[u8]) -> Bomb {
    let mut compressed = full_flush_block(header);
    let block = full_flush_block(chunk);
    compressed.reserve(block.len() * repeats);
    for _ in 0..repeats {
        compressed.extend_from_slice(&block);
    }
    compressed.extend_from_slice(&full_flush_block(trailer));
    compressed.extend_from_slice(&[0x03, 0x00]);
    Bomb {
        compressed,
        uncompressed_size: (header.len() + chunk.len() * repeats + trailer.len()) as u64,
        crc: 0,
    }
}

#[derive(Clone)]
pub struct ZipEntry {
    pub name: Vec<u8>,
    pub central_name: Option<Vec<u8>>,
    pub method: u16,
    pub flags: u16,
    pub payload: Vec<u8>,
    pub crc: u32,
    pub uncompressed_size: u64,
    pub central_compressed_size: Option<u64>,
    pub central_uncompressed_size: Option<u64>,
    pub local_sizes_zero: bool,
    pub zip64: bool,
    pub alias_of: Option<usize>,
}

impl ZipEntry {
    pub fn new(name: &str, method: u16, contents: &[u8]) -> Self {
        let mut crc = Crc::new();
        crc.update(contents);
        ZipEntry {
            name: name.as_bytes().to_vec(),
            central_name: None,
            method,
            flags: 0,
            payload: if method == METHOD_DEFLATED {
                deflate(contents)
            } else {
                contents.to_vec()
            },
            crc: crc.sum(),
            uncompressed_size: contents.len() as u64,
            central_compressed_size: None,
            central_uncompressed_size: None,
            local_sizes_zero: false,
            zip64: false,
            alias_of: None,
        }
    }

    pub fn from_bomb(name: &str, bomb: Bomb) -> Self {
        ZipEntry {
            name: name.as_bytes().to_vec(),
            central_name: None,
            method: METHOD_DEFLATED,
            flags: 0,
            crc: bomb.crc,
            uncompressed_size: bomb.uncompressed_size,
            payload: bomb.compressed,
            central_compressed_size: None,
            central_uncompressed_size: None,
            local_sizes_zero: false,
            zip64: true,
            alias_of: None,
        }
    }

    pub fn alias(name: &str, target: usize) -> Self {
        let mut entry = ZipEntry::new(name, METHOD_STORED, b"");
        entry.alias_of = Some(target);
        entry
    }
}

#[derive(Default, Clone)]
pub struct ZipBuilder {
    pub entries: Vec<ZipEntry>,
    pub prefix: Vec<u8>,
    pub comment: Vec<u8>,
}

impl ZipBuilder {
    pub fn new() -> Self {
        ZipBuilder::default()
    }

    pub fn file(mut self, name: &str, contents: &[u8]) -> Self {
        self.entries
            .push(ZipEntry::new(name, METHOD_DEFLATED, contents));
        self
    }

    pub fn stored(mut self, name: &str, contents: &[u8]) -> Self {
        self.entries
            .push(ZipEntry::new(name, METHOD_STORED, contents));
        self
    }

    pub fn entry(mut self, entry: ZipEntry) -> Self {
        self.entries.push(entry);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = self.prefix.clone();
        let base = out.len();
        let mut offsets = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            if entry.alias_of.is_some() {
                offsets.push(0);
                continue;
            }
            offsets.push((out.len() - base) as u64);
            let (compressed, uncompressed) = if entry.local_sizes_zero {
                (0, 0)
            } else if entry.zip64 {
                (u32::MAX, u32::MAX)
            } else {
                (entry.payload.len() as u32, entry.uncompressed_size as u32)
            };
            let extra = if entry.zip64 {
                let mut extra = vec![0x01, 0x00, 16, 0];
                extra.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
                extra.extend_from_slice(&(entry.payload.len() as u64).to_le_bytes());
                extra
            } else {
                Vec::new()
            };
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&entry.flags.to_le_bytes());
            out.extend_from_slice(&entry.method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0x21, 0]);
            out.extend_from_slice(&entry.crc.to_le_bytes());
            out.extend_from_slice(&compressed.to_le_bytes());
            out.extend_from_slice(&uncompressed.to_le_bytes());
            out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            out.extend_from_slice(&entry.name);
            out.extend_from_slice(&extra);
            out.extend_from_slice(&entry.payload);
        }
        let central_start = out.len();
        for (index, entry) in self.entries.iter().enumerate() {
            let source = entry
                .alias_of
                .and_then(|target| {
                    self.entries
                        .get(target)
                        .map(|target_entry| (target, target_entry))
                })
                .unwrap_or((index, entry));
            let (source_index, source_entry) = source;
            let offset = offsets[source_index];
            let compressed = entry
                .central_compressed_size
                .unwrap_or(source_entry.payload.len() as u64);
            let uncompressed = entry
                .central_uncompressed_size
                .unwrap_or(source_entry.uncompressed_size);
            let zip64 = source_entry.zip64 || offset > u32::MAX as u64;
            let mut extra = Vec::new();
            if zip64 {
                extra.extend_from_slice(&[0x01, 0x00, 24, 0]);
                extra.extend_from_slice(&uncompressed.to_le_bytes());
                extra.extend_from_slice(&compressed.to_le_bytes());
                extra.extend_from_slice(&offset.to_le_bytes());
            }
            let name = entry.central_name.as_ref().unwrap_or(&entry.name);
            out.extend_from_slice(b"PK\x01\x02");
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&45u16.to_le_bytes());
            out.extend_from_slice(&source_entry.flags.to_le_bytes());
            out.extend_from_slice(&source_entry.method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0x21, 0]);
            out.extend_from_slice(&source_entry.crc.to_le_bytes());
            if zip64 {
                out.extend_from_slice(&u32::MAX.to_le_bytes());
                out.extend_from_slice(&u32::MAX.to_le_bytes());
            } else {
                out.extend_from_slice(&(compressed as u32).to_le_bytes());
                out.extend_from_slice(&(uncompressed as u32).to_le_bytes());
            }
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            if zip64 {
                out.extend_from_slice(&u32::MAX.to_le_bytes());
            } else {
                out.extend_from_slice(&(offset as u32).to_le_bytes());
            }
            out.extend_from_slice(name);
            out.extend_from_slice(&extra);
        }
        let central_size = out.len() - central_start;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0, 0, 0, 0]);
        let count = self.entries.len().min(0xFFFF) as u16;
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(central_size as u32).to_le_bytes());
        out.extend_from_slice(&((central_start - base) as u32).to_le_bytes());
        out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.comment);
        out
    }
}

pub fn docx(document_body: &str) -> ZipBuilder {
    ZipBuilder::new()
        .file("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>")
        .file(
            "_rels/.rels",
            b"<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>",
        )
        .file(
            "word/document.xml",
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><w:document {W_NS} {MC_NS}><w:body>{document_body}</w:body></w:document>").as_bytes(),
        )
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next() % bound as u64) as usize
        }
    }
}

pub fn mutate(data: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut mutated = data.to_vec();
    for _ in 0..1 + rng.below(8) {
        if mutated.is_empty() {
            break;
        }
        let at = rng.below(mutated.len());
        match rng.below(6) {
            0 => {
                mutated.remove(at);
            }
            1 => mutated.insert(at, rng.next() as u8),
            2 => mutated[at] = b"<>/&;\"'{}\\"[rng.below(10)],
            3 => {
                let len = rng.below(64).min(mutated.len() - at);
                let copy = mutated[at..at + len].to_vec();
                let to = rng.below(mutated.len());
                mutated.splice(to..to, copy);
            }
            4 => mutated.truncate(at),
            _ => mutated[at] = rng.next() as u8,
        }
    }
    mutated
}
