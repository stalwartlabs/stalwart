/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{cell::RefCell, sync::LazyLock};
use zstd::{
    bulk::{Compressor, Decompressor},
    dict::{DecoderDictionary, EncoderDictionary},
    zstd_safe::{
        CParameter, compress_bound, get_dict_id_from_dict, get_dict_id_from_frame,
        get_frame_content_size,
    },
};

pub const COMPRESSION_LEVEL: i32 = 3;
pub const TERM_COMPRESSION_LEVEL: i32 = 6;
pub const COMPRESS_WATERMARK: usize = 256;
pub const COMPRESS_WATERMARK_DICTIONARY: usize = 64;
pub const MAX_ARCHIVE_SIZE: usize = 64 * 1024 * 1024;

const DICTIONARIES: [&[u8]; 6] = [
    include_bytes!("../../../../resources/zstd/common-v1.dict"),
    include_bytes!("../../../../resources/zstd/email-v1.dict"),
    include_bytes!("../../../../resources/zstd/calendar-v1.dict"),
    include_bytes!("../../../../resources/zstd/contact-v1.dict"),
    include_bytes!("../../../../resources/zstd/sieve-v1.dict"),
    include_bytes!("../../../../resources/zstd/term-v1.dict"),
];

const ALL_DICTIONARIES: [Dictionary; DICTIONARIES.len()] = [
    Dictionary::Common,
    Dictionary::Email,
    Dictionary::Calendar,
    Dictionary::Contact,
    Dictionary::Sieve,
    Dictionary::Term,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dictionary {
    Common,
    Email,
    Calendar,
    Contact,
    Sieve,
    Term,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd(Option<Dictionary>),
}

pub trait ArchiveCompression {
    const COMPRESSION: Compression = Compression::Zstd(None);
}

impl ArchiveCompression for () {
    const COMPRESSION: Compression = Compression::None;
}

impl Dictionary {
    #[inline(always)]
    fn index(self) -> usize {
        match self {
            Dictionary::Common => 0,
            Dictionary::Email => 1,
            Dictionary::Calendar => 2,
            Dictionary::Contact => 3,
            Dictionary::Sieve => 4,
            Dictionary::Term => 5,
        }
    }

    #[inline(always)]
    const fn level(self) -> i32 {
        match self {
            Dictionary::Term => TERM_COMPRESSION_LEVEL,
            _ => COMPRESSION_LEVEL,
        }
    }
}

#[inline(always)]
pub const fn compress_watermark(dictionary: Option<Dictionary>) -> usize {
    if dictionary.is_some() {
        COMPRESS_WATERMARK_DICTIONARY
    } else {
        COMPRESS_WATERMARK
    }
}

static ENCODER_DICTIONARIES: LazyLock<Vec<EncoderDictionary<'static>>> = LazyLock::new(|| {
    DICTIONARIES
        .iter()
        .zip(ALL_DICTIONARIES)
        .map(|(dict, dictionary)| EncoderDictionary::copy(dict, dictionary.level()))
        .collect()
});

static DECODER_DICTIONARIES: LazyLock<Vec<(u32, DecoderDictionary<'static>)>> =
    LazyLock::new(|| {
        let mut dictionaries: Vec<(u32, DecoderDictionary<'static>)> =
            Vec::with_capacity(DICTIONARIES.len());
        for dict in DICTIONARIES {
            let id = get_dict_id_from_dict(dict)
                .expect("shipped compression dictionary carries no identifier")
                .get();
            if !dictionaries.iter().any(|(known, _)| *known == id) {
                dictionaries.push((id, DecoderDictionary::copy(dict)));
            }
        }
        dictionaries
    });

pub fn init() {
    LazyLock::force(&ENCODER_DICTIONARIES);
    LazyLock::force(&DECODER_DICTIONARIES);
}

thread_local! {
    static COMPRESSORS: RefCell<Vec<Compressor<'static>>> = RefCell::new(
        std::iter::once(None)
            .chain(ALL_DICTIONARIES.map(Some))
            .map(|dictionary| {
                new_compressor(dictionary).expect("failed to create a zstd compression context")
            })
            .collect(),
    );
    static DECOMPRESSORS: RefCell<Vec<Decompressor<'static>>> = RefCell::new({
        let mut decompressors = Vec::with_capacity(DECODER_DICTIONARIES.len() + 1);
        decompressors.push(
            Decompressor::new().expect("failed to create a zstd decompression context"),
        );
        for (_, dictionary) in DECODER_DICTIONARIES.iter() {
            decompressors.push(
                Decompressor::with_prepared_dictionary(dictionary)
                    .expect("failed to create a zstd decompression context"),
            );
        }
        decompressors
    });
}

fn new_compressor(dictionary: Option<Dictionary>) -> std::io::Result<Compressor<'static>> {
    let mut compressor = match dictionary {
        Some(dictionary) => {
            Compressor::with_prepared_dictionary(&ENCODER_DICTIONARIES[dictionary.index()])?
        }
        None => Compressor::new(COMPRESSION_LEVEL)?,
    };
    compressor.set_parameter(CParameter::ChecksumFlag(true))?;
    compressor.set_parameter(CParameter::ContentSizeFlag(true))?;
    Ok(compressor)
}

pub fn compress(
    dictionary: Option<Dictionary>,
    input: &[u8],
    trailer_len: usize,
) -> std::io::Result<Vec<u8>> {
    let slot = dictionary.map_or(0, |dictionary| dictionary.index() + 1);
    let mut output = Vec::with_capacity(compress_bound(input.len()));

    COMPRESSORS
        .with_borrow_mut(|compressors| compressors[slot].compress_to_buffer(input, &mut output))?;
    output.reserve(trailer_len);

    Ok(output)
}

fn decoder_slot(frame: &[u8]) -> std::io::Result<usize> {
    match get_dict_id_from_frame(frame).map(|id| id.get()) {
        Some(id) => DECODER_DICTIONARIES
            .iter()
            .position(|(known, _)| *known == id)
            .map(|slot| slot + 1)
            .ok_or_else(|| std::io::Error::other(format!("unknown compression dictionary {id}"))),
        None => Ok(0),
    }
}

fn frame_capacity(frame: &[u8], limit: usize) -> std::io::Result<usize> {
    match get_frame_content_size(frame) {
        Ok(Some(size)) if size <= limit as u64 => Ok(size as usize),
        Ok(Some(size)) => Err(std::io::Error::other(format!(
            "archive of {size} bytes exceeds the {limit} byte limit"
        ))),
        Ok(None) => Err(std::io::Error::other(
            "compression frame declares no content size",
        )),
        Err(err) => Err(std::io::Error::other(format!(
            "malformed compression frame header: {err}"
        ))),
    }
}

pub fn decompress(frame: &[u8]) -> std::io::Result<Vec<u8>> {
    let slot = decoder_slot(frame)?;
    let capacity = frame_capacity(frame, MAX_ARCHIVE_SIZE)?;

    DECOMPRESSORS.with_borrow_mut(|decompressors| decompressors[slot].decompress(frame, capacity))
}

pub fn decompress_into(frame: &[u8], output: &mut Vec<u8>, limit: usize) -> std::io::Result<()> {
    let slot = decoder_slot(frame)?;
    let capacity = frame_capacity(frame, limit)?;

    output.clear();
    output.reserve(capacity);
    DECOMPRESSORS
        .with_borrow_mut(|decompressors| decompressors[slot].decompress_to_buffer(frame, output))
        .map(|_| ())
}
