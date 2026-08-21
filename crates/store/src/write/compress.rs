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
pub const COMPRESS_WATERMARK: usize = 256;
pub const COMPRESS_WATERMARK_DICTIONARY: usize = 64;
pub const MAX_ARCHIVE_SIZE: usize = 64 * 1024 * 1024;

const EMAIL_DICTIONARY: &[u8] = include_bytes!("../../../../resources/zstd/email-v1.dict");

// TODO: only `Email` is trained. `Common`, `Calendar`, `Contact` and `Sieve` are placeholders
// pointing at the email dictionary and have to be trained before release:
//
//   Common   - the small archives that take the default: Mailbox, Identity, EmailSubmission,
//              SieveScript, the SMTP queue Message, PushSubscriptions, ParticipantIdentities,
//              Calendar, AddressBook and FileNode. Highest value of the four: between 128 and 512
//              bytes a dictionary encodes 4 to 5 times faster and stores 20% less than none.
//   Calendar - CalendarEvent and CalendarEventNotification, dominated by iCalendar content.
//   Contact  - ContactCard, dominated by vCard content.
//   Sieve    - compiled Sieve scripts, which are rkyv-encoded bytecode rather than text.
//
// Entries may be retrained but never removed or reordered: a frame records the identifier of the
// dictionary it was written with, and a value becomes undecodable if that identifier disappears
// from the table.

const DICTIONARIES: [&[u8]; 5] = [
    EMAIL_DICTIONARY,
    EMAIL_DICTIONARY,
    EMAIL_DICTIONARY,
    EMAIL_DICTIONARY,
    EMAIL_DICTIONARY,
];

const ALL_DICTIONARIES: [Dictionary; DICTIONARIES.len()] = [
    Dictionary::Common,
    Dictionary::Email,
    Dictionary::Calendar,
    Dictionary::Contact,
    Dictionary::Sieve,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dictionary {
    Common,
    Email,
    Calendar,
    Contact,
    Sieve,
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
        .map(|dict| EncoderDictionary::copy(dict, COMPRESSION_LEVEL))
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

    let len = COMPRESSORS
        .with_borrow_mut(|compressors| compressors[slot].compress_to_buffer(input, &mut output))?;
    output.shrink_to(len + trailer_len);

    Ok(output)
}

pub fn decompress(frame: &[u8]) -> std::io::Result<Vec<u8>> {
    let slot = match get_dict_id_from_frame(frame).map(|id| id.get()) {
        Some(id) => {
            DECODER_DICTIONARIES
                .iter()
                .position(|(known, _)| *known == id)
                .ok_or_else(|| {
                    std::io::Error::other(format!("unknown compression dictionary {id}"))
                })?
                + 1
        }
        None => 0,
    };

    let capacity = match get_frame_content_size(frame) {
        Ok(Some(size)) if size <= MAX_ARCHIVE_SIZE as u64 => size as usize,
        Ok(Some(size)) => {
            return Err(std::io::Error::other(format!(
                "archive of {size} bytes exceeds the {MAX_ARCHIVE_SIZE} byte limit"
            )));
        }
        Ok(None) => {
            return Err(std::io::Error::other(
                "compression frame declares no content size",
            ));
        }
        Err(err) => {
            return Err(std::io::Error::other(format!(
                "malformed compression frame header: {err}"
            )));
        }
    };

    DECOMPRESSORS.with_borrow_mut(|decompressors| decompressors[slot].decompress(frame, capacity))
}
