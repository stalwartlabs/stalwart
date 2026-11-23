/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::charsets::Charset;

pub(crate) mod address;
pub mod blob;
pub mod category;
pub mod context;
pub mod conversation;
pub mod ical;
pub mod mime;
pub mod model;
pub mod roaming;
pub mod rtf;
pub mod tags;
pub mod tnef;
pub mod vcard;
pub mod work_hours;

pub use address::{
    RECEIVED_REPRESENTING_IDS, clear_received_representing, set_received_representing,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    Rtf,
    Recurrence,
    TimeZoneDefinition,
    TimeZoneStruct,
    GlobalObjectId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertError {
    Mime,
    TooLarge,
    BadBlob { what: BlobKind, offset: u32 },
    Crc,
    Tnef { offset: u32 },
    Unsupported,
}

pub const MAX_EMBED_DEPTH: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobLimits {
    pub max_exceptions: u16,
    pub max_attr_len: u32,
    pub max_depth: u8,
    pub max_bag_props: u16,
    pub max_stream_moves: u32,
}

impl BlobLimits {
    pub const DEFAULT: Self = BlobLimits {
        max_exceptions: 1024,
        max_attr_len: 64 * 1024 * 1024,
        max_depth: MAX_EMBED_DEPTH,
        max_bag_props: 2048,
        max_stream_moves: 2 * 2048 * 2048,
    };
}

pub(crate) fn code_page_charset(code_page: u16) -> Charset {
    match code_page {
        65001 => Charset::Utf8,
        1250 => Charset::Windows1250,
        1251 => Charset::Windows1251,
        1253 => Charset::Windows1253,
        1254 => Charset::Windows1254,
        1255 => Charset::Windows1255,
        1256 => Charset::Windows1256,
        1257 => Charset::Windows1257,
        1258 => Charset::Windows1258,
        874 => Charset::Windows874,
        932 => Charset::ShiftJis,
        936 => Charset::Gbk,
        949 => Charset::EucKr,
        950 => Charset::Big5,
        866 => Charset::Ibm866,
        437 | 850 => Charset::Ibm850,
        10000 => Charset::Macintosh,
        20866 => Charset::Koi8R,
        21866 => Charset::Koi8U,
        51932 => Charset::EucJp,
        50220..=50222 => Charset::Iso2022Jp,
        54936 => Charset::Gb18030,
        28592 => Charset::Iso8859_2,
        28593 => Charset::Iso8859_3,
        28594 => Charset::Iso8859_4,
        28595 => Charset::Iso8859_5,
        28596 => Charset::Iso8859_6,
        28597 => Charset::Iso8859_7,
        28598 => Charset::Iso8859_8,
        28599 => Charset::Iso8859_9,
        28603 => Charset::Iso8859_13,
        28605 => Charset::Iso8859_15,
        _ => Charset::Windows1252,
    }
}

pub(crate) fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

impl Default for BlobLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
