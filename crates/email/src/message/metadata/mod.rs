/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod build;
pub mod header_id;
pub mod row;
pub mod source;
pub mod view;

#[cfg(test)]
mod tests;

use std::ops::{BitOr, BitOrAssign};
use types::{blob::MAX_SECTION_CONTAINERS, blob_hash::BlobHash};

pub use build::{ExtraHeaders, MAX_POOL_LEN, NewMetadata};
pub use header_id::HeaderId;
pub use row::{MetadataRow, MetadataStructure};
pub use source::{DecodedText, PartSource, RawMessage, SourceChain};
pub use view::{
    AddressHeader, AddressItem, Addresses, BodyList, ContentTypeView, EnvelopeView, Group,
    HeaderList, HeaderMatcher, HeaderView, Mailbox, MessageView, Occurrence, PartView, TextItems,
};

pub use common::config::mailstore::limits::MAX_HEADER_ENTRIES;

pub const NONE: u32 = u32::MAX;
pub const GROUP_BIT: u16 = 1 << 15;
pub const MAX_PART_ENTRIES: usize = 16_384;
pub const MAX_ADDRESS_ENTRIES: usize = Span::MAX_LEN;
pub const MAX_FIELD_ADDRESSES: usize = GROUP_BIT as usize - 1;
pub const MAX_TEXT_ITEMS: usize = 4_096;
pub const MAX_PARAMS: usize = 4_096;
pub const MAX_VALUE_LEN: usize = Str::MAX_LEN;
pub const MAX_PROTECTED_VALUE_LEN: usize = 127;
pub const MAX_SOURCE_DEPTH: usize = MAX_SECTION_CONTAINERS;
pub const MAX_NESTING: usize = 256;

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct Str {
    pub start: u32,
    pub len: u16,
}

#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[rkyv(derive(Debug))]
pub struct Span {
    pub start: u32,
    pub len: u16,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Default)]
pub struct MessageMetadata {
    pub blob_hash: BlobHash,
    pub blob_body_offset: u32,
    pub preview: Str,
    pub messages: Vec<MessageEntry>,
    pub parts: Vec<PartEntry>,
    pub headers: Vec<HeaderEntry>,
    pub ids: Vec<u32>,
    pub addresses: Vec<AddressEntry>,
    pub texts: Vec<Str>,
    pub params: Vec<ParamEntry>,
    pub strings: String,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct MessageEntry {
    pub parts: Span,
    pub container: u32,
    pub source: u32,
    pub text_body: Span,
    pub html_body: Span,
    pub attachments: Span,
    pub envelope: Envelope,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct Envelope {
    pub date: Option<MetadataDate>,
    pub date_raw: Str,
    pub subject: Str,
    pub from: AddressField,
    pub sender: AddressField,
    pub reply_to: AddressField,
    pub to: AddressField,
    pub cc: AddressField,
    pub bcc: AddressField,
    pub in_reply_to: Span,
    pub message_id: Span,
}

#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[rkyv(derive(Debug))]
pub struct AddressField {
    pub entries: Span,
    pub last: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct MetadataDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_hour: u8,
    pub tz_minute: TzMinute,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq))]
pub struct TzMinute(u8);

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct PartEntry {
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
    pub message: u32,
    pub headers: Span,
    pub children: Span,
    pub decoded_size: u32,
    pub lines: u32,
    pub content_type: ContentTypeEntry,
    pub content_disposition: ContentTypeEntry,
    pub content_id: Str,
    pub content_description: Str,
    pub content_transfer_encoding: Str,
    pub content_location: Str,
    pub content_md5: Str,
    pub content_language: Span,
    pub info: PartInfo,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq))]
pub struct PartInfo(u16);

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct ContentTypeEntry {
    pub ctype: Str,
    pub subtype: Str,
    pub params: Span,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct HeaderEntry {
    pub name: HeaderId,
    pub offset_field: u32,
    pub offset_value: u32,
    pub offset_end: u32,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct AddressEntry {
    pub name: Str,
    pub address: Str,
    pub group: u16,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy)]
#[rkyv(derive(Debug))]
pub struct ParamEntry {
    pub name: Str,
    pub value: Str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PartKind {
    Text = 0,
    Html = 1,
    Binary = 2,
    InlineBinary = 3,
    Multipart = 4,
    Message = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransferEncoding {
    None = 0,
    QuotedPrintable = 1,
    Base64 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PartFlags(pub u8);

impl PartFlags {
    pub const IN_TEXT_BODY: PartFlags = PartFlags(1);
    pub const IN_HTML_BODY: PartFlags = PartFlags(1 << 1);
    pub const ATTACHMENT: PartFlags = PartFlags(1 << 2);
    pub const UNKNOWN_TRANSFER_ENCODING: PartFlags = PartFlags(1 << 3);

    pub fn contains(self, other: PartFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for PartFlags {
    type Output = PartFlags;

    fn bitor(self, other: PartFlags) -> PartFlags {
        PartFlags(self.0 | other.0)
    }
}

impl BitOrAssign for PartFlags {
    fn bitor_assign(&mut self, other: PartFlags) {
        self.0 |= other.0;
    }
}

impl Str {
    pub const ABSENT_LEN: u16 = u16::MAX;
    pub const MAX_LEN: usize = Str::ABSENT_LEN as usize - 1;
    pub const NONE: Str = Str {
        start: 0,
        len: Str::ABSENT_LEN,
    };

    #[inline]
    fn new(start: u32, len: usize) -> Str {
        debug_assert!(len <= Str::MAX_LEN);
        Str {
            start,
            len: len.min(Str::MAX_LEN) as u16,
        }
    }
}

impl Default for Str {
    fn default() -> Self {
        Str::NONE
    }
}

impl Span {
    pub const MAX_LEN: usize = u16::MAX as usize - 1;
    pub const EMPTY: Span = Span { start: 0, len: 0 };
    pub const ABSENT: Span = Span {
        start: NONE,
        len: 0,
    };

    #[inline]
    fn between(start: u32, end: usize) -> Span {
        let len = end.saturating_sub(start as usize);
        debug_assert!(len <= Span::MAX_LEN);
        Span {
            start,
            len: len.min(Span::MAX_LEN) as u16,
        }
    }
}

impl PartKind {
    #[inline]
    fn from_bits(bits: u16) -> PartKind {
        match bits {
            0 => PartKind::Text,
            1 => PartKind::Html,
            3 => PartKind::InlineBinary,
            4 => PartKind::Multipart,
            5 => PartKind::Message,
            _ => PartKind::Binary,
        }
    }
}

impl TransferEncoding {
    #[inline]
    fn from_bits(bits: u16) -> TransferEncoding {
        match bits {
            1 => TransferEncoding::QuotedPrintable,
            2 => TransferEncoding::Base64,
            _ => TransferEncoding::None,
        }
    }
}

impl PartInfo {
    const FLAGS: u16 = 0x00ff;
    const KIND_SHIFT: u32 = 8;
    const KIND: u16 = 0x7 << PartInfo::KIND_SHIFT;
    const ENCODING_SHIFT: u32 = 11;
    const ENCODING: u16 = 0x3 << PartInfo::ENCODING_SHIFT;

    pub const fn new(kind: PartKind, encoding: TransferEncoding, flags: PartFlags) -> Self {
        PartInfo(
            flags.0 as u16
                | (kind as u16) << PartInfo::KIND_SHIFT
                | (encoding as u16) << PartInfo::ENCODING_SHIFT,
        )
    }

    #[inline]
    pub fn kind(self) -> PartKind {
        PartKind::from_bits((self.0 & PartInfo::KIND) >> PartInfo::KIND_SHIFT)
    }

    #[inline]
    pub fn encoding(self) -> TransferEncoding {
        TransferEncoding::from_bits((self.0 & PartInfo::ENCODING) >> PartInfo::ENCODING_SHIFT)
    }

    #[inline]
    pub fn flags(self) -> PartFlags {
        PartFlags((self.0 & PartInfo::FLAGS) as u8)
    }
}

impl BitOrAssign<PartFlags> for PartInfo {
    fn bitor_assign(&mut self, flags: PartFlags) {
        self.0 |= u16::from(flags.0);
    }
}

impl TzMinute {
    const BEFORE_GMT: u8 = 1 << 7;
    const MINUTE: u8 = !TzMinute::BEFORE_GMT;

    #[inline]
    pub fn new(minute: u8, before_gmt: bool) -> Self {
        TzMinute(minute.min(TzMinute::MINUTE) | if before_gmt { TzMinute::BEFORE_GMT } else { 0 })
    }

    #[inline]
    pub fn minute(self) -> u8 {
        self.0 & TzMinute::MINUTE
    }

    #[inline]
    pub fn is_before_gmt(self) -> bool {
        self.0 & TzMinute::BEFORE_GMT != 0
    }
}

impl ContentTypeEntry {
    pub const NONE: ContentTypeEntry = ContentTypeEntry {
        ctype: Str::NONE,
        subtype: Str::NONE,
        params: Span::EMPTY,
    };
}

impl AddressField {
    pub const EMPTY: AddressField = AddressField {
        entries: Span::EMPTY,
        last: 0,
    };
}

impl Envelope {
    pub const EMPTY: Envelope = Envelope {
        date: None,
        date_raw: Str::NONE,
        subject: Str::NONE,
        from: AddressField::EMPTY,
        sender: AddressField::EMPTY,
        reply_to: AddressField::EMPTY,
        to: AddressField::EMPTY,
        cc: AddressField::EMPTY,
        bcc: AddressField::EMPTY,
        in_reply_to: Span::ABSENT,
        message_id: Span::ABSENT,
    };
}

impl From<mail_parser::DateTime> for MetadataDate {
    fn from(date: mail_parser::DateTime) -> Self {
        MetadataDate {
            year: date.year,
            month: date.month,
            day: date.day,
            hour: date.hour,
            minute: date.minute,
            second: date.second,
            tz_hour: date.tz_hour,
            tz_minute: TzMinute::new(date.tz_minute, date.tz_before_gmt),
        }
    }
}

impl From<&ArchivedMetadataDate> for mail_parser::DateTime {
    fn from(date: &ArchivedMetadataDate) -> Self {
        let tz_minute = TzMinute(date.tz_minute.0);
        mail_parser::DateTime {
            year: date.year.to_native(),
            month: date.month,
            day: date.day,
            hour: date.hour,
            minute: date.minute,
            second: date.second,
            tz_before_gmt: tz_minute.is_before_gmt(),
            tz_hour: date.tz_hour,
            tz_minute: tz_minute.minute(),
        }
    }
}
