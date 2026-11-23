/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

#[rustfmt::skip]
mod table;

pub use table::tag;

pub const PAGE_COUNT: usize = 26;
pub const TOKENS_PER_PAGE: usize = 64;
const TOKEN_MASK: u8 = 0x3F;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag(u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagInfo {
    pub versions: VersionSet,
    pub value: ValueEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueEncoding {
    Container,
    Text,
    Opaque,
    Base64Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    V140,
    V141,
    V160,
    V161,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VersionSet(u8);

impl Tag {
    pub const fn new(page: u8, token: u8) -> Self {
        Tag(((page as u16) << 8) | (token & TOKEN_MASK) as u16)
    }

    pub const fn page(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub const fn token(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    pub const fn from_raw(raw: u16) -> Self {
        Tag(raw)
    }

    pub const fn raw(self) -> u16 {
        self.0
    }

    pub fn name(self) -> Option<&'static str> {
        table::name(self.page(), self.token())
    }

    pub fn from_name(page: u8, name: &[u8]) -> Option<Self> {
        table::from_name(page, name)
    }

    pub fn info(self) -> TagInfo {
        usize::from(self.page())
            .checked_mul(TOKENS_PER_PAGE)
            .and_then(|base| base.checked_add(usize::from(self.token())))
            .and_then(|index| table::INFO.get(index))
            .copied()
            .unwrap_or(TagInfo::UNKNOWN)
    }

    pub fn is_known(self) -> bool {
        self.info().versions != VersionSet::EMPTY
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (page_name(self.page()), self.name()) {
            (Some(page), Some(name)) => write!(f, "{page}:{name}"),
            _ => write!(f, "{}:0x{:02X}", self.page(), self.token()),
        }
    }
}

pub fn page_name(page: u8) -> Option<&'static str> {
    table::page_name(page)
}

pub fn page_from_name(name: &[u8]) -> Option<u8> {
    table::page_from_name(name)
}

impl TagInfo {
    pub const UNKNOWN: TagInfo = TagInfo {
        versions: VersionSet::EMPTY,
        value: ValueEncoding::Text,
    };
}

impl ProtocolVersion {
    pub const ALL: [ProtocolVersion; 4] = [
        ProtocolVersion::V140,
        ProtocolVersion::V141,
        ProtocolVersion::V160,
        ProtocolVersion::V161,
    ];

    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::map!(
            value.trim_ascii(),
            ProtocolVersion,
            "14.0" => ProtocolVersion::V140,
            "14.1" => ProtocolVersion::V141,
            "16.0" => ProtocolVersion::V160,
            "16.1" => ProtocolVersion::V161,
        )
        .copied()
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            140 => Some(ProtocolVersion::V140),
            141 => Some(ProtocolVersion::V141),
            160 => Some(ProtocolVersion::V160),
            161 => Some(ProtocolVersion::V161),
            _ => None,
        }
    }

    pub fn code(self) -> u8 {
        match self {
            ProtocolVersion::V140 => 140,
            ProtocolVersion::V141 => 141,
            ProtocolVersion::V160 => 160,
            ProtocolVersion::V161 => 161,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ProtocolVersion::V140 => "14.0",
            ProtocolVersion::V141 => "14.1",
            ProtocolVersion::V160 => "16.0",
            ProtocolVersion::V161 => "16.1",
        }
    }

    pub fn is_16(self) -> bool {
        self >= ProtocolVersion::V160
    }

    const fn bit(self) -> u8 {
        match self {
            ProtocolVersion::V140 => VersionSet::V140,
            ProtocolVersion::V141 => VersionSet::V141,
            ProtocolVersion::V160 => VersionSet::V160,
            ProtocolVersion::V161 => VersionSet::V161,
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl VersionSet {
    pub const EMPTY: VersionSet = VersionSet(0);
    pub const V25: u8 = 0x01;
    pub const V120: u8 = 0x02;
    pub const V121: u8 = 0x04;
    pub const V140: u8 = 0x08;
    pub const V141: u8 = 0x10;
    pub const V160: u8 = 0x20;
    pub const V161: u8 = 0x40;

    pub const fn from_bits(bits: u8) -> Self {
        VersionSet(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, v: ProtocolVersion) -> bool {
        self.0 & v.bit() != 0
    }
}

macro_rules! eas_tokens {
    (
        pages { $( $pnum:tt $pname:tt ),* $(,)? }
        $(
            $page:tt $module:ident {
                $( $token:tt $konst:ident $name:tt $versions:tt $value:ident ),* $(,)?
            }
        )*
    ) => {
        pub mod tag {
            $(
                pub mod $module {
                    use $crate::eas::tokens::Tag;
                    $( pub const $konst: Tag = Tag::new($page, $token); )*
                }
            )*
        }

        pub(super) fn page_name(page: u8) -> Option<&'static str> {
            match page {
                $( $pnum => Some($pname), )*
                _ => None,
            }
        }

        pub(super) fn page_from_name(name: &[u8]) -> Option<u8> {
            hashify::map!(name, u8, $( $pname => $pnum, )*).copied()
        }

        pub(super) const fn info(page: u8, token: u8) -> super::TagInfo {
            match (page, token) {
                $( $(
                    ($page, $token) => super::TagInfo {
                        versions: super::VersionSet::from_bits($versions),
                        value: super::ValueEncoding::$value,
                    },
                )* )*
                _ => super::TagInfo::UNKNOWN,
            }
        }

        pub(super) fn name(page: u8, token: u8) -> Option<&'static str> {
            match (page, token) {
                $( $( ($page, $token) => Some($name), )* )*
                _ => None,
            }
        }

        pub(super) fn from_name(page: u8, name: &[u8]) -> Option<super::Tag> {
            match page {
                $( $page => hashify::map!(name, super::Tag, $( $name => super::Tag::new($page, $token), )*).copied(), )*
                _ => None,
            }
        }

        #[allow(clippy::indexing_slicing, clippy::cast_possible_truncation, clippy::arithmetic_side_effects)]
        pub(super) static INFO: [super::TagInfo; super::PAGE_COUNT * super::TOKENS_PER_PAGE] = {
            let mut table = [super::TagInfo::UNKNOWN; super::PAGE_COUNT * super::TOKENS_PER_PAGE];
            let mut index = 0;
            while index < table.len() {
                table[index] = info((index / super::TOKENS_PER_PAGE) as u8, (index % super::TOKENS_PER_PAGE) as u8);
                index += 1;
            }
            table
        };
    };
}

use eas_tokens;
