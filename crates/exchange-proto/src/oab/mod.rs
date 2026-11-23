/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod lzx;
pub mod manifest;
pub mod path;
pub mod writer;

use crate::mapi::prop::PropTag;

pub use lzx::{wrap, wrapped_len};
pub use manifest::{ManifestFile, OabManifest, write_manifest};
pub use path::{OabFile, OabRequest};
pub use writer::{OabHeader, full_head, write_record};

pub const FLAG_ANR: u32 = 1;
pub const FLAG_PRIMARY_KEY: u32 = 2;

pub const GAL_NAME: &str = "\\Global Address List";
pub const FULL_VERSION: u32 = 0x20;
pub const TEMPLATE_VERSION: u32 = 7;

pub const OAB_NAME: PropTag = PropTag(0x6800_001F);
pub const OAB_DISTINGUISHED_NAME: PropTag = PropTag(0x6804_001E);
pub const OAB_SEQUENCE: PropTag = PropTag(0x6801_0003);
pub const OAB_CONTAINER_GUID: PropTag = PropTag(0x6802_001E);
pub const OAB_TRUNCATED_PROPERTIES: PropTag = PropTag(0x6805_1003);

pub const EMAIL_ADDRESS: PropTag = PropTag(0x3003_001E);
pub const HOME_MESSAGE_DATABASE: PropTag = PropTag(0x8006_001E);
pub const ADDRESS_BOOK_MEMBER: PropTag = PropTag(0x8009_101E);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OabProp {
    pub tag: PropTag,
    pub flags: u32,
}

impl OabProp {
    pub const fn new(tag: u32, flags: u32) -> Self {
        OabProp {
            tag: PropTag(tag),
            flags,
        }
    }
}

pub const HEADER_PROPS: [OabProp; 4] = [
    OabProp::new(OAB_NAME.0, 0),
    OabProp::new(OAB_DISTINGUISHED_NAME.0, 0),
    OabProp::new(OAB_SEQUENCE.0, 0),
    OabProp::new(OAB_CONTAINER_GUID.0, 0),
];

pub const OBJECT_PROPS: [OabProp; 40] = [
    OabProp::new(EMAIL_ADDRESS.0, FLAG_PRIMARY_KEY),
    OabProp::new(0x39FE_001F, FLAG_PRIMARY_KEY),
    OabProp::new(0x3001_001F, FLAG_ANR),
    OabProp::new(0x3A00_001F, FLAG_ANR),
    OabProp::new(0x3A11_001F, FLAG_ANR),
    OabProp::new(0x3A06_001F, FLAG_ANR),
    OabProp::new(0x800F_101F, FLAG_ANR),
    OabProp::new(0x3A19_001F, FLAG_ANR),
    OabProp::new(0x3900_0003, 0),
    OabProp::new(0x0FFE_0003, 0),
    OabProp::new(0x3A40_000B, 0),
    OabProp::new(0x3A08_001F, 0),
    OabProp::new(0x3A0A_001F, 0),
    OabProp::new(0x3A29_001F, 0),
    OabProp::new(0x3A27_001F, 0),
    OabProp::new(0x3A28_001F, 0),
    OabProp::new(0x3A2A_001F, 0),
    OabProp::new(0x3A26_001F, 0),
    OabProp::new(0x3A17_001F, 0),
    OabProp::new(0x3A16_001F, 0),
    OabProp::new(0x3A30_001F, 0),
    OabProp::new(0x3A18_001F, 0),
    OabProp::new(0x8011_001F, 0),
    OabProp::new(0x3A09_001F, 0),
    OabProp::new(0x3A1B_101F, 0),
    OabProp::new(0x3A2F_101F, 0),
    OabProp::new(0x3A23_001F, 0),
    OabProp::new(0x3A1C_001F, 0),
    OabProp::new(0x3A2E_001F, 0),
    OabProp::new(0x3A21_001F, 0),
    OabProp::new(0x3004_001F, 0),
    OabProp::new(0x3A22_0102, 0),
    OabProp::new(0x3A70_1102, 0),
    OabProp::new(0x8C6A_1102, 0),
    OabProp::new(HOME_MESSAGE_DATABASE.0, 0),
    OabProp::new(0x39FF_001E, 0),
    OabProp::new(0x3905_0003, 0),
    OabProp::new(0x8008_101E, 0),
    OabProp::new(ADDRESS_BOOK_MEMBER.0, 0),
    OabProp::new(OAB_TRUNCATED_PROPERTIES.0, 0),
];

pub const TEMPLATE_LEN: usize = 256;

pub const TEMPLATE: [u8; TEMPLATE_LEN] = {
    let mut template = [0u8; TEMPLATE_LEN];
    let version = TEMPLATE_VERSION.to_le_bytes();
    template[0] = version[0];
    template[1] = version[1];
    template[2] = version[2];
    template[3] = version[3];
    template
};

#[derive(Debug, Clone, Copy)]
pub enum OabValue<'x> {
    Bool(bool),
    Int(u32),
    Binary(&'x [u8]),
    Text(&'x str),
    Texts(&'x [Box<str>]),
    Online,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OabError {
    TooLarge,
}

pub fn crc(parts: &[&[u8]]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize() ^ u32::MAX
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/oab/tests.rs"]
mod tests;
