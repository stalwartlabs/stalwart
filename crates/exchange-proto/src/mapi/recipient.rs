/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    emsmdb::MapiLimits,
    prop::{CodePage, PropTag, codec::write_utf16, row::RowValues},
    rop::{RopDecodeError, views::MapiString},
};
use crate::{
    common::{LeReader, LeWriter},
    ids::entryid::{EntryId, OneOffEntryId, one_off_flags},
};
use bytes::Bytes;
use std::borrow::Cow;

pub mod flags {
    pub const TYPE_MASK: u16 = 0x0007;
    pub const EMAIL: u16 = 0x0008;
    pub const DISPLAY_NAME: u16 = 0x0010;
    pub const TRANSMITTABLE: u16 = 0x0020;
    pub const SAME_AS_DISPLAY: u16 = 0x0040;
    pub const OTHER_TRANSPORT: u16 = 0x0080;
    pub const NO_RICH_TEXT: u16 = 0x0100;
    pub const UNICODE: u16 = 0x0200;
    pub const SIMPLE_DISPLAY_NAME: u16 = 0x0400;
    pub const RESERVED: u16 = 0x7800;
    pub const NON_STANDARD: u16 = 0x8000;
    pub const PRESERVED: u16 = SAME_AS_DISPLAY | OTHER_TRANSPORT | NO_RICH_TEXT;
}

const SMTP_KEY_PREFIX: &[u8] = b"SMTP:";
const TYPE_NONE: u16 = 0;
const TYPE_X500: u16 = 1;
const TYPE_MSMAIL: u16 = 2;
const TYPE_SMTP: u16 = 3;
const TYPE_FAX: u16 = 4;
const TYPE_PROFESSIONAL_OFFICE: u16 = 5;
const TYPE_PERSONAL_DL1: u16 = 6;
const TYPE_PERSONAL_DL2: u16 = 7;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientKind<'a> {
    NoType {
        address_type: Option<&'a [u8]>,
    },
    X500Dn {
        prefix_used: u8,
        display_type: u8,
        dn: &'a [u8],
    },
    MsMail,
    Smtp,
    Fax,
    ProfessionalOfficeSystem,
    PersonalDistributionList {
        second: bool,
        entry_id: &'a [u8],
        search_key: &'a [u8],
    },
}

impl RecipientKind<'_> {
    const fn code(&self) -> u16 {
        match self {
            RecipientKind::NoType { .. } => TYPE_NONE,
            RecipientKind::X500Dn { .. } => TYPE_X500,
            RecipientKind::MsMail => TYPE_MSMAIL,
            RecipientKind::Smtp => TYPE_SMTP,
            RecipientKind::Fax => TYPE_FAX,
            RecipientKind::ProfessionalOfficeSystem => TYPE_PROFESSIONAL_OFFICE,
            RecipientKind::PersonalDistributionList { second: false, .. } => TYPE_PERSONAL_DL1,
            RecipientKind::PersonalDistributionList { second: true, .. } => TYPE_PERSONAL_DL2,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecipientRow<'a> {
    pub flags: u16,
    pub kind: RecipientKind<'a>,
    pub email: Option<MapiString<'a>>,
    pub display_name: Option<MapiString<'a>>,
    pub simple_display_name: Option<MapiString<'a>>,
    pub transmittable_display_name: Option<MapiString<'a>>,
    pub columns: RowValues<'a>,
}

fn read_sized<'a>(r: &mut LeReader<'a>) -> Result<&'a [u8], RopDecodeError> {
    let len = usize::from(r.u16()?);
    Ok(r.bytes(len)?)
}

impl<'a> RecipientRow<'a> {
    pub fn decode(r: &mut LeReader<'a>, columns: &[PropTag]) -> Result<Self, RopDecodeError> {
        Self::decode_with(r, columns, &MapiLimits::DEFAULT)
    }

    pub fn decode_with(
        r: &mut LeReader<'a>,
        columns: &[PropTag],
        limits: &MapiLimits,
    ) -> Result<Self, RopDecodeError> {
        let offset = r.offset();
        let bad = RopDecodeError::BadValue {
            offset: RopDecodeError::at(offset),
        };
        let row_flags = r.u16()? & !flags::RESERVED;
        let unicode = row_flags & flags::UNICODE != 0;
        let kind = match row_flags & flags::TYPE_MASK {
            TYPE_X500 => RecipientKind::X500Dn {
                prefix_used: r.u8()?,
                display_type: r.u8()?,
                dn: r.ascii_z()?,
            },
            code @ (TYPE_PERSONAL_DL1 | TYPE_PERSONAL_DL2) => {
                RecipientKind::PersonalDistributionList {
                    second: code == TYPE_PERSONAL_DL2,
                    entry_id: read_sized(r)?,
                    search_key: read_sized(r)?,
                }
            }
            TYPE_NONE => RecipientKind::NoType {
                address_type: if row_flags & flags::NON_STANDARD != 0 {
                    Some(r.ascii_z()?)
                } else {
                    None
                },
            },
            TYPE_MSMAIL => RecipientKind::MsMail,
            TYPE_SMTP => RecipientKind::Smtp,
            TYPE_FAX => RecipientKind::Fax,
            _ => RecipientKind::ProfessionalOfficeSystem,
        };
        let mut optional = |flag: u16| -> Result<Option<MapiString<'a>>, RopDecodeError> {
            if row_flags & flag != 0 {
                MapiString::decode(r, unicode).map(Some)
            } else {
                Ok(None)
            }
        };
        let email = optional(flags::EMAIL)?;
        let display_name = optional(flags::DISPLAY_NAME)?;
        let simple_display_name = optional(flags::SIMPLE_DISPLAY_NAME)?;
        let transmittable_display_name = optional(flags::TRANSMITTABLE)?;
        let count = usize::from(r.u16()?);
        let columns = columns.get(..count).ok_or(bad)?;
        let columns = RowValues::decode(r, columns, limits)?;
        Ok(RecipientRow {
            flags: row_flags,
            kind,
            email,
            display_name,
            simple_display_name,
            transmittable_display_name,
            columns,
        })
    }

    fn strings(&self) -> impl Iterator<Item = &MapiString<'a>> {
        [
            &self.email,
            &self.display_name,
            &self.simple_display_name,
            &self.transmittable_display_name,
        ]
        .into_iter()
        .flatten()
    }

    fn is_unicode(&self) -> bool {
        self.strings()
            .any(|text| matches!(text, MapiString::Unicode(_)))
            || !self
                .strings()
                .any(|text| matches!(text, MapiString::String8(_)))
    }

    pub fn wire_flags(&self) -> u16 {
        let mut out = (self.flags & flags::PRESERVED) | self.kind.code();
        if self.is_unicode() {
            out |= flags::UNICODE;
        }
        for (present, flag) in [
            (self.email.is_some(), flags::EMAIL),
            (self.display_name.is_some(), flags::DISPLAY_NAME),
            (
                self.simple_display_name.is_some(),
                flags::SIMPLE_DISPLAY_NAME,
            ),
            (
                self.transmittable_display_name.is_some(),
                flags::TRANSMITTABLE,
            ),
        ] {
            if present {
                out |= flag;
            }
        }
        if matches!(
            self.kind,
            RecipientKind::NoType {
                address_type: Some(_)
            }
        ) {
            out |= flags::NON_STANDARD;
        }
        out
    }

    pub fn encode(&self, out: &mut Vec<u8>, code_page: CodePage) {
        out.put_u16(self.wire_flags());
        match &self.kind {
            RecipientKind::X500Dn {
                prefix_used,
                display_type,
                dn,
            } => {
                out.put_u8(*prefix_used);
                out.put_u8(*display_type);
                out.put_ascii_z(dn);
            }
            RecipientKind::PersonalDistributionList {
                entry_id,
                search_key,
                ..
            } => {
                for blob in [entry_id, search_key] {
                    let blob = blob.get(..usize::from(u16::MAX)).unwrap_or(blob);
                    out.put_u16(u16::try_from(blob.len()).unwrap_or(0));
                    out.extend_from_slice(blob);
                }
            }
            RecipientKind::NoType {
                address_type: Some(address_type),
            } => out.put_ascii_z(address_type),
            _ => {}
        }
        let unicode = self.is_unicode();
        for text in self.strings() {
            match text {
                MapiString::Unicode(text) => write_utf16(out, text.as_bytes()),
                MapiString::String8(bytes) if unicode => {
                    code_page.widen(bytes, usize::MAX, out);
                    out.put_u16(0);
                }
                MapiString::String8(bytes) => out.put_ascii_z(bytes),
            }
        }
        out.put_u16(self.columns.columns());
        out.extend_from_slice(self.columns.as_bytes());
    }
}

pub(crate) fn one_off(name: &str, address_type: &str, email: &str) -> Option<Bytes> {
    let mut entry_id = Vec::new();
    write_one_off(&mut entry_id, name, address_type, email)?;
    Some(entry_id.into())
}

pub(crate) fn write_one_off(
    out: &mut Vec<u8>,
    name: &str,
    address_type: &str,
    email: &str,
) -> Option<()> {
    let start = out.len();
    let encoded = EntryId::OneOff(OneOffEntryId {
        flags: one_off_flags::UNICODE,
        display_name: Cow::Borrowed(name),
        address_type: Cow::Borrowed(address_type),
        email: Cow::Borrowed(email),
    })
    .encode(out);
    if encoded.is_err() {
        out.truncate(start);
        return None;
    }
    Some(())
}

pub(crate) fn smtp_search_key(email: &str) -> Bytes {
    let mut key = Vec::with_capacity(
        email
            .len()
            .saturating_add(SMTP_KEY_PREFIX.len())
            .saturating_add(1),
    );
    key.extend_from_slice(SMTP_KEY_PREFIX);
    key.extend(email.bytes().map(|byte| byte.to_ascii_uppercase()));
    key.push(0);
    key.into()
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/recipient/tests.rs"]
mod tests;
