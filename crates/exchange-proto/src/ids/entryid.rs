/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::eid::Gid;
use crate::{
    common::{Guid, LeReader, Truncated, Utf16Le},
    mapi::nspi::minid::MinimalId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntryId {
    pub flags: u32,
    pub provider: Guid,
    pub folder_type: u16,
    pub gid: Gid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEntryId {
    pub flags: u32,
    pub provider: Guid,
    pub message_type: u16,
    pub folder: Gid,
    pub message: Gid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntryId<'a> {
    pub flags: u32,
    pub wrapped_provider: Guid,
    pub wrapped_type: u32,
    pub server: Cow<'a, [u8]>,
    pub mailbox_dn: Option<Cow<'a, [u8]>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneOffEntryId<'a> {
    pub flags: u16,
    pub display_name: Cow<'a, str>,
    pub address_type: Cow<'a, str>,
    pub email: Cow<'a, str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBookEntryId<'a> {
    pub flags: u32,
    pub display_type: u32,
    pub dn: Cow<'a, [u8]>,
}

pub type PermanentEntryId<'a> = AddressBookEntryId<'a>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralEntryId {
    pub server: Guid,
    pub display_type: u32,
    pub mid: MinimalId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryId<'a> {
    Folder(FolderEntryId),
    Message(MessageEntryId),
    Store(StoreEntryId<'a>),
    OneOff(OneOffEntryId<'a>),
    AddressBook(AddressBookEntryId<'a>),
    Ephemeral(EphemeralEntryId),
    Unknown { provider: Guid, data: &'a [u8] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryIdError {
    Truncated { offset: u32 },
    TrailingData { offset: u32 },
    BadVersion,
    InteriorNul,
}

pub mod provider {
    use crate::common::Guid;

    pub const ADDRESS_BOOK: Guid = Guid::from_wire([
        0xDC, 0xA7, 0x40, 0xC8, 0xC0, 0x42, 0x10, 0x1A, 0xB4, 0xB9, 0x08, 0x00, 0x2B, 0x2F, 0xE1,
        0x82,
    ]);
    pub const ONE_OFF: Guid = Guid::from_wire([
        0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54,
        0x02,
    ]);
    pub const STORE_WRAP: Guid = Guid::from_wire([
        0x38, 0xA1, 0xBB, 0x10, 0x05, 0xE5, 0x10, 0x1A, 0xA1, 0xBB, 0x08, 0x00, 0x2B, 0x2A, 0x56,
        0xC2,
    ]);
    pub const WRAPPED_PRIVATE: Guid = Guid::from_wire([
        0x1B, 0x55, 0xFA, 0x20, 0xAA, 0x66, 0x11, 0xCD, 0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4,
        0x5A,
    ]);
    pub const WRAPPED_PUBLIC: Guid = Guid::from_wire([
        0x1C, 0x83, 0x02, 0x10, 0xAA, 0x66, 0x11, 0xCD, 0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4,
        0x5A,
    ]);
    pub const PUBLIC_STORE: Guid = Guid::from_wire([
        0x1A, 0x44, 0x73, 0x90, 0xAA, 0x66, 0x11, 0xCD, 0x9B, 0xC8, 0x00, 0xAA, 0x00, 0x2F, 0xC4,
        0x5A,
    ]);
}

pub mod object_type {
    pub const PRIVATE_FOLDER: u16 = 0x0001;
    pub const PUBLIC_FOLDER: u16 = 0x0003;
    pub const MAPPED_PUBLIC_FOLDER: u16 = 0x0005;
    pub const PRIVATE_MESSAGE: u16 = 0x0007;
    pub const PUBLIC_MESSAGE: u16 = 0x0009;
    pub const MAPPED_PUBLIC_MESSAGE: u16 = 0x000B;
    pub const PUBLIC_NEWSGROUP_FOLDER: u16 = 0x000C;
}

pub mod wrapped_type {
    pub const MAILBOX: u32 = 0x0000_000C;
    pub const PUBLIC: u32 = 0x0000_0006;
}

pub mod one_off_flags {
    pub const NO_RICH_INFO: u16 = 0x0001;
    pub const UNICODE: u16 = 0x8000;
}

const EPHEMERAL_ID_TYPE: u8 = 0x87;
const EPHEMERAL_LEN: usize = 32;
const AB_VERSION: u32 = 1;
const EPHEMERAL_VERSION: u32 = 1;
const ONE_OFF_VERSION: u16 = 0;
const HEADER_LEN: usize = 20;
const GID_PAD: [u8; 2] = [0, 0];
const FOLDER_BODY_LEN: usize = 2 + Gid::LEN + 2;
const MESSAGE_BODY_LEN: usize = 2 + 2 * (Gid::LEN + 2);
const STORE_DLL_NAME: [u8; 14] = *b"EMSMDB.DLL\0\0\0\0";

impl From<Truncated> for EntryIdError {
    fn from(err: Truncated) -> Self {
        EntryIdError::Truncated {
            offset: offset_u32(err.offset),
        }
    }
}

fn offset_u32(offset: usize) -> u32 {
    u32::try_from(offset).unwrap_or(u32::MAX)
}

impl<'a> EntryId<'a> {
    pub fn decode(b: &'a [u8]) -> Result<Self, EntryIdError> {
        let mut r = LeReader::new(b);
        let flags_bytes = r.array::<4>()?;
        let flags = u32::from_le_bytes(flags_bytes);
        let provider = r.guid()?;
        let body = r.remaining();

        if flags_bytes.first() == Some(&EPHEMERAL_ID_TYPE) && b.len() == EPHEMERAL_LEN {
            let _version = r.u32()?;
            let display_type = r.u32()?;
            let mid = MinimalId(r.u32()?);
            return Ok(EntryId::Ephemeral(EphemeralEntryId {
                server: provider,
                display_type,
                mid,
            }));
        }

        let decoded = match provider {
            provider::ADDRESS_BOOK => EntryId::AddressBook(decode_address_book(&mut r, flags)?),
            provider::ONE_OFF => EntryId::OneOff(decode_one_off(&mut r)?),
            provider::STORE_WRAP => EntryId::Store(decode_store(&mut r, flags)?),
            _ => {
                return Ok(
                    decode_store_object(&mut r, flags, provider, body.len()).unwrap_or(
                        EntryId::Unknown {
                            provider,
                            data: body,
                        },
                    ),
                );
            }
        };
        if r.is_empty() {
            Ok(decoded)
        } else {
            Err(EntryIdError::TrailingData {
                offset: offset_u32(r.offset()),
            })
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EntryIdError> {
        match self {
            EntryId::Folder(id) => {
                out.reserve(HEADER_LEN + FOLDER_BODY_LEN);
                write_header(out, &id.provider);
                out.extend_from_slice(&id.folder_type.to_le_bytes());
                write_gid(out, &id.gid);
            }
            EntryId::Message(id) => {
                out.reserve(HEADER_LEN + MESSAGE_BODY_LEN);
                write_header(out, &id.provider);
                out.extend_from_slice(&id.message_type.to_le_bytes());
                write_gid(out, &id.folder);
                write_gid(out, &id.message);
            }
            EntryId::Store(id) => {
                let server = without_nul(&id.server)?;
                let dn = id.mailbox_dn.as_deref().map(without_nul).transpose()?;
                write_header(out, &provider::STORE_WRAP);
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&STORE_DLL_NAME);
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(id.wrapped_provider.as_bytes());
                out.extend_from_slice(&id.wrapped_type.to_le_bytes());
                write_z(out, server);
                if let Some(dn) = dn {
                    write_z(out, dn);
                }
            }
            EntryId::OneOff(id) => {
                for s in [&id.display_name, &id.address_type, &id.email] {
                    without_nul(s.as_bytes())?;
                }
                write_header(out, &provider::ONE_OFF);
                out.extend_from_slice(&ONE_OFF_VERSION.to_le_bytes());
                out.extend_from_slice(&(id.flags | one_off_flags::UNICODE).to_le_bytes());
                for s in [&id.display_name, &id.address_type, &id.email] {
                    out.reserve(s.len().saturating_add(1).saturating_mul(2));
                    for unit in s.encode_utf16() {
                        out.extend_from_slice(&unit.to_le_bytes());
                    }
                    out.extend_from_slice(&[0, 0]);
                }
            }
            EntryId::AddressBook(id) => {
                let dn = without_nul(&id.dn)?;
                out.reserve(dn.len().saturating_add(HEADER_LEN + 9));
                write_header(out, &provider::ADDRESS_BOOK);
                out.extend_from_slice(&AB_VERSION.to_le_bytes());
                out.extend_from_slice(&id.display_type.to_le_bytes());
                write_z(out, dn);
            }
            EntryId::Ephemeral(id) => {
                out.reserve(EPHEMERAL_LEN);
                out.extend_from_slice(&[EPHEMERAL_ID_TYPE, 0, 0, 0]);
                out.extend_from_slice(id.server.as_bytes());
                out.extend_from_slice(&EPHEMERAL_VERSION.to_le_bytes());
                out.extend_from_slice(&id.display_type.to_le_bytes());
                out.extend_from_slice(&id.mid.0.to_le_bytes());
            }
            EntryId::Unknown { provider, data } => {
                out.reserve(data.len().saturating_add(HEADER_LEN));
                write_header(out, provider);
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }
}

fn decode_address_book<'a>(
    r: &mut LeReader<'a>,
    flags: u32,
) -> Result<AddressBookEntryId<'a>, EntryIdError> {
    if r.u32()? != AB_VERSION {
        return Err(EntryIdError::BadVersion);
    }
    let display_type = r.u32()?;
    let dn = r.ascii_z()?;
    Ok(AddressBookEntryId {
        flags,
        display_type,
        dn: Cow::Borrowed(dn),
    })
}

fn decode_one_off<'a>(r: &mut LeReader<'a>) -> Result<OneOffEntryId<'a>, EntryIdError> {
    if r.u16()? != ONE_OFF_VERSION {
        return Err(EntryIdError::BadVersion);
    }
    let flags = r.u16()?;
    let unicode = flags & one_off_flags::UNICODE != 0;
    let mut next = || -> Result<Cow<'a, str>, EntryIdError> {
        if unicode {
            Ok(Cow::Owned(utf16_string(r.utf16_z()?)))
        } else {
            Ok(mbcs_string(r.ascii_z()?))
        }
    };
    let display_name = next()?;
    let address_type = next()?;
    let email = next()?;
    Ok(OneOffEntryId {
        flags,
        display_name,
        address_type,
        email,
    })
}

fn decode_store<'a>(r: &mut LeReader<'a>, flags: u32) -> Result<StoreEntryId<'a>, EntryIdError> {
    let [version, flag] = r.array::<2>()?;
    if version != 0 || flag != 0 {
        return Err(EntryIdError::BadVersion);
    }
    r.skip(STORE_DLL_NAME.len())?;
    let _wrapped_flags = r.u32()?;
    let wrapped_provider = r.guid()?;
    let wrapped_type = r.u32()?;
    let server = r.ascii_z()?;
    let mailbox_dn = if r.is_empty() {
        None
    } else {
        Some(Cow::Borrowed(r.ascii_z()?))
    };
    Ok(StoreEntryId {
        flags,
        wrapped_provider,
        wrapped_type,
        server: Cow::Borrowed(server),
        mailbox_dn,
    })
}

fn decode_store_object<'a>(
    r: &mut LeReader<'a>,
    flags: u32,
    provider: Guid,
    body_len: usize,
) -> Option<EntryId<'a>> {
    let object_type = r.u16().ok()?;
    match (object_type, body_len) {
        (
            object_type::PRIVATE_FOLDER
            | object_type::PUBLIC_FOLDER
            | object_type::MAPPED_PUBLIC_FOLDER
            | object_type::PUBLIC_NEWSGROUP_FOLDER,
            FOLDER_BODY_LEN,
        ) => Some(EntryId::Folder(FolderEntryId {
            flags,
            provider,
            folder_type: object_type,
            gid: read_gid(r)?,
        })),
        (
            object_type::PRIVATE_MESSAGE
            | object_type::PUBLIC_MESSAGE
            | object_type::MAPPED_PUBLIC_MESSAGE,
            MESSAGE_BODY_LEN,
        ) => Some(EntryId::Message(MessageEntryId {
            flags,
            provider,
            message_type: object_type,
            folder: read_gid(r)?,
            message: read_gid(r)?,
        })),
        _ => None,
    }
}

fn read_gid(r: &mut LeReader<'_>) -> Option<Gid> {
    let gid = Gid::from_wire(r.bytes(Gid::LEN).ok()?)?;
    r.skip(GID_PAD.len()).ok()?;
    Some(gid)
}

fn write_gid(out: &mut Vec<u8>, gid: &Gid) {
    out.extend_from_slice(&gid.to_wire());
    out.extend_from_slice(&GID_PAD);
}

fn write_header(out: &mut Vec<u8>, provider: &Guid) {
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(provider.as_bytes());
}

fn write_z(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value);
    out.push(0);
}

fn without_nul(value: &[u8]) -> Result<&[u8], EntryIdError> {
    match memchr::memchr(0, value) {
        Some(_) => Err(EntryIdError::InteriorNul),
        None => Ok(value),
    }
}

fn utf16_string(value: Utf16Le<'_>) -> String {
    let mut out = String::new();
    value.to_string_lossy(&mut out);
    out
}

fn mbcs_string(value: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(value) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(value.iter().map(|&b| char::from(b)).collect()),
    }
}
