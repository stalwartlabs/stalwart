/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Write;
use store::rand;
use utils::codec::base32_custom::{Base32Reader, Base32Writer};

pub const MAX_PRIVATE_LINKS_PER_CALENDAR: usize = 20;
pub const MAX_PUBLIC_LINKS_PER_CALENDAR: usize = 2;
pub const FEED_PAST_SECONDS: i64 = 30 * 86400;
pub const FEED_FUTURE_SECONDS: i64 = 2 * 365 * 86400;
pub const LAST_USED_DEBOUNCE_SECONDS: i64 = 3600;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[repr(u8)]
pub enum PublishAccess {
    #[default]
    Private = 0,
    Public = 1,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[repr(u8)]
pub enum PublishVisibility {
    #[default]
    Full = 0,
    Busy = 1,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub struct CalendarPublishLink {
    pub document_id: u32,
    pub link_id: [u8; 16],
    pub calendar_id: u32,
    pub access: PublishAccess,
    pub visibility: PublishVisibility,
    pub label: Option<String>,
    pub secret_hash: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
}

pub struct PublishLinkSecret {
    pub secret: [u8; 18],
}

impl PublishLinkSecret {
    pub fn new() -> Self {
        PublishLinkSecret {
            secret: rand::random(),
        }
    }

    pub fn parse(token: &str) -> Option<Self> {
        let mut reader = Base32Reader::new(token.as_bytes());
        let mut secret = [0u8; 18];
        for byte in secret.iter_mut() {
            *byte = reader.next()?;
        }
        if reader.next().is_none() {
            Some(PublishLinkSecret { secret })
        } else {
            None
        }
    }

    pub fn build(&self) -> String {
        let mut writer = Base32Writer::with_capacity(32);
        let _ = writer.write_all(&self.secret);
        writer.finalize()
    }
}

impl CalendarPublishLink {
    pub fn new(
        document_id: u32,
        calendar_id: u32,
        access: PublishAccess,
        visibility: PublishVisibility,
        label: Option<String>,
        secret_hash: Option<String>,
        created_at: i64,
        expires_at: Option<i64>,
    ) -> Self {
        CalendarPublishLink {
            document_id,
            link_id: rand::random(),
            calendar_id,
            access,
            visibility,
            label,
            secret_hash,
            created_at,
            last_used_at: None,
            expires_at,
        }
    }

    pub fn link_id_string(&self) -> String {
        format_uuid(&self.link_id)
    }
}

pub fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let s = s.strip_suffix(".ics").unwrap_or(s);
    if s.len() != 36 {
        return None;
    }
    let bytes = [
        parse_hex_pair(s.get(0..2)?)?,
        parse_hex_pair(s.get(2..4)?)?,
        parse_hex_pair(s.get(4..6)?)?,
        parse_hex_pair(s.get(6..8)?)?,
        parse_hex_pair(s.get(9..11)?)?,
        parse_hex_pair(s.get(11..13)?)?,
        parse_hex_pair(s.get(14..16)?)?,
        parse_hex_pair(s.get(16..18)?)?,
        parse_hex_pair(s.get(19..21)?)?,
        parse_hex_pair(s.get(21..23)?)?,
        parse_hex_pair(s.get(24..26)?)?,
        parse_hex_pair(s.get(26..28)?)?,
        parse_hex_pair(s.get(28..30)?)?,
        parse_hex_pair(s.get(30..32)?)?,
        parse_hex_pair(s.get(32..34)?)?,
        parse_hex_pair(s.get(34..36)?)?,
    ];
    if s.chars().nth(8) != Some('-')
        || s.chars().nth(13) != Some('-')
        || s.chars().nth(18) != Some('-')
        || s.chars().nth(23) != Some('-')
    {
        return None;
    }
    Some(bytes)
}

fn parse_hex_pair(s: &str) -> Option<u8> {
    let hi = s.chars().next()?.to_digit(16)?;
    let lo = s.chars().nth(1)?.to_digit(16)?;
    Some((hi << 4 | lo) as u8)
}

