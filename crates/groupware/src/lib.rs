/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use calcard::common::timezone::Tz;
use common::GroupwareResources;
pub use common::storage::dav::{RFC_3986, encode_path_segment, is_uri_segment};
use percent_encoding::percent_decode_str;
use std::borrow::Cow;
use types::collection::{Collection, SyncCollection};

pub mod cache;
pub mod calendar;
pub mod contact;
pub mod file;
pub mod scheduling;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavResourceName {
    Card,
    Cal,
    File,
    Principal,
    Scheduling,
}

pub struct SizeWriter(usize);

impl std::fmt::Write for SizeWriter {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.0 += text.len();
        Ok(())
    }
}

impl SizeWriter {
    pub fn ical(ical: &calcard::icalendar::ICalendar) -> usize {
        let mut writer = SizeWriter(0);
        let _ = ical.write_to(&mut writer);
        writer.0
    }

    pub fn vcard(vcard: &calcard::vcard::VCard, version: calcard::vcard::VCardVersion) -> usize {
        let mut writer = SizeWriter(0);
        let _ = vcard.write_to(&mut writer, version);
        writer.0
    }
}

#[derive(Default)]
pub struct MetaHasher(store::xxhash_rust::xxh3::Xxh3);

impl MetaHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.0.update(&(value.len() as u64).to_le_bytes());
        self.0.update(value);
        self
    }

    pub fn str(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    pub fn opt_str(&mut self, value: Option<&str>) -> &mut Self {
        match value {
            Some(value) => {
                self.0.update(&[1]);
                self.str(value)
            }
            None => {
                self.0.update(&[0]);
                self
            }
        }
    }

    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.0.update(&value.to_le_bytes());
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.0.update(&value.to_le_bytes());
        self
    }

    pub fn i64(&mut self, value: i64) -> &mut Self {
        self.0.update(&value.to_le_bytes());
        self
    }

    pub fn opt_u32(&mut self, value: Option<u32>) -> &mut Self {
        match value {
            Some(value) => {
                self.0.update(&[1]);
                self.u32(value)
            }
            None => {
                self.0.update(&[0]);
                self
            }
        }
    }

    pub fn finish(&self) -> u32 {
        self.0.digest() as u32
    }
}

pub struct DestroyArchive<T>(pub T);

impl DavResourceName {
    pub fn parse(service: &str) -> Option<Self> {
        hashify::tiny_map!(service.as_bytes(),
            "card" => DavResourceName::Card,
            "cal" => DavResourceName::Cal,
            "file" => DavResourceName::File,
            "pal" => DavResourceName::Principal,
            "itip" => DavResourceName::Scheduling,
        )
    }

    pub fn base_path(&self) -> &'static str {
        match self {
            DavResourceName::Card => "/dav/card",
            DavResourceName::Cal => "/dav/cal",
            DavResourceName::File => "/dav/file",
            DavResourceName::Principal => "/dav/pal",
            DavResourceName::Scheduling => "/dav/itip",
        }
    }

    pub fn collection_path(&self) -> &'static str {
        match self {
            DavResourceName::Card => "/dav/card/",
            DavResourceName::Cal => "/dav/cal/",
            DavResourceName::File => "/dav/file/",
            DavResourceName::Principal => "/dav/pal/",
            DavResourceName::Scheduling => "/dav/itip/",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DavResourceName::Card => "CardDAV",
            DavResourceName::Cal => "CalDAV",
            DavResourceName::File => "WebDAV",
            DavResourceName::Principal => "Principal",
            DavResourceName::Scheduling => "Scheduling",
        }
    }
}

impl From<DavResourceName> for Collection {
    fn from(value: DavResourceName) -> Self {
        match value {
            DavResourceName::Card => Collection::AddressBook,
            DavResourceName::Cal => Collection::Calendar,
            DavResourceName::File => Collection::FileNode,
            DavResourceName::Principal => Collection::Principal,
            DavResourceName::Scheduling => Collection::CalendarEventNotification,
        }
    }
}

impl From<Collection> for DavResourceName {
    fn from(value: Collection) -> Self {
        match value {
            Collection::AddressBook => DavResourceName::Card,
            Collection::Calendar => DavResourceName::Cal,
            Collection::FileNode => DavResourceName::File,
            Collection::Principal => DavResourceName::Principal,
            Collection::CalendarEventNotification => DavResourceName::Scheduling,
            _ => unreachable!(),
        }
    }
}

impl From<SyncCollection> for DavResourceName {
    fn from(value: SyncCollection) -> Self {
        match value {
            SyncCollection::AddressBook => DavResourceName::Card,
            SyncCollection::Calendar => DavResourceName::Cal,
            SyncCollection::FileNode => DavResourceName::File,
            SyncCollection::CalendarEventNotification => DavResourceName::Scheduling,
            _ => unreachable!(),
        }
    }
}

pub trait DavCalendarResource {
    fn calendar_default_tz(&self, calendar_id: u32, account_id: u32) -> Option<Tz>;
}

impl DavCalendarResource for GroupwareResources {
    fn calendar_default_tz(&self, calendar_id: u32, account_id: u32) -> Option<Tz> {
        self.container_resource_by_id(calendar_id)
            .and_then(|c| c.calendar_preferences(account_id).map(|p| p.tz))
    }
}

pub fn strip_mailto_scheme(value: &str) -> &str {
    value
        .split_once(':')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("mailto"))
        .map_or(value, |(_, address)| address.trim())
}

pub fn decode_mailto_address(value: &str) -> Cow<'_, str> {
    match value.split_once(':') {
        Some((scheme, address)) if scheme.eq_ignore_ascii_case("mailto") => {
            let address = address.trim();
            let address = address.split_once('?').map_or(address, |(to, _)| to);
            percent_decode_str(address).decode_utf8_lossy()
        }
        _ => Cow::Borrowed(value),
    }
}

pub fn extract_addr_spec(value: &str) -> Option<&str> {
    value
        .rsplit_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(addr, _)| addr.trim())
        .filter(|addr| !addr.is_empty())
}
