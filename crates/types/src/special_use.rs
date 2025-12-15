/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Property, Value};
use utils::config::utils::ParseValue;

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    PartialOrd,
    Ord,
)]
#[rkyv(derive(Debug))]
pub enum SpecialUse {
    Inbox,
    Trash,
    Junk,
    Drafts,
    Archive,
    Sent,
    Shared,
    Important,
    None,
    Memos,
    Scheduled,
    Snoozed,
}

impl SpecialUse {
    pub fn parse(s: &str) -> Option<Self> {
        hashify::tiny_map_ignore_case!(s.as_bytes(),
            b"inbox" => SpecialUse::Inbox,
            b"trash" => SpecialUse::Trash,
            b"junk" => SpecialUse::Junk,
            b"drafts" => SpecialUse::Drafts,
            b"archive" => SpecialUse::Archive,
            b"sent" => SpecialUse::Sent,
            b"shared" => SpecialUse::Shared,
            b"important" => SpecialUse::Important,
            b"memos" => SpecialUse::Memos,
            b"scheduled" => SpecialUse::Scheduled,
            b"snoozed" => SpecialUse::Snoozed,
        )
    }

    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            SpecialUse::Inbox => Some("inbox"),
            SpecialUse::Trash => Some("trash"),
            SpecialUse::Junk => Some("junk"),
            SpecialUse::Drafts => Some("drafts"),
            SpecialUse::Archive => Some("archive"),
            SpecialUse::Sent => Some("sent"),
            SpecialUse::Shared => Some("shared"),
            SpecialUse::Important => Some("important"),
            SpecialUse::Memos => Some("memos"),
            SpecialUse::Scheduled => Some("scheduled"),
            SpecialUse::Snoozed => Some("snoozed"),
            SpecialUse::None => None,
        }
    }
}

impl ArchivedSpecialUse {
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            ArchivedSpecialUse::Inbox => Some("inbox"),
            ArchivedSpecialUse::Trash => Some("trash"),
            ArchivedSpecialUse::Junk => Some("junk"),
            ArchivedSpecialUse::Drafts => Some("drafts"),
            ArchivedSpecialUse::Archive => Some("archive"),
            ArchivedSpecialUse::Sent => Some("sent"),
            ArchivedSpecialUse::Shared => Some("shared"),
            ArchivedSpecialUse::Important => Some("important"),
            ArchivedSpecialUse::Memos => Some("memos"),
            ArchivedSpecialUse::Scheduled => Some("scheduled"),
            ArchivedSpecialUse::Snoozed => Some("snoozed"),
            ArchivedSpecialUse::None => None,
        }
    }
}

impl From<&ArchivedSpecialUse> for SpecialUse {
    fn from(value: &ArchivedSpecialUse) -> Self {
        match value {
            ArchivedSpecialUse::Inbox => SpecialUse::Inbox,
            ArchivedSpecialUse::Trash => SpecialUse::Trash,
            ArchivedSpecialUse::Junk => SpecialUse::Junk,
            ArchivedSpecialUse::Drafts => SpecialUse::Drafts,
            ArchivedSpecialUse::Archive => SpecialUse::Archive,
            ArchivedSpecialUse::Sent => SpecialUse::Sent,
            ArchivedSpecialUse::Shared => SpecialUse::Shared,
            ArchivedSpecialUse::Important => SpecialUse::Important,
            ArchivedSpecialUse::Memos => SpecialUse::Memos,
            ArchivedSpecialUse::Scheduled => SpecialUse::Scheduled,
            ArchivedSpecialUse::Snoozed => SpecialUse::Snoozed,
            ArchivedSpecialUse::None => SpecialUse::None,
        }
    }
}

impl ParseValue for SpecialUse {
    fn parse_value(value: &str) -> Result<Self, String> {
        SpecialUse::parse(value).ok_or_else(|| format!("Unknown folder role {:?}", value))
    }
}

impl<'x, P: Property, E: Element + From<SpecialUse>> From<SpecialUse> for Value<'x, P, E> {
    fn from(id: SpecialUse) -> Self {
        Value::Element(E::from(id))
    }
}
