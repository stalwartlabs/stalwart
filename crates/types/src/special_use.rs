/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Property, Value};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
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
        hashify::map_ignore_case!(s.as_bytes(), SpecialUse,
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
        .copied()
    }

    #[inline(always)]
    pub fn parse_use_attr(s: &str) -> Option<Self> {
        Self::parse(s.strip_prefix('\\').unwrap_or(s))
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

    pub const fn id(self) -> u8 {
        match self {
            SpecialUse::None => 0,
            SpecialUse::Inbox => 1,
            SpecialUse::Trash => 2,
            SpecialUse::Junk => 3,
            SpecialUse::Drafts => 4,
            SpecialUse::Archive => 5,
            SpecialUse::Sent => 6,
            SpecialUse::Shared => 7,
            SpecialUse::Important => 8,
            SpecialUse::Memos => 9,
            SpecialUse::Scheduled => 10,
            SpecialUse::Snoozed => 11,
        }
    }

    pub const fn from_id(id: u8) -> Self {
        match id {
            1 => SpecialUse::Inbox,
            2 => SpecialUse::Trash,
            3 => SpecialUse::Junk,
            4 => SpecialUse::Drafts,
            5 => SpecialUse::Archive,
            6 => SpecialUse::Sent,
            7 => SpecialUse::Shared,
            8 => SpecialUse::Important,
            9 => SpecialUse::Memos,
            10 => SpecialUse::Scheduled,
            11 => SpecialUse::Snoozed,
            _ => SpecialUse::None,
        }
    }
}

impl<'x, P: Property, E: Element + From<SpecialUse>> From<SpecialUse> for Value<'x, P, E> {
    fn from(id: SpecialUse) -> Self {
        Value::Element(E::from(id))
    }
}
