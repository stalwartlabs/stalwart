/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod blob;
pub mod blob_hash;
pub mod collection;
pub mod dead_property;
pub mod field;
pub mod id;
pub mod keyword;
pub mod semver;
pub mod special_use;
pub mod type_state;

pub type DocumentId = u32;
pub type ChangeId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "test_mode", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeRange {
    pub start: i64,
    pub end: i64,
}

impl TimeRange {
    pub fn new(start: i64, end: i64) -> Self {
        Self { start, end }
    }

    pub fn is_in_range(&self, match_overlap: bool, start: i64, end: i64) -> bool {
        if !match_overlap {
            // RFC4791#9.9: (start <  DTEND AND end > DTSTART)
            self.start < end && self.end > start
        } else {
            // RFC4791#9.9: ((start <  DUE) OR (start <= DTSTART)) AND ((end > DTSTART) OR (end >= DUE))
            ((start < self.end) || (start <= self.start)) && (end > self.start || end >= self.end)
        }
    }
}

impl Default for TimeRange {
    fn default() -> Self {
        Self {
            start: i64::MIN,
            end: i64::MAX,
        }
    }
}
