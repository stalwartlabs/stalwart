/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadVersionPolicy {
    #[default]
    Cached,
    Fresh,
    At(Version),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReadVersionCache {
    pub refresh_after: Duration,
    pub max_age: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Series {
    V7_1,
    V7_2,
    V7_3,
    V7_4,
    V8_0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProtocolPolicy {
    #[default]
    Negotiate,
    Fixed(Series),
}

impl Version {
    pub const fn new(version: i64) -> Option<Self> {
        if version > 0 {
            Some(Version(version))
        } else {
            None
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl ReadVersionCache {
    pub const MAX_AGE_LIMIT: Duration = Duration::from_secs(5);
}

impl Default for ReadVersionCache {
    fn default() -> Self {
        ReadVersionCache {
            refresh_after: Duration::from_secs(1),
            max_age: Duration::from_secs(4),
        }
    }
}

impl ProtocolVersion {
    const SERIES_MASK: u64 = 0xFFFF_FFFF_FFFF_0000;

    pub const fn new(version: u64) -> Self {
        ProtocolVersion(version)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn series(self) -> Option<Series> {
        match self.0 & Self::SERIES_MASK {
            0x0FDB_00B0_7101_0000 => Some(Series::V7_1),
            0x0FDB_00B0_7200_0000 => Some(Series::V7_2),
            0x0FDB_00B0_7300_0000 => Some(Series::V7_3),
            0x0FDB_00B0_7400_0000 => Some(Series::V7_4),
            0x0FDB_00B0_8000_0000 => Some(Series::V8_0),
            _ => None,
        }
    }
}

impl Series {
    pub(crate) const NEWEST: Series = Series::V8_0;

    pub const fn protocol_version(self) -> ProtocolVersion {
        ProtocolVersion(match self {
            Series::V7_1 => 0x0FDB_00B0_7101_0000,
            Series::V7_2 => 0x0FDB_00B0_7200_0000,
            Series::V7_3 => 0x0FDB_00B0_7300_0000,
            Series::V7_4 => 0x0FDB_00B0_7400_0000,
            Series::V8_0 => 0x0FDB_00B0_8000_0000,
        })
    }
}
