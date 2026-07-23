/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::report::AggregateFrequency;
use mail_parser::DateTime;
use std::time::SystemTime;

pub mod analysis;
pub mod dkim;
pub mod dmarc;
pub mod inbound;
pub mod index;
pub mod scheduler;
pub mod send;
pub mod spf;
pub mod tls;

pub trait AggregateTimestamp {
    fn to_timestamp(&self) -> u64;
    fn to_timestamp_(&self, dt: DateTime) -> u64;
    fn as_secs(&self) -> u64;
    fn due(&self) -> u64;
}

impl AggregateTimestamp for AggregateFrequency {
    fn to_timestamp(&self) -> u64 {
        self.to_timestamp_(DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        ))
    }

    fn to_timestamp_(&self, mut dt: DateTime) -> u64 {
        (match self {
            AggregateFrequency::Hourly => {
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp()
            }
            AggregateFrequency::Daily => {
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp()
            }
            AggregateFrequency::Weekly => {
                let dow = dt.day_of_week();
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp() - (86400 * dow as i64)
            }
            AggregateFrequency::Never => dt.to_timestamp(),
        }) as u64
    }

    fn as_secs(&self) -> u64 {
        match self {
            AggregateFrequency::Hourly => 3600,
            AggregateFrequency::Daily => 86400,
            AggregateFrequency::Weekly => 7 * 86400,
            AggregateFrequency::Never => 0,
        }
    }

    fn due(&self) -> u64 {
        self.to_timestamp() + self.as_secs()
    }
}
