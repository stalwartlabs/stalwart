/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::report::AggregateFrequency;
use compact_str::CompactString;
use mail_parser::DateTime;
use std::time::SystemTime;
use trc::OutgoingReportEvent;
use utils::sanitize_email;

pub mod aggregate;
pub mod analysis;
pub mod dkim;
pub mod dmarc;
pub mod inbound;
pub mod index;
pub mod mdn;
pub mod scheduler;
pub mod send;
pub mod spf;
pub mod tls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportAddress<'x>(&'x str);

impl<'x> ReportAddress<'x> {
    const MAX_LOCAL_PART_LEN: usize = 64;
    const MAX_DOMAIN_LEN: usize = 255;
    const MAX_PATH_LEN: usize = 256;
    const PATH_PUNCTUATION_LEN: usize = 2;

    pub fn parse(address: &'x str) -> Option<Self> {
        let (local_part, domain) = address.rsplit_once('@')?;
        (local_part.len() <= ReportAddress::MAX_LOCAL_PART_LEN
            && domain.len() <= ReportAddress::MAX_DOMAIN_LEN
            && address.len() + ReportAddress::PATH_PUNCTUATION_LEN <= ReportAddress::MAX_PATH_LEN
            && !address
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
            && sanitize_email(address).is_some())
        .then_some(ReportAddress(address))
    }

    pub fn checked(address: &'x str, session_id: u64) -> Option<Self> {
        let parsed = ReportAddress::parse(address);
        if parsed.is_none() {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::UnauthorizedReportingAddress),
                SpanId = session_id,
                Url = CompactString::from(address),
                Details = "Invalid reporting address",
            );
        }
        parsed
    }

    #[inline]
    pub fn as_str(&self) -> &'x str {
        self.0
    }
}

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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/smtp/src/reporting/tests.rs"]
mod tests;
