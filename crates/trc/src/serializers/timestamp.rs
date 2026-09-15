/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write;

use mail_parser::DateTime;

pub struct TimestampCache {
    timestamp: u64,
    text: String,
}

impl TimestampCache {
    pub fn new() -> Self {
        Self {
            timestamp: u64::MAX,
            text: String::with_capacity(20),
        }
    }

    #[inline(always)]
    pub fn get(&mut self, timestamp: u64) -> &str {
        if self.timestamp != timestamp {
            self.timestamp = timestamp;
            self.text.clear();
            write_rfc3339(&mut self.text, timestamp);
        }
        &self.text
    }
}

impl Default for TimestampCache {
    fn default() -> Self {
        Self::new()
    }
}

pub fn write_rfc3339(out: &mut impl Write, timestamp: u64) {
    let dt = DateTime::from_timestamp(timestamp as i64);
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    );
}

#[cfg(test)]
mod tests {
    use super::TimestampCache;
    use mail_parser::DateTime;

    #[test]
    fn timestamp_matches_rfc3339() {
        let mut cache = TimestampCache::new();
        for timestamp in [
            0u64,
            1,
            59,
            86_399,
            951_782_400,
            1_700_000_000,
            1_757_000_000,
            4_102_444_800,
            253_402_300_799,
        ] {
            let expected = DateTime::from_timestamp(timestamp as i64).to_rfc3339();
            assert_eq!(cache.get(timestamp), expected);
            assert_eq!(cache.get(timestamp), expected);
        }
    }
}
