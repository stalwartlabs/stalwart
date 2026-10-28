/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, SystemTime};

const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
const MAX_SERVER_DELAY: Duration = Duration::from_secs(60 * 60);
const MAX_GRPC_TIMEOUT_DIGITS: u64 = 99_999_999;
const MAX_RETRY_AFTER_LEN: usize = 64;

pub struct Backoff {
    attempt: u32,
    rng: u64,
}

impl Backoff {
    pub fn new(seed: u64) -> Self {
        Self {
            attempt: 0,
            rng: seed | 1,
        }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn next_delay(&mut self) -> Duration {
        let cap = INITIAL_BACKOFF
            .saturating_mul(1u32 << self.attempt.min(16))
            .min(MAX_BACKOFF);
        self.attempt = self.attempt.saturating_add(1);
        let half = cap / 2;
        let jitter_ms = u64::try_from(half.as_millis()).unwrap_or(u64::MAX).max(1);
        half + Duration::from_millis(self.next_random() % jitter_ms)
    }

    fn next_random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }
}

pub fn parse_retry_after(value: &[u8], now: SystemTime) -> Option<Duration> {
    let value = value.trim_ascii();
    if value.is_empty() || value.len() > MAX_RETRY_AFTER_LEN {
        return None;
    }
    if value.iter().all(u8::is_ascii_digit) {
        let mut seconds = 0u64;
        for digit in value {
            seconds = seconds
                .saturating_mul(10)
                .saturating_add((digit - b'0') as u64);
        }
        return Some(Duration::from_secs(seconds).min(MAX_SERVER_DELAY));
    }
    let date = httpdate::parse_http_date(std::str::from_utf8(value).ok()?).ok()?;
    Some(
        date.duration_since(now)
            .unwrap_or(Duration::ZERO)
            .min(MAX_SERVER_DELAY),
    )
}

pub fn cap_server_delay(delay: Duration) -> Duration {
    delay.min(MAX_SERVER_DELAY)
}

pub fn write_grpc_timeout(timeout: Duration, out: &mut [u8; 16]) -> &[u8] {
    let millis = u64::try_from(timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let (value, unit) = if millis <= MAX_GRPC_TIMEOUT_DIGITS {
        (millis, b'm')
    } else {
        (timeout.as_secs().min(MAX_GRPC_TIMEOUT_DIGITS), b'S')
    };
    let mut buffer = itoa::Buffer::new();
    let digits = buffer.format(value).as_bytes();
    let len = digits.len();
    if let Some((dst, rest)) = out.split_at_mut_checked(len) {
        dst.copy_from_slice(digits);
        if let Some(slot) = rest.first_mut() {
            *slot = unit;
        }
    }
    out.get(..len + 1).unwrap_or_default()
}
