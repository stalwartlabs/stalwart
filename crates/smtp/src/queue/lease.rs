/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::spool::LOCK_EXPIRY;
use rand::RngExt;
use std::time::{Duration, Instant};
use store::write::ArchiveVersion;
use trc::{EventType, Key, StoreEvent, Value};

const DEADLINE_MARGIN: Duration = Duration::from_secs(150);
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub struct QueueLease {
    deadline: Instant,
    version: ArchiveVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    First,
    Retry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalWrite {
    Committed,
    Failed,
    Pending,
}

pub enum Backoff {
    Sleep(Duration),
    Stop(FinalWrite),
}

impl Backoff {
    pub fn is_stop(&self) -> bool {
        matches!(self, Backoff::Stop(_))
    }
}

pub struct WriteRetry {
    deadline: Instant,
    backoff: Duration,
    attempt: Attempt,
}

impl QueueLease {
    pub fn new(locked_at: Instant, version: ArchiveVersion) -> Self {
        QueueLease {
            deadline: locked_at + Duration::from_secs(LOCK_EXPIRY).saturating_sub(DEADLINE_MARGIN),
            version,
        }
    }

    pub fn single_attempt() -> Self {
        QueueLease {
            deadline: Instant::now(),
            version: ArchiveVersion::Unversioned,
        }
    }

    pub fn version(&self) -> ArchiveVersion {
        self.version
    }

    pub fn retry(&self) -> WriteRetry {
        WriteRetry {
            deadline: self.deadline,
            backoff: BACKOFF_MIN,
            attempt: Attempt::First,
        }
    }
}

impl WriteRetry {
    pub fn attempt(&self) -> Attempt {
        self.attempt
    }

    pub fn next(&mut self, err: &trc::Error) -> Backoff {
        if !is_transient(err) {
            return Backoff::Stop(FinalWrite::Failed);
        }
        if Instant::now() + self.backoff >= self.deadline {
            return Backoff::Stop(FinalWrite::Pending);
        }
        let backoff = self.backoff;
        self.backoff = (backoff * 2).min(BACKOFF_MAX);
        self.attempt = Attempt::Retry;
        let jitter = rand::rng().random_range(0..=backoff.as_millis() as u64 / 2);
        Backoff::Sleep(backoff + Duration::from_millis(jitter))
    }
}

fn is_transient(err: &trc::Error) -> bool {
    match err.event_type() {
        EventType::Store(StoreEvent::PostgresqlError) => match err.key(Key::Code) {
            Some(Value::String(code)) => is_transient_sqlstate(code.as_bytes()),
            _ => true,
        },
        EventType::Store(StoreEvent::FoundationdbError) => match err.key(Key::Code) {
            Some(Value::Int(code)) => !(2000..3000).contains(code),
            Some(Value::UInt(code)) => !(2000..3000).contains(code),
            _ => true,
        },
        EventType::Store(StoreEvent::MysqlError | StoreEvent::PoolError) => true,
        _ => false,
    }
}

fn is_transient_sqlstate(code: &[u8]) -> bool {
    code.starts_with(b"08")
        || hashify::set!(
            code, "25006", "40001", "40P01", "53300", "57P01", "57P02", "57P03"
        )
}
