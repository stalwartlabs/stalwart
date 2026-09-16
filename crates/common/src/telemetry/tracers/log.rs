/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Write},
    path::PathBuf,
    thread::Builder,
    time::SystemTime,
};

use crate::config::telemetry::{LogTracer, RotationStrategy};

use compact_str::{CompactString, ToCompactString};
use mail_parser::DateTime;
use tokio::sync::mpsc::Receiver;
use trc::{
    TelemetryEvent,
    ipc::subscriber::{EventBatch, SubscriberBuilder},
    serializers::text::FmtWriter,
};

const FLUSH_THRESHOLD: usize = 1 << 16;

pub(crate) fn spawn_log_tracer(builder: SubscriberBuilder, settings: LogTracer) {
    let (_, rx, _) = builder.register();
    if let Err(err) = Builder::new()
        .name("stalwart-log".to_string())
        .spawn(move || LogWriter::new(settings).run(rx))
    {
        trc::event!(
            Telemetry(TelemetryEvent::LogError),
            Details = "Failed to spawn log writer thread",
            Reason = err.to_compact_string(),
        );
    }
}

struct LogWriter {
    formatter: FmtWriter,
    settings: LogTracer,
    file: Option<File>,
    file_timestamp: u64,
    rotation_timestamp: u64,
    buf: Vec<u8>,
    lost_events: u64,
    pending_events: u64,
    is_failing: bool,
    failure_kind: Option<ErrorKind>,
    is_torn: bool,
}

impl LogWriter {
    fn new(settings: LogTracer) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        Self {
            formatter: FmtWriter::new()
                .with_ansi(settings.ansi)
                .with_multiline(settings.multiline),
            file: None,
            file_timestamp: now,
            rotation_timestamp: settings.next_rotation(now),
            settings,
            buf: Vec::with_capacity(FLUSH_THRESHOLD),
            lost_events: 0,
            pending_events: 0,
            is_failing: false,
            failure_kind: None,
            is_torn: false,
        }
    }

    fn run(mut self, mut rx: Receiver<EventBatch>) {
        self.flush();

        while let Some(events) = rx.blocking_recv() {
            for event in events {
                let timestamp = event.inner.timestamp;
                if self.rotation_timestamp != 0 && timestamp > self.rotation_timestamp {
                    self.flush();
                    self.file = None;
                    self.file_timestamp = timestamp;
                    self.rotation_timestamp = self.settings.next_rotation(timestamp);
                }

                self.formatter.write(&event, &mut self.buf);
                self.pending_events += 1;
                if self.buf.len() >= FLUSH_THRESHOLD {
                    self.flush();
                }
            }

            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.is_torn && !self.buf.is_empty() {
            self.buf.insert(0, b'\n');
        }

        let result = match &mut self.file {
            Some(file) => file.write_all(&self.buf),
            None => match self.settings.open(self.file_timestamp) {
                Ok(file) => self.file.insert(file).write_all(&self.buf),
                Err((path, err)) => {
                    self.failed(err, "Failed to create log file", Some(path));
                    return;
                }
            },
        };

        match result {
            Ok(()) => {
                if !self.buf.is_empty() {
                    self.is_torn = false;
                }
                self.buf.clear();
                self.pending_events = 0;
                if self.is_failing {
                    self.is_failing = false;
                    self.failure_kind = None;
                    trc::event!(
                        Telemetry(TelemetryEvent::LogError),
                        Details = "Resumed writing to log file",
                        Total = std::mem::take(&mut self.lost_events),
                    );
                }
            }
            Err(err) => {
                self.file = None;
                self.is_torn = true;
                self.failed(err, "Failed to write to log file", None);
            }
        }
    }

    fn failed(&mut self, err: std::io::Error, details: &'static str, path: Option<CompactString>) {
        self.buf.clear();
        self.lost_events += std::mem::take(&mut self.pending_events);
        if self.is_failing && self.failure_kind == Some(err.kind()) {
            return;
        }
        self.is_failing = true;
        self.failure_kind = Some(err.kind());

        match path {
            Some(path) => trc::event!(
                Telemetry(TelemetryEvent::LogError),
                Details = details,
                Path = path,
                Reason = err.to_compact_string(),
            ),
            None => trc::event!(
                Telemetry(TelemetryEvent::LogError),
                Details = details,
                Reason = err.to_compact_string(),
            ),
        }
    }
}

impl LogTracer {
    fn open(&self, timestamp: u64) -> Result<File, (CompactString, std::io::Error)> {
        let now = DateTime::from_timestamp(timestamp as i64);
        let file_name = match self.rotate {
            RotationStrategy::Daily => {
                format!(
                    "{}.{:04}-{:02}-{:02}",
                    self.prefix, now.year, now.month, now.day
                )
            }
            RotationStrategy::Hourly => {
                format!(
                    "{}.{:04}-{:02}-{:02}T{:02}",
                    self.prefix, now.year, now.month, now.day, now.hour
                )
            }
            RotationStrategy::Minutely => {
                format!(
                    "{}.{:04}-{:02}-{:02}T{:02}:{:02}",
                    self.prefix, now.year, now.month, now.day, now.hour, now.minute
                )
            }
            RotationStrategy::Never => self.prefix.clone(),
        };
        let path = PathBuf::from(&self.path).join(file_name);

        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|err| (CompactString::from(path.to_string_lossy()), err))
    }

    fn next_rotation(&self, timestamp: u64) -> u64 {
        let mut now = DateTime::from_timestamp(timestamp as i64);

        now.second = 0;

        match self.rotate {
            RotationStrategy::Daily => {
                now.hour = 0;
                now.minute = 0;
                now.to_timestamp() as u64 + 86400
            }
            RotationStrategy::Hourly => {
                now.minute = 0;
                now.to_timestamp() as u64 + 3600
            }
            RotationStrategy::Minutely => now.to_timestamp() as u64 + 60,
            RotationStrategy::Never => 0,
        }
    }
}
