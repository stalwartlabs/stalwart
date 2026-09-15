/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    io::{Write, stderr},
    thread::Builder,
};

use crate::config::telemetry::ConsoleTracer;
use compact_str::ToCompactString;
use trc::{TelemetryEvent, ipc::subscriber::SubscriberBuilder, serializers::text::FmtWriter};

const FLUSH_THRESHOLD: usize = 1 << 16;

pub(crate) fn spawn_console_tracer(builder: SubscriberBuilder, settings: ConsoleTracer) {
    let (_, mut rx) = builder.register();
    if let Err(err) = Builder::new()
        .name("stalwart-console".to_string())
        .spawn(move || {
            let mut formatter = FmtWriter::new()
                .with_ansi(settings.ansi)
                .with_multiline(settings.multiline);
            let mut buf = Vec::with_capacity(if settings.buffered {
                FLUSH_THRESHOLD
            } else {
                1024
            });

            while let Some(events) = rx.blocking_recv() {
                let mut stderr = stderr().lock();
                for event in events {
                    formatter.write(&event, &mut buf);
                    if !settings.buffered || buf.len() >= FLUSH_THRESHOLD {
                        let _ = stderr.write_all(&buf);
                        buf.clear();
                    }
                }

                if !buf.is_empty() {
                    let _ = stderr.write_all(&buf);
                    buf.clear();
                }
            }
        })
    {
        trc::event!(
            Telemetry(TelemetryEvent::LogError),
            Details = "Failed to spawn console writer thread",
            Reason = err.to_compact_string(),
        );
    }
}
