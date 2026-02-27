/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistryGetResponse;
use chrono::DateTime;
use registry::{
    jmap::IntoValue,
    schema::{enums::TracingLevel, structs::Log},
    types::{EnumImpl, datetime::UTCDateTime},
};
use rev_lines::RevLines;
use std::{
    fs::{self, File},
    io,
    path::Path,
};
use store::ahash::AHashSet;
use tokio::sync::oneshot;
use trc::EventType;
use types::id::Id;

pub(crate) async fn log_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let Some(path) = get.server.core.metrics.log_path.clone() else {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("No log tracers configured on the server"));
    };

    let ids = if let Some(ids) = get.ids.take() {
        ids.into_iter().map(|id| id.id()).collect::<AHashSet<_>>()
    } else {
        (0u64..get.server.core.jmap.get_max_objects as u64).collect()
    };

    if !ids.is_empty() {
        // TODO: Use worker pool
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(read_log_entries(path, ids));
        });

        rx.await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?
            .map_err(|err| {
                trc::ManageEvent::Error
                    .reason(err)
                    .details("Failed to read log files")
                    .caused_by(trc::location!())
            })?
            .into_iter()
            .for_each(|(id, log)| {
                get.insert(id, log.into_value());
            });
    }

    Ok(get)
}

fn line_numbers(
    path: impl AsRef<Path>,
    filter: &str,
    mut offset: usize,
    limit: usize,
) -> io::Result<(usize, Vec<Id>)> {
    let mut logs = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    let mut total = 0;

    // Sort the entries by file name in reverse order.
    logs.sort_by_key(|b| std::cmp::Reverse(b.file_name()));

    let mut entries = Vec::with_capacity(limit);
    let mut logs = logs.into_iter();
    let mut current_line = 0u64;
    while let Some(log) = logs.next() {
        if log.file_type()?.is_file() {
            let mut rev_lines = RevLines::new(File::open(log.path())?);

            while let Some(line) = rev_lines.next() {
                let line = line.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                if filter.is_empty() || line.contains(filter) {
                    total += 1;
                    if offset == 0 {
                        entries.push(Id::from(current_line));
                        if entries.len() == limit {
                            if rev_lines.next().is_some() || logs.next().is_some() {
                                total += limit;
                            }

                            return Ok((total, entries));
                        }
                    } else {
                        offset -= 1;
                    }
                }

                current_line += 1;
            }
        }
    }

    Ok((total, entries))
}

fn read_log_entries(path: impl AsRef<Path>, lines: AHashSet<u64>) -> io::Result<Vec<(Id, Log)>> {
    let mut logs = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;

    // Sort the entries by file name in reverse order.
    logs.sort_by_key(|b| std::cmp::Reverse(b.file_name()));

    let mut entries = Vec::with_capacity(lines.len());
    let mut current_line = 0;

    'outer: for log in logs.into_iter() {
        if log.file_type()?.is_file() {
            for line in RevLines::new(File::open(log.path())?) {
                let line = line.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                if lines.contains(&current_line)
                    && let Some(log) = log_from_line(&line)
                {
                    entries.push((Id::from(current_line), log));

                    if entries.len() == lines.len() {
                        break 'outer;
                    }
                }

                current_line += 1;
            }
        }
    }

    Ok(entries)
}

fn log_from_line(line: &str) -> Option<Log> {
    let (timestamp, rest) = line.split_once(' ')?;
    let timestamp = DateTime::parse_from_rfc3339(timestamp).ok()?;
    let (level, rest) = rest.trim().split_once(' ')?;
    let (_, rest) = rest.trim().split_once(" (")?;
    let (event_id, details) = rest.split_once(")")?;

    Some(Log {
        timestamp: UTCDateTime::from_timestamp(timestamp.timestamp()),
        level: TracingLevel::parse(&level.to_ascii_uppercase()).unwrap_or(TracingLevel::Info),
        event: EventType::parse(event_id)?,
        details: details.trim().to_string(),
    })
}
