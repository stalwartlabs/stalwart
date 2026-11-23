/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse},
        query::RegistryQueryFilters,
    },
};
use common::config::telemetry::LogFiles;
use jiff::Timestamp;
use jmap_proto::types::state::State;
use memchr::{memmem, memrchr};
use registry::{
    jmap::IntoValue,
    schema::{enums::TracingLevel, prelude::Property, structs::Log},
    types::{EnumImpl, datetime::UTCDateTime},
};
use std::{
    borrow::Cow,
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom},
    mem,
};
use store::ahash::AHashMap;
use tokio::sync::oneshot;
use trc::EventType;
use types::id::Id;

pub(crate) async fn log_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let Some(files) = get.server.core.metrics.log_files.clone() else {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("No log tracers configured on the server"));
    };

    let ids = get.ids.take();

    if ids.as_ref().is_none_or(|ids| !ids.is_empty()) {
        // TODO: Use worker pool
        let limit = get.server.core.jmap.get_max_objects;
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _ = tx.send(read_log_entries(&files, ids, limit));
        });

        rx.await
            .map_err(|err| {
                trc::EventType::Server(trc::ServerEvent::ThreadError)
                    .reason(err)
                    .caused_by(trc::location!())
            })?
            .map_err(|err| {
                trc::EventType::Telemetry(trc::TelemetryEvent::LogError)
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

pub(crate) async fn log_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let Some(files) = req.server.core.metrics.log_files.clone() else {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("No log tracers configured on the server"));
    };

    let mut filter = None;

    req.request
        .extract_filters(|property, _, value| match property {
            Property::Text => {
                if let serde_json::Value::String(due) = value {
                    filter = Some(due);
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    let anchor = req.request.anchor.map(|id| id.id()).unwrap_or(0);
    let limit = std::cmp::min(
        req.request.limit.unwrap_or(usize::MAX),
        req.server.core.jmap.query_max_results,
    );

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, Property::Id.into())?;

    if params.sort_by != Property::Id {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Only sorting by 'id' is supported for logs"));
    }

    if req.request.position.unwrap_or(0) != 0 {
        return Err(trc::JmapEvent::InvalidArguments
            .into_err()
            .details("Pagination is only possible using anchors for logs"));
    }

    let (tx, rx) = oneshot::channel();

    tokio::task::spawn_blocking(move || {
        let _ = tx.send(read_log_offsets(&files, filter.as_deref(), anchor, limit));
    });

    // Build response
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    response.response.ids = rx
        .await
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
        })?
        .map_err(|err| {
            trc::EventType::Telemetry(trc::TelemetryEvent::LogError)
                .reason(err)
                .details("Failed to read log files")
                .caused_by(trc::location!())
        })?;
    response.anchor_found = true;

    Ok(response)
}

fn read_log_offsets(
    files: &LogFiles,
    filter: Option<&str>,
    anchor: u64,
    limit: usize,
) -> io::Result<Vec<Id>> {
    let logs = files.newest_first()?;
    let mut entries = Vec::with_capacity(limit);
    let finder = filter.map(memmem::Finder::new);
    let mut file_number = 0u64;
    let mut found_anchor = anchor == 0;
    let file_anchor = anchor >> 48;

    'outer: for log in logs {
        if !found_anchor && file_anchor != file_number {
            file_number += 1;
            continue;
        }

        let file = File::open(log)?;
        let file_size = file.metadata()?.len();
        let mut rev_lines = RawRevLines::new(file);
        rev_lines.init_reader()?;

        let mut offset = file_size;
        let mut continuation_matches = false;

        for line in rev_lines {
            let line = line?;
            offset = offset.saturating_sub(line.len() as u64 + 1); // +1 for the newline character

            let line_matches = finder
                .as_ref()
                .is_some_and(|finder| finder.find(&line).is_some());

            if !is_log_header(&line) {
                continuation_matches |= line_matches;
                continue;
            }

            let matches = finder.is_none() || mem::take(&mut continuation_matches) || line_matches;
            let id = (file_number << 48) | offset;

            if !found_anchor {
                found_anchor = id == anchor;
                continue;
            }

            if matches {
                entries.push(Id::from(id));
                if entries.len() == limit {
                    break 'outer;
                }
            }
        }

        file_number += 1;
    }

    Ok(entries)
}

fn read_log_entries(
    files: &LogFiles,
    ids: Option<Vec<Id>>,
    limit: usize,
) -> io::Result<Vec<(Id, Log)>> {
    let ids = if let Some(mut ids) = ids {
        ids.truncate(limit);
        ids
    } else {
        read_log_offsets(files, None, 0, limit)?
    };

    let logs = files.newest_first()?;

    let mut entries = Vec::with_capacity(ids.len());

    // Group files and offsets
    let mut offset_map = AHashMap::new();
    let total_ids = ids.len();
    for id in ids {
        let file_number = id.id() >> 48;
        let offset = id.id() & 0xFFFFFFFFFFFF;
        offset_map
            .entry(file_number)
            .or_insert_with(Vec::new)
            .push(offset);
    }

    let mut line = String::with_capacity(256);
    let mut continuation = Vec::with_capacity(256);

    'outer: for (file_number, log) in (0u64..).zip(logs) {
        if let Some(offsets) = offset_map.get(&file_number) {
            let mut reader = BufReader::new(File::open(log)?);

            for offset in offsets {
                // seek to the offset and read the line
                reader.seek(SeekFrom::Start(*offset))?;
                line.clear();
                reader.read_line(&mut line)?;

                if let Some(mut log) = log_from_line(&line) {
                    while reader.fill_buf()?.first() == Some(&b'\t') {
                        continuation.clear();
                        reader.read_until(b'\n', &mut continuation)?;
                        let key = String::from_utf8_lossy(&continuation);
                        let key = strip_ansi(&key);
                        let key = key.trim();
                        if !key.is_empty() {
                            if !log.details.is_empty() {
                                log.details.push_str(", ");
                            }
                            log.details.push_str(key);
                        }
                    }
                    entries.push((Id::from((file_number << 48) | *offset), log));

                    if entries.len() == total_ids {
                        break 'outer;
                    }
                }
            }
        }
    }

    Ok(entries)
}

const ESC_BYTE: u8 = 0x1b;

fn is_log_header(line: &[u8]) -> bool {
    if !line
        .first()
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == ESC_BYTE)
    {
        return false;
    }
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let line = strip_ansi(line);
    line.split_once(' ').is_some_and(|(timestamp, _)| {
        timestamp.starts_with(|c: char| c.is_ascii_digit())
            && timestamp.parse::<Timestamp>().is_ok()
    })
}

fn log_from_line(line: &str) -> Option<Log> {
    let line = strip_ansi(line);
    let (timestamp, rest) = line.split_once(' ')?;
    let timestamp = timestamp.parse::<Timestamp>().ok()?;
    let (level, rest) = rest.trim().split_once(' ')?;
    let (_, rest) = rest.trim().split_once(" (")?;
    let (event_id, details) = rest.split_once(")")?;

    Some(Log {
        timestamp: UTCDateTime::from_timestamp(timestamp.as_second()),
        level: TracingLevel::parse(&level.to_ascii_lowercase()).unwrap_or(TracingLevel::Info),
        event: EventType::parse(event_id)?,
        details: details.trim().to_string(),
    })
}

fn strip_ansi(line: &str) -> Cow<'_, str> {
    if !line.contains('\x1b') {
        return Cow::Borrowed(line);
    }

    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if matches!(c as u32, 0x40..=0x7e) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    Cow::Owned(out)
}

/*
 * SPDX-FileCopyrightText: 2017 Michael Coyne <mjc@hey.com>
 *
 * SPDX-License-Identifier: MIT
 */

// Adapted from https://github.com/mjc-gh/rev_lines/blob/main/src/lib.rs

static DEFAULT_SIZE: usize = 4096;
static LF_BYTE: u8 = b'\n';

/// `RevLines` struct
pub struct RawRevLines<R> {
    reader: BufReader<R>,
    reader_cursor: u64,
    buffer: Vec<u8>,
    buffer_end: usize,
    read_len: usize,
}

impl<R: Seek + Read> RawRevLines<R> {
    /// Create a new `RawRevLines` struct from a Reader.
    /// Internal buffering for iteration will default to 4096 bytes at a time.
    pub fn new(reader: R) -> RawRevLines<R> {
        RawRevLines::with_capacity(DEFAULT_SIZE, reader)
    }

    /// Create a new `RawRevLines` struct from a Reader`.
    /// Internal buffering for iteration will use `cap` bytes at a time.
    pub fn with_capacity(cap: usize, reader: R) -> RawRevLines<R> {
        RawRevLines {
            reader: BufReader::new(reader),
            reader_cursor: u64::MAX,
            buffer: vec![0; cap],
            buffer_end: 0,
            read_len: 0,
        }
    }

    pub fn init_reader(&mut self) -> io::Result<()> {
        // Move cursor to the end of the file and store the cursor position
        self.reader_cursor = self.reader.seek(SeekFrom::End(0))?;
        // Next read will be the full buffer size or the remaining bytes in the file
        self.read_len = std::cmp::min(self.buffer.len(), self.reader_cursor as usize);
        // Move cursor just before the next bytes to read
        self.reader.seek_relative(-(self.read_len as i64))?;
        // Update the cursor position
        self.reader_cursor -= self.read_len as u64;

        self.read_to_buffer()?;

        // Handle any trailing new line characters for the reader
        // so the first next call does not return Some("")
        if self.buffer_end > 0
            && let Some(last_byte) = self.buffer.get(self.buffer_end - 1)
            && *last_byte == LF_BYTE
        {
            self.buffer_end -= 1;
        }

        Ok(())
    }

    fn read_to_buffer(&mut self) -> io::Result<()> {
        // Read the next bytes into the buffer, self.read_len was already prepared for that
        self.reader.read_exact(&mut self.buffer[0..self.read_len])?;
        // Specify which part of the buffer is valid
        self.buffer_end = self.read_len;

        // Determine what the next read length will be
        let next_read_len = std::cmp::min(self.buffer.len(), self.reader_cursor as usize);
        // Move the cursor just in front of the next read
        self.reader
            .seek_relative(-((self.read_len + next_read_len) as i64))?;
        // Update cursor position
        self.reader_cursor -= next_read_len as u64;

        // Store the next read length, it'll be used in the next call
        self.read_len = next_read_len;

        Ok(())
    }

    fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Reader cursor will only ever be u64::MAX if the reader has not been initialized
        // If by some chance the reader is initialized with a file of length u64::MAX this will still work,
        // as some read length value is subtracted from the cursor position right away
        if self.reader_cursor == u64::MAX {
            self.init_reader()?;
        }

        // For most sane scenarios, where size of the buffer is greater than the length of the line,
        // the result will only contain one and at most two elements, making the flattening trivial.
        // At the same time, instead of pushing one element at a time, it allows us to copy a subslice of the buffer,
        // which is very performant on modern architectures.
        let mut result: Vec<Vec<u8>> = Vec::new();

        'outer: loop {
            // Current buffer was read to completion, read new contents
            if self.buffer_end == 0 {
                // Read the of minimum between the desired
                // buffer size or remaining length of the reader
                self.read_to_buffer()?;
            }

            // If buffer_end is still 0, it means the reader is empty
            if self.buffer_end == 0 {
                if result.is_empty() {
                    return Ok(None);
                } else {
                    break;
                }
            }

            let buffer = self.buffer.get(..self.buffer_end).unwrap_or_default();
            match memrchr(LF_BYTE, buffer) {
                Some(pos) => {
                    result.push(buffer.get(pos + 1..).unwrap_or_default().to_vec());
                    self.buffer_end = pos;
                    break 'outer;
                }
                None => {
                    result.push(buffer.to_vec());
                    self.buffer_end = 0;
                }
            }
        }

        result.reverse();
        Ok(Some(if result.len() == 1 {
            result.swap_remove(0)
        } else {
            result.concat()
        }))
    }
}

impl<R: Read + Seek> Iterator for RawRevLines<R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<io::Result<Vec<u8>>> {
        self.next_line().transpose()
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/jmap/src/registry/mapping/log/tests.rs"]
mod tests;
