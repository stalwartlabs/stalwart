/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{request::RequestBuilder, span_id_value, trace_id, unix_nanos, value::ValueEncoder};
use crate::proto::writer::LenHint;
use trc::{Event, EventDetails, Key, Level, event::KeySet};

const SCOPE_LOG_RECORDS: u32 = 2;

const LOG_TIME: u32 = 1;
const LOG_SEVERITY_NUMBER: u32 = 2;
const LOG_SEVERITY_TEXT: u32 = 3;
const LOG_BODY: u32 = 5;
const LOG_ATTRIBUTES: u32 = 6;
const LOG_FLAGS: u32 = 8;
const LOG_TRACE_ID: u32 = 9;
const LOG_SPAN_ID: u32 = 10;
const LOG_OBSERVED_TIME: u32 = 11;
const LOG_EVENT_NAME: u32 = 12;

const ANY_STRING: u32 = 1;
const TRACE_FLAG_SAMPLED: u32 = 0x01;

const SEVERITY_TRACE: u64 = 1;
const SEVERITY_DEBUG: u64 = 5;
const SEVERITY_INFO: u64 = 9;
const SEVERITY_WARN: u64 = 13;
const SEVERITY_ERROR: u64 = 17;

#[inline(always)]
fn severity_number(level: Level) -> u64 {
    match level {
        Level::Trace => SEVERITY_TRACE,
        Level::Debug => SEVERITY_DEBUG,
        Level::Info => SEVERITY_INFO,
        Level::Warn => SEVERITY_WARN,
        Level::Error | Level::Disable => SEVERITY_ERROR,
    }
}

pub fn encode_log(
    request: &mut RequestBuilder,
    values: &mut ValueEncoder,
    event: &Event<EventDetails>,
    observed_unix_nano: u64,
    trace_prefix: &[u8; 8],
) {
    let w = request.writer();
    let description = event.inner.typ.description();

    let record = w.begin(SCOPE_LOG_RECORDS, LenHint::Medium);
    w.fixed64(LOG_TIME, unix_nanos(event.inner.timestamp));
    w.uint64(LOG_SEVERITY_NUMBER, severity_number(event.inner.level));
    w.bytes(LOG_SEVERITY_TEXT, event.inner.level.as_str().as_bytes());
    w.len_prefix(
        LOG_BODY,
        crate::proto::len_field_len(ANY_STRING, description.len()),
    );
    w.bytes_always(ANY_STRING, description.as_bytes());

    let mut span_id = 0u64;
    let mut seen_keys = KeySet::default();
    let span_keys = event
        .inner
        .span
        .as_ref()
        .map_or(&[][..], |span| span.keys.as_slice());
    for (pos, (key, value)) in event.keys.iter().chain(span_keys).enumerate() {
        if *key == Key::SpanId {
            if pos < event.keys.len() && span_id == 0 {
                span_id = span_id_value(value);
            }
        } else if seen_keys.insert(*key) {
            values.key_value(w, LOG_ATTRIBUTES, *key, value);
        }
    }

    if span_id != 0 {
        w.fixed32(LOG_FLAGS, TRACE_FLAG_SAMPLED);
        w.bytes_always(LOG_TRACE_ID, &trace_id(trace_prefix, span_id));
        w.bytes_always(LOG_SPAN_ID, &span_id.to_be_bytes());
    }
    w.fixed64(LOG_OBSERVED_TIME, observed_unix_nano);
    w.bytes(LOG_EVENT_NAME, event.inner.typ.as_str().as_bytes());
    w.end(record);
    request.commit();
}
