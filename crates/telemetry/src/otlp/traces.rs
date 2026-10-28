/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{request::RequestBuilder, span_id_value, trace_id, unix_nanos, value::ValueEncoder};
use crate::proto::writer::{LenHint, ProtoWriter};
use trc::{Event, EventDetails, Key};

const SCOPE_SPANS: u32 = 2;

const SPAN_TRACE_ID: u32 = 1;
const SPAN_SPAN_ID: u32 = 2;
const SPAN_NAME: u32 = 5;
const SPAN_KIND: u32 = 6;
const SPAN_START_TIME: u32 = 7;
const SPAN_END_TIME: u32 = 8;
const SPAN_ATTRIBUTES: u32 = 9;
const SPAN_EVENTS: u32 = 11;
const SPAN_FLAGS: u32 = 16;

const EVENT_TIME: u32 = 1;
const EVENT_NAME: u32 = 2;
const EVENT_ATTRIBUTES: u32 = 3;

const SPAN_KIND_SERVER: u64 = 2;
const SPAN_FLAGS_SAMPLED_NOT_REMOTE: u32 = 0x101;

pub fn encode_span<'x>(
    request: &mut RequestBuilder,
    values: &mut ValueEncoder,
    start: &Event<EventDetails>,
    end: &'x Event<EventDetails>,
    events: impl Iterator<Item = &'x Event<EventDetails>>,
    trace_prefix: &[u8; 8],
) -> bool {
    let span_id = start
        .keys
        .iter()
        .find(|(key, _)| *key == Key::SpanId)
        .map_or(0, |(_, value)| span_id_value(value));
    if span_id == 0 {
        return false;
    }

    let w = request.writer();
    let span = w.begin(SCOPE_SPANS, LenHint::Medium);
    w.bytes_always(SPAN_TRACE_ID, &trace_id(trace_prefix, span_id));
    w.bytes_always(SPAN_SPAN_ID, &span_id.to_be_bytes());
    w.bytes(SPAN_NAME, start.inner.typ.as_str().as_bytes());
    w.uint64(SPAN_KIND, SPAN_KIND_SERVER);
    w.fixed64(SPAN_START_TIME, unix_nanos(start.inner.timestamp));
    w.fixed64(SPAN_END_TIME, unix_nanos(end.inner.timestamp));
    write_attributes(w, values, SPAN_ATTRIBUTES, start);
    for event in events.chain(std::iter::once(end)) {
        let span_event = w.begin(SPAN_EVENTS, LenHint::Small);
        w.fixed64(EVENT_TIME, unix_nanos(event.inner.timestamp));
        w.bytes(EVENT_NAME, event.inner.typ.as_str().as_bytes());
        write_attributes(w, values, EVENT_ATTRIBUTES, event);
        w.end(span_event);
    }
    w.fixed32(SPAN_FLAGS, SPAN_FLAGS_SAMPLED_NOT_REMOTE);
    w.end(span);
    request.commit();
    true
}

#[inline(always)]
fn write_attributes(
    w: &mut ProtoWriter,
    values: &mut ValueEncoder,
    field: u32,
    event: &Event<EventDetails>,
) {
    for (key, value) in &event.keys {
        if *key != Key::SpanId {
            values.key_value(w, field, *key, value);
        }
    }
}
