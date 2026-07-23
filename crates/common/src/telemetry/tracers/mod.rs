/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(unix)]
pub mod journald;
pub mod log;
pub mod otel;
pub mod stdout;

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod store;
// SPDX-SnippetEnd

use registry::{
    schema::structs::{
        Trace, TraceEvent, TraceKeyValue, TraceValue, TraceValueBoolean, TraceValueDuration,
        TraceValueEvent, TraceValueFloat, TraceValueInteger, TraceValueIpAddr, TraceValueList,
        TraceValueString, TraceValueUTCDateTime, TraceValueUnsignedInt,
    },
    types::{datetime::UTCDateTime, ipaddr::IpAddr, list::List},
};
use trc::{Event, EventDetails, Value};

pub trait TraceEvents {
    fn build_trace_events<'x>(
        span_events: impl IntoIterator<Item = &'x Event<EventDetails>>,
        num_events: usize,
    ) -> Vec<TraceEvent>;

    fn from_events<'x>(
        span_events: impl IntoIterator<Item = &'x Event<EventDetails>>,
        num_events: usize,
    ) -> Self;
}

impl TraceEvents for Trace {
    fn build_trace_events<'x>(
        span_events: impl IntoIterator<Item = &'x Event<EventDetails>>,
        num_events: usize,
    ) -> Vec<TraceEvent> {
        let mut events = Vec::with_capacity(num_events);

        for event in span_events {
            let mut key_values = Vec::with_capacity(event.keys.len());
            for (key, value) in &event.keys {
                key_values.push(TraceKeyValue {
                    key: *key,
                    value: map_value(value),
                });
            }

            events.push(TraceEvent {
                event: event.inner.typ,
                timestamp: UTCDateTime::from_timestamp(event.inner.timestamp as i64),
                key_values: key_values.into(),
            });
        }

        events
    }

    fn from_events<'x>(
        span_events: impl IntoIterator<Item = &'x Event<EventDetails>>,
        num_events: usize,
    ) -> Self {
        Trace {
            events: Self::build_trace_events(span_events, num_events).into(),
        }
    }
}

fn map_value(value: &Value) -> TraceValue {
    match value {
        Value::String(value) => TraceValue::String(TraceValueString {
            value: value.to_string(),
        }),
        Value::UInt(value) => TraceValue::UnsignedInt(TraceValueUnsignedInt { value: *value }),
        Value::Int(value) => TraceValue::Integer(TraceValueInteger { value: *value }),
        Value::Float(value) => TraceValue::Float(TraceValueFloat {
            value: (*value).into(),
        }),
        Value::Timestamp(value) => TraceValue::UTCDateTime(TraceValueUTCDateTime {
            value: UTCDateTime::from_timestamp(*value as i64),
        }),
        Value::Duration(value) => TraceValue::Duration(TraceValueDuration { value: *value }),
        Value::Bytes(items) => TraceValue::String(TraceValueString {
            value: String::from_utf8_lossy(items).to_string(),
        }),
        Value::Bool(value) => TraceValue::Boolean(TraceValueBoolean { value: *value }),
        Value::Ipv4(ipv4_addr) => TraceValue::IpAddr(TraceValueIpAddr {
            value: IpAddr((*ipv4_addr).into()),
        }),
        Value::Ipv6(ipv6_addr) => TraceValue::IpAddr(TraceValueIpAddr {
            value: IpAddr((*ipv6_addr).into()),
        }),
        Value::Event(event) => TraceValue::Event(TraceValueEvent {
            value: event
                .keys()
                .iter()
                .map(|(k, v)| TraceKeyValue {
                    key: *k,
                    value: map_value(v),
                })
                .collect(),
            event: event.event_type(),
        }),
        Value::Array(values) => TraceValue::List(TraceValueList {
            value: List::from_iter(values.iter().map(map_value)),
        }),
        Value::None => TraceValue::Null,
    }
}
