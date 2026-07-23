/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use common::{Server, auth::AccessToken, telemetry::tracers::TraceEvents};
use http_body_util::{StreamBody, combinators::BoxBody};
use http_proto::*;
use hyper::{
    StatusCode,
    body::{Bytes, Frame},
};
use mail_parser::DateTime;
use registry::schema::{enums::Permission, structs::Trace};
use std::future::Future;
use std::{
    fmt::Write,
    time::{Duration, Instant},
};
use store::ahash::{AHashMap, AHashSet};
use trc::{
    Collector, EventType, Key, MetricType, Value,
    ipc::{bitset::Bitset, subscriber::SubscriberBuilder},
};
use utils::url_params::UrlParams;

pub trait TelemetryApi: Sync + Send {
    fn handle_telemetry_api_request(
        &self,
        req: &HttpRequest,
        is_tracing: bool,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl TelemetryApi for Server {
    async fn handle_telemetry_api_request(
        &self,
        req: &HttpRequest,
        is_tracing: bool,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        let params = UrlParams::new(req.uri().query());
        if is_tracing {
            // Validate the access token
            access_token.enforce_permission(Permission::LiveTracing)?;

            let mut key_filters = AHashMap::new();
            let mut filter = None;

            for (key, value) in params.into_inner() {
                if key == "filter" {
                    filter = value.into_owned().into();
                } else if let Some(key) = Key::parse(key.to_ascii_lowercase().as_str()) {
                    key_filters.insert(key, value.into_owned());
                }
            }

            let (_, mut rx) = SubscriberBuilder::new("live-tracer".to_string())
                .with_interests(Box::new(Bitset::all()))
                .with_lossy(false)
                .register();
            let throttle = Duration::from_secs(1);
            let ping_interval = Duration::from_secs(30);
            let ping_payload = Bytes::from(format!(
                "event: ping\ndata: {{\"interval\": {}}}\n\n",
                ping_interval.as_millis()
            ));
            let mut last_ping = Instant::now();
            let mut events = Vec::new();
            let mut active_span_ids = AHashSet::new();

            Ok(HttpResponse::new(StatusCode::OK)
                .with_content_type("text/event-stream")
                .with_cache_control("no-store")
                .with_stream_body(BoxBody::new(StreamBody::new(
                    async_stream::stream! {
                        let mut last_message = Instant::now() - throttle;
                        let mut timeout = ping_interval;

                        yield Ok(Frame::data(ping_payload.clone()));

                        loop {
                            match tokio::time::timeout(timeout, rx.recv()).await {
                                Ok(Some(event_batch)) => {
                                    for event in event_batch {
                                        if (filter.is_none() && key_filters.is_empty())
                                            || event
                                                .span_id()
                                                .is_some_and(|span_id| active_span_ids.contains(&span_id))
                                        {
                                            events.push(event);
                                        } else {
                                            let mut matched_keys = AHashSet::new();
                                            for (key, value) in event
                                                .keys
                                                .iter()
                                                .chain(event.inner.span.as_ref().map_or(([]).iter(), |s| s.keys.iter()))
                                            {
                                                if let Some(needle) = key_filters.get(key).or(filter.as_ref()) {
                                                    let matches = match value {
                                                        Value::String(haystack) => haystack.contains(needle),
                                                        Value::Timestamp(haystack) => {
                                                            DateTime::from_timestamp(*haystack as i64)
                                                                .to_rfc3339()
                                                                .contains(needle)
                                                        }
                                                        Value::Bool(true) => needle == "true",
                                                        Value::Bool(false) => needle == "false",
                                                        Value::Ipv4(haystack) => haystack.to_string().contains(needle),
                                                        Value::Ipv6(haystack) => haystack.to_string().contains(needle),
                                                        Value::Event(_) |
                                                        Value::Array(_) |
                                                        Value::UInt(_) |
                                                        Value::Int(_) |
                                                        Value::Float(_) |
                                                        Value::Duration(_) |
                                                        Value::Bytes(_) |
                                                        Value::None => false,
                                                    };

                                                    if matches {
                                                        matched_keys.insert(*key);
                                                        if filter.is_some() || matched_keys.len() == key_filters.len() {
                                                            if let Some(span_id) = event.span_id() {
                                                                active_span_ids.insert(span_id);
                                                            }
                                                            events.push(event);
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Ok(None) => {
                                    break;
                                }
                                Err(_) => (),
                            }

                            timeout = if !events.is_empty() {
                                let elapsed = last_message.elapsed();
                                if elapsed >= throttle {
                                    last_message = Instant::now();
                                    let num_events = events.len();
                                    yield Ok(Frame::data(Bytes::from(format!(
                                        "event: trace\ndata: {}\n\n",
                                        serde_json::to_string(
                                            &Trace::build_trace_events(events.iter().map(|e| e.as_ref()), num_events)).unwrap_or_default()
                                    ))));

                                    ping_interval
                                } else {
                                    throttle - elapsed
                                }
                            } else {
                                let elapsed = last_ping.elapsed();
                                if elapsed >= ping_interval {
                                    last_ping = Instant::now();
                                    yield Ok(Frame::data(ping_payload.clone()));
                                    ping_interval
                                } else {
                                    ping_interval - elapsed
                                }
                            };
                        }
                    },
                ))))
        } else {
            // Validate the access token
            access_token.enforce_permission(Permission::LiveMetrics)?;

            let interval = Duration::from_secs(
                params
                    .parse::<u64>("interval")
                    .filter(|interval| *interval >= 1)
                    .unwrap_or(30),
            );
            let mut event_types = AHashSet::new();
            let mut metric_types = AHashSet::new();
            for metric_name in params.get("metrics").unwrap_or_default().split(',') {
                let metric_name = metric_name.trim();
                if !metric_name.is_empty() {
                    if let Some(event_type) = EventType::parse(metric_name) {
                        event_types.insert(event_type);
                    } else if let Some(metric_type) = MetricType::parse(metric_name) {
                        metric_types.insert(metric_type);
                    }
                }
            }

            // Refresh expensive metrics
            for metric_type in [
                MetricType::QueueCount,
                MetricType::UserCount,
                MetricType::DomainCount,
            ] {
                if metric_types.contains(&metric_type) {
                    let value = match metric_type {
                        MetricType::QueueCount => self.total_queued_messages().await?,
                        MetricType::UserCount => self.total_accounts().await? as u64,
                        MetricType::DomainCount => self.total_domains().await? as u64,
                        _ => unreachable!(),
                    };
                    Collector::update_gauge(metric_type, value);
                }
            }

            Ok(HttpResponse::new(StatusCode::OK)
                .with_content_type("text/event-stream")
                .with_cache_control("no-store")
                .with_stream_body(BoxBody::new(StreamBody::new(
                    async_stream::stream! {
                        loop {
                            let mut metrics = String::with_capacity(512);
                            metrics.push_str("event: metrics\ndata: [");
                            let mut is_first = true;

                            for counter in Collector::collect_counters(true) {
                                if event_types.is_empty() || event_types.contains(&counter.id()) {
                                    if !is_first {
                                        metrics.push(',');
                                    } else {
                                        is_first = false;
                                    }
                                    let _ = write!(
                                        &mut metrics,
                                        "{{\"metric\":\"{}\",\"@type\":\"Counter\",\"count\":{}}}",
                                        counter.id().as_str(),
                                        counter.value()
                                    );
                                }
                            }
                            for gauge in Collector::collect_gauges(true) {
                                if metric_types.is_empty() || metric_types.contains(&gauge.id()) {
                                    if !is_first {
                                        metrics.push(',');
                                    } else {
                                        is_first = false;
                                    }
                                    let _ = write!(
                                        &mut metrics,
                                        "{{\"metric\":\"{}\",\"@type\":\"Gauge\",\"count\":{}}}",
                                        gauge.id().as_str(),
                                        gauge.get()
                                    );
                                }
                            }
                            for histogram in Collector::collect_histograms(true) {
                                if metric_types.is_empty() || metric_types.contains(&histogram.id()) {
                                    if !is_first {
                                        metrics.push(',');
                                    } else {
                                        is_first = false;
                                    }
                                    let _ = write!(
                                        &mut metrics,
                                        "{{\"metric\":\"{}\",\"@type\":\"Histogram\",\"count\":{},\"sum\":{}}}",
                                        histogram.id().as_str(),
                                        histogram.count(),
                                        histogram.sum()
                                    );
                                }
                            }
                            metrics.push_str("]\n\n");

                            yield Ok(Frame::data(Bytes::from(metrics)));
                            tokio::time::sleep(interval).await;
                        }
                    },
                ))))
        }
    }
}
