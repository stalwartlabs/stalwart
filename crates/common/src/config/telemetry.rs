/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::storage::Storage;
use ahash::{AHashMap, AHashSet};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::HeaderMap;
use opentelemetry::{InstrumentationScope, KeyValue, logs::LoggerProvider};
use opentelemetry_otlp::{
    LogExporter, MetricExporter, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::{
    Resource,
    logs::{SdkLogger, SdkLoggerProvider},
    metrics::Temporality,
};
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use registry::schema::{
    enums::{EventPolicy, LogRotateFrequency},
    prelude::ObjectType,
    structs::{self, EventTracingLevel, MetricsPrometheus, Tracer, WebHook},
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use store::registry::bootstrap::Bootstrap;
use trc::{EventType, Level, MetricType, TelemetryEvent, ipc::subscriber::Interests};

#[derive(Debug)]
pub struct TelemetrySubscriber {
    pub id: String,
    pub interests: Interests,
    pub typ: TelemetrySubscriberType,
    pub lossy: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum TelemetrySubscriberType {
    ConsoleTracer(ConsoleTracer),
    LogTracer(LogTracer),
    OtelTracer(OtelTracer),
    Webhook(WebhookTracer),
    #[cfg(unix)]
    JournalTracer(crate::telemetry::tracers::journald::Subscriber),
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    StoreTracer(StoreTracer),
    // SPDX-SnippetEnd
}

#[derive(Debug)]
pub struct OtelTracer {
    pub span_exporter: SpanExporter,
    pub span_exporter_enable: bool,
    pub log_exporter: LogExporter,
    pub log_provider: SdkLogger,
    pub log_exporter_enable: bool,
    pub throttle: Duration,
}

pub struct OtelMetrics {
    pub resource: Resource,
    pub instrumentation: InstrumentationScope,
    pub exporter: MetricExporter,
    pub interval: Duration,
}

#[derive(Debug)]
pub struct ConsoleTracer {
    pub ansi: bool,
    pub multiline: bool,
    pub buffered: bool,
}

#[derive(Debug)]
pub struct LogTracer {
    pub path: String,
    pub prefix: String,
    pub rotate: RotationStrategy,
    pub ansi: bool,
    pub multiline: bool,
}

#[derive(Debug)]
pub struct WebhookTracer {
    pub url: String,
    pub key: String,
    pub timeout: Duration,
    pub throttle: Duration,
    pub discard_after: Duration,
    pub tls_allow_invalid_certs: bool,
    pub headers: HeaderMap,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[derive(Debug)]
#[cfg(feature = "enterprise")]
pub struct StoreTracer {
    pub store: store::Store,
}
// SPDX-SnippetEnd

#[derive(Debug)]
pub enum RotationStrategy {
    Daily,
    Hourly,
    Minutely,
    Never,
}

#[derive(Debug)]
pub struct Telemetry {
    pub tracers: Tracers,
    pub metrics: Interests,
}

#[derive(Debug)]
pub struct Tracers {
    pub interests: Interests,
    pub levels: AHashMap<EventType, Level>,
    pub subscribers: Vec<TelemetrySubscriber>,
}

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub prometheus: Option<PrometheusMetrics>,
    pub otel: Option<Arc<OtelMetrics>>,
    pub log_path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PrometheusMetrics {
    pub auth: Option<String>,
}

impl Telemetry {
    pub async fn parse(bp: &mut Bootstrap, storage: &Storage) -> Self {
        let mut telemetry = Telemetry {
            tracers: Tracers::parse(bp, storage).await,
            metrics: Interests::default(),
        };

        // Parse metrics
        let metrics = bp.setting_infallible::<structs::Metrics>().await;
        apply_metrics(metrics.metrics, metrics.metrics_policy, |metric_type| {
            let event_id = metric_type.event_id();
            if event_id != usize::MAX {
                telemetry.metrics.set(event_id);
            }
        });

        telemetry
    }
}

impl Tracers {
    pub async fn parse(bp: &mut Bootstrap, storage: &Storage) -> Self {
        // Parse custom logging levels
        let mut custom_levels = AHashMap::new();
        for level in bp.list_infallible::<EventTracingLevel>().await {
            custom_levels.insert(level.object.event, level.object.level.into());
        }

        // Parse tracers
        let mut tracers: Vec<TelemetrySubscriber> = Vec::new();
        let mut global_interests = Interests::default();

        for tracer in bp.list_infallible::<Tracer>().await {
            let id = tracer.id;
            let tracer = tracer.object;
            let level;
            let lossy;
            let events;
            let events_policy;

            let typ = match tracer {
                Tracer::Log(tracer) if tracer.enable => {
                    level = Level::from(tracer.level);
                    lossy = tracer.lossy;
                    events = tracer.events;
                    events_policy = tracer.events_policy;

                    TelemetrySubscriberType::LogTracer(LogTracer {
                        path: tracer.path,
                        prefix: tracer.prefix,
                        rotate: match tracer.rotate {
                            LogRotateFrequency::Daily => RotationStrategy::Daily,
                            LogRotateFrequency::Hourly => RotationStrategy::Hourly,
                            LogRotateFrequency::Minutely => RotationStrategy::Minutely,
                            LogRotateFrequency::Never => RotationStrategy::Never,
                        },
                        ansi: tracer.ansi,
                        multiline: tracer.multiline,
                    })
                }
                Tracer::Stdout(tracer) if tracer.enable => {
                    level = Level::from(tracer.level);
                    lossy = tracer.lossy;
                    events = tracer.events;
                    events_policy = tracer.events_policy;

                    if !tracers
                        .iter()
                        .any(|t| matches!(t.typ, TelemetrySubscriberType::ConsoleTracer(_)))
                    {
                        TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                            ansi: tracer.ansi,
                            multiline: tracer.multiline,
                            buffered: tracer.buffered,
                        })
                    } else {
                        bp.build_error(id, "Only one console tracer is allowed");
                        continue;
                    }
                }
                Tracer::Journal(tracer) if tracer.enable => {
                    #[cfg(unix)]
                    {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;

                        if !tracers
                            .iter()
                            .any(|t| matches!(t.typ, TelemetrySubscriberType::JournalTracer(_)))
                        {
                            match crate::telemetry::tracers::journald::Subscriber::new() {
                                Ok(subscriber) => {
                                    TelemetrySubscriberType::JournalTracer(subscriber)
                                }
                                Err(e) => {
                                    bp.build_error(
                                        id,
                                        format!("Failed to create journald subscriber: {e}"),
                                    );
                                    continue;
                                }
                            }
                        } else {
                            bp.build_error(id, "Only one journal tracer is allowed");
                            continue;
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        bp.build_error(id, "Journald is only available on Unix systems.");
                        continue;
                    }
                }
                Tracer::OtelHttp(tracer) if tracer.enable => {
                    level = Level::from(tracer.level);
                    lossy = tracer.lossy;
                    events = tracer.events;
                    events_policy = tracer.events_policy;

                    let headers = match tracer
                        .http_auth
                        .build_headers(tracer.http_headers, None)
                        .await
                    {
                        Ok(headers) => headers
                            .into_iter()
                            .filter_map(|(k, v)| {
                                k.and_then(|k| Some((k.to_string(), v.to_str().ok()?.to_string())))
                            })
                            .collect::<HashMap<String, String>>(),
                        Err(err) => {
                            bp.build_error(
                                id,
                                format!("Failed to build OpenTelemetry HTTP headers: {err}"),
                            );
                            continue;
                        }
                    };

                    let mut span_exporter = SpanExporter::builder()
                        .with_http()
                        .with_endpoint(tracer.endpoint.clone())
                        .with_timeout(tracer.timeout.into_inner());
                    let mut log_exporter = LogExporter::builder()
                        .with_http()
                        .with_endpoint(tracer.endpoint)
                        .with_timeout(tracer.timeout.into_inner());
                    if !headers.is_empty() {
                        span_exporter = span_exporter.with_headers(headers.clone());
                        log_exporter = log_exporter.with_headers(headers);
                    }

                    match (span_exporter.build(), log_exporter.build()) {
                        (Ok(span_exporter), Ok(log_exporter)) => {
                            TelemetrySubscriberType::OtelTracer(OtelTracer {
                                span_exporter,
                                log_exporter,
                                throttle: tracer.throttle.into_inner(),
                                span_exporter_enable: tracer.enable_span_exporter,
                                log_exporter_enable: tracer.enable_log_exporter,
                                log_provider: SdkLoggerProvider::builder()
                                    .build()
                                    .logger("stalwart"),
                            })
                        }
                        (Err(err), _) => {
                            bp.build_error(
                                id,
                                format!("Failed to build OpenTelemetry span exporter: {err}"),
                            );
                            continue;
                        }
                        (_, Err(err)) => {
                            bp.build_error(
                                id,
                                format!("Failed to build OpenTelemetry log exporter: {err}"),
                            );
                            continue;
                        }
                    }
                }
                Tracer::OtelGrpc(tracer) if tracer.enable => {
                    level = Level::from(tracer.level);
                    lossy = tracer.lossy;
                    events = tracer.events;
                    events_policy = tracer.events_policy;

                    let mut span_exporter = SpanExporter::builder()
                        .with_tonic()
                        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                        .with_timeout(tracer.timeout.into_inner());
                    let mut log_exporter = LogExporter::builder()
                        .with_tonic()
                        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                        .with_timeout(tracer.timeout.into_inner());
                    if let Some(endpoint) = tracer.endpoint {
                        span_exporter = span_exporter.with_endpoint(endpoint.clone());
                        log_exporter = log_exporter.with_endpoint(endpoint);
                    }

                    match (span_exporter.build(), log_exporter.build()) {
                        (Ok(span_exporter), Ok(log_exporter)) => {
                            TelemetrySubscriberType::OtelTracer(OtelTracer {
                                span_exporter,
                                log_exporter,
                                throttle: tracer.throttle.into_inner(),
                                span_exporter_enable: tracer.enable_span_exporter,
                                log_exporter_enable: tracer.enable_log_exporter,
                                log_provider: SdkLoggerProvider::builder()
                                    .build()
                                    .logger("stalwart"),
                            })
                        }
                        (Err(err), _) => {
                            bp.build_error(
                                id,
                                format!("Failed to build OpenTelemetry span exporter: {err}"),
                            );
                            continue;
                        }
                        (_, Err(err)) => {
                            bp.build_error(
                                id,
                                format!("Failed to build OpenTelemetry log exporter: {err}"),
                            );
                            continue;
                        }
                    }
                }
                _ => continue,
            };

            // Create tracer
            let mut tracer = TelemetrySubscriber {
                id: format!("t_{}", id.id()),
                interests: Default::default(),
                lossy,
                typ,
            };

            // Parse disabled events
            let exclude_event = match &tracer.typ {
                TelemetrySubscriberType::ConsoleTracer(_) => None,
                TelemetrySubscriberType::LogTracer(_) => {
                    EventType::Telemetry(TelemetryEvent::LogError).into()
                }
                TelemetrySubscriberType::OtelTracer(_) => {
                    EventType::Telemetry(TelemetryEvent::OtelExporterError).into()
                }
                TelemetrySubscriberType::Webhook(_) => {
                    EventType::Telemetry(TelemetryEvent::WebhookError).into()
                }
                #[cfg(unix)]
                TelemetrySubscriberType::JournalTracer(_) => {
                    EventType::Telemetry(TelemetryEvent::JournalError).into()
                }
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                TelemetrySubscriberType::StoreTracer(_) => None,
                // SPDX-SnippetEnd
            };

            // Parse disabled events
            apply_events(events, events_policy, |event_type| {
                if exclude_event != Some(event_type) {
                    let event_level = custom_levels
                        .get(&event_type)
                        .copied()
                        .unwrap_or(event_type.level());
                    if level.is_contained(event_level) {
                        tracer.interests.set(event_type);
                        global_interests.set(event_type);
                    }
                }
            });

            if !tracer.interests.is_empty() {
                tracers.push(tracer);
            } else {
                bp.build_warning(id, "No events enabled for tracer");
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Parse tracing history
        #[cfg(feature = "enterprise")]
        if storage.tracing.is_active() {
            let mut tracer = TelemetrySubscriber {
                id: "history".to_string(),
                interests: Default::default(),
                lossy: false,
                typ: TelemetrySubscriberType::StoreTracer(StoreTracer {
                    store: storage.tracing.clone(),
                }),
            };

            for event_type in StoreTracer::default_events() {
                tracer.interests.set(event_type);
                global_interests.set(event_type);
            }

            tracers.push(tracer);
        }
        // SPDX-SnippetEnd

        // Parse webhooks
        for hook in bp.list_infallible::<WebHook>().await {
            let id = hook.id;
            let hook = hook.object;

            if !hook.enable {
                continue;
            }

            let headers = match hook
                .http_auth
                .build_headers(hook.http_headers, "application/json".into())
                .await
            {
                Ok(headers) => headers,
                Err(err) => {
                    bp.build_error(id, format!("Unable to build HTTP headers: {}", err));
                    continue;
                }
            };

            // Build tracer
            let mut tracer = TelemetrySubscriber {
                id: format!("w_{}", id.id()),
                interests: Default::default(),
                lossy: hook.lossy,
                typ: TelemetrySubscriberType::Webhook(WebhookTracer {
                    url: hook.url,
                    timeout: hook.timeout.into_inner(),
                    tls_allow_invalid_certs: hook.allow_invalid_certs,
                    headers,
                    key: hook
                        .signature_key
                        .secret()
                        .await
                        .map_err(|err| {
                            bp.build_error(
                                id,
                                format!("Unable to retrieve signature key: {}", err),
                            );
                        })
                        .unwrap_or_default()
                        .unwrap_or_default()
                        .into_owned(),
                    throttle: hook.throttle.into_inner(),
                    discard_after: hook.discard_after.into_inner(),
                }),
            };

            // Parse webhook events
            apply_events(hook.events, hook.events_policy, |event_type| {
                if event_type != EventType::Telemetry(TelemetryEvent::WebhookError) {
                    tracer.interests.set(event_type);
                    global_interests.set(event_type);
                }
            });

            if !tracer.interests.is_empty() {
                tracers.push(tracer);
            } else {
                bp.build_error(id, "No events enabled for webhook");
            }
        }

        // Add default tracer if none were found
        #[cfg(not(feature = "test_mode"))]
        if tracers.is_empty() {
            for event_type in EventType::variants() {
                let event_level = custom_levels
                    .get(&event_type)
                    .copied()
                    .unwrap_or(event_type.level());
                if Level::Info.is_contained(event_level) {
                    global_interests.set(event_type.to_id() as usize);
                }
            }

            tracers.push(TelemetrySubscriber {
                id: "default".to_string(),
                interests: global_interests.clone(),
                typ: TelemetrySubscriberType::ConsoleTracer(ConsoleTracer {
                    ansi: true,
                    multiline: false,
                    buffered: true,
                }),
                lossy: false,
            });
        }

        Tracers {
            subscribers: tracers,
            interests: global_interests,
            levels: custom_levels,
        }
    }
}

impl Metrics {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let metrics = bp.setting_infallible::<structs::Metrics>().await;
        let resource = Resource::builder()
            .with_service_name("stalwart")
            .with_attribute(KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
            .build();
        let instrumentation = InstrumentationScope::builder("stalwart")
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();

        Metrics {
            prometheus: match metrics.prometheus {
                MetricsPrometheus::Enabled(prom) => {
                    let secret = prom
                        .auth_secret
                        .secret()
                        .await
                        .map_err(|err| {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Unable to retrieve Prometheus auth secret: {err}"),
                            );
                        })
                        .unwrap_or_default();
                    Some(PrometheusMetrics {
                        auth: prom.auth_username.and_then(|user| {
                            secret.map(|secret| STANDARD.encode(format!("{user}:{secret}")))
                        }),
                    })
                }
                MetricsPrometheus::Disabled => None,
            },
            otel: match metrics.open_telemetry {
                structs::MetricsOtel::Http(otel) => {
                    let headers = match otel.http_auth.build_headers(otel.http_headers, None).await
                    {
                        Ok(headers) => headers
                            .into_iter()
                            .filter_map(|(k, v)| {
                                k.and_then(|k| Some((k.to_string(), v.to_str().ok()?.to_string())))
                            })
                            .collect::<HashMap<String, String>>(),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Failed to build OpenTelemetry HTTP headers: {err}"),
                            );
                            Default::default()
                        }
                    };

                    let mut exporter = MetricExporter::builder()
                        .with_temporality(Temporality::Delta)
                        .with_http()
                        .with_endpoint(otel.endpoint)
                        .with_timeout(otel.timeout.into_inner());
                    if !headers.is_empty() {
                        exporter = exporter.with_headers(headers);
                    }

                    match exporter.build() {
                        Ok(exporter) => Some(Arc::new(OtelMetrics {
                            exporter,
                            interval: otel.interval.into_inner(),
                            resource,
                            instrumentation,
                        })),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Failed to build OpenTelemetry metrics exporter: {err}"),
                            );
                            None
                        }
                    }
                }
                structs::MetricsOtel::Grpc(otel) => {
                    let mut exporter = MetricExporter::builder()
                        .with_temporality(Temporality::Delta)
                        .with_tonic()
                        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                        .with_timeout(otel.timeout.into_inner());
                    if let Some(endpoint) = otel.endpoint {
                        exporter = exporter.with_endpoint(endpoint);
                    }

                    match exporter.build() {
                        Ok(exporter) => Some(Arc::new(OtelMetrics {
                            exporter,
                            interval: otel.interval.into_inner(),
                            resource,
                            instrumentation,
                        })),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("Failed to build OpenTelemetry metrics exporter: {err}"),
                            );
                            None
                        }
                    }
                }
                structs::MetricsOtel::Disabled => None,
            },
            log_path: bp
                .list_infallible::<Tracer>()
                .await
                .into_iter()
                .find_map(|tracer| {
                    if let Tracer::Log(log_tracer) = tracer.object
                        && log_tracer.enable
                    {
                        Some(log_tracer.path)
                    } else {
                        None
                    }
                }),
        }
    }
}

fn apply_events(
    event_types: impl IntoIterator<Item = EventType>,
    policy: EventPolicy,
    mut apply_fn: impl FnMut(EventType),
) {
    let mut exclude_events = AHashSet::new();

    for event_type in event_types {
        if policy == EventPolicy::Include {
            apply_fn(event_type);
        } else {
            exclude_events.insert(event_type);
        }
    }

    if policy != EventPolicy::Include {
        for event_type in EventType::variants() {
            if !exclude_events.contains(event_type) {
                apply_fn(*event_type);
            }
        }
    }
}

fn apply_metrics(
    event_types: impl IntoIterator<Item = MetricType>,
    policy: EventPolicy,
    mut apply_fn: impl FnMut(MetricType),
) {
    let mut exclude_events = AHashSet::new();

    for event_type in event_types {
        if policy == EventPolicy::Include {
            apply_fn(event_type);
        } else {
            exclude_events.insert(event_type);
        }
    }

    if policy != EventPolicy::Include {
        for event_type in MetricType::variants() {
            if !exclude_events.contains(event_type) {
                apply_fn(*event_type);
            }
        }
    }
}

impl std::fmt::Debug for OtelMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtelMetrics")
            .field("interval", &self.interval)
            .finish()
    }
}
