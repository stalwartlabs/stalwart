/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::storage::Storage;
use crate::ipc::IndexQueueNotify;
use ahash::{AHashMap, AHashSet};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use encodify::base64::STANDARD;
use hyper::HeaderMap;
use registry::schema::{
    enums::{EventPolicy, LogRotateFrequency},
    prelude::ObjectType,
    structs::{self, EventTracingLevel, HttpAuth, MetricsPrometheus, Tracer, WebHook},
};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use registry::schema::structs::Search;
// SPDX-SnippetEnd
use serde::Serialize;
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    str::FromStr,
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};
use store::registry::bootstrap::Bootstrap;
use telemetry::{
    exporter::{
        DEFAULT_MAX_PENDING_BYTES, DEFAULT_MAX_REQUEST_BYTES, OtlpConfig, OtlpTracer,
        metrics::OtlpMetricsExporter,
    },
    otlp::resource::{ProcessIdentity, Resource},
    transport::{
        endpoint::{Endpoint, Transport},
        sender::is_reserved_header,
    },
};
use trc::{EventType, Level, MetricType, TelemetryEvent, ipc::subscriber::Interests};
use utils::{http::shared_tls_config, map::vec_map::VecMap};

const DEFAULT_GRPC_URL: &str = "http://localhost:4317";

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

pub type OtelTracer = OtlpTracer;

pub struct OtelMetrics {
    pub exporter: tokio::sync::Mutex<OtlpMetricsExporter>,
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
    pub client: reqwest::Client,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[derive(Debug)]
#[cfg(feature = "enterprise")]
pub struct StoreTracer {
    pub store: store::Store,
    pub data: Option<store::Store>,
    pub index_tx: IndexQueueNotify,
    pub index: bool,
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

#[derive(Debug, Clone)]
pub struct PrometheusMetrics {
    pub auth: PrometheusAuth,
    pub size_hint: Arc<AtomicUsize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrometheusAuth {
    None,
    Basic(Box<str>),
}

impl PrometheusAuth {
    fn new(username: Option<&str>, secret: Option<&str>) -> Result<Self, &'static str> {
        match (
            username.filter(|username| !username.is_empty()),
            secret.filter(|secret| !secret.is_empty()),
        ) {
            (None, None) => Ok(PrometheusAuth::None),
            (Some(username), Some(secret)) => Ok(PrometheusAuth::Basic(
                STANDARD
                    .encode(format!("{username}:{secret}"))
                    .into_boxed_str(),
            )),
            (Some(_), None) => Err("Prometheus authUsername is set but authSecret is not"),
            (None, Some(_)) => Err("Prometheus authSecret is set but authUsername is not"),
        }
    }

    pub fn is_authorized(&self, basic_credentials: Option<&str>) -> bool {
        match self {
            PrometheusAuth::None => true,
            PrometheusAuth::Basic(expected) => basic_credentials.is_some_and(|credentials| {
                verify_slices_are_equal(expected.as_bytes(), credentials.as_bytes()).is_ok()
            }),
        }
    }
}

impl Telemetry {
    pub async fn parse(bp: &mut Bootstrap, storage: &Storage, index_tx: IndexQueueNotify) -> Self {
        let metrics = bp.setting_infallible::<structs::Metrics>().await;
        let resource = OtlpResource::new(bp, &metrics);
        let mut telemetry = Telemetry {
            tracers: Tracers::parse(bp, storage, index_tx, &resource).await,
            metrics: Interests::default(),
        };

        // Parse metrics
        apply_metrics(metrics.metrics, metrics.metrics_policy, |metric_type| {
            let event_id = metric_type.event_id();
            if event_id != usize::MAX {
                telemetry.metrics.set(event_id);
            }
        });

        telemetry
    }
}

macro_rules! strip_interests {
    ($tracer:expr) => {{
        $tracer.enable = true;
        $tracer.lossy = false;
        $tracer.events = Default::default();
        $tracer.events_policy = Default::default();
    }};
    ($tracer:expr, level) => {{
        strip_interests!($tracer);
        $tracer.level = Default::default();
    }};
}

fn sink_fingerprint<T: Serialize>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    serde_json::to_vec(value)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

fn tracer_sink_fingerprint(tracer: &Tracer, resource: &OtlpResource) -> u64 {
    let mut tracer = tracer.clone();
    let resource_fingerprint = match &mut tracer {
        Tracer::Log(t) => {
            strip_interests!(t, level);
            0
        }
        Tracer::Stdout(t) => {
            strip_interests!(t, level);
            0
        }
        Tracer::Journal(t) => {
            strip_interests!(t, level);
            0
        }
        Tracer::OtelHttp(t) => {
            strip_interests!(t, level);
            resource.fingerprint
        }
        Tracer::OtelGrpc(t) => {
            strip_interests!(t, level);
            resource.fingerprint
        }
    };
    sink_fingerprint(&tracer) ^ resource_fingerprint
}

pub struct OtlpResource {
    resource: Resource,
    fingerprint: u64,
}

impl OtlpResource {
    fn new(bp: &Bootstrap, metrics: &structs::Metrics) -> Self {
        Self {
            resource: Resource::new(
                &ProcessIdentity::new(bp.registry.process_nonce()),
                &metrics.service_name,
                metrics.service_namespace.as_deref(),
                metrics
                    .resource_attributes
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            ),
            fingerprint: sink_fingerprint(&(
                &metrics.service_name,
                &metrics.service_namespace,
                &metrics.resource_attributes,
            )),
        }
    }
}

struct OtlpSettings {
    transport: Transport,
    url: Option<String>,
    http_auth: HttpAuth,
    http_headers: VecMap<String, String>,
    allow_invalid_certs: bool,
    timeout: Duration,
}

impl OtlpSettings {
    async fn build(self) -> Result<OtlpConfig, String> {
        let url = self.url.as_deref().unwrap_or(DEFAULT_GRPC_URL);
        let endpoint = Endpoint::parse(url).map_err(|err| err.to_string())?;
        let header_map = self
            .http_auth
            .build_headers(self.http_headers, None)
            .await
            .map_err(|err| format!("Failed to build OpenTelemetry headers: {err}"))?;
        let mut headers = Vec::with_capacity(header_map.len());
        let mut name = None;
        for (next_name, value) in header_map {
            if next_name.is_some() {
                name = next_name;
            }
            if let Some(name) = name.as_ref().filter(|name| !is_reserved_header(name)) {
                headers.push((name.clone(), value));
            }
        }
        Ok(OtlpConfig {
            endpoint,
            transport: self.transport,
            headers: headers.into(),
            tls: Arc::new(shared_tls_config(self.allow_invalid_certs)),
            timeout: self.timeout,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
        })
    }
}

impl Tracers {
    #[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
    pub async fn parse(
        bp: &mut Bootstrap,
        storage: &Storage,
        index_tx: IndexQueueNotify,
        resource: &OtlpResource,
    ) -> Self {
        let mut custom_levels = AHashMap::new();
        let mut tracers: Vec<TelemetrySubscriber> = Vec::new();
        let mut global_interests = Interests::default();

        if !bp.registry.is_recovery_mode() {
            // Parse custom logging levels
            for level in bp.list_infallible::<EventTracingLevel>().await {
                custom_levels.insert(level.object.event, level.object.level.into());
            }

            // Parse tracers
            for tracer in bp.list_infallible::<Tracer>().await {
                let id = tracer.id;
                let tracer = tracer.object;
                let sink = tracer_sink_fingerprint(&tracer, resource);
                let level;
                let lossy;
                let events;
                let events_policy;
                let enable;

                let typ = match tracer {
                    Tracer::Log(tracer) if tracer.enable => {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;
                        enable = tracer.enable;

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
                        enable = tracer.enable;

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
                            enable = tracer.enable;

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
                        enable = tracer.enable;

                        match (OtlpSettings {
                            transport: Transport::Http,
                            url: Some(tracer.url),
                            http_auth: tracer.http_auth,
                            http_headers: tracer.http_headers,
                            allow_invalid_certs: tracer.allow_invalid_certs,
                            timeout: tracer.timeout.into_inner(),
                        })
                        .build()
                        .await
                        {
                            Ok(otlp) => TelemetrySubscriberType::OtelTracer(OtlpTracer {
                                otlp,
                                resource: resource.resource.clone(),
                                throttle: tracer.throttle.into_inner(),
                                export_logs: tracer.enable_log_exporter,
                                export_spans: tracer.enable_span_exporter,
                            }),
                            Err(err) => {
                                bp.build_error(id, err);
                                continue;
                            }
                        }
                    }
                    Tracer::OtelGrpc(tracer) if tracer.enable => {
                        level = Level::from(tracer.level);
                        lossy = tracer.lossy;
                        events = tracer.events;
                        events_policy = tracer.events_policy;
                        enable = tracer.enable;

                        match (OtlpSettings {
                            transport: Transport::Grpc,
                            url: tracer.url,
                            http_auth: tracer.http_auth,
                            http_headers: tracer.http_headers,
                            allow_invalid_certs: tracer.allow_invalid_certs,
                            timeout: tracer.timeout.into_inner(),
                        })
                        .build()
                        .await
                        {
                            Ok(otlp) => TelemetrySubscriberType::OtelTracer(OtlpTracer {
                                otlp,
                                resource: resource.resource.clone(),
                                throttle: tracer.throttle.into_inner(),
                                export_logs: tracer.enable_log_exporter,
                                export_spans: tracer.enable_span_exporter,
                            }),
                            Err(err) => {
                                bp.build_error(id, err);
                                continue;
                            }
                        }
                    }
                    _ => continue,
                };

                if !enable {
                    continue;
                }

                // Create tracer
                let mut tracer = TelemetrySubscriber {
                    id: format!("t_{}_{sink:x}", id.id()),
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
                let index = bp.setting_infallible::<Search>().await.index_telemetry;
                let mut tracer = TelemetrySubscriber {
                    id: if index { "history-idx" } else { "history" }.to_string(),
                    interests: Default::default(),
                    lossy: false,
                    typ: TelemetrySubscriberType::StoreTracer(StoreTracer {
                        data: (!storage.tracing.is_same(&storage.data))
                            .then(|| storage.data.clone()),
                        store: storage.tracing.clone(),
                        index_tx,
                        index,
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
                let sink = {
                    let mut hook = hook.clone();
                    strip_interests!(hook, level);
                    sink_fingerprint(&hook)
                };

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
                    id: format!("w_{}_{sink:x}", id.id()),
                    interests: Default::default(),
                    lossy: hook.lossy,
                    typ: TelemetrySubscriberType::Webhook(WebhookTracer {
                        url: hook.url,
                        timeout: hook.timeout.into_inner(),
                        tls_allow_invalid_certs: hook.allow_invalid_certs,
                        client: utils::http::http_client_builder(hook.allow_invalid_certs)
                            .build()
                            .unwrap_or_default(),
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
                let level = Level::from(hook.level);
                apply_events(hook.events, hook.events_policy, |event_type| {
                    if event_type != EventType::Telemetry(TelemetryEvent::WebhookError)
                        && level.is_contained(
                            custom_levels
                                .get(&event_type)
                                .copied()
                                .unwrap_or(event_type.level()),
                        )
                    {
                        tracer.interests.set(event_type);
                        global_interests.set(event_type);
                    }
                });

                if !tracer.interests.is_empty() {
                    tracers.push(tracer);
                } else {
                    bp.build_warning(id, "No events enabled for webhook");
                }
            }

            #[cfg(feature = "dev_mode")]
            if let Ok(level) = std::env::var("LOG") {
                let level = Level::from_str(&level).expect("Invalid LOG level");
                for event_type in EventType::variants() {
                    let event_level = custom_levels
                        .get(event_type)
                        .copied()
                        .unwrap_or(event_type.level());
                    if level.is_contained(event_level) {
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
        } else {
            // Add default tracer if none were found
            let level = std::env::var("STALWART_RECOVERY_MODE_LOG_LEVEL")
                .ok()
                .and_then(|level| Level::from_str(&level).ok())
                .unwrap_or(Level::Info);
            for event_type in EventType::variants() {
                let event_level = custom_levels
                    .get(event_type)
                    .copied()
                    .unwrap_or(event_type.level());
                if level.is_contained(event_level) {
                    global_interests.set(event_type.to_id() as usize);
                }
            }

            tracers.push(TelemetrySubscriber {
                id: "recover-log".to_string(),
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
        let resource = OtlpResource::new(bp, &metrics).resource;

        Metrics {
            prometheus: match metrics.prometheus {
                MetricsPrometheus::Enabled(prom) => {
                    let auth = match prom.auth_secret.secret().await {
                        Ok(secret) => {
                            PrometheusAuth::new(prom.auth_username.as_deref(), secret.as_deref())
                                .map_err(|err| err.to_string())
                        }
                        Err(err) => {
                            Err(format!("Unable to retrieve Prometheus auth secret: {err}"))
                        }
                    };
                    match auth {
                        Ok(auth) => Some(PrometheusMetrics {
                            auth,
                            size_hint: Arc::new(AtomicUsize::new(0)),
                        }),
                        Err(err) => {
                            bp.build_error(
                                ObjectType::Metrics.singleton(),
                                format!("{err}, Prometheus endpoint disabled"),
                            );
                            None
                        }
                    }
                }
                MetricsPrometheus::Disabled => None,
            },
            otel: {
                let settings = match metrics.open_telemetry {
                    structs::MetricsOtel::Http(otel) => Some((
                        OtlpSettings {
                            transport: Transport::Http,
                            url: Some(otel.url),
                            http_auth: otel.http_auth,
                            http_headers: otel.http_headers,
                            allow_invalid_certs: otel.allow_invalid_certs,
                            timeout: otel.timeout.into_inner(),
                        },
                        otel.interval.into_inner(),
                    )),
                    structs::MetricsOtel::Grpc(otel) => Some((
                        OtlpSettings {
                            transport: Transport::Grpc,
                            url: otel.url,
                            http_auth: otel.http_auth,
                            http_headers: otel.http_headers,
                            allow_invalid_certs: otel.allow_invalid_certs,
                            timeout: otel.timeout.into_inner(),
                        },
                        otel.interval.into_inner(),
                    )),
                    structs::MetricsOtel::Disabled => None,
                };
                match settings {
                    Some((settings, interval)) => {
                        match settings.build().await.and_then(|config| {
                            OtlpMetricsExporter::new(config, resource)
                                .map_err(|err| err.to_string())
                        }) {
                            Ok(exporter) => Some(Arc::new(OtelMetrics {
                                exporter: tokio::sync::Mutex::new(exporter),
                                interval,
                            })),
                            Err(err) => {
                                bp.build_error(
                                    ObjectType::Metrics.singleton(),
                                    format!(
                                        "Failed to build OpenTelemetry metrics exporter: {err}"
                                    ),
                                );
                                None
                            }
                        }
                    }
                    None => None,
                }
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/config/telemetry/tests.rs"]
mod tests;
