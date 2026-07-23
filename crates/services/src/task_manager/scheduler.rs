/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;
use std::{
    collections::BinaryHeap,
    sync::Arc,
    time::{Instant, SystemTime},
};

use common::{
    BuildServer, Inner, LONG_1D_SLUMBER,
    config::{mailstore::spamfilter, telemetry::OtelMetrics},
};
use registry::{
    schema::{
        enums::{TaskSpamFilterMaintenanceType, TaskStoreMaintenanceType, TaskType},
        structs::{Task, TaskSpamFilterMaintenance, TaskStatus, TaskStoreMaintenance},
    },
    types::EnumImpl,
};
use store::write::{BatchBuilder, now};
use trc::{ClusterEvent, Collector, MetricType, TaskManagerEvent, TelemetryEvent};

#[derive(PartialEq, Eq)]
struct Action {
    due: Instant,
    event: Event,
}

#[derive(PartialEq, Eq, Debug)]
enum Event {
    PurgeAccount,
    PurgeDataStore,
    PurgeBlobStore,
    OtelMetrics,
    CalculateMetrics,
    TrainSpamClassifier,
    RenewNodeIdLease,
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    InternalMetrics,
    #[cfg(feature = "enterprise")]
    AlertMetrics,
    #[cfg(feature = "enterprise")]
    RenewLicense,
    // SPDX-SnippetEnd
}

#[derive(Default)]
struct Queue {
    heap: BinaryHeap<Action>,
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
const METRIC_ALERTS_INTERVAL: Duration = Duration::from_secs(5 * 60);
// SPDX-SnippetEnd

pub fn spawn_task_scheduler(inner: Arc<Inner>) {
    tokio::spawn(async move {
        trc::event!(TaskManager(TaskManagerEvent::SchedulerStarted));
        let start_time = SystemTime::now();

        // Add all events to queue
        let mut queue = Queue::default();
        {
            let server = inner.build_server();

            // Account purge
            queue.schedule(
                Instant::now() + server.core.email.account_purge_frequency.time_to_next(),
                Event::PurgeAccount,
            );
            queue.schedule(
                Instant::now() + server.core.email.data_purge_frequency.time_to_next(),
                Event::PurgeDataStore,
            );
            queue.schedule(
                Instant::now() + server.core.email.blob_purge_frequency.time_to_next(),
                Event::PurgeBlobStore,
            );

            // Node ID lease renewal
            if server.core.storage.coordinator.is_enabled() {
                queue.schedule(
                    Instant::now() + server.registry().refresh_node_id_interval(),
                    Event::RenewNodeIdLease,
                );
            }

            // Spam classifier training
            if let Some(train_frequency) = server
                .core
                .spam
                .classifier
                .as_ref()
                .and_then(|c| c.train_frequency)
            {
                let next_train = match server.inner.data.spam_classifier.load().as_ref() {
                    spamfilter::SpamClassifier::FhClassifier {
                        last_trained_at, ..
                    }
                    | spamfilter::SpamClassifier::CcfhClassifier {
                        last_trained_at, ..
                    } => now().saturating_sub(*last_trained_at).min(train_frequency),
                    spamfilter::SpamClassifier::Disabled => train_frequency,
                };

                queue.schedule(
                    Instant::now() + Duration::from_secs(next_train),
                    Event::TrainSpamClassifier,
                );
            }

            // OTEL Push Metrics
            if let Some(otel) = &server.core.metrics.otel {
                OtelMetrics::enable_errors();
                queue.schedule(Instant::now() + otel.interval, Event::OtelMetrics);
            }

            // Calculate expensive metrics
            queue.schedule(Instant::now(), Event::CalculateMetrics);

            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL

            // Enterprise Edition license management
            #[cfg(feature = "enterprise")]
            if let Some(enterprise) = &server.core.enterprise {
                queue.schedule(
                    Instant::now() + enterprise.license.renew_in(),
                    Event::RenewLicense,
                );

                queue.schedule(
                    Instant::now() + enterprise.metrics_interval.time_to_next(),
                    Event::InternalMetrics,
                );

                queue.schedule(Instant::now() + METRIC_ALERTS_INTERVAL, Event::AlertMetrics);
            }

            // SPDX-SnippetEnd
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        // Metrics history
        #[cfg(feature = "enterprise")]
        let metrics_history = common::telemetry::metrics::store::SharedMetricHistory::default();
        // SPDX-SnippetEnd

        let mut next_metric_update = Instant::now();

        loop {
            tokio::time::sleep(queue.wake_up_time()).await;

            let server = inner.build_server();
            let roles = &server.core.network.roles;
            let mut batch = (roles.task_scheduler).then(BatchBuilder::new);

            while let Some(event) = queue.pop() {
                match event.event {
                    Event::PurgeAccount => {
                        queue.schedule(
                            Instant::now()
                                + server.core.email.account_purge_frequency.time_to_next(),
                            Event::PurgeAccount,
                        );

                        if let Some(batch) = batch.as_mut() {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskQueued),
                                Type = TaskStoreMaintenanceType::PurgeAccounts.as_str()
                            );

                            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                                maintenance_type: TaskStoreMaintenanceType::PurgeAccounts,
                                status: TaskStatus::now(),
                                shard_index: None,
                            }));
                        }
                    }
                    Event::PurgeDataStore => {
                        queue.schedule(
                            Instant::now() + server.core.email.data_purge_frequency.time_to_next(),
                            Event::PurgeDataStore,
                        );

                        if let Some(batch) = batch.as_mut() {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskQueued),
                                Type = TaskStoreMaintenanceType::PurgeData.as_str()
                            );

                            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                                maintenance_type: TaskStoreMaintenanceType::PurgeData,
                                status: TaskStatus::now(),
                                shard_index: None,
                            }));
                        }
                    }
                    Event::PurgeBlobStore => {
                        queue.schedule(
                            Instant::now() + server.core.email.blob_purge_frequency.time_to_next(),
                            Event::PurgeBlobStore,
                        );

                        if let Some(batch) = batch.as_mut() {
                            trc::event!(
                                TaskManager(TaskManagerEvent::TaskQueued),
                                Type = TaskStoreMaintenanceType::PurgeBlob.as_str()
                            );

                            batch.schedule_task(Task::StoreMaintenance(TaskStoreMaintenance {
                                maintenance_type: TaskStoreMaintenanceType::PurgeBlob,
                                status: TaskStatus::now(),
                                shard_index: None,
                            }));
                        }
                    }
                    Event::RenewNodeIdLease => {
                        queue.schedule(
                            Instant::now() + server.registry().refresh_node_id_interval(),
                            Event::RenewNodeIdLease,
                        );

                        trc::event!(
                            Cluster(ClusterEvent::NodeIdRenewed),
                            Id = server.registry().node_id()
                        );

                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(err) = server.registry().refresh_node_id_lease().await {
                                trc::error!(err.details("Failed to renew node ID lease"));
                            }
                        });
                    }
                    Event::OtelMetrics => {
                        if let Some(otel) = &server.core.metrics.otel {
                            queue.schedule(Instant::now() + otel.interval, Event::OtelMetrics);

                            if roles.metrics_push {
                                let otel = otel.clone();

                                // SPDX-SnippetBegin
                                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                                // SPDX-License-Identifier: LicenseRef-SEL
                                #[cfg(feature = "enterprise")]
                                let is_enterprise = server.is_enterprise_edition();
                                // SPDX-SnippetEnd

                                #[cfg(not(feature = "enterprise"))]
                                let is_enterprise = false;

                                tokio::spawn(async move {
                                    let elapsed = Instant::now();
                                    otel.push_metrics(is_enterprise, start_time).await;

                                    trc::event!(
                                        Telemetry(TelemetryEvent::MetricsPushed),
                                        Elapsed = elapsed.elapsed()
                                    );
                                });
                            }
                        }
                    }
                    Event::CalculateMetrics => {
                        // Calculate expensive metrics every 5 minutes
                        queue.schedule(
                            Instant::now() + Duration::from_secs(5 * 60),
                            Event::CalculateMetrics,
                        );

                        let update_other_metrics = if Instant::now() >= next_metric_update {
                            next_metric_update = Instant::now() + Duration::from_secs(86400);
                            true
                        } else {
                            false
                        };

                        let server = server.clone();
                        tokio::spawn(async move {
                            let elapsed = Instant::now();
                            if server.core.network.roles.metrics_calculate {
                                // SPDX-SnippetBegin
                                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                                // SPDX-License-Identifier: LicenseRef-SEL
                                #[cfg(feature = "enterprise")]
                                if server.is_enterprise_edition() {
                                    // Obtain queue size
                                    match server.total_queued_messages().await {
                                        Ok(total) => {
                                            Collector::update_gauge(MetricType::QueueCount, total);
                                        }
                                        Err(err) => {
                                            trc::error!(err.details("Failed to obtain queue size"));
                                        }
                                    }
                                }
                                // SPDX-SnippetEnd

                                if update_other_metrics {
                                    match server.total_accounts().await {
                                        Ok(total) => {
                                            Collector::update_gauge(
                                                MetricType::UserCount,
                                                total as u64,
                                            );
                                        }
                                        Err(err) => {
                                            trc::error!(
                                                err.details("Failed to obtain account count")
                                            );
                                        }
                                    }

                                    match server.total_domains().await {
                                        Ok(total) => {
                                            Collector::update_gauge(
                                                MetricType::DomainCount,
                                                total as u64,
                                            );
                                        }
                                        Err(err) => {
                                            trc::error!(
                                                err.details("Failed to obtain domain count")
                                            );
                                        }
                                    }
                                }
                            }

                            match tokio::task::spawn_blocking(memory_stats::memory_stats).await {
                                Ok(Some(stats)) => {
                                    Collector::update_gauge(
                                        MetricType::ServerMemory,
                                        stats.physical_mem as u64,
                                    );
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    trc::error!(
                                        trc::EventType::Server(trc::ServerEvent::ThreadError,)
                                            .reason(err)
                                            .caused_by(trc::location!())
                                            .details("Join Error")
                                    );
                                }
                            }

                            trc::event!(
                                Telemetry(TelemetryEvent::MetricsCollected),
                                Elapsed = elapsed.elapsed()
                            );
                        });
                    }
                    Event::TrainSpamClassifier => {
                        if let Some(train_frequency) = server
                            .core
                            .spam
                            .classifier
                            .as_ref()
                            .and_then(|c| c.train_frequency)
                        {
                            // Schedule next training
                            queue.schedule(
                                Instant::now() + Duration::from_secs(train_frequency),
                                Event::TrainSpamClassifier,
                            );

                            if let Some(batch) = batch.as_mut() {
                                trc::event!(
                                    TaskManager(TaskManagerEvent::TaskQueued),
                                    Type = TaskType::SpamFilterMaintenance.as_str()
                                );

                                batch.schedule_task(Task::SpamFilterMaintenance(
                                    TaskSpamFilterMaintenance {
                                        maintenance_type: TaskSpamFilterMaintenanceType::Train,
                                        status: TaskStatus::now(),
                                    },
                                ));
                            }
                        }
                    }

                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    Event::InternalMetrics => {
                        if let Some(enterprise) = &server.core.enterprise {
                            queue.schedule(
                                Instant::now() + enterprise.metrics_interval.time_to_next(),
                                Event::InternalMetrics,
                            );
                        }

                        if server.core.storage.metrics.is_active() {
                            use common::telemetry::metrics::store::MetricsStore;

                            let metrics_store = server.core.storage.metrics.clone();
                            let metrics_history = metrics_history.clone();
                            tokio::spawn(async move {
                                let elapsed = Instant::now();
                                if let Err(err) =
                                    metrics_store.write_metrics(None, metrics_history).await
                                {
                                    trc::error!(err.details("Failed to write metrics"));
                                }
                                trc::event!(
                                    Telemetry(TelemetryEvent::MetricsStored),
                                    Elapsed = elapsed.elapsed()
                                );
                            });
                        }
                    }

                    #[cfg(feature = "enterprise")]
                    Event::AlertMetrics => {
                        queue
                            .schedule(Instant::now() + METRIC_ALERTS_INTERVAL, Event::AlertMetrics);

                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Some(messages) = server.process_alerts().await {
                                use smtp::reporting::send::MtaReportSend;

                                for message in messages {
                                    server
                                        .send_autogenerated(
                                            message.from,
                                            message.to.into_iter(),
                                            message.body,
                                            None,
                                            0,
                                        )
                                        .await;
                                }
                            }
                        });
                    }

                    #[cfg(feature = "enterprise")]
                    Event::RenewLicense => {
                        use common::ipc::RegistryChange;
                        use registry::schema::prelude::ObjectType;

                        trc::event!(
                            TaskManager(TaskManagerEvent::TaskQueued),
                            Type = "validateLicense"
                        );

                        match Box::pin(
                            server.reload_registry(RegistryChange::Reload(ObjectType::Enterprise)),
                        )
                        .await
                        {
                            Ok(result) => {
                                if !result.has_errors() {
                                    if let Some(enterprise) =
                                        server.inner.build_server().core.enterprise.as_ref()
                                    {
                                        let renew_in = if enterprise.license.is_near_expiration() {
                                            // Something went wrong during renewal, try again in 1 day or 1 hour,
                                            // depending on the time left on the license
                                            if enterprise.license.expires_in()
                                                < Duration::from_secs(86400)
                                            {
                                                Duration::from_secs(3600)
                                            } else {
                                                Duration::from_secs(86400)
                                            }
                                        } else {
                                            enterprise.license.renew_in()
                                        };

                                        queue.schedule(
                                            Instant::now() + renew_in,
                                            Event::RenewLicense,
                                        );
                                    }

                                    server
                                        .cluster_broadcast(common::ipc::BroadcastEvent::reload(
                                            ObjectType::Enterprise,
                                        ))
                                        .await;
                                } else {
                                    result.log();
                                }
                            }
                            Err(err) => {
                                trc::error!(err.details("Failed to reload configuration."));
                            }
                        }
                    } // SPDX-SnippetEnd
                }
            }

            if let Some(mut batch) = batch
                && !batch.is_empty()
                && let Err(err) = server.store().write(batch.build_all()).await
            {
                trc::error!(err.details("Failed to write scheduled tasks"));
            }
        }
    });
}

impl Queue {
    pub fn schedule(&mut self, due: Instant, event: Event) {
        trc::event!(
            TaskManager(TaskManagerEvent::TaskScheduled),
            Due = trc::Value::Timestamp(
                now() + due.saturating_duration_since(Instant::now()).as_secs()
            ),
            Id = event.name()
        );

        self.heap.push(Action { due, event });
    }

    pub fn wake_up_time(&self) -> Duration {
        self.heap
            .peek()
            .map(|e| e.due.saturating_duration_since(Instant::now()))
            .unwrap_or(LONG_1D_SLUMBER)
    }

    pub fn pop(&mut self) -> Option<Action> {
        if self.heap.peek()?.due <= Instant::now() {
            self.heap.pop()
        } else {
            None
        }
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.due.cmp(&other.due).reverse()
    }
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Event {
    fn name(&self) -> &'static str {
        match self {
            Event::PurgeAccount => "purgeAccount",
            Event::PurgeDataStore => "purgeDataStore",
            Event::PurgeBlobStore => "purgeBlobStore",
            Event::OtelMetrics => "otelMetrics",
            Event::CalculateMetrics => "calculateMetrics",
            Event::TrainSpamClassifier => "trainSpamClassifier",
            Event::RenewNodeIdLease => "renewNodeIdLease",
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <info@stalwartlabs.com>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            Event::InternalMetrics => "internalMetrics",
            #[cfg(feature = "enterprise")]
            Event::AlertMetrics => "alertMetrics",
            #[cfg(feature = "enterprise")]
            Event::RenewLicense => "renewLicense",
            // SPDX-SnippetEnd
        }
    }
}
