/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::broadcast::{BROADCAST_TOPIC, BroadcastBatch, RETRY_INITIAL, RETRY_MAX};
use common::{
    BuildServer, IPC_CHANNEL_BUFFER, Inner,
    ipc::{BroadcastEvent, PushEvent, PushNotification, QueueEvent, QueueRefresh, RegistryChange},
};
use compact_str::format_compact;
use coordinator::MsgKind;
use registry::types::EnumImpl;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    ahash::AHashSet,
    rand::{self, RngExt},
    write::TaskTypes,
};
use tokio::sync::{mpsc, watch};
use trc::{ClusterEvent, ServerEvent};

const STABLE_SUBSCRIPTION: Duration = Duration::from_secs(1);

struct BroadcastReceiver {
    inner: Arc<Inner>,
    node_id: u16,
    registry_tx: mpsc::Sender<RegistryChange>,
}

pub fn spawn_broadcast_subscriber(inner: Arc<Inner>, mut shutdown_rx: watch::Receiver<bool>) {
    let node_id = {
        let core = inner.shared_core.load();
        if core.storage.coordinator.is_none() || core.storage.registry.is_recovery_mode() {
            return;
        }
        core.network.node_id as u16
    };

    tokio::spawn(async move {
        let receiver = BroadcastReceiver {
            registry_tx: spawn_registry_worker(inner.clone()),
            inner,
            node_id,
        };
        let mut retry_count = 0;
        let mut is_resubscribe = false;

        trc::event!(Cluster(ClusterEvent::SubscriberStart));

        'subscribe: loop {
            let coordinator = receiver
                .inner
                .shared_core
                .load()
                .storage
                .coordinator
                .clone();
            if coordinator.is_none() {
                trc::event!(
                    Cluster(ClusterEvent::SubscriberError),
                    Details = "Coordinator is no longer configured"
                );
                break;
            }

            match coordinator.subscribe(BROADCAST_TOPIC).await {
                Ok(mut subscription) => {
                    if std::mem::replace(&mut is_resubscribe, true) {
                        receiver.catch_up().await;
                    }
                    let subscribed_at = Instant::now();
                    let mut has_received = false;
                    let mut stream = subscription.stream();
                    loop {
                        tokio::select! {
                            message = stream.next() => match message {
                                Some(message) => {
                                    has_received = true;
                                    match message.kind() {
                                        MsgKind::Payload => receiver.receive(message.payload()).await,
                                        MsgKind::CatchUp => receiver.catch_up().await,
                                        MsgKind::Ignore => {}
                                    }
                                }
                                None => {
                                    trc::event!(Cluster(ClusterEvent::SubscriberDisconnected));
                                    break;
                                }
                            },
                            _ = shutdown_rx.changed() => {
                                break 'subscribe;
                            }
                        }
                    }
                    if has_received || subscribed_at.elapsed() >= STABLE_SUBSCRIPTION {
                        retry_count = 0;
                        continue;
                    }
                }
                Err(err) => {
                    trc::event!(
                        Cluster(ClusterEvent::SubscriberError),
                        CausedBy = err,
                        Details = "Failed to subscribe to channel"
                    );
                }
            }

            match tokio::time::timeout(retry_delay(retry_count), shutdown_rx.changed()).await {
                Ok(_) => break,
                Err(_) => retry_count += 1,
            }
        }

        trc::event!(Cluster(ClusterEvent::SubscriberStop));
    });
}

fn retry_delay(retry_count: u32) -> Duration {
    (RETRY_INITIAL * 4 * (1 << retry_count.min(6)))
        .min(RETRY_MAX)
        .mul_f64(rand::rng().random_range(0.75..=1.0))
}

impl BroadcastReceiver {
    async fn catch_up(&self) {
        let inner = &self.inner;
        inner.build_server().invalidate_all_local_caches();
        inner.ipc.task_tx.notify(TaskTypes::ALL);
        inner.ipc.index_tx.notify_one();
        if inner.shared_core.load().network.roles.outbound_mta {
            let _ = inner
                .ipc
                .queue_tx
                .send(QueueEvent::Refresh(QueueRefresh::All))
                .await;
        }
    }

    async fn receive(&self, payload: &[u8]) {
        let mut batch = BroadcastBatch::new(payload);
        let node_id = match (batch.node_id(), batch.read_version()) {
            (Some(node_id), Some(read_version)) if node_id != self.node_id => {
                let core = self.inner.shared_core.load();
                match read_version {
                    Some(version) => core.storage.data.advance_read_snapshot(version),
                    None => core.storage.data.invalidate_read_snapshot(),
                }
                node_id
            }
            (Some(_), Some(_)) => {
                trc::event!(Cluster(ClusterEvent::MessageSkipped), Contents = payload);
                return;
            }
            _ => {
                trc::event!(Cluster(ClusterEvent::MessageInvalid), Contents = payload);
                return;
            }
        };

        loop {
            match batch.next_event() {
                Ok(Some(event)) => {
                    trc::event!(
                        Cluster(ClusterEvent::MessageReceived),
                        RemoteNodeId = node_id,
                        NodeId = self.node_id,
                        Contents = log_event(&event),
                    );
                    self.apply(event).await;
                    tokio::task::consume_budget().await;
                }
                Ok(None) => break,
                Err(_) => {
                    trc::event!(Cluster(ClusterEvent::MessageInvalid), Contents = payload);
                    break;
                }
            }
        }
    }

    async fn apply(&self, event: BroadcastEvent) {
        let inner = &self.inner;
        match event {
            BroadcastEvent::PushNotification(notification) => {
                inner.mark_caches_stale_for(&notification);
                inner.publish_push_notification(notification).await;
            }
            BroadcastEvent::PushServerUpdate(account_id) => {
                if inner
                    .ipc
                    .push_tx
                    .send(PushEvent::PushServerUpdate {
                        account_id,
                        broadcast: false,
                    })
                    .await
                    .is_err()
                {
                    trc::event!(
                        Server(ServerEvent::ThreadError),
                        Details = "Error sending reload request.",
                        CausedBy = trc::location!()
                    );
                }
            }
            BroadcastEvent::CacheInvalidate(changes) => {
                inner.build_server().invalidate_local_caches(&changes);
            }
            BroadcastEvent::CacheInvalidateAll => {
                inner.build_server().invalidate_all_local_caches();
            }
            BroadcastEvent::CacheInvalidateNegative => {
                inner.build_server().invalidate_all_local_negative_caches();
            }
            BroadcastEvent::MtaQueueStatus { is_running } => {
                let _ = inner
                    .ipc
                    .queue_tx
                    .send(QueueEvent::Paused(!is_running))
                    .await;
            }
            BroadcastEvent::QueueRefresh(queues) => {
                if inner.shared_core.load().network.roles.outbound_mta {
                    let _ = inner
                        .ipc
                        .queue_tx
                        .send(QueueEvent::Refresh(QueueRefresh::Queues(queues)))
                        .await;
                }
            }
            BroadcastEvent::TaskQueueRefresh(task_types) => {
                inner.ipc.task_tx.notify(task_types);
            }
            BroadcastEvent::IndexQueueRefresh => {
                inner.ipc.index_tx.notify_one();
            }
            BroadcastEvent::RegistryChange(change) => {
                if self.registry_tx.send(change).await.is_err() {
                    trc::event!(
                        Server(ServerEvent::ThreadError),
                        Details = "Error sending registry change.",
                        CausedBy = trc::location!()
                    );
                }
            }
        }
    }
}

fn spawn_registry_worker(inner: Arc<Inner>) -> mpsc::Sender<RegistryChange> {
    let (registry_tx, mut registry_rx) = mpsc::channel::<RegistryChange>(IPC_CHANNEL_BUFFER);

    tokio::spawn(async move {
        let mut changes = Vec::new();
        let mut applied = AHashSet::new();
        while registry_rx
            .recv_many(&mut changes, IPC_CHANNEL_BUFFER)
            .await
            > 0
        {
            for change in changes.drain(..) {
                if applied.insert(change) {
                    match inner.build_server().reload_registry(change).await {
                        Ok(result) => {
                            result.log();
                        }
                        Err(err) => {
                            trc::error!(
                                err.details("Failed to reload settings")
                                    .caused_by(trc::location!())
                            );
                        }
                    }
                }
            }
            applied.clear();
        }
    });

    registry_tx
}

fn log_event(event: &BroadcastEvent) -> trc::Value {
    match event {
        BroadcastEvent::PushNotification(notification) => match notification {
            PushNotification::StateChange(state_change) => trc::Value::Array(vec![
                "StateChange".into(),
                state_change.account_id.into(),
                state_change.change_id.into(),
                (*state_change.types.as_ref()).into(),
            ]),
            PushNotification::ViewerStateChange(viewer_change) => trc::Value::Array(vec![
                "ViewerStateChange".into(),
                viewer_change.change.account_id.into(),
                viewer_change.viewer_id.into(),
                viewer_change.change.change_id.into(),
                (*viewer_change.change.types.as_ref()).into(),
            ]),
            PushNotification::CalendarAlert(calendar_alert) => trc::Value::Array(vec![
                "CalendarAlert".into(),
                calendar_alert.account_id.into(),
                calendar_alert.event_id.into(),
                calendar_alert.recurrence_id.into(),
                calendar_alert.uid.clone().into(),
                calendar_alert.alert_id.clone().into(),
            ]),
            PushNotification::EmailPush(email_push) => trc::Value::Array(vec![
                "EmailPush".into(),
                email_push.account_id.into(),
                email_push.email_id.into(),
                email_push.change_id.into(),
            ]),
        },
        BroadcastEvent::PushServerUpdate(account_id) => {
            trc::Value::Array(vec!["PushServerUpdate".into(), (*account_id).into()])
        }
        BroadcastEvent::RegistryChange(change) => match change {
            RegistryChange::Insert(id) => trc::Value::Array(vec![
                "RegistryInsert".into(),
                id.object().as_str().into(),
                id.id().id().into(),
            ]),
            RegistryChange::Delete(id) => trc::Value::Array(vec![
                "RegistryDelete".into(),
                id.object().as_str().into(),
                id.id().id().into(),
            ]),
            RegistryChange::Reload(object) => {
                trc::Value::Array(vec!["RegistryReload".into(), object.as_str().into()])
            }
        },
        BroadcastEvent::CacheInvalidate(items) => {
            let mut array = Vec::with_capacity(items.len() + 1);
            array.push("CacheInvalidation".into());
            for item in items {
                array.push(format_compact!("{:?}", item).into());
            }
            trc::Value::Array(array)
        }
        BroadcastEvent::CacheInvalidateAll => "CacheInvalidateAll".into(),
        BroadcastEvent::CacheInvalidateNegative => "CacheInvalidateNegative".into(),
        BroadcastEvent::MtaQueueStatus { is_running } => {
            if *is_running {
                "MtaQueueRunning".into()
            } else {
                "MtaQueuePaused".into()
            }
        }
        BroadcastEvent::QueueRefresh(_) => "QueueRefresh".into(),
        BroadcastEvent::TaskQueueRefresh(_) => "TaskQueueRefresh".into(),
        BroadcastEvent::IndexQueueRefresh => "IndexQueueRefresh".into(),
    }
}
