/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::broadcast::{BROADCAST_TOPIC, BroadcastBatch};
use common::{
    Inner,
    core::BuildServer,
    ipc::{BroadcastEvent, HousekeeperEvent, PushEvent, PushNotification},
};
use compact_str::CompactString;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use trc::{ClusterEvent, ServerEvent};

pub fn spawn_broadcast_subscriber(inner: Arc<Inner>, mut shutdown_rx: watch::Receiver<bool>) {
    let this_node_id = {
        let _core = inner.shared_core.load();
        if _core.storage.pubsub.is_none() {
            return;
        }
        _core.network.node_id as u16
    };

    tokio::spawn(async move {
        let mut retry_count = 0;

        trc::event!(Cluster(ClusterEvent::SubscriberStart));

        loop {
            let pubsub = inner.shared_core.load().storage.pubsub.clone();
            if pubsub.is_none() {
                trc::event!(
                    Cluster(ClusterEvent::SubscriberError),
                    Details = "PubSub is no longer configured"
                );
                break;
            }

            let mut stream = match pubsub.subscribe(BROADCAST_TOPIC).await {
                Ok(stream) => {
                    retry_count = 0;
                    stream
                }
                Err(err) => {
                    trc::event!(
                        Cluster(ClusterEvent::SubscriberError),
                        CausedBy = err,
                        Details = "Failed to subscribe to channel"
                    );

                    match tokio::time::timeout(
                        Duration::from_secs(1 << retry_count.max(6)),
                        shutdown_rx.changed(),
                    )
                    .await
                    {
                        Ok(_) => {
                            break;
                        }
                        Err(_) => {
                            retry_count += 1;
                            continue;
                        }
                    }
                }
            };

            tokio::select! {
                message = stream.next() => {
                    match message {
                        Some(message) => {
                            let mut batch = BroadcastBatch::new(message.payload().iter());
                            let node_id = match batch.node_id() {
                                Some(node_id) => {
                                    if node_id != this_node_id {
                                        node_id
                                    } else {
                                        trc::event!(
                                            Cluster(ClusterEvent::MessageSkipped),
                                            Details = message.payload()
                                        );
                                        continue;
                                    }
                                }
                                None => {
                                    trc::event!(
                                        Cluster(ClusterEvent::MessageInvalid),
                                        Details = message.payload()
                                    );
                                    continue;
                                }
                            };

                            loop {
                                match batch.next_event() {
                                    Ok(Some(event)) => {
                                        trc::event!(
                                            Cluster(ClusterEvent::MessageReceived),
                                            From = node_id,
                                            To = this_node_id,
                                            Details = log_event(&event),
                                        );
                                        match event {
                                            BroadcastEvent::PushNotification(notification) => {
                                                if inner
                                                    .ipc
                                                    .push_tx
                                                    .send(PushEvent::Publish {
                                                        notification,
                                                        broadcast: false,
                                                    })
                                                    .await
                                                    .is_err()
                                                {
                                                    trc::event!(
                                                        Server(ServerEvent::ThreadError),
                                                        Details = "Error sending push notification.",
                                                        CausedBy = trc::location!()
                                                    );
                                                }
                                            }
                                            BroadcastEvent::ReloadPushServers(account_id) => {
                                                if inner
                                                    .ipc
                                                    .push_tx
                                                    .send(PushEvent::PushServerUpdate { account_id, broadcast: false })
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
                                            BroadcastEvent::InvalidateAccessTokens(ids) => {
                                                for id in &ids {
                                                    inner.cache.permissions.remove(id);
                                                    inner.cache.access_tokens.remove(id);
                                                }
                                            }
                                            BroadcastEvent::InvalidateGroupwareCache(ids) => {
                                                for id in &ids {
                                                    inner.cache.files.remove(id);
                                                    inner.cache.contacts.remove(id);
                                                    inner.cache.events.remove(id);
                                                    inner.cache.scheduling.remove(id);
                                                }
                                            }
                                            BroadcastEvent::ReloadSettings => {
                                                match inner.build_server().reload().await {
                                                    Ok(result) => {
                                                        if let Some(new_core) = result.new_core {
                                                            // Update core
                                                            inner.shared_core.store(new_core.into());

                                                            if inner
                                                                .ipc
                                                                .housekeeper_tx
                                                                .send(HousekeeperEvent::ReloadSettings)
                                                                .await
                                                                .is_err()
                                                            {
                                                                trc::event!(
                                                                    Server(trc::ServerEvent::ThreadError),
                                                                    Details = "Failed to send setting reload event to housekeeper",
                                                                    CausedBy = trc::location!(),
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Err(err) => {
                                                        trc::error!(
                                                            err.details("Failed to reload settings")
                                                                .caused_by(trc::location!())
                                                        );
                                                    }
                                                }
                                            }
                                            BroadcastEvent::ReloadBlockedIps => {
                                                if let Err(err) = inner.build_server().reload_blocked_ips().await {
                                                    trc::error!(
                                                        err.details("Failed to reload settings")
                                                            .caused_by(trc::location!())
                                                    );
                                                }
                                            }
                                            BroadcastEvent::ReloadSpamFilter => {
                                                if let Err(err) = inner.build_server().spam_model_reload().await {
                                                    trc::error!(
                                                        err.details("Failed to reload spam filter model")
                                                            .caused_by(trc::location!())
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(_) => {
                                        trc::event!(
                                            Cluster(ClusterEvent::MessageInvalid),
                                            Details = message.payload()
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        None => {
                            trc::event!(
                                Cluster(ClusterEvent::SubscriberDisconnected),
                            );
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    break;
                }
            };
        }

        trc::event!(Cluster(ClusterEvent::SubscriberStop));
    });
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
        BroadcastEvent::ReloadSettings => CompactString::const_new("ReloadSettings").into(),
        BroadcastEvent::ReloadBlockedIps => CompactString::const_new("ReloadBlockedIps").into(),
        BroadcastEvent::InvalidateAccessTokens(items) => {
            let mut array = Vec::with_capacity(items.len() + 1);
            array.push("InvalidateAccessTokens".into());
            for item in items {
                array.push((*item).into());
            }
            trc::Value::Array(array)
        }
        BroadcastEvent::InvalidateGroupwareCache(items) => {
            let mut array = Vec::with_capacity(items.len() + 1);
            array.push("InvalidateGroupwareCache".into());
            for item in items {
                array.push((*item).into());
            }
            trc::Value::Array(array)
        }
        BroadcastEvent::ReloadPushServers(account_id) => {
            trc::Value::Array(vec!["ReloadPushServers".into(), (*account_id).into()])
        }
        BroadcastEvent::ReloadSpamFilter => CompactString::const_new("ReloadSpamFilter").into(),
    }
}
