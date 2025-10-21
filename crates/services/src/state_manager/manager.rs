/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Event, PURGE_EVERY, SEND_TIMEOUT, push::spawn_push_manager};
use crate::state_manager::IpcSubscriber;
use common::{
    Inner,
    ipc::{BroadcastEvent, PushEvent},
};
use std::{sync::Arc, time::Instant};
use store::ahash::AHashMap;
use tokio::sync::mpsc;
use trc::ServerEvent;

#[derive(Default)]
struct Subscriber {
    ipc: Vec<IpcSubscriber>,
    is_push: bool,
}

#[allow(clippy::unwrap_or_default)]
pub fn spawn_push_router(inner: Arc<Inner>, mut change_rx: mpsc::Receiver<PushEvent>) {
    let push_tx = spawn_push_manager(inner.clone());

    tokio::spawn(async move {
        let mut subscribers: AHashMap<u32, Subscriber> = AHashMap::default();
        let mut last_purge = Instant::now();

        while let Some(event) = change_rx.recv().await {
            let mut purge_needed = last_purge.elapsed() >= PURGE_EVERY;

            match event {
                PushEvent::Stop => {
                    if push_tx.send(Event::Reset).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push reset.",
                            CausedBy = trc::location!()
                        );
                    }
                    break;
                }

                PushEvent::Subscribe {
                    account_ids,
                    types,
                    tx,
                } => {
                    for account_id in account_ids {
                        subscribers
                            .entry(account_id)
                            .or_default()
                            .ipc
                            .push(IpcSubscriber {
                                types,
                                tx: tx.clone(),
                            });
                    }
                }

                PushEvent::PushServerRegister { activate, expired } => {
                    for account_id in activate {
                        subscribers.entry(account_id).or_default().is_push = true;
                    }

                    for account_id in expired {
                        let mut remove_account = false;
                        if let Some(subscriber_list) = subscribers.get_mut(&account_id) {
                            subscriber_list.is_push = false;
                            remove_account = subscriber_list.ipc.is_empty();
                        }
                        if remove_account {
                            subscribers.remove(&account_id);
                        }
                    }
                }

                PushEvent::Publish {
                    notification,
                    broadcast,
                } => {
                    // Publish event to cluster
                    if broadcast
                        && let Some(broadcast_tx) = &inner.ipc.broadcast_tx.clone()
                        && broadcast_tx
                            .send(BroadcastEvent::PushNotification(notification.clone()))
                            .await
                            .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending broadcast event.",
                            CausedBy = trc::location!()
                        );
                    }

                    let account_id = notification.account_id();
                    if let Some(subscribers) = subscribers.get(&account_id) {
                        for subscriber in &subscribers.ipc {
                            if let Some(notification) = notification.filter_types(&subscriber.types)
                            {
                                if subscriber.is_valid() {
                                    let subscriber_tx = subscriber.tx.clone();

                                    tokio::spawn(async move {
                                        // Timeout after 500ms in case there is a blocked client
                                        if subscriber_tx
                                            .send_timeout(notification, SEND_TIMEOUT)
                                            .await
                                            .is_err()
                                        {
                                            trc::event!(
                                                Server(ServerEvent::ThreadError),
                                                Details =
                                                    "Error sending state change to subscriber.",
                                                CausedBy = trc::location!()
                                            );
                                        }
                                    });
                                } else {
                                    purge_needed = true;
                                }
                            }
                        }

                        if subscribers.is_push
                            && push_tx.send(Event::Push { notification }).await.is_err()
                        {
                            trc::event!(
                                Server(ServerEvent::ThreadError),
                                Details = "Error sending push updates.",
                                CausedBy = trc::location!()
                            );
                        }
                    }
                }

                PushEvent::PushServerUpdate {
                    account_id,
                    broadcast,
                } => {
                    // Publish event to cluster
                    if broadcast
                        && let Some(broadcast_tx) = &inner.ipc.broadcast_tx.clone()
                        && broadcast_tx
                            .send(BroadcastEvent::ReloadPushServers(account_id))
                            .await
                            .is_err()
                    {
                        trc::event!(
                            Server(trc::ServerEvent::ThreadError),
                            Details = "Error sending broadcast event.",
                            CausedBy = trc::location!()
                        );
                    }

                    // Notify push manager
                    if push_tx.send(Event::Update { account_id }).await.is_err() {
                        trc::event!(
                            Server(ServerEvent::ThreadError),
                            Details = "Error sending push updates.",
                            CausedBy = trc::location!()
                        );
                    }
                }
            }

            if purge_needed {
                let mut remove_account_ids = Vec::new();

                for (account_id, subscribers) in &mut subscribers {
                    subscribers.ipc.retain(|subscriber| subscriber.is_valid());

                    if subscribers.ipc.is_empty() && !subscribers.is_push {
                        remove_account_ids.push(*account_id);
                    }
                }

                for remove_account_id in remove_account_ids {
                    subscribers.remove(&remove_account_id);
                }

                last_purge = Instant::now();
            }
        }
    });
}
