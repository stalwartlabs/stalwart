/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Event,
    http::{build_push_client, http_request},
};
use crate::state_manager::{PushBatch, PushRegistration};
use common::{
    BuildServer, IPC_CHANNEL_BUFFER, Inner, LONG_1Y_SLUMBER, Server,
    auth::BuildAccessToken,
    ipc::{PushEvent, PushNotification},
};
use email::push::{PushSubscription, PushSubscriptions, Urgency};
use reqwest::Client;
use std::{
    collections::hash_map::Entry,
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{Archive, ArchiveBytes, now},
};
use tokio::sync::mpsc;
use trc::{AddContext, PushSubscriptionEvent, ServerEvent};
use types::{collection::Collection, field::PrincipalField, id::Id};

pub fn spawn_push_manager(inner: Arc<Inner>) -> mpsc::Sender<Event> {
    let (push_tx_, mut push_rx) = mpsc::channel::<Event>(IPC_CHANNEL_BUFFER);
    let push_tx = push_tx_.clone();

    tokio::spawn(async move {
        let mut push_servers: AHashMap<Id, PushRegistration> = AHashMap::default();
        let mut account_push_ids: AHashMap<u32, AHashSet<Id>> = AHashMap::default();
        let mut last_verify: AHashMap<u32, (Instant, u32)> = AHashMap::default();
        let mut pending_verify: AHashMap<u32, (Instant, Arc<PushSubscription>)> =
            AHashMap::default();
        let mut next_verify: Option<Instant> = None;
        let mut last_retry = Instant::now();
        let mut retry_timeout = LONG_1Y_SLUMBER;
        let mut retry_ids = AHashSet::default();
        let push_client = build_push_client();

        // Load active subscriptions on startup
        {
            let server = inner.build_server();

            if server.core.network.roles.push_notifications {
                match server
                    .document_ids(
                        u32::MAX,
                        Collection::Principal,
                        PrincipalField::PushSubscriptions,
                    )
                    .await
                {
                    Ok(account_ids) => {
                        for account_id in account_ids {
                            if server.core.jmap.push_total_shards <= 1
                                || account_id % server.core.jmap.push_total_shards
                                    == server.registry().cluster_push_shard()
                            {
                                // Load push subscriptions for account
                                let (subscriptions, member_account_ids) =
                                    match load_push_subscriptions(&server, account_id).await {
                                        Ok(subscriptions) => subscriptions,
                                        Err(err) => {
                                            trc::error!(err.caused_by(trc::location!()));
                                            continue;
                                        }
                                    };
                                let current_time = now();
                                for subscription in subscriptions
                                    .subscriptions
                                    .into_iter()
                                    .filter(|s| s.verified && s.expires > current_time)
                                {
                                    let id = Id::from_parts(subscription.id, account_id);
                                    let subscription = Arc::new(subscription);

                                    for account_id in &member_account_ids {
                                        account_push_ids.entry(*account_id).or_default().insert(id);
                                    }
                                    push_servers.insert(
                                        id,
                                        PushRegistration {
                                            member_account_ids: member_account_ids.clone(),
                                            num_attempts: 0,
                                            last_request: Instant::now()
                                                - (server.core.jmap.push_throttle
                                                    + Duration::from_millis(1)),
                                            pending: PushBatch::default(),
                                            server: subscription.clone(),
                                            in_flight: false,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    Err(err) => {
                        trc::error!(err.caused_by(trc::location!()));
                    }
                }

                // Subscribe to push events
                if !account_push_ids.is_empty()
                    && server
                        .inner
                        .ipc
                        .push_tx
                        .clone()
                        .send(PushEvent::PushServerRegister {
                            activate: account_push_ids.keys().copied().collect(),
                            expired: vec![],
                        })
                        .await
                        .is_err()
                {
                    trc::event!(
                        Server(ServerEvent::ThreadError),
                        Details = "Error sending state change.",
                        CausedBy = trc::location!()
                    );
                }
            }
        }

        loop {
            if let Some(verify_due) = next_verify {
                let current_instant = Instant::now();
                if verify_due <= current_instant {
                    let server = inner.build_server();
                    let push_timeout = server.core.jmap.push_timeout;
                    let current_time = now();
                    next_verify = None;
                    pending_verify.retain(|account_id, (verify_due, subscription)| {
                        if *verify_due > current_instant {
                            next_verify =
                                Some(next_verify.map_or(*verify_due, |next| next.min(*verify_due)));
                            true
                        } else {
                            if subscription.expires > current_time {
                                last_verify.insert(*account_id, (current_instant, subscription.id));
                                send_verification(
                                    &push_client,
                                    subscription.clone(),
                                    &server,
                                    push_timeout,
                                );
                            }
                            false
                        }
                    });
                }
            }

            // Wait for the next event or timeout
            let wait_timeout = next_verify.map_or(retry_timeout, |verify_due| {
                retry_timeout.min(verify_due.saturating_duration_since(Instant::now()))
            });
            let event_or_timeout = tokio::time::timeout(wait_timeout, push_rx.recv()).await;

            // Load settings
            let server = inner.build_server();
            let push_attempt_interval = server.core.jmap.push_attempt_interval;
            let push_attempts_max = server.core.jmap.push_attempts_max;
            let push_retry_interval = server.core.jmap.push_retry_interval;
            let push_timeout = server.core.jmap.push_timeout;
            let push_verify_timeout = server.core.jmap.push_verify_timeout;
            let push_throttle = server.core.jmap.push_throttle;

            match event_or_timeout {
                Ok(Some(event)) => match event {
                    Event::Update { account_id } => {
                        if server.core.jmap.push_total_shards > 1
                            && account_id % server.core.jmap.push_total_shards
                                != server.registry().cluster_push_shard()
                        {
                            continue;
                        }

                        // Load push subscriptions for account
                        let (subscriptions, member_account_ids) =
                            match load_push_subscriptions(&server, account_id).await {
                                Ok(subscriptions) => subscriptions,
                                Err(err) => {
                                    trc::error!(err.caused_by(trc::location!()));
                                    continue;
                                }
                            };
                        let old_account_push_ids = account_push_ids
                            .remove(&account_id)
                            .filter(|v| !v.is_empty());

                        // Process subscriptions
                        let current_time = now();
                        let mut newest_unverified: Option<Arc<PushSubscription>> = None;
                        for subscription in subscriptions
                            .subscriptions
                            .into_iter()
                            .filter(|s| s.expires > current_time)
                        {
                            let id = Id::from_parts(subscription.id, account_id);
                            let subscription = Arc::new(subscription);

                            if subscription.verified {
                                for account_id in &member_account_ids {
                                    account_push_ids.entry(*account_id).or_default().insert(id);
                                }

                                match push_servers.entry(id) {
                                    Entry::Occupied(mut entry) => {
                                        // Update existing subscription
                                        let entry = entry.get_mut();
                                        entry.server = subscription.clone();
                                        entry.member_account_ids = member_account_ids.clone();
                                    }
                                    Entry::Vacant(entry) => {
                                        entry.insert(PushRegistration {
                                            member_account_ids: member_account_ids.clone(),
                                            num_attempts: 0,
                                            last_request: Instant::now()
                                                - (push_throttle + Duration::from_millis(1)),
                                            pending: PushBatch::default(),
                                            server: subscription.clone(),
                                            in_flight: false,
                                        });
                                    }
                                }
                            } else {
                                match &newest_unverified {
                                    Some(existing) if existing.id >= subscription.id => {}
                                    _ => newest_unverified = Some(subscription),
                                }
                            }
                        }

                        if let Some(subscription) = newest_unverified {
                            let current_time = Instant::now();

                            #[cfg(feature = "test_mode")]
                            if subscription.url.contains("skip_checks") {
                                last_verify.remove(&account_id);
                            }

                            match last_verify
                                .get(&account_id)
                                .map(|(verified_at, verified_id)| {
                                    (*verified_at + push_verify_timeout, *verified_id)
                                })
                                .filter(|(verify_due, _)| *verify_due >= current_time)
                            {
                                None => {
                                    last_verify.retain(|_, (verified_at, _)| {
                                        current_time.duration_since(*verified_at)
                                            <= push_verify_timeout
                                    });
                                    last_verify.insert(account_id, (current_time, subscription.id));
                                    pending_verify.remove(&account_id);
                                    send_verification(
                                        &push_client,
                                        subscription,
                                        &server,
                                        push_timeout,
                                    );
                                }
                                Some((_, verified_id)) if verified_id == subscription.id => {
                                    trc::event!(
                                        PushSubscription(PushSubscriptionEvent::Error),
                                        Details = "Failed to verify push subscription",
                                        Url = subscription.url.clone(),
                                        AccountId = account_id,
                                        Reason = "Too many requests"
                                    );
                                    pending_verify.remove(&account_id);
                                }
                                Some((verify_due, _)) => {
                                    trc::event!(
                                        PushSubscription(PushSubscriptionEvent::Error),
                                        Details = "Push subscription verification deferred",
                                        Url = subscription.url.clone(),
                                        AccountId = account_id,
                                        Reason = "Too many requests"
                                    );
                                    next_verify = Some(
                                        next_verify.map_or(verify_due, |next| next.min(verify_due)),
                                    );
                                    pending_verify.insert(account_id, (verify_due, subscription));
                                }
                            }
                        } else {
                            pending_verify.remove(&account_id);
                        }

                        // Update subscriptions
                        let mut remove_push_ids = AHashSet::new();
                        let mut active_account_ids = Vec::new();
                        let mut inactive_account_ids = Vec::new();
                        match (old_account_push_ids, account_push_ids.get(&account_id)) {
                            (Some(old), Some(current)) if &old != current => {
                                for id in old.difference(current) {
                                    remove_push_ids.insert(*id);
                                }
                                active_account_ids = member_account_ids;
                            }
                            (Some(old), None) => {
                                remove_push_ids = old;
                            }
                            (None, Some(_)) => {
                                active_account_ids = member_account_ids;
                            }
                            _ => {}
                        }

                        // Update push server registrations
                        if !remove_push_ids.is_empty() {
                            for id in remove_push_ids {
                                if let Some(subscription) = push_servers.remove(&id) {
                                    for account_id in &subscription.member_account_ids {
                                        if let Some(ids) = account_push_ids.get_mut(account_id) {
                                            ids.remove(&id);
                                            if ids.is_empty() {
                                                account_push_ids.remove(account_id);
                                                inactive_account_ids.push(*account_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (!active_account_ids.is_empty() || !inactive_account_ids.is_empty())
                            && server
                                .inner
                                .ipc
                                .push_tx
                                .clone()
                                .send(PushEvent::PushServerRegister {
                                    activate: active_account_ids,
                                    expired: inactive_account_ids,
                                })
                                .await
                                .is_err()
                        {
                            trc::event!(
                                Server(ServerEvent::ThreadError),
                                Details = "Error sending state change.",
                                CausedBy = trc::location!()
                            );
                        }
                    }
                    Event::Push { notification } => {
                        let account_id = notification.account_id();
                        if let Some(ids) = account_push_ids.get_mut(&account_id) {
                            let current_time = now();
                            let mut remove_ids = Vec::new();

                            for id in ids.iter() {
                                if let Some(subscription) = push_servers.get_mut(id) {
                                    if subscription.server.expires > current_time {
                                        if let Some(mut notification) =
                                            notification.filter_types(&subscription.server.types)
                                        {
                                            if let PushNotification::EmailPush(email_push) =
                                                &notification
                                                && !subscription
                                                    .server
                                                    .email_push
                                                    .iter()
                                                    .any(|ep| ep.account_id == account_id)
                                            {
                                                notification = PushNotification::StateChange(
                                                    email_push.to_state_change(),
                                                );
                                            }

                                            subscription.pending.push(notification);
                                            let last_request = subscription.last_request.elapsed();

                                            if !subscription.in_flight
                                                && ((subscription.num_attempts == 0
                                                    && last_request > push_throttle)
                                                    || ((1..push_attempts_max)
                                                        .contains(&subscription.num_attempts)
                                                        && last_request > push_attempt_interval))
                                            {
                                                subscription.send(
                                                    *id,
                                                    &push_client,
                                                    push_tx.clone(),
                                                    push_timeout,
                                                    server.clone(),
                                                );
                                                retry_ids.remove(id);
                                            } else {
                                                retry_ids.insert(*id);
                                            }
                                        }
                                    } else {
                                        push_servers.remove(id);
                                    }
                                } else {
                                    remove_ids.push(*id);
                                }
                            }

                            if !remove_ids.is_empty() {
                                for remove_id in remove_ids {
                                    ids.remove(&remove_id);
                                }
                                if ids.is_empty() {
                                    account_push_ids.remove(&account_id);
                                    if server
                                        .inner
                                        .ipc
                                        .push_tx
                                        .clone()
                                        .send(PushEvent::PushServerRegister {
                                            activate: vec![],
                                            expired: vec![account_id],
                                        })
                                        .await
                                        .is_err()
                                    {
                                        trc::event!(
                                            Server(ServerEvent::ThreadError),
                                            Details = "Error sending state change.",
                                            CausedBy = trc::location!()
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Event::Reset => {
                        push_servers.clear();
                        account_push_ids.clear();
                        pending_verify.clear();
                        next_verify = None;
                    }
                    Event::DeliverySuccess { id } => {
                        if let Some(subscription) = push_servers.get_mut(&id) {
                            subscription.num_attempts = 0;
                            subscription.in_flight = false;
                            if subscription.pending.is_empty() {
                                retry_ids.remove(&id);
                            } else {
                                retry_ids.insert(id);
                            }
                        }
                    }
                    Event::DeliveryFailure { id, failed } => {
                        if let Some(subscription) = push_servers.get_mut(&id) {
                            subscription.last_request = Instant::now();
                            subscription.num_attempts += 1;
                            subscription.pending.merge_failed(failed);
                            subscription.in_flight = false;
                            retry_ids.insert(id);
                        }
                    }
                },
                Ok(None) => {
                    break;
                }
                Err(_) => (),
            }

            retry_timeout = if !retry_ids.is_empty() {
                let last_retry_elapsed = last_retry.elapsed();

                if last_retry_elapsed >= push_retry_interval {
                    retry_ids.retain(|retry_id| {
                        let Some(subscription) = push_servers.get_mut(retry_id) else {
                            return false;
                        };
                        let last_request = subscription.last_request.elapsed();
                        let is_due = !subscription.in_flight
                            && ((subscription.num_attempts == 0 && last_request >= push_throttle)
                                || (subscription.num_attempts > 0
                                    && last_request >= push_attempt_interval));
                        if !is_due {
                            return true;
                        }

                        if subscription.num_attempts < push_attempts_max {
                            subscription.send(
                                *retry_id,
                                &push_client,
                                push_tx.clone(),
                                push_timeout,
                                server.clone(),
                            );
                        } else {
                            trc::event!(
                                PushSubscription(PushSubscriptionEvent::Error),
                                Details = "Failed to deliver push subscription",
                                Url = subscription.server.url.clone(),
                                Reason = "Too many failed attempts"
                            );

                            subscription.pending.clear();
                            subscription.num_attempts = 0;
                        }
                        false
                    });

                    if retry_ids.is_empty() {
                        LONG_1Y_SLUMBER
                    } else {
                        last_retry = Instant::now();
                        push_retry_interval
                    }
                } else {
                    push_retry_interval - last_retry_elapsed
                }
            } else {
                LONG_1Y_SLUMBER
            };
        }
    });

    push_tx_
}

fn send_verification(
    push_client: &Client,
    subscription: Arc<PushSubscription>,
    server: &Server,
    push_timeout: Duration,
) {
    let core = server.core.clone();
    let push_client = push_client.clone();
    tokio::spawn(async move {
        http_request(
            &push_client,
            &subscription,
            format!(
                concat!(
                    "{{\"@type\":\"PushVerification\",",
                    "\"pushSubscriptionId\":\"{}\",",
                    "\"verificationCode\":\"{}\"}}"
                ),
                Id::from(subscription.id),
                subscription.verification_code
            )
            .into_bytes(),
            push_timeout,
            core.jmap.vapid.as_ref(),
            Urgency::Normal,
        )
        .await;
    });
}

async fn load_push_subscriptions(
    server: &Server,
    account_id: u32,
) -> trc::Result<(PushSubscriptions, Vec<u32>)> {
    let member_of = server
        .access_token(account_id)
        .await
        .caused_by(trc::location!())?
        .build()
        .member_ids()
        .collect::<Vec<_>>();

    if let Some(push_subscriptions) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::Principal,
            0,
            PrincipalField::PushSubscriptions,
        ))
        .await?
    {
        push_subscriptions
            .deserialize::<PushSubscriptions>()
            .map(|push_subscriptions| (push_subscriptions, member_of))
            .caused_by(trc::location!())
    } else {
        Ok((PushSubscriptions::default(), member_of))
    }
}
