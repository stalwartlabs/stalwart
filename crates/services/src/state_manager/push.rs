/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Event, http::http_request};
use crate::state_manager::PushRegistration;
use common::{
    IPC_CHANNEL_BUFFER, Inner, LONG_1Y_SLUMBER, Server,
    core::BuildServer,
    ipc::{PushEvent, PushNotification},
};
use email::push::PushSubscriptions;
use std::{
    collections::hash_map::Entry,
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{AlignedBytes, Archive, now},
};
use tokio::sync::mpsc;
use trc::{AddContext, PushSubscriptionEvent, ServerEvent};
use types::{collection::Collection, field::PrincipalField, id::Id};

pub fn spawn_push_manager(inner: Arc<Inner>) -> mpsc::Sender<Event> {
    let (push_tx_, mut push_rx) = mpsc::channel::<Event>(IPC_CHANNEL_BUFFER);
    let push_tx = push_tx_.clone();

    tokio::spawn(async move {});

    tokio::spawn(async move {
        let mut push_servers: AHashMap<Id, PushRegistration> = AHashMap::default();
        let mut account_push_ids: AHashMap<u32, AHashSet<Id>> = AHashMap::default();
        let mut last_verify: AHashMap<u32, Instant> = AHashMap::default();
        let mut last_retry = Instant::now();
        let mut retry_timeout = LONG_1Y_SLUMBER;
        let mut retry_ids = AHashSet::default();

        // Load active subscriptions on startup
        {
            let server = inner.build_server();

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
                        if server
                            .core
                            .network
                            .roles
                            .push_notifications
                            .is_enabled_for_integer(account_id)
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
                                        notifications: Vec::new(),
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

        loop {
            // Wait for the next event or timeout
            let event_or_timeout = tokio::time::timeout(retry_timeout, push_rx.recv()).await;

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
                        if !server
                            .core
                            .network
                            .roles
                            .push_notifications
                            .is_enabled_for_integer(account_id)
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
                                            notifications: Vec::new(),
                                            server: subscription.clone(),
                                            in_flight: false,
                                        });
                                    }
                                }
                            } else {
                                let current_time = Instant::now();

                                #[cfg(feature = "test_mode")]
                                if subscription.url.contains("skip_checks") {
                                    last_verify.insert(
                                        account_id,
                                        current_time
                                            - (push_verify_timeout + Duration::from_millis(1)),
                                    );
                                }

                                if last_verify
                                    .get(&account_id)
                                    .map(|last_verify| {
                                        current_time - *last_verify > push_verify_timeout
                                    })
                                    .unwrap_or(true)
                                {
                                    tokio::spawn(async move {
                                        http_request(
                                            &subscription,
                                            format!(
                                                concat!(
                                                    "{{\"@type\":\"PushVerification\",",
                                                    "\"pushSubscriptionId\":\"{}\",",
                                                    "\"verificationCode\":\"{}\"}}"
                                                ),
                                                Id::from(subscription.id),
                                                subscription.verification_code
                                            ),
                                            push_timeout,
                                        )
                                        .await;
                                    });

                                    last_verify.insert(account_id, current_time);
                                } else {
                                    trc::event!(
                                        PushSubscription(PushSubscriptionEvent::Error),
                                        Details = "Failed to verify push subscription",
                                        Url = subscription.url.clone(),
                                        AccountId = account_id,
                                        Reason = "Too many requests"
                                    );

                                    continue;
                                }
                            }
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
                                            // Build email push notification
                                            if let PushNotification::EmailPush(email_push) =
                                                &notification
                                            {
                                                if let Some(_email_push) = subscription
                                                    .server
                                                    .email_push
                                                    .iter()
                                                    .find(|ep| ep.account_id == account_id)
                                                {
                                                    // TODO: Apply filters once RFC is finalized
                                                } else {
                                                    notification = PushNotification::StateChange(
                                                        email_push.to_state_change(),
                                                    );
                                                }
                                            }

                                            subscription.notifications.push(notification);
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
                                                    push_tx.clone(),
                                                    push_timeout,
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
                    }
                    Event::DeliverySuccess { id } => {
                        if let Some(subscription) = push_servers.get_mut(&id) {
                            subscription.num_attempts = 0;
                            subscription.in_flight = false;
                            retry_ids.remove(&id);
                        }
                    }
                    Event::DeliveryFailure { id, notifications } => {
                        if let Some(subscription) = push_servers.get_mut(&id) {
                            subscription.last_request = Instant::now();
                            subscription.num_attempts += 1;
                            subscription.notifications.extend(notifications);
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
                    let mut remove_ids = Vec::with_capacity(retry_ids.len());

                    for retry_id in &retry_ids {
                        if let Some(subscription) = push_servers.get_mut(retry_id) {
                            let last_request = subscription.last_request.elapsed();

                            if !subscription.in_flight
                                && ((subscription.num_attempts == 0
                                    && last_request >= push_throttle)
                                    || (subscription.num_attempts > 0
                                        && last_request >= push_attempt_interval))
                            {
                                if subscription.num_attempts < push_attempts_max {
                                    subscription.send(*retry_id, push_tx.clone(), push_timeout);
                                } else {
                                    trc::event!(
                                        PushSubscription(PushSubscriptionEvent::Error),
                                        Details = "Failed to deliver push subscription",
                                        Url = subscription.server.url.clone(),
                                        Reason = "Too many failed attempts"
                                    );

                                    subscription.notifications.clear();
                                    subscription.num_attempts = 0;
                                }
                                remove_ids.push(*retry_id);
                            }
                        } else {
                            remove_ids.push(*retry_id);
                        }
                    }

                    if remove_ids.len() < retry_ids.len() {
                        for remove_id in remove_ids {
                            retry_ids.remove(&remove_id);
                        }
                        last_retry = Instant::now();
                        push_retry_interval
                    } else {
                        retry_ids.clear();
                        LONG_1Y_SLUMBER
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

async fn load_push_subscriptions(
    server: &Server,
    account_id: u32,
) -> trc::Result<(PushSubscriptions, Vec<u32>)> {
    let member_of = server
        .get_access_token(account_id)
        .await
        .caused_by(trc::location!())?
        .member_ids()
        .collect::<Vec<_>>();

    if let Some(push_subscriptions) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(ValueKey::property(
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
