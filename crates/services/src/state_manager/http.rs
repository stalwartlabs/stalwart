/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Event, ece::ece_encrypt, email_push::build_email_push_object};
use crate::state_manager::PushRegistration;
use calcard::jscalendar::JSCalendarDateTime;
use common::{Server, ipc::PushNotification, network::webpush::Vapid};
use email::push::{PushSubscription, Urgency};
use jmap_proto::{
    object::email::{EmailProperty, EmailValue},
    response::status::PushObject,
    types::state::State,
};
use jmap_tools::Value;
use reqwest::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use std::time::{Duration, Instant};
use store::write::now;
use tokio::sync::mpsc;
use trc::PushSubscriptionEvent;
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

#[derive(Default)]
struct EmailPushObject {
    emails: Vec<Value<'static, EmailProperty, EmailValue>>,
    change_id: Option<u64>,
    urgency: Urgency,
}

impl PushRegistration {
    pub fn send(
        &mut self,
        id: Id,
        push_tx: mpsc::Sender<Event>,
        push_timeout: Duration,
        server: Server,
    ) {
        let subscription = self.server.clone();
        let notifications = std::mem::take(&mut self.notifications);

        self.in_flight = true;
        self.last_request = Instant::now();

        tokio::spawn(async move {
            let mut changed: VecMap<Id, VecMap<DataType, State>> = VecMap::new();
            let mut email_pushes: VecMap<Id, EmailPushObject> = VecMap::new();

            let mut failed_state_change = false;
            let mut failed_email_pushes = Vec::new();
            let mut failed_calendar_alerts = Vec::new();

            for notification in &notifications {
                match notification {
                    PushNotification::StateChange(state_change) => {
                        for type_state in state_change.types {
                            changed
                                .get_mut_or_insert(state_change.account_id.into())
                                .set(type_state, (state_change.change_id).into());
                        }
                    }
                    PushNotification::CalendarAlert(calendar_alert) => {
                        let payload = PushObject::CalendarAlert {
                            account_id: calendar_alert.account_id.into(),
                            calendar_event_id: calendar_alert.event_id.into(),
                            uid: calendar_alert.uid.clone(),
                            recurrence_id: calendar_alert.recurrence_id.map(|timestamp| {
                                JSCalendarDateTime::new(timestamp, true).to_rfc3339()
                            }),
                            alert_id: calendar_alert.alert_id.clone(),
                        };
                        if !http_request(
                            &subscription,
                            serde_json::to_string(&payload).unwrap().into_bytes(),
                            push_timeout,
                            server.core.jmap.vapid.as_ref(),
                            Urgency::Normal,
                        )
                        .await
                        {
                            failed_calendar_alerts
                                .push((calendar_alert.account_id, calendar_alert.event_id));
                        }
                    }
                    PushNotification::EmailPush(email_push) => {
                        if let Some(config) = subscription
                            .email_push
                            .iter()
                            .find(|config| config.account_id == email_push.account_id)
                        {
                            match build_email_push_object(
                                &server,
                                email_push.account_id,
                                email_push.email_id,
                                config,
                                server.core.jmap.push_max_size,
                            )
                            .await
                            {
                                Ok(Some(object)) => {
                                    let emails = email_pushes
                                        .get_mut_or_insert(email_push.account_id.into());
                                    emails.urgency = config.urgency;
                                    if emails
                                        .change_id
                                        .is_none_or(|change_id| email_push.change_id > change_id)
                                    {
                                        emails.change_id = Some(email_push.change_id);
                                    }
                                    emails.emails.push(object);
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    trc::error!(
                                        err.details(
                                            "Failed to build EmailPush notification object."
                                        )
                                    );
                                    failed_email_pushes.push(email_push.account_id);
                                }
                            }
                        }
                    }
                }
            }

            if !changed.is_empty() {
                failed_state_change = !http_request(
                    &subscription,
                    serde_json::to_string(&PushObject::StateChange { changed })
                        .unwrap()
                        .into_bytes(),
                    push_timeout,
                    server.core.jmap.vapid.as_ref(),
                    Urgency::Normal,
                )
                .await;
            }

            for (account_id, email_push) in email_pushes {
                let payload = PushObject::EmailPush {
                    account_id,
                    emails: email_push.emails,
                    state: email_push.change_id.map(State::from),
                };

                if !http_request(
                    &subscription,
                    serde_json::to_string(&payload).unwrap().into_bytes(),
                    push_timeout,
                    server.core.jmap.vapid.as_ref(),
                    email_push.urgency,
                )
                .await
                {
                    failed_email_pushes.push(account_id.document_id());
                }
            }

            let result = if !failed_state_change
                && failed_email_pushes.is_empty()
                && failed_calendar_alerts.is_empty()
            {
                Event::DeliverySuccess { id }
            } else {
                let mut failed_notifications = Vec::with_capacity(
                    failed_state_change as usize
                        + failed_email_pushes.len()
                        + failed_calendar_alerts.len(),
                );

                for notification in notifications {
                    match &notification {
                        PushNotification::StateChange(_) => {
                            if failed_state_change {
                                failed_notifications.push(notification);
                            }
                        }
                        PushNotification::EmailPush(email_push) => {
                            if failed_email_pushes.contains(&email_push.account_id) {
                                failed_notifications.push(notification);
                            }
                        }
                        PushNotification::CalendarAlert(calendar_alert) => {
                            if failed_calendar_alerts
                                .contains(&(calendar_alert.account_id, calendar_alert.event_id))
                            {
                                failed_notifications.push(notification);
                            }
                        }
                    }
                }

                Event::DeliveryFailure {
                    id,
                    notifications: failed_notifications,
                }
            };

            push_tx.send(result).await.ok();
        });
    }
}

pub(crate) async fn http_request(
    details: &PushSubscription,
    mut body: Vec<u8>,
    push_timeout: Duration,
    vapid: Option<&Vapid>,
    urgency: Urgency,
) -> bool {
    let client_builder = reqwest::Client::builder().timeout(push_timeout);

    #[cfg(feature = "test_mode")]
    let client_builder = client_builder.danger_accept_invalid_certs(true);

    let mut client = client_builder
        .build()
        .unwrap_or_default()
        .post(details.url.as_str())
        .header(CONTENT_TYPE, "application/json")
        .header("TTL", "86400")
        .header("Urgency", urgency.as_str());

    if let Some(authorization) = vapid.and_then(|vapid| vapid.authorization(&details.url, now())) {
        client = client.header(AUTHORIZATION, authorization);
    }

    if let Some(keys) = &details.keys {
        match ece_encrypt(&keys.p256dh, &keys.auth, &body) {
            Ok(body_) => {
                body = body_;
                client = client.header(CONTENT_ENCODING, "aes128gcm");
            }
            Err(err) => {
                // Do not reattempt if encryption fails.

                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Error),
                    Details = "Failed to encrypt push subscription",
                    Url = details.url.to_string(),
                    Reason = err
                );
                return true;
            }
        }
    }

    match client.body(body).send().await {
        Ok(response) => {
            if response.status().is_success() {
                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Success),
                    Url = details.url.to_string()
                );

                true
            } else {
                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Error),
                    Details = "HTTP POST failed",
                    Url = details.url.to_string(),
                    Code = response.status().as_u16(),
                );

                false
            }
        }
        Err(err) => {
            trc::event!(
                PushSubscription(PushSubscriptionEvent::Error),
                Details = "HTTP POST failed",
                Url = details.url.to_string(),
                Reason = err.to_string()
            );

            false
        }
    }
}
