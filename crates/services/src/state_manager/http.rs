/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Event, ece::ece_encrypt};
use crate::state_manager::PushRegistration;
use base64::Engine;
use calcard::jscalendar::JSCalendarDateTime;
use common::ipc::PushNotification;
use email::push::PushSubscription;
use jmap_proto::{
    response::status::{EmailPushObject, PushObject},
    types::state::State,
};
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use trc::PushSubscriptionEvent;
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

impl PushRegistration {
    pub fn send(&mut self, id: Id, push_tx: mpsc::Sender<Event>, push_timeout: Duration) {
        let server = self.server.clone();
        let notifications = std::mem::take(&mut self.notifications);

        self.in_flight = true;
        self.last_request = Instant::now();

        tokio::spawn(async move {
            let mut changed: VecMap<Id, VecMap<DataType, State>> = VecMap::new();
            let mut objects = Vec::with_capacity(notifications.len());
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
                        objects.push(PushObject::CalendarAlert {
                            account_id: calendar_alert.account_id.into(),
                            calendar_event_id: calendar_alert.event_id.into(),
                            uid: calendar_alert.uid.clone(),
                            recurrence_id: calendar_alert.recurrence_id.map(|timestamp| {
                                JSCalendarDateTime::new(timestamp, true).to_rfc3339()
                            }),
                            alert_id: calendar_alert.alert_id.clone(),
                        });
                    }
                    PushNotification::EmailPush(email_push) => {
                        objects.push(PushObject::EmailPush {
                            account_id: email_push.account_id.into(),
                            email: EmailPushObject {
                                subject: Default::default(),
                            },
                        });
                    }
                }
            }

            let response = if !objects.is_empty() {
                if changed.is_empty() {
                    objects.push(PushObject::StateChange { changed });
                }
                if objects.len() > 1 {
                    PushObject::Group { entries: objects }
                } else {
                    objects.into_iter().next().unwrap()
                }
            } else {
                PushObject::StateChange { changed }
            };

            push_tx
                .send(
                    if http_request(
                        &server,
                        serde_json::to_string(&response).unwrap(),
                        push_timeout,
                    )
                    .await
                    {
                        Event::DeliverySuccess { id }
                    } else {
                        Event::DeliveryFailure { id, notifications }
                    },
                )
                .await
                .ok();
        });
    }
}

pub(crate) async fn http_request(
    details: &PushSubscription,
    mut body: String,
    push_timeout: Duration,
) -> bool {
    let client_builder = reqwest::Client::builder().timeout(push_timeout);

    #[cfg(feature = "test_mode")]
    let client_builder = client_builder.danger_accept_invalid_certs(true);

    let mut client = client_builder
        .build()
        .unwrap_or_default()
        .post(details.url.as_str())
        .header(CONTENT_TYPE, "application/json")
        .header("TTL", "86400");

    if let Some(keys) = &details.keys {
        match ece_encrypt(&keys.p256dh, &keys.auth, body.as_bytes())
            .map(|b| base64::engine::general_purpose::URL_SAFE.encode(b))
        {
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
