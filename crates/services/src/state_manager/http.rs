/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Event,
    ece::{ECE_WEBPUSH_MAX_PLAINTEXT_SIZE, WEBPUSH_MAX_BODY_SIZE, ece_encrypt},
    email_push::build_email_push_object,
};
use crate::state_manager::{PushBatch, PushRegistration};
use calcard::jscalendar::JSCalendarDateTime;
use common::{Server, ipc::PushNotification, network::webpush::Vapid};
use compact_str::{CompactString, ToCompactString};
use email::push::{PushSubscription, Urgency};
use jmap_proto::{
    object::email::{EmailProperty, EmailValue},
    response::status::PushObject,
    types::state::State,
};
use jmap_tools::Value;
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
    redirect::Policy,
};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use store::write::now;
use tokio::sync::mpsc;
use trc::PushSubscriptionEvent;
use types::id::Id;
use utils::map::vec_map::VecMap;

const MAX_ERROR_RESPONSE_LEN: usize = 1024;
const MAX_REDIRECTS: usize = 4;
const PUSH_OBJECT_OVERHEAD: usize = 128;

#[derive(Default)]
struct EmailPushObject {
    emails: Vec<Value<'static, EmailProperty, EmailValue>>,
    change_id: Option<u64>,
    urgency: Urgency,
    used: usize,
}

impl PushRegistration {
    pub fn send(
        &mut self,
        id: Id,
        push_client: &Client,
        push_tx: mpsc::Sender<Event>,
        push_timeout: Duration,
        server: Server,
    ) {
        let subscription = self.server.clone();
        let push_client = push_client.clone();
        let batch = std::mem::take(&mut self.pending);

        self.in_flight = true;
        self.last_request = Instant::now();

        tokio::spawn(async move {
            let vapid = server.core.jmap.vapid.as_ref();
            let mut email_pushes: VecMap<Id, EmailPushObject> = VecMap::new();

            let mut failed = PushBatch::default();
            let mut failed_email_pushes = Vec::new();
            let mut failed_calendar_alerts = Vec::new();

            for notification in &batch.notifications {
                match notification {
                    PushNotification::StateChange(_) => {}
                    PushNotification::CalendarAlert(calendar_alert) => {
                        let payload = PushObject::CalendarAlert {
                            account_id: calendar_alert.event_account_id.into(),
                            calendar_event_id: calendar_alert.event_id.into(),
                            uid: calendar_alert.uid.clone(),
                            recurrence_id: calendar_alert.recurrence_id.map(|timestamp| {
                                JSCalendarDateTime::new(timestamp, true).to_rfc3339()
                            }),
                            alert_id: calendar_alert.alert_id.clone(),
                        };
                        if !post_object(
                            &push_client,
                            &subscription,
                            &payload,
                            push_timeout,
                            vapid,
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
                            let emails =
                                email_pushes.get_mut_or_insert(Id::from(email_push.account_id));
                            let remaining = server
                                .core
                                .jmap
                                .push_max_size
                                .min(if subscription.keys.is_some() {
                                    ECE_WEBPUSH_MAX_PLAINTEXT_SIZE
                                } else {
                                    WEBPUSH_MAX_BODY_SIZE
                                })
                                .saturating_sub(PUSH_OBJECT_OVERHEAD)
                                .saturating_sub(emails.used);

                            match build_email_push_object(
                                &server,
                                email_push.account_id,
                                email_push.email_id,
                                config,
                                remaining,
                            )
                            .await
                            {
                                Ok(Some((object, used))) => {
                                    emails.urgency = config.urgency;
                                    if emails
                                        .change_id
                                        .is_none_or(|change_id| email_push.change_id > change_id)
                                    {
                                        emails.change_id = Some(email_push.change_id);
                                    }
                                    emails.used += used;
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

            if !batch.state_changes.is_empty() {
                let payload = PushObject::StateChange {
                    changed: batch.state_changes,
                };
                if !post_object(
                    &push_client,
                    &subscription,
                    &payload,
                    push_timeout,
                    vapid,
                    Urgency::Normal,
                )
                .await
                    && let PushObject::StateChange { changed } = payload
                {
                    failed.state_changes = changed;
                }
            }

            for (account_id, email_push) in email_pushes {
                if email_push.emails.is_empty() {
                    continue;
                }

                let payload = PushObject::EmailPush {
                    account_id,
                    emails: email_push.emails,
                    state: email_push.change_id.map(State::Exact),
                };

                if !post_object(
                    &push_client,
                    &subscription,
                    &payload,
                    push_timeout,
                    vapid,
                    email_push.urgency,
                )
                .await
                {
                    failed_email_pushes.push(account_id.document_id());
                }
            }

            let result = if failed.state_changes.is_empty()
                && failed_email_pushes.is_empty()
                && failed_calendar_alerts.is_empty()
            {
                Event::DeliverySuccess { id }
            } else {
                failed.notifications = batch
                    .notifications
                    .into_iter()
                    .filter(|notification| match notification {
                        PushNotification::StateChange(_) => false,
                        PushNotification::EmailPush(email_push) => {
                            failed_email_pushes.contains(&email_push.account_id)
                        }
                        PushNotification::CalendarAlert(calendar_alert) => failed_calendar_alerts
                            .contains(&(calendar_alert.account_id, calendar_alert.event_id)),
                    })
                    .collect();

                Event::DeliveryFailure { id, failed }
            };

            push_tx.send(result).await.ok();
        });
    }
}

async fn post_object(
    push_client: &Client,
    subscription: &PushSubscription,
    object: &PushObject,
    push_timeout: Duration,
    vapid: Option<&Vapid>,
    urgency: Urgency,
) -> bool {
    match serde_json::to_vec(object) {
        Ok(body) => {
            http_request(
                push_client,
                subscription,
                body,
                push_timeout,
                vapid,
                urgency,
            )
            .await
        }
        Err(err) => {
            trc::event!(
                PushSubscription(PushSubscriptionEvent::Error),
                Details = "Failed to serialize push object",
                Url = subscription.url.to_string(),
                Reason = err.to_string()
            );
            true
        }
    }
}

pub(crate) fn build_push_client() -> Client {
    utils::http::http_client_builder(cfg!(feature = "test_mode"))
        .redirect(Policy::custom(|attempt| match attempt.previous().last() {
            Some(previous) if is_same_organization(previous, attempt.url()) => {
                if attempt.previous().len() > MAX_REDIRECTS {
                    attempt.error("Too many redirects.")
                } else {
                    attempt.follow()
                }
            }
            _ => attempt.stop(),
        }))
        .build()
        .unwrap_or_default()
}

pub(crate) async fn http_request(
    push_client: &Client,
    details: &PushSubscription,
    mut body: Vec<u8>,
    push_timeout: Duration,
    vapid: Option<&Vapid>,
    urgency: Urgency,
) -> bool {
    let mut client = push_client
        .post(details.url.as_str())
        .timeout(push_timeout)
        .header("TTL", "86400")
        .header("Urgency", urgency.as_str());

    if let Some(authorization) = vapid.and_then(|vapid| vapid.authorization(&details.url, now())) {
        client = client.header(AUTHORIZATION, authorization);
    }

    let mut content_type = "application/json";
    if let Some(keys) = &details.keys {
        match ece_encrypt(&keys.p256dh, &keys.auth, &body) {
            Ok(body_) => {
                body = body_;
                content_type = "application/octet-stream";
                client = client.header(CONTENT_ENCODING, "aes128gcm");
            }
            Err(err) => {
                // Do not reattempt if encryption fails.

                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Error),
                    Details = "Failed to encrypt push subscription",
                    Url = CompactString::from(&details.url),
                    Reason = err
                );
                return true;
            }
        }
    }

    match client
        .header(CONTENT_TYPE, content_type)
        .body(body)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();

            if status.is_success() {
                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Success),
                    Url = CompactString::from(&details.url)
                );

                true
            } else {
                let mut reason = response.text().await.unwrap_or_default();
                reason.truncate(reason.ceil_char_boundary(MAX_ERROR_RESPONSE_LEN));

                trc::event!(
                    PushSubscription(PushSubscriptionEvent::Error),
                    Details = "HTTP POST failed",
                    Url = CompactString::from(&details.url),
                    Code = status.as_u16(),
                    Reason = reason,
                );

                false
            }
        }
        Err(err) => {
            trc::event!(
                PushSubscription(PushSubscriptionEvent::Error),
                Details = "HTTP POST failed",
                Url = CompactString::from(&details.url),
                Reason = err.to_compact_string()
            );

            false
        }
    }
}

fn is_same_organization(previous: &Url, next: &Url) -> bool {
    if previous.scheme() == next.scheme()
        && let (Some(previous_host), Some(next_host)) = (previous.host_str(), next.host_str())
    {
        if is_ip_literal(previous_host) || is_ip_literal(next_host) {
            previous_host == next_host
        } else {
            match (psl::domain_str(previous_host), psl::domain_str(next_host)) {
                (Some(previous_domain), Some(next_domain)) => previous_domain == next_domain,
                _ => previous_host == next_host,
            }
        }
    } else {
        false
    }
}

fn is_ip_literal(host: &str) -> bool {
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::is_same_organization;
    use reqwest::Url;

    #[test]
    fn same_organization_redirects() {
        for (previous, next, expected) in [
            (
                "https://push.example.org/a",
                "https://push.example.org/b",
                true,
            ),
            (
                "https://push.example.org/a",
                "https://push2.example.org/b",
                true,
            ),
            ("https://push.example.org/a", "https://example.org/b", true),
            (
                "https://push.example.org/a",
                "https://push.example.org:8443/b",
                true,
            ),
            (
                "https://push.example.org/a",
                "https://push.evil.org/b",
                false,
            ),
            (
                "https://push.example.org/a",
                "http://push.example.org/b",
                false,
            ),
            (
                "https://push.example.co.uk/a",
                "https://evil.co.uk/b",
                false,
            ),
            ("https://1.2.3.4/a", "https://1.2.3.4/b", true),
            ("https://1.2.3.4/a", "https://5.6.7.8/b", false),
            ("https://1.2.3.4/a", "https://5.6.3.4/b", false),
            ("https://1.2.3.4/a", "https://127.0.0.1/b", false),
            ("https://[2606:4700::1111]/a", "https://[::1]/b", false),
            (
                "https://[2606:4700::1111]/a",
                "https://[2606:4700::1111]/b",
                true,
            ),
        ] {
            let previous = Url::parse(previous).unwrap();
            let next = Url::parse(next).unwrap();

            assert_eq!(
                is_same_organization(&previous, &next),
                expected,
                "{previous} -> {next}"
            );
        }
    }
}
