/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::queue::{build_rcpt, new_message},
    utils::server::TestServerBuilder,
};
use common::config::smtp::queue::QueueName;
use smtp::queue::{Error, ErrorDetails, Message, Recipient, Status, spool::SmtpSpool};
use std::time::Duration;
use store::write::now;

#[tokio::test]
async fn queue_due() {
    let mut local = TestServerBuilder::new("smtp_queue_manager")
        .await
        .with_http_listener(19040)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_allow_relaying().await;
    local_admin.mta_allow_non_fqdn().await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let mut message = new_message(0);
    message.message.recipients.push(build_rcpt("c", 3, 8, 9));
    message.save_changes(&local.server, 0.into()).await;

    let mut message = new_message(1);
    message.message.recipients.push(build_rcpt("b", 2, 6, 7));
    message.save_changes(&local.server, 0.into()).await;

    let mut message = new_message(2);
    message.message.recipients.push(build_rcpt("a", 1, 4, 5));
    message.save_changes(&local.server, 0.into()).await;

    for domain in vec!["a", "b", "c"].into_iter() {
        let now = now();
        let queued = local.all_queued_messages().await;
        if queued.messages.is_empty() {
            let wake_up = queued.next_refresh - now;
            assert_eq!(wake_up, 1);
            std::thread::sleep(Duration::from_secs(wake_up));
        }

        for queue_event in local.all_queued_messages().await.messages {
            if let Some(message) = local
                .server
                .read_message(queue_event.queue_id, QueueName::default())
                .await
            {
                message.message.rcpt(domain);
                message.remove(&local.server, queue_event.due.into()).await;
            } else {
                panic!("Message not found");
            }
        }
    }

    local.assert_queue_is_empty().await;
}

#[test]
fn delivery_events() {
    let mut message = new_message(0).message;
    message.created = now();

    message.recipients.push(build_rcpt("a", 1, 2, 3));
    message.recipients.push(build_rcpt("b", 4, 5, 6));
    message.recipients.push(build_rcpt("c", 7, 8, 9));

    for t in 0..2 {
        assert_eq!(
            message.next_event(None).unwrap(),
            message.rcpt("a").retry.due
        );
        assert_eq!(
            message.next_delivery_event(None).unwrap(),
            message.rcpt("a").retry.due
        );
        assert_eq!(
            next_event_after(
                &message,
                None,
                message.rcpt("a").expiration_time(message.created).unwrap()
            )
            .unwrap(),
            message.rcpt("b").retry.due
        );
        assert_eq!(
            next_event_after(
                &message,
                None,
                message.rcpt("b").expiration_time(message.created).unwrap()
            )
            .unwrap(),
            message.rcpt("c").retry.due
        );
        assert_eq!(
            next_event_after(&message, None, message.rcpt("c").notify.due).unwrap(),
            message.rcpt("c").expiration_time(message.created).unwrap()
        );
        assert!(
            next_event_after(
                &message,
                None,
                message.rcpt("c").expiration_time(message.created).unwrap()
            )
            .is_none()
        );

        if t == 0 {
            message.recipients.reverse();
        } else {
            message.recipients.swap(0, 1);
        }
    }

    message.rcpt_mut("a").status = Status::PermanentFailure(ErrorDetails {
        entity: "localhost".into(),
        details: Error::ConcurrencyLimited,
    });
    assert_eq!(
        message.next_event(None).unwrap(),
        message.rcpt("b").retry.due
    );
    assert_eq!(
        message.next_delivery_event(None).unwrap(),
        message.rcpt("b").retry.due
    );

    message.rcpt_mut("b").status = Status::PermanentFailure(ErrorDetails {
        entity: "localhost".into(),
        details: Error::ConcurrencyLimited,
    });
    assert_eq!(
        message.next_event(None).unwrap(),
        message.rcpt("c").retry.due
    );
    assert_eq!(
        message.next_delivery_event(None).unwrap(),
        message.rcpt("c").retry.due
    );

    message.rcpt_mut("c").status = Status::PermanentFailure(ErrorDetails {
        entity: "localhost".into(),
        details: Error::ConcurrencyLimited,
    });
    assert!(message.next_event(None).is_none());
}

fn next_event_after(message: &Message, queue: Option<QueueName>, instant: u64) -> Option<u64> {
    let mut next_event = None;

    for rcpt in &message.recipients {
        if matches!(rcpt.status, Status::Scheduled | Status::TemporaryFailure(_))
            && queue.is_none_or(|q| rcpt.queue == q)
        {
            if rcpt.retry.due > instant
                && next_event.as_ref().is_none_or(|ne| rcpt.retry.due.lt(ne))
            {
                next_event = rcpt.retry.due.into();
            }
            if rcpt.notify.due > instant
                && next_event.as_ref().is_none_or(|ne| rcpt.notify.due.lt(ne))
            {
                next_event = rcpt.notify.due.into();
            }
            if let Some(expires) = rcpt.expiration_time(message.created)
                && expires > instant
                && next_event.as_ref().is_none_or(|ne| expires.lt(ne))
            {
                next_event = expires.into();
            }
        }
    }

    next_event
}

pub trait TestMessage {
    fn rcpt(&self, name: &str) -> &Recipient;
    fn rcpt_mut(&mut self, name: &str) -> &mut Recipient;
}

impl TestMessage for Message {
    fn rcpt(&self, name: &str) -> &Recipient {
        self.recipients
            .iter()
            .find(|d| d.address() == name)
            .unwrap_or_else(|| panic!("Expected rcpt {name} not found in {:?}", self.recipients))
    }

    fn rcpt_mut(&mut self, name: &str) -> &mut Recipient {
        self.recipients
            .iter_mut()
            .find(|d| d.address() == name)
            .unwrap()
    }
}
