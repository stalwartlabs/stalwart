/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::smtp::{
    TestSMTP,
    inbound::{TestMessage, TestQueueEvent},
    queue::QueuedEvents,
    session::{TestSession, VerifyResponse},
};
use ahash::AHashSet;
use common::{
    config::smtp::queue::QueueName,
    ipc::{QueueEvent, QueueEventStatus},
};
use smtp::queue::spool::{QUEUE_REFRESH, SmtpSpool};
use store::write::now;

const CONFIG: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.extensions]
deliver-by = "1h"
future-release = "1h"

[queue.schedule.sender-default]
retry = ["1s", "2s", "3s"]
notify = ["15h", "22h"]
expire = "1d"
queue-name = "default"

[queue.schedule.sender-test]
retry = ["1s", "2s", "3s"]
notify = ["1s", "2s"]
expire = "6s"
#max-attempts = 3
queue-name = "default"

[queue.strategy]
schedule = [{if = "sender_domain == 'test.org'", then = "'sender-test'"},
           {else = "'sender-default'"}]
"#;

#[tokio::test]
async fn queue_retry() {
    // Enable logging
    crate::enable_logging();

    // Create temp dir for queue
    let mut local = TestSMTP::new("smtp_queue_retry_test", CONFIG).await;

    // Create test message
    let core = local.build_smtp();
    let mut session = local.new_session();
    let qr = &mut local.queue_receiver;

    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    let attempt = qr.expect_message_then_deliver().await;

    // Expect a failed DSN
    attempt.try_deliver(core.clone());
    let message = qr.expect_message().await;
    assert_eq!(message.message.return_path.as_ref(), "");
    assert_eq!(
        message.message.recipients.first().unwrap().address(),
        "john@test.org"
    );
    message
        .read_lines(qr)
        .await
        .assert_contains("Content-Type: multipart/report")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: failed");
    qr.read_event().await.assert_done();
    qr.clear_queue(&core).await;

    // Expect a failed DSN for foobar.org, followed by two delayed DSN and
    // a final failed DSN for _dns_error.org.
    session
        .send_message(
            "john@test.org",
            &["bill@foobar.org", "jane@_dns_error.org"],
            "test:no_dkim",
            "250",
        )
        .await;
    let mut in_fight = AHashSet::new();
    let attempt = qr.expect_message_then_deliver().await;
    let mut dsn = Vec::new();
    let mut retries = Vec::new();
    in_fight.insert(attempt.queue_id);
    attempt.try_deliver(core.clone());

    loop {
        match qr.try_read_event().await {
            Some(QueueEvent::WorkerDone {
                queue_id, status, ..
            }) => {
                in_fight.remove(&queue_id);
                match &status {
                    QueueEventStatus::Completed | QueueEventStatus::Deferred => (),
                    _ => panic!("unexpected status {queue_id}: {status:?}"),
                }
            }
            Some(QueueEvent::Refresh) | Some(QueueEvent::ReloadSettings) => (),
            None | Some(QueueEvent::Stop) | Some(QueueEvent::Paused(_)) => break,
        }

        let now = now();
        let mut events = core.all_queued_messages().await;
        if events.messages.is_empty() {
            if events.next_refresh < now + QUEUE_REFRESH {
                tokio::time::sleep(Duration::from_secs(events.next_refresh - now)).await;
                events = core.all_queued_messages().await;
            } else if in_fight.is_empty() {
                break;
            }
        }

        for event in events.messages {
            if in_fight.contains(&event.queue_id) {
                continue;
            }

            let message = core
                .read_message(event.queue_id, QueueName::default())
                .await
                .unwrap();
            if message.message.return_path.is_empty() {
                message.clone().remove(&core, event.due.into()).await;
                dsn.push(message);
            } else {
                retries.push(event.due.saturating_sub(now));
                in_fight.insert(event.queue_id);
                event.try_deliver(core.clone());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    qr.assert_queue_is_empty().await;
    assert_eq!(retries, vec![1, 2, 3]);
    assert_eq!(dsn.len(), 4);
    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<bill@foobar.org> (failed to lookup 'foobar.org'")
        .assert_contains("Final-Recipient: rfc822;bill@foobar.org")
        .assert_contains("Action: failed");

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(qr)
        .await
        .assert_contains("<jane@_dns_error.org> (failed to lookup '_dns_error.org'")
        .assert_contains("Final-Recipient: rfc822;jane@_dns_error.org")
        .assert_contains("Action: failed");

    // Test FUTURERELEASE + DELIVERBY (RETURN)
    session.data.remote_ip_str = "10.0.0.2".into();
    session.eval_session_params().await;
    session
        .send_message(
            "<bill@foobar.org> HOLDFOR=60 BY=3600;R",
            &["john@test.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    let now_ = now();
    let message = qr.expect_message().await;
    assert!([59, 60].contains(&(qr.message_due(message.queue_id).await - now_)));
    assert!([59, 60].contains(&(message.message.next_delivery_event(None).unwrap() - now_)));
    assert!(
        [3599, 3600].contains(
            &(message
                .message
                .recipients
                .first()
                .unwrap()
                .expiration_time(message.message.created)
                .unwrap()
                - now_)
        )
    );
    assert!(
        [54059, 54060].contains(&(message.message.recipients.first().unwrap().notify.due - now_))
    );

    // Test DELIVERBY (NOTIFY)
    session
        .send_message(
            "<bill@foobar.org> BY=3600;N",
            &["john@test.net"],
            "test:no_dkim",
            "250",
        )
        .await;
    let schedule = qr.expect_message().await;
    assert!(
        [3599, 3600].contains(&(schedule.message.recipients.first().unwrap().notify.due - now()))
    );
}
