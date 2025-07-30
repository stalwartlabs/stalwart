/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use common::{
    config::{server::ServerProtocol, smtp::queue::QueueName},
    ipc::QueueEvent,
};
use mail_auth::MX;
use store::write::now;

use crate::smtp::{
    DnsCache, TestSMTP,
    inbound::{TestMessage, TestQueueEvent},
    queue::QueuedEvents,
    session::{TestSession, VerifyResponse},
};
use smtp::queue::spool::{QUEUE_REFRESH, SmtpSpool};

const LOCAL: &str = r#"
[session.rcpt]
relay = true
max-recipients = 100

[session.extensions]
dsn = true

[queue.schedule.default]
retry = "1s"
notify = "1s"
expire = "7s"
queue-name = "default"

[queue.schedule.foobar-org]
retry = "1s"
notify = ["1s", "2s"]
expire = "6s"
queue-name = "default"

[queue.schedule.foobar-com]
retry = "1s"
notify = ["5s", "6s"]
expire = "7s"
queue-name = "default"


[queue.strategy]
schedule = [{if = "rcpt_domain == 'foobar.org'", then = "'foobar-org'"},
            {if = "rcpt_domain == 'foobar.com'", then = "'foobar-com'"},
            {else = "'default'"}]

[spam-filter]
enable = false

"#;

const REMOTE: &str = r#"
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.extensions]
dsn = true
chunking = false

[spam-filter]
enable = false

"#;

const SMUGGLER: &str = r#"From: Joe SixPack <john@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: Is dinner ready?

Hi.

We lost the game. Are you hungry yet?
.hey
Joe.

<SEP>.
MAIL FROM:<admin@foobar.net>
RCPT TO:<ok@foobar.org>
DATA
From: Joe SixPack <admin@foobar.net>
To: Suzie Q <suzie@foobar.org>
Subject: smuggled message

This is a smuggled message
"#;

#[tokio::test]
#[serial_test::serial]
async fn smtp_delivery() {
    // Enable logging
    crate::enable_logging();

    // Start test server
    let mut remote = TestSMTP::new("smtp_delivery_remote", REMOTE).await;
    let _rx = remote.start(&[ServerProtocol::Smtp]).await;
    let remote_core = remote.build_smtp();

    // Multiple delivery attempts
    let mut local = TestSMTP::new("smtp_delivery_local", LOCAL).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    for domain in ["foobar.org", "foobar.net", "foobar.com"] {
        core.mx_add(
            domain,
            vec![MX {
                exchanges: vec![format!("mx1.{domain}"), format!("mx2.{domain}")],
                preference: 10,
            }],
            Instant::now() + Duration::from_secs(10),
        );
        core.ipv4_add(
            format!("mx1.{domain}"),
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(30),
        );
        core.ipv4_add(
            format!("mx2.{domain}"),
            vec!["127.0.0.1".parse().unwrap()],
            Instant::now() + Duration::from_secs(30),
        );
    }

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &[
                "<ok@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<ok@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.net> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    let message = local.queue_receiver.expect_message().await;
    let num_recipients = message.message.recipients.len();
    assert_eq!(num_recipients, 7);
    local
        .queue_receiver
        .delivery_attempt(message.queue_id)
        .await
        .try_deliver(core.clone());
    let mut dsn = Vec::new();
    let mut rcpt_retries = vec![0; num_recipients];
    loop {
        match local.queue_receiver.try_read_event().await {
            Some(QueueEvent::Refresh | QueueEvent::WorkerDone { .. }) => {}
            Some(QueueEvent::Paused(_)) | Some(QueueEvent::ReloadSettings) => unreachable!(),
            None | Some(QueueEvent::Stop) => {
                break;
            }
        }

        let mut events = core.all_queued_messages().await;
        if events.messages.is_empty() {
            let now = now();
            if events.next_refresh < now + QUEUE_REFRESH {
                tokio::time::sleep(Duration::from_secs(events.next_refresh - now)).await;
                events = core.all_queued_messages().await;
            } else {
                break;
            }
        }
        for event in events.messages {
            let message = core
                .read_message(event.queue_id, QueueName::default())
                .await
                .unwrap();
            if message.message.return_path.is_empty() {
                message.clone().remove(&core, event.due.into()).await;
                dsn.push(message);
            } else {
                for (idx, rcpt) in message.message.recipients.iter().enumerate() {
                    rcpt_retries[idx] = rcpt.retry.inner;
                }
                event.try_deliver(core.clone());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert_eq!(rcpt_retries[0], 0, "retries {rcpt_retries:?}");
    assert!(rcpt_retries[1] >= 5, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[2], 0, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[3], 0, "retries {rcpt_retries:?}");
    assert!(rcpt_retries[4] >= 5, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[5], 0, "retries {rcpt_retries:?}");
    assert_eq!(rcpt_retries[6], 0, "retries {rcpt_retries:?}");
    assert!(
        rcpt_retries[1] >= rcpt_retries[4],
        "retries {rcpt_retries:?}"
    );

    local.queue_receiver.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 5);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<ok@foobar.net> (delivered to")
        .assert_contains("<ok@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.net> (host ")
        .assert_contains("<fail@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.org> (host ")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.org> (host ");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.net> (host ")
        .assert_contains("Action: failed");

    let mut recipients = remote
        .queue_receiver
        .consume_message(&remote_core)
        .await
        .message
        .recipients
        .into_iter()
        .map(|r| r.address().to_string())
        .collect::<Vec<_>>();
    recipients.extend(
        remote
            .queue_receiver
            .consume_message(&remote_core)
            .await
            .message
            .recipients
            .into_iter()
            .map(|r| r.address().to_string()),
    );
    recipients.sort();
    assert_eq!(
        recipients,
        vec!["ok@foobar.net".to_string(), "ok@foobar.org".to_string()]
    );

    remote.queue_receiver.assert_no_events();

    // SMTP smuggling
    for separator in ["\n", "\r"].iter() {
        session.data.remote_ip_str = "10.0.0.2".into();
        session.eval_session_params().await;
        session.ehlo("mx.test.org").await;

        let message = SMUGGLER
            .replace('\r', "")
            .replace('\n', "\r\n")
            .replace("<SEP>", separator);

        session
            .send_message("john@doe.org", &["bill@foobar.com"], &message, "250")
            .await;
        local
            .queue_receiver
            .expect_message_then_deliver()
            .await
            .try_deliver(core.clone());
        local
            .queue_receiver
            .read_event()
            .await
            .assert_refresh_or_done();

        let message = remote
            .queue_receiver
            .consume_message(&remote_core)
            .await
            .read_message(&remote.queue_receiver)
            .await;

        assert!(
            message.contains("This is a smuggled message"),
            "message: {:?}",
            message
        );
        assert!(
            message.contains("We lost the game."),
            "message: {:?}",
            message
        );
        assert!(
            message.contains(&format!("{separator}..\r\nMAIL FROM:<",)),
            "message: {:?}",
            message
        );
    }
}
