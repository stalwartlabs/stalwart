/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use crate::smtp::{
    DnsCache, TestSMTP,
    inbound::TestMessage,
    queue::QueuedEvents,
    session::{TestSession, VerifyResponse},
};
use common::{
    config::{server::ServerProtocol, smtp::queue::QueueName},
    ipc::QueueEvent,
};
use smtp::queue::spool::{QUEUE_REFRESH, SmtpSpool};
use store::write::now;

const REMOTE: &str = "
[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = true

[session.extensions]
dsn = true
";

const LOCAL: &str = r#"
[queue.strategy]
route = [{if = "rcpt_domain = 'foobar.org'", then = "'lmtp'"},
            {else = "'mx'"}]
schedule = [{if = "rcpt_domain = 'foobar.org'", then = "'foobar'"},
            {else = "'default'"}]

[session.rcpt]
relay = true
max-recipients = 100

[session.extensions]
dsn = true

[queue.schedule.default]
retry = "1s"
notify = "1s"
expire = "5s"
queue-name = "default"

[queue.schedule.foobar]
retry = "1s"
notify = ["1s", "2s"]
expire = "4s"
queue-name = "default"

[queue.connection.default.timeout]
connect = "1s"
data = "50ms"

[queue.route.lmtp]
type = "relay"
address = lmtp.foobar.org
port = 9924
protocol = 'lmtp'
concurrency = 5

[queue.route.lmtp.tls]
implicit = true
allow-invalid-certs = true
"#;

#[tokio::test]
#[serial_test::serial]
async fn lmtp_delivery() {
    // Enable logging
    crate::enable_logging();

    // Start test server
    let mut remote = TestSMTP::new("lmtp_delivery_remote", REMOTE).await;
    let _rx = remote.start(&[ServerProtocol::Lmtp]).await;

    // Multiple delivery attempts
    let mut local = TestSMTP::new("lmtp_delivery_local", LOCAL).await;

    // Add mock DNS entries
    let core = local.build_smtp();
    core.ipv4_add(
        "lmtp.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message(
            "john@test.org",
            &[
                "<bill@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<jane@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<john@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<delay@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<fail@foobar.org> NOTIFY=SUCCESS,DELAY,FAILURE",
                "<invalid@domain.org> NOTIFY=SUCCESS,DELAY,FAILURE",
            ],
            "test:no_dkim",
            "250",
        )
        .await;
    local
        .queue_receiver
        .expect_message_then_deliver()
        .await
        .try_deliver(core.clone());
    let mut dsn = Vec::new();
    loop {
        match local.queue_receiver.try_read_event().await {
            Some(QueueEvent::Refresh | QueueEvent::WorkerDone { .. }) => {}
            Some(QueueEvent::Paused(_)) | Some(QueueEvent::ReloadSettings) => unreachable!(),
            None | Some(QueueEvent::Stop) => break,
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
                event.try_deliver(core.clone());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    local.queue_receiver.assert_queue_is_empty().await;
    assert_eq!(dsn.len(), 4);

    let mut dsn = dsn.into_iter();

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<bill@foobar.org> (delivered to")
        .assert_contains("<jane@foobar.org> (delivered to")
        .assert_contains("<john@foobar.org> (delivered to")
        .assert_contains("<invalid@domain.org> (failed to lookup")
        .assert_contains("<fail@foobar.org> (host 'lmtp.foobar.org' rejected command");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: delayed");

    dsn.next()
        .unwrap()
        .read_lines(&local.queue_receiver)
        .await
        .assert_contains("<delay@foobar.org> (host 'lmtp.foobar.org' rejected")
        .assert_contains("Action: failed");

    assert_eq!(
        remote
            .queue_receiver
            .expect_message()
            .await
            .message
            .recipients
            .into_iter()
            .map(|r| r.address().to_string())
            .collect::<Vec<_>>(),
        vec![
            "bill@foobar.org".to_string(),
            "jane@foobar.org".to_string(),
            "john@foobar.org".to_string()
        ]
    );
    remote.queue_receiver.assert_no_events();
}
