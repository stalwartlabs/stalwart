/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::TestSession,
    utils::{
        account::Account,
        dns::DnsCache,
        server::{TestServer, TestServerBuilder},
    },
};
use common::{config::smtp::queue::QueueName, ipc::QueueEvent};
use mail_auth::{DnssecStatus, Mx};
use registry::schema::{
    enums::NetworkListenerProtocol,
    prelude::ObjectType,
    structs::{
        Expression, MtaConnectionStrategy, MtaExtensions, MtaOutboundStrategy, MtaStageRcpt,
    },
};
use smtp::queue::{Error, Status, spool::SmtpSpool};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const NUM_OK_RCPTS: usize = 120;

#[tokio::test]
#[serial_test::serial]
async fn outbound_pipelining() {
    deliver_mixed_recipients(true, 19072).await;
}

#[tokio::test]
#[serial_test::serial]
async fn outbound_no_pipelining() {
    deliver_mixed_recipients(false, 19074).await;
}

async fn deliver_mixed_recipients(pipelining: bool, http_port: u16) {
    let mut local = TestServerBuilder::new(if pipelining {
        "smtp_pipelining_local"
    } else {
        "smtp_no_pipelining_local"
    })
    .await
    .with_http_listener(http_port)
    .await
    .disable_services()
    .capture_queue()
    .build()
    .await;
    let mut remote = TestServerBuilder::new(if pipelining {
        "smtp_pipelining_remote"
    } else {
        "smtp_no_pipelining_remote"
    })
    .await
    .with_http_listener(http_port + 1)
    .await
    .with_listener(NetworkListenerProtocol::Smtp, "smtp-debug", 9925, false)
    .await
    .disable_services()
    .capture_queue()
    .build()
    .await;

    let local_admin = local.account("admin");
    allow_recipients(local_admin).await;
    local_admin.reload_settings().await;

    let remote_admin = remote.account("admin");
    allow_recipients(remote_admin).await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin
        .registry_create_object(MtaExtensions {
            pipelining: Expression {
                else_: pipelining.to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    remote_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    local.server.mx_add(
        "foobar.org",
        vec![Mx {
            exchanges: vec!["mx1.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Insecure,
        Instant::now() + Duration::from_secs(60),
    );
    local.server.ipv4_add(
        "mx1.foobar.org",
        vec!["127.0.0.1".parse().expect("valid ip")],
        Instant::now() + Duration::from_secs(60),
    );

    let mut rcpts = (0..NUM_OK_RCPTS)
        .map(|idx| format!("ok{idx}@foobar.org"))
        .collect::<Vec<_>>();
    rcpts.insert(5, "fail@foobar.org".to_string());
    rcpts.insert(105, "delay@foobar.org".to_string());
    let rcpt_refs = rcpts.iter().map(String::as_str).collect::<Vec<_>>();

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &rcpt_refs, "test:no_dkim", "250")
        .await;
    let message = local.expect_message().await;
    let queue_id = message.queue_id;
    local
        .delivery_attempt(queue_id)
        .await
        .try_deliver(local.server.clone());
    local
        .read_event_matching(|event| matches!(event, QueueEvent::WorkerDone { .. }))
        .await;

    let message = local
        .server
        .read_message(
            queue_id,
            QueueName::new("remote").expect("valid queue name"),
        )
        .await
        .expect("message with deferred recipient stays queued");
    for rcpt in &message.message.recipients {
        let address = rcpt.address();
        match &rcpt.status {
            Status::Completed(_) => assert!(address.starts_with("ok"), "{address}"),
            Status::PermanentFailure(err) => {
                assert_eq!(address, "fail@foobar.org", "{err:?}")
            }
            Status::TemporaryFailure(err) => {
                assert_eq!(address, "delay@foobar.org", "{err:?}")
            }
            Status::Scheduled => panic!("{address} was not attempted"),
        }
    }
    assert_eq!(message.message.recipients.len(), NUM_OK_RCPTS + 2);

    let mut delivered = remote
        .consume_message()
        .await
        .message
        .recipients
        .into_iter()
        .map(|rcpt| rcpt.address().to_string())
        .collect::<Vec<_>>();
    delivered.sort_unstable();
    let mut expected = rcpts
        .iter()
        .filter(|rcpt| rcpt.starts_with("ok"))
        .cloned()
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(delivered, expected, "pipelining {pipelining}");
}

async fn allow_recipients(admin: &Account) {
    admin
        .registry_create_object(MtaStageRcpt {
            max_recipients: Expression {
                else_: "1000".into(),
                ..Default::default()
            },
            allow_relaying: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin.mta_no_auth().await;
    admin.mta_disable_spam_filter().await;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Peer {
    Pipelined,
    PipelinedSplitReplies,
    MailRejected,
    AllRejected,
    ClosedMidBatch,
    Sequential,
    SlowMailReply,
    SlowRcptReplyWithinTimeout,
    SlowRcptReplyTimeout,
}

const PEER_RCPTS: [&str; 3] = ["ok@d.peer", "fail@d.peer", "delay@d.peer"];
const LONG_GROUP_RCPTS: usize = 100;
const ECHO_REPLY_LINES: usize = 12;
const MAX_GROUP_BYTES: usize = 8192;

fn rcpt_reply(line: &str, all_rejected: bool) -> &'static str {
    match (line.contains("<ok@"), line.contains("<fail@"), all_rejected) {
        (true, _, false) => "250 2.1.5 ok\r\n",
        (true, _, true) => "451 4.3.0 later\r\n",
        (_, true, false) => "550 5.1.1 no such user\r\n",
        (_, true, true) => "452 4.2.2 full\r\n",
        _ => "451 4.3.0 try later\r\n",
    }
}

fn group_replies(transcript: &[String], all_rejected: bool) -> String {
    let mut replies = String::from("250 2.1.0 ok\r\n");
    for line in &transcript[2..] {
        replies.push_str(rcpt_reply(line, all_rejected));
    }
    replies
}
const MAIL_TIMEOUT: Duration = Duration::from_millis(1000);
const RCPT_TIMEOUT: Duration = Duration::from_millis(2500);

struct PeerConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl PeerConn {
    async fn fill(&mut self, wait: Duration) -> Result<bool, String> {
        let mut chunk = [0u8; 4096];
        match tokio::time::timeout(wait, self.stream.read(&mut chunk)).await {
            Ok(Ok(0)) => Err("client closed the connection".to_string()),
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Ok(false),
        }
    }

    async fn line(&mut self) -> Result<String, String> {
        loop {
            if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = self.buf.drain(..pos + 2).collect::<Vec<_>>();
                return String::from_utf8(line).map_err(|err| err.to_string());
            }
            if !self.fill(Duration::from_secs(10)).await? {
                return Err(format!(
                    "timeout waiting for a line, pending {:?}",
                    self.buf
                ));
            }
        }
    }

    async fn lines(&mut self, count: usize) -> Result<Vec<String>, String> {
        let mut lines = Vec::with_capacity(count);
        for _ in 0..count {
            lines.push(self.line().await?);
        }
        Ok(lines)
    }

    async fn data(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if let Some(pos) = self.buf.windows(5).position(|w| w == b"\r\n.\r\n") {
                let mut data = self.buf.drain(..pos + 5).collect::<Vec<_>>();
                data.truncate(pos);
                return Ok(data);
            }
            if !self.fill(Duration::from_secs(10)).await? {
                return Err("timeout waiting for the end of DATA".to_string());
            }
        }
    }

    async fn message(&mut self) -> Result<(), String> {
        loop {
            if let Some(pos) = self.buf.windows(5).position(|w| w == b"\r\n.\r\n") {
                self.buf.drain(..pos + 5);
                return Ok(());
            }
            if !self.fill(Duration::from_secs(10)).await? {
                return Err("timeout waiting for the end of DATA".to_string());
            }
        }
    }

    async fn is_quiet(&mut self) -> Result<bool, String> {
        Ok(self.buf.is_empty() && !self.fill(Duration::from_millis(300)).await?)
    }

    async fn send(&mut self, data: &str) -> Result<(), String> {
        self.stream
            .write_all(data.as_bytes())
            .await
            .map_err(|err| err.to_string())?;
        self.stream.flush().await.map_err(|err| err.to_string())
    }

    async fn send_split(&mut self, data: &str) -> Result<(), String> {
        for byte in data.as_bytes().chunks(3) {
            self.stream
                .write_all(byte)
                .await
                .map_err(|err| err.to_string())?;
            self.stream.flush().await.map_err(|err| err.to_string())?;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok(())
    }

    async fn expect(&mut self, prefix: &str) -> Result<String, String> {
        let line = self.line().await?;
        if line.starts_with(prefix) {
            Ok(line)
        } else {
            Err(format!("expected {prefix:?}, got {line:?}"))
        }
    }

    async fn finish_data_and_quit(&mut self) -> Result<(), String> {
        self.expect("DATA").await?;
        self.send("354 go ahead\r\n").await?;
        self.message().await?;
        self.send("250 2.0.0 queued\r\n").await?;
        self.expect_quit().await
    }

    async fn expect_quit(&mut self) -> Result<(), String> {
        self.expect("QUIT").await?;
        self.send("221 bye\r\n").await
    }
}

async fn run_peer(listener: Arc<TcpListener>, peer: Peer) -> Result<Vec<String>, String> {
    let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .map_err(|_| "no connection".to_string())?
        .map_err(|err| err.to_string())?;
    let _ = stream.set_nodelay(true);
    let mut conn = PeerConn {
        stream,
        buf: Vec::new(),
    };
    let mut transcript = Vec::new();
    conn.send("220 peer ESMTP\r\n").await?;
    transcript.push(conn.expect("EHLO ").await?);
    if peer == Peer::Sequential {
        conn.send("250-peer\r\n250-SIZE 100000000\r\n250 8BITMIME\r\n")
            .await?;
    } else {
        conn.send("250-peer\r\n250-SIZE 100000000\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
            .await?;
    }

    match peer {
        Peer::Sequential => {
            transcript.push(conn.line().await?);
            for idx in 0..=PEER_RCPTS.len() {
                if !conn.is_quiet().await? {
                    return Err(format!(
                        "client pipelined without PIPELINING: {transcript:?}"
                    ));
                }
                if idx == 0 {
                    conn.send("250 2.1.0 ok\r\n").await?;
                } else {
                    let reply = rcpt_reply(transcript.last().map_or("", String::as_str), false);
                    conn.send(reply).await?;
                }
                if idx < PEER_RCPTS.len() {
                    transcript.push(conn.line().await?);
                }
            }
            conn.finish_data_and_quit().await?;
        }
        Peer::Pipelined | Peer::PipelinedSplitReplies => {
            transcript.extend(conn.lines(4).await?);
            let replies = group_replies(&transcript, false);
            if peer == Peer::Pipelined {
                conn.send(&replies).await?;
            } else {
                conn.send_split(&replies).await?;
            }
            conn.finish_data_and_quit().await?;
        }
        Peer::MailRejected => {
            transcript.extend(conn.lines(4).await?);
            conn.send("451 4.7.1 sender deferred\r\n503 5.5.1 no MAIL\r\n503 5.5.1 no MAIL\r\n503 5.5.1 no MAIL\r\n")
                .await?;
            conn.expect_quit().await?;
        }
        Peer::AllRejected => {
            transcript.extend(conn.lines(4).await?);
            conn.send(&group_replies(&transcript, true)).await?;
            conn.expect_quit().await?;
        }
        Peer::ClosedMidBatch => {
            transcript.extend(conn.lines(4).await?);
            conn.send(&format!(
                "250 2.1.0 ok\r\n{}",
                rcpt_reply(&transcript[2], false)
            ))
            .await?;
        }
        Peer::SlowMailReply => {
            transcript.extend(conn.lines(4).await?);
            tokio::time::sleep(MAIL_TIMEOUT + Duration::from_millis(700)).await;
            let _ = conn.send(&group_replies(&transcript, false)).await;
        }
        Peer::SlowRcptReplyWithinTimeout | Peer::SlowRcptReplyTimeout => {
            transcript.extend(conn.lines(4).await?);
            conn.send(&format!(
                "250 2.1.0 ok\r\n{}",
                rcpt_reply(&transcript[2], false)
            ))
            .await?;
            tokio::time::sleep(if peer == Peer::SlowRcptReplyWithinTimeout {
                MAIL_TIMEOUT + Duration::from_millis(700)
            } else {
                RCPT_TIMEOUT + Duration::from_millis(700)
            })
            .await;
            let rest = transcript[3..]
                .iter()
                .map(|line| rcpt_reply(line, false))
                .collect::<String>();
            if conn.send(&rest).await.is_ok() && peer == Peer::SlowRcptReplyWithinTimeout {
                conn.finish_data_and_quit().await?;
            }
        }
    }
    Ok(transcript)
}

#[tokio::test]
#[serial_test::serial]
async fn outbound_pipelining_peer() {
    let mut local = peer_local("smtp_pipelining_peer_local", 19076).await;
    let listener = Arc::new(
        TcpListener::bind("127.0.0.1:9925")
            .await
            .expect("bind peer port"),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;

    for peer in [
        Peer::Pipelined,
        Peer::PipelinedSplitReplies,
        Peer::MailRejected,
        Peer::AllRejected,
        Peer::ClosedMidBatch,
        Peer::Sequential,
        Peer::SlowMailReply,
        Peer::SlowRcptReplyWithinTimeout,
        Peer::SlowRcptReplyTimeout,
    ] {
        local.clear_queue().await;
        session
            .send_message("john@test.org", &PEER_RCPTS, "test:no_dkim", "250")
            .await;
        let queued = local.expect_message().await;
        let queue_id = queued.queue_id;
        let rcpt_lines = queued
            .message
            .recipients
            .iter()
            .map(|rcpt| format!("RCPT TO:<{}>\r\n", rcpt.address()))
            .collect::<Vec<_>>();
        let peer_task = tokio::spawn(run_peer(listener.clone(), peer));
        local
            .delivery_attempt(queue_id)
            .await
            .try_deliver(local.server.clone());
        local
            .read_event_matching(|event| matches!(event, QueueEvent::WorkerDone { .. }))
            .await;
        let transcript = peer_task
            .await
            .expect("peer task")
            .unwrap_or_else(|err| panic!("{peer:?}: {err}"));

        assert!(
            transcript[0].starts_with("EHLO "),
            "{peer:?} {transcript:?}"
        );
        assert!(
            transcript[1].starts_with("MAIL FROM:<john@test.org>"),
            "{peer:?} {transcript:?}"
        );
        assert_eq!(&transcript[2..], rcpt_lines, "{peer:?}");

        let message = local
            .server
            .read_message(
                queue_id,
                QueueName::new("remote").expect("valid queue name"),
            )
            .await
            .unwrap_or_else(|| panic!("{peer:?}: message was removed"));
        let mut statuses = message
            .message
            .recipients
            .iter()
            .map(|rcpt| {
                let status = match &rcpt.status {
                    Status::Completed(_) => "completed".to_string(),
                    Status::PermanentFailure(err) | Status::TemporaryFailure(err) => format!(
                        "{}:{}",
                        if matches!(rcpt.status, Status::PermanentFailure(_)) {
                            "perm"
                        } else {
                            "temp"
                        },
                        match &err.details {
                            Error::UnexpectedResponse(response) => format!(
                                "{}:{}",
                                response.command.split(':').next().unwrap_or_default(),
                                response.response.code
                            ),
                            Error::ConnectionError(_) => "connection".to_string(),
                            other => format!("{other:?}"),
                        }
                    ),
                    Status::Scheduled => "scheduled".to_string(),
                };
                (rcpt.address().to_string(), status)
            })
            .collect::<Vec<_>>();
        statuses.sort_unstable();
        let expected: [&str; 3] = match peer {
            Peer::Pipelined
            | Peer::PipelinedSplitReplies
            | Peer::Sequential
            | Peer::SlowRcptReplyWithinTimeout => {
                ["temp:RCPT TO:451", "perm:RCPT TO:550", "completed"]
            }
            Peer::MailRejected => [
                "temp:MAIL FROM:451",
                "temp:MAIL FROM:451",
                "temp:MAIL FROM:451",
            ],
            Peer::AllRejected => ["temp:RCPT TO:451", "temp:RCPT TO:452", "temp:RCPT TO:451"],
            Peer::ClosedMidBatch | Peer::SlowMailReply | Peer::SlowRcptReplyTimeout => {
                ["temp:connection", "temp:connection", "temp:connection"]
            }
        };
        let expected = ["delay@d.peer", "fail@d.peer", "ok@d.peer"]
            .into_iter()
            .zip(expected)
            .map(|(address, status)| (address.to_string(), status.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(statuses, expected, "{peer:?}");
    }
}

async fn peer_local(name: &str, http_port: u16) -> TestServer {
    let mut local = TestServerBuilder::new(name)
        .await
        .with_http_listener(http_port)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let local_admin = local.account("admin");
    allow_recipients(local_admin).await;
    local_admin
        .registry_destroy_all(ObjectType::MtaInboundThrottle)
        .await;
    local_admin
        .registry_create_object(MtaConnectionStrategy {
            name: "peer".into(),
            mail_from_timeout: (MAIL_TIMEOUT.as_millis() as u64).into(),
            rcpt_to_timeout: (RCPT_TIMEOUT.as_millis() as u64).into(),
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaOutboundStrategy {
            connection: Expression {
                else_: "'peer'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    local.server.mx_add(
        "d.peer",
        vec![Mx {
            exchanges: vec!["mx.d.peer".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Insecure,
        Instant::now() + Duration::from_secs(600),
    );
    local.server.ipv4_add(
        "mx.d.peer",
        vec!["127.0.0.1".parse().expect("valid ip")],
        Instant::now() + Duration::from_secs(600),
    );
    local
}

#[tokio::test]
#[serial_test::serial]
async fn outbound_pipelining_long_group() {
    let mut local = peer_local("smtp_pipelining_long_group_local", 19078).await;
    let listener = TcpListener::bind("127.0.0.1:9925")
        .await
        .expect("bind peer port");

    let rcpts = (0..LONG_GROUP_RCPTS)
        .map(|idx| format!("u{idx:03}{}@d.peer", "x".repeat(230)))
        .collect::<Vec<_>>();
    let rcpt_refs = rcpts.iter().map(String::as_str).collect::<Vec<_>>();
    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &rcpt_refs, "test:no_dkim", "250")
        .await;
    let queue_id = local.expect_message().await.queue_id;
    let peer_task = tokio::spawn(run_echo_peer(listener));
    local
        .delivery_attempt(queue_id)
        .await
        .try_deliver(local.server.clone());
    local
        .read_event_matching(|event| matches!(event, QueueEvent::WorkerDone { .. }))
        .await;
    let groups = peer_task
        .await
        .expect("peer task")
        .unwrap_or_else(|err| panic!("echo peer: {err}"));
    assert!(
        local
            .server
            .read_message(
                queue_id,
                QueueName::new("remote").expect("valid queue name")
            )
            .await
            .is_none(),
        "message still queued after delivery"
    );
    assert_eq!(
        groups.iter().map(|(_, rcpts)| rcpts).sum::<usize>(),
        LONG_GROUP_RCPTS
    );
    assert!(groups.len() >= 3, "{groups:?}");
    assert!(
        groups
            .iter()
            .all(|(bytes, _)| *bytes <= MAX_GROUP_BYTES + 512),
        "{groups:?}"
    );
}

async fn run_echo_peer(listener: TcpListener) -> Result<Vec<(usize, usize)>, String> {
    let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .map_err(|_| "no connection".to_string())?
        .map_err(|err| err.to_string())?;
    let _ = stream.set_nodelay(true);
    let mut conn = PeerConn {
        stream,
        buf: Vec::new(),
    };
    conn.send("220 peer ESMTP\r\n").await?;
    conn.expect("EHLO ").await?;
    conn.send("250-peer\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
        .await?;
    let mut groups = Vec::new();
    loop {
        if !conn.fill(Duration::from_secs(10)).await? {
            return Err("timeout waiting for a command group".to_string());
        }
        while conn.fill(Duration::from_millis(200)).await? {}
        let group_bytes = conn.buf.len();
        let mut group_rcpts = 0;
        let mut reply = String::new();
        while conn.buf.windows(2).any(|w| w == b"\r\n") {
            let line = conn.line().await?;
            if line.starts_with("MAIL FROM:") {
                reply.push_str("250 2.1.0 ok\r\n");
            } else if let Some(address) = line.strip_prefix("RCPT TO:") {
                for _ in 0..ECHO_REPLY_LINES {
                    reply.push_str("250-");
                    reply.push_str(address.trim_end());
                    reply.push_str("\r\n");
                }
                reply.push_str("250 2.1.5 ok\r\n");
                group_rcpts += 1;
            } else if line.starts_with("DATA") {
                conn.send("354 go ahead\r\n").await?;
                conn.message().await?;
                conn.send("250 2.0.0 queued\r\n").await?;
                conn.expect_quit().await?;
                return Ok(groups);
            } else {
                return Err(format!("unexpected command {line:?}"));
            }
        }
        groups.push((group_bytes, group_rcpts));
        conn.send(&reply).await?;
    }
}

#[tokio::test]
#[serial_test::serial]
async fn outbound_dot_stuffing() {
    let mut local = peer_local("smtp_dot_stuffing_local", 19080).await;
    let listener = TcpListener::bind("127.0.0.1:9925")
        .await
        .expect("bind peer port");

    let mut body = String::from("From: john@test.org\r\nTo: ok@d.peer\r\nSubject: dots\r\n\r\n");
    for idx in 0..3000 {
        if idx % 3 == 0 {
            body.push_str(&format!("..leading dot line {idx}\r\n"));
        } else {
            body.push_str(&format!("plain line {idx}. with a dot\r\n"));
        }
    }
    for _ in 0..1500 {
        body.push_str(&"A".repeat(76));
        body.push_str("\r\n");
    }
    for _ in 0..500 {
        body.push_str("..x\r\n..\r\n");
    }
    body.push_str("end");

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["ok@d.peer"], &body, "250")
        .await;
    let queued = local.expect_message().await;
    let stored = local
        .server
        .blob_store()
        .get_blob(queued.message.blob_hash.as_slice(), 0..usize::MAX)
        .await
        .expect("blob read")
        .expect("blob exists");
    let mut expected = Vec::with_capacity(stored.len() + 4096);
    let mut prev = 0u8;
    for &byte in &stored {
        if byte == b'.' && matches!(prev, b'\r' | b'\n') {
            expected.push(b'.');
        }
        expected.push(byte);
        prev = byte;
    }

    let peer_task = tokio::spawn(async move {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .map_err(|_| "no connection".to_string())?
            .map_err(|err| err.to_string())?;
        let mut conn = PeerConn {
            stream,
            buf: Vec::new(),
        };
        conn.send("220 peer ESMTP\r\n").await?;
        conn.expect("EHLO ").await?;
        conn.send("250-peer\r\n250 8BITMIME\r\n").await?;
        conn.expect("MAIL FROM:").await?;
        conn.send("250 2.1.0 ok\r\n").await?;
        conn.expect("RCPT TO:").await?;
        conn.send("250 2.1.5 ok\r\n").await?;
        conn.expect("DATA").await?;
        conn.send("354 go ahead\r\n").await?;
        let data = conn.data().await?;
        conn.send("250 2.0.0 queued\r\n").await?;
        conn.expect_quit().await?;
        Ok::<_, String>(data)
    });
    local
        .delivery_attempt(queued.queue_id)
        .await
        .try_deliver(local.server.clone());
    local
        .read_event_matching(|event| matches!(event, QueueEvent::WorkerDone { .. }))
        .await;
    let received = peer_task
        .await
        .expect("peer task")
        .unwrap_or_else(|err| panic!("dot peer: {err}"));
    assert!(stored.len() > 2 * 65536, "{}", stored.len());
    assert_eq!(received.len(), expected.len());
    assert!(
        received == expected,
        "stuffed DATA differs from the reference"
    );
}
