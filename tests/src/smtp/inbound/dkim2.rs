/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{inbound::TestMessage, session::TestSession},
    utils::{account::Account, dns::DnsCache, server::TestServer, server::TestServerBuilder},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use mail_auth::{
    DnssecStatus, MX,
    common::{crypto::Ed25519Key, parse::TxtRecordParser, verify::DomainKey},
    dkim2::{Dkim2Signer, Hop},
};
use registry::schema::{
    enums::{DkimCanonicalization, DkimRotationStage},
    structs::{
        CertificateManagement, Dkim1Signature, Dkim2Signature, DkimManagement, DkimSignature,
        DnsManagement, Domain, DsnReportSettings, Expression, SecretText, SecretTextValue,
        SenderAuth,
    },
};
use std::time::{Duration, Instant};
use types::id::Id;

const ED_PRIVATE: &str = concat!(
    "-----BEGIN PRIVATE KEY-----\n",
    "MC4CAQAwBQYDK2VwBCIEIIOQVf8MDGvvmIkpUbgoqtyUIxjlzRqaBR6aP12tcGGE\n",
    "-----END PRIVATE KEY-----\n"
);
const ED_PUBLIC: &str = "hwjviTXyzUXSCWayBqE17s/4NSynQKxw58jayHudRAI=";

#[tokio::test]
#[serial_test::serial]
async fn dkim2_all_disclosed() {
    let (mut local, remote) = build_signer_and_verifier(19040, 19041, false).await;

    let delivered = deliver_and_collect(
        &mut local,
        &remote,
        "john@example.com",
        &["alice@foobar.org", "bob@foobar.org"],
        &message("To: Alice <alice@foobar.org>, Bob <bob@foobar.org>\r\n"),
        1,
    )
    .await;

    assert_eq!(delivered.len(), 1);
    let msg = &delivered[0];
    assert_eq!(msg.recipients, vec!["alice@foobar.org", "bob@foobar.org"]);
    assert!(
        msg.body.contains("DKIM2-Signature"),
        "missing DKIM2 signature: {}",
        msg.body
    );
    assert!(
        without_whitespace(&msg.body).contains("dkim2=pass"),
        "verifier did not report dkim2=pass: {}",
        msg.body
    );

    // Both disclosed recipients belong to the same shared signature
    let stripped = without_whitespace(&msg.body);
    assert!(stripped.contains(&rt_token("alice@foobar.org")));
    assert!(stripped.contains(&rt_token("bob@foobar.org")));
}

#[tokio::test]
#[serial_test::serial]
async fn dkim2_mixed_recipients_do_not_leak_bcc() {
    let (mut local, remote) = build_signer_and_verifier(19042, 19043, false).await;

    let delivered = deliver_and_collect(
        &mut local,
        &remote,
        "john@example.com",
        &[
            "alice@foobar.org",
            "bob@foobar.org",
            "eve@foobar.org",
            "mallory@foobar.org",
        ],
        &message("To: Alice <alice@foobar.org>\r\nCc: Bob <bob@foobar.org>\r\n"),
        3,
    )
    .await;

    assert_eq!(delivered.len(), 3);

    let eve = rt_token("eve@foobar.org");
    let mallory = rt_token("mallory@foobar.org");

    for msg in &delivered {
        let stripped = without_whitespace(&msg.body);
        assert!(
            stripped.contains("dkim2=pass"),
            "verifier did not report dkim2=pass for {:?}: {}",
            msg.recipients,
            msg.body
        );

        if msg.recipients == vec!["alice@foobar.org", "bob@foobar.org"] {
            // Disclosed copy: the two Bcc recipients must not appear anywhere
            assert!(
                !stripped.contains(&eve) && !stripped.contains(&mallory),
                "Bcc recipient leaked into the disclosed signature: {}",
                msg.body
            );
            assert!(!msg.body.contains("eve@foobar.org"));
            assert!(!msg.body.contains("mallory@foobar.org"));
            assert!(stripped.contains(&rt_token("alice@foobar.org")));
            assert!(stripped.contains(&rt_token("bob@foobar.org")));
        } else if msg.recipients == vec!["eve@foobar.org"] {
            // Bcc copy: only Eve's address is in this signature
            assert!(stripped.contains(&eve));
            assert!(!stripped.contains(&mallory));
            assert!(!msg.body.contains("mallory@foobar.org"));
        } else if msg.recipients == vec!["mallory@foobar.org"] {
            assert!(stripped.contains(&mallory));
            assert!(!stripped.contains(&eve));
            assert!(!msg.body.contains("eve@foobar.org"));
        } else {
            panic!("unexpected recipient grouping: {:?}", msg.recipients);
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn dkim2_all_undisclosed_do_not_leak() {
    let (mut local, remote) = build_signer_and_verifier(19044, 19045, false).await;

    let rcpts = ["carol@foobar.org", "dave@foobar.org", "frank@foobar.org"];
    let delivered = deliver_and_collect(
        &mut local,
        &remote,
        "john@example.com",
        &rcpts,
        &message("To: undisclosed-recipients:;\r\n"),
        3,
    )
    .await;

    assert_eq!(delivered.len(), 3);

    for msg in &delivered {
        assert_eq!(msg.recipients.len(), 1, "expected one recipient per copy");
        let own = msg.recipients[0].as_str();
        let stripped = without_whitespace(&msg.body);
        assert!(
            stripped.contains("dkim2=pass"),
            "verifier did not report dkim2=pass for {own}: {}",
            msg.body
        );
        assert!(stripped.contains(&rt_token(own)));

        // No other recipient may appear in this copy
        for other in rcpts.iter().filter(|r| **r != own) {
            assert!(
                !stripped.contains(&rt_token(other)),
                "recipient {other} leaked into the copy for {own}: {}",
                msg.body
            );
            assert!(
                !msg.body.contains(other),
                "recipient {other} leaked into the copy for {own}: {}",
                msg.body
            );
        }
    }
}

#[tokio::test]
#[serial_test::serial]
async fn dkim1_and_dkim2_signed_together() {
    let (mut local, remote) = build_signer_and_verifier(19046, 19047, true).await;

    let delivered = deliver_and_collect(
        &mut local,
        &remote,
        "john@example.com",
        &["alice@foobar.org", "bob@foobar.org"],
        &message("To: Alice <alice@foobar.org>, Bob <bob@foobar.org>\r\n"),
        1,
    )
    .await;

    assert_eq!(delivered.len(), 1);
    let stripped = without_whitespace(&delivered[0].body);
    assert!(
        delivered[0].body.contains("DKIM-Signature"),
        "missing DKIM1 signature: {}",
        delivered[0].body
    );
    assert!(
        delivered[0].body.contains("DKIM2-Signature"),
        "missing DKIM2 signature: {}",
        delivered[0].body
    );
    assert!(
        stripped.contains("dkim=pass"),
        "DKIM1 did not pass: {}",
        delivered[0].body
    );
    assert!(
        stripped.contains("dkim2=pass"),
        "DKIM2 did not pass: {}",
        delivered[0].body
    );
}

#[tokio::test]
#[serial_test::serial]
async fn dkim2_dsn_is_signed() {
    let mut local = TestServerBuilder::new("dkim2_dsn_signer")
        .await
        .with_http_listener(19048)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = local.account("admin");
    admin.mta_allow_relaying().await;
    admin.mta_no_auth().await;
    admin.mta_all_extensions().await;
    admin.mta_disable_spam_filter().await;
    admin.mta_add_all_headers().await;
    let domain_id = admin.create_signing_domain(false).await;
    admin
        .registry_create_object(DsnReportSettings {
            dkim_sign_domain: expr("'example.com'"),
            ..Default::default()
        })
        .await;
    let _ = domain_id;
    admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    // Deliver to a domain with no DNS records: the lookup fails permanently and
    // a DSN is generated for the sender.
    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session
        .send_message(
            "john@example.com",
            &["bob@does-not-resolve.invalid"],
            &message("To: Bob <bob@does-not-resolve.invalid>\r\n"),
            "250",
        )
        .await;

    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());

    let dsn = local.expect_message().await;
    assert!(
        dsn.message.return_path.is_empty(),
        "expected a DSN (null return path)"
    );
    let body = dsn.read_message(&local).await;
    assert!(
        body.contains("Content-Type: multipart/report"),
        "not a DSN: {body}"
    );
    assert!(
        body.contains("DKIM2-Signature"),
        "the generated DSN was not DKIM2 signed: {body}"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn dkim2_inbound_dsn_validation() {
    let mut server = TestServerBuilder::new("dkim2_dsn_receiver")
        .await
        .with_http_listener(19049)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = server.account("admin");
    admin.mta_allow_relaying().await;
    admin.mta_no_auth().await;
    admin.mta_all_extensions().await;
    admin.mta_disable_spam_filter().await;
    admin.mta_add_all_headers().await;
    admin.configure_sender_auth("''").await;
    admin.reload_settings().await;
    server.reload_core();
    server.expect_reload_settings().await;

    // The returned message is signed by us (example.com); the DSN is signed by
    // the bouncing domain (foobar.org). Publish both keys.
    server
        .server
        .txt_add("ed._domainkey.example.com", dkim_dns_record(), valid());
    server
        .server
        .txt_add("ed._domainkey.foobar.org", dkim_dns_record(), valid());

    let returned = dkim2_sign(
        "example.com",
        "ed",
        RETURNED_PLAIN.as_bytes(),
        "john@example.com",
        &["bob@foobar.org"],
    );

    // A well-formed, aligned DSN is accepted
    let dsn_ok = build_dsn(&returned, true);
    let mut session = server.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.foobar.org").await;
    session
        .send_message(
            "<>",
            &["john@example.com"],
            &String::from_utf8(dsn_ok).unwrap(),
            "250",
        )
        .await;

    // Tampering the returned message body breaks its signature chain, so the DSN
    // is rejected.
    let returned_tampered = String::from_utf8(returned)
        .unwrap()
        .replace("DKIM2-ORIGINAL-BODY-CONTENT", "DKIM2-TAMPERED-BODY-CONTENT")
        .into_bytes();
    let dsn_bad = build_dsn(&returned_tampered, true);
    session
        .send_message(
            "<>",
            &["john@example.com"],
            &String::from_utf8(dsn_bad).unwrap(),
            "550",
        )
        .await;
}

impl Account {
    async fn create_signing_domain(&self, with_dkim1: bool) -> Id {
        let domain_id = self
            .registry_create_object(Domain {
                name: "example.com".into(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                allow_relaying: true,
                ..Default::default()
            })
            .await;

        self.registry_create_object(DkimSignature::Dkim2Ed25519Sha256(Dkim2Signature {
            stage: DkimRotationStage::Active,
            selector: "ed2".to_string(),
            domain_id,
            private_key: SecretText::Text(SecretTextValue {
                secret: ED_PRIVATE.to_string(),
            }),
            ..Default::default()
        }))
        .await;

        if with_dkim1 {
            self.registry_create_object(DkimSignature::Dkim1Ed25519Sha256(Dkim1Signature {
                stage: DkimRotationStage::Active,
                selector: "ed1".to_string(),
                canonicalization: DkimCanonicalization::RelaxedRelaxed,
                domain_id,
                private_key: SecretText::Text(SecretTextValue {
                    secret: ED_PRIVATE.to_string(),
                }),
                ..Default::default()
            }))
            .await;
        }

        domain_id
    }

    async fn configure_sender_auth(&self, dkim_sign_domain: &str) {
        self.registry_create_object(SenderAuth {
            dmarc_verify: expr("relaxed"),
            reverse_ip_verify: expr("relaxed"),
            spf_ehlo_verify: expr("relaxed"),
            spf_from_verify: expr("relaxed"),
            arc_verify: expr("relaxed"),
            dkim_sign_domain: expr(dkim_sign_domain),
            dkim_verify: expr("relaxed"),
            dkim_strict: false,
        })
        .await;
    }
}

async fn build_signer_and_verifier(
    http_local: u16,
    http_remote: u16,
    with_dkim1: bool,
) -> (TestServer, TestServer) {
    let mut local = TestServerBuilder::new("dkim2_signer")
        .await
        .with_http_listener(http_local)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("dkim2_verifier")
        .await
        .with_http_listener(http_remote)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    // Signer (originating MTA)
    let admin = local.account("admin");
    admin.mta_allow_relaying().await;
    admin.mta_no_auth().await;
    admin.mta_all_extensions().await;
    admin.mta_disable_spam_filter().await;
    admin.mta_add_all_headers().await;
    admin.create_signing_domain(with_dkim1).await;
    admin.configure_sender_auth("'example.com'").await;
    admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    // Verifier (receiving MTA)
    let remote_admin = remote.account("admin");
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_no_auth().await;
    remote_admin.mta_all_extensions().await;
    remote_admin.mta_disable_spam_filter().await;
    remote_admin.mta_add_all_headers().await;
    remote_admin.configure_sender_auth("''").await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Publish the signer's public keys in the verifier's DNS
    remote
        .server
        .txt_add("ed2._domainkey.example.com", dkim_dns_record(), valid());
    if with_dkim1 {
        remote
            .server
            .txt_add("ed1._domainkey.example.com", dkim_dns_record(), valid());
    }

    // Route foobar.org deliveries back to the local (in-process) receiver
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        valid(),
    );
    local
        .server
        .ipv4_add("mx.foobar.org", vec!["127.0.0.1".parse().unwrap()], valid());

    (local, remote)
}

fn message(to_header: &str) -> String {
    format!(
        concat!(
            "From: John Doe <john@example.com>\r\n",
            "{}",
            "Subject: DKIM2 privacy test\r\n",
            "\r\n",
            "This is a DKIM2 test message.\r\n",
        ),
        to_header
    )
}

fn build_dsn(returned: &[u8], sign_dsn: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: text/plain\r\n\r\n");
    body.extend_from_slice(b"Delivery to bob@foobar.org failed.\r\n");
    body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: message/delivery-status\r\n\r\n");
    body.extend_from_slice(b"Reporting-MTA: dns; foobar.org\r\n\r\n");
    body.extend_from_slice(b"Final-Recipient: rfc822; bob@foobar.org\r\n");
    body.extend_from_slice(b"Action: failed\r\nStatus: 5.1.1\r\n");
    body.extend_from_slice(b"--BOUNDARY\r\nContent-Type: message/rfc822\r\n\r\n");
    body.extend_from_slice(returned);
    body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");

    let mut dsn = Vec::new();
    dsn.extend_from_slice(b"From: postmaster@foobar.org\r\n");
    dsn.extend_from_slice(b"To: john@example.com\r\n");
    dsn.extend_from_slice(b"Subject: Delivery Status Notification (Failure)\r\n");
    dsn.extend_from_slice(b"Date: Sat, 01 Mar 2026 12:05:00 +0000\r\n");
    dsn.extend_from_slice(b"Message-ID: <dsn@foobar.org>\r\n");
    dsn.extend_from_slice(
        b"Content-Type: multipart/report; report-type=delivery-status; boundary=\"BOUNDARY\"\r\n\r\n",
    );
    dsn.extend_from_slice(&body);

    if sign_dsn {
        dkim2_sign("foobar.org", "ed", &dsn, "<>", &["john@example.com"])
    } else {
        dsn
    }
}

fn ed25519_key() -> Ed25519Key {
    let der = STANDARD
        .decode("MC4CAQAwBQYDK2VwBCIEIIOQVf8MDGvvmIkpUbgoqtyUIxjlzRqaBR6aP12tcGGE")
        .unwrap();
    Ed25519Key::from_pkcs8_maybe_unchecked_der(&der).unwrap()
}

fn dkim2_sign(
    domain: &str,
    selector: &str,
    message: &[u8],
    mail_from: &str,
    rcpt_to: &[&str],
) -> Vec<u8> {
    let signed = Dkim2Signer::from_key(ed25519_key())
        .domain(domain)
        .selector(selector)
        .sign(message, Hop::real(mail_from, rcpt_to))
        .expect("dkim2 sign");
    let mut out = signed.to_header().into_bytes();
    out.extend_from_slice(message);
    out
}

const RETURNED_PLAIN: &str = concat!(
    "From: John Doe <john@example.com>\r\n",
    "To: Bob <bob@foobar.org>\r\n",
    "Subject: Original message\r\n",
    "Date: Sat, 01 Mar 2026 12:00:00 +0000\r\n",
    "Message-ID: <original@example.com>\r\n",
    "\r\n",
    "DKIM2-ORIGINAL-BODY-CONTENT\r\n",
);

struct Delivered {
    recipients: Vec<String>,
    body: String,
}

async fn deliver_and_collect(
    local: &mut TestServer,
    remote: &TestServer,
    from: &str,
    rcpts: &[&str],
    raw: &str,
    expected: usize,
) -> Vec<Delivered> {
    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.example.com").await;
    session.send_message(from, rcpts, raw, "250").await;

    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());

    let mut delivered = Vec::new();
    for _ in 0..expected {
        let mut waited = 0;
        let msg = loop {
            if let Some(msg) = remote.read_queued_messages().await.into_iter().next() {
                break msg;
            }
            assert!(waited < 100, "timed out waiting for a delivered message");
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited += 1;
        };
        let body = msg.read_message(remote).await;
        let mut recipients = msg
            .message
            .recipients
            .iter()
            .map(|r| r.address().to_string())
            .collect::<Vec<_>>();
        recipients.sort();
        let due = remote.message_due(msg.queue_id).await;
        msg.clone().remove(&remote.server, due.into()).await;
        delivered.push(Delivered { recipients, body });
    }

    delivered
}

fn rt_token(address: &str) -> String {
    STANDARD.encode(format!("<{address}>"))
}

fn without_whitespace(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}

fn dkim_dns_record() -> DomainKey {
    DomainKey::parse(format!("v=DKIM1; k=ed25519; p={ED_PUBLIC}").as_bytes()).unwrap()
}

fn valid() -> Instant {
    Instant::now() + Duration::from_secs(300)
}

fn expr(value: &str) -> Expression {
    Expression {
        else_: value.into(),
        ..Default::default()
    }
}
