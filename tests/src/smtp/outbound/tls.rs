/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::{
        inbound::TestMessage,
        session::{TestSession, VerifyResponse},
    },
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use mail_auth::{DnssecStatus, MX};
use registry::{
    schema::{
        enums::MtaRequiredOrOptional,
        structs::{
            Expression, ExpressionMatch, MtaConnectionStrategy, MtaDeliverySchedule,
            MtaOutboundStrategy, MtaTlsStrategy, MtaVirtualQueue,
        },
    },
    types::list::List,
};
use std::time::{Duration, Instant};
use store::write::now;

#[tokio::test]
#[serial_test::serial]
async fn starttls_optional() {
    let mut local = TestServerBuilder::new("smtp_starttls_local")
        .await
        .with_http_listener(19034)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;
    let mut remote = TestServerBuilder::new("smtp_starttls_remote")
        .await
        .with_http_listener(19035)
        .await
        .with_smtp_listener(9925)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin.mta_no_auth().await;
    local_admin.mta_allow_relaying().await;
    local_admin
        .registry_create_object(MtaOutboundStrategy {
            tls: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "retry_num > 0 && last_error == 'tls'".into(),
                    then: "'no-tls'".into(),
                }]),
                else_: "'default'".into(),
            },
            connection: Expression {
                else_: "'badtls'".into(),
                ..Default::default()
            },
            schedule: Expression {
                else_: "'default'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    let queue_id = local_admin
        .registry_create_object(MtaVirtualQueue {
            name: "default".into(),
            threads_per_node: 25,
            description: None,
        })
        .await;
    local_admin
        .registry_create_object(MtaDeliverySchedule {
            name: "default".into(),
            queue_id,
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaConnectionStrategy {
            name: "badtls".into(),
            ehlo_hostname: "badtls.foobar.org".to_string().into(),
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaTlsStrategy {
            name: "no-tls".into(),
            allow_invalid_certs: true,
            start_tls: MtaRequiredOrOptional::Disable,
            ..Default::default()
        })
        .await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    let remote_admin = remote.account("admin");
    remote_admin.mta_no_auth().await;
    remote_admin.mta_allow_relaying().await;
    remote_admin.mta_allow_non_fqdn().await;
    remote_admin.mta_all_extensions().await;
    remote_admin.reload_settings().await;
    remote.reload_core();
    remote.expect_reload_settings().await;

    // Add mock DNS entries
    local.server.mx_add(
        "foobar.org",
        vec![MX {
            exchanges: vec!["mx.foobar.org".into()].into_boxed_slice(),
            preference: 10,
        }],
        DnssecStatus::Secure,
        Instant::now() + Duration::from_secs(10),
    );
    local.server.ipv4_add(
        "mx.foobar.org",
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;
    local
        .expect_message_for_queue_then_deliver("default")
        .await
        .try_deliver(local.server.clone());
    let mut retry = local.expect_message().await;
    let prev_due = retry.message.recipients[0].retry.due;
    let next_due = now();
    let queue_id = retry.queue_id;
    retry.message.recipients[0].retry.due = next_due;
    retry.save_changes(&local.server, prev_due.into()).await;
    local
        .delivery_attempt_for_queue(queue_id, "default")
        .await
        .try_deliver(local.server.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    remote
        .expect_message()
        .await
        .read_lines(&remote)
        .await
        .assert_not_contains("using TLSv1.3 with cipher");
}
