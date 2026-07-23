/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::session::{TestSession, VerifyResponse},
    utils::server::TestServerBuilder,
};
use registry::{
    schema::structs::{Expression, ExpressionMatch, MtaInboundSession},
    types::list::List,
};
use std::time::{Duration, Instant};

#[tokio::test]
async fn limits() {
    let mut test = TestServerBuilder::new("smtp_inbound_limits_test")
        .await
        .with_http_listener(19013)
        .await
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin
        .registry_create_object(MtaInboundSession {
            max_duration: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.3'".into(),
                    then: "500ms".into(),
                }]),
                else_: "60m".into(),
            },
            timeout: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.2'".into(),
                    then: "500ms".into(),
                }]),
                else_: "30m".into(),
            },
            transfer_limit: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "remote_ip = '10.0.0.1'".into(),
                    then: "10".into(),
                }]),
                else_: "1024".into(),
            },
        })
        .await;
    admin.reload_settings().await;
    test.reload_core();

    // Exceed max line length
    let (mut session, _tx) = test.new_mta_session_with_shutdown();
    session.data.remote_ip_str = "10.0.0.1".into();
    let mut buf = vec![b'A'; 4097];
    session.ingest(&buf).await.unwrap();
    session.ingest(b"\r\n").await.unwrap();
    session.response().assert_code("554 5.3.4");

    // Invalid command
    buf.extend_from_slice(b"\r\n");
    session.ingest(&buf).await.unwrap();
    session.response().assert_code("500 5.5.1");

    // Exceed transfer quota
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("452 4.7.28");

    // Loitering
    session.data.remote_ip_str = "10.0.0.3".into();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("421 4.3.2");

    // Timeout
    session.data.remote_ip_str = "10.0.0.2".into();
    session.data.valid_until = Instant::now();
    session.eval_session_params().await;
    session.write_rx("MAIL FROM:<this_is_a_long@command_over_10_chars.com>\r\n");
    session.handle_conn().await;
    session.response().assert_code("221 2.0.0");
}
