/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    system::authentication::validate_password_with_ip,
    utils::{
        http::HttpRequest,
        imap::{ImapConnection, Type},
        registry::UnwrapRegistryId,
        server::TestServer,
    },
};
use common::ipc::RegistryChange;
use imap_proto::ResponseType;
use jmap_client::{
    client::{Client, Credentials},
    mailbox::{self},
};
use registry::{
    schema::{
        enums::BlockReason,
        prelude::{ObjectType, Property},
        structs::{Action, BlockedIp, Http, Jmap},
    },
    types::ipmask::IpAddrOrMask,
};
use serde_json::json;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use store::{registry::write::RegistryWrite, write::now};
use types::id::Id;

pub async fn test(test: &mut TestServer) {
    println!("Running Security tests...");

    let admin = test.account("admin@example.org");

    // Set security settings
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: true,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin
        .registry_update_setting(
            Jmap {
                max_concurrent_uploads: Some(4),
                max_concurrent_requests: Some(8),
                max_upload_size: 5000000,
                ..Default::default()
            },
            &[
                Property::MaxConcurrentUploads,
                Property::MaxConcurrentRequests,
                Property::MaxUploadSize,
            ],
        )
        .await;
    admin.reload_settings().await;

    // Create a test user
    let user = test
        .create_user_account(
            "admin@example.org",
            "user@example.org",
            "this is a very strong password",
            &[],
            "user@example.org",
        )
        .await;
    let user_id = user.id();

    // Incorrect passwords should be rejected with a 401 error
    assert!(matches!(
        Client::new()
            .credentials(Credentials::basic("user@example.org", "abcde"))
            .accept_invalid_certs(true) .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await,
        Err(jmap_client::Error::Problem(err)) if err.status() == Some(401)));

    // Wait until the beginning of the 5 seconds bucket
    const LIMIT: u64 = 5;
    let now = now();
    let range_start = now / LIMIT;
    let range_end = (range_start * LIMIT) + LIMIT;
    tokio::time::sleep(Duration::from_secs(range_end - now)).await;

    // Make sure that the IP address is not blocked before the test
    assert_eq!(
        admin
            .registry_query_ids(
                ObjectType::BlockedIp,
                Vec::<(&str, &str)>::new(),
                Vec::<&str>::new()
            )
            .await,
        Vec::<Id>::new()
    );

    for _ in 0..98 {
        validate_password_with_ip("unknown@example.org", "wrong password", "127.0.0.1", false)
            .await;
    }

    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.send("AUTHENTICATE PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;

    // There are already 100 failed login attempts for this IP address
    // so the next one should be rejected, even if done over IMAP
    imap.send("AUTHENTICATE PLAIN AGpvaG4AY2hpbWljaGFuZ2Fz")
        .await;
    imap.assert_disconnect().await;

    // Make sure the IP address is blocked
    let blocked_id = test
        .server
        .registry()
        .primary_key(
            ObjectType::BlockedIp.into(),
            Property::Address,
            IpAddrOrMask::from_ip(Ipv4Addr::LOCALHOST.into()).to_index_key(),
        )
        .await
        .unwrap()
        .expect("Blocked IP should have been created after too many failed login attempts");
    let blocked_ip = test
        .server
        .registry()
        .object::<BlockedIp>(blocked_id.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked_ip.reason, BlockReason::AuthFailure);

    ImapConnection::connect(b"_y ")
        .await
        .assert_disconnect()
        .await;

    // Lift ban
    test.server
        .registry()
        .write(RegistryWrite::delete(blocked_id))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    test.server
        .reload_registry(RegistryChange::Delete(blocked_id))
        .await
        .unwrap();

    // Valid authentication requests should not be rate limited
    for _ in 0..110 {
        validate_password_with_ip(
            "user@example.org",
            "this is a very strong password",
            "127.0.0.1",
            true,
        )
        .await;
    }

    // Set fail2ban expiration
    admin
        .registry_update_object(
            ObjectType::Security,
            Id::singleton(),
            json!({
                Property::AuthBanPeriod: registry::types::duration::Duration::from_millis(1000)
            }),
        )
        .await;
    admin.reload_settings().await;

    // Block IP 10.0.0.2
    for _ in 0..105 {
        validate_password_with_ip("unknown@example.org", "wrong password", "10.0.0.2", false).await;
    }
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        false,
    )
    .await;

    // Check that the IP is blocked
    let blocked_ids = admin
        .registry_query_ids(
            ObjectType::BlockedIp,
            [(Property::Address, "10.0.0.2")],
            Vec::<&str>::new(),
        )
        .await;
    assert_eq!(blocked_ids.len(), 1);
    let blocked_ip = admin.registry_get::<BlockedIp>(blocked_ids[0]).await;
    assert_eq!(blocked_ip.reason, BlockReason::AuthFailure);
    assert!(blocked_ip.expires_at.is_some());

    // After 1 second the ban should be lifted
    tokio::time::sleep(Duration::from_secs(2)).await;
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        true,
    )
    .await;

    // Make sure the IP remains unblocked after reload
    admin.registry_create_object(Action::ReloadBlockedIps).await;
    validate_password_with_ip(
        "user@example.org",
        "this is a very strong password",
        "10.0.0.2",
        true,
    )
    .await;

    // Login with the correct credentials
    let client = Client::new()
        .credentials(Credentials::basic(
            "user@example.org",
            "this is a very strong password",
        ))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect("https://127.0.0.1:8899")
        .await
        .unwrap();
    assert_eq!(client.session().username(), "user@example.org");
    assert_eq!(
        client
            .session()
            .account(&user_id.to_string())
            .unwrap()
            .name(),
        "user@example.org"
    );
    assert!(
        client
            .session()
            .account(&user_id.to_string())
            .unwrap()
            .is_personal()
    );

    // Uploads up to 5000000 bytes should be allowed
    assert_eq!(
        client
            .upload(None, vec![b'A'; 5000000], None)
            .await
            .unwrap()
            .size(),
        5000000
    );
    assert!(
        client
            .upload(None, vec![b'A'; 5000001], None)
            .await
            .is_err()
    );

    // Concurrent requests check
    let client = Arc::new(client);
    let raw_http =
        HttpRequest::with_credentials(8899, "user@example.org", "this is a very strong password");
    for _ in 0..8 {
        let client_ = client.clone();
        tokio::spawn(async move {
            let _ = client_
                .mailbox_query(
                    mailbox::query::Filter::name("__sleep").into(),
                    [mailbox::query::Comparator::name()].into(),
                )
                .await;
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let body = serde_json::to_vec(&json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [
            ["Mailbox/query", {
                "accountId": user_id.to_string(),
                "filter": { "name": "__sleep" }
            }, "c1"]
        ]
    }))
    .unwrap();
    let resp = raw_http
        .send_full(
            hyper::Method::POST,
            "/jmap/",
            Some(body),
            Some("application/json"),
        )
        .await;
    assert_eq!(
        resp.status.as_u16(),
        400,
        "concurrent-requests body: {}",
        resp.body
    );
    let policy = resp
        .rate_limit_policy()
        .unwrap_or_else(|| panic!("missing RateLimit-Policy header on {:?}", resp.headers));
    assert!(
        policy.contains("\"concurrent-requests\"") && policy.contains("q=8"),
        "RateLimit-Policy = {policy}"
    );
    assert!(
        policy.contains(r#"qu="concurrent-requests""#),
        "RateLimit-Policy = {policy}"
    );
    let state = resp
        .rate_limit()
        .unwrap_or_else(|| panic!("missing RateLimit header on {:?}", resp.headers));
    assert!(
        state.contains("\"concurrent-requests\"") && state.contains("r=0"),
        "RateLimit = {state}"
    );

    // Wait for sleep to be done
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Concurrent upload test
    for _ in 0..4 {
        let client_ = client.clone();
        tokio::spawn(async move {
            client_.upload(None, b"sleep".to_vec(), None).await.unwrap();
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let resp = raw_http
        .send_full(
            hyper::Method::POST,
            &format!("/jmap/upload/{user_id}"),
            Some(b"sleep".to_vec()),
            Some("application/octet-stream"),
        )
        .await;
    assert_eq!(
        resp.status.as_u16(),
        400,
        "concurrent-uploads body: {}",
        resp.body
    );
    let policy = resp
        .rate_limit_policy()
        .unwrap_or_else(|| panic!("missing RateLimit-Policy header on {:?}", resp.headers));
    assert!(
        policy.contains("\"concurrent-uploads\"") && policy.contains("q=4"),
        "RateLimit-Policy = {policy}"
    );
    let state = resp
        .rate_limit()
        .unwrap_or_else(|| panic!("missing RateLimit header on {:?}", resp.headers));
    assert!(
        state.contains("\"concurrent-uploads\"") && state.contains("r=0"),
        "RateLimit = {state}"
    );

    // Wait for sleep to be done before continuing
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Disable X-Forwarded-For processing
    admin
        .registry_update_setting(
            Http {
                use_x_forwarded: false,
                ..Default::default()
            },
            &[Property::UseXForwarded],
        )
        .await;
    admin.reload_settings().await;

    // Destroy account
    admin.destroy_account(user).await;

    test.cleanup().await;
}
