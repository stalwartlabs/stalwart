/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    imap::idle,
    utils::{
        imap::{ImapConnection, Type},
        server::TestServerBuilder,
    },
};
use imap_proto::ResponseType;
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        prelude::{ObjectType, Property, SocketAddr},
        structs::{
            ClusterListenerGroup, ClusterListenerGroupProperties, ClusterRole, ClusterTaskGroup,
            Coordinator, NatsCoordinator, NetworkListener, RedisStore,
        },
    },
    types::map::Map,
};
use serde_json::json;
use std::str::FromStr;
use store::registry::RegistryQuery;
use types::id::Id;

pub const NUM_NODES: usize = 3;

#[tokio::test(flavor = "multi_thread")]
pub async fn cluster_tests() {
    println!("Running cluster broadcast tests...");
    let mut servers = Vec::with_capacity(NUM_NODES);

    let coordinator_id = std::env::var("COORDINATOR").expect(concat!(
        "Missing coordinator type. Try running `STORE=<store_type> ",
        "COORDINATOR=<coordinator_type> cargo test`"
    ));
    let coordinator = match coordinator_id.as_str() {
        "Nats" => {
            crate::utils::containers::ensure_nats().await;
            Coordinator::Nats(NatsCoordinator {
                addresses: Map::new(vec!["127.0.0.1:4222".to_string()]),
                use_tls: false,
                ..Default::default()
            })
        }
        "Redis" => {
            crate::utils::containers::ensure_redis().await;
            Coordinator::Redis(RedisStore {
                url: "redis://127.0.0.1".to_string(),
                ..Default::default()
            })
        }
        _ => panic!("Unsupported coordinator type: {}", coordinator_id),
    };

    // Create initial server
    let test = TestServerBuilder::new("cluster_test_0")
        .await
        .with_object(coordinator)
        .await
        .with_listener(NetworkListenerProtocol::Http, "http_0", 11000, true)
        .await
        .with_imap_listener(12000)
        .await
        .with_listener(NetworkListenerProtocol::Lmtp, "lmtp_0", 11200, false)
        .await
        .build()
        .await;
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    let account = admin
        .create_user_account(
            "jdoe@example.com",
            "this is john's secret",
            "John's account",
            &[],
            vec![],
        )
        .await;
    admin.reload_settings().await;

    // Create listeners
    let mut listeners = vec![
        test.server
            .registry()
            .query::<Vec<Id>>(RegistryQuery::new(ObjectType::NetworkListener))
            .await
            .unwrap(),
    ];
    for node_id in 1..NUM_NODES {
        let http_listener_id = admin
            .registry_create_object(NetworkListener {
                name: format!("http_{}", node_id),
                bind: Map::new(vec![
                    SocketAddr::from_str(&format!("127.0.0.1:1100{node_id}")).unwrap(),
                ]),
                protocol: NetworkListenerProtocol::Http,
                tls_implicit: true,
                use_tls: true,
                ..Default::default()
            })
            .await;
        let imap_listener_id = admin
            .registry_create_object(NetworkListener {
                name: format!("imap_{}", node_id),
                bind: Map::new(vec![
                    SocketAddr::from_str(&format!("127.0.0.1:1200{node_id}")).unwrap(),
                ]),
                protocol: NetworkListenerProtocol::Imap,
                tls_implicit: false,
                use_tls: true,
                ..Default::default()
            })
            .await;
        listeners.push(vec![http_listener_id, imap_listener_id]);
    }

    // Create node roles
    for (role_id, listener_ids) in listeners.into_iter().enumerate() {
        admin
            .registry_create_object(ClusterRole {
                name: format!("role_{role_id}"),
                listeners: ClusterListenerGroup::EnableSome(ClusterListenerGroupProperties {
                    listener_ids: Map::new(listener_ids),
                }),
                tasks: ClusterTaskGroup::EnableAll,
                description: None,
            })
            .await;
    }
    servers.push(test);

    // Build additional servers
    for node_id in 1..NUM_NODES {
        let test = TestServerBuilder::new_with_role(
            &format!("cluster_test_{node_id}"),
            format!("mail-{node_id}.example.com"),
            Some(format!("role_{node_id}")),
            false,
        )
        .await
        .build_with_opts(false)
        .await;

        // Verify that the server was assigned the correct node id
        assert_eq!(test.server.registry().node_id(), node_id as u16);
        servers.push(test);
    }

    // Verify cross-cluster cache invalidations
    let admin = servers[0].account("admin");
    let server1 = &servers[1].server;
    let server2 = &servers[2].server;
    let account_id = account.id().document_id();
    assert_eq!(
        server1
            .account(account_id)
            .await
            .unwrap()
            .description
            .as_deref(),
        Some("John's account")
    );
    assert_eq!(
        server2
            .account(account_id)
            .await
            .unwrap()
            .description
            .as_deref(),
        Some("John's account")
    );
    admin
        .registry_update_object(
            ObjectType::Account,
            account.id(),
            json!({
                Property::Description: "John Doe"
            }),
        )
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        server1
            .account(account_id)
            .await
            .unwrap()
            .description
            .as_deref(),
        Some("John Doe")
    );
    assert_eq!(
        server2
            .account(account_id)
            .await
            .unwrap()
            .description
            .as_deref(),
        Some("John Doe")
    );

    // Run IMAP idle tests across nodes
    let mut node1_client = imap_client("jdoe@example.com", "this is john's secret", 1).await;
    let mut node2_client = imap_client("jdoe@example.com", "this is john's secret", 2).await;
    idle::test(&mut node1_client, &mut node2_client, true).await;
}

async fn imap_client(login: &str, secret: &str, node_id: u32) -> ImapConnection {
    let mut conn = ImapConnection::connect_to(b"A1 ", format!("127.0.0.1:1200{node_id}")).await;
    conn.assert_read(Type::Untagged, ResponseType::Ok).await;
    conn.authenticate(login, secret).await;
    conn
}
