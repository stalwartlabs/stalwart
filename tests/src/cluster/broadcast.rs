/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ClusterTest;
use crate::imap::idle;
use directory::backend::internal::{
    PrincipalAction, PrincipalField, PrincipalUpdate, PrincipalValue,
    manage::{ManageDirectory, UpdatePrincipal},
};
use groupware::cache::GroupwareCache;
use std::net::IpAddr;
use types::collection::SyncCollection;

pub async fn test(cluster: &ClusterTest) {
    println!("Running cluster broadcast tests...");

    // Run IMAP idle tests across nodes
    let server1 = cluster.server(1);
    let server2 = cluster.server(2);
    let mut node1_client = cluster.imap_client("john", 1).await;
    let mut node2_client = cluster.imap_client("john", 2).await;
    idle::test(&mut node1_client, &mut node2_client, true).await;

    // Test event broadcast
    let test_ip: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(!server1.is_ip_blocked(&test_ip));
    assert!(!server2.is_ip_blocked(&test_ip));
    server1.block_ip(test_ip).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(server1.is_ip_blocked(&test_ip));
    assert!(server2.is_ip_blocked(&test_ip));

    // Change John's password and expect it to propagate
    let account_id = cluster.account_id("john");
    assert!(server1.inner.cache.access_tokens.get(&account_id).is_some());
    assert!(server2.inner.cache.access_tokens.get(&account_id).is_some());
    let changes = server1
        .core
        .storage
        .data
        .update_principal(
            UpdatePrincipal::by_id(account_id).with_updates(vec![PrincipalUpdate {
                action: PrincipalAction::AddItem,
                field: PrincipalField::Secrets,
                value: PrincipalValue::String("hello".into()),
            }]),
        )
        .await
        .unwrap();
    server1.invalidate_principal_caches(changes).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(server1.inner.cache.access_tokens.get(&account_id).is_none());
    assert!(server2.inner.cache.access_tokens.get(&account_id).is_none());

    // Rename John to Juan and expect DAV caches to be invalidated
    let access_token = server1.get_access_token(account_id).await.unwrap();
    server1
        .fetch_dav_resources(&access_token, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    server2
        .fetch_dav_resources(&access_token, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    assert!(server1.inner.cache.events.get(&account_id).is_some());
    assert!(server2.inner.cache.events.get(&account_id).is_some());
    let changes = server1
        .core
        .storage
        .data
        .update_principal(
            UpdatePrincipal::by_id(account_id).with_updates(vec![PrincipalUpdate {
                action: PrincipalAction::Set,
                field: PrincipalField::Name,
                value: PrincipalValue::String("juan".into()),
            }]),
        )
        .await
        .unwrap();
    server1.invalidate_principal_caches(changes).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(server1.inner.cache.events.get(&account_id).is_none());
    assert!(server2.inner.cache.events.get(&account_id).is_none());
}
