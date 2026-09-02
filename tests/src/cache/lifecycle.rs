/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::{
    Server,
    auth::AccessToken,
    cache::{
        invalidate::CacheInvalidationBuilder,
        swap::{SwapKey, SwapPart},
    },
    ipc::CacheInvalidation,
};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::INBOX_ID,
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use groupware::{cache::GroupwareCache, file::FileNode};
use mail_parser::MessageParser;
use store::write::BatchBuilder;
use types::collection::{Collection, SyncCollection};

pub async fn test(test: &TestServer, account_id: u32) {
    println!("Running cache swap lifecycle tests...");

    message_cache_survives_an_eviction(test, account_id).await;
    resource_cache_survives_an_eviction(test, account_id).await;
    a_snapshot_from_the_future_is_discarded(test, account_id).await;
    an_update_is_persisted_once(test, account_id).await;
    an_uncacheable_account_is_persisted_on_a_cadence(test, account_id).await;
    a_destroyed_account_leaves_no_snapshot(test, account_id).await;
}

async fn ingest(server: &Server, account_id: u32, subject: &str, received_at: u64) -> u32 {
    let raw = format!(
        "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: {subject}\r\n\r\nbody\r\n"
    );
    server
        .email_ingest(IngestEmail {
            raw_message: raw.as_bytes(),
            message: MessageParser::new().parse(raw.as_bytes()),
            blob_hash: None,
            access_token: &AccessToken::from_id_maybe_invalid(account_id),
            mailbox_ids: vec![INBOX_ID],
            keywords: vec![],
            received_at: Some(received_at),
            source: IngestSource::Restore,
            session_id: 0,
        })
        .await
        .unwrap()
        .document_id
}

async fn message_cache_survives_an_eviction(test: &TestServer, account_id: u32) {
    let server = &test.server;

    server
        .get_cached_messages(account_id)
        .await
        .expect("failed to settle the message cache");

    for i in 0..40u32 {
        ingest(
            server,
            account_id,
            &format!("swap-{i}"),
            1_700_000_000 + i as u64,
        )
        .await;
    }

    let before = server.get_cached_messages(account_id).await.unwrap();
    assert!(before.emails.len() >= 40);

    server.inner.cache.swap.flush().await;

    let key = SwapKey::messages(account_id);
    let snapshot = server
        .inner
        .cache
        .swap
        .load(key)
        .await
        .expect("swap load failed")
        .expect("no snapshot was written for the message cache");
    assert!(!snapshot.is_empty());

    server.inner.cache.messages.remove(&account_id);
    assert!(
        server.inner.cache.messages.peek(&account_id).is_none(),
        "the message cache entry was not evicted"
    );

    let after = server.get_cached_messages(account_id).await.unwrap();
    assert_eq!(
        before.emails.len(),
        after.emails.len(),
        "the restored message cache lost messages"
    );
    assert_eq!(
        before.last_change_id, after.last_change_id,
        "the restored message cache is at a different change id"
    );
    for (a, b) in before.emails.iter().zip(after.emails.iter()) {
        assert_eq!(a.document_id(), b.document_id());
        assert_eq!(a.received_at(), b.received_at());
        assert_eq!(a.keywords(), b.keywords());
        assert_eq!(a.mailboxes(), b.mailboxes());
    }
    assert_eq!(
        before.in_mailbox(INBOX_ID).count(),
        after.in_mailbox(INBOX_ID).count(),
        "the restored message cache lost mailbox membership"
    );

    let document_id = ingest(server, account_id, "after-restore", 1_800_000_000).await;
    let caught_up = server.get_cached_messages(account_id).await.unwrap();
    assert_eq!(caught_up.emails.len(), after.emails.len() + 1);
    assert!(
        caught_up.emails.contains(document_id),
        "a message ingested after the restore is missing from the cache"
    );

    server.inner.cache.messages.remove(&account_id);
    let restored = server.get_cached_messages(account_id).await.unwrap();
    assert_eq!(
        restored.emails.len(),
        caught_up.emails.len(),
        "the change-log catch-up after a restore lost a message"
    );
    assert!(restored.emails.contains(document_id));
}

async fn resource_cache_survives_an_eviction(test: &TestServer, account_id: u32) {
    let server = &test.server;

    let before = server
        .fetch_dav_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();

    server.inner.cache.swap.flush().await;

    server.inner.cache.events.remove(&account_id);
    assert!(server.inner.cache.events.peek(&account_id).is_none());

    let after = server
        .fetch_dav_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();

    assert_eq!(
        before.resources.len(),
        after.resources.len(),
        "the restored resource cache lost resources"
    );
    assert_eq!(before.paths.len(), after.paths.len());
    assert_eq!(before.highest_change_id, after.highest_change_id);
    for (a, b) in before.resources.iter().zip(after.resources.iter()) {
        assert_eq!(a.document_id(), b.document_id());
        assert_eq!(a.is_container(), b.is_container());
    }
}

async fn an_update_is_persisted_once(test: &TestServer, account_id: u32) {
    let server = &test.server;

    server.get_cached_messages(account_id).await.unwrap();
    server.inner.cache.swap.flush().await;

    let changes = 5u64;
    let before = server.inner.cache.swap.snapshots_written();
    for i in 0..changes {
        ingest(
            server,
            account_id,
            &format!("cadence-{i}"),
            1_900_000_000 + i,
        )
        .await;
        server.get_cached_messages(account_id).await.unwrap();
    }
    server.inner.cache.swap.flush().await;

    let written = server.inner.cache.swap.snapshots_written() - before;
    assert!(
        written <= changes,
        "{changes} changes produced {written} snapshot writes; a cache update is still \
         enqueuing the snapshot it displaced, which doubles every write"
    );
}

async fn an_uncacheable_account_is_persisted_on_a_cadence(test: &TestServer, account_id: u32) {
    let server = &test.server;
    let key = SwapKey::new(account_id, SyncCollection::FileNode, SwapPart::Resources);
    server.inner.cache.swap.remove(key).await.unwrap();

    let access_token = AccessToken::from_id_maybe_invalid(account_id);
    let mut batch = BatchBuilder::new();
    for i in 0..40u32 {
        let document_id = batch.reserve_document_id(account_id, Collection::FileNode);
        FileNode {
            name: format!("swap-folder-{i:04}-with-a-name-long-enough-to-weigh"),
            ..Default::default()
        }
        .insert(
            access_token.account_tenant_ids(),
            account_id,
            document_id,
            true,
            true,
            &mut batch,
        )
        .expect("failed to stage a file node");
    }
    server
        .commit_batch(batch)
        .await
        .expect("failed to create the file nodes");

    let resources = server
        .fetch_dav_resources(account_id, account_id, SyncCollection::FileNode)
        .await
        .unwrap();
    assert!(
        server.inner.cache.files.peek(&account_id).is_none(),
        "the file cache budget is not small enough for this test to exercise the \
         uncacheable path"
    );
    server.inner.cache.swap.flush().await;

    let snapshot = server
        .inner
        .cache
        .swap
        .load(key)
        .await
        .unwrap()
        .expect("an account that is too large to cache was never persisted");
    assert_eq!(
        u64::from_le_bytes(snapshot[8..16].try_into().unwrap()),
        resources.highest_change_id,
        "the persisted snapshot is not at the change id of the account"
    );

    let before = server.inner.cache.swap.snapshots_written();
    for _ in 0..5 {
        server
            .fetch_dav_resources(account_id, account_id, SyncCollection::FileNode)
            .await
            .unwrap();
    }
    server.inner.cache.swap.flush().await;

    assert_eq!(
        server.inner.cache.swap.snapshots_written(),
        before,
        "an account that is too large to cache wrote a snapshot on every request"
    );
}

async fn a_destroyed_account_leaves_no_snapshot(test: &TestServer, account_id: u32) {
    let server = &test.server;

    server.get_cached_messages(account_id).await.unwrap();
    server.inner.cache.swap.flush().await;
    assert!(
        server
            .inner
            .cache
            .swap
            .load(SwapKey::messages(account_id))
            .await
            .unwrap()
            .is_some(),
        "the account under test has no snapshot to destroy"
    );

    server
        .invalidate_caches(CacheInvalidationBuilder::from(
            CacheInvalidation::MessageCache(account_id),
        ))
        .await
        .unwrap();
    server.inner.cache.swap.forget(account_id);
    server.inner.cache.swap.remove_account(account_id).await;

    assert!(
        server.inner.cache.messages.peek(&account_id).is_none(),
        "the destroyed account is still resident in the message cache"
    );

    server.inner.cache.swap.flush().await;
    for key in SwapKey::all_parts(account_id) {
        assert!(
            server.inner.cache.swap.load(key).await.unwrap().is_none(),
            "a snapshot of the destroyed account came back after a flush"
        );
    }
}

async fn a_snapshot_from_the_future_is_discarded(test: &TestServer, account_id: u32) {
    let server = &test.server;
    let key = SwapKey::messages(account_id);

    let expected = server.get_cached_messages(account_id).await.unwrap();
    server.inner.cache.swap.flush().await;

    let mut snapshot = server
        .inner
        .cache
        .swap
        .load(key)
        .await
        .unwrap()
        .expect("no snapshot to tamper with");

    let change_id = u64::from_le_bytes(snapshot[8..16].try_into().unwrap());
    snapshot[8..16].copy_from_slice(&(change_id + 1_000_000).to_le_bytes());
    server.inner.cache.swap.store(key, &snapshot).await.unwrap();

    server.inner.cache.messages.remove(&account_id);
    let rebuilt = server.get_cached_messages(account_id).await.unwrap();
    assert_eq!(
        rebuilt.emails.len(),
        expected.emails.len(),
        "the fallback rebuild after discarding a future snapshot lost messages"
    );
    assert_eq!(rebuilt.last_change_id, expected.last_change_id);
}
