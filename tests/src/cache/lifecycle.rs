/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::{Server, auth::AccessToken, cache::swap::SwapKey};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::INBOX_ID,
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use groupware::cache::GroupwareCache;
use mail_parser::MessageParser;
use types::collection::SyncCollection;

pub async fn test(test: &TestServer, account_id: u32) {
    println!("Running cache swap lifecycle tests...");

    message_cache_survives_an_eviction(test, account_id).await;
    resource_cache_survives_an_eviction(test, account_id).await;
    a_snapshot_from_the_future_is_discarded(test, account_id).await;

    test.server
        .inner
        .cache
        .swap
        .remove_account(account_id)
        .await;
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
