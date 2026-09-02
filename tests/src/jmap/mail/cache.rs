/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::{MessageStoreCache, Server, auth::AccessToken};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        delete::EmailDeletion,
        ingest::{EmailIngest, IngestEmail, IngestSource},
        messagedata::{KeywordDiff, merge_keywords},
    },
};
use email::{
    mailbox::INBOX_ID,
    message::sortkeys::{EmailSortKeys, MessageCacheField, MessageComparator},
};
use mail_parser::MessageParser;
use std::sync::Arc;
use store::{
    rand::{self, RngExt},
    roaring::RoaringBitmap,
    write::BatchBuilder,
};
use store::{search::SearchQuery, write::SearchIndex};
use types::{collection::Collection, keyword::Keyword};

pub async fn test(test: &TestServer) {
    println!("Running message cache tests...");

    received_order_survives_an_out_of_order_insert(test).await;
    received_order_survives_a_flag_toggle(test).await;
    mailbox_membership_survives_an_unrelated_mutation(test).await;
    tie_order_is_stable_across_a_rebuild(test).await;
    received_at_query_is_a_total_order(test).await;
    merge_agrees_with_a_full_rebuild(test).await;

    test.destroy_all_mailboxes(test.account("jdoe@example.com"))
        .await;
    test.assert_is_empty().await;
}

async fn ingest(
    server: &Server,
    account_id: u32,
    subject: &str,
    received_at: u64,
    mailbox_ids: Vec<u32>,
) -> u32 {
    let raw = format!(
        "From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: {subject}\r\n\r\nbody\r\n"
    );
    server
        .email_ingest(IngestEmail {
            raw_message: raw.as_bytes(),
            message: MessageParser::new().parse(raw.as_bytes()),
            blob_hash: None,
            access_token: &AccessToken::from_id_maybe_invalid(account_id),
            mailbox_ids,
            keywords: vec![],
            received_at: Some(received_at),
            source: IngestSource::Restore,
            session_id: 0,
        })
        .await
        .unwrap()
        .document_id
}

async fn toggle_keyword(server: &Server, account_id: u32, document_id: u32, keyword: Keyword) {
    let cache = server.get_cached_messages(account_id).await.unwrap();
    let item = cache.email_by_id(&document_id).unwrap();
    let thread_id = item.thread_id();
    let mut keywords = cache.expand_keywords(item).collect::<Vec<_>>();
    if let Some(pos) = keywords.iter().position(|k| *k == keyword) {
        keywords.remove(pos);
    } else {
        keywords.push(keyword);
    }
    let diff = KeywordDiff::replace(keywords);

    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Email)
        .with_document(document_id);
    merge_keywords(&mut batch, thread_id, diff);
    server.commit_batch(batch).await.unwrap();
}

async fn delete(server: &Server, account_id: u32, document_ids: RoaringBitmap) {
    let mut batch = BatchBuilder::new();
    server
        .emails_delete(account_id, None, &mut batch, document_ids)
        .await
        .unwrap();
    if !batch.is_empty() {
        server.commit_batch(batch).await.unwrap();
    }
}

fn received_order(cache: &MessageStoreCache) -> Vec<(u64, u32)> {
    cache
        .emails
        .iter()
        .map(|item| (item.received_at(), item.document_id()))
        .collect()
}

async fn rebuilt_from_scratch(server: &Server, account_id: u32) -> Arc<MessageStoreCache> {
    server.inner.cache.messages.remove(&account_id);
    server.get_cached_messages(account_id).await.unwrap()
}

fn assert_sorted(cache: &MessageStoreCache, context: &str) {
    let order = received_order(cache);
    for pair in order.windows(2) {
        assert!(
            pair[0] < pair[1],
            "{context}: items are not ordered by (received_at, document_id): {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

async fn account_for(test: &TestServer, server: &Server, name: &str) -> u32 {
    let account_id = test.account(name).id().document_id();
    server.inner.cache.messages.remove(&account_id);
    let existing = server
        .get_cached_messages(account_id)
        .await
        .unwrap()
        .email_document_ids();
    if !existing.is_empty() {
        delete(server, account_id, existing).await;
    }
    account_id
}

async fn received_order_survives_an_out_of_order_insert(test: &TestServer) {
    let server = &test.server;
    let account_id = account_for(test, server, "jdoe@example.com").await;

    let base = 1_700_000_000u64;
    for i in 0..20u64 {
        ingest(
            server,
            account_id,
            &format!("recent {i}"),
            base + i * 60,
            vec![INBOX_ID],
        )
        .await;
    }
    let cache = server.get_cached_messages(account_id).await.unwrap();
    assert_sorted(&cache, "before the out-of-order insert");

    let old_id = ingest(
        server,
        account_id,
        "ancient",
        base - 86_400 * 365,
        vec![INBOX_ID],
    )
    .await;

    let cache = server.get_cached_messages(account_id).await.unwrap();
    assert_sorted(&cache, "after an insert with an older received_at");
    assert_eq!(
        cache.emails.at(0).map(|item| item.document_id()),
        Some(old_id),
        "the message with the oldest received_at must sort first despite the highest document id"
    );
    assert_eq!(
        received_order(&cache),
        received_order(rebuilt_from_scratch(server, account_id).await.as_ref()),
        "the merged order must match a full rebuild"
    );

    delete(
        server,
        account_id,
        server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids(),
    )
    .await;
}

async fn received_order_survives_a_flag_toggle(test: &TestServer) {
    let server = &test.server;
    let account_id = account_for(test, server, "jdoe@example.com").await;

    let base = 1_700_000_000u64;
    let mut ids = Vec::new();
    for i in 0..20u64 {
        ids.push(
            ingest(
                server,
                account_id,
                &format!("msg {i}"),
                base + i * 60,
                vec![INBOX_ID],
            )
            .await,
        );
    }
    let before = received_order(&server.get_cached_messages(account_id).await.unwrap());

    toggle_keyword(server, account_id, ids[ids.len() / 2], Keyword::Seen).await;

    let cache = server.get_cached_messages(account_id).await.unwrap();
    assert_sorted(&cache, "after a flag toggle");
    assert_eq!(
        before,
        received_order(&cache),
        "toggling a flag on a middle message must not reorder the cache"
    );
    assert!(
        cache.has_keyword(
            cache.email_by_id(&ids[ids.len() / 2]).unwrap(),
            &Keyword::Seen
        ),
        "the toggled keyword must be visible in the merged cache"
    );

    delete(
        server,
        account_id,
        server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids(),
    )
    .await;
}

async fn mailbox_membership_survives_an_unrelated_mutation(test: &TestServer) {
    let server = &test.server;
    let account_id = account_for(test, server, "jdoe@example.com").await;

    let existing_mailboxes = server
        .get_cached_messages(account_id)
        .await
        .unwrap()
        .mailboxes
        .items
        .iter()
        .map(|mailbox| mailbox.document_id)
        .collect::<Vec<_>>();
    assert!(
        existing_mailboxes.len() >= 3,
        "the fixture needs at least three real mailboxes, found {existing_mailboxes:?}"
    );

    let base = 1_700_000_000u64;
    let mut ids = Vec::new();
    for i in 0..300u64 {
        let mut mailbox_ids = vec![existing_mailboxes[0]];
        if i % 3 == 0 {
            mailbox_ids.push(existing_mailboxes[1]);
        }
        if i % 7 == 0 {
            mailbox_ids.push(existing_mailboxes[2]);
        }
        ids.push(
            ingest(
                server,
                account_id,
                &format!("msg {i}"),
                base + i * 60,
                mailbox_ids,
            )
            .await,
        );
    }

    let membership = |cache: &MessageStoreCache| {
        cache
            .emails
            .iter()
            .map(|item| {
                let mut mailboxes = item
                    .mailboxes()
                    .iter()
                    .map(|uid| uid.mailbox_id)
                    .collect::<Vec<_>>();
                mailboxes.sort_unstable();
                (item.document_id(), mailboxes)
            })
            .collect::<Vec<_>>()
    };

    let before = membership(&server.get_cached_messages(account_id).await.unwrap());
    assert!(
        before.iter().any(|(_, mailboxes)| mailboxes.len() > 1),
        "the fixture must contain messages filed in more than one mailbox"
    );

    toggle_keyword(server, account_id, ids[123], Keyword::Flagged).await;

    let cache = server.get_cached_messages(account_id).await.unwrap();
    let after = membership(&cache);
    assert_eq!(
        before, after,
        "mutating one message must not change any other message's mailbox set"
    );
    assert_eq!(
        after,
        membership(rebuilt_from_scratch(server, account_id).await.as_ref()),
        "merged mailbox membership must match a full rebuild"
    );

    delete(
        server,
        account_id,
        server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids(),
    )
    .await;
}

async fn tie_order_is_stable_across_a_rebuild(test: &TestServer) {
    let server = &test.server;
    let account_id = account_for(test, server, "jdoe@example.com").await;

    let tied_at = 1_700_000_000u64;
    for i in 0..25u64 {
        ingest(
            server,
            account_id,
            &format!("tied {i}"),
            tied_at,
            vec![INBOX_ID],
        )
        .await;
    }

    let merged = received_order(&server.get_cached_messages(account_id).await.unwrap());
    assert!(
        merged
            .iter()
            .all(|(received_at, _)| *received_at == tied_at),
        "the fixture must place every message in one received_at tie"
    );
    assert_eq!(
        merged,
        received_order(rebuilt_from_scratch(server, account_id).await.as_ref()),
        "a tie must resolve identically on a rebuild"
    );
    assert_eq!(
        merged,
        received_order(rebuilt_from_scratch(server, account_id).await.as_ref()),
        "a tie must resolve identically on every rebuild"
    );

    delete(
        server,
        account_id,
        server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids(),
    )
    .await;
}

async fn merge_agrees_with_a_full_rebuild(test: &TestServer) {
    let server = &test.server;
    let account_id = account_for(test, server, "jdoe@example.com").await;

    let base = 1_700_000_000u64;
    let mut ids = Vec::new();
    for i in 0..120u64 {
        ids.push(
            ingest(
                server,
                account_id,
                &format!("seed {i}"),
                base + i * 60,
                vec![INBOX_ID],
            )
            .await,
        );
    }

    let snapshot = |cache: &MessageStoreCache| {
        let items = cache
            .emails
            .iter()
            .map(|item| {
                let mut mailboxes = item
                    .mailboxes()
                    .iter()
                    .map(|uid| uid.mailbox_id)
                    .collect::<Vec<_>>();
                mailboxes.sort_unstable();
                let mut keywords = cache.expand_keywords(item).collect::<Vec<_>>();
                keywords.sort_unstable_by_key(|k| format!("{k:?}"));
                (
                    item.document_id(),
                    item.received_at(),
                    item.thread_id(),
                    item.size(),
                    mailboxes,
                    keywords,
                )
            })
            .collect::<Vec<_>>();
        let index = cache
            .emails
            .document_ids()
            .map(|id| (id, cache.emails.position(id).unwrap()))
            .collect::<std::collections::BTreeMap<_, _>>();
        (items, index)
    };

    let mut rng = rand::rng();
    for round in 0..12 {
        let updates_only = round % 2 == 0;
        let mut alive = server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids()
            .into_iter()
            .collect::<Vec<_>>();

        for _ in 0..rng.random_range(1..=6) {
            if alive.is_empty() {
                break;
            }
            let idx = rng.random_range(0..alive.len());
            toggle_keyword(server, account_id, alive[idx], Keyword::Seen).await;
        }

        for _ in 0..if updates_only {
            0
        } else {
            rng.random_range(1..=3)
        } {
            if alive.len() < 2 {
                break;
            }
            let idx = rng.random_range(0..alive.len());
            let victim = alive.remove(idx);
            delete(server, account_id, RoaringBitmap::from_iter([victim])).await;
        }

        for i in 0..if updates_only {
            0
        } else {
            rng.random_range(1..=4)
        } {
            let received_at = if rng.random_bool(0.5) {
                base.saturating_sub(rng.random_range(1..=200_000))
            } else {
                base + rng.random_range(0..=10_000)
            };
            ingest(
                server,
                account_id,
                &format!("round {round} insert {i}"),
                received_at,
                vec![INBOX_ID],
            )
            .await;
        }

        let merged = server.get_cached_messages(account_id).await.unwrap();
        assert_sorted(&merged, &format!("round {round}"));
        let merged = snapshot(&merged);
        let rebuilt = snapshot(rebuilt_from_scratch(server, account_id).await.as_ref());
        assert_eq!(
            merged,
            rebuilt,
            "round {round} ({}): merged cache must equal a full rebuild",
            if updates_only {
                "patch path, positions stable"
            } else {
                "rebuild path, positions shift"
            }
        );
    }

    delete(
        server,
        account_id,
        server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids(),
    )
    .await;
}

async fn received_at_query_is_a_total_order(test: &TestServer) {
    let server = &test.server;
    let account_id = account_for(test, server, "jdoe@example.com").await;

    let tied_at = 1_700_000_000u64;
    let mut ids = Vec::new();
    for i in 0..30u64 {
        let received_at = if i % 3 == 0 { tied_at } else { tied_at + i };
        ids.push(
            ingest(
                server,
                account_id,
                &format!("q {i}"),
                received_at,
                vec![INBOX_ID],
            )
            .await,
        );
    }

    let sorted_by = async |ascending: bool| {
        let cache = server.get_cached_messages(account_id).await.unwrap();
        server
            .query_emails(
                account_id,
                &cache,
                SearchQuery::new(SearchIndex::Email)
                    .with_account_id(account_id)
                    .with_mask(cache.email_document_ids()),
                vec![MessageComparator::Cache {
                    field: MessageCacheField::ReceivedAt,
                    ascending,
                }],
            )
            .await
            .unwrap()
    };

    let ascending = sorted_by(true).await;
    let descending = sorted_by(false).await;

    assert_eq!(
        ascending.len(),
        ids.len(),
        "every message must appear in the result"
    );
    let mut reversed = descending.clone();
    reversed.reverse();
    assert_eq!(
        ascending, reversed,
        "descending must be the exact reverse of ascending, which only holds for a total order"
    );

    let cache = server.get_cached_messages(account_id).await.unwrap();
    let key = |document_id: &u32| {
        let item = cache.email_by_id(document_id).unwrap();
        (item.received_at(), item.document_id())
    };
    let keys = ascending.iter().map(key).collect::<Vec<_>>();
    for pair in keys.windows(2) {
        assert!(
            pair[0] < pair[1],
            "sort:receivedAt must be a strict total order on (received_at, document_id): {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
    assert!(
        keys.windows(2).any(|p| p[0].0 == p[1].0),
        "the fixture must contain a received_at tie"
    );

    server.inner.cache.messages.remove(&account_id);
    assert_eq!(
        ascending,
        sorted_by(true).await,
        "the order must be reproducible across a cache rebuild"
    );

    delete(
        server,
        account_id,
        server
            .get_cached_messages(account_id)
            .await
            .unwrap()
            .email_document_ids(),
    )
    .await;
}
