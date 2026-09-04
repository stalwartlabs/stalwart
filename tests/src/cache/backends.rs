/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use common::{
    CustomKeywords, DavName, DavPath, GroupwareResource, GroupwareResourceMetadata, GroupwareResources, MessageCache,
    MessageUid, MessagesCache, PathIndex, ResourceStore, UpdateLock,
    cache::swap::{
        SwapBackend, SwapCadence, SwapKey, SwapPart, SwapTier, blob::BlobSwapStore,
        file::FileSwapStore,
    },
    storage::dav::ResourceChunkBuilder,
};
use compact_str::CompactString;
use registry::schema::structs;
use std::sync::Arc;
use tinyvec::TinyVec;
use types::collection::SyncCollection;

const ACCOUNT_ID: u32 = 1234;

pub async fn test(test: &TestServer) {
    println!("Running cache swap tier tests...");

    let root = test.temp_dir.path.join("swap");
    let (file_tier, _file_rx) = SwapTier::new(
        SwapBackend::File(
            FileSwapStore::open(&structs::LocalFileSwap {
                path: root.to_string_lossy().into_owned(),
                ..Default::default()
            })
            .await
            .expect("Failed to open the local file swap store"),
        ),
        SwapCadence::default(),
    );
    run_suite("local file", &file_tier).await;
    corrupt_snapshot_is_discarded(&root).await;

    let (blob_tier, _blob_rx) = SwapTier::new(
        SwapBackend::Blob(BlobSwapStore::new(
            test.server.blob_store().clone(),
            test.server.store().clone(),
            7 * 24 * 3600,
            SwapCadence::default().max_account_size,
        )),
        SwapCadence::default(),
    );
    run_suite("blob store", &blob_tier).await;

    #[cfg(feature = "redis")]
    {
        use common::cache::swap::redis::RedisSwapStore;
        use store::backend::redis::RedisStore;

        crate::utils::containers::ensure_redis().await;
        let store = RedisStore::open_single(structs::RedisStore {
            url: "redis://127.0.0.1".into(),
            ..Default::default()
        })
        .await
        .expect("Failed to open the Redis store");

        let (redis_tier, _redis_rx) = SwapTier::new(
            SwapBackend::Redis(RedisSwapStore::new(store, 4096, 3600, 64 * 1024 * 1024)),
            SwapCadence::default(),
        );
        run_suite("redis", &redis_tier).await;
    }
}

async fn wait_until_ready(backend: &str, tier: &SwapTier, key: SwapKey) {
    let mut last_error = None;
    for _ in 0..40 {
        match tier.load(key).await {
            Ok(_) => return,
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
    }
    panic!("{backend}: backend never became reachable: {last_error:?}");
}

async fn run_suite(backend: &str, tier: &SwapTier) {
    println!("  backend: {backend}");

    assert!(tier.is_enabled(), "{backend}: tier reports disabled");

    let messages_key = SwapKey::messages(ACCOUNT_ID);
    let resources_key = SwapKey::new(ACCOUNT_ID, SyncCollection::Calendar, SwapPart::Resources);
    wait_until_ready(backend, tier, messages_key).await;

    for key in [messages_key, resources_key] {
        tier.remove(key).await.expect("remove");
        assert!(
            tier.load(key).await.expect("load").is_none(),
            "{backend}: a missing key did not read back as None"
        );
    }

    let messages = sample_messages(20_000);
    let encoded = messages.to_snapshot().expect("encode messages");
    assert!(
        encoded.len() > 512 * 1024,
        "{backend}: the message fixture must span several Redis chunks, got {} bytes",
        encoded.len()
    );

    tier.store(messages_key, &encoded).await.expect("store");
    let loaded = tier
        .load(messages_key)
        .await
        .expect("load")
        .expect("snapshot missing after store");
    assert_eq!(
        loaded, encoded,
        "{backend}: the message snapshot did not read back byte for byte"
    );

    let decoded = MessagesCache::from_snapshot(&loaded).expect("decode messages");
    assert_messages_match(backend, &messages, &decoded);

    let resources = sample_resources(5_000);
    let encoded_resources = resources.to_snapshot().expect("encode resources");
    tier.store(resources_key, &encoded_resources)
        .await
        .expect("store");
    let loaded_resources = tier
        .load(resources_key)
        .await
        .expect("load")
        .expect("snapshot missing after store");
    assert_eq!(
        loaded_resources, encoded_resources,
        "{backend}: the resource snapshot did not read back byte for byte"
    );

    let decoded_resources =
        GroupwareResources::from_snapshot(&loaded_resources).expect("decode resources");
    assert_resources_match(backend, &resources, &decoded_resources);

    assert_eq!(
        tier.load(messages_key).await.expect("load"),
        Some(encoded.clone()),
        "{backend}: writing one part disturbed the other"
    );

    let smaller = sample_messages(1_000);
    let encoded_smaller = smaller.to_snapshot().expect("encode");
    assert!(encoded_smaller.len() < encoded.len());
    tier.store(messages_key, &encoded_smaller)
        .await
        .expect("overwrite");
    assert_eq!(
        tier.load(messages_key).await.expect("load"),
        Some(encoded_smaller),
        "{backend}: overwriting with a smaller snapshot left stale bytes behind"
    );

    let regrown = sample_messages(20_000);
    let encoded_regrown = regrown.to_snapshot().expect("encode");
    tier.store(messages_key, &encoded_regrown)
        .await
        .expect("regrow");
    assert_eq!(
        tier.load(messages_key).await.expect("load"),
        Some(encoded_regrown),
        "{backend}: growing a snapshot back after a shrink did not read back cleanly"
    );

    tier.remove_account(ACCOUNT_ID).await;
    for key in [messages_key, resources_key] {
        assert!(
            tier.load(key).await.expect("load").is_none(),
            "{backend}: remove_account left a snapshot behind"
        );
    }
}

async fn corrupt_snapshot_is_discarded(root: &std::path::Path) {
    let (tier, _rx) = SwapTier::new(
        SwapBackend::File(
            FileSwapStore::open(&structs::LocalFileSwap {
                path: root.to_string_lossy().into_owned(),
                ..Default::default()
            })
            .await
            .expect("Failed to open the local file swap store"),
        ),
        SwapCadence::default(),
    );

    let key = SwapKey::messages(ACCOUNT_ID);
    let messages = sample_messages(2_000);
    let encoded = messages.to_snapshot().expect("encode");
    tier.store(key, &encoded).await.expect("store");

    let path = root
        .join(format!("{:02x}", ACCOUNT_ID % 256))
        .join(key.file_name());
    let mut stored = std::fs::read(&path).expect("read back the snapshot file");
    assert_eq!(stored, encoded);

    let at = stored.len() / 2;
    stored[at] ^= 0x01;
    std::fs::write(&path, &stored).expect("write the corrupted snapshot");

    let loaded = tier.load(key).await.expect("load").expect("still present");
    assert!(
        MessagesCache::from_snapshot(&loaded).is_none(),
        "a corrupted snapshot on disk was accepted"
    );

    std::fs::write(&path, &encoded[..encoded.len() / 3]).expect("truncate the snapshot");
    let loaded = tier.load(key).await.expect("load").expect("still present");
    assert!(
        MessagesCache::from_snapshot(&loaded).is_none(),
        "a truncated snapshot on disk was accepted"
    );

    tier.remove(key).await.expect("remove");
}

fn sample_messages(count: usize) -> MessagesCache {
    let mut items = Vec::with_capacity(count);
    let mut keywords = Vec::new();

    for document_id in 0..count as u32 {
        let mut mailboxes: TinyVec<[MessageUid; 2]> = TinyVec::new();
        for slot in 0..((document_id % 4) + 1) {
            mailboxes.push(MessageUid {
                mailbox_id: (document_id + slot) % 23,
                uid: document_id + slot,
            });
        }

        if document_id % 11 == 0 {
            keywords.push(CustomKeywords {
                names: vec![CompactString::from(format!("label-{document_id}"))].into_boxed_slice(),
                document_id,
            });
        }

        items.push(MessageCache::new(
            document_id,
            mailboxes,
            document_id % 29,
            document_id / 5,
            (document_id as u64) * 3,
            2048 + document_id,
            1_700_000_000 + (document_id as u64 % 97),
            -20 + (document_id as i32 % 900),
        ));
    }

    items.sort_unstable_by_key(|item| item.sort_rank());
    MessagesCache::new(9_876_543, items, keywords)
}

fn sample_resources(items: usize) -> GroupwareResources {
    let mut containers = ResourceChunkBuilder::with_capacity(4);
    let mut entries = Vec::new();

    for document_id in 0..4u32 {
        let name = containers.push_str(&format!("calendar-{document_id}"));
        let acls = containers.push_acls(&[]);
        let preferences = containers.push_prefs(&[]);
        containers.records.push(GroupwareResource {
            document_id,
            data: GroupwareResourceMetadata::Calendar {
                name,
                acls,
                preferences,
                etag: document_id,
            },
        });
        entries.push((
            format!("calendar-{document_id}"),
            DavPath {
                path: Default::default(),
                parent_id: common::NO_ID,
                hierarchy_seq: common::storage::dav::CONTAINER_FLAG,
                document_id,
            },
        ));
    }

    let mut chunks = Vec::new();
    let mut chunk = ResourceChunkBuilder::with_capacity(common::DAV_CHUNK);
    for document_id in 0..items as u32 {
        if chunk.len() == common::DAV_CHUNK {
            chunks.push(std::mem::replace(
                &mut chunk,
                ResourceChunkBuilder::with_capacity(common::DAV_CHUNK),
            ));
        }
        let parent_id = document_id % 4;
        let names = chunk.push_names(&[DavName {
            name: format!("event-{document_id}.ics"),
            parent_id,
        }]);
        let uid = chunk.push_str(&format!("uid-{document_id}@example.org"));
        chunk.records.push(GroupwareResource {
            document_id,
            data: GroupwareResourceMetadata::CalendarEvent {
                names,
                start: 1_700_000_000 + document_id as i64,
                duration: 1800 + document_id,
                created_at: 1_600_000_000 + document_id as i64,
                modified_at: -(document_id as i32),
                uid,
                etag: document_id,
            },
        });
        entries.push((
            format!("calendar-{parent_id}/event-{document_id}.ics"),
            DavPath {
                path: Default::default(),
                parent_id,
                hierarchy_seq: 0,
                document_id,
            },
        ));
    }
    chunks.push(chunk);

    let mut resources = GroupwareResources {
        base_path: "/dav/cal/tester".to_string(),
        paths: Arc::new(PathIndex::pack(entries)),
        resources: ResourceStore::from_sorted(vec![containers], chunks, false),
        item_change_id: 555,
        container_change_id: 111,
        highest_change_id: 555,
        size: 0,
        update_lock: Arc::new(UpdateLock::new()),
        verification: Default::default(),
    };
    resources.recompute_size();
    resources
}

fn assert_messages_match(backend: &str, left: &MessagesCache, right: &MessagesCache) {
    assert_eq!(left.len(), right.len(), "{backend}: message count");
    assert_eq!(left.change_id, right.change_id, "{backend}: change id");
    assert_eq!(left.size, right.size, "{backend}: cache size");

    for (a, b) in left.iter().zip(right.iter()) {
        assert_eq!(a.document_id(), b.document_id(), "{backend}: document id");
        assert_eq!(a.received_at(), b.received_at(), "{backend}: received at");
        assert_eq!(a.keywords(), b.keywords(), "{backend}: keywords");
        assert_eq!(a.thread_id(), b.thread_id(), "{backend}: thread id");
        assert_eq!(a.change_id(), b.change_id(), "{backend}: message change id");
        assert_eq!(a.size(), b.size(), "{backend}: message size");
        assert_eq!(a.sent_at(), b.sent_at(), "{backend}: sent at");
        assert_eq!(
            a.mailboxes(),
            b.mailboxes(),
            "{backend}: mailbox membership"
        );
    }

    for document_id in left.document_ids() {
        assert_eq!(
            left.position(document_id),
            right.position(document_id),
            "{backend}: index position for {document_id}"
        );
        assert_eq!(
            left.custom_keywords_of(document_id),
            right.custom_keywords_of(document_id),
            "{backend}: custom keywords for {document_id}"
        );
    }
}

fn assert_resources_match(backend: &str, left: &GroupwareResources, right: &GroupwareResources) {
    assert_eq!(left.base_path, right.base_path, "{backend}: base path");
    assert_eq!(left.size, right.size, "{backend}: cache size");
    assert_eq!(
        left.resources.len(),
        right.resources.len(),
        "{backend}: resource count"
    );
    assert_eq!(left.paths.len(), right.paths.len(), "{backend}: path count");
    assert_eq!(
        left.item_change_id, right.item_change_id,
        "{backend}: item change id"
    );
    assert_eq!(
        left.container_change_id, right.container_change_id,
        "{backend}: container change id"
    );
    assert_eq!(
        left.highest_change_id, right.highest_change_id,
        "{backend}: highest change id"
    );

    for (a, b) in left.resources.iter().zip(right.resources.iter()) {
        assert_eq!(a.document_id(), b.document_id(), "{backend}: document id");
        assert_eq!(
            a.is_container(),
            b.is_container(),
            "{backend}: is container"
        );
        assert_eq!(a.uid(), b.uid(), "{backend}: uid");
        assert_eq!(
            a.event_time_range(),
            b.event_time_range(),
            "{backend}: event range"
        );
        assert_eq!(a.created_at(), b.created_at(), "{backend}: created at");
        assert_eq!(a.modified_at(), b.modified_at(), "{backend}: modified at");
        assert_eq!(a.acls(), b.acls(), "{backend}: acls");
    }

    for (chunk, path) in left.paths.iter() {
        let name = std::str::from_utf8(&chunk.bytes[path.path.range()]).expect("valid path");
        let (_, other) = right
            .paths
            .get(name)
            .unwrap_or_else(|| panic!("{backend}: path {name} missing after round trip"));
        assert_eq!(path.document_id, other.document_id, "{backend}: path owner");
        assert_eq!(path.parent_id, other.parent_id, "{backend}: path parent");
        assert_eq!(
            path.hierarchy_seq, other.hierarchy_seq,
            "{backend}: hierarchy seq"
        );
    }
}
