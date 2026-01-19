/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{
    JMAPTest,
    mail::changes::{LogAction, ParseState},
};
use ::email::message::metadata::MessageData;
use common::storage::index::ObjectIndexBuilder;
use jmap_client::{
    core::query::{Comparator, Filter},
    email,
    mailbox::Role,
};
use jmap_proto::types::state::State;
use std::str::FromStr;
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{AlignedBytes, Archive, BatchBuilder},
};
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email QueryChanges tests...");
    let server = params.server.clone();
    let account = params.account("jdoe@example.com");
    let client = account.client();

    let mailbox1_id = client
        .mailbox_create("JMAP Changes 1", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let mailbox2_id = client
        .mailbox_create("JMAP Changes 2", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    let mut states = vec![State::Initial];
    let mut id_map = AHashMap::default();

    let mut updated_ids = AHashSet::default();
    let mut removed_ids = AHashSet::default();
    let mut type1_ids = AHashSet::default();
    let mut thread_id_map: AHashMap<u32, Id> = AHashMap::default();

    let mut thread_id = 100;

    for (change_num, change) in [
        LogAction::Insert(0),
        LogAction::Insert(1),
        LogAction::Insert(2),
        LogAction::Move(0, 3),
        LogAction::Insert(4),
        LogAction::Insert(5),
        LogAction::Update(1),
        LogAction::Update(2),
        LogAction::Delete(1),
        LogAction::Insert(6),
        LogAction::Insert(7),
        LogAction::Update(2),
        LogAction::Update(4),
        LogAction::Update(5),
        LogAction::Update(6),
        LogAction::Update(7),
        LogAction::Delete(4),
        LogAction::Delete(5),
        LogAction::Delete(6),
        LogAction::Insert(8),
        LogAction::Insert(9),
        LogAction::Insert(10),
        LogAction::Update(3),
        LogAction::Update(2),
        LogAction::Update(8),
        LogAction::Move(9, 11),
        LogAction::Move(10, 12),
        LogAction::Delete(8),
    ]
    .iter()
    .enumerate()
    {
        match &change {
            LogAction::Insert(id) => {
                let jmap_id = Id::from_str(
                    client
                        .email_import(
                            format!(
                                "From: test_{}\nSubject: test_{}\n\ntest",
                                if change_num % 2 == 0 { 1 } else { 2 },
                                *id
                            )
                            .into_bytes(),
                            [if change_num % 2 == 0 {
                                &mailbox1_id
                            } else {
                                &mailbox2_id
                            }],
                            [if change_num % 2 == 0 { "1" } else { "2" }].into(),
                            Some(*id as i64),
                        )
                        .await
                        .unwrap()
                        .id()
                        .unwrap(),
                )
                .unwrap();

                id_map.insert(*id, jmap_id);
                if change_num % 2 == 0 {
                    type1_ids.insert(jmap_id);
                }
                thread_id_map
                    .entry(jmap_id.prefix_id())
                    .or_insert(jmap_id);
            }
            LogAction::Update(id) => {
                let id = *id_map.get(id).unwrap();
                let mut batch = BatchBuilder::new();
                batch
                    .with_document(id.document_id())
                    .log_item_update(SyncCollection::Email, id.prefix_id().into());
                server.store().write(batch.build_all()).await.unwrap();
                updated_ids.insert(id);
            }
            LogAction::Delete(id) => {
                let id = *id_map.get(id).unwrap();
                client.email_destroy(&id.to_string()).await.unwrap();
                removed_ids.insert(id);
            }
            LogAction::Move(from, to) => {
                let id = *id_map.get(from).unwrap();
                let new_id = Id::from_parts(thread_id, id.document_id());

                //let new_thread_id = store::rand::random::<u32>();

                let old_message_ = server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account.id().document_id(),
                        Collection::Email,
                        id.document_id(),
                    ))
                    .await
                    .unwrap()
                    .unwrap();
                let old_message = old_message_.to_unarchived::<MessageData>().unwrap();
                let mut new_message = old_message.deserialize::<MessageData>().unwrap();
                new_message.thread_id = thread_id;

                server
                    .core
                    .storage
                    .data
                    .write(
                        BatchBuilder::new()
                            .with_account_id(account.id().document_id())
                            .with_collection(Collection::Email)
                            .with_document(id.document_id())
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_current(old_message)
                                    .with_changes(new_message),
                            )
                            .unwrap()
                            .build_all(),
                    )
                    .await
                    .unwrap();

                id_map.insert(*to, new_id);
                if type1_ids.contains(&id) {
                    type1_ids.insert(new_id);
                }
                removed_ids.insert(id);
                thread_id_map.insert(new_id.prefix_id(), new_id);
                thread_id += 1;
            }
            LogAction::UpdateChild(_) => unreachable!(),
        }

        let mut new_state = State::Initial;
        for state in &states {
            for (test_num, query) in vec![
                QueryChanges {
                    filter: None,
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                    collapse_threads: false,
                },
                QueryChanges {
                    filter: Some(email::query::Filter::from("test_1").into()),
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                    collapse_threads: false,
                },
                QueryChanges {
                    filter: Some(email::query::Filter::in_mailbox(&mailbox1_id).into()),
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                    collapse_threads: false,
                },
                QueryChanges {
                    filter: None,
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: id_map
                        .get(&7)
                        .map(|id| id.to_string().into())
                        .unwrap_or(None),
                    collapse_threads: false,
                },
                QueryChanges {
                    filter: None,
                    sort: vec![email::query::Comparator::received_at()],
                    since_query_state: state.clone(),
                    max_changes: 0,
                    up_to_id: None,
                    collapse_threads: true,
                },
            ]
            .into_iter()
            .enumerate()
            {
                if (test_num == 3 || test_num == 4) && query.up_to_id.is_none() {
                    continue;
                }
                if test_num == 4 && !query.collapse_threads {
                    continue;
                }
                let mut request = client.build();
                let query_request = request
                    .query_email_changes(query.since_query_state.to_string())
                    .sort(query.sort);

                if let Some(filter) = query.filter {
                    query_request.filter(filter);
                }

                if let Some(up_to_id) = query.up_to_id {
                    query_request.up_to_id(up_to_id);
                }

                if query.collapse_threads {
                    query_request.arguments().collapse_threads(true);
                }

                let changes = request.send_query_email_changes().await.unwrap();

                if test_num == 0 || test_num == 1 {
                    // Immutable filters should not return modified ids, only deletions.
                    for id in changes.removed() {
                        let id = Id::from_str(id).unwrap();
                        assert!(
                            removed_ids.contains(&id),
                            "{:?} (id: {:?})",
                            changes,
                            id_map.iter().find(|(_, v)| **v == id).map(|(k, _)| k)
                        );
                    }
                }
                if test_num == 1 || test_num == 2 {
                    // Only type 1 results should be added to the list.
                    for item in changes.added() {
                        let id = Id::from_str(item.id()).unwrap();
                        assert!(
                            type1_ids.contains(&id),
                            "{:?} (id: {:?})",
                            changes,
                            id_map.iter().find(|(_, v)| **v == id).map(|(k, _)| k)
                        );
                    }
                }
                if test_num == 3 {
                    // Only ids up to 7 should be added to the list.
                    for item in changes.added() {
                        let item_id = Id::from_str(item.id()).unwrap();
                        let id = id_map.iter().find(|(_, v)| **v == item_id).unwrap().0;
                        assert!(id < &7, "{:?} (id: {})", changes, id);
                    }
                }
                if test_num == 4 {
                    // With collapse_threads, only first email per thread should be added.
                    let mut seen_threads = AHashSet::new();
                    for item in changes.added() {
                        let item_id = Id::from_str(item.id()).unwrap();
                        let thread_id = item_id.prefix_id();
                        assert!(
                            seen_threads.insert(thread_id),
                            "Thread {} appears multiple times with collapse_threads: {:?}",
                            thread_id,
                            changes
                        );
                        // Verify this is the first email in this thread
                        assert_eq!(
                            thread_id_map.get(&thread_id),
                            Some(&item_id),
                            "Expected first email in thread {}, got {:?}",
                            thread_id,
                            item_id
                        );
                    }
                }

                if let State::Initial = state {
                    new_state = State::parse_str(changes.new_query_state()).unwrap();
                }
            }
        }
        states.push(new_state);
    }

    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}

#[derive(Debug, Clone)]
pub struct QueryChanges {
    pub filter: Option<Filter<email::query::Filter>>,
    pub sort: Vec<Comparator<email::query::Comparator>>,
    pub since_query_state: State,
    pub max_changes: usize,
    pub up_to_id: Option<String>,
    pub collapse_threads: bool,
}
