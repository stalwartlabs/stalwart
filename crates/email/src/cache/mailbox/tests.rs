/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MailboxCacheAccess;
use common::{MailboxCache, MailboxesCache, MessageStoreCache, MessagesCache, UpdateLock};
use std::sync::Arc;
use types::{metadata::MetadataKinds, special_use::SpecialUse};

fn cache(paths: &[&str]) -> MessageStoreCache {
    let items = paths
        .iter()
        .enumerate()
        .map(|(document_id, path)| MailboxCache {
            document_id: document_id as u32,
            name: path.rsplit('/').next().unwrap_or_default().to_string(),
            path: path.to_string(),
            role: SpecialUse::None,
            parent_id: 0,
            sort_order: 0,
            subscribers: Default::default(),
            uid_validity: 0,
            acls: Default::default(),
            metadata_kinds: MetadataKinds::NONE,
        })
        .collect::<Box<[_]>>();

    MessageStoreCache {
        emails: Arc::new(MessagesCache::new(1, Vec::new(), Vec::new())),
        mailboxes: Arc::new(MailboxesCache {
            change_id: 1,
            index: items
                .iter()
                .enumerate()
                .map(|(idx, item)| (item.document_id, idx as u32))
                .collect(),
            items,
            size: 0,
        }),
        update_lock: Arc::new(UpdateLock::new()),
        last_change_id: 1,
        size: 0,
        verification: Default::default(),
    }
}

fn reference_walk(cache: &MessageStoreCache, path: &str) -> Option<u32> {
    let mut found_path = String::new();
    let mut found = None;
    for name in path.split('/').map(|v| v.trim()) {
        if !found_path.is_empty() {
            found_path.push('/');
        }
        for ch in name.chars() {
            for ch in ch.to_lowercase() {
                found_path.push(ch);
            }
        }
        found = Some(
            cache
                .mailboxes
                .items
                .iter()
                .find(|item| item.path.to_lowercase() == found_path)?
                .document_id,
        );
    }
    found
}

#[test]
fn folded_path_lookup_matches_the_create_path_walk() {
    let cache = cache(&[
        "Inbox",
        "Work",
        "Work/Projects",
        "Work/Projects/Ünïcödé",
        "Straße",
        "Straße/İstanbul",
        "Archive",
        "archive",
        " Spaced ",
    ]);

    for path in [
        "Inbox",
        "INBOX",
        "inbox",
        "work/projects",
        " Work / PROJECTS ",
        "Work/Projects/ÜNÏCÖDÉ",
        "work/projects/missing",
        "work/missing/projects",
        "/Work",
        "Work/",
        "Work//Projects",
        "STRASSE",
        "straße",
        "STRAẞE",
        "Straße/i̇stanbul",
        "ARCHIVE",
        "Spaced",
        " Spaced ",
        "",
        "Missing",
    ] {
        assert_eq!(
            cache
                .mailbox_by_folded_path(path)
                .map(|mailbox| mailbox.document_id),
            reference_walk(&cache, path),
            "path {path:?}"
        );
    }

    assert_eq!(
        cache
            .mailbox_by_folded_path("work/projects")
            .map(|mailbox| mailbox.document_id),
        Some(2)
    );
    assert_eq!(
        cache
            .mailbox_by_folded_path("Archive")
            .map(|mailbox| mailbox.document_id),
        Some(6)
    );
}
