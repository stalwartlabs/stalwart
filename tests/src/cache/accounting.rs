/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use email::{cache::MessageCacheFetch, mailbox::manage::MailboxFnc};
use utils::cache::CacheItemWeight;

pub async fn test(test: &TestServer, account_id: u32, second_account_id: u32) {
    println!("Running cache accounting tests...");

    mailbox_size_accounts_for_materialised_paths(test, account_id).await;
    store_cache_size_is_the_sum_of_its_parts(test, second_account_id).await;
}

async fn mailbox_size_accounts_for_materialised_paths(test: &TestServer, account_id: u32) {
    let server = &test.server;

    server.get_cached_messages(account_id).await.unwrap();

    server
        .mailbox_create_path(
            account_id,
            "deeply/nested/folder/hierarchy/with/long/segment/names",
        )
        .await
        .unwrap()
        .expect("failed to create the nested mailbox path");

    let cache = server.get_cached_messages(account_id).await.unwrap();

    let deepest = cache
        .mailboxes
        .items
        .iter()
        .max_by_key(|item| item.path.len())
        .expect("no mailboxes were created");
    assert!(
        deepest.path.len() > deepest.name.len(),
        "the deepest mailbox path was never materialised: {:?}",
        deepest.path
    );

    let counted = cache
        .mailboxes
        .items
        .iter()
        .map(|item| {
            (std::mem::size_of_val(item)
                + if item.name.len() > std::mem::size_of::<String>() {
                    item.name.len()
                } else {
                    0
                }
                + if item.path.len() > std::mem::size_of::<String>() {
                    item.path.len()
                } else {
                    0
                }) as u64
        })
        .sum::<u64>();

    assert_eq!(
        cache.mailboxes.size, counted,
        "MailboxesCache::size does not match the heap its items actually occupy, \
         which means the size was accumulated before the paths were materialised"
    );
}

async fn store_cache_size_is_the_sum_of_its_parts(test: &TestServer, account_id: u32) {
    let server = &test.server;

    let cache = server.get_cached_messages(account_id).await.unwrap();

    assert_eq!(
        cache.size,
        cache.emails.size + cache.mailboxes.size,
        "MessageStoreCache::size is not the sum of its two parts"
    );
    assert_eq!(
        cache.weight(),
        cache.size,
        "the cache weight used for admission does not match its reported size"
    );
}
