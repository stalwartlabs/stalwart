/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod antispam;
pub mod append;
pub mod basic;
pub mod body_structure;
pub mod condstore;
pub mod copy_move;
pub mod fetch;
pub mod idle;
pub mod mailbox;
pub mod managesieve;
pub mod objectid;
pub mod pop;
pub mod search;
pub mod store;
pub mod thread;

use crate::utils::{
    imap::{AssertResult, ImapConnection, Type},
    server::TestServerBuilder,
};
use ahash::AHashSet;
use imap_proto::ResponseType;
use registry::{
    schema::{
        enums::{Permission, SpecialUse},
        prelude::ObjectType,
        structs::{
            Email, EmailFolder, Expression, Imap, MemoryLookupKey, MtaStageAuth, MtaStageData,
            SpamClassifier, SpamTag, SpamTagScore,
        },
    },
    types::float::Float,
};
use serde_json::json;
use std::{path::PathBuf, time::Instant};
use utils::map::vec_map::VecMap;

#[tokio::test(flavor = "multi_thread")]
pub async fn imap_tests() {
    let mut test = TestServerBuilder::new("imap_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;

    // Create admin account
    let admin = test.create_admin_account("admin@example.com").await;

    // Create test users
    for (name, secret, description, aliases) in [
        (
            "jdoe@example.com",
            "12345 + extra safety",
            "John Doe",
            &["john.doe@example.com"][..],
        ),
        (
            "jane.smith@example.com",
            "abcde + extra safety",
            "Jane Smith",
            &["jane@example.com"][..],
        ),
        (
            "foobar@example.com",
            "098765 + extra safety",
            "Bill Foobar",
            &["bill.foobar@example.com"][..],
        ),
        (
            "popper@example.com",
            "a_pop3_safe_secret_with_extra_safety",
            "Karl Popper",
            &["karl.popper@example.com"][..],
        ),
        (
            "sgd@example.com",
            "secret2 + extra safety",
            "Sigmund Gudmund Dudmundsson",
            &[][..],
        ),
        (
            "spamtrap@example.com",
            "secret3 + extra safety",
            "Spam Trap",
            &[][..],
        ),
    ] {
        let account = admin
            .create_user_account(
                name,
                secret,
                description,
                aliases,
                vec![Permission::UnlimitedRequests, Permission::UnlimitedUploads],
            )
            .await;
        test.insert_account(account);
    }

    // Create test group
    test.insert_account(
        admin
            .create_group_account("support@example.com", "Support Group", &[])
            .await,
    );

    // Add Jane to the Support group
    let support_id = test.account("support@example.com").id();
    admin
        .registry_update_object(
            ObjectType::Account,
            test.account("jane.smith@example.com").id(),
            json!({
                "memberGroupIds": { support_id: true },
            }),
        )
        .await;

    // Add test settings
    admin
        .registry_create_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SpamClassifier {
            min_ham_samples: 10,
            min_spam_samples: 10,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Email {
            default_folders: VecMap::from_iter(
                [
                    (SpecialUse::Inbox, "Inbox"),
                    (SpecialUse::Sent, "Sent Items"),
                    (SpecialUse::Trash, "Deleted Items"),
                    (SpecialUse::Junk, "Junk Mail"),
                    (SpecialUse::Drafts, "Drafts"),
                ]
                .into_iter()
                .map(|(use_, name)| {
                    (
                        use_,
                        EmailFolder {
                            name: name.into(),
                            subscribe: false,
                            ..Default::default()
                        },
                    )
                }),
            ),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageData {
            add_delivered_to_header: false,
            enable_spam_filter: Expression {
                else_: "recipients[0] != 'popper@example.com'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SpamTag::Score(SpamTagScore {
            score: Float::new(10.0),
            tag: "PROB_SPAM_LOW".into(),
        }))
        .await;
    admin
        .registry_create_object(SpamTag::Score(SpamTagScore {
            score: Float::new(10.0),
            tag: "PROB_SPAM_HIGH".into(),
        }))
        .await;
    admin
        .registry_create_object(SpamTag::Score(SpamTagScore {
            score: Float::new(100.0),
            tag: "SPAM_TRAP".into(),
        }))
        .await;
    admin
        .registry_create_object(MemoryLookupKey {
            is_glob_pattern: true,
            key: "spamtrap@*".into(),
            namespace: "spam-traps".into(),
        })
        .await;
    admin.reload_settings().await;
    admin.reload_lookup_stores().await;

    test.insert_account(admin);

    let start_time = Instant::now();

    // Body structure tests
    body_structure::test();

    // Connect to IMAP server
    let mut imap_check = ImapConnection::connect(b"_y ").await;
    let mut imap = ImapConnection::connect(b"_x ").await;
    for imap in [&mut imap, &mut imap_check] {
        imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    }

    // Unauthenticated tests
    basic::test(&mut imap, &mut imap_check).await;

    // Login
    let account = test.account("jdoe@example.com");
    for imap in [&mut imap, &mut imap_check] {
        imap.authenticate(account.name(), account.secret()).await;
    }

    // Test GETJMAPACCESS (RFC 9698)
    imap.send("GETJMAPACCESS").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* JMAPACCESS \"")
        .assert_contains("/.well-known/jmap\"");

    // Delete folders
    for mailbox in ["Drafts", "Junk Mail", "Sent Items"] {
        imap.send(&format!("DELETE \"{}\"", mailbox)).await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    }

    mailbox::test(&mut imap, &mut imap_check, &test).await;
    append::test(&mut imap, &mut imap_check, &test).await;
    search::test(&mut imap, &mut imap_check, &test).await;
    fetch::test(&mut imap, &mut imap_check).await;
    objectid::test(&test).await;
    store::test(&mut imap, &mut imap_check, &test).await;
    copy_move::test(&mut imap, &mut imap_check).await;
    thread::test(&mut imap, &mut imap_check, &test).await;
    idle::test(&mut imap, &mut imap_check, false).await;
    condstore::test(&mut imap, &mut imap_check).await;
    acl::test(&mut imap, &mut imap_check, &test).await;

    // Logout
    for imap in [&mut imap, &mut imap_check] {
        imap.send("UNAUTHENTICATE").await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;

        imap.send("LOGOUT").await;
        imap.assert_read(Type::Untagged, ResponseType::Bye).await;
    }

    // Antispam training
    antispam::test(&test).await;

    // Run ManageSieve tests
    managesieve::test(&test).await;

    // Run POP3 tests
    pop::test(&test).await;

    // Print elapsed time
    let elapsed = start_time.elapsed();
    println!(
        "Elapsed: {}.{:03}s",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    // Remove test data
    if test.is_reset() {
        test.temp_dir.delete();
    }
}

pub fn expand_uid_list(list: &str) -> AHashSet<u32> {
    let mut items = AHashSet::new();
    for uid in list.split(',') {
        if let Some((start, end)) = uid.split_once(':') {
            let start = start.parse::<u32>().unwrap();
            let end = end.parse::<u32>().unwrap();
            for uid in start..=end {
                items.insert(uid);
            }
        } else {
            items.insert(uid.parse::<u32>().unwrap());
        }
    }

    items
}

fn resources_dir() -> PathBuf {
    let mut resources = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resources.push("resources");
    resources.push("imap");
    resources
}
