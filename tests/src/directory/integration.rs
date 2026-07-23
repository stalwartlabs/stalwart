/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    directory::ldap::ldap_test_directory,
    utils::{server::TestServerBuilder, smtp::SmtpConnection},
};
use ahash::AHashMap;
use email::cache::MessageCacheFetch;
use registry::schema::structs::{Account, AccountSettings, Directory};
use types::id::Id;

pub async fn test() {
    println!("Running directory integration tests...");
    crate::utils::containers::ensure_openldap().await;
    let test = TestServerBuilder::new("directory_integration_test")
        .await
        .with_default_listeners()
        .await
        .with_object(Directory::Ldap(ldap_test_directory()))
        .await
        .build()
        .await;
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin.mta_disable_spam_filter().await;
    admin.reload_settings().await;

    // Test account creation by login
    let account = crate::utils::account::Account::new(
        "john.doe@example.org",
        "this is John's LDAP password",
        &[],
        "",
        Id::from(u32::MAX),
    );
    assert_eq!(
        account
            .registry_get::<AccountSettings>(Id::singleton())
            .await
            .description
            .as_deref(),
        Some("John Doe")
    );

    // Test account creation by rcpt
    let mut lmtp = SmtpConnection::connect().await;
    for rcpt in [
        "corporate@example.org",
        "jane.smith@example.org",
        "john@example.org",
        "bill@example.org",
        "sales@example.org",
    ] {
        lmtp.ingest(
            "bill@remote.org",
            &[rcpt],
            &TEST_EMAIL.replace("$RCPT", rcpt),
        )
        .await;
    }

    // Fetch all accounts
    let mut accounts = admin
        .registry_get_all::<Account>()
        .await
        .into_iter()
        .map(|(id, account)| {
            (
                match &account {
                    Account::User(user_account) => user_account.name.clone(),
                    Account::Group(group_account) => group_account.name.clone(),
                },
                (account, id),
            )
        })
        .collect::<AHashMap<_, _>>();
    assert_eq!(accounts.len(), 5, "Got: {accounts:#?}");

    // Validate accounts
    for (name, description, secret, groups, aliases) in [
        (
            "john.doe",
            "John Doe",
            "$app$8958830913002348890$",
            &["sales"][..],
            &["john"][..],
        ),
        (
            "jane.smith",
            "Jane Smith",
            "$app$4096614298472586996$",
            &["sales", "corporate"][..],
            &[][..],
        ),
        (
            "bill.foobar",
            "Bill Foobar",
            "",
            &["corporate"][..],
            &["bill"][..],
        ),
    ] {
        let (account, id) = accounts
            .remove(name)
            .map(|(account, id)| (account.into_user().unwrap(), id))
            .unwrap();
        assert_eq!(account.description.as_deref(), Some(description));
        if !secret.is_empty() {
            assert_eq!(
                test.server
                    .registry()
                    .object::<Account>(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .into_user()
                    .unwrap()
                    .credentials
                    .values()
                    .next()
                    .and_then(|v| v.as_main_credential())
                    .map(|v| v.secret.as_str()),
                Some(secret)
            );
        }
        for group in groups {
            let id = accounts.get(*group).unwrap().1;
            assert!(
                account
                    .member_group_ids
                    .iter()
                    .any(|group_id| group_id == &id),
                "Account {name} is not a member of group {group}"
            );
        }
        for alias in aliases {
            assert!(
                account
                    .aliases
                    .iter()
                    .any(|account_alias| account_alias.name == *alias),
                "Account {name} does not have alias {alias}"
            );
        }
        assert_eq!(
            test.server
                .get_cached_messages(id.document_id())
                .await
                .unwrap()
                .emails
                .index
                .len(),
            1
        );
    }

    // Validate groups
    for (name, description, aliases) in [
        ("sales", "sales", &[][..]),
        ("corporate", "corporate", &["everyone"][..]),
    ] {
        let (account, id) = accounts
            .remove(name)
            .map(|(account, id)| (account.into_group().unwrap(), id))
            .unwrap();
        assert_eq!(account.description.as_deref(), Some(description));
        for alias in aliases {
            assert!(
                account
                    .aliases
                    .iter()
                    .any(|account_alias| account_alias.name == *alias),
                "Group {name} does not have alias {alias}"
            );
        }
        assert_eq!(
            test.server
                .get_cached_messages(id.document_id())
                .await
                .unwrap()
                .emails
                .index
                .len(),
            1
        );
    }
}

const TEST_EMAIL: &str = r#"From: bill@remote.org
To: $RCPT
Subject: TPS Report for $RCPT

I'm going to need those TPS reports ASAP. So, if you could do that, that'd be great.

"#;
