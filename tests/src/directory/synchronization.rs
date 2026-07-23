/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use registry::schema::{
    prelude::ObjectType,
    structs::{Account, Domain, EmailAlias},
};
use types::id::Id;

pub async fn test() {
    println!("Running directory synchronization tests...");
    let test = TestServerBuilder::new("directory_synchronization_test")
        .await
        .with_default_listeners()
        .await
        .disable_services()
        .build()
        .await;
    let admin = test.account("admin");

    // Synchronizing an account with an unknown domain should fail
    assert!(
        test.server
            .synchronize_account(directory::Account {
                email: "john@unknown.org".to_string(),
                email_aliases: vec![],
                secret: "supersecret".to_string().into(),
                groups: Some(vec![]),
                description: "John Doe".to_string().into(),
            })
            .await
            .is_err()
    );

    // Initial account synchronization
    let mut account_in = directory::Account {
        email: "john@example.org".to_string(),
        email_aliases: vec![
            "john.doe@example.org".to_string(),
            "j.doe@example.org".to_string(),
        ],
        secret: "supersecret".to_string().into(),
        groups: Some(vec![
            "corporate@example.org".to_string(),
            "sales@example.org".to_string(),
        ]),
        description: "John Doe".to_string().into(),
    };
    let result = test
        .server
        .synchronize_account(account_in.clone())
        .await
        .unwrap();
    let account_id = Id::from(result.id);
    let account_out = test
        .server
        .registry()
        .object::<Account>(account_id)
        .await
        .unwrap()
        .unwrap()
        .into_user()
        .unwrap();
    let domain_id = account_out.domain_id;
    assert_eq!(
        admin.registry_get::<Domain>(domain_id).await.name,
        "example.org"
    );
    assert_eq!(account_out.name, "john");
    assert_eq!(account_out.description.as_deref(), Some("John Doe"));
    assert_eq!(
        account_out
            .credentials
            .values()
            .next()
            .and_then(|v| v.as_main_credential())
            .map(|c| c.secret.as_str()),
        Some("supersecret")
    );
    assert_eq!(account_out.aliases.len(), 2);
    let aliases = account_out.aliases.iter().collect::<Vec<_>>();
    assert_eq!(
        aliases[0],
        &EmailAlias {
            description: None,
            domain_id,
            enabled: true,
            name: "john.doe".to_string(),
        }
    );
    assert_eq!(
        aliases[1],
        &EmailAlias {
            description: None,
            domain_id,
            enabled: true,
            name: "j.doe".to_string(),
        }
    );
    assert_eq!(account_out.member_group_ids.len(), 2);
    for (idx, group_id) in account_out.member_group_ids.iter().enumerate() {
        let group = admin
            .registry_get::<Account>(*group_id)
            .await
            .into_group()
            .unwrap();
        assert_eq!(group.name, if idx == 0 { "corporate" } else { "sales" });
        assert_eq!(group.domain_id, domain_id);
    }
    assert_eq!(
        test.server
            .registry()
            .count_object(ObjectType::Account)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        test.server
            .registry()
            .count_object(ObjectType::Domain)
            .await
            .unwrap(),
        1
    );

    // No changes should not cause any updates
    assert_eq!(
        test.server
            .synchronize_account(account_in.clone())
            .await
            .unwrap()
            .id,
        account_id.document_id()
    );
    assert_eq!(
        test.server
            .registry()
            .object::<Account>(account_id)
            .await
            .unwrap()
            .unwrap()
            .into_user()
            .unwrap(),
        account_out
    );
    assert_eq!(
        test.server
            .registry()
            .count_object(ObjectType::Account)
            .await
            .unwrap(),
        3
    );

    // Make some changes and synchronize again
    account_in.description = "Johnathan Doe".to_string().into();
    account_in
        .email_aliases
        .push("johnny@example.org".to_string());
    let groups = account_in.groups.get_or_insert_default();
    groups.pop();
    groups.push("support@example.org".to_string());
    account_in.secret = "evenmoresecret".to_string().into();
    assert_eq!(
        test.server
            .synchronize_account(account_in.clone())
            .await
            .unwrap()
            .id,
        account_id.document_id()
    );
    let account_out = test
        .server
        .registry()
        .object::<Account>(account_id)
        .await
        .unwrap()
        .unwrap()
        .into_user()
        .unwrap();
    assert_eq!(
        account_out
            .credentials
            .values()
            .next()
            .and_then(|v| v.as_main_credential())
            .map(|c| c.secret.as_str()),
        Some("evenmoresecret")
    );
    assert_eq!(account_out.description.as_deref(), Some("Johnathan Doe"));
    assert_eq!(account_out.aliases.len(), 3);
    let aliases = account_out.aliases.iter().collect::<Vec<_>>();
    assert_eq!(
        aliases[2],
        &EmailAlias {
            description: None,
            domain_id,
            enabled: true,
            name: "johnny".to_string(),
        }
    );
    assert_eq!(account_out.member_group_ids.len(), 2);
    let account_groups = account_out
        .member_group_ids
        .iter()
        .copied()
        .collect::<Vec<_>>();
    for (idx, group_id) in account_groups.iter().enumerate() {
        let group = admin
            .registry_get::<Account>(*group_id)
            .await
            .into_group()
            .unwrap();
        assert_eq!(group.name, if idx == 0 { "corporate" } else { "support" });
        assert_eq!(group.domain_id, domain_id);
    }
    assert_eq!(
        test.server
            .registry()
            .count_object(ObjectType::Account)
            .await
            .unwrap(),
        4
    );

    account_in.groups = None;
    test.server
        .synchronize_account(account_in.clone())
        .await
        .unwrap();
    let account_out = test
        .server
        .registry()
        .object::<Account>(account_id)
        .await
        .unwrap()
        .unwrap()
        .into_user()
        .unwrap();
    assert_eq!(account_out.member_group_ids.len(), 2);

    account_in.groups = Some(vec![]);
    test.server
        .synchronize_account(account_in.clone())
        .await
        .unwrap();
    let account_out = test
        .server
        .registry()
        .object::<Account>(account_id)
        .await
        .unwrap()
        .unwrap()
        .into_user()
        .unwrap();
    assert_eq!(account_out.member_group_ids.len(), 0);

    // Synchronize a group
    assert_eq!(
        test.server
            .synchronize_group(directory::Group {
                email: "corporate@example.org".to_string(),
                email_aliases: vec!["everyone@example.org".to_string()],
                description: "Corporate Group".to_string().into(),
            })
            .await
            .unwrap(),
        account_groups[0].document_id()
    );
    let group_out = test
        .server
        .registry()
        .object::<Account>(account_groups[0])
        .await
        .unwrap()
        .unwrap()
        .into_group()
        .unwrap();
    assert_eq!(group_out.name, "corporate");
    assert_eq!(group_out.description.as_deref(), Some("Corporate Group"));
    assert_eq!(group_out.aliases.len(), 1);
    let aliases = group_out.aliases.iter().collect::<Vec<_>>();
    assert_eq!(
        aliases[0],
        &EmailAlias {
            description: None,
            domain_id,
            enabled: true,
            name: "everyone".to_string(),
        }
    );
    assert_eq!(
        test.server
            .registry()
            .count_object(ObjectType::Account)
            .await
            .unwrap(),
        4
    );
}
