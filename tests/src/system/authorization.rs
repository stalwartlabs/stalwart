/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use ahash::AHashMap;
use common::auth::{BuildAccessToken, permissions::DefaultPermissions};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::{
            self, AccountSettings, Credential, CustomRoles, PasswordCredential, Role, UserAccount,
            UserRoles,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use serde_json::json;
use std::str::FromStr;
use types::id::Id;

pub async fn test(test: &mut TestServer) {
    println!("Running Authorization tests...");

    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    // Create nested roles
    let l3_role_id = admin
        .registry_create_object(Role {
            description: "Level 3 role".to_string(),
            enabled_permissions: Map::new(vec![Permission::SysAccountSettingsGet]),
            ..Default::default()
        })
        .await;
    let l2_role_id = admin
        .registry_create_object(Role {
            description: "Level 2 role".to_string(),
            enabled_permissions: Map::new(vec![
                Permission::AuthenticateWithAlias,
                Permission::SysAccountSettingsUpdate,
            ]),
            role_ids: Map::new(vec![l3_role_id]),
            ..Default::default()
        })
        .await;
    let l1_role_id = admin
        .registry_create_object(Role {
            description: "Level 1 role".to_string(),
            enabled_permissions: Map::new(vec![Permission::Authenticate]),
            role_ids: Map::new(vec![l2_role_id]),
            ..Default::default()
        })
        .await;

    // Create a user with the nested role
    let user_id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "user".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "this is a very strong password".to_string(),
                ..Default::default()
            })]),
            roles: UserRoles::Custom(CustomRoles {
                role_ids: Map::new(vec![l1_role_id]),
            }),
            ..Default::default()
        }))
        .await;
    let user = crate::utils::account::Account::new(
        "user@example.org",
        "this is a very strong password",
        &[],
        "User",
        user_id,
    );

    // Verify user permissions include all permissions from the nested roles
    user.registry_update_object(
        ObjectType::AccountSettings,
        Id::singleton(),
        json!({
            Property::Description: "Updated description"
        }),
    )
    .await;
    assert_eq!(
        user.registry_get::<AccountSettings>(Id::singleton())
            .await
            .description
            .as_deref(),
        Some("Updated description")
    );

    // Remove read permissions from the l3 role and verify the user can no longer read account settings
    admin
        .registry_update_object(
            ObjectType::Role,
            l3_role_id,
            json!({
                Property::EnabledPermissions: {}
            }),
        )
        .await;
    assert_eq!(
        user.registry_get_many(ObjectType::AccountSettings, [Id::singleton()])
            .await
            .method_response()
            .text_field("type"),
        "forbidden"
    );

    // User should still be able to update account settings due to permissions from the l2 role
    user.registry_update_object(
        ObjectType::AccountSettings,
        Id::singleton(),
        json!({
            Property::Description: "Updated description v2"
        }),
    )
    .await;

    // Disable account settings update permission in the l3 role
    admin
        .registry_update_object(
            ObjectType::Role,
            l3_role_id,
            json!({
                Property::DisabledPermissions: Map::new(vec![Permission::SysAccountSettingsUpdate]),
            }),
        )
        .await;
    assert_eq!(
        user.registry_update(
            ObjectType::AccountSettings,
            [(
                Id::singleton(),
                json!({
                    Property::Description: "Updated description v3"
                })
            )]
        )
        .await
        .method_response()
        .text_field("type"),
        "forbidden"
    );

    // Assign user to the default user role
    admin
        .registry_update_object(
            ObjectType::Account,
            user_id,
            json!({
                Property::Roles: UserRoles::User
            }),
        )
        .await;

    // Make sure the user does not have any administrator permissions
    let permissions = DefaultPermissions::default();
    let mut num_permissions_verified = 0;
    let mut num_objects_verified = 0;
    let user_access_token = test
        .server
        .access_token(user_id.document_id())
        .await
        .unwrap()
        .build();
    for permission in permissions.superuser {
        if permissions.user.contains(&permission) {
            continue;
        }
        num_permissions_verified += 1;
        assert!(
            !user_access_token.has_permission(permission),
            "User should not have {:?} permission",
            permission
        );

        if let Some(name) = permission
            .as_str()
            .strip_prefix("sys")
            .and_then(|perm| perm.strip_suffix("Get"))
        {
            let object_type = ObjectType::parse(name).unwrap();

            assert_eq!(
                user.registry_get_many(object_type, Vec::<&str>::new())
                    .await
                    .method_response()
                    .text_field("type"),
                "forbidden",
                "User should not have permission to read {:?} objects",
                object_type
            );

            num_objects_verified += 1;
        }
    }
    assert_ne!(
        num_permissions_verified, 0,
        "No permissions were verified in the test"
    );
    assert_ne!(
        num_objects_verified, 0,
        "No object read permissions were verified in the test"
    );

    // Deleting a linked role should not be allowed
    admin
        .registry_destroy_object_expect_err(ObjectType::Role, l2_role_id)
        .await
        .assert_type(SetErrorType::ObjectIsLinked);

    // Delete the account and roles in the correct order
    admin.destroy_account(user).await;
    for role_id in [l1_role_id, l2_role_id, l3_role_id] {
        admin
            .registry_destroy(ObjectType::Role, [role_id])
            .await
            .assert_destroyed(&[role_id]);
    }

    // Create test data for John and Jane
    let john = test
        .create_user_account(
            "admin@example.org",
            "john@example.org",
            "this is john's secret",
            &[],
            "john@example.org",
        )
        .await;
    let jane = test
        .create_user_account(
            "admin@example.org",
            "jane@example.org",
            "this is jane's secret",
            &[],
            "jane@example.org",
        )
        .await;
    let mut john_ids = AHashMap::new();
    let mut jane_ids = AHashMap::new();
    for (account, ids) in [(&john, &mut john_ids), (&jane, &mut jane_ids)] {
        let pk_id = account
            .registry_create_many(
                ObjectType::PublicKey,
                [json!({
                    Property::Description:"This is a public key",
                    Property::Key: SMIME_CERTIFICATE,
                })],
            )
            .await
            .created(0)
            .object_id();
        ids.insert(ObjectType::PublicKey, pk_id);

        let masked_id = account
            .registry_create_many(
                ObjectType::MaskedEmail,
                [json!({
                    Property::EmailDomain: "example.org",
                })],
            )
            .await
            .created(0)
            .object_id();
        ids.insert(ObjectType::MaskedEmail, masked_id);
    }

    // John should not be able to see Jane's objects and vice versa
    for (account, own_ids, other_ids) in
        [(&john, &john_ids, &jane_ids), (&jane, &jane_ids, &john_ids)]
    {
        for (object_type, id) in own_ids {
            assert_eq!(
                account
                    .registry_query(*object_type, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
                    .await
                    .object_ids()
                    .collect::<Vec<_>>(),
                vec![*id]
            );
            assert_eq!(
                account
                    .registry_get_many(*object_type, Vec::<&str>::new())
                    .await
                    .list()
                    .len(),
                1
            );
        }

        for (object_type, id) in other_ids {
            assert_eq!(
                account
                    .registry_get_many(*object_type, [*id])
                    .await
                    .not_found()
                    .map(|id| Id::from_str(id).unwrap())
                    .collect::<Vec<_>>(),
                vec![*id]
            );

            account
                .registry_update_object_expect_err(
                    *object_type,
                    *id,
                    json!({
                        Property::Description: "Hacked description"
                    }),
                )
                .await
                .assert_type(SetErrorType::NotFound);

            account
                .registry_destroy_object_expect_err(*object_type, *id)
                .await
                .assert_type(SetErrorType::NotFound);
        }
    }

    // Admin should see all objects
    for object_type in [ObjectType::PublicKey, ObjectType::MaskedEmail] {
        let objects = admin
            .registry_query(object_type, Vec::<(&str, &str)>::new(), Vec::<&str>::new())
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(objects.len(), 2);
        assert!(
            objects.contains(&john_ids[&object_type]) && objects.contains(&jane_ids[&object_type]),
        );

        // Filter by account id should work
        let objects = admin
            .registry_query(
                object_type,
                [(Property::AccountId, john.id().to_string())],
                Vec::<&str>::new(),
            )
            .await
            .object_ids()
            .collect::<Vec<_>>();
        assert_eq!(objects, vec![john_ids[&object_type]]);
    }

    // Destroy test data
    for (account, ids) in [(&john, &john_ids), (&jane, &jane_ids)] {
        for (object_type, id) in ids {
            account
                .registry_destroy(*object_type, [*id])
                .await
                .assert_destroyed(&[*id]);
        }
    }
    admin.destroy_account(john).await;
    admin.destroy_account(jane).await;

    test.cleanup().await;
}

const SMIME_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----
MIIDbjCCAlagAwIBAgIUZ4K0WXNSS8H0cUcZavD9EYqqTAswDQYJKoZIhvcNAQEN
BQAwLTErMCkGA1UEAxMiU2FtcGxlIExBTVBTIENlcnRpZmljYXRlIEF1dGhvcml0
eTAgFw0xOTExMjAwNjU0MThaGA8yMDUyMDkyNzA2NTQxOFowGTEXMBUGA1UEAxMO
QWxpY2UgTG92ZWxhY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDD
7q35ZdG2JAzzJGNZDZ9sV7AKh0hlRfoFjTZN5m4RegQAYSyag43ouWi1xRN0avf0
UTYrwjK04qRdV7GzCACoEKq/xiNUOsjfJXzbCublN3fZMOXDshKKBqThlK75SjA9
Czxg7ejGoiY/iidk0e91neK30SCCaBTJlfR2ZDrPk73IPMeksxoTatfF9hw9dDA+
/Hi1yptN/aG0Q/s9icFrxr6y2zQXsjuQPmjMZgj10aD9cazWVgRYCgflhmA0V1uQ
l1wobYU8DAVxVn+GgabqyjGQMoythIK0Gn5+ofwxXXUM/zbU+g6+1ISdoXxRRFtq
2GzbIqkAHZZQm+BbnFrhAgMBAAGjgZcwgZQwDAYDVR0TAQH/BAIwADAeBgNVHREE
FzAVgRNhbGljZUBzbWltZS5leGFtcGxlMBMGA1UdJQQMMAoGCCsGAQUFBwMEMA8G
A1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYEFKwuVFqk/VUYry7oZkQ40SXR1wB5MB8G
A1UdIwQYMBaAFLdSTXPAiD2yw3paDPOU9/eAonfbMA0GCSqGSIb3DQEBDQUAA4IB
AQB76o4Yz7yrVSFcpXqLrcGtdI4q93aKCXECCCzNQLp4yesh6brqaZHNJtwYcJ5T
qbUym9hJ70iJE4jGNN+yAZR1ltte0HFKYIBKM4EJumG++2hqbUaLz4tl06BHaQPC
v/9NiNY7q9R9c/B6s1YzHhwqkWht2a+AtgJ4BkpG+g+MmZMQV/Ao7RwLFKJ9OlMW
LBmEXFcpIJN0HpPasT0nEl/MmotSu+8RnClAi3yFfyTKb+8rD7VxuyXetqDZ6dU/
9/iqD/SZS7OQIjywtd343mACz3B1RlFxMHSA6dQAf2btGumqR0KiAp3KkYRAePoa
JqYkB7Zad06ngFl0G0FHON+7
-----END CERTIFICATE-----
";
