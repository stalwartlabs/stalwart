/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use ahash::{AHashMap, AHashSet};
use common::auth::BuildAccessToken;
use email::message::delivery::{IngestMessage, IngestRecipient, LocalDeliveryStatus, MailDelivery};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{AccountType, Permission, TenantStorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            Account, CertificateManagement, Credential, Dkim1Signature, DkimManagement,
            DkimSignature, DnsManagement, DnsServer, DnsServerCloudflare, Domain, GroupAccount,
            MailingList, OAuthClient, PasswordCredential, Permissions, PermissionsList, Role,
            SecretKey, SecretKeyValue, SecretText, SecretTextValue, Tenant, UserAccount, UserRoles,
        },
    },
    types::{EnumImpl, ObjectImpl, list::List, map::Map},
};
use serde_json::json;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub async fn test(test: &mut TestServer) {
    println!("Running Multi-tenancy tests...");
    let admin_system = test.account("admin@example.org");

    // Create tenants
    let mut tenant_x_ids = AHashMap::new();
    let mut tenant_y_ids = AHashMap::new();
    for (tenant_ids, name) in [(&mut tenant_x_ids, "x"), (&mut tenant_y_ids, "y")] {
        let tenant_id = admin_system
            .registry_create_object(Tenant {
                name: format!("Tenant {}", name),
                quotas: VecMap::from_iter([
                    (TenantStorageQuota::MaxAccounts, 2),
                    (TenantStorageQuota::MaxGroups, 1),
                    (TenantStorageQuota::MaxDomains, 1),
                    (TenantStorageQuota::MaxMailingLists, 1),
                    (TenantStorageQuota::MaxRoles, 1),
                    (TenantStorageQuota::MaxOauthClients, 1),
                    (TenantStorageQuota::MaxDkimKeys, 1),
                    (TenantStorageQuota::MaxDnsServers, 1),
                    (TenantStorageQuota::MaxDiskQuota, TENANT_QUOTA),
                ]),
                ..Default::default()
            })
            .await;

        let domain_id = admin_system
            .registry_create_object(Domain {
                name: format!("tenant{name}.org"),
                member_tenant_id: tenant_id.into(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                ..Default::default()
            })
            .await;

        let tenant_admin_id = admin_system
            .registry_create_object(Account::User(UserAccount {
                name: "admin".to_string(),
                domain_id,
                member_tenant_id: tenant_id.into(),
                roles: UserRoles::Admin,
                description: format!("Tenant {name} Admin").into(),
                credentials: List::from_iter([Credential::Password(PasswordCredential {
                    secret: format!("tenant {name} secret"),
                    ..Default::default()
                })]),
                ..Default::default()
            }))
            .await;

        tenant_ids.insert(ObjectType::Tenant, tenant_id);
        tenant_ids.insert(ObjectType::Domain, domain_id);
        tenant_ids.insert(ObjectType::TaskManager, tenant_admin_id);
    }

    // Tenants should not be allowed to create new tenants or modify their own tenant records
    let admin_x = crate::utils::account::Account::new(
        "admin@tenantx.org",
        "tenant x secret",
        &[],
        "Admin X",
        tenant_x_ids[&ObjectType::TaskManager],
    );
    let admin_y = crate::utils::account::Account::new(
        "admin@tenanty.org",
        "tenant y secret",
        &[],
        "Admin Y",
        tenant_y_ids[&ObjectType::TaskManager],
    );
    assert_eq!(
        admin_x
            .registry_create([Tenant {
                name: "Tenant Z".to_string(),
                ..Default::default()
            }])
            .await
            .method_response()
            .text_field("type"),
        "forbidden"
    );
    assert_eq!(
        admin_x
            .registry_update(
                ObjectType::Tenant,
                [(
                    tenant_x_ids[&ObjectType::Tenant],
                    json!({
                        "name": "New Tenant X Name"
                    }),
                )],
            )
            .await
            .method_response()
            .text_field("type"),
        "forbidden"
    );

    // Tenants should not be able to create accounts without a domain
    admin_x
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "user".to_string(),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::ValidationFailed);

    // Test wrong tenant assignment, invalid domain, exceeding tenant quotas, and successful creation for each object type
    let mut tenant_ids = [tenant_x_ids, tenant_y_ids];
    let mut tests_run = AHashSet::new();
    for (admin, tenant_id_pos, other_tenant_id_pos) in [(&admin_x, 0, 1), (&admin_y, 1, 0)] {
        for result in [
            ExpectedResult::WrongTenant,
            ExpectedResult::InvalidDomain,
            ExpectedResult::Success,
            ExpectedResult::QuotaExceeded,
        ] {
            if result != ExpectedResult::Success && tenant_id_pos == 1 {
                // Skip testing wrong tenant and invalid domain for tenant y, as they would be the same as tenant x
                continue;
            }

            tests_run.insert(result);

            let member_tenant_id = if result == ExpectedResult::WrongTenant {
                Some(tenant_ids[other_tenant_id_pos][&ObjectType::Tenant])
            } else {
                None
            };
            let domain_id = if result == ExpectedResult::InvalidDomain {
                tenant_ids[other_tenant_id_pos][&ObjectType::Domain]
            } else {
                tenant_ids[tenant_id_pos][&ObjectType::Domain]
            };

            if matches!(
                result,
                ExpectedResult::WrongTenant | ExpectedResult::QuotaExceeded
            ) {
                result
                    .assert(
                        admin,
                        &mut tenant_ids[tenant_id_pos],
                        ObjectType::Domain,
                        Domain {
                            name: format!("tenant{tenant_id_pos}.org"),
                            member_tenant_id,
                            certificate_management: CertificateManagement::Manual,
                            dns_management: DnsManagement::Manual,
                            dkim_management: DkimManagement::Manual,
                            ..Default::default()
                        },
                    )
                    .await;
            }

            result
                .assert(
                    admin,
                    &mut tenant_ids[tenant_id_pos],
                    ObjectType::Account,
                    Account::User(UserAccount {
                        name: "user".to_string(),
                        domain_id,
                        member_tenant_id,
                        ..Default::default()
                    }),
                )
                .await;

            result
                .assert(
                    admin,
                    &mut tenant_ids[tenant_id_pos],
                    ObjectType::AccountSettings,
                    Account::Group(GroupAccount {
                        name: "group".to_string(),
                        domain_id,
                        member_tenant_id,
                        ..Default::default()
                    }),
                )
                .await;

            result
                .assert(
                    admin,
                    &mut tenant_ids[tenant_id_pos],
                    ObjectType::MailingList,
                    MailingList {
                        name: "list".to_string(),
                        domain_id,
                        member_tenant_id,
                        ..Default::default()
                    },
                )
                .await;

            result
                .assert(
                    admin,
                    &mut tenant_ids[tenant_id_pos],
                    ObjectType::DkimSignature,
                    DkimSignature::Dkim1Ed25519Sha256(Dkim1Signature {
                        domain_id,
                        member_tenant_id,
                        selector: "ed-key".to_string(),
                        private_key: SecretText::Text(SecretTextValue {
                            secret: DKIM_KEY.to_string(),
                        }),
                        ..Default::default()
                    }),
                )
                .await;

            if result != ExpectedResult::InvalidDomain {
                result
                    .assert(
                        admin,
                        &mut tenant_ids[tenant_id_pos],
                        ObjectType::Role,
                        Role {
                            description: "role".to_string(),
                            member_tenant_id,
                            ..Default::default()
                        },
                    )
                    .await;

                result
                    .assert(
                        admin,
                        &mut tenant_ids[tenant_id_pos],
                        ObjectType::OAuthClient,
                        OAuthClient {
                            client_id: format!("oauth-{tenant_id_pos}"),
                            member_tenant_id,
                            ..Default::default()
                        },
                    )
                    .await;

                result
                    .assert(
                        admin,
                        &mut tenant_ids[tenant_id_pos],
                        ObjectType::DnsServer,
                        DnsServer::Cloudflare(DnsServerCloudflare {
                            member_tenant_id,
                            description: "Cloudflare DNS".to_string(),
                            secret: SecretKey::Value(SecretKeyValue {
                                secret: "abc".to_string(),
                            }),
                            ..Default::default()
                        }),
                    )
                    .await;
            }
        }
    }
    assert_eq!(tests_run.len(), 4, "Not all expected results were tested");
    let tenant_x_ids = &tenant_ids[0];
    let tenant_y_ids = &tenant_ids[1];

    // Assigning permissions not assigned to the tenant should be removed
    let user_x_id = tenant_x_ids[&ObjectType::Account];
    let user_x_at = test
        .server
        .access_token(user_x_id.document_id())
        .await
        .unwrap()
        .build();
    assert!(!user_x_at.has_permission(Permission::FetchAnyBlob));
    assert!(!user_x_at.has_permission(Permission::Impersonate));

    admin_x
        .registry_update_object(
            ObjectType::Account,
            user_x_id,
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    disabled_permissions: Map::default(),
                    enabled_permissions: Map::new(vec![Permission::FetchAnyBlob, Permission::Impersonate]),
                })
            }),
        )
        .await;
    let user_x_at = test
        .server
        .access_token(user_x_id.document_id())
        .await
        .unwrap()
        .build();
    assert!(user_x_at.has_permission(Permission::FetchAnyBlob));
    assert!(!user_x_at.has_permission(Permission::Impersonate));

    // Tenants should only see their own objects
    for object_type in [
        ObjectType::Domain,
        ObjectType::Account,
        ObjectType::AccountSettings,
        ObjectType::MailingList,
        ObjectType::Role,
        ObjectType::OAuthClient,
        ObjectType::DnsServer,
        ObjectType::DkimSignature,
    ] {
        let expected_id = tenant_y_ids[&object_type];
        match object_type {
            ObjectType::Account => {
                let expected = vec![tenant_y_ids[&ObjectType::TaskManager], expected_id];
                assert_eq!(
                    admin_y
                        .registry_query_ids(
                            ObjectType::Account,
                            [(Property::Type, AccountType::User.as_str())],
                            Vec::<&str>::new()
                        )
                        .await,
                    expected
                );
                assert_eq!(
                    admin_y
                        .registry_get_many(ObjectType::Account, expected.iter())
                        .await
                        .list()
                        .len(),
                    expected.len()
                );
            }
            ObjectType::AccountSettings => {
                assert_eq!(
                    admin_y
                        .registry_query_ids(
                            ObjectType::Account,
                            [(Property::Type, AccountType::Group.as_str())],
                            Vec::<&str>::new()
                        )
                        .await,
                    vec![expected_id]
                );

                // Fetch a single id and make sure member tenant id is not included in the response
                let account = admin_y.registry_get::<Account>(expected_id).await;
                assert_eq!(account.into_group().unwrap().member_tenant_id, None);

                // Fetch all account types
                assert_eq!(
                    admin_y
                        .registry_get_many(ObjectType::Account, Vec::<&str>::new())
                        .await
                        .list()
                        .len(),
                    3
                );
            }
            _ => {
                assert_eq!(
                    admin_y
                        .registry_query_ids(
                            object_type,
                            Vec::<(&str, &str)>::new(),
                            Vec::<&str>::new()
                        )
                        .await,
                    vec![expected_id]
                );
                assert_eq!(
                    admin_y
                        .registry_get_many(object_type, vec![expected_id])
                        .await
                        .list()
                        .len(),
                    1
                );
                assert_eq!(
                    admin_y
                        .registry_get_many(object_type, Vec::<&str>::new())
                        .await
                        .list()
                        .len(),
                    1
                );
            }
        }
    }

    // Tenants should not see, modify or destroy objects from other tenants, even if they have the id
    for object_type in [
        ObjectType::Domain,
        ObjectType::Account,
        ObjectType::AccountSettings,
        ObjectType::MailingList,
        ObjectType::Role,
        ObjectType::OAuthClient,
        ObjectType::DnsServer,
        ObjectType::DkimSignature,
    ] {
        let foreign_id = tenant_x_ids[&object_type];
        match object_type {
            ObjectType::Account => {
                assert_eq!(
                    admin_y
                        .registry_get_many(
                            ObjectType::Account,
                            vec![tenant_x_ids[&ObjectType::TaskManager], foreign_id]
                        )
                        .await
                        .list()
                        .len(),
                    0
                );

                admin_y
                    .registry_update_object_expect_err(
                        ObjectType::Account,
                        foreign_id,
                        json!({
                            "name": "hacked"
                        }),
                    )
                    .await
                    .assert_type(SetErrorType::NotFound);

                admin_y
                    .registry_destroy_object_expect_err(ObjectType::Account, foreign_id)
                    .await
                    .assert_type(SetErrorType::NotFound);
            }
            ObjectType::AccountSettings => {
                assert_eq!(
                    admin_y
                        .registry_get_many(ObjectType::Account, vec![foreign_id])
                        .await
                        .list()
                        .len(),
                    0
                );

                admin_y
                    .registry_update_object_expect_err(
                        ObjectType::Account,
                        foreign_id,
                        json!({
                            "name": "hacked"
                        }),
                    )
                    .await
                    .assert_type(SetErrorType::NotFound);

                admin_y
                    .registry_destroy_object_expect_err(ObjectType::Account, foreign_id)
                    .await
                    .assert_type(SetErrorType::NotFound);
            }
            _ => {
                assert_eq!(
                    admin_y
                        .registry_get_many(object_type, vec![foreign_id])
                        .await
                        .list()
                        .len(),
                    0
                );

                admin_y
                    .registry_update_object_expect_err(
                        object_type,
                        foreign_id,
                        json!({
                            "name": "hacked"
                        }),
                    )
                    .await
                    .assert_type(SetErrorType::NotFound);

                admin_y
                    .registry_destroy_object_expect_err(object_type, foreign_id)
                    .await
                    .assert_type(SetErrorType::NotFound);
            }
        }
    }

    // Test tenant quotas
    let (message_blob, _) = test
        .server
        .put_temporary_blob(user_x_id.document_id(), TEST_MESSAGE.as_bytes(), 60)
        .await
        .unwrap();
    assert_eq!(
        test.server
            .deliver_message(IngestMessage {
                sender_address: "bill@foobar.org".to_string(),
                sender_authenticated: true,
                recipients: vec![IngestRecipient {
                    address: "user@tenantx.org".to_string(),
                    orcpt: None,
                    is_spam: false
                }],
                message_blob: message_blob.clone(),
                message_size: TEST_MESSAGE.len() as u64,
                session_id: 0,
            })
            .await
            .status,
        vec![LocalDeliveryStatus::Success]
    );

    // Quota for the tenant and user should be updated
    const EXTRA_BYTES: i64 = 51; // Storage overhead
    assert_eq!(
        test.server
            .get_used_quota_account(user_x_id.document_id())
            .await
            .unwrap(),
        TEST_MESSAGE.len() as i64 + EXTRA_BYTES
    );
    assert_eq!(
        test.server
            .get_used_quota_tenant(tenant_x_ids[&ObjectType::Tenant].document_id())
            .await
            .unwrap(),
        TEST_MESSAGE.len() as i64 + EXTRA_BYTES
    );

    // Next delivery should fail due to tenant quota
    assert_eq!(
        test.server
            .deliver_message(IngestMessage {
                sender_address: "bill@foobar.org".to_string(),
                sender_authenticated: true,
                recipients: vec![IngestRecipient {
                    address: "user@tenantx.org".to_string(),
                    orcpt: None,
                    is_spam: false
                }],
                message_blob,
                message_size: TEST_MESSAGE.len() as u64,
                session_id: 0,
            })
            .await
            .status,
        vec![LocalDeliveryStatus::TemporaryFailure {
            reason: "Organization over quota.".into()
        }]
    );
    test.wait_for_tasks().await;

    // Delete everything created during the test
    for (admin, tenant_id_pos) in [(&admin_x, 0), (&admin_y, 1)] {
        for object_type in [
            ObjectType::Account,
            ObjectType::AccountSettings,
            ObjectType::MailingList,
            ObjectType::Role,
            ObjectType::OAuthClient,
            ObjectType::DnsServer,
            ObjectType::DkimSignature,
        ] {
            let id = tenant_ids[tenant_id_pos][&object_type];
            let object_type = if object_type == ObjectType::AccountSettings {
                ObjectType::Account
            } else {
                object_type
            };
            assert_eq!(
                admin
                    .registry_destroy(object_type, [id])
                    .await
                    .destroyed_ids()
                    .count(),
                1
            );
        }
    }

    for tenant_id_pos in [0, 1] {
        for object_type in [
            ObjectType::TaskManager,
            ObjectType::Domain,
            ObjectType::Tenant,
        ] {
            let id = tenant_ids[tenant_id_pos][&object_type];
            let object_type = if object_type == ObjectType::TaskManager {
                ObjectType::Account
            } else {
                object_type
            };
            assert_eq!(
                admin_system
                    .registry_destroy(object_type, [id])
                    .await
                    .destroyed_ids()
                    .count(),
                1
            );
        }
    }

    test.cleanup().await;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum ExpectedResult {
    Success,
    WrongTenant,
    QuotaExceeded,
    InvalidDomain,
}

impl ExpectedResult {
    async fn assert<T: ObjectImpl>(
        &self,
        account: &crate::utils::account::Account,
        ids: &mut AHashMap<ObjectType, Id>,
        item_type: ObjectType,
        item: T,
    ) {
        match self {
            ExpectedResult::Success => {
                assert!(
                    ids.insert(item_type, account.registry_create_object(item).await)
                        .is_none(),
                    "Expected to create object successfully, but it already exists"
                )
            }
            ExpectedResult::WrongTenant => {
                account
                    .registry_create_object_expect_err(item)
                    .await
                    .assert_type(SetErrorType::InvalidPatch)
                    .assert_description_contains("Cannot modify memberTenantId property");
            }
            ExpectedResult::QuotaExceeded => {
                account
                    .registry_create_object_expect_err(item)
                    .await
                    .assert_type(SetErrorType::OverQuota);
            }
            ExpectedResult::InvalidDomain => {
                account
                    .registry_create_object_expect_err(item)
                    .await
                    .assert_type(SetErrorType::InvalidForeignKey);
            }
        }
    }
}

const TENANT_QUOTA: u64 = TEST_MESSAGE.len() as u64;
const TEST_MESSAGE: &str = concat!(
    "From: bill@foobar.org\r\n",
    "To: jdoe@foobar.com\r\n",
    "Subject: TPS Report\r\n",
    "\r\n",
    "I'm going to need those TPS reports ASAP. ",
    "So, if you could do that, that'd be great."
);

const DKIM_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAO3hAf144lTAVjTkht3ZwBTK0CMCCd1bI0alggneN3B
-----END PRIVATE KEY-----
";
