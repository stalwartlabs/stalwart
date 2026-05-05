/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{registry::UnwrapRegistryId, server::TestServer};
use jmap_tools::JsonPointer;
use registry::{
    jmap::{IntoValue, JmapValue, JsonPointerPatch, MaybeUnpatched, RegistryJsonPatch},
    pickle::{Pickle, PickledStream},
    schema::{
        enums::{AccountType, Locale, Permission, StorageQuota},
        prelude::{Object, ObjectType, Property},
        structs::{
            Account, CertificateManagement, Credential, CredentialPermissions,
            CredentialPermissionsList, CustomRoles, DkimManagement, DnsManagement, Domain,
            EmailAlias, EncryptionAtRest, EncryptionSettings, GroupAccount, MailingList,
            PasswordCredential, Permissions, PermissionsList, PublicKey, SecondaryCredential,
            SieveUserScript, UserAccount, UserRoles,
        },
    },
    types::{
        EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId, ipmask::IpAddrOrMask,
        list::List, map::Map,
    },
};
use std::str::FromStr;
use store::{
    registry::{
        RegistryQuery,
        write::{RegistryWrite, RegistryWriteResult},
    },
    write::now,
};
use types::id::Id;
use utils::map::vec_map::VecMap;

pub async fn test(test: &TestServer) {
    let r = test.server.registry();

    println!("Registry tests...");

    test_patch_regressions();

    // Pickle-unpickle test
    let mut account = Account::User(UserAccount {
        aliases: List::from_iter([
            EmailAlias {
                description: "Test Alias 1".to_string().into(),
                domain_id: 1000u64.into(),
                enabled: true,
                name: "alias1".into(),
            },
            EmailAlias {
                description: "Test Alias 2".to_string().into(),
                domain_id: 1001u64.into(),
                enabled: true,
                name: "alias2".into(),
            },
        ]),
        created_at: UTCDateTime::now(),
        credentials: List::from_iter([
            Credential::Password(PasswordCredential {
                allowed_ips: Map::new(vec![IpAddrOrMask::from_str("192.168.1.1").unwrap()]),
                credential_id: 3u64.into(),
                expires_at: None,
                otp_auth: "otpauth://totp/test?secret=SECRET".to_string().into(),
                secret: "secret".into(),
            }),
            Credential::AppPassword(SecondaryCredential {
                allowed_ips: Map::new(vec![IpAddrOrMask::from_str("192.168.1.0/24").unwrap()]),
                created_at: UTCDateTime::now(),
                credential_id: 4u64.into(),
                description: "App Password".into(),
                expires_at: Some(UTCDateTime::from_timestamp((now() + 1000) as i64)),
                permissions: CredentialPermissions::Disable(CredentialPermissionsList {
                    permissions: Map::new(vec![
                        Permission::Authenticate,
                        Permission::ActionClassifySpam,
                    ]),
                }),
                secret: "app_password_secret".into(),
            }),
        ]),
        description: "This is a test Account".to_string().into(),
        domain_id: 1004u64.into(),
        encryption_at_rest: EncryptionAtRest::Aes128(EncryptionSettings {
            allow_spam_training: true,
            encrypt_on_append: false,
            public_key: 0u64.into(),
        }),
        locale: Locale::EnUS,
        member_group_ids: Map::new(vec![2000u64.into(), 2001u64.into()]),
        member_tenant_id: None,
        name: "user".into(),
        permissions: Permissions::Merge(PermissionsList {
            disabled_permissions: Map::new(vec![Permission::Impersonate]),
            enabled_permissions: Map::new(vec![Permission::JmapBlobGet]),
        }),
        quotas: VecMap::from_iter([
            (StorageQuota::MaxDiskQuota, 1024u64),
            (StorageQuota::MaxApiKeys, 3u64),
        ]),
        roles: UserRoles::Custom(CustomRoles {
            role_ids: Map::new(vec![5000u64.into()]),
        }),
        time_zone: None,
    });
    let account_pickle = account.to_pickled_vec();
    assert_eq!(
        account,
        Account::unpickle(&mut PickledStream::new(&account_pickle).unwrap()).unwrap()
    );

    // Pickle compression test
    let script = SieveUserScript {
        contents: "A".repeat(100_000),
        description: "B".repeat(100_000).into(),
        is_active: true,
        name: "C".repeat(100_000),
    };
    let script_pickle = script.to_pickled_vec();
    assert!(
        script_pickle.len() < 8_192,
        "Pickle was not compressed: {} bytes",
        script_pickle.len()
    );
    assert_eq!(
        script,
        SieveUserScript::unpickle(&mut PickledStream::new(&script_pickle).unwrap()).unwrap()
    );

    // Create a domain and a group
    let domain_id = r
        .write(RegistryWrite::insert(
            &Domain {
                name: "test.org".into(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                is_enabled: true,
                ..Default::default()
            }
            .into(),
        ))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    let domain_id_2 = r
        .write(RegistryWrite::insert(
            &Domain {
                name: "test.net".into(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                is_enabled: true,
                ..Default::default()
            }
            .into(),
        ))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    let group_id = r
        .write(RegistryWrite::insert(
            &Account::Group(GroupAccount {
                name: "group".into(),
                domain_id,
                ..Default::default()
            })
            .into(),
        ))
        .await
        .unwrap()
        .unwrap_id(trc::location!());

    // Inserting an account linking non-existing ids should fail
    test.assert_registry_insert_error(
        account.clone(),
        RegistryWriteResult::InvalidForeignKey {
            object_id: ObjectId::new(ObjectType::Account, Id::new(2000)),
        },
        trc::location!(),
    )
    .await;
    account.assert_patch(
        &format!("memberGroupIds/{}", Id::new(2000)),
        false,
        trc::location!(),
    );
    account.assert_patch(
        &format!("memberGroupIds/{}", Id::new(2001)),
        false,
        trc::location!(),
    );
    account.assert_patch(
        &format!("memberGroupIds/{}", group_id),
        true,
        trc::location!(),
    );

    test.assert_registry_insert_error(
        account.clone(),
        RegistryWriteResult::InvalidForeignKey {
            object_id: ObjectId::new(ObjectType::Domain, Id::new(1000)),
        },
        trc::location!(),
    )
    .await;
    account.assert_patch("aliases/0/domainId", domain_id, trc::location!());
    account.assert_patch("aliases/1/domainId", domain_id, trc::location!());

    test.assert_registry_insert_error(
        account.clone(),
        RegistryWriteResult::InvalidForeignKey {
            object_id: ObjectId::new(ObjectType::Domain, Id::new(1004)),
        },
        trc::location!(),
    )
    .await;
    account.assert_patch("domainId", domain_id, trc::location!());

    test.assert_registry_insert_error(
        account.clone(),
        RegistryWriteResult::InvalidForeignKey {
            object_id: ObjectId::new(ObjectType::PublicKey, Id::new(0)),
        },
        trc::location!(),
    )
    .await;
    account.assert_patch(
        "encryptionAtRest",
        EncryptionAtRest::Disabled.into_value(),
        trc::location!(),
    );

    test.assert_registry_insert_error(
        account.clone(),
        RegistryWriteResult::InvalidForeignKey {
            object_id: ObjectId::new(ObjectType::Role, Id::new(5000)),
        },
        trc::location!(),
    )
    .await;
    account.assert_patch("roles", UserRoles::User.into_value(), trc::location!());

    let account_id = r
        .write(RegistryWrite::insert(&account.into()))
        .await
        .unwrap()
        .unwrap_id(trc::location!());

    // Deleting linked objects should fail
    test.assert_registry_delete_error(
        ObjectType::Domain,
        domain_id,
        RegistryWriteResult::CannotDeleteLinked {
            object_id: ObjectId::new(ObjectType::Domain, domain_id),
            linked_objects: vec![
                ObjectId::new(ObjectType::Account, group_id),
                ObjectId::new(ObjectType::Account, account_id),
            ],
        },
        trc::location!(),
    )
    .await;

    // Primary key violations should not be allowed
    test.assert_registry_insert_error(
        Domain {
            name: "test.org".into(),
            is_enabled: true,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        },
        RegistryWriteResult::PrimaryKeyConflict {
            property: Property::Name,
            existing_id: ObjectId::new(ObjectType::Domain, domain_id),
        },
        trc::location!(),
    )
    .await;
    test.assert_registry_insert_error(
        Account::Group(GroupAccount {
            name: "group".into(),
            domain_id,
            ..Default::default()
        }),
        RegistryWriteResult::PrimaryKeyConflict {
            property: Property::Email,
            existing_id: ObjectId::new(ObjectType::Account, group_id),
        },
        trc::location!(),
    )
    .await;
    test.assert_registry_insert_error(
        MailingList {
            name: "user".into(),
            domain_id,
            recipients: Map::new(vec!["rcpt@domain.org".into()]),
            ..Default::default()
        },
        RegistryWriteResult::PrimaryKeyConflict {
            property: Property::Email,
            existing_id: ObjectId::new(ObjectType::Account, account_id),
        },
        trc::location!(),
    )
    .await;
    test.assert_registry_insert_error(
        MailingList {
            name: "mailing-list".into(),
            domain_id,
            aliases: List::from_iter([EmailAlias {
                description: "Test Alias 1".to_string().into(),
                domain_id,
                enabled: true,
                name: "alias1".into(),
            }]),
            recipients: Map::new(vec!["rcpt@domain.org".into()]),
            ..Default::default()
        },
        RegistryWriteResult::PrimaryKeyConflict {
            property: Property::Email,
            existing_id: ObjectId::new(ObjectType::Account, account_id),
        },
        trc::location!(),
    )
    .await;

    // Create a public key and link it to the account
    let pk_id = r
        .write(RegistryWrite::insert(
            &PublicKey {
                account_id,
                key: "secret".into(),
                description: "Test Key".into(),
                ..Default::default()
            }
            .into(),
        ))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    let old_account = r
        .get(ObjectId::new(ObjectType::Account, account_id))
        .await
        .unwrap()
        .unwrap();
    let mut account = old_account.clone();
    assert_obj_patch(
        &mut account,
        "encryptionAtRest",
        EncryptionAtRest::Aes128(EncryptionSettings {
            allow_spam_training: true,
            encrypt_on_append: false,
            public_key: pk_id,
        })
        .into_value(),
        trc::location!(),
    );
    r.write(RegistryWrite::update(account_id, &account, &old_account))
        .await
        .unwrap()
        .unwrap_id(trc::location!());

    // Search tests
    assert_eq!(
        r.query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain))
            .await
            .unwrap(),
        vec![domain_id, domain_id_2]
    );
    assert_eq!(
        r.query::<Vec<Id>>(RegistryQuery::new(ObjectType::Domain).equal_pk(
            Property::Name,
            "test.org".to_string(),
            true,
        ))
        .await
        .unwrap(),
        vec![domain_id]
    );
    assert_eq!(
        r.query::<Vec<Id>>(RegistryQuery::new(ObjectType::Account))
            .await
            .unwrap(),
        vec![group_id, account_id]
    );
    assert_eq!(
        r.query::<Vec<Id>>(
            RegistryQuery::new(ObjectType::Account)
                .equal(Property::Type, AccountType::User.to_id())
                .text(Property::Text, "this is a test")
                .equal(Property::Name, "user")
        )
        .await
        .unwrap(),
        vec![account_id]
    );

    // Sort test
    assert_eq!(
        r.sort_by_index(ObjectType::Account, Property::Type, None, true)
            .await
            .unwrap(),
        vec![account_id, group_id]
    );
    assert_eq!(
        r.sort_by_index(
            ObjectType::Account,
            Property::Type,
            Some(vec![group_id, account_id]),
            true
        )
        .await
        .unwrap(),
        vec![account_id, group_id]
    );
    assert_eq!(
        r.sort_by_index(ObjectType::Account, Property::Name, None, true)
            .await
            .unwrap(),
        vec![group_id, account_id]
    );
    assert_eq!(
        r.sort_by_pk(ObjectType::Domain, Property::Name, None, true)
            .await
            .unwrap(),
        vec![domain_id_2, domain_id]
    );
    assert_eq!(
        r.sort_by_pk(
            ObjectType::Domain,
            Property::Name,
            Some(vec![domain_id, domain_id_2]),
            true
        )
        .await
        .unwrap(),
        vec![domain_id_2, domain_id]
    );

    // Delete everything
    let old_account = r
        .get(ObjectId::new(ObjectType::Account, account_id))
        .await
        .unwrap()
        .unwrap();
    let mut account = old_account.clone();
    assert_obj_patch(
        &mut account,
        "encryptionAtRest",
        EncryptionAtRest::Disabled.into_value(),
        trc::location!(),
    );
    r.write(RegistryWrite::update(account_id, &account, &old_account))
        .await
        .unwrap()
        .unwrap_id(trc::location!());
    r.write(RegistryWrite::delete(ObjectId::new(
        ObjectType::PublicKey,
        pk_id,
    )))
    .await
    .unwrap()
    .unwrap_id(trc::location!());
    r.write(RegistryWrite::delete(ObjectId::new(
        ObjectType::Account,
        account_id,
    )))
    .await
    .unwrap()
    .unwrap_id(trc::location!());
    r.write(RegistryWrite::delete(ObjectId::new(
        ObjectType::Account,
        group_id,
    )))
    .await
    .unwrap()
    .unwrap_id(trc::location!());
    r.write(RegistryWrite::delete(ObjectId::new(
        ObjectType::Domain,
        domain_id,
    )))
    .await
    .unwrap()
    .unwrap_id(trc::location!());
    r.write(RegistryWrite::delete(ObjectId::new(
        ObjectType::Domain,
        domain_id_2,
    )))
    .await
    .unwrap()
    .unwrap_id(trc::location!());

    test.assert_is_empty().await;
}

impl TestServer {
    pub async fn assert_registry_insert_error(
        &self,
        obj: impl Into<Object>,
        result: RegistryWriteResult,
        location: &str,
    ) {
        let obj = obj.into();

        assert_eq!(
            self.server
                .registry()
                .write(RegistryWrite::insert(&obj))
                .await
                .unwrap(),
            result,
            "{}",
            location
        );
    }

    pub async fn assert_registry_delete_error(
        &self,
        object_type: ObjectType,
        id: Id,
        result: RegistryWriteResult,
        location: &str,
    ) {
        assert_eq!(
            self.server
                .registry()
                .write(RegistryWrite::delete(ObjectId::new(object_type, id)))
                .await
                .unwrap(),
            result,
            "{}",
            location
        );
    }
}

fn test_patch_regressions() {
    fn fresh_account() -> Account {
        Account::User(UserAccount {
            credentials: List::from_iter([
                Credential::Password(PasswordCredential {
                    allowed_ips: Map::new(vec![
                        IpAddrOrMask::from_str("192.168.1.1").unwrap(),
                        IpAddrOrMask::from_str("192.168.1.2").unwrap(),
                    ]),
                    credential_id: 3u64.into(),
                    expires_at: None,
                    otp_auth: None,
                    secret: "secret".into(),
                }),
                Credential::Password(PasswordCredential {
                    allowed_ips: Map::new(vec![IpAddrOrMask::from_str("10.0.0.1").unwrap()]),
                    credential_id: 4u64.into(),
                    expires_at: None,
                    otp_auth: None,
                    secret: "another".into(),
                }),
            ]),
            domain_id: 1u64.into(),
            name: "patch-target".into(),
            ..Default::default()
        })
    }

    fn user(account: &Account) -> &UserAccount {
        match account {
            Account::User(u) => u,
            _ => panic!("expected user account"),
        }
    }

    fn user_mut(account: &mut Account) -> &mut UserAccount {
        match account {
            Account::User(u) => u,
            _ => panic!("expected user account"),
        }
    }

    fn password_at(account: &Account, idx: u32) -> &PasswordCredential {
        let cred = user(account)
            .credentials
            .0
            .get(&idx)
            .expect("credential at index");
        match cred {
            Credential::Password(p) => p,
            _ => panic!("expected password credential at idx {idx}"),
        }
    }

    // Leaf-null patch into a List<T> entry removes only the leaf not the whole entry.
    let mut account = fresh_account();
    account.assert_patch(
        "credentials/0/allowedIps/192.168.1.1",
        JmapValue::Null,
        trc::location!(),
    );
    {
        let cred = password_at(&account, 0);
        assert_eq!(cred.allowed_ips.len(), 1, "one ip should remain");
        assert!(
            cred.allowed_ips
                .contains(&IpAddrOrMask::from_str("192.168.1.2").unwrap()),
            "remaining ip survived"
        );
        assert!(
            !cred
                .allowed_ips
                .contains(&IpAddrOrMask::from_str("192.168.1.1").unwrap()),
            "targeted ip removed"
        );
    }
    // The sibling credential is untouched.
    {
        let cred = password_at(&account, 1);
        assert_eq!(cred.allowed_ips.len(), 1);
        assert!(
            cred.allowed_ips
                .contains(&IpAddrOrMask::from_str("10.0.0.1").unwrap())
        );
    }

    // Removing every leaf still leaves the entry in place with an empty map.
    let mut account = fresh_account();
    account.assert_patch(
        "credentials/0/allowedIps/192.168.1.1",
        JmapValue::Null,
        trc::location!(),
    );
    account.assert_patch(
        "credentials/0/allowedIps/192.168.1.2",
        JmapValue::Null,
        trc::location!(),
    );
    {
        assert_eq!(
            user(&account).credentials.len(),
            2,
            "credential entry retained"
        );
        let cred = password_at(&account, 0);
        assert!(cred.allowed_ips.is_empty(), "leaf map drained");
    }

    // Direct removal of a list entry with no remaining segments still works.
    let mut account = fresh_account();
    account.assert_patch("credentials/0", JmapValue::Null, trc::location!());
    {
        assert_eq!(user(&account).credentials.len(), 1, "credential 0 removed");
        let cred = password_at(&account, 1);
        assert_eq!(cred.allowed_ips.len(), 1);
    }

    // Leaf-null patch into a scalar property of a list entry clears only that property.
    let mut account = fresh_account();
    {
        let cred = user_mut(&mut account)
            .credentials
            .inner_mut()
            .get_mut(&0)
            .expect("credential at 0");
        if let Credential::Password(p) = cred {
            p.expires_at = Some(UTCDateTime::from_timestamp(now() as i64));
        }
    }
    account.assert_patch("credentials/0/expiresAt", JmapValue::Null, trc::location!());
    {
        let cred = password_at(&account, 0);
        assert!(cred.expires_at.is_none(), "expiresAt cleared");
        assert_eq!(cred.allowed_ips.len(), 2, "siblings untouched");
    }

    // Map<T> set-style patches
    fn account_with_groups() -> Account {
        let mut account = match fresh_account() {
            Account::User(u) => u,
            _ => unreachable!(),
        };
        account.member_group_ids = Map::new(vec![Id::new(2000), Id::new(2001)]);
        Account::User(account)
    }

    let mut account = account_with_groups();
    account.assert_patch(
        &format!("memberGroupIds/{}", Id::new(2000)),
        JmapValue::Null,
        trc::location!(),
    );
    assert_eq!(
        user(&account).member_group_ids.len(),
        1,
        "one member removed"
    );
    assert!(
        user(&account).member_group_ids.contains(&Id::new(2001)),
        "sibling preserved"
    );

    let mut account = account_with_groups();
    let extra_path = format!("memberGroupIds/{}/extra", Id::new(2000));
    let ptr = JsonPointer::parse(&extra_path);
    let outcome = account.patch(JsonPointerPatch::new(&ptr), JmapValue::Null);
    assert!(outcome.is_err(), "extra segments must error on remove");
    assert_eq!(
        user(&account).member_group_ids.len(),
        2,
        "membership unchanged after rejected patch"
    );

    let mut account = account_with_groups();
    let ptr = JsonPointer::parse(&format!("memberGroupIds/{}/extra", Id::new(2002)));
    let outcome = account.patch(JsonPointerPatch::new(&ptr), JmapValue::Bool(true));
    assert!(outcome.is_err(), "extra segments must error on add");
    assert_eq!(
        user(&account).member_group_ids.len(),
        2,
        "membership unchanged after rejected add"
    );

    // Direct adds and removes still work.
    let mut account = account_with_groups();
    account.assert_patch(
        &format!("memberGroupIds/{}", Id::new(2002)),
        true,
        trc::location!(),
    );
    assert_eq!(user(&account).member_group_ids.len(), 3, "member added");
    assert!(user(&account).member_group_ids.contains(&Id::new(2002)));
}

trait AssertPatch {
    fn assert_patch(&mut self, patch: &str, value: impl Into<JmapValue<'static>>, location: &str);
}

impl<T: RegistryJsonPatch> AssertPatch for T {
    fn assert_patch(&mut self, patch: &str, value: impl Into<JmapValue<'static>>, location: &str) {
        let ptr = JsonPointer::parse(patch);
        let patch = JsonPointerPatch::new(&ptr);
        let value = value.into();
        match self.patch(patch, value) {
            Ok(maybe_unpatched) => {
                match maybe_unpatched {
                    MaybeUnpatched::Patched => {
                        // Patch succeeded
                    }
                    MaybeUnpatched::Unpatched { property, value } => {
                        panic!(
                            "Expected patch to succeed but it was unpatched at {}: property: {}, value: {:?}",
                            location, property, value
                        );
                    }
                    MaybeUnpatched::UnpatchedMany { properties } => {
                        panic!(
                            "Expected patch to succeed but it was unpatched at {}: properties: {:?}",
                            location, properties
                        );
                    }
                }
            }
            Err(err) => panic!("Patch failed at {}: {:?}", location, err),
        }
    }
}

fn assert_obj_patch(
    obj: &mut Object,
    patch: &str,
    value: impl Into<JmapValue<'static>>,
    location: &str,
) {
    let ptr = JsonPointer::parse(patch);
    let patch = JsonPointerPatch::new(&ptr);
    let value = value.into();
    match obj.patch(patch, value) {
        Ok(maybe_unpatched) => {
            match maybe_unpatched {
                MaybeUnpatched::Patched => {
                    // Patch succeeded
                }
                MaybeUnpatched::Unpatched { property, value } => {
                    panic!(
                        "Expected patch to succeed but it was unpatched at {}: property: {}, value: {:?}",
                        location, property, value
                    );
                }
                MaybeUnpatched::UnpatchedMany { properties } => {
                    panic!(
                        "Expected patch to succeed but it was unpatched at {}: properties: {:?}",
                        location, properties
                    );
                }
            }
        }
        Err(err) => panic!("Patch failed at {}: {:?}", location, err),
    }
}
