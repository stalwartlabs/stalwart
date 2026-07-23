/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{jmap::JmapUtils, server::TestServer};
use common::{
    auth::{ACCOUNT_IS_USER, EmailAddress, EmailCache},
    network::RcptResolution,
};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{AccountType, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            Account, CertificateManagement, Credential, DkimManagement, DnsManagement, Domain,
            EmailAlias, Expression, ExpressionMatch, GroupAccount, MailingList, PasswordCredential,
            SubAddressing, SubAddressingCustom, UserAccount,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use serde_json::json;
use std::sync::Arc;
use utils::map::vec_map::VecMap;

pub async fn test(test: &TestServer) {
    println!("Running Directory tests...");
    let account = test.account("admin@example.org");

    // Create a domain and make sure it's in the cache
    let domain_id = account
        .registry_create_object(Domain {
            name: "example.com".to_string(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            aliases: Map::new(vec!["beispiel.de".to_string()]),
            is_enabled: true,
            catch_all_address: Some("catchy@example.com".to_string()),
            sub_addressing: SubAddressing::Enabled,
            ..Default::default()
        })
        .await;
    let domain_cache = test
        .server
        .domain_by_id(domain_id.document_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &domain_cache.names,
        &Box::from_iter(["example.com".into(), "beispiel.de".into()])
    );
    assert_eq!(domain_cache.id, domain_id.document_id());
    assert_eq!(
        domain_cache.catch_all.as_deref(),
        Some("catchy@example.com")
    );

    // Multiple domains with the same name should not be allowed
    account
        .registry_create_object_expect_err(Domain {
            name: "example.com".to_string(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await
        .assert_type(SetErrorType::PrimaryKeyViolation);

    // Invalid local part should not be allowed
    account
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "!invalid".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "hello world".to_string(),
                ..Default::default()
            })]),
            aliases: List::from_iter([EmailAlias {
                name: "inva..lid".to_string(),
                domain_id,
                enabled: true,
                ..Default::default()
            }]),
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::InvalidPatch)
        .assert_description_contains("Invalid email local part");

    // Valid account creation with local part sanitization
    let account_id = account
        .registry_create_object(Account::User(UserAccount {
            name: " john doe".to_string(),
            domain_id,
            description: "John 'Johnny-D' Doe".to_string().into(),
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: "hello world".to_string(),
                ..Default::default()
            })]),
            aliases: List::from_iter([EmailAlias {
                name: "jdoe".to_string(),
                domain_id,
                enabled: true,
                ..Default::default()
            }]),
            quotas: VecMap::from_iter([
                (StorageQuota::MaxDiskQuota, 1024u64),
                (StorageQuota::MaxEmails, 100u64),
            ]),
            ..Default::default()
        }))
        .await;
    let account_cache = test.server.account(account_id.document_id()).await.unwrap();
    assert_eq!(account_cache.name.as_ref(), "johndoe@example.com");
    assert_eq!(
        account_cache.description.as_deref(),
        Some("John 'Johnny-D' Doe")
    );
    assert_eq!(account_cache.id, account_id.document_id());
    assert_eq!(account_cache.quota_disk, 1024);
    assert_eq!(
        account_cache
            .quota_objects
            .as_ref()
            .unwrap()
            .get(StorageQuota::MaxEmails),
        100
    );
    assert_eq!(
        account_cache.addresses,
        vec![
            EmailAddress {
                local_part: "johndoe".into(),
                domain_id: domain_id.document_id(),
            },
            EmailAddress {
                local_part: "jdoe".into(),
                domain_id: domain_id.document_id(),
            }
        ]
        .into_boxed_slice()
    );
    assert!(account_cache.flags & ACCOUNT_IS_USER != 0);

    // Duplicate account names should not be allowed
    account
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "johndoe".to_string(),
            domain_id,
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::PrimaryKeyViolation);
    account
        .registry_create_object_expect_err(Account::User(UserAccount {
            name: "jdoe".to_string(),
            domain_id,
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::PrimaryKeyViolation);
    account
        .registry_create_object_expect_err(Account::Group(GroupAccount {
            name: "jdoe".to_string(),
            domain_id,
            ..Default::default()
        }))
        .await
        .assert_type(SetErrorType::PrimaryKeyViolation);
    account
        .registry_create_object_expect_err(MailingList {
            name: "jdoe".to_string(),
            domain_id,
            ..Default::default()
        })
        .await
        .assert_type(SetErrorType::PrimaryKeyViolation);

    // Create a group and add it to the account
    let group_id = account
        .registry_create_object(Account::Group(GroupAccount {
            name: "sales".to_string(),
            domain_id,
            ..Default::default()
        }))
        .await;
    let account_cache = test.server.account(group_id.document_id()).await.unwrap();
    assert_eq!(account_cache.name.as_ref(), "sales@example.com");
    assert!(account_cache.flags & ACCOUNT_IS_USER == 0);
    account
        .registry_update_object(
            ObjectType::Account,
            account_id,
            json!({
                Property::MemberGroupIds: {
                    group_id: true
                }
            }),
        )
        .await;
    let account_cache = test.server.account(account_id.document_id()).await.unwrap();
    assert_eq!(
        account_cache.id_member_of.as_ref(),
        &[group_id.document_id()]
    );

    // Linking invalid groups should not be allowed
    account
        .registry_update_object_expect_err(
            ObjectType::Account,
            account_id,
            json!({
                Property::MemberGroupIds: {
                    account_id: true
                }
            }),
        )
        .await
        .assert_type(SetErrorType::InvalidForeignKey);

    // Remove the group membership and make sure it's gone
    account
        .registry_update_object(
            ObjectType::Account,
            account_id,
            json!({
                Property::MemberGroupIds: {
                    group_id: false
                }
            }),
        )
        .await;
    let account_cache = test.server.account(account_id.document_id()).await.unwrap();
    assert!(account_cache.id_member_of.as_ref().is_empty());

    // Create a masked email
    let john = crate::utils::account::Account::new(
        "johndoe@example.com",
        "hello world",
        &[],
        "John",
        account_id,
    );
    let response = john
        .registry_create_many(
            ObjectType::MaskedEmail,
            [json!({
                Property::EmailPrefix: "test",
            })],
        )
        .await;
    let masked = response.created(0);
    let masked_id = masked.object_id();
    let masked_email = masked.text_field("email").to_string();
    assert_eq!(
        test.server
            .account_id_from_email("johndoe@example.com", true)
            .await
            .unwrap(),
        Some(account_id.document_id())
    );
    assert_eq!(
        test.server
            .account_id_from_email(&masked_email, true)
            .await
            .unwrap(),
        Some(account_id.document_id())
    );

    // Create a mailing list
    let list_id = account
        .registry_create_object(MailingList {
            name: "newsletter".to_string(),
            domain_id,
            recipients: Map::new(vec!["jdoe@example.com".to_string()]),
            ..Default::default()
        })
        .await;
    let list_cache = test
        .server
        .try_list(list_id.document_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &list_cache.recipients,
        &Arc::from(Box::from_iter(["jdoe@example.com".into()]))
    );

    // Update mailing list
    account
        .registry_update_object(
            ObjectType::MailingList,
            list_id,
            json!({
                "recipients/sales@example.com": true
            }),
        )
        .await;
    let list_cache = test
        .server
        .try_list(list_id.document_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &list_cache.recipients,
        &Arc::from(Box::from_iter([
            "jdoe@example.com".into(),
            "sales@example.com".into()
        ]))
    );

    // Verify RCPT expansion
    for (address, expected) in [
        (
            "johndoe@example.com",
            EmailCache::Account(account_id.document_id()),
        ),
        (
            "jdoe@example.com",
            EmailCache::Account(account_id.document_id()),
        ),
        (
            "johndoe@beispiel.de",
            EmailCache::Account(account_id.document_id()),
        ),
        (
            "jdoe@beispiel.de",
            EmailCache::Account(account_id.document_id()),
        ),
        (
            "sales@example.com",
            EmailCache::Account(group_id.document_id()),
        ),
        (
            "sales@beispiel.de",
            EmailCache::Account(group_id.document_id()),
        ),
        (
            "newsletter@example.com",
            EmailCache::MailingList(list_id.document_id()),
        ),
        (
            "newsletter@beispiel.de",
            EmailCache::MailingList(list_id.document_id()),
        ),
    ] {
        assert_eq!(
            test.server.rcpt_id_from_email(address).await.unwrap(),
            Some(expected),
            "Unexpected result for address: {address}"
        );
    }
    assert_eq!(
        test.server
            .rcpt_id_from_email("unknown@example.com")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        test.server
            .rcpt_id_from_email("unknown@unknown.com")
            .await
            .unwrap(),
        None
    );

    // MTA rcpt resolve
    let domain_2_id = account
        .registry_create_object(Domain {
            name: "another-example.com".to_string(),
            is_enabled: true,
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            sub_addressing: SubAddressing::Custom(SubAddressingCustom {
                custom_rule: Expression {
                    else_: "false".to_string(),
                    match_: List::from_iter([ExpressionMatch {
                        if_: "matches('^([^.]+)\\.([^.]+)', rcpt)".to_string(),
                        then: "$1".to_string(),
                    }]),
                },
            }),
            ..Default::default()
        })
        .await;
    let account_2_id = account
        .registry_create_object(Account::User(UserAccount {
            name: "subaddresser".to_string(),
            domain_id: domain_2_id,
            ..Default::default()
        }))
        .await;
    assert_eq!(
        test.server.rcpt_resolve("unknown", 0).await.unwrap(),
        RcptResolution::UnknownDomain
    );
    assert_eq!(
        test.server
            .rcpt_resolve("unknown@unknown.org", 0)
            .await
            .unwrap(),
        RcptResolution::UnknownDomain
    );
    assert_eq!(
        test.server
            .rcpt_resolve("jdoe@example.com", 0)
            .await
            .unwrap(),
        RcptResolution::Accept
    );
    assert_eq!(
        test.server
            .rcpt_resolve("johndoe@beispiel.de", 0)
            .await
            .unwrap(),
        RcptResolution::Accept
    );
    assert_eq!(
        test.server
            .rcpt_resolve("sales@example.com", 0)
            .await
            .unwrap(),
        RcptResolution::Accept
    );
    assert_eq!(
        test.server
            .rcpt_resolve("jdoe+promotions@example.com", 0)
            .await
            .unwrap(),
        RcptResolution::Rewrite("jdoe@example.com".into())
    );
    assert_eq!(
        test.server
            .rcpt_resolve("newsletter@example.com", 0)
            .await
            .unwrap(),
        RcptResolution::Expand(Arc::from(Box::from_iter([
            "jdoe@example.com".into(),
            "sales@example.com".into()
        ])))
    );
    assert_eq!(
        test.server
            .rcpt_resolve("unknown@example.com", 0)
            .await
            .unwrap(),
        RcptResolution::Rewrite("catchy@example.com".into())
    );
    assert_eq!(
        test.server
            .rcpt_resolve("subaddresser.ignoreme@another-example.com", 0)
            .await
            .unwrap(),
        RcptResolution::Rewrite("subaddresser@another-example.com".into())
    );
    assert_eq!(
        test.server
            .rcpt_resolve("unknown@another-example.com", 0)
            .await
            .unwrap(),
        RcptResolution::UnknownRecipient
    );
    assert_eq!(
        test.server
            .rcpt_resolve(masked_email.as_str(), 0)
            .await
            .unwrap(),
        RcptResolution::Rewrite("johndoe@example.com".into())
    );

    // Query tests
    assert_eq!(
        account
            .registry_query_ids(
                ObjectType::Domain,
                [(Property::Name, "example.com")],
                [Property::Name]
            )
            .await,
        vec![domain_id]
    );
    assert_eq!(
        account
            .registry_query_ids(
                ObjectType::Account,
                [
                    (Property::Name, "johndoe"),
                    (Property::Type, AccountType::User.as_str()),
                    (Property::Text, "johnny")
                ],
                [Property::Name]
            )
            .await,
        vec![account_id]
    );

    // Delete everything
    john.registry_destroy(ObjectType::MaskedEmail, [masked_id])
        .await
        .assert_destroyed(&[masked_id]);
    account
        .registry_destroy(ObjectType::MailingList, [list_id])
        .await
        .assert_destroyed(&[list_id]);
    account
        .registry_destroy(ObjectType::Account, [group_id, account_id, account_2_id])
        .await
        .assert_destroyed(&[group_id, account_id, account_2_id]);
    account
        .registry_destroy(ObjectType::Domain, [domain_id, domain_2_id])
        .await
        .assert_destroyed(&[domain_id, domain_2_id]);
    assert!(
        test.server
            .try_list(list_id.document_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        test.server
            .try_account(account_id.document_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        test.server
            .try_account(group_id.document_id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(test.server.domain("example.com").await.unwrap().is_none());
    assert!(
        test.server
            .domain("another-example.com")
            .await
            .unwrap()
            .is_none()
    );

    test.cleanup().await;
}
