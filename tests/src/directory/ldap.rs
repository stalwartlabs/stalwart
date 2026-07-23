/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{Account, Credentials, Group, Recipient, backend::ldap::LdapDirectory};
use registry::{
    schema::structs::{self, SecretKeyOptional, SecretKeyValue},
    types::map::Map,
};

pub async fn test() {
    println!("Running LDAP directory tests...");
    crate::utils::containers::ensure_openldap().await;
    let mut config = ldap_test_directory();

    // Test bind authentication
    let ldap = LdapDirectory::open(config.clone()).await.unwrap();
    assert_eq!(
        ldap.authenticate(&Credentials::Basic {
            username: "john.doe@example.org".into(),
            secret: "this is John's LDAP password".into(),
            mfa_token: None,
        })
        .await
        .unwrap(),
        Account {
            email: "john.doe@example.org".into(),
            email_aliases: vec!["john@example.org".into()],
            secret: Some("$app$8958830913002348890$".into()),
            groups: Some(vec!["sales@example.org".into()]),
            description: Some("John Doe".into()),
        }
    );
    assert_eq!(
        ldap.authenticate(&Credentials::Basic {
            username: "jane.smith@example.org".into(),
            secret: "this is Jane's LDAP password".into(),
            mfa_token: None,
        })
        .await
        .unwrap(),
        Account {
            email: "jane.smith@example.org".into(),
            email_aliases: vec![],
            secret: Some("$app$4096614298472586996$".into()),
            groups: Some(vec![
                "sales@example.org".into(),
                "corporate@example.org".into()
            ]),
            description: Some("Jane Smith".into()),
        }
    );
    assert!(
        ldap.authenticate(&Credentials::Basic {
            username: "jane.smith@example.org".into(),
            secret: "this is a wrong LDAP password".into(),
            mfa_token: None,
        })
        .await
        .is_err()
    );

    // Test direct authentication (without bind)
    config.attr_secret = Map::new(vec!["userPassword".to_string()]);
    config.attr_secret_changed = Map::new(vec![]);
    config.bind_authentication = false;
    let ldap = LdapDirectory::open(config.clone()).await.unwrap();
    assert_eq!(
        ldap.authenticate(&Credentials::Basic {
            username: "john.doe@example.org".into(),
            secret: "this is John's LDAP password".into(),
            mfa_token: None,
        })
        .await
        .unwrap(),
        Account {
            email: "john.doe@example.org".into(),
            email_aliases: vec!["john@example.org".into()],
            secret: Some("this is John's LDAP password".into()),
            groups: Some(vec!["sales@example.org".into()]),
            description: Some("John Doe".into()),
        }
    );
    assert!(
        ldap.authenticate(&Credentials::Basic {
            username: "john.doe@example.org".into(),
            secret: "this is a wrong LDAP password".into(),
            mfa_token: None,
        })
        .await
        .is_err()
    );

    // Test recipient lookup
    assert_eq!(
        ldap.recipient("john.doe@example.org").await.unwrap(),
        Recipient::Account(Account {
            email: "john.doe@example.org".into(),
            email_aliases: vec!["john@example.org".into()],
            secret: Some("this is John's LDAP password".into()),
            groups: Some(vec!["sales@example.org".into()]),
            description: Some("John Doe".into())
        })
    );
    assert_eq!(
        ldap.recipient("jane.smith@example.org").await.unwrap(),
        Recipient::Account(Account {
            email: "jane.smith@example.org".into(),
            email_aliases: vec![],
            secret: Some("this is Jane's LDAP password".into()),
            groups: Some(vec![
                "sales@example.org".into(),
                "corporate@example.org".into()
            ]),
            description: Some("Jane Smith".into())
        })
    );
    assert_eq!(
        ldap.recipient("sales@example.org").await.unwrap(),
        Recipient::Group(Group {
            email: "sales@example.org".into(),
            email_aliases: vec![],
            description: Some("sales".into())
        })
    );
    assert_eq!(
        ldap.recipient("corporate@example.org").await.unwrap(),
        Recipient::Group(Group {
            email: "corporate@example.org".into(),
            email_aliases: vec!["everyone@example.org".into()],
            description: Some("corporate".into())
        })
    );
    assert_eq!(
        ldap.recipient("nonexistent@example.org").await.unwrap(),
        Recipient::Invalid
    );
}

pub fn ldap_test_directory() -> structs::LdapDirectory {
    structs::LdapDirectory {
        url: "ldap://localhost".into(),
        use_tls: false,
        attr_class: Map::new(vec!["objectClass".to_string()]),
        attr_description: Map::new(vec!["cn".to_string()]),
        attr_email: Map::new(vec!["mail".to_string()]),
        attr_email_alias: Map::new(vec!["mailAlias".to_string()]),
        attr_member_of: Map::new(vec!["memberOf".to_string()]),
        attr_secret: Map::new(vec![]),
        attr_secret_changed: Map::new(vec!["shadowLastChange".to_string()]),
        base_dn: "dc=stalwart,dc=test".into(),
        bind_dn: "cn=admin,dc=stalwart,dc=test".to_string().into(),
        bind_secret: SecretKeyOptional::Value(SecretKeyValue {
            secret: "admin".into(),
        }),
        filter_member_of: "(&(objectClass=groupOfNames)(member=?))".to_string().into(),
        filter_login: "(&(objectClass=inetOrgPerson)(mail=?))".into(),
        filter_mailbox: concat!(
            "(|(&(objectClass=inetOrgPerson)(|(mail=?)(mailAlias=?)))",
            "(&(objectClass=groupOfNames)(|(mail=?)(mailAlias=?))))"
        )
        .into(),
        group_class: "groupOfNames".into(),
        bind_authentication: true,
        description: "Test LDAP directory".into(),
        ..Default::default()
    }
}
