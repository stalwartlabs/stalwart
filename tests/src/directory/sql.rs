/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use directory::{Account, Credentials, Group, Recipient, backend::sql::SqlDirectory};
use registry::schema::structs::{self, SqlAuthStore};
use store::{Store, backend::sqlite::SqliteStore};

pub async fn test() {
    println!("Running SQL directory tests...");
    let sql_store = Store::SQLite(SqliteStore::open_memory().unwrap().into());

    // Create test directory
    for query in [
        concat!(
            "CREATE TABLE accounts (name TEXT PRIMARY KEY, secret TEXT, description TEXT,",
            " type TEXT NOT NULL, active BOOLEAN DEFAULT TRUE)"
        ),
        concat!(
            "CREATE TABLE group_members (name TEXT NOT NULL, member_of ",
            "TEXT NOT NULL, PRIMARY KEY (name, member_of))"
        ),
        concat!(
            "CREATE TABLE emails (name TEXT NOT NULL, address TEXT NOT",
            " NULL, PRIMARY KEY (name, address))"
        ),
        concat!(
            "INSERT INTO accounts (name, secret, description, type) ",
            "VALUES ('john@example.org', 'john secret', 'John Doe', 'individual')"
        ),
        concat!(
            "INSERT INTO accounts (name, secret, description, type) ",
            "VALUES ('jane@example.org', 'jane secret', 'Jane Doe', 'individual')"
        ),
        concat!(
            "INSERT INTO accounts (name, secret, description, type) ",
            "VALUES ('sales@example.org', NULL, 'Sales Team', 'group')"
        ),
        concat!(
            "INSERT INTO group_members (name, member_of) VALUES ",
            "('john@example.org', 'sales@example.org')"
        ),
        concat!(
            "INSERT INTO group_members (name, member_of) VALUES ",
            "('jane@example.org', 'sales@example.org')"
        ),
        concat!(
            "INSERT INTO emails (name, address) VALUES ",
            "('john@example.org', 'john.doe@example.org')"
        ),
    ] {
        sql_store
            .sql_query::<usize>(query, vec![])
            .await
            .unwrap_or_else(|_| panic!("failed for {query}"));
    }

    let config = structs::SqlDirectory {
        description: "Test SQL directory".to_string(),
        query_login: concat!(
            "SELECT name, secret, description, type FROM accounts ",
            "WHERE name = $1 AND active = true"
        )
        .into(),
        query_recipient: concat!(
            "SELECT name, secret, description, type FROM accounts ",
            "WHERE name = $1 AND active = true"
        )
        .into(),
        query_email_aliases: concat!("SELECT address FROM emails ", "WHERE name = $1")
            .to_string()
            .into(),
        query_member_of: concat!("SELECT member_of FROM group_members ", "WHERE name = $1")
            .to_string()
            .into(),
        column_class: "type".to_string().into(),
        column_description: "description".to_string().into(),
        column_email: "name".into(),
        column_secret: "secret".into(),
        store: SqlAuthStore::Default,
        member_tenant_id: None,
    };

    // Test authentication
    let sql = SqlDirectory::open(config, &sql_store).await.unwrap();
    assert_eq!(
        sql.authenticate(&Credentials::Basic {
            username: "john@example.org".to_string(),
            secret: "john secret".to_string(),
            mfa_token: None,
        })
        .await
        .unwrap(),
        Account {
            email: "john@example.org".to_string(),
            email_aliases: vec!["john.doe@example.org".to_string(),],
            secret: Some("john secret".to_string()),
            groups: Some(vec!["sales@example.org".to_string()]),
            description: Some("John Doe".to_string()),
        }
    );
    assert!(
        sql.authenticate(&Credentials::Basic {
            username: "john@example.org".to_string(),
            secret: "wrong secret".to_string(),
            mfa_token: None,
        })
        .await
        .is_err()
    );

    // Test recipient lookup
    assert_eq!(
        sql.recipient("john@example.org").await.unwrap(),
        Recipient::Account(Account {
            email: "john@example.org".to_string(),
            email_aliases: vec!["john.doe@example.org".to_string()],
            secret: Some("john secret".to_string()),
            groups: Some(vec!["sales@example.org".to_string()]),
            description: Some("John Doe".to_string()),
        })
    );
    assert_eq!(
        sql.recipient("jane@example.org").await.unwrap(),
        Recipient::Account(Account {
            email: "jane@example.org".to_string(),
            email_aliases: vec![],
            secret: Some("jane secret".to_string()),
            groups: Some(vec!["sales@example.org".to_string()]),
            description: Some("Jane Doe".to_string()),
        })
    );
    assert_eq!(
        sql.recipient("sales@example.org").await.unwrap(),
        Recipient::Group(Group {
            email: "sales@example.org".to_string(),
            email_aliases: vec![],
            description: Some("Sales Team".to_string())
        })
    );
    assert_eq!(
        sql.recipient("unknown@example.org").await.unwrap(),
        Recipient::Invalid
    );
}
