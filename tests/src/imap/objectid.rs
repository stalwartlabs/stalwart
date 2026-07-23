/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AssertResult, Type};
use crate::utils::server::TestServer;
use imap_proto::ResponseType;

pub async fn test(test: &TestServer) {
    println!("Running OBJECTID+ tests...");

    let account = test.account("jdoe@example.com");
    let account_id = account.id_string().to_string();
    let mut imap = account.imap_client().await;

    // OBJECTID+ is advertised
    imap.send("CAPABILITY").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("OBJECTID+")
        .assert_count("OBJECTID ", 0);

    // Before activation no object identifiers are leaked
    imap.send("SELECT INBOX").await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("OBJECTID") || l.contains("MAILBOXID")),
        "Pre-activation SELECT leaked object identifiers: {lines:?}"
    );

    // Explicit activation via ENABLE
    imap.send("ENABLE OBJECTID+").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("ENABLED OBJECTID+");

    // SELECT now returns a compound OBJECTID with MAILBOXID and ACCOUNTID
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("[OBJECTID (")
        .assert_contains("MAILBOXID ")
        .assert_contains(&format!("ACCOUNTID {account_id}"));

    // STATUS OBJECTID returns the compound for the queried mailbox, and an
    // already-activated session is not sent a second ENABLED response
    imap.send("STATUS INBOX (OBJECTID)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("OBJECTID (")
        .assert_contains("MAILBOXID ")
        .assert_contains(&format!("ACCOUNTID {account_id}"))
        .assert_not_contains("ENABLED OBJECTID+");

    // FETCH OBJECTID returns EMAILID and THREADID but never ACCOUNTID
    imap.send("UID FETCH 1 (OBJECTID)").await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("OBJECTID (") && l.contains("EMAILID ") && l.contains("THREADID ")),
        "FETCH OBJECTID must include EMAILID and THREADID: {lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("ACCOUNTID")),
        "FETCH OBJECTID must not include ACCOUNTID: {lines:?}"
    );

    // Commands that do not request the OBJECTID item never emit it, even once activated
    imap.send("UID FETCH 1 (FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("OBJECTID");
    imap.send("STATUS INBOX (MESSAGES)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("OBJECTID");

    // EXAMINE returns the compound OBJECTID response code just like SELECT
    imap.send("EXAMINE INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("[OBJECTID (")
        .assert_contains("MAILBOXID ")
        .assert_contains(&format!("ACCOUNTID {account_id}"));

    // CREATE returns the compound OBJECTID response code
    imap.send("CREATE \"ObjIdTest\"").await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let mailbox_id = extract_value(&lines, "MAILBOXID ");
    assert!(
        lines
            .iter()
            .any(|l| l.contains(&format!("ACCOUNTID {account_id}"))),
        "CREATE OBJECTID missing ACCOUNTID: {lines:?}"
    );

    // RENAME returns the compound OBJECTID response code and preserves the MAILBOXID
    imap.send("RENAME \"ObjIdTest\" \"ObjIdRenamed\"").await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let renamed_id = extract_value(&lines, "MAILBOXID ");
    assert_eq!(
        mailbox_id, renamed_id,
        "RENAME must preserve the MAILBOXID: {lines:?}"
    );

    // Identifier-based selection resolves the mailbox regardless of its current name
    imap.send(&format!(
        "SELECT \"DoesNotExist\" (OBJECTID (MAILBOXID {mailbox_id} ACCOUNTID {account_id}))"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("MAILBOXID {mailbox_id}"));

    // An unknown MAILBOXID falls back to selecting by name
    imap.send("SELECT \"ObjIdRenamed\" (OBJECTID (MAILBOXID abcdefgh ACCOUNTID abcdefgh))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("MAILBOXID {mailbox_id}"));

    // An undecodable identifier falls back to selecting by name instead of failing
    imap.send("SELECT \"ObjIdRenamed\" (OBJECTID (MAILBOXID 456))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("MAILBOXID {mailbox_id}"));

    // Unrecognised keys in the OBJECTID parameter are ignored
    imap.send("SELECT \"ObjIdRenamed\" (OBJECTID (FOOBAR baz MAILBOXID 456))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("MAILBOXID {mailbox_id}"));

    // Cleanup
    imap.send("UNSELECT").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("DELETE \"ObjIdRenamed\"").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Implicit activation via the STATUS attribute on a fresh session
    let mut imap2 = test.account("jdoe@example.com").imap_client().await;
    imap2.send("STATUS INBOX (OBJECTID)").await;
    let lines = imap2.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        lines.iter().any(|l| l.contains("ENABLED OBJECTID+")),
        "STATUS did not implicitly activate OBJECTID+: {lines:?}"
    );

    // Implicit activation via the SELECT OBJECTID parameter on a fresh session
    let mut imap3 = test.account("jdoe@example.com").imap_client().await;
    imap3.send("SELECT INBOX (OBJECTID)").await;
    let lines = imap3.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        lines.iter().any(|l| l.contains("ENABLED OBJECTID+")),
        "SELECT (OBJECTID) did not implicitly activate OBJECTID+: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("[OBJECTID (")),
        "SELECT (OBJECTID) did not return a compound OBJECTID: {lines:?}"
    );

    // Activation via FETCH then a plain SELECT/CREATE must still carry the compound code
    let mut imap4 = test.account("jdoe@example.com").imap_client().await;
    imap4.send("SELECT INBOX").await;
    imap4.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap4.send("UID FETCH 1 (OBJECTID)").await;
    let lines = imap4.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        lines.iter().any(|l| l.contains("ENABLED OBJECTID+")),
        "FETCH (OBJECTID) did not implicitly activate OBJECTID+: {lines:?}"
    );
    imap4.send("SELECT INBOX").await;
    imap4
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("[OBJECTID (");
    imap4.send("CREATE \"ObjIdTest4\"").await;
    imap4
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("[OBJECTID (");
    imap4.send("DELETE \"ObjIdTest4\"").await;
    imap4.assert_read(Type::Tagged, ResponseType::Ok).await;
}

fn extract_value(lines: &[String], key: &str) -> String {
    for line in lines {
        if let Some((_, rest)) = line.split_once(key) {
            return rest
                .split([' ', ')'])
                .next()
                .expect("Missing value delimiter")
                .to_string();
        }
    }
    panic!("Key {key:?} not found in {lines:?}");
}
