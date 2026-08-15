/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AssertResult, ImapConnection, Type};
use crate::utils::server::TestServer;
use imap_proto::ResponseType;

pub async fn test(test: &TestServer) {
    println!("Running UIDONLY tests...");

    // UIDONLY is a one-way switch, so it runs on a connection of its own
    let account = test.account("jdoe@example.com");
    let mut imap = ImapConnection::connect(b"_u ").await;
    imap.assert_read(Type::Untagged, ResponseType::Ok).await;
    imap.authenticate(account.name(), account.secret()).await;

    // The capability is only advertised once authenticated
    imap.send("CAPABILITY").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("UIDONLY");

    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Message numbers still work before UIDONLY is enabled
    imap.send("FETCH 1 (UID)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(" FETCH (")
        .assert_not_contains("UIDFETCH");

    // Enable UIDONLY
    imap.send("ENABLE UIDONLY").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* ENABLED UIDONLY");

    // Every sequence-number command is now rejected with BAD [UIDREQUIRED]
    for command in [
        "FETCH 1 (UID)",
        "STORE 1 +FLAGS (\\Seen)",
        "SEARCH ALL",
        "COPY 1 \"Deleted Items\"",
        "MOVE 1 \"Deleted Items\"",
        "SORT (ARRIVAL) UTF-8 ALL",
        "THREAD REFERENCES UTF-8 ALL",
    ] {
        imap.send(command).await;
        imap.assert_read(Type::Tagged, ResponseType::Bad)
            .await
            .assert_response_code("UIDREQUIRED");
    }

    // The UID variants keep working and now answer with UIDFETCH
    imap.send("UID FETCH 1:* (FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(" UIDFETCH (")
        .assert_not_contains(" FETCH (");

    // The UID is the first token of a UIDFETCH response
    imap.send("UID FETCH 1 (FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 1 UIDFETCH (");

    // UID STORE also answers with UIDFETCH
    imap.send("UID STORE 1 +FLAGS (\\Answered)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(" UIDFETCH (")
        .assert_not_contains(" FETCH (");
    imap.send("UID STORE 1 -FLAGS (\\Answered)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Plain EXPUNGE stays legal, it carries no message numbers
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // The bare sequence set criterion is banned
    imap.send("UID SEARCH 1:*").await;
    imap.assert_read(Type::Tagged, ResponseType::Bad)
        .await
        .assert_response_code("UIDREQUIRED");

    // RFC 9586 names "UID <sequence set>" and ALL as the replacements, so both
    // must keep working; UIDBATCHES results are consumed through the former
    imap.send("UID SEARCH UID 1:*").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID SEARCH ALL").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID FETCH 1:* (UID)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // The SEARCHRES $ variable is not a sequence set either
    imap.send("UID SEARCH RETURN (SAVE) ALL").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID SEARCH $").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // UIDNOTSTICKY must never be advertised alongside UIDONLY
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("UIDNOTSTICKY");

    // Deletions are reported with VANISHED rather than EXPUNGE
    imap.send("UID STORE 1 +FLAGS (\\Deleted)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* VANISHED ")
        .assert_not_contains("* 1 EXPUNGE");

    // The QRESYNC sequence matching parameter is rejected once UIDONLY is on
    imap.send("ENABLE QRESYNC").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("SELECT INBOX (QRESYNC (1 1 1:10 (1,2,3 1,2,3)))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Bad)
        .await
        .assert_response_code("UIDREQUIRED");

    // RFC 8437 requires UNAUTHENTICATE to clear every enabled extension, so
    // message numbers must work again for the next user of this connection
    imap.send("UNAUTHENTICATE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.authenticate(account.name(), account.secret()).await;
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("FETCH 1 (UID)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(" FETCH (")
        .assert_not_contains("UIDFETCH");

    imap.send("LOGOUT").await;
    imap.assert_read(Type::Untagged, ResponseType::Bye).await;
}
