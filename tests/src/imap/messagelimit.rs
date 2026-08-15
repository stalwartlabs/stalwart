/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AssertResult, ImapConnection, Type, expand_uid_list};
use imap_proto::ResponseType;

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection) {
    println!("Running MESSAGELIMIT tests...");

    // Both limits are advertised, and SAVELIMIT must not be the stricter of the
    // two or MESSAGELIMIT-only clients would hit unexpected COPY rejections
    imap.send("CAPABILITY").await;
    let capabilities = imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("MESSAGELIMIT=")
        .assert_contains("SAVELIMIT=");
    assert!(
        advertised_limit(&capabilities, "SAVELIMIT=")
            >= advertised_limit(&capabilities, "MESSAGELIMIT="),
        "SAVELIMIT must be at least MESSAGELIMIT, got {capabilities:?}"
    );

    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // The test mailboxes hold far fewer messages than the limit, so no
    // command should be truncated and no MESSAGELIMIT code should appear
    for command in [
        "UID FETCH 1:* (UID)",
        "UID SEARCH ALL",
        "UID STORE 1:* +FLAGS.SILENT (\\Seen)",
        "UID STORE 1:* -FLAGS.SILENT (\\Seen)",
    ] {
        imap.send(command).await;
        imap.assert_read(Type::Tagged, ResponseType::Ok)
            .await
            .assert_not_contains("MESSAGELIMIT");
    }

    // EXPUNGE and CLOSE are never limited
    imap.send("EXPUNGE").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("MESSAGELIMIT");

    // COPY is governed by SAVELIMIT and stays well under it here
    imap.send("CREATE Savelimit").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID COPY 1:* Savelimit").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("[COPYUID ")
        .assert_not_contains("MESSAGELIMIT");
    imap.send("DELETE Savelimit").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // UIDAFTER and UIDBEFORE are the search criteria added by RFC 9738
    imap.send("UID SEARCH UIDAFTER 0").await;
    let all = imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap.send("UID SEARCH ALL").await;
    let expected = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert_eq!(
        search_results(&all),
        search_results(&expected),
        "UIDAFTER 0 must match every message"
    );

    // UIDBEFORE 1 can never match anything
    imap.send("UID SEARCH UIDBEFORE 1").await;
    let none = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        search_results(&none).is_empty(),
        "UIDBEFORE 1 must match nothing, got {none:?}"
    );

    // The two criteria partition the mailbox around a pivot UID
    let pivot = search_results(&expected)
        .into_iter()
        .max()
        .expect("INBOX should not be empty");

    imap.send(&format!("UID SEARCH UIDBEFORE {pivot}")).await;
    let before = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        search_results(&before).iter().all(|uid| *uid < pivot),
        "UIDBEFORE {pivot} returned a UID at or above the pivot"
    );

    imap.send(&format!("UID SEARCH UIDAFTER {pivot}")).await;
    let after = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert!(
        search_results(&after).is_empty(),
        "UIDAFTER on the highest UID must match nothing, got {after:?}"
    );

    // Both criteria are still usable inside a boolean expression
    imap.send(&format!("UID SEARCH UIDAFTER 0 UIDBEFORE {pivot}"))
        .await;
    let between = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert_eq!(search_results(&between), search_results(&before));
}

fn advertised_limit(response: &[String], capability: &str) -> u32 {
    response
        .iter()
        .find_map(|line| {
            line.split_whitespace()
                .find_map(|token| token.strip_prefix(capability))
                .map(|limit| limit.trim_end_matches(']').parse().unwrap())
        })
        .unwrap_or_else(|| panic!("No {capability} capability in {response:?}"))
}

fn search_results(response: &[String]) -> Vec<u32> {
    let mut uids: Vec<u32> = response
        .iter()
        .find_map(|line| {
            let line = line.trim_end();
            if let Some(list) = line.strip_prefix("* SEARCH") {
                Some(
                    list.split_whitespace()
                        .filter_map(|uid| uid.parse().ok())
                        .collect(),
                )
            } else if line.starts_with("* ESEARCH") {
                // * ESEARCH (TAG "_x") UID ALL 1:12
                Some(
                    line.split_once(" ALL ")
                        .map(|(_, list)| expand_uid_list(list).into_iter().collect())
                        .unwrap_or_default(),
                )
            } else {
                None
            }
        })
        .unwrap_or_default();
    uids.sort_unstable();
    uids
}
