/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::AssertResult;
use crate::utils::{server::TestServer, sieve::SieveConnection};
use imap_proto::ResponseType;

pub async fn test(test: &TestServer) {
    println!("Running ManageSieve tests...");

    // Connect to ManageSieve
    let mut sieve = SieveConnection::connect().await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("IMPLEMENTATION");

    // Authenticate
    let account = test.account("jdoe@example.com");
    sieve.authenticate(account.name(), account.secret()).await;

    // CheckScript
    sieve.send("CHECKSCRIPT \"if true { keep; }\"").await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve.send("CHECKSCRIPT \"keep :invalidtag;\"").await;
    sieve.assert_read(ResponseType::No).await;

    // PutScript
    sieve
        .send_literal("PUTSCRIPT \"simple script\" ", "if true { keep; }\r\n")
        .await;
    sieve.assert_read(ResponseType::Ok).await;

    // PutScript should overwrite existing scripts
    sieve.send("PUTSCRIPT \"holidays\" \"discard;\"").await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve
        .send_literal(
            "PUTSCRIPT \"holidays\" ",
            "require \"vacation\"; vacation \"Gone fishin'\";\r\n",
        )
        .await;
    sieve.assert_read(ResponseType::Ok).await;

    // GetScript
    sieve.send("GETSCRIPT \"simple script\"").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("if true");
    sieve.send("GETSCRIPT \"holidays\"").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("Gone fishin'");
    sieve.send("GETSCRIPT \"dummy\"").await;
    sieve.assert_read(ResponseType::No).await;

    // ListScripts
    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("simple script")
        .assert_contains("holidays")
        .assert_count("ACTIVE", 0);

    // RenameScript
    sieve
        .send("RENAMESCRIPT \"simple script\" \"minimalist script\"")
        .await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve
        .send("RENAMESCRIPT \"holidays\" \"minimalist script\"")
        .await;
    sieve
        .assert_read(ResponseType::No)
        .await
        .assert_contains("ALREADYEXISTS");

    // SetActive
    sieve.send("SETACTIVE \"holidays\"").await;
    sieve.assert_read(ResponseType::Ok).await;

    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("minimalist script")
        .assert_contains("holidays\" ACTIVE");

    // Deleting an active script should not be allowed
    sieve.send("DELETESCRIPT \"holidays\"").await;
    sieve
        .assert_read(ResponseType::No)
        .await
        .assert_contains("ACTIVE");

    // Deactivate all
    sieve.send("SETACTIVE \"\"").await;
    sieve.assert_read(ResponseType::Ok).await;

    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_contains("minimalist script")
        .assert_contains("holidays")
        .assert_count("ACTIVE", 0);

    // DeleteScript
    sieve.send("DELETESCRIPT \"holidays\"").await;
    sieve.assert_read(ResponseType::Ok).await;
    sieve.send("DELETESCRIPT \"minimalist script\"").await;
    sieve.assert_read(ResponseType::Ok).await;

    sieve.send("LISTSCRIPTS").await;
    sieve
        .assert_read(ResponseType::Ok)
        .await
        .assert_count("minimalist script", 0)
        .assert_count("holidays", 0);
}
