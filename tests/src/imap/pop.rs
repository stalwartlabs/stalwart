/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    imap::AssertResult,
    pop3::{Pop3Connection, ResponseType},
    server::TestServer,
    smtp::SmtpConnection,
};

pub async fn test(test: &TestServer) {
    println!("Running POP3 tests...");

    // Send 3 test emails
    for i in 0..3 {
        let mut lmtp = SmtpConnection::connect().await;
        lmtp.ingest(
            "bill@example.com",
            &["popper@example.com"],
            &format!(
                concat!(
                    "From: bill@example.com\r\n",
                    "To: popper@example.com\r\n",
                    "Subject: TPS Report {}\r\n",
                    "X-Spam-Status: No\r\n",
                    "\r\n",
                    "I'm going to need those TPS {} reports ASAP.\r\n",
                    "..\r\n",
                    "So, if you could do that, that'd be great."
                ),
                i, i
            ),
        )
        .await;
    }

    // Connect to POP3
    let account = test.account("popper@example.com");
    let mut pop3 = Pop3Connection::connect().await;

    // Capabilities
    pop3.send("CAPA").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("SASL PLAIN")
        .assert_contains("IMPLEMENTATION");

    // Noop
    pop3.send("NOOP").await;
    pop3.assert_read(ResponseType::Ok).await;

    // Authenticate user/pass
    pop3.send("PASS secret").await;
    pop3.assert_read(ResponseType::Err).await;
    pop3.send("USER popper@example.com").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("PASS wrong_secret").await;
    pop3.assert_read(ResponseType::Err).await;
    pop3.send("USER popper@example.com").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send(&format!("PASS {}", account.secret())).await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;

    // Authenticate using AUTH PLAIN
    let mut pop3 = Pop3Connection::connect().await;
    pop3.authenticate(account.name(), account.secret()).await;

    // STAT
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 3 609");

    // UTF8
    pop3.send("UTF8").await;
    pop3.assert_read(ResponseType::Ok).await;

    // LIST
    pop3.send("LIST").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 3 messages")
        .assert_contains("1 203")
        .assert_contains("2 203")
        .assert_contains("3 203");
    pop3.send("LIST 2").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 2 203");

    // UIDL
    pop3.send("UIDL").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 3 messages")
        .assert_contains("1 ")
        .assert_contains("2 ")
        .assert_contains("3 ");
    pop3.send("UIDL 2").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 2 ");

    // RETR
    pop3.send("RETR 1").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 203 octets")
        .assert_contains("I'm going to need those TPS 0 reports ASAP.")
        .assert_contains("So, if you could do that, that'd be great.");
    pop3.send("RETR 3").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 203 octets")
        .assert_contains("I'm going to need those TPS 2 reports ASAP.")
        .assert_contains("So, if you could do that, that'd be great.");
    pop3.send("RETR 4").await;
    pop3.assert_read(ResponseType::Err).await;

    // TOP
    pop3.send("TOP 1 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 203 octets")
        .assert_contains("Subject: TPS Report 0")
        .assert_not_contains("I'm going to need those TPS 0 reports ASAP.");
    pop3.send("TOP 3 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("+OK 203 octets")
        .assert_contains("Subject: TPS Report 2")
        .assert_not_contains("I'm going to need those TPS 2 reports ASAP.");

    // DELE + RSET + QUIT (should not delete messages)
    pop3.send("DELE 1").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("DELE 4").await;
    pop3.assert_read(ResponseType::Err).await;
    pop3.send("RSET").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;
    let mut pop3 = Pop3Connection::connect().await;
    pop3.authenticate(account.name(), account.secret()).await;
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 3 609");

    // DELE + QUIT (should delete messages)
    pop3.send("DELE 2").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;
    pop3.assert_read(ResponseType::Ok).await;
    let mut pop3 = Pop3Connection::connect().await;
    pop3.authenticate(account.name(), account.secret()).await;
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 2 406");
    pop3.send("TOP 1 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("TPS Report 0");
    pop3.send("TOP 2 4").await;
    pop3.assert_read(ResponseType::Multiline)
        .await
        .assert_contains("TPS Report 2");

    // DELE using pipelining
    pop3.send("DELE 1\r\nDELE 2").await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.assert_read(ResponseType::Ok).await;
    pop3.send("QUIT").await;
    pop3.assert_read(ResponseType::Ok).await;
    let mut pop3 = Pop3Connection::connect().await;
    pop3.authenticate(account.name(), account.secret()).await;
    pop3.send("STAT").await;
    pop3.assert_read(ResponseType::Ok)
        .await
        .assert_contains("+OK 0 0");
    pop3.send("QUIT").await;
}
