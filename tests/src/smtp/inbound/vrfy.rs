/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Core;

use store::Stores;
use utils::config::Config;

use smtp::core::Session;

use crate::{
    AssertConfig,
    smtp::{
        TempDir, TestSMTP,
        session::{TestSession, VerifyResponse},
    },
};

const CONFIG: &str = r#"
[storage]
data = "rocksdb"
lookup = "rocksdb"
blob = "rocksdb"
fts = "rocksdb"
directory = "local"

[store."rocksdb"]
type = "rocksdb"
path = "{TMP}/data.db"

[directory."local"]
type = "memory"

[[directory."local".principals]]
name = "john"
description = "John Doe"
secret = "secret"
email = ["john@foobar.org"]
email-list = ["sales@foobar.org"]

[[directory."local".principals]]
name = "jane"
description = "Jane Doe"
secret = "p4ssw0rd"
email = "jane@foobar.org"
email-list = ["sales@foobar.org"]

[[directory."local".principals]]
name = "bill"
description = "Bill Foobar"
secret = "p4ssw0rd"
email = "bill@foobar.org"
email-list = ["sales@foobar.org"]

[session.rcpt]
directory = "'local'"

[session.extensions]
vrfy = [{if = "remote_ip = '10.0.0.1'", then = true},
        {else = false}]
expn = [{if = "remote_ip = '10.0.0.1'", then = true},
        {else = false}]

"#;

#[tokio::test]
async fn vrfy_expn() {
    // Enable logging
    crate::enable_logging();

    let tmp_dir = TempDir::new("smtp_vrfy_test", true);
    let mut config = Config::new(tmp_dir.update_config(CONFIG)).unwrap();
    let stores = Stores::parse_all(&mut config, false).await;
    let core = Core::parse(&mut config, stores, Default::default()).await;
    config.assert_no_errors();

    // EHLO should not advertise VRFY/EXPN to 10.0.0.2
    let mut session = Session::test(TestSMTP::from_core(core).server);
    session.data.remote_ip_str = "10.0.0.2".into();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_not_contains("EXPN")
        .assert_not_contains("VRFY");
    session.cmd("VRFY john", "252 2.5.1").await;
    session.cmd("EXPN sales@foobar.org", "252 2.5.1").await;

    // EHLO should advertise VRFY/EXPN for 10.0.0.1
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session
        .ehlo("mx.foobar.org")
        .await
        .assert_contains("EXPN")
        .assert_contains("VRFY");

    // Successful VRFY
    session.cmd("VRFY john", "250 john@foobar.org").await;

    // Successful EXPN
    session
        .cmd("EXPN sales@foobar.org", "250")
        .await
        .assert_contains("250-john@foobar.org")
        .assert_contains("250-jane@foobar.org")
        .assert_contains("250 bill@foobar.org");

    // Non-existent VRFY
    session.cmd("VRFY robert", "550 5.1.2").await;

    // Non-existent EXPN
    session.cmd("EXPN procurement", "550 5.1.2").await;
}
