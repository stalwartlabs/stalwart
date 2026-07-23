/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{smtp::session::TestSession, utils::server::TestServerBuilder};
use registry::{
    schema::structs::{
        Expression, ExpressionMatch, MtaStageMail, MtaStageRcpt, SieveSystemInterpreter,
        SieveSystemScript,
    },
    types::list::List,
};

const MAIL_SCRIPT: &str = r#"require ["variables", "envelope"];
if allof( envelope :domain :is "from" "foobar.org", 
          envelope :localpart :contains "from" "admin" ) {
     set "envelope.from" "MAILER-DAEMON@foobar.org";
}
"#;
const MAIL_RCPT: &str = r#"require ["variables", "envelope", "regex"];
if allof( envelope :localpart :contains "to" ".",
          envelope :regex "to" "(.+)@(.+)$") {
    set :replace "." "" "to" "${1}";
    set "envelope.to" "${to}@${2}";
}
"#;

#[tokio::test(flavor = "multi_thread")]
pub async fn address_rewrite() {
    let mut test = TestServerBuilder::new("smtp_rewrite_test")
        .await
        .with_http_listener(19007)
        .await
        .disable_services()
        .build()
        .await;

    // Add test settings
    let admin = test.account("admin");
    admin.mta_no_auth().await;
    admin
        .registry_create_object(MtaStageMail {
            rewrite: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: concat!(
                        "ends_with(sender_domain, '.foobar.net') & ",
                        "matches('^([^.]+)@([^.]+)\\.(.+)$', sender)"
                    )
                    .into(),
                    then: "$1 + '+' + $2 + '@' + $3".into(),
                }]),
                else_: "false".into(),
            },
            script: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "sender_domain = 'foobar.org'".into(),
                    then: "'mail'".into(),
                }]),
                else_: "false".into(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaStageRcpt {
            rewrite: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "rcpt_domain = 'foobar.net' & matches('^([^.]+)\\.([^.]+)@(.+)$', rcpt)"
                        .into(),
                    then: "$1 + '+' + $2 + '@' + $3".into(),
                }]),
                else_: "false".into(),
            },
            script: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "rcpt_domain = 'foobar.org'".into(),
                    then: "'rcpt'".into(),
                }]),
                else_: "false".into(),
            },
            allow_relaying: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(SieveSystemInterpreter {
            default_from_address: Expression {
                else_: "'sieve@foobar.org'".into(),
                ..Default::default()
            },

            default_from_name: Expression {
                else_: "'Sieve Daemon'".into(),
                ..Default::default()
            },
            default_return_path: Expression {
                else_: "''".into(),
                ..Default::default()
            },
            message_id_hostname: Some("'mx.foobar.org'".into()),
            duplicate_expiry: (86_400u64 * 100 * 7).into(),
            max_cpu_cycles: 10000,
            max_nested_includes: 5,
            max_out_messages: 5,
            max_received_headers: 50,
            max_redirects: 3,
            ..Default::default()
        })
        .await;
    for (name, contents) in [("mail", MAIL_SCRIPT), ("rcpt", MAIL_RCPT)] {
        admin
            .registry_create_object(SieveSystemScript {
                name: name.to_string(),
                contents: contents.to_string(),
                is_active: true,
                ..Default::default()
            })
            .await;
    }
    admin.reload_settings().await;
    test.reload_core();

    // Init session
    let mut session = test.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.doe.org").await;

    // Sender rewrite using regex
    session.mail_from("bill@doe.foobar.net", "250").await;
    assert_eq!(
        session.data.mail_from.as_ref().unwrap().address,
        "bill+doe@foobar.net"
    );
    session.reset();

    // Sender rewrite using sieve
    session.mail_from("this_is_admin@foobar.org", "250").await;
    assert_eq!(
        session.data.mail_from.as_ref().unwrap().address_lcase,
        "mailer-daemon@foobar.org"
    );

    // Recipient rewrite using regex
    session.rcpt_to("mary.smith@foobar.net", "250").await;
    assert_eq!(
        session.data.rcpt_to.last().unwrap().address,
        "mary+smith@foobar.net"
    );

    // Remove duplicates
    session.rcpt_to("mary.smith@foobar.net", "250").await;
    assert_eq!(session.data.rcpt_to.len(), 1);

    // Recipient rewrite using sieve
    session.rcpt_to("m.a.r.y.s.m.i.t.h@foobar.org", "250").await;
    assert_eq!(
        session.data.rcpt_to.last().unwrap().address,
        "marysmith@foobar.org"
    );
}
