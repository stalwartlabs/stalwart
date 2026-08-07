/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServerBuilder;
use registry::{
    schema::{
        enums::{MtaProtocol, Permission},
        properties::Property,
        structs::{
            CalendarAlarm, Expression, ExpressionMatch, Imap, Jmap, MtaExtensions,
            MtaOutboundStrategy, MtaRoute, MtaRouteRelay, MtaStageAuth, Sharing,
        },
    },
    types::list::List,
};

pub mod calendar;
pub mod compliance;
pub mod contacts;
pub mod core;
pub mod files;
pub mod mail;
pub mod principal;

#[tokio::test(flavor = "multi_thread")]
pub async fn jmap_tests() {
    let mut test = TestServerBuilder::new("jmap_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;

    // Create admin account
    let admin = test.create_admin_account("admin@example.com").await;

    // Create test users
    for (name, secret, description, aliases) in [
        (
            "jdoe@example.com",
            "12345 + extra safety",
            "John Doe",
            &["john.doe@example.com"][..],
        ),
        (
            "jane.smith@example.com",
            "abcde + extra safety",
            "Jane Smith",
            &["jane@example.com"],
        ),
        (
            "bill@example.com",
            "098765 + extra safety",
            "Bill Foobar",
            &["bill.foobar@example.com"],
        ),
        (
            "robert@example.com",
            "aabbcc + extra safety",
            "Robert Foobar",
            &[][..],
        ),
    ] {
        let account = admin
            .create_user_account(
                name,
                secret,
                description,
                aliases,
                vec![Permission::UnlimitedRequests, Permission::UnlimitedUploads],
            )
            .await;
        test.insert_account(account);
    }

    // Create test group
    test.insert_account(
        admin
            .create_group_account("sales@example.com", "Sales Group", &[])
            .await,
    );

    // Add test settings
    admin
        .registry_create_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await;
    admin
        .registry_update_setting(
            Jmap {
                set_max_objects: 100_000,
                get_max_results: 100_000,
                event_source_throttle: 500u64.into(),
                push_throttle: 500u64.into(),
                websocket_throttle: 500u64.into(),
                push_attempt_wait: 500u64.into(),
                ..Default::default()
            },
            &[
                Property::SetMaxObjects,
                Property::GetMaxResults,
                Property::EventSourceThrottle,
                Property::PushThrottle,
                Property::WebsocketThrottle,
                Property::PushAttemptWait,
            ],
        )
        .await;
    admin
        .registry_create_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(CalendarAlarm {
            min_trigger_interval: 1000u64.into(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(Sharing {
            allow_directory_queries: true,
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaOutboundStrategy {
            route: Expression {
                match_: List::from_iter([
                    ExpressionMatch {
                        if_: "rcpt_domain == 'example.com'".into(),
                        then: "'local'".into(),
                    },
                    ExpressionMatch {
                        if_: concat!(
                            "contains(['remote.org', 'foobar.com', ",
                            "'test.com', 'other_domain.com'], rcpt_domain)"
                        )
                        .into(),
                        then: "'mock-smtp'".into(),
                    },
                ]),
                else_: "'mx'".to_string(),
            },
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MtaRoute::Relay(MtaRouteRelay {
            address: "127.0.0.1".into(),
            port: 9999,
            allow_invalid_certs: true,
            implicit_tls: false,
            name: "mock-smtp".into(),
            protocol: MtaProtocol::Smtp,
            ..Default::default()
        }))
        .await;
    admin
        .registry_create_object(MtaExtensions {
            future_release: Expression {
                match_: List::from_iter([ExpressionMatch {
                    if_: "!is_empty(authenticated_as)".into(),
                    then: "99999999d".into(),
                }]),
                else_: "false".to_string(),
            },
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    test.insert_account(admin);

    mail::get::test(&test).await;
    mail::set::test(&test).await;
    mail::parse::test(&test).await;
    mail::query::test(&test).await;
    mail::search_snippet::test(&test).await;
    mail::changes::test(&test).await;
    mail::query_changes::test(&test).await;
    mail::copy::test(&test).await;
    mail::thread_get::test(&test).await;
    mail::thread_merge::test(&test).await;
    mail::mailbox::test(&test).await;
    mail::acl::test(&test).await;
    mail::sieve_script::test(&test).await;
    mail::vacation_response::test(&test).await;
    mail::submission::test(&test).await;

    core::event_source::test(&test).await;
    core::websocket::test(&test).await;
    core::push_subscription::test(&test).await;
    core::blob::test(&test).await;

    contacts::addressbook::test(&test).await;
    contacts::contact::test(&test).await;
    contacts::acl::test(&test).await;

    files::node::test(&test).await;
    files::acl::test(&test).await;

    calendar::calendars::test(&test).await;
    calendar::event::test(&test).await;
    calendar::notification::test(&test).await;
    calendar::alarm::test(&test).await;

    calendar::identity::test(&test).await;
    calendar::acl::test(&test).await;

    principal::get::test(&test).await;
    principal::availability::test(&test).await;

    compliance::test(&test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

pub fn find_values(string: &str, name: &str) -> Vec<String> {
    let mut last_pos = 0;
    let mut values = Vec::new();

    while let Some(pos) = string[last_pos..].find(name) {
        let mut value = string[last_pos + pos + name.len()..]
            .split('"')
            .nth(1)
            .unwrap();
        if value.ends_with('\\') {
            value = &value[..value.len() - 1];
        }
        values.push(value.to_string());
        last_pos += pos + name.len();
    }

    values
}

pub fn replace_values(mut string: String, find: &[String], replace: &[String]) -> String {
    for (find, replace) in find.iter().zip(replace.iter()) {
        string = string.replace(find, replace);
    }
    string
}

pub fn replace_boundaries(string: String) -> String {
    let values = find_values(&string, "boundary=");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("boundary_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}

pub fn replace_blob_ids(string: String) -> String {
    let values = find_values(&string, "blobId\":");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("blob_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}
