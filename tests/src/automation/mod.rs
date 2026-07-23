/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acme;
pub mod dkim;
pub mod dns;
pub mod rfc2136;

use registry::{
    schema::{
        enums::{NetworkListenerProtocol, ServiceProtocol},
        prelude::Property,
        structs::{MailExchanger, Service, SystemSettings},
    },
    types::list::List,
};
use utils::map::vec_map::VecMap;

use crate::utils::server::TestServerBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn automation_tests() {
    crate::utils::containers::ensure_acme().await;
    let mut test = TestServerBuilder::new("automation_tests")
        .await
        .with_listener(NetworkListenerProtocol::Http, "http", 8898, false)
        .await
        .with_default_listeners()
        .await
        .build()
        .await;

    // Create admin account
    let account = test.create_admin_account("admin@example.org").await;
    account
        .registry_update_setting(
            SystemSettings {
                mail_exchangers: List::from_iter([
                    MailExchanger {
                        priority: 10u64,
                        hostname: "mx1.example.org".to_string().into(),
                    },
                    MailExchanger {
                        priority: 20u64,
                        hostname: "mx2.example.org".to_string().into(),
                    },
                ]),
                services: VecMap::from_iter([
                    (
                        ServiceProtocol::Caldav,
                        Service {
                            cleartext: false,
                            ..Default::default()
                        },
                    ),
                    (
                        ServiceProtocol::Carddav,
                        Service {
                            cleartext: false,
                            ..Default::default()
                        },
                    ),
                    (
                        ServiceProtocol::Imap,
                        Service {
                            cleartext: false,
                            hostname: "imap.example.org".to_string().into(),
                        },
                    ),
                    (
                        ServiceProtocol::Jmap,
                        Service {
                            cleartext: false,
                            ..Default::default()
                        },
                    ),
                    (
                        ServiceProtocol::Managesieve,
                        Service {
                            cleartext: false,
                            ..Default::default()
                        },
                    ),
                    (
                        ServiceProtocol::Pop3,
                        Service {
                            cleartext: false,
                            hostname: "pop3.example.org".to_string().into(),
                        },
                    ),
                    (
                        ServiceProtocol::Smtp,
                        Service {
                            cleartext: false,
                            hostname: "smtp.example.org".to_string().into(),
                        },
                    ),
                    (
                        ServiceProtocol::Webdav,
                        Service {
                            cleartext: false,
                            ..Default::default()
                        },
                    ),
                ]),

                ..Default::default()
            },
            &[Property::MailExchangers, Property::Services],
        )
        .await;
    account.reload_settings().await;
    test.insert_account(account);

    acme::test(&test).await;
    dkim::test(&test).await;
    dns::test(&test).await;
    rfc2136::test(&test).await;
}
