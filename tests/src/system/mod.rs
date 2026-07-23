/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod antispam;
pub mod archiving;
pub mod authentication;
pub mod authorization;
pub mod crypto;
pub mod delivery;
pub mod directory;
pub mod oidc;
pub mod purge;
pub mod quota;
pub mod security;
pub mod task;
pub mod tenant;

use crate::utils::server::TestServerBuilder;
use registry::schema::structs::{Expression, Imap, MtaStageAuth};

#[tokio::test(flavor = "multi_thread")]
pub async fn system_tests() {
    let mut test = TestServerBuilder::new("system_tests")
        .await
        .with_default_listeners()
        .await
        .with_object(Imap {
            allow_plain_text_auth: true,
            ..Default::default()
        })
        .await
        .with_object(MtaStageAuth {
            require: Expression {
                else_: "false".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await
        .build()
        .await;

    // Create admin account
    let admin = test
        .create_user_account(
            "admin",
            "admin@example.org",
            "these_pretzels_are_making_me_thirsty",
            &[],
            "Admin",
        )
        .await;
    test.account("admin")
        .assign_roles_to_account(admin.id(), &["user", "system"])
        .await;
    test.insert_account(admin);

    directory::test(&test).await;
    authentication::test(&test).await;
    oidc::test(&mut test).await;
    authorization::test(&mut test).await;
    tenant::test(&mut test).await;
    security::test(&mut test).await;
    quota::test(&mut test).await;
    purge::test(&mut test).await;
    delivery::test(&mut test).await;
    crypto::test(&mut test).await;
    antispam::test(&mut test).await;
    archiving::test(&mut test).await;
    task::test(&mut test).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}
