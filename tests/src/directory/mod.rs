/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod integration;
pub mod ldap;
pub mod oidc;
#[cfg(feature = "sqlite")]
pub mod sql;
pub mod synchronization;

#[tokio::test(flavor = "multi_thread")]
pub async fn directory_tests() {
    ldap::test().await;
    oidc::test().await;
    #[cfg(feature = "sqlite")]
    sql::test().await;
    synchronization::test().await;
    integration::test().await;
}
