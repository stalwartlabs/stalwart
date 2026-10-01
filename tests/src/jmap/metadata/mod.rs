/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;

pub mod capability;
pub mod changes;
pub mod copy;
pub mod cross_protocol;
pub mod fixture;
pub mod get_set;
pub mod objects;
pub mod performance;
pub mod private;
pub mod private_cleanup;
pub mod push;
pub mod query;
pub mod quota;
pub mod rights;
pub mod selection;
pub mod tenant_quota;
pub mod validation;

pub async fn test(test: &TestServer) {
    let only = std::env::var("METADATA_TESTS").ok();
    let enabled = |group: &str| {
        only.as_deref()
            .is_none_or(|groups| groups.split(',').any(|g| g.trim() == group))
    };

    if enabled("capability") {
        capability::test(test).await;
    }
    if enabled("get_set") {
        get_set::test(test).await;
    }
    if enabled("selection") {
        selection::test(test).await;
    }
    if enabled("validation") {
        validation::test(test).await;
    }
    if enabled("rights") {
        rights::test(test).await;
    }
    if enabled("changes") {
        changes::test(test).await;
    }
    if enabled("query") {
        query::test(test).await;
    }
    if enabled("copy") {
        copy::test(test).await;
    }
    if enabled("quota") {
        quota::test(test).await;
        tenant_quota::test(test).await;
    }
    if enabled("private") {
        private::test(test).await;
        private_cleanup::test(test).await;
        push::test(test).await;
    }
    if enabled("cross_protocol") {
        cross_protocol::test(test).await;
    }
    if enabled("performance") {
        performance::test(test).await;
    }
    if enabled("objects") {
        objects::test(test).await;
    }
}
