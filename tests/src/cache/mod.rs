/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod accounting;
pub mod backends;
pub mod lifecycle;

use crate::utils::server::TestServerBuilder;
use common::cache::swap::SwapTier;
use registry::schema::{
    prelude::Object,
    structs::{
        self, CertificateManagement, DkimManagement, DnsManagement, Domain, LocalFileSwap,
        UserAccount,
    },
};
use types::id::Id;

#[tokio::test(flavor = "multi_thread")]
pub async fn cache_tests() {
    let builder = TestServerBuilder::new("cache_tests").await;
    let swap_path = std::path::PathBuf::from(builder.tmp_dir()).join("swap");
    std::fs::create_dir_all(&swap_path).expect("Failed to create the swap directory");

    let builder = builder
        .with_object(Object::from(structs::Cache {
            swap: structs::CacheSwap::LocalFile(LocalFileSwap {
                path: swap_path.to_string_lossy().into_owned(),
                flush_changes: 1,
                min_account_size: 0,
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await;

    let domain_id = create_domain(&builder).await;
    let accounts = [
        provision_account(&builder, domain_id, "cachetester").await,
        provision_account(&builder, domain_id, "cachetester2").await,
        provision_account(&builder, domain_id, "cachetester3").await,
    ];

    let test = builder.build().await;

    println!("Testing caching subsystem...");

    assert!(
        test.server.inner.cache.swap.is_enabled(),
        "the swap tier did not come up from the registry settings"
    );
    SwapTier::start(&test.server.inner);

    backends::test(&test).await;
    accounting::test(&test, accounts[0], accounts[1]).await;
    lifecycle::test(&test, accounts[2]).await;

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

async fn create_domain(builder: &TestServerBuilder) -> Id {
    builder
        .insert_object(Domain {
            is_enabled: true,
            name: "cachetest.example.org".to_string(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await
}

async fn provision_account(builder: &TestServerBuilder, domain_id: Id, name: &str) -> u32 {
    builder
        .insert_object(structs::Account::User(UserAccount {
            name: name.to_string(),
            domain_id,
            description: name.to_string().into(),
            ..Default::default()
        }))
        .await
        .document_id()
}
