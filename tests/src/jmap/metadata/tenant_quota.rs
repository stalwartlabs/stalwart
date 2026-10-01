/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use super::{
    fixture::{Ctx, MetaType},
    quota::{ENTRY_SIZE, entry},
};
use crate::utils::server::TestServer;
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{Permission, TenantStorageQuota},
        prelude::{ObjectType, Property},
        structs::{CertificateManagement, DkimManagement, DnsManagement, Domain, Tenant},
    },
    types::EnumImpl,
};
use serde_json::json;

const FILLERS: u64 = 3;

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata tenant quota tests...");
    let ctx = Ctx::new(test);
    let admin = ctx.account("admin");

    let tenant_id = admin
        .registry_create_object(Tenant {
            name: "Metadata Tenant".to_string(),
            ..Default::default()
        })
        .await;
    let domain_id = admin
        .registry_create_object(Domain {
            name: "metatenant.org".to_string(),
            member_tenant_id: tenant_id.into(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let user = admin
        .create_tenant_user_account(
            "member@metatenant.org",
            "tenant member secret with extra safety",
            "Tenant member",
            &[],
            vec![Permission::UnlimitedRequests, Permission::UnlimitedUploads],
            Some(tenant_id),
        )
        .await;

    let mut mailboxes = Vec::new();
    for _ in 0..=FILLERS {
        let response = ctx
            .method(
                &user,
                super::fixture::Using::Plain,
                "Mailbox/set",
                json!({
                    "accountId": user.id_string(),
                    "create": {"m": {"name": ctx.unique(MetaType::Mailbox)}}
                }),
            )
            .await;
        mailboxes.push(
            response
                .pointer("/methodResponses/0/1/created/m/id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("Mailbox not created: {response:?}"))
                .to_string(),
        );
    }

    let tenant_before = test
        .server
        .get_used_quota_tenant(tenant_id.document_id())
        .await
        .expect("tenant quota");
    let (last, fill) = mailboxes.split_last().expect("mailboxes");
    for mailbox in fill {
        ctx.update_ok(
            &user,
            &user,
            MetaType::Mailbox,
            mailbox,
            json!({"metadata": entry()}),
        )
        .await;
    }
    let tenant_after = test
        .server
        .get_used_quota_tenant(tenant_id.document_id())
        .await
        .expect("tenant quota");
    assert!(
        tenant_after - tenant_before >= (ENTRY_SIZE as u64 * FILLERS) as i64,
        "metadata must be charged to the owner's tenant: {tenant_before} before, {tenant_after} after"
    );
    let per_filler = (tenant_after - tenant_before) / FILLERS as i64;
    admin
        .registry_update_object(
            ObjectType::Tenant,
            tenant_id,
            json!({
                Property::Quotas: {
                    TenantStorageQuota::MaxDiskQuota.as_str(): tenant_after + per_filler / 2
                }
            }),
        )
        .await;

    ctx.update_err(
        &user,
        &user,
        MetaType::Mailbox,
        last,
        json!({"metadata": entry()}),
    )
    .await
    .assert_type(SetErrorType::OverQuota);
    ctx.update_err(
        &user,
        &user,
        MetaType::Mailbox,
        last,
        json!({"privateMetadata": entry()}),
    )
    .await
    .assert_type(SetErrorType::OverQuota);

    ctx.destroy(&user, MetaType::Mailbox, &[&fill[0]]).await;
    test.wait_for_tasks().await;
    ctx.update_ok(
        &user,
        &user,
        MetaType::Mailbox,
        last,
        json!({"metadata": entry()}),
    )
    .await;

    ctx.destroy_all(&user).await;
    ctx.purge(&[&user]).await;
    admin.destroy_account(user).await;
    test.wait_for_tasks().await;
    admin
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await;
    admin
        .registry_destroy(ObjectType::Tenant, [tenant_id])
        .await;
    test.wait_for_tasks().await;
}
