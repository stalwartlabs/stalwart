/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::{enums::Locale, prelude::Object};
use store::write::now;

use crate::{
    Server,
    auth::{
        AccountCache, AccountInfo, AccountTenantIds, DomainCache, EmailCache, RoleCache,
        TenantCache,
    },
    config::smtp::auth::DkimSigner,
    storage::ObjectQuota,
};
use std::sync::Arc;

impl Server {
    pub async fn domain(&self, domain: &str) -> trc::Result<Option<Arc<DomainCache>>> {
        todo!()
    }

    pub async fn account(&self, id: u32) -> trc::Result<Arc<AccountCache>> {
        /*

        Err(trc::AuthEvent::Error
                .into_err()
                .details("Account not found.")
                .caused_by(trc::location!()))
         */
        todo!()
    }

    pub async fn account_id(&self, address: &str) -> trc::Result<Option<u32>> {
        todo!()
    }

    pub async fn account_info(&self, id: u32) -> trc::Result<AccountInfo> {
        let account = self.account(id).await?;
        let mut member_of = Vec::with_capacity(account.id_member_of.len());
        for &group_id in &account.id_member_of {
            member_of.push(self.account(group_id).await?);
        }

        Ok(AccountInfo {
            account_id: id,
            account,
            member_of,
        })
    }

    pub async fn role(&self, id: u32) -> trc::Result<Arc<RoleCache>> {
        todo!()
    }

    pub async fn tenant(&self, id: u32) -> trc::Result<Arc<TenantCache>> {
        todo!()
    }

    pub async fn dkim_signers(&self, domain: &str) -> trc::Result<Option<Arc<[DkimSigner]>>> {
        todo!()
    }
}

impl AccountInfo {
    #[inline(always)]
    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    pub fn name(&self) -> &str {
        self.account
            .addresses
            .first()
            .map(|s| s.as_ref())
            .unwrap_or_default()
    }

    #[inline(always)]
    pub fn description(&self) -> Option<&str> {
        self.account.description.as_deref()
    }

    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.account.id_tenant
    }

    #[inline(always)]
    pub fn account_tenant_ids(&self) -> AccountTenantIds {
        AccountTenantIds {
            account_id: self.account_id,
            tenant_id: self.account.id_tenant,
        }
    }

    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        self.account
            .addresses
            .iter()
            .chain(
                self.member_of
                    .iter()
                    .flat_map(move |member| member.addresses.iter()),
            )
            .map(|a| a.as_str())
    }

    #[inline(always)]
    pub fn is_user_account(&self) -> bool {
        self.account.is_user
    }

    #[inline(always)]
    pub fn locale(&self) -> Locale {
        self.account.locale
    }

    #[inline(always)]
    pub fn object_quotas(&self) -> Option<&ObjectQuota> {
        self.account.quota_objects.as_deref()
    }
}

impl AccountCache {
    #[inline(always)]
    pub fn name(&self) -> &str {
        self.addresses
            .first()
            .map(|s| s.as_ref())
            .unwrap_or_default()
    }

    #[inline(always)]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[inline(always)]
    pub fn tenant_id(&self) -> Option<u32> {
        self.id_tenant
    }

    #[inline(always)]
    pub fn is_user_account(&self) -> bool {
        self.is_user
    }

    #[inline(always)]
    pub fn disk_quota(&self) -> u64 {
        self.quota_disk
    }

    #[inline(always)]
    pub fn object_quotas(&self) -> Option<&ObjectQuota> {
        self.quota_objects.as_deref()
    }

    #[inline(always)]
    pub fn account_tenant_ids(&self, account_id: u32) -> AccountTenantIds {
        AccountTenantIds {
            account_id,
            tenant_id: self.id_tenant,
        }
    }
}
