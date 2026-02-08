/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::write::now;

use crate::{
    Server,
    auth::{
        AccountCache, AccountInfo, AccountTenantIds, DomainCache, EmailCache, RoleCache,
        TemporaryAddress, TenantCache,
    },
    config::smtp::auth::DkimSigner,
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
    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    pub fn name(&self) -> &str {
        self.account
            .addresses
            .first()
            .map(|s| s.as_ref())
            .unwrap_or("")
    }

    pub fn description(&self) -> Option<&str> {
        self.account.description.as_deref()
    }

    pub fn tenant_id(&self) -> Option<u32> {
        if self.account.id_tenant != u32::MAX {
            Some(self.account.id_tenant)
        } else {
            None
        }
    }

    pub fn account_tenant_ids(&self) -> AccountTenantIds {
        AccountTenantIds {
            account_id: self.account_id,
            tenant_id: self.tenant_id(),
        }
    }

    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        let now = now();
        self.account.addresses(now).chain(
            self.member_of
                .iter()
                .flat_map(move |member| member.addresses(now)),
        )
    }

    pub fn is_user_account(&self) -> bool {
        self.account.is_user
    }
}

impl AccountCache {
    fn addresses(&self, now: u64) -> impl Iterator<Item = &str> {
        self.addresses.iter().map(|s| s.as_ref()).chain(
            self.addresses_temporary
                .iter()
                .filter_map(move |a| a.validate(now)),
        )
    }
}

impl TemporaryAddress {
    pub fn validate(&self, now: u64) -> Option<&str> {
        if self.expires_at > now {
            Some(self.address.as_ref())
        } else {
            None
        }
    }
}
