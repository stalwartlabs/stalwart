/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    storage::{ObjectQuota, TenantQuota},
};
use registry::{
    schema::enums::{StorageQuota, TenantStorageQuota},
    types::EnumType,
};
use store::write::DirectoryClass;
use trc::AddContext;

impl Server {
    pub async fn get_used_quota_account(&self, account_id: u32) -> trc::Result<i64> {
        self.core
            .storage
            .data
            .get_counter(DirectoryClass::UsedQuota(account_id))
            .await
            .add_context(|err| err.caused_by(trc::location!()).account_id(account_id))
    }

    pub async fn get_used_quota_tenant(&self, tenant_id: u32) -> trc::Result<i64> {
        let todo = "use correct counter";
        self.core
            .storage
            .data
            .get_counter(DirectoryClass::UsedQuota(tenant_id))
            .await
            .add_context(|err| err.caused_by(trc::location!()))
    }

    pub async fn has_available_quota(&self, account_id: u32, item_size: u64) -> trc::Result<()> {
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        if account.quota_disk != 0 {
            let used_quota = self.get_used_quota_account(account_id).await? as u64;

            if used_quota + item_size > account.quota_disk {
                return Err(trc::LimitEvent::Quota
                    .into_err()
                    .ctx(trc::Key::Limit, account.quota_disk)
                    .ctx(trc::Key::Size, used_quota));
            }
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition()
            && let Some(tenant_id) = account.id_tenant
        {
            let tenant = self.tenant(tenant_id).await.caused_by(trc::location!())?;

            if tenant.quota_disk != 0 {
                let used_quota = self.get_used_quota_tenant(tenant_id).await? as u64;

                if used_quota + item_size > tenant.quota_disk {
                    return Err(trc::LimitEvent::TenantQuota
                        .into_err()
                        .ctx(trc::Key::Limit, tenant.quota_disk)
                        .ctx(trc::Key::Size, used_quota));
                }
            }
        }

        // SPDX-SnippetEnd

        Ok(())
    }

    #[inline(always)]
    pub fn object_quota(&self, user_quotas: Option<&ObjectQuota>, object: StorageQuota) -> u32 {
        user_quotas.unwrap_or(&self.core.email.max_objects).0[object as usize]
    }
}

impl ObjectQuota {
    #[inline(always)]
    pub fn set(&mut self, item: StorageQuota, max: u32) {
        self.0[item as usize] = max;
    }

    #[inline(always)]
    pub fn get(&self, item: StorageQuota) -> u32 {
        self.0[item as usize]
    }
}

impl TenantQuota {
    #[inline(always)]
    pub fn set(&mut self, item: TenantStorageQuota, max: u32) {
        self.0[item as usize] = max;
    }

    #[inline(always)]
    pub fn get(&self, item: TenantStorageQuota) -> u32 {
        self.0[item as usize]
    }
}

impl Default for ObjectQuota {
    fn default() -> Self {
        Self([u32::MAX; StorageQuota::COUNT - 1])
    }
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self([u32::MAX; TenantStorageQuota::COUNT - 1])
    }
}
