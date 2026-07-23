/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    auth::{AccessToken, RECOVERY_ADMIN_ID, permissions::PermissionsListBuilder},
};
use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use registry::{
    schema::enums::{Locale, Permission},
    types::EnumImpl,
};
use serde::Serialize;
use utils::DomainPart;

#[derive(Debug, Clone, Serialize)]
pub struct Account {
    pub permissions: Vec<Permission>,
    pub edition: &'static str,
    pub locale: Locale,
}

pub trait AccountApiHandler: Sync + Send {
    fn handle_account_request(
        &self,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl AccountApiHandler for Server {
    async fn handle_account_request(
        &self,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        #[cfg(not(feature = "enterprise"))]
        let edition = "oss";

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let edition = if self.core.is_enterprise_edition() {
            "enterprise"
        } else {
            "community"
        };
        // SPDX-SnippetEnd

        let account_info = self.account_info(access_token.account_id()).await?;
        let is_external_directory = if let Some(domain_name) = account_info.name().try_domain_part()
            && self.get_directory_for_domain(domain_name).await?.is_some()
        {
            true
        } else {
            false
        };
        let is_recovery_admin = access_token.account_id() == RECOVERY_ADMIN_ID;
        let permissions = if !self.registry().is_bootstrap_mode()
            && let Some(scope) = access_token.access_scope()
        {
            let mut permissions = scope.permissions.clone();

            for p in [
                Permission::SysDmarcInternalReportUpdate,
                Permission::SysDmarcInternalReportCreate,
                Permission::SysDmarcExternalReportUpdate,
                Permission::SysDmarcExternalReportCreate,
                Permission::SysTlsInternalReportUpdate,
                Permission::SysTlsInternalReportCreate,
                Permission::SysTlsExternalReportUpdate,
                Permission::SysTlsExternalReportCreate,
                Permission::SysArfExternalReportCreate,
                Permission::SysArfExternalReportUpdate,
                Permission::SysQueuedMessageCreate,
                Permission::SysLogCreate,
                Permission::SysLogDestroy,
                Permission::SysLogUpdate,
                Permission::SysClusterNodeCreate,
                Permission::SysClusterNodeUpdate,
                Permission::SysClusterNodeDestroy,
                Permission::SysBootstrapGet,
                Permission::SysBootstrapUpdate,
            ] {
                permissions.clear(p.to_id() as usize);
            }

            if !self.core.groupware.allow_directory_query {
                for p in [
                    Permission::JmapPrincipalQuery,
                    Permission::JmapPrincipalQueryChanges,
                    Permission::JmapPrincipalGet,
                    Permission::JmapPrincipalGetAvailability,
                    Permission::JmapPrincipalChanges,
                ] {
                    permissions.clear(p.to_id() as usize);
                }
            }

            if is_external_directory || is_recovery_admin {
                permissions.clear(Permission::SysAccountPasswordGet.to_id() as usize);
                permissions.clear(Permission::SysAccountPasswordUpdate.to_id() as usize);
            }

            if is_recovery_admin {
                for p in [
                    Permission::SysAccountSettingsGet,
                    Permission::SysAccountSettingsUpdate,
                    Permission::SysApiKeyCreate,
                    Permission::SysApiKeyUpdate,
                    Permission::SysApiKeyDestroy,
                    Permission::SysApiKeyQuery,
                    Permission::SysApiKeyGet,
                    Permission::SysAppPasswordCreate,
                    Permission::SysAppPasswordUpdate,
                    Permission::SysAppPasswordDestroy,
                    Permission::SysAppPasswordQuery,
                    Permission::SysAppPasswordGet,
                ] {
                    permissions.clear(p.to_id() as usize);
                }
            }

            permissions.build_permissions_list()
        } else if self.registry().is_bootstrap_mode() {
            vec![Permission::SysBootstrapGet, Permission::SysBootstrapUpdate]
        } else {
            Vec::new()
        };

        Ok(JsonResponse::new(Account {
            permissions,
            edition,
            locale: account_info.locale(),
        })
        .into_http_response())
    }
}
