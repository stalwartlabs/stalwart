/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::{AccessToken, Permissions, PermissionsGroup},
};
use ahash::AHashSet;
use registry::{
    schema::{
        enums::Permission,
        structs::{self, Account, PermissionsList},
    },
    types::EnumImpl,
};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

impl Server {
    pub async fn add_role_permissions(
        &self,
        mut base_permissions: PermissionsGroup,
        roles: impl IntoIterator<Item = u32>,
    ) -> trc::Result<PermissionsGroup> {
        let mut role_ids = roles.into_iter().collect::<Vec<u32>>();
        let mut fetched_role_ids = AHashSet::new();

        while let Some(role_id) = role_ids.pop() {
            if fetched_role_ids.insert(role_id) {
                let role = self.role(role_id).await.caused_by(trc::location!())?;

                base_permissions.union(&role.permissions);
                role_ids.extend(role.id_roles.iter().copied());
            }
        }

        Ok(base_permissions)
    }

    pub async fn effective_permissions(
        &self,
        permissions: &structs::Permissions,
        role_ids: &[Id],
        tenant_id: Option<u32>,
    ) -> trc::Result<PermissionsGroup> {
        // Calculate effective permissions
        let (mut permissions, roles) = match permissions {
            structs::Permissions::Inherit => (PermissionsGroup::default(), role_ids),
            structs::Permissions::Merge(permissions) => {
                (PermissionsGroup::from(permissions), role_ids)
            }
            structs::Permissions::Replace(permissions) => {
                (PermissionsGroup::from(permissions), &[][..])
            }
        };
        if !roles.is_empty() {
            permissions = self
                .add_role_permissions(permissions, roles.iter().map(|v| v.id() as u32))
                .await
                .caused_by(trc::location!())?
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        #[cfg(feature = "enterprise")]
        {
            if let Some(tenant_id) = tenant_id {
                if self.is_enterprise_edition() {
                    // Limit tenant permissions
                    let tenant = self.tenant(tenant_id).await.caused_by(trc::location!())?;
                    let (mut tenant_permissions, tenant_roles) =
                        if let Some(permissions) = &tenant.permissions {
                            if permissions.merge {
                                ((**permissions).clone(), tenant.id_roles.as_slice())
                            } else {
                                ((**permissions).clone(), &[][..])
                            }
                        } else {
                            (PermissionsGroup::default(), tenant.id_roles.as_slice())
                        };
                    if !tenant_roles.is_empty() {
                        tenant_permissions = self
                            .add_role_permissions(tenant_permissions, tenant_roles.iter().copied())
                            .await
                            .caused_by(trc::location!())?
                    }

                    permissions.restrict(&tenant_permissions);
                } else {
                    // Enterprise edition downgrade, remove any tenant administrator permissions
                    permissions.restrict(&PermissionsGroup::user());
                }
            }
        }

        // SPDX-SnippetEnd

        Ok(permissions)
    }

    pub async fn can_set_permissions(
        &self,
        access_token: &AccessToken,
        account: &Account,
    ) -> trc::Result<Result<(), Vec<Permission>>> {
        let (permissions, role_ids, tenant_id) = match account {
            Account::User(account) => (
                &account.permissions,
                account
                    .roles
                    .role_ids()
                    .unwrap_or(self.core.network.security.default_role_ids_user.as_slice()),
                account.member_tenant_id.map(|t| t.document_id()),
            ),
            Account::Group(account) => (
                &account.permissions,
                account
                    .roles
                    .role_ids()
                    .unwrap_or(self.core.network.security.default_role_ids_group.as_slice()),
                account.member_tenant_id.map(|t| t.document_id()),
            ),
        };

        self.effective_permissions(permissions, role_ids, tenant_id)
            .await
            .map(|permissions| access_token.can_grant_permissions(permissions.finalize()))
    }
}

impl AccessToken {
    pub fn can_grant_permissions(
        &self,
        mut requested_permissions: Permissions,
    ) -> Result<(), Vec<Permission>> {
        requested_permissions.difference(self.permissions_bits());
        if requested_permissions.is_empty() {
            Ok(())
        } else {
            Err(build_permissions_list(&requested_permissions))
        }
    }
}

pub(crate) fn build_permissions_list(permissions_in: &Permissions) -> Vec<Permission> {
    const USIZE_BITS: usize = std::mem::size_of::<usize>() * 8;
    const USIZE_MASK: u32 = USIZE_BITS as u32 - 1;
    let mut permissions = Vec::new();

    for (block_num, bytes) in permissions_in.inner().iter().enumerate() {
        let mut bytes = *bytes;

        while bytes != 0 {
            let item = USIZE_MASK - bytes.leading_zeros();
            bytes ^= 1 << item;
            if let Some(permission) =
                Permission::from_id(((block_num * USIZE_BITS) + item as usize) as u16)
            {
                permissions.push(permission);
            }
        }
    }
    permissions
}

impl PermissionsGroup {
    pub fn with_merge(mut self, merge: bool) -> Self {
        self.merge = merge;
        self
    }

    pub fn union(&mut self, other: &PermissionsGroup) {
        self.enabled.union(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn restrict(&mut self, other: &PermissionsGroup) {
        self.enabled.intersection(&other.enabled);
        self.disabled.union(&other.disabled);
    }

    pub fn finalize(mut self) -> Permissions {
        self.enabled.difference(&self.disabled);
        self.enabled
    }

    pub fn finalize_as_ref(&self) -> Permissions {
        let mut enabled = self.enabled.clone();
        enabled.difference(&self.disabled);
        enabled
    }

    pub fn user() -> Self {
        let mut permissions = PermissionsGroup::default();
        for permission in [
            Permission::Authenticate,
            Permission::AuthenticateOauth,
            Permission::EmailSend,
            Permission::EmailReceive,
            Permission::ManageEncryption,
            Permission::ManagePasswords,
            Permission::JmapEmailGet,
            Permission::JmapMailboxGet,
            Permission::JmapThreadGet,
            Permission::JmapIdentityGet,
            Permission::JmapEmailSubmissionGet,
            Permission::JmapPushSubscriptionGet,
            Permission::JmapSieveScriptGet,
            Permission::JmapVacationResponseGet,
            Permission::JmapQuotaGet,
            Permission::JmapBlobGet,
            Permission::JmapEmailSet,
            Permission::JmapMailboxSet,
            Permission::JmapIdentitySet,
            Permission::JmapEmailSubmissionSet,
            Permission::JmapPushSubscriptionSet,
            Permission::JmapSieveScriptSet,
            Permission::JmapVacationResponseSet,
            Permission::JmapEmailChanges,
            Permission::JmapMailboxChanges,
            Permission::JmapThreadChanges,
            Permission::JmapIdentityChanges,
            Permission::JmapEmailSubmissionChanges,
            Permission::JmapQuotaChanges,
            Permission::JmapEmailCopy,
            Permission::JmapBlobCopy,
            Permission::JmapEmailImport,
            Permission::JmapEmailParse,
            Permission::JmapEmailQueryChanges,
            Permission::JmapMailboxQueryChanges,
            Permission::JmapEmailSubmissionQueryChanges,
            Permission::JmapSieveScriptQueryChanges,
            Permission::JmapQuotaQueryChanges,
            Permission::JmapEmailQuery,
            Permission::JmapMailboxQuery,
            Permission::JmapEmailSubmissionQuery,
            Permission::JmapSieveScriptQuery,
            Permission::JmapQuotaQuery,
            Permission::JmapSearchSnippet,
            Permission::JmapSieveScriptValidate,
            Permission::JmapBlobLookup,
            Permission::JmapBlobUpload,
            Permission::JmapEcho,
            Permission::ImapAuthenticate,
            Permission::ImapAclGet,
            Permission::ImapAclSet,
            Permission::ImapMyRights,
            Permission::ImapListRights,
            Permission::ImapAppend,
            Permission::ImapCapability,
            Permission::ImapId,
            Permission::ImapCopy,
            Permission::ImapMove,
            Permission::ImapCreate,
            Permission::ImapDelete,
            Permission::ImapEnable,
            Permission::ImapExpunge,
            Permission::ImapFetch,
            Permission::ImapIdle,
            Permission::ImapList,
            Permission::ImapLsub,
            Permission::ImapNamespace,
            Permission::ImapRename,
            Permission::ImapSearch,
            Permission::ImapSort,
            Permission::ImapSelect,
            Permission::ImapExamine,
            Permission::ImapStatus,
            Permission::ImapStore,
            Permission::ImapSubscribe,
            Permission::ImapThread,
            Permission::Pop3Authenticate,
            Permission::Pop3List,
            Permission::Pop3Uidl,
            Permission::Pop3Stat,
            Permission::Pop3Retr,
            Permission::Pop3Dele,
            Permission::SieveAuthenticate,
            Permission::SieveListScripts,
            Permission::SieveSetActive,
            Permission::SieveGetScript,
            Permission::SievePutScript,
            Permission::SieveDeleteScript,
            Permission::SieveRenameScript,
            Permission::SieveCheckScript,
            Permission::SieveHaveSpace,
            Permission::DavSyncCollection,
            Permission::DavExpandProperty,
            Permission::DavPrincipalAcl,
            Permission::DavPrincipalList,
            Permission::DavPrincipalSearch,
            Permission::DavPrincipalMatch,
            Permission::DavPrincipalSearchPropSet,
            Permission::DavFilePropFind,
            Permission::DavFilePropPatch,
            Permission::DavFileGet,
            Permission::DavFileMkCol,
            Permission::DavFileDelete,
            Permission::DavFilePut,
            Permission::DavFileCopy,
            Permission::DavFileMove,
            Permission::DavFileLock,
            Permission::DavFileAcl,
            Permission::DavCardPropFind,
            Permission::DavCardPropPatch,
            Permission::DavCardGet,
            Permission::DavCardMkCol,
            Permission::DavCardDelete,
            Permission::DavCardPut,
            Permission::DavCardCopy,
            Permission::DavCardMove,
            Permission::DavCardLock,
            Permission::DavCardAcl,
            Permission::DavCardQuery,
            Permission::DavCardMultiGet,
            Permission::DavCalPropFind,
            Permission::DavCalPropPatch,
            Permission::DavCalGet,
            Permission::DavCalMkCol,
            Permission::DavCalDelete,
            Permission::DavCalPut,
            Permission::DavCalCopy,
            Permission::DavCalMove,
            Permission::DavCalLock,
            Permission::DavCalAcl,
            Permission::DavCalQuery,
            Permission::DavCalMultiGet,
            Permission::DavCalFreeBusyQuery,
            Permission::CalendarAlarms,
            Permission::CalendarSchedulingSend,
            Permission::CalendarSchedulingReceive,
            Permission::JmapAddressBookGet,
            Permission::JmapAddressBookSet,
            Permission::JmapAddressBookChanges,
            Permission::JmapContactCardGet,
            Permission::JmapContactCardChanges,
            Permission::JmapContactCardQuery,
            Permission::JmapContactCardQueryChanges,
            Permission::JmapContactCardSet,
            Permission::JmapContactCardCopy,
            Permission::JmapContactCardParse,
            Permission::JmapFileNodeGet,
            Permission::JmapFileNodeSet,
            Permission::JmapFileNodeChanges,
            Permission::JmapFileNodeQuery,
            Permission::JmapFileNodeQueryChanges,
            Permission::JmapPrincipalGetAvailability,
            Permission::JmapPrincipalChanges,
            Permission::JmapPrincipalQuery,
            Permission::JmapPrincipalGet,
            Permission::JmapPrincipalQueryChanges,
            Permission::JmapShareNotificationGet,
            Permission::JmapShareNotificationSet,
            Permission::JmapShareNotificationChanges,
            Permission::JmapShareNotificationQuery,
            Permission::JmapShareNotificationQueryChanges,
            Permission::JmapCalendarGet,
            Permission::JmapCalendarSet,
            Permission::JmapCalendarChanges,
            Permission::JmapCalendarEventGet,
            Permission::JmapCalendarEventSet,
            Permission::JmapCalendarEventChanges,
            Permission::JmapCalendarEventQuery,
            Permission::JmapCalendarEventQueryChanges,
            Permission::JmapCalendarEventCopy,
            Permission::JmapCalendarEventParse,
            Permission::JmapCalendarEventNotificationGet,
            Permission::JmapCalendarEventNotificationSet,
            Permission::JmapCalendarEventNotificationChanges,
            Permission::JmapCalendarEventNotificationQuery,
            Permission::JmapCalendarEventNotificationQueryChanges,
            Permission::JmapParticipantIdentityGet,
            Permission::JmapParticipantIdentitySet,
            Permission::JmapParticipantIdentityChanges,
        ] {
            permissions.enabled.set(permission as usize);
        }

        permissions
    }
}

impl From<PermissionsList> for PermissionsGroup {
    fn from(value: PermissionsList) -> Self {
        PermissionsGroup::from(&value.permissions)
    }
}

impl From<&PermissionsList> for PermissionsGroup {
    fn from(value: &PermissionsList) -> Self {
        PermissionsGroup::from(&value.permissions)
    }
}

impl From<&VecMap<Permission, bool>> for PermissionsGroup {
    fn from(value: &VecMap<Permission, bool>) -> Self {
        let mut permissions = PermissionsGroup::default();
        for (permission, is_set) in value {
            if *is_set {
                permissions.enabled.set(*permission as usize);
            } else {
                permissions.disabled.set(*permission as usize);
            }
        }
        permissions
    }
}
