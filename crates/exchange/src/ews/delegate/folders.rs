/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::rule::{DelegateEdit, DelegateWriter, Planned, Principal};
use crate::{
    ews::context::EwsContext,
    folders::{
        AclWriteError, FolderNode, FolderWriteError, FolderWrites, SpecialFolder,
        rights::{AclTarget, DelegateRole, GrantedRole, MemberChange, RowMode},
    },
    store::{FolderKind, FolderRef},
};
use common::{GroupwareResources, MessageStoreCache, Server};
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use exchange_proto::{
    ews::{schema::DelegateFolderPermissionLevel, types::delegate::DelegatePermissions},
    rules::DelegateRule,
};
use groupware::cache::GroupwareCache;
use std::sync::Arc;
use types::{
    acl::{Acl, AclGrant},
    collection::SyncCollection,
};
use utils::map::bitmap::Bitmap;

const MAX_ACL_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Calendar,
    Tasks,
    Inbox,
    Contacts,
    Notes,
    Journal,
}

pub(super) struct MappedFolder {
    node: FolderNode,
    acl: AclTarget,
    grants: Vec<AclGrant>,
}

pub(super) struct DelegateFolders {
    folders: [Option<MappedFolder>; Target::COUNT],
}

impl Target {
    pub(super) const COUNT: usize = 6;
    pub(super) const ALL: [Target; Target::COUNT] = [
        Target::Calendar,
        Target::Tasks,
        Target::Inbox,
        Target::Contacts,
        Target::Notes,
        Target::Journal,
    ];

    const fn special(self) -> SpecialFolder {
        match self {
            Target::Calendar => SpecialFolder::Calendar,
            Target::Tasks => SpecialFolder::Tasks,
            Target::Inbox => SpecialFolder::Inbox,
            Target::Contacts => SpecialFolder::Contacts,
            Target::Notes => SpecialFolder::Notes,
            Target::Journal => SpecialFolder::Journal,
        }
    }

    pub(super) fn level(
        self,
        permissions: &DelegatePermissions,
    ) -> Option<DelegateFolderPermissionLevel> {
        match self {
            Target::Calendar => permissions.calendar,
            Target::Tasks => permissions.tasks,
            Target::Inbox => permissions.inbox,
            Target::Contacts => permissions.contacts,
            Target::Notes => permissions.notes,
            Target::Journal => permissions.journal,
        }
    }

    fn set_level(
        self,
        permissions: &mut DelegatePermissions,
        level: DelegateFolderPermissionLevel,
    ) {
        let slot = match self {
            Target::Calendar => &mut permissions.calendar,
            Target::Tasks => &mut permissions.tasks,
            Target::Inbox => &mut permissions.inbox,
            Target::Contacts => &mut permissions.contacts,
            Target::Notes => &mut permissions.notes,
            Target::Journal => &mut permissions.journal,
        };
        *slot = Some(level);
    }
}

pub(super) const fn role_of(level: DelegateFolderPermissionLevel) -> Option<DelegateRole> {
    match level {
        DelegateFolderPermissionLevel::None => Some(DelegateRole::None),
        DelegateFolderPermissionLevel::Reviewer => Some(DelegateRole::Reviewer),
        DelegateFolderPermissionLevel::Author => Some(DelegateRole::Author),
        DelegateFolderPermissionLevel::Editor => Some(DelegateRole::Editor),
        DelegateFolderPermissionLevel::Custom => None,
    }
}

const fn level_of(role: GrantedRole) -> DelegateFolderPermissionLevel {
    match role {
        GrantedRole::Role(DelegateRole::None) => DelegateFolderPermissionLevel::None,
        GrantedRole::Role(DelegateRole::Reviewer) => DelegateFolderPermissionLevel::Reviewer,
        GrantedRole::Role(DelegateRole::Author) => DelegateFolderPermissionLevel::Author,
        GrantedRole::Role(DelegateRole::Editor) => DelegateFolderPermissionLevel::Editor,
        GrantedRole::Custom => DelegateFolderPermissionLevel::Custom,
    }
}

impl MappedFolder {
    fn grants_of(&self, principal_id: u32) -> Bitmap<Acl> {
        self.grants
            .iter()
            .find(|grant| grant.account_id == principal_id)
            .map_or_else(Bitmap::new, |grant| grant.grants)
    }

    fn role(&self, principal_id: u32) -> GrantedRole {
        DelegateRole::from_grants(self.grants_of(principal_id), self.acl)
    }
}

impl DelegateFolders {
    pub(super) async fn load(server: &Server, ctx: &EwsContext) -> trc::Result<Self> {
        let account_id = ctx.account.account_id;
        let tree = ctx.folder_tree(server).await?;
        let mut mailboxes: Option<Arc<MessageStoreCache>> = None;
        let mut calendars: Option<Arc<GroupwareResources>> = None;
        let mut address_books: Option<Arc<GroupwareResources>> = None;
        let mut folders: [Option<MappedFolder>; Target::COUNT] = Default::default();
        for (target, slot) in Target::ALL.into_iter().zip(&mut folders) {
            let Some(node) = tree.special(target.special()).map(|entry| entry.node) else {
                continue;
            };
            let FolderNode::Stored(FolderRef { kind, id }) = node else {
                continue;
            };
            let Some(acl) = AclTarget::of(node) else {
                continue;
            };
            let grants = match kind {
                FolderKind::Mailbox => {
                    if mailboxes.is_none() {
                        mailboxes = Some(server.get_cached_messages(account_id).await?);
                    }
                    mailboxes
                        .as_deref()
                        .and_then(|cache| cache.mailbox_by_id(&id))
                        .map(|mailbox| mailbox.acls.to_vec())
                }
                FolderKind::Calendar | FolderKind::AddressBook => {
                    let (cache, collection) = if kind == FolderKind::Calendar {
                        (&mut calendars, SyncCollection::Calendar)
                    } else {
                        (&mut address_books, SyncCollection::AddressBook)
                    };
                    if cache.is_none() {
                        *cache = Some(
                            server
                                .fetch_groupware_resources(account_id, account_id, collection)
                                .await?,
                        );
                    }
                    cache
                        .as_deref()
                        .and_then(|cache| cache.container_resource_by_id(id))
                        .map(|resource| resource.acls().to_vec())
                }
                FolderKind::Virtual | FolderKind::FileNode => None,
            };
            if let Some(grants) = grants {
                *slot = Some(MappedFolder { node, acl, grants });
            }
        }
        Ok(DelegateFolders { folders })
    }

    pub(super) async fn members(
        &self,
        server: &Server,
        account_id: u32,
        rule: Option<&DelegateRule>,
    ) -> trc::Result<Vec<Principal>> {
        let mut candidates: Vec<u32> = Vec::new();
        let granted = self.folders.iter().flatten().flat_map(|folder| {
            folder
                .grants
                .iter()
                .filter(|grant| {
                    DelegateRole::from_grants(grant.grants, folder.acl)
                        != GrantedRole::Role(DelegateRole::None)
                })
                .map(|grant| grant.account_id)
        });
        for principal_id in granted {
            if principal_id != account_id && !candidates.contains(&principal_id) {
                candidates.push(principal_id);
            }
        }
        let recipients = rule.map_or(&[][..], |rule| rule.recipients.as_slice());
        let mut members = Vec::with_capacity(candidates.len() + recipients.len());
        for principal_id in candidates {
            if let Some(principal) = Principal::load_user(server, principal_id).await? {
                members.push(principal);
            }
        }
        for recipient in recipients {
            if recipient.principal_id == account_id
                || members
                    .iter()
                    .any(|member: &Principal| member.id == recipient.principal_id)
            {
                continue;
            }
            members.push(
                match Principal::load_user(server, recipient.principal_id).await? {
                    Some(principal) => principal,
                    None => Principal::orphan(recipient),
                },
            );
        }
        Ok(members)
    }

    pub(super) fn role(&self, index: usize, principal_id: u32) -> Option<GrantedRole> {
        self.folders
            .get(index)?
            .as_ref()
            .map(|folder| folder.role(principal_id))
    }

    pub(super) fn is_mapped(&self, index: usize) -> bool {
        self.folders.get(index).is_some_and(Option::is_some)
    }

    pub(super) fn permissions(&self, principal_id: u32) -> DelegatePermissions {
        let mut permissions = DelegatePermissions::default();
        for (target, folder) in Target::ALL.into_iter().zip(&self.folders) {
            if let Some(role) = folder
                .as_ref()
                .map(|folder| folder.role(principal_id))
                .filter(|role| *role != GrantedRole::Role(DelegateRole::None))
            {
                target.set_level(&mut permissions, level_of(role));
            }
        }
        permissions
    }

    pub(super) async fn write(
        &self,
        writer: DelegateWriter<'_>,
        edit: DelegateEdit,
        planned: &mut [Planned],
    ) -> trc::Result<()> {
        let mut changes: Vec<MemberChange> = Vec::with_capacity(planned.len());
        let mut touched: Vec<usize> = Vec::with_capacity(planned.len());
        for (index, folder) in self.folders.iter().enumerate() {
            let Some(folder) = folder else {
                continue;
            };
            changes.clear();
            touched.clear();
            for (position, plan) in planned.iter().enumerate() {
                let principal_id = plan.principal.id;
                let change = match edit {
                    DelegateEdit::Remove => (!folder.grants_of(principal_id).is_empty()).then_some(
                        MemberChange::Remove {
                            account_id: principal_id,
                        },
                    ),
                    DelegateEdit::Add | DelegateEdit::Update => plan
                        .levels
                        .get(index)
                        .copied()
                        .flatten()
                        .filter(|role| folder.role(principal_id) != GrantedRole::Role(*role))
                        .map(|role| MemberChange::Add {
                            account_id: principal_id,
                            rights: role.rights(),
                        }),
                };
                if let Some(change) = change {
                    changes.push(change);
                    touched.push(position);
                }
            }
            if changes.is_empty() {
                continue;
            }
            let acl = folder.acl;
            let rewrite = |current: &[AclGrant]| acl.edit(current, &changes, RowMode::Merge, false);
            let mut attempts = 0;
            let result = loop {
                attempts += 1;
                match writer
                    .server
                    .folder_set_acl(
                        writer.caller.access_token,
                        writer.account_id,
                        folder.node,
                        &rewrite,
                    )
                    .await?
                {
                    Err(AclWriteError::Folder(FolderWriteError::Conflict))
                        if attempts < MAX_ACL_ATTEMPTS => {}
                    result => break result,
                }
            };
            if result.is_err() {
                for position in &touched {
                    if let Some(plan) = planned.get_mut(*position) {
                        plan.failed = true;
                    }
                }
            }
        }
        Ok(())
    }
}
