/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderEntry, FolderNode, FolderTree, SpecialFolder,
    rights::{CONTAINER_VISIBLE, FolderRights, MAILBOX_VISIBLE},
};
use crate::store::{FolderKind, FolderRef};
use common::{GroupwareResources, MessageStoreCache, auth::AccessToken, sharing::EffectiveAcl};
use email::cache::mailbox::MailboxCacheAccess;
use groupware::calendar::privacy::EventPrivacy;
use std::sync::Arc;
use types::{
    acl::{Acl, AclGrant},
    collection::Collection,
};

const DELEGATE_COLLECTIONS: [Collection; 6] = [
    Collection::Mailbox,
    Collection::Email,
    Collection::Calendar,
    Collection::CalendarEvent,
    Collection::AddressBook,
    Collection::ContactCard,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonAccess {
    Owner,
    Member,
    Delegate,
}

impl LogonAccess {
    pub fn of(access_token: &AccessToken, mailbox_id: u32) -> Option<Self> {
        if access_token.is_account_id(mailbox_id) {
            Some(LogonAccess::Owner)
        } else if access_token.member_ids().any(|id| id == mailbox_id) {
            Some(LogonAccess::Member)
        } else if access_token.is_shared(mailbox_id)
            && DELEGATE_COLLECTIONS
                .into_iter()
                .any(|collection| access_token.has_access(mailbox_id, collection))
        {
            Some(LogonAccess::Delegate)
        } else {
            None
        }
    }

    pub fn reads_all(access: Option<Self>) -> bool {
        matches!(access, Some(LogonAccess::Owner | LogonAccess::Member))
    }
}

impl FolderRights {
    pub(crate) const ACCESS_MODIFY: i32 = 0x01;
    const ACCESS_READ: i32 = 0x02;
    const ACCESS_DELETE: i32 = 0x04;
    const ACCESS_CREATE_HIERARCHY: i32 = 0x08;
    const ACCESS_CREATE_CONTENTS: i32 = 0x10;
    const ACCESS_CREATE_ASSOCIATED: i32 = 0x20;

    pub fn access(self) -> i32 {
        [
            (
                Self::FOLDER_OWNER,
                Self::ACCESS_MODIFY | Self::ACCESS_DELETE,
            ),
            (Self::FOLDER_VISIBLE, Self::ACCESS_READ),
            (Self::CREATE_SUBFOLDER, Self::ACCESS_CREATE_HIERARCHY),
            (Self::CREATE, Self::ACCESS_CREATE_CONTENTS),
            (Self::FOLDER_OWNER, Self::ACCESS_CREATE_ASSOCIATED),
        ]
        .into_iter()
        .filter(|(right, _)| self.contains(*right))
        .fold(0, |access, (_, bit)| access | bit)
    }

    pub fn message_access(self, node: FolderNode, associated: bool) -> i32 {
        let (modify, delete) = if associated {
            let owner = self.contains(Self::FOLDER_OWNER);
            (owner, owner)
        } else {
            let own_events = matches!(
                node,
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Calendar,
                    ..
                })
            ) && self.contains(Self::EDIT_OWNED);
            (
                self.contains(Self::EDIT_ANY) || own_events,
                self.contains(Self::DELETE_ANY) || own_events,
            )
        };
        [
            (modify, Self::ACCESS_MODIFY),
            (self.reads_items(), Self::ACCESS_READ),
            (delete, Self::ACCESS_DELETE),
        ]
        .into_iter()
        .filter(|(granted, _)| *granted)
        .fold(0, |access, (_, bit)| access | bit)
    }
}

pub struct DelegateRights {
    tree: Arc<FolderTree>,
    by_position: Box<[FolderRights]>,
}

impl DelegateRights {
    pub fn build(
        tree: Arc<FolderTree>,
        access_token: &AccessToken,
        mailboxes: Option<&MessageStoreCache>,
        calendars: Option<&GroupwareResources>,
        address_books: Option<&GroupwareResources>,
    ) -> Self {
        let container = |resources: Option<&GroupwareResources>, id: u32| {
            resources
                .and_then(|resources| resources.container_resource_by_id(id))
                .map_or(FolderRights::NONE, |resource| {
                    acl_rights(resource.acls(), access_token, CONTAINER_VISIBLE)
                })
        };
        Self::from_entries(tree, |entry| match entry.node {
            FolderNode::Special(special) => structural(special),
            FolderNode::Stored(FolderRef { kind, id }) => match kind {
                FolderKind::Mailbox => mailboxes
                    .and_then(|mailboxes| mailboxes.mailbox_by_id(&id))
                    .map_or(FolderRights::NONE, |mailbox| {
                        acl_rights(&mailbox.acls, access_token, MAILBOX_VISIBLE)
                    }),
                FolderKind::Calendar => container(calendars, id),
                FolderKind::AddressBook => container(address_books, id),
                FolderKind::Virtual | FolderKind::FileNode => FolderRights::NONE,
            },
        })
    }

    pub fn from_entries(
        tree: Arc<FolderTree>,
        mut own: impl FnMut(&FolderEntry) -> FolderRights,
    ) -> Self {
        let mut by_position: Vec<FolderRights> = Vec::with_capacity(tree.len());
        for entry in tree.iter() {
            let parent_visible = entry.parent.is_none_or(|parent| {
                tree.position(parent)
                    .and_then(|position| by_position.get(position))
                    .is_some_and(|rights| rights.is_visible())
            });
            let rights = if parent_visible {
                own(entry)
            } else {
                FolderRights::NONE
            };
            by_position.push(if rights.is_visible() {
                rights
            } else {
                FolderRights::NONE
            });
        }
        DelegateRights {
            tree,
            by_position: by_position.into_boxed_slice(),
        }
    }

    pub fn creates_mail(&self) -> bool {
        self.tree
            .iter()
            .zip(self.by_position.iter())
            .any(|(entry, rights)| {
                matches!(
                    entry.node,
                    FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        ..
                    })
                ) && rights.contains(FolderRights::CREATE)
            })
    }

    pub fn hides_descendant(&self, node: FolderNode) -> bool {
        self.tree
            .descendants(node)
            .any(|entry| !self.of(entry.node).is_visible())
    }

    pub fn visible_tree(&self) -> FolderTree {
        self.tree
            .subset(self.by_position.iter().map(|rights| rights.is_visible()))
    }

    pub fn of(&self, node: FolderNode) -> FolderRights {
        self.tree
            .position(node)
            .and_then(|position| self.by_position.get(position))
            .copied()
            .unwrap_or_default()
    }
}

pub(crate) fn structural(special: SpecialFolder) -> FolderRights {
    match special {
        SpecialFolder::Root
        | SpecialFolder::IpmSubtree
        | SpecialFolder::Finder
        | SpecialFolder::CommonViews => FolderRights::FOLDER_VISIBLE,
        _ => FolderRights::NONE,
    }
}

fn acl_rights(acls: &[AclGrant], access_token: &AccessToken, visible: &[Acl]) -> FolderRights {
    FolderRights::from_acl(acls.effective_acl(access_token), visible)
}

#[derive(Clone)]
pub enum ViewRights {
    Owner,
    Member,
    Delegate(Arc<DelegateRights>),
    Revoked,
}

impl ViewRights {
    pub fn of(&self, node: FolderNode) -> FolderRights {
        match self {
            ViewRights::Owner => FolderRights::OWNER,
            ViewRights::Member => FolderRights::OWNER,
            ViewRights::Delegate(rights) => rights.of(node),
            ViewRights::Revoked => FolderRights::NONE,
        }
    }

    pub fn hides_descendant(&self, node: FolderNode) -> bool {
        matches!(self, ViewRights::Delegate(rights) if rights.hides_descendant(node))
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, ViewRights::Owner)
    }

    pub fn sends_as_owner(&self) -> bool {
        matches!(self, ViewRights::Owner | ViewRights::Member)
    }

    pub fn is_delegate(&self) -> bool {
        matches!(self, ViewRights::Delegate(_))
    }

    pub fn hides(&self, resources: &GroupwareResources, document_id: u32) -> bool {
        self.privacy(resources, document_id) == EventPrivacy::Secret
    }

    pub fn privacy(&self, resources: &GroupwareResources, document_id: u32) -> EventPrivacy {
        match self {
            ViewRights::Owner | ViewRights::Member => EventPrivacy::Public,
            ViewRights::Delegate(_) | ViewRights::Revoked => resources
                .item_by_id(document_id)
                .and_then(|item| item.event_flags())
                .map_or(EventPrivacy::Public, EventPrivacy::from_flags),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemWrite {
    Create,
    Edit,
    Delete,
    ReadState,
    Associated,
}

impl ItemWrite {
    pub fn of_staged(associated: bool, existing: bool) -> Self {
        match (associated, existing) {
            (true, _) => ItemWrite::Associated,
            (false, true) => ItemWrite::Edit,
            (false, false) => ItemWrite::Create,
        }
    }

    pub fn needs(self, node: FolderNode) -> FolderRights {
        match (self, node) {
            (ItemWrite::Associated, _) => FolderRights::FOLDER_OWNER,
            (ItemWrite::ReadState, _) => FolderRights::READ_ANY.with(FolderRights::EDIT_ANY),
            (
                _,
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Calendar | FolderKind::AddressBook,
                    ..
                }),
            ) => FolderRights::FOLDER_VISIBLE,
            (ItemWrite::Create, _) => FolderRights::CREATE,
            (ItemWrite::Edit, _) => FolderRights::EDIT_ANY,
            (ItemWrite::Delete, _) => FolderRights::DELETE_ANY,
        }
    }
}
