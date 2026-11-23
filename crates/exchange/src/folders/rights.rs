/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::FolderNode;
use crate::store::{FolderKind, FolderRef};
use types::acl::{Acl, AclGrant};
use utils::map::bitmap::Bitmap;

pub const MAILBOX_VISIBLE: &[Acl] = &[Acl::Read];
pub const CONTAINER_VISIBLE: &[Acl] = &[Acl::Read, Acl::ReadItems];

const FOLDER_CONTACT: i32 = 0x0200;
const FREE_BUSY: i32 =
    FolderRights::FREE_BUSY_SIMPLE.bits() | FolderRights::FREE_BUSY_DETAILED.bits();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FolderRights(i32);

impl FolderRights {
    pub const NONE: FolderRights = FolderRights(0);
    pub const READ_ANY: FolderRights = FolderRights(0x0001);
    pub const CREATE: FolderRights = FolderRights(0x0002);
    pub const EDIT_OWNED: FolderRights = FolderRights(0x0008);
    pub const DELETE_OWNED: FolderRights = FolderRights(0x0010);
    pub const EDIT_ANY: FolderRights = FolderRights(0x0020);
    pub const DELETE_ANY: FolderRights = FolderRights(0x0040);
    pub const CREATE_SUBFOLDER: FolderRights = FolderRights(0x0080);
    pub const FOLDER_OWNER: FolderRights = FolderRights(0x0100);
    pub const FOLDER_VISIBLE: FolderRights = FolderRights(0x0400);
    pub const FREE_BUSY_SIMPLE: FolderRights = FolderRights(0x0800);
    pub const FREE_BUSY_DETAILED: FolderRights = FolderRights(0x1000);
    pub const OWNER: FolderRights = FolderRights(0x07FB);
    pub const READER: FolderRights = FolderRights(0x0401);

    pub fn from_acl(grants: Bitmap<Acl>, visible: &[Acl]) -> Self {
        let rights = [
            (Acl::ReadItems, Self::READ_ANY),
            (Acl::AddItems, Self::CREATE),
            (Acl::ModifyItemsOwn, Self::EDIT_OWNED),
            (Acl::ModifyItems, Self::EDIT_OWNED.with(Self::EDIT_ANY)),
            (Acl::RemoveItems, Self::DELETE_OWNED.with(Self::DELETE_ANY)),
            (Acl::CreateChild, Self::CREATE_SUBFOLDER),
            (Acl::Share, Self::FOLDER_OWNER),
        ]
        .into_iter()
        .filter(|(acl, _)| grants.contains(*acl))
        .fold(Self::NONE, |rights, (_, right)| rights.with(right));
        if grants.contains_any(visible.iter().copied()) {
            rights.with(Self::FOLDER_VISIBLE)
        } else {
            rights
        }
    }

    pub const fn with(self, other: FolderRights) -> Self {
        FolderRights(self.0 | other.0)
    }

    pub const fn contains(self, other: FolderRights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_visible(self) -> bool {
        self.contains(Self::FOLDER_VISIBLE)
    }

    pub const fn reads_items(self) -> bool {
        self.contains(Self::READ_ANY)
    }

    pub const fn bits(self) -> i32 {
        self.0
    }
}

pub(crate) fn member_rights(grants: Bitmap<Acl>, visible: &[Acl], free_busy: bool) -> i32 {
    let rights = FolderRights::from_acl(grants, visible);
    let rights = if !free_busy {
        rights
    } else if grants.contains(Acl::ReadItems) {
        rights
            .with(FolderRights::FREE_BUSY_SIMPLE)
            .with(FolderRights::FREE_BUSY_DETAILED)
    } else if grants.contains(Acl::SchedulingReadFreeBusy) {
        rights.with(FolderRights::FREE_BUSY_SIMPLE)
    } else {
        rights
    };
    if grants.contains(Acl::Share) {
        rights.bits() | FOLDER_CONTACT
    } else {
        rights.bits()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclTarget {
    Mailbox,
    Calendar,
    AddressBook,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberChange {
    Add { account_id: u32, rights: i32 },
    Modify { account_id: u32, rights: i32 },
    Remove { account_id: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowMode {
    Merge,
    Replace,
}

struct RightRule {
    flag: FolderRights,
    set: &'static [Acl],
    clear: &'static [Acl],
}

const fn rule(flag: FolderRights, set: &'static [Acl], clear: &'static [Acl]) -> RightRule {
    RightRule { flag, set, clear }
}

const MAILBOX_RULES: &[RightRule] = &[
    rule(FolderRights::FOLDER_VISIBLE, &[Acl::Read], &[Acl::Read]),
    rule(
        FolderRights::READ_ANY,
        &[Acl::Read, Acl::ReadItems],
        &[Acl::ReadItems],
    ),
];

const CONTAINER_RULES: &[RightRule] = &[
    rule(
        FolderRights::FOLDER_VISIBLE,
        &[Acl::Read],
        &[Acl::Read, Acl::ReadItems],
    ),
    rule(
        FolderRights::READ_ANY,
        &[Acl::Read, Acl::ReadItems],
        &[Acl::ReadItems],
    ),
];

const ITEM_RULES: &[RightRule] = &[
    rule(FolderRights::CREATE, &[Acl::AddItems], &[Acl::AddItems]),
    rule(
        FolderRights::EDIT_OWNED,
        &[Acl::ModifyItemsOwn],
        &[Acl::ModifyItemsOwn, Acl::ModifyItems],
    ),
    rule(
        FolderRights::EDIT_ANY,
        &[Acl::ModifyItems],
        &[Acl::ModifyItems],
    ),
    rule(FolderRights::DELETE_OWNED, &[], &[Acl::RemoveItems]),
    rule(
        FolderRights::DELETE_ANY,
        &[Acl::RemoveItems],
        &[Acl::RemoveItems],
    ),
    rule(
        FolderRights::CREATE_SUBFOLDER,
        &[Acl::CreateChild],
        &[Acl::CreateChild],
    ),
    rule(
        FolderRights::FOLDER_OWNER,
        &[Acl::Share, Acl::Modify, Acl::Delete],
        &[Acl::Share, Acl::Modify, Acl::Delete],
    ),
    rule(
        FolderRights::FREE_BUSY_SIMPLE,
        &[Acl::SchedulingReadFreeBusy],
        &[Acl::SchedulingReadFreeBusy],
    ),
    rule(
        FolderRights::FREE_BUSY_DETAILED,
        &[Acl::SchedulingReadFreeBusy],
        &[],
    ),
];

impl AclTarget {
    pub(crate) fn of(node: FolderNode) -> Option<Self> {
        match node {
            FolderNode::Stored(FolderRef { kind, .. }) => match kind {
                FolderKind::Mailbox => Some(AclTarget::Mailbox),
                FolderKind::Calendar => Some(AclTarget::Calendar),
                FolderKind::AddressBook => Some(AclTarget::AddressBook),
                FolderKind::Virtual | FolderKind::FileNode => None,
            },
            FolderNode::Special(_) => None,
        }
    }

    pub(crate) fn visible(self) -> &'static [Acl] {
        match self {
            AclTarget::Mailbox => MAILBOX_VISIBLE,
            AclTarget::Calendar | AclTarget::AddressBook => CONTAINER_VISIBLE,
        }
    }

    fn rules(self) -> impl Iterator<Item = &'static RightRule> {
        match self {
            AclTarget::Mailbox => MAILBOX_RULES,
            AclTarget::Calendar | AclTarget::AddressBook => CONTAINER_RULES,
        }
        .iter()
        .chain(ITEM_RULES)
    }

    pub(crate) fn apply(self, grants: Bitmap<Acl>, rights: i32, free_busy: bool) -> Bitmap<Acl> {
        let free_busy = free_busy && self == AclTarget::Calendar;
        let old = member_rights(grants, self.visible(), free_busy);
        let new = if free_busy {
            rights
        } else {
            rights & !FREE_BUSY
        };
        let cleared = old & !new;
        let mut grants = grants;
        for rule in self.rules() {
            if cleared & rule.flag.bits() != 0 {
                grants.remove_many(rule.clear.iter().copied());
            }
        }
        let missing = new & !member_rights(grants, self.visible(), free_busy);
        for rule in self.rules() {
            if missing & rule.flag.bits() != 0 {
                grants.insert_many(rule.set.iter().copied());
            }
        }
        grants
    }

    pub(crate) fn edit(
        self,
        current: &[AclGrant],
        changes: &[MemberChange],
        mode: RowMode,
        free_busy: bool,
    ) -> Vec<AclGrant> {
        let mut grants = match mode {
            RowMode::Merge => current.to_vec(),
            RowMode::Replace => Vec::with_capacity(changes.len()),
        };
        for change in changes {
            match *change {
                MemberChange::Add { account_id, rights } => {
                    match grants
                        .iter_mut()
                        .find(|grant| grant.account_id == account_id)
                    {
                        Some(grant) => grant.grants = self.apply(grant.grants, rights, free_busy),
                        None => grants.push(AclGrant {
                            account_id,
                            grants: self.apply(Bitmap::new(), rights, free_busy),
                        }),
                    }
                }
                MemberChange::Modify { account_id, rights } => {
                    if let Some(grant) = grants
                        .iter_mut()
                        .find(|grant| grant.account_id == account_id)
                    {
                        grant.grants = self.apply(grant.grants, rights, free_busy);
                    }
                }
                MemberChange::Remove { account_id } => {
                    grants.retain(|grant| grant.account_id != account_id);
                }
            }
        }
        grants.retain(|grant| !grant.grants.is_empty());
        grants
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateRole {
    None,
    Reviewer,
    Author,
    Editor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantedRole {
    Role(DelegateRole),
    Custom,
}

impl DelegateRole {
    const ALL: [DelegateRole; 4] = [
        DelegateRole::None,
        DelegateRole::Reviewer,
        DelegateRole::Author,
        DelegateRole::Editor,
    ];

    pub const fn rights(self) -> i32 {
        match self {
            DelegateRole::None => 0,
            DelegateRole::Reviewer => 0x0401,
            DelegateRole::Author => 0x041B,
            DelegateRole::Editor => 0x047B,
        }
    }

    pub(crate) fn grants(self, target: AclTarget) -> Bitmap<Acl> {
        target.apply(Bitmap::new(), self.rights(), false)
    }

    pub(crate) fn from_grants(grants: Bitmap<Acl>, target: AclTarget) -> GrantedRole {
        let visible = target.visible();
        let rights = member_rights(grants, visible, false);
        Self::ALL
            .into_iter()
            .find(|role| member_rights(role.grants(target), visible, false) == rights)
            .map_or(GrantedRole::Custom, GrantedRole::Role)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/folders/rights/tests.rs"]
mod tests;
