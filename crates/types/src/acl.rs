/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Display};
use utils::map::bitmap::{Bitmap, BitmapItem};

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Copy,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
#[repr(u8)]
pub enum Acl {
    Read = 0,
    Modify = 1,
    Delete = 2,
    ReadItems = 3,
    AddItems = 4,
    ModifyItems = 5,
    RemoveItems = 6,
    CreateChild = 7,
    Share = 8,
    Submit = 9,
    SchedulingReadFreeBusy = 10,
    SchedulingInvite = 11,
    SchedulingReply = 12,
    ModifyItemsOwn = 13,
    ModifyPrivateProperties = 14,
    ModifyRSVP = 15,
    None = 16,
}

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    Default,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AclGrant {
    pub account_id: u32,
    pub grants: Bitmap<Acl>,
}

impl Acl {
    fn as_str(&self) -> &'static str {
        match self {
            Acl::Read => "read",
            Acl::Modify => "modify",
            Acl::Delete => "delete",
            Acl::ReadItems => "readItems",
            Acl::AddItems => "addItems",
            Acl::ModifyItems => "modifyItems",
            Acl::RemoveItems => "removeItems",
            Acl::CreateChild => "createChild",
            Acl::Share => "share",
            Acl::Submit => "submit",
            Acl::ModifyItemsOwn => "modifyItemsOwn",
            Acl::ModifyPrivateProperties => "modifyPrivateProperties",
            Acl::None => "",
            Acl::SchedulingReadFreeBusy => "schedulingReadFreeBusy",
            Acl::SchedulingInvite => "schedulingInvite",
            Acl::SchedulingReply => "schedulingReply",
            Acl::ModifyRSVP => "modifyRSVP",
        }
    }
}

impl Display for Acl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl serde::Serialize for Acl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl BitmapItem for Acl {
    fn max() -> u64 {
        Acl::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, Acl::None)
    }
}

impl From<Acl> for u64 {
    fn from(value: Acl) -> Self {
        value as u64
    }
}

impl From<u64> for Acl {
    fn from(value: u64) -> Self {
        match value {
            0 => Acl::Read,
            1 => Acl::Modify,
            2 => Acl::Delete,
            3 => Acl::ReadItems,
            4 => Acl::AddItems,
            5 => Acl::ModifyItems,
            6 => Acl::RemoveItems,
            7 => Acl::CreateChild,
            8 => Acl::Share,
            9 => Acl::Submit,
            10 => Acl::SchedulingReadFreeBusy,
            11 => Acl::SchedulingInvite,
            12 => Acl::SchedulingReply,
            13 => Acl::ModifyItemsOwn,
            14 => Acl::ModifyPrivateProperties,
            15 => Acl::ModifyRSVP,
            _ => Acl::None,
        }
    }
}

impl From<&ArchivedAclGrant> for AclGrant {
    fn from(value: &ArchivedAclGrant) -> Self {
        Self {
            account_id: u32::from(value.account_id),
            grants: (&value.grants).into(),
        }
    }
}
