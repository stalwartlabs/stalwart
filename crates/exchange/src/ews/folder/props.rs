/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::filter::{FilterProp, PropValue};
use exchange_proto::ews::{
    schema::{MapiPropertyTypeName, UnindexedField},
    types::{
        path::Path,
        xprop::{ExtendedFieldUri, XPropTarget},
    },
};
use jiff::Timestamp;

pub(crate) const CHANGE_TIME_BASE: i64 = 946_684_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FolderProp {
    DisplayName,
    Class,
    ChildCount,
    Subfolders,
    TotalCount,
    UnreadCount,
    CommitTimeMax,
    LastModified,
}

pub(crate) const EXTENDED_PROPS: [(u16, MapiPropertyTypeName, FolderProp); 8] = [
    (
        0x3001,
        MapiPropertyTypeName::String,
        FolderProp::DisplayName,
    ),
    (0x3613, MapiPropertyTypeName::String, FolderProp::Class),
    (
        0x6638,
        MapiPropertyTypeName::Integer,
        FolderProp::ChildCount,
    ),
    (
        0x360A,
        MapiPropertyTypeName::Boolean,
        FolderProp::Subfolders,
    ),
    (
        0x3602,
        MapiPropertyTypeName::Integer,
        FolderProp::TotalCount,
    ),
    (
        0x3603,
        MapiPropertyTypeName::Integer,
        FolderProp::UnreadCount,
    ),
    (
        0x670A,
        MapiPropertyTypeName::SystemTime,
        FolderProp::CommitTimeMax,
    ),
    (
        0x3008,
        MapiPropertyTypeName::SystemTime,
        FolderProp::LastModified,
    ),
];

impl FilterProp for FolderProp {
    fn of_path(path: &Path<'_>) -> Option<Self> {
        match path {
            Path::Field(field) => Self::of_field(*field),
            Path::Extended(uri) => Self::of_extended(uri).map(|(_, prop)| prop),
            Path::Indexed { .. } => None,
        }
    }
}

impl FolderProp {
    fn of_field(field: UnindexedField) -> Option<Self> {
        Some(match field {
            UnindexedField::FolderDisplayName => FolderProp::DisplayName,
            UnindexedField::FolderFolderClass => FolderProp::Class,
            UnindexedField::FolderChildFolderCount => FolderProp::ChildCount,
            UnindexedField::FolderTotalCount => FolderProp::TotalCount,
            UnindexedField::FolderUnreadCount => FolderProp::UnreadCount,
            _ => return None,
        })
    }

    pub fn of_extended(uri: &ExtendedFieldUri<'_>) -> Option<(usize, Self)> {
        let XPropTarget::Tag(tag) = uri.target else {
            return None;
        };
        EXTENDED_PROPS
            .iter()
            .enumerate()
            .find(|(_, (known, ptype, _))| *known == tag && *ptype == uri.ptype)
            .map(|(index, (_, _, prop))| (index, *prop))
    }

    pub const fn is_change_time(self) -> bool {
        matches!(self, FolderProp::CommitTimeMax | FolderProp::LastModified)
    }

    pub const fn needs_counts(self) -> bool {
        matches!(
            self,
            FolderProp::TotalCount
                | FolderProp::UnreadCount
                | FolderProp::CommitTimeMax
                | FolderProp::LastModified
        )
    }
}

pub(crate) fn change_time(change_id: u64) -> Option<PropValue<'static>> {
    i64::try_from(change_id)
        .ok()
        .and_then(|seconds| seconds.checked_add(CHANGE_TIME_BASE))
        .and_then(|seconds| Timestamp::from_second(seconds).ok())
        .map(PropValue::Time)
}
