/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    folder::UserId,
    value::{ews_fields, ews_struct, fields_value},
};
use crate::ews::schema::DelegateFolderPermissionLevel;

ews_fields! {
    pub struct DelegatePermissions {
        calendar: "CalendarFolderPermissionLevel" => DelegateFolderPermissionLevel,
        tasks: "TasksFolderPermissionLevel" => DelegateFolderPermissionLevel,
        inbox: "InboxFolderPermissionLevel" => DelegateFolderPermissionLevel,
        contacts: "ContactsFolderPermissionLevel" => DelegateFolderPermissionLevel,
        notes: "NotesFolderPermissionLevel" => DelegateFolderPermissionLevel,
        journal: "JournalFolderPermissionLevel" => DelegateFolderPermissionLevel,
    }
}

fields_value!(DelegatePermissions);

ews_struct! {
    pub struct DelegateUser<'x> {
        user_id: req "UserId" => UserId<'x>,
        delegate_permissions: opt "DelegatePermissions" => DelegatePermissions,
        receive_copies_of_meeting_messages: opt "ReceiveCopiesOfMeetingMessages" => bool,
        view_private_items: opt "ViewPrivateItems" => bool,
    }
}
