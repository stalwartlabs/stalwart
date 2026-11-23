/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    common::{EffectiveRights, RetentionTag},
    ids::{BaseFolderId, FolderId},
    restriction::Restriction,
    value::{EwsValue, Present, Repeated, Strings, T, ews_fields, fields_value},
    xprop::ExtendedProperty,
};
use crate::{
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{
            CalendarPermissionLevel, CalendarPermissionReadAccess, DistinguishedFolderName,
            DistinguishedUser, PermissionAction, PermissionLevel, SearchFolderTraversal,
        },
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

ews_fields! {
    pub struct FolderFields<'x> {
        folder_id: "FolderId" => FolderId<'x>,
        parent_folder_id: "ParentFolderId" => FolderId<'x>,
        folder_class: "FolderClass" => Cow<'x, str>,
        display_name: "DisplayName" => Cow<'x, str>,
        total_count: "TotalCount" => i32,
        child_folder_count: "ChildFolderCount" => i32,
        extended_property: "ExtendedProperty" => Repeated<ExtendedProperty<'x>>,
        effective_rights: "EffectiveRights" => EffectiveRights,
        distinguished_folder_id: "DistinguishedFolderId" => DistinguishedFolderName,
        policy_tag: "PolicyTag" => RetentionTag,
        archive_tag: "ArchiveTag" => RetentionTag,
        replica_list: "ReplicaList" => Strings<'x>,
        sharing_effective_rights: "SharingEffectiveRights" => CalendarPermissionReadAccess,
        permission_set: "PermissionSet" => PermissionSet<'x>,
        unread_count: "UnreadCount" => i32,
        source_id: "SourceId" => Cow<'x, str>,
        account_name: "AccountName" => Cow<'x, str>,
        search_parameters: "SearchParameters" => Box<SearchParameters<'x>>,
        managed_folder_information: "ManagedFolderInformation" => Present,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Folder<'x> {
    Folder(FolderFields<'x>),
    Calendar(FolderFields<'x>),
    Contacts(FolderFields<'x>),
    Search(FolderFields<'x>),
    Tasks(FolderFields<'x>),
}

#[derive(Clone, Copy)]
enum FolderKind {
    Folder,
    Calendar,
    Contacts,
    Search,
    Tasks,
}

impl<'x> Folder<'x> {
    pub fn parse_child(p: &mut Parser<'x>, child: &Child<'x>) -> Result<Option<Self>> {
        let Some(kind) = hashify::map!(child.local.as_bytes(), FolderKind,
            "Folder" => FolderKind::Folder,
            "CalendarFolder" => FolderKind::Calendar,
            "ContactsFolder" => FolderKind::Contacts,
            "SearchFolder" => FolderKind::Search,
            "TasksFolder" => FolderKind::Tasks,
        )
        .copied() else {
            return Ok(None);
        };
        p.expect_types(child)?;
        let mut fields = FolderFields::default();
        while let Some(child) = p.child()? {
            if !fields.parse_child(p, &child)? {
                p.skip()?;
            }
        }
        Ok(Some(match kind {
            FolderKind::Folder => Folder::Folder(fields),
            FolderKind::Calendar => Folder::Calendar(fields),
            FolderKind::Contacts => Folder::Contacts(fields),
            FolderKind::Search => Folder::Search(fields),
            FolderKind::Tasks => Folder::Tasks(fields),
        }))
    }

    pub fn parse_one(p: &mut Parser<'x>) -> Result<Self> {
        let mut found = None;
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(folder) if found.is_none() => found = Some(folder),
                Some(_) => return Err(p.error(ParseErrorKind::InvalidValue("Folder"))),
                None => p.skip()?,
            }
        }
        found.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Folder")))
    }

    pub fn parse_list(p: &mut Parser<'x>) -> Result<Vec<Self>> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Self::parse_child(p, &child)? {
                Some(folder) => {
                    p.count_id()?;
                    list.push(folder);
                }
                None => p.skip()?,
            }
        }
        Ok(list)
    }

    pub const fn element(&self) -> &'static str {
        match self {
            Folder::Folder(_) => "Folder",
            Folder::Calendar(_) => "CalendarFolder",
            Folder::Contacts(_) => "ContactsFolder",
            Folder::Search(_) => "SearchFolder",
            Folder::Tasks(_) => "TasksFolder",
        }
    }

    pub fn fields(&self) -> &FolderFields<'x> {
        match self {
            Folder::Folder(fields)
            | Folder::Calendar(fields)
            | Folder::Contacts(fields)
            | Folder::Search(fields)
            | Folder::Tasks(fields) => fields,
        }
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        let name = self.element();
        w.start(T, name);
        self.fields().write_fields(w);
        w.end(T, name);
    }
}

ews_fields! {
    pub struct UserId<'x> {
        sid: "SID" => Cow<'x, str>,
        primary_smtp_address: "PrimarySmtpAddress" => Cow<'x, str>,
        display_name: "DisplayName" => Cow<'x, str>,
        distinguished_user: "DistinguishedUser" => DistinguishedUser,
        external_user_identity: "ExternalUserIdentity" => Cow<'x, str>,
    }
}

fields_value!(UserId<'x>);

ews_fields! {
    pub struct Permission<'x> {
        user_id: "UserId" => UserId<'x>,
        can_create_items: "CanCreateItems" => bool,
        can_create_sub_folders: "CanCreateSubFolders" => bool,
        is_folder_owner: "IsFolderOwner" => bool,
        is_folder_visible: "IsFolderVisible" => bool,
        is_folder_contact: "IsFolderContact" => bool,
        edit_items: "EditItems" => PermissionAction,
        delete_items: "DeleteItems" => PermissionAction,
        read_items: "ReadItems" => CalendarPermissionReadAccess,
        permission_level: "PermissionLevel" => PermissionLevel,
        calendar_permission_level: "CalendarPermissionLevel" => CalendarPermissionLevel,
    }
}

fields_value!(Permission<'x>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSetKind {
    Folder,
    Calendar,
}

impl PermissionSetKind {
    const fn names(self) -> (&'static str, &'static str) {
        match self {
            PermissionSetKind::Folder => ("Permissions", "Permission"),
            PermissionSetKind::Calendar => ("CalendarPermissions", "CalendarPermission"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PermissionSet<'x> {
    pub kind: PermissionSetKind,
    pub permissions: Vec<Permission<'x>>,
    pub unknown_entries: Vec<Cow<'x, str>>,
}

impl<'x> EwsValue<'x> for PermissionSet<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut set = PermissionSet {
            kind: PermissionSetKind::Folder,
            permissions: Vec::new(),
            unknown_entries: Vec::new(),
        };
        while let Some(child) = p.child()? {
            let kind = hashify::fnc_map!(child.local.as_bytes(),
                "Permissions" => { PermissionSetKind::Folder },
                "CalendarPermissions" => { PermissionSetKind::Calendar },
                "UnknownEntries" => {
                    p.expect_types(&child)?;
                    while let Some(entry) = p.child()? {
                        if entry.local == "UnknownEntry" {
                            p.expect_types(&entry)?;
                            set.unknown_entries.push(p.text()?);
                        } else {
                            p.skip()?;
                        }
                    }
                    continue;
                },
                _ => {
                    p.skip()?;
                    continue;
                }
            );
            p.expect_types(&child)?;
            set.kind = kind;
            let (_, item) = kind.names();
            while let Some(entry) = p.child()? {
                if entry.local == item {
                    p.expect_types(&entry)?;
                    p.count_id()?;
                    set.permissions.push(Permission::parse(p, &entry.attrs)?);
                } else {
                    p.skip()?;
                }
            }
        }
        Ok(set)
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        let (list, item) = self.kind.names();
        w.start(T, local);
        w.start(T, list);
        for permission in &self.permissions {
            permission.write(w, item);
        }
        w.end(T, list);
        if !self.unknown_entries.is_empty() {
            w.start(T, "UnknownEntries");
            for entry in &self.unknown_entries {
                w.leaf(T, "UnknownEntry", entry);
            }
            w.end(T, "UnknownEntries");
        }
        w.end(T, local);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchParameters<'x> {
    pub traversal: Option<SearchFolderTraversal>,
    pub restriction: Option<Restriction<'x>>,
    pub base_folder_ids: Vec<BaseFolderId<'x>>,
}

impl<'x> EwsValue<'x> for SearchParameters<'x> {
    fn parse(p: &mut Parser<'x>, attrs: &Attrs<'x>) -> Result<Self> {
        let traversal = p.attr_enum(attrs, "Traversal", SearchFolderTraversal::parse)?;
        let mut restriction = None;
        let mut base_folder_ids = Vec::new();
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "Restriction" => {
                    p.expect_types(&child)?;
                    restriction = Some(Restriction::parse(p)?);
                },
                "BaseFolderIds" => {
                    p.expect_types(&child)?;
                    base_folder_ids = BaseFolderId::parse_list(p)?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(SearchParameters {
            traversal,
            restriction,
            base_folder_ids,
        })
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        w.start(T, local);
        if let Some(traversal) = self.traversal {
            w.attr("Traversal", traversal.as_str());
        }
        if let Some(restriction) = &self.restriction {
            w.start(T, "Restriction");
            restriction.write_expression(w);
            w.end(T, "Restriction");
        }
        w.start(T, "BaseFolderIds");
        for id in &self.base_folder_ids {
            id.write(w);
        }
        w.end(T, "BaseFolderIds");
        w.end(T, local);
    }
}
