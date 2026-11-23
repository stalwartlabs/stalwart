/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod access;
mod build;
pub(crate) mod copy;
pub mod rights;
pub(crate) mod tree;
mod write;

pub use build::ExchangeFolders;
pub(crate) use build::default_container;
pub use tree::{FolderEntry, FolderTree, HierarchyVersion, ScopeKinds};
pub use write::{
    AclEdit, AclWriteError, AclWriteResult, FolderContents, FolderCreate, FolderUpdate,
    FolderWriteError, FolderWriteResult, FolderWrites, FolderWritten, WritableFolder, WriteOutcome,
};

use crate::store::{FolderKind, FolderRef, eas::StoredFolder};
use exchange_proto::{
    ids::token::ObjectKind,
    mapi::prop::{OwnedPropValue, PropKeyRef, PropValue, read_canonical_borrowed, tags},
};
use std::sync::Arc;
use store::write::metadata::ExchangeFolder;

macro_rules! special_folders {
    ($($variant:ident = $code:literal, $name:literal, $class:ident;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SpecialFolder {
            $($variant),+
        }

        const _: () = { $(assert!($code < u32::BITS);)+ };

        impl SpecialFolder {
            pub const ALL: &'static [SpecialFolder] = &[$(SpecialFolder::$variant),+];

            pub const fn code(self) -> u8 {
                match self {
                    $(SpecialFolder::$variant => $code),+
                }
            }

            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $($code => Some(SpecialFolder::$variant),)+
                    _ => None,
                }
            }

            pub const fn display_name(self) -> &'static str {
                match self {
                    $(SpecialFolder::$variant => $name),+
                }
            }

            pub const fn bit(self) -> u32 {
                1 << self.code()
            }

            pub fn class(self) -> ContainerClass {
                match self {
                    $(SpecialFolder::$variant => special_folders!(@class $class)),+
                }
            }
        }
    };
    (@class None) => { ContainerClass::Other(Box::default()) };
    (@class $class:ident) => { ContainerClass::$class };
}

special_folders! {
    Root = 0, "Root", None;
    IpmSubtree = 1, "Top of Information Store", None;
    Inbox = 2, "Inbox", Note;
    Drafts = 3, "Drafts", Note;
    SentItems = 4, "Sent Items", Note;
    DeletedItems = 5, "Deleted Items", Note;
    JunkEmail = 6, "Junk Email", Note;
    Archive = 7, "Archive", Note;
    Outbox = 8, "Outbox", Note;
    SyncIssues = 9, "Sync Issues", Note;
    Conflicts = 10, "Conflicts", Note;
    LocalFailures = 11, "Local Failures", Note;
    ServerFailures = 12, "Server Failures", Note;
    Calendar = 13, "Calendar", Appointment;
    Contacts = 14, "Contacts", Contact;
    Tasks = 15, "Tasks", Task;
    Notes = 16, "Notes", StickyNote;
    Journal = 17, "Journal", Journal;
    Views = 18, "Views", None;
    CommonViews = 19, "Common Views", None;
    Finder = 20, "Finder", None;
    Schedule = 21, "Schedule", None;
    Shortcuts = 22, "Shortcuts", None;
    DeferredAction = 23, "Deferred Action", None;
    SpoolerQueue = 24, "Spooler Queue", None;
}

pub(crate) const SYNC_ISSUES_FOLDERS: [SpecialFolder; 3] = [
    SpecialFolder::Conflicts,
    SpecialFolder::LocalFailures,
    SpecialFolder::ServerFailures,
];

impl SpecialFolder {
    pub const fn is_fixed(self) -> bool {
        matches!(
            self,
            SpecialFolder::Root
                | SpecialFolder::IpmSubtree
                | SpecialFolder::Outbox
                | SpecialFolder::Conflicts
                | SpecialFolder::LocalFailures
                | SpecialFolder::ServerFailures
                | SpecialFolder::Views
                | SpecialFolder::CommonViews
                | SpecialFolder::Finder
                | SpecialFolder::Schedule
                | SpecialFolder::Shortcuts
                | SpecialFolder::DeferredAction
                | SpecialFolder::SpoolerQueue
        )
    }

    pub const fn holds_fai(self) -> bool {
        self.is_fixed() || matches!(self, SpecialFolder::SyncIssues)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ContainerClass {
    Note,
    StickyNote,
    Appointment,
    Contact,
    Task,
    Journal,
    Other(Box<str>),
}

impl ContainerClass {
    pub fn parse(class: &str) -> Self {
        hashify::fnc_map!(class.as_bytes(),
            "IPF.Note" => ContainerClass::Note,
            "IPF.StickyNote" => ContainerClass::StickyNote,
            "IPF.Appointment" => ContainerClass::Appointment,
            "IPF.Contact" => ContainerClass::Contact,
            "IPF.Task" => ContainerClass::Task,
            "IPF.Journal" => ContainerClass::Journal,
            _ => ContainerClass::Other(class.into())
        )
    }

    pub fn as_str(&self) -> &str {
        match self {
            ContainerClass::Note => "IPF.Note",
            ContainerClass::StickyNote => "IPF.StickyNote",
            ContainerClass::Appointment => "IPF.Appointment",
            ContainerClass::Contact => "IPF.Contact",
            ContainerClass::Task => "IPF.Task",
            ContainerClass::Journal => "IPF.Journal",
            ContainerClass::Other(class) => class,
        }
    }

    pub fn family(&self) -> Option<WritableFolder> {
        match self {
            ContainerClass::Note
            | ContainerClass::StickyNote
            | ContainerClass::Task
            | ContainerClass::Journal => Some(WritableFolder::Mailbox),
            ContainerClass::Appointment => Some(WritableFolder::Calendar),
            ContainerClass::Contact => Some(WritableFolder::AddressBook),
            ContainerClass::Other(class) => {
                let base = class.strip_prefix(CLASS_PREFIX)?;
                let base = base.split_once('.').map_or(base, |(base, _)| base);
                (!base.is_empty()).then(|| {
                    hashify::map!(base.as_bytes(), WritableFolder,
                        "Appointment" => WritableFolder::Calendar,
                        "Contact" => WritableFolder::AddressBook,
                    )
                    .copied()
                    .unwrap_or(WritableFolder::Mailbox)
                })
            }
        }
    }

    pub(crate) fn property_key() -> Vec<u8> {
        let mut key = Vec::with_capacity(TAG_KEY_LEN);
        PropKeyRef::Tag(tags::CONTAINER_CLASS.id()).write_canonical(&mut key);
        key
    }

    pub(crate) fn property_value(&self) -> Vec<u8> {
        let mut value = Vec::new();
        OwnedPropValue::Unicode(self.as_str().into()).write_canonical(&mut value);
        value
    }

    pub(crate) fn wire_value(value: PropValue<'_>) -> PropValue<'_> {
        match value {
            PropValue::Unicode(units) if units.as_bytes().starts_with(CLASS_PREFIX.as_bytes()) => {
                let bytes = units.as_bytes();
                PropValue::String8(bytes.split(|byte| *byte == 0).next().unwrap_or(bytes))
            }
            value => value,
        }
    }

    pub(crate) fn from_property_value(value: &[u8]) -> Option<Self> {
        match read_canonical_borrowed(value)? {
            (PropValue::Unicode(text), _) => {
                let mut class = String::new();
                text.to_string_lossy(&mut class);
                Some(ContainerClass::parse(&class))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FolderNode {
    Special(SpecialFolder),
    Stored(FolderRef),
}

const SPECIAL_ID_BASE: u32 = 0xFFFF_FF00;
const SPECIAL_PARENT_KIND: u8 = 0x0F;
const TAG_KEY_LEN: usize = 3;
const PARENT_VALUE_LEN: usize = 14;
const CLASS_PREFIX: &str = "IPF.";

impl FolderNode {
    pub fn object_id(self) -> Option<(ObjectKind, u32)> {
        match self {
            FolderNode::Stored(FolderRef { kind, id }) => match kind {
                FolderKind::Mailbox => Some((ObjectKind::MailFolder, id)),
                FolderKind::Calendar => Some((ObjectKind::Calendar, id)),
                FolderKind::AddressBook => Some((ObjectKind::AddressBook, id)),
                FolderKind::Virtual => Some((ObjectKind::VirtualFolder, id)),
                FolderKind::FileNode => None,
            },
            FolderNode::Special(special) => Some((
                ObjectKind::VirtualFolder,
                SPECIAL_ID_BASE | u32::from(special.code()),
            )),
        }
    }

    pub(crate) const fn exchange_folder(self) -> ExchangeFolder {
        match self {
            FolderNode::Special(special) => ExchangeFolder {
                kind: SPECIAL_PARENT_KIND,
                id: special.code() as u32,
            },
            FolderNode::Stored(folder) => folder.stored(),
        }
    }

    pub fn to_stored(self) -> StoredFolder {
        let ExchangeFolder { kind, id } = self.exchange_folder();
        StoredFolder { kind, id }
    }

    pub fn from_stored(kind: u8, id: u32) -> Option<Self> {
        if kind == SPECIAL_PARENT_KIND {
            SpecialFolder::from_code(u8::try_from(id).ok()?).map(FolderNode::Special)
        } else {
            FolderKind::from_code(kind).map(|kind| FolderNode::Stored(FolderRef { kind, id }))
        }
    }

    pub(crate) fn parent_property_key() -> Vec<u8> {
        let mut key = Vec::with_capacity(TAG_KEY_LEN);
        PropKeyRef::Tag(tags::PARENT_FOLDER_ID.id()).write_canonical(&mut key);
        key
    }

    pub(crate) fn parent_property_value(self) -> Vec<u8> {
        let ExchangeFolder { kind, id } = self.exchange_folder();
        let mut value = Vec::with_capacity(PARENT_VALUE_LEN);
        OwnedPropValue::I64((i64::from(kind) << u32::BITS) | i64::from(id))
            .write_canonical(&mut value);
        value
    }

    pub(crate) fn parent_from_property(value: &[u8]) -> Option<ExchangeFolder> {
        let (PropValue::I64(packed), _) = read_canonical_borrowed(value)? else {
            return None;
        };
        Some(ExchangeFolder {
            kind: u8::try_from(packed >> u32::BITS).ok()?,
            id: u32::try_from(packed & i64::from(u32::MAX)).ok()?,
        })
    }

    pub(crate) const fn ipm_parent() -> ExchangeFolder {
        FolderNode::Special(SpecialFolder::IpmSubtree).exchange_folder()
    }

    pub fn from_object_id(kind: ObjectKind, id: u32) -> Option<Self> {
        let kind = match kind {
            ObjectKind::MailFolder => FolderKind::Mailbox,
            ObjectKind::Calendar => FolderKind::Calendar,
            ObjectKind::AddressBook => FolderKind::AddressBook,
            ObjectKind::VirtualFolder if id >= SPECIAL_ID_BASE => {
                return SpecialFolder::from_code(u8::try_from(id - SPECIAL_ID_BASE).ok()?)
                    .map(FolderNode::Special);
            }
            ObjectKind::VirtualFolder => FolderKind::Virtual,
            _ => return None,
        };
        Some(FolderNode::Stored(FolderRef { kind, id }))
    }
}

pub(crate) fn special_name(folder: SpecialFolder) -> Arc<str> {
    Arc::from(folder.display_name())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/folders/tests.rs"]
mod tests;
