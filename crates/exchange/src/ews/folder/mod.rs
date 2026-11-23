/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod copy;
pub mod get;
pub mod props;
pub mod sync;
pub mod write;

use self::props::{EXTENDED_PROPS, FolderProp, change_time};
use super::context::{EwsContext, MailboxOwner};
use super::filter::PropValue;
use crate::{
    folders::{
        ContainerClass, FolderEntry, FolderNode, FolderTree, SpecialFolder, access::ViewRights,
        rights::FolderRights,
    },
    store::{FolderKind, FolderRef},
};
use ahash::AHashMap;
use common::{GroupwareResources, Server};
use email::cache::MessageCacheFetch;
use exchange_proto::{
    ews::{
        MessageXml, Status,
        schema::{BaseShape, DistinguishedFolderName, ResponseCode, UnindexedField},
        types::{
            common::EffectiveRights,
            folder::{Folder, FolderFields},
            ids::{BaseFolderId, DistinguishedFolderId, EwsIdStr, FolderId, TargetFolderId},
            path::Path,
            shape::FolderShape,
            value::Repeated,
            xprop::{ExtendedFieldUri, ExtendedProperty, XPropTarget, XPropValue},
        },
    },
    ids::ews::{EwsChangeKey, EwsObjectId},
};
use groupware::cache::GroupwareCache;
use smallvec::smallvec;
use std::{borrow::Cow, sync::Arc};
use types::{collection::SyncCollection, keyword::SEEN, type_state::DataType};

const FOLDER_NOT_FOUND: &str = "The specified folder could not be found in the store.";
const ID_MALFORMED: &str = "Id is malformed.";
const SAVED_FOLDER_NOT_FOUND: &str = "The folder to save the item in could not be found.";
const PARENT_FOLDER_NOT_FOUND: &str = "The parent folder could not be found.";
const CROSS_MAILBOX: &str = "Items and folders cannot be moved or copied between mailboxes.";
const MAILBOX_ITEM_NOT_FOUND: &str = "The specified object was not found in the store., The process failed to get the correct properties.";
const NON_EXISTENT_MAILBOX: &str = "The SMTP address has no mailbox associated with it.";
const SMTP_ADDRESS: &str = "SmtpAddress";
const SEEN_BIT: u32 = 1 << SEEN;

#[derive(Clone, Copy)]
pub(crate) enum FolderSelector<'r, 'a> {
    Id(&'r FolderId<'a>),
    Distinguished(&'r DistinguishedFolderId<'a>),
    AddressList,
}

impl<'r, 'a> From<&'r BaseFolderId<'a>> for FolderSelector<'r, 'a> {
    fn from(id: &'r BaseFolderId<'a>) -> Self {
        match id {
            BaseFolderId::Folder(id) => FolderSelector::Id(id),
            BaseFolderId::Distinguished(id) => FolderSelector::Distinguished(id),
        }
    }
}

impl<'r, 'a> From<&'r TargetFolderId<'a>> for FolderSelector<'r, 'a> {
    fn from(id: &'r TargetFolderId<'a>) -> Self {
        match id {
            TargetFolderId::Folder(id) => FolderSelector::Id(id),
            TargetFolderId::Distinguished(id) => FolderSelector::Distinguished(id),
            TargetFolderId::AddressList(_) => FolderSelector::AddressList,
        }
    }
}

pub(crate) async fn resolve_folder<'t>(
    server: &Server,
    ctx: &EwsContext,
    tree: &'t FolderTree,
    selector: FolderSelector<'_, '_>,
) -> trc::Result<Result<&'t FolderEntry, Status<'static>>> {
    let node = match selector {
        FolderSelector::Id(id) => match EwsObjectId::decode(id.id.as_str()) {
            Some(EwsObjectId::Folder { account, kind, id }) => {
                match FolderNode::from_object_id(kind, id) {
                    Some(node) if account == ctx.account.account_id => node,
                    _ => return Ok(Err(folder_not_found())),
                }
            }
            _ => {
                return Ok(Err(Status::error(
                    ResponseCode::ErrorInvalidIdMalformed,
                    ID_MALFORMED,
                )));
            }
        },
        FolderSelector::Distinguished(id) => {
            let address = id
                .mailbox
                .as_ref()
                .and_then(|mailbox| mailbox.email_address.as_deref())
                .filter(|address| !address.is_empty());
            match address {
                Some(address) => match ctx.mailbox_owner(server, address).await? {
                    MailboxOwner::Target => {}
                    MailboxOwner::Other => return Ok(Err(mailbox_item_not_found())),
                    MailboxOwner::Unknown => return Ok(Err(non_existent_mailbox(address))),
                },
                None if !ctx.targets_caller() => return Ok(Err(folder_not_found())),
                None => {}
            }
            let found = special_of(id.name).and_then(|special| tree.special(special));
            return Ok(match found {
                Some(entry) => Ok(entry),
                None if address.is_some() && ctx.access.is_delegate() => {
                    Err(mailbox_item_not_found())
                }
                None => Err(folder_not_found()),
            });
        }
        FolderSelector::AddressList => return Ok(Err(folder_not_found())),
    };
    Ok(match node {
        FolderNode::Special(special) => tree.special(special),
        node => tree.get(node),
    }
    .ok_or_else(folder_not_found))
}

pub(crate) fn removed_folder_status(
    ctx: &EwsContext,
    tree: &FolderTree,
    id: &BaseFolderId<'_>,
) -> Option<Status<'static>> {
    let BaseFolderId::Folder(id) = id else {
        return None;
    };
    let Some(EwsObjectId::Folder { account, kind, id }) = EwsObjectId::decode(id.id.as_str())
    else {
        return None;
    };
    let node = FolderNode::from_object_id(kind, id)?;
    let missing = match node {
        FolderNode::Special(special) => tree.special(special),
        node => tree.get(node),
    }
    .is_none();
    (missing && account == ctx.account.account_id && !ctx.access.is_delegate())
        .then(mailbox_item_not_found)
}

pub(crate) fn saved_folder_status(ctx: &EwsContext, status: Status<'static>) -> Status<'static> {
    delegate_not_found(
        ctx,
        status,
        ResponseCode::ErrorSavedItemFolderNotFound,
        SAVED_FOLDER_NOT_FOUND,
    )
}

pub(crate) fn parent_folder_status(ctx: &EwsContext, status: Status<'static>) -> Status<'static> {
    delegate_not_found(
        ctx,
        status,
        ResponseCode::ErrorParentFolderNotFound,
        PARENT_FOLDER_NOT_FOUND,
    )
}

fn delegate_not_found(
    ctx: &EwsContext,
    status: Status<'static>,
    code: ResponseCode,
    text: &'static str,
) -> Status<'static> {
    if ctx.access.is_delegate()
        && matches!(
            status.code,
            ResponseCode::ErrorFolderNotFound | ResponseCode::ErrorItemNotFound
        )
    {
        Status::error(code, text)
    } else {
        status
    }
}

pub(crate) fn crosses_mailbox(ctx: &EwsContext, id: &TargetFolderId<'_>) -> bool {
    !ctx.targets_caller()
        && match id {
            TargetFolderId::Folder(id) => EwsObjectId::decode(id.id.as_str())
                .is_some_and(|id| id.account() != ctx.account.account_id),
            TargetFolderId::Distinguished(id) => id
                .mailbox
                .as_ref()
                .and_then(|mailbox| mailbox.email_address.as_deref())
                .is_none_or(str::is_empty),
            TargetFolderId::AddressList(_) => false,
        }
}

pub(crate) fn cross_mailbox_status() -> Status<'static> {
    Status::error(ResponseCode::ErrorCrossMailboxMoveCopy, CROSS_MAILBOX)
}

pub(crate) fn folder_not_found() -> Status<'static> {
    Status::error(ResponseCode::ErrorFolderNotFound, FOLDER_NOT_FOUND)
}

fn mailbox_item_not_found() -> Status<'static> {
    Status::error(ResponseCode::ErrorItemNotFound, MAILBOX_ITEM_NOT_FOUND)
}

#[cold]
fn non_existent_mailbox(address: &str) -> Status<'static> {
    Status::error(ResponseCode::ErrorNonExistentMailbox, NON_EXISTENT_MAILBOX).with_message_xml(
        MessageXml::Values(smallvec![(SMTP_ADDRESS, Cow::Owned(address.to_owned()))]),
    )
}

pub(crate) fn folder_id(account_id: u32, node: FolderNode, change_id: u64) -> FolderId<'static> {
    match node.object_id() {
        Some((kind, id)) => FolderId {
            id: EwsIdStr::Minted(
                EwsObjectId::Folder {
                    account: account_id,
                    kind,
                    id,
                }
                .encode(),
            ),
            change_key: Some(EwsIdStr::Minted(EwsChangeKey { kind, change_id }.encode())),
        },
        None => FolderId {
            id: EwsIdStr::Parsed(Cow::Borrowed("")),
            change_key: None,
        },
    }
}

fn special_of(name: DistinguishedFolderName) -> Option<SpecialFolder> {
    Some(match name {
        DistinguishedFolderName::Root => SpecialFolder::Root,
        DistinguishedFolderName::Msgfolderroot => SpecialFolder::IpmSubtree,
        DistinguishedFolderName::Inbox => SpecialFolder::Inbox,
        DistinguishedFolderName::Drafts => SpecialFolder::Drafts,
        DistinguishedFolderName::Sentitems => SpecialFolder::SentItems,
        DistinguishedFolderName::Deleteditems => SpecialFolder::DeletedItems,
        DistinguishedFolderName::Junkemail => SpecialFolder::JunkEmail,
        DistinguishedFolderName::Archive => SpecialFolder::Archive,
        DistinguishedFolderName::Outbox => SpecialFolder::Outbox,
        DistinguishedFolderName::Syncissues => SpecialFolder::SyncIssues,
        DistinguishedFolderName::Conflicts => SpecialFolder::Conflicts,
        DistinguishedFolderName::Localfailures => SpecialFolder::LocalFailures,
        DistinguishedFolderName::Serverfailures => SpecialFolder::ServerFailures,
        DistinguishedFolderName::Calendar => SpecialFolder::Calendar,
        DistinguishedFolderName::Contacts => SpecialFolder::Contacts,
        DistinguishedFolderName::Tasks => SpecialFolder::Tasks,
        DistinguishedFolderName::Notes => SpecialFolder::Notes,
        DistinguishedFolderName::Journal => SpecialFolder::Journal,
        DistinguishedFolderName::Searchfolders => SpecialFolder::Finder,
        _ => return None,
    })
}

fn distinguished_of(special: SpecialFolder) -> Option<DistinguishedFolderName> {
    Some(match special {
        SpecialFolder::Root => DistinguishedFolderName::Root,
        SpecialFolder::IpmSubtree => DistinguishedFolderName::Msgfolderroot,
        SpecialFolder::Inbox => DistinguishedFolderName::Inbox,
        SpecialFolder::Drafts => DistinguishedFolderName::Drafts,
        SpecialFolder::SentItems => DistinguishedFolderName::Sentitems,
        SpecialFolder::DeletedItems => DistinguishedFolderName::Deleteditems,
        SpecialFolder::JunkEmail => DistinguishedFolderName::Junkemail,
        SpecialFolder::Archive => DistinguishedFolderName::Archive,
        SpecialFolder::Outbox => DistinguishedFolderName::Outbox,
        SpecialFolder::SyncIssues => DistinguishedFolderName::Syncissues,
        SpecialFolder::Conflicts => DistinguishedFolderName::Conflicts,
        SpecialFolder::LocalFailures => DistinguishedFolderName::Localfailures,
        SpecialFolder::ServerFailures => DistinguishedFolderName::Serverfailures,
        SpecialFolder::Calendar => DistinguishedFolderName::Calendar,
        SpecialFolder::Contacts => DistinguishedFolderName::Contacts,
        SpecialFolder::Tasks => DistinguishedFolderName::Tasks,
        SpecialFolder::Notes => DistinguishedFolderName::Notes,
        SpecialFolder::Journal => DistinguishedFolderName::Journal,
        SpecialFolder::Finder => DistinguishedFolderName::Searchfolders,
        SpecialFolder::Views
        | SpecialFolder::CommonViews
        | SpecialFolder::Schedule
        | SpecialFolder::Shortcuts
        | SpecialFolder::DeferredAction
        | SpecialFolder::SpoolerQueue => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FolderFieldSet(u32);

impl FolderFieldSet {
    const ID: u32 = 1;
    const PARENT: u32 = 1 << 1;
    const CLASS: u32 = 1 << 2;
    const NAME: u32 = 1 << 3;
    const TOTAL: u32 = 1 << 4;
    const CHILDREN: u32 = 1 << 5;
    const UNREAD: u32 = 1 << 6;
    const RIGHTS: u32 = 1 << 7;
    const DISTINGUISHED: u32 = 1 << 8;
    const EXTENDED_SHIFT: usize = 9;
    const EXTENDED: u32 = ((1 << EXTENDED_PROPS.len()) - 1) << Self::EXTENDED_SHIFT;
    const EXTENDED_COUNTS: u32 = {
        let mut mask = 0;
        let mut index = 0;
        while index < EXTENDED_PROPS.len() {
            if EXTENDED_PROPS[index].2.needs_counts() {
                mask |= 1 << (Self::EXTENDED_SHIFT + index);
            }
            index += 1;
        }
        mask
    };
    const EXTENDED_TIMES: u32 = {
        let mut mask = 0;
        let mut index = 0;
        while index < EXTENDED_PROPS.len() {
            if EXTENDED_PROPS[index].2.is_change_time() {
                mask |= 1 << (Self::EXTENDED_SHIFT + index);
            }
            index += 1;
        }
        mask
    };
    const DEFAULT: u32 = Self::ID | Self::NAME | Self::TOTAL | Self::CHILDREN | Self::UNREAD;
    const ALL: u32 = Self::DEFAULT | Self::PARENT | Self::CLASS | Self::RIGHTS;

    pub fn from_shape(shape: &FolderShape<'_>) -> Self {
        let mut fields = match shape.base {
            BaseShape::IdOnly => Self::ID,
            BaseShape::Default => Self::DEFAULT,
            BaseShape::AllProperties | BaseShape::PcxPeopleSearch => Self::ALL,
        };
        for path in &shape.additional {
            fields |= Self::of_path(path);
        }
        FolderFieldSet(fields)
    }

    fn of_path(path: &Path<'_>) -> u32 {
        let field = match path {
            Path::Field(field) => field,
            Path::Extended(uri) => {
                return FolderProp::of_extended(uri)
                    .map_or(0, |(index, _)| 1 << (Self::EXTENDED_SHIFT + index));
            }
            Path::Indexed { .. } => return 0,
        };
        match field {
            UnindexedField::FolderFolderId => Self::ID,
            UnindexedField::FolderParentFolderId => Self::PARENT,
            UnindexedField::FolderFolderClass => Self::CLASS,
            UnindexedField::FolderDisplayName => Self::NAME,
            UnindexedField::FolderTotalCount => Self::TOTAL,
            UnindexedField::FolderChildFolderCount => Self::CHILDREN,
            UnindexedField::FolderUnreadCount => Self::UNREAD,
            UnindexedField::FolderEffectiveRights => Self::RIGHTS,
            UnindexedField::FolderDistinguishedFolderId => Self::DISTINGUISHED,
            _ => 0,
        }
    }

    fn has(self, field: u32) -> bool {
        self.0 & field != 0
    }

    pub fn needs_counts(self) -> bool {
        self.has(Self::TOTAL | Self::UNREAD | Self::EXTENDED_COUNTS)
    }

    pub fn with_counts(self) -> Self {
        FolderFieldSet(self.0 | Self::TOTAL | Self::EXTENDED_TIMES)
    }

    fn needs_change_times(self) -> bool {
        self.has(Self::EXTENDED_TIMES)
    }

    fn has_extended(self, index: usize) -> bool {
        self.has(1 << (Self::EXTENDED_SHIFT + index))
    }
}

#[derive(Default)]
pub(crate) struct FolderCounts {
    mail: AHashMap<u32, (usize, usize)>,
    mail_changes: AHashMap<u32, u64>,
    calendars: Option<Arc<GroupwareResources>>,
    delegate: Option<ViewRights>,
    address_books: Option<Arc<GroupwareResources>>,
}

impl FolderCounts {
    pub async fn load<'t>(
        server: &Server,
        ctx: &EwsContext,
        fields: FolderFieldSet,
        entries: impl Iterator<Item = &'t FolderEntry> + Clone,
    ) -> trc::Result<Self> {
        let mut counts = FolderCounts {
            delegate: ctx.access.is_delegate().then(|| ctx.access.clone()),
            ..Default::default()
        };
        if !fields.needs_counts() {
            return Ok(counts);
        }
        let account_id = ctx.account.account_id;
        let mut calendars = false;
        let mut address_books = false;
        let mut mail = false;
        for entry in entries.clone() {
            match entry.node {
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    ..
                }) => mail = true,
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Calendar,
                    ..
                }) => calendars = true,
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::AddressBook,
                    ..
                }) => address_books = true,
                _ => {}
            }
        }
        if mail && ctx.account.data_types.contains(DataType::Email) {
            let cache = server.get_cached_messages(account_id).await?;
            counts.mail = entries
                .filter_map(|entry| match entry.node {
                    FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        id,
                    }) => Some((id, (0, 0))),
                    _ => None,
                })
                .collect();
            let change_times = fields.needs_change_times();
            if change_times {
                counts.mail_changes = counts.mail.keys().map(|id| (*id, 0)).collect();
            }
            for message in cache.emails.iter() {
                let unread = usize::from(message.keywords() & SEEN_BIT == 0);
                let mailboxes = message.mailboxes();
                for (pos, uid) in mailboxes.iter().enumerate() {
                    if let Some((total, unread_count)) = counts.mail.get_mut(&uid.mailbox_id)
                        && !mailboxes
                            .iter()
                            .take(pos)
                            .any(|prev| prev.mailbox_id == uid.mailbox_id)
                    {
                        *total += 1;
                        *unread_count += unread;
                    }
                    if change_times
                        && let Some(change_id) = counts.mail_changes.get_mut(&uid.mailbox_id)
                    {
                        *change_id = (*change_id).max(message.change_id());
                    }
                }
            }
        }
        if calendars && ctx.account.data_types.contains(DataType::CalendarEvent) {
            counts.calendars = Some(
                server
                    .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
                    .await?,
            );
        }
        if address_books && ctx.account.data_types.contains(DataType::ContactCard) {
            counts.address_books = Some(
                server
                    .fetch_groupware_resources(account_id, account_id, SyncCollection::AddressBook)
                    .await?,
            );
        }
        Ok(counts)
    }

    fn of(&self, node: FolderNode) -> (usize, usize) {
        let FolderNode::Stored(FolderRef { kind, id }) = node else {
            return (0, 0);
        };
        match kind {
            FolderKind::Mailbox => self.mail.get(&id).copied().unwrap_or_default(),
            FolderKind::Calendar => (self.calendar_count(id), 0),
            FolderKind::AddressBook => (children_count(self.address_books.as_deref(), id), 0),
            FolderKind::FileNode | FolderKind::Virtual => (0, 0),
        }
    }
}

impl FolderCounts {
    fn change_id(&self, entry: &FolderEntry) -> u64 {
        let FolderNode::Stored(FolderRef { kind, id }) = entry.node else {
            return entry.change_id;
        };
        match kind {
            FolderKind::Mailbox => self
                .mail_changes
                .get(&id)
                .map(|change_id| (*change_id).max(entry.change_id)),
            FolderKind::Calendar => self
                .calendars
                .as_deref()
                .map(|resources| resources.highest_change_id),
            FolderKind::AddressBook => self
                .address_books
                .as_deref()
                .map(|resources| resources.highest_change_id),
            FolderKind::FileNode | FolderKind::Virtual => None,
        }
        .unwrap_or(entry.change_id)
    }
}

impl FolderCounts {
    fn calendar_count(&self, id: u32) -> usize {
        let Some(resources) = self.calendars.as_deref() else {
            return 0;
        };
        match &self.delegate {
            Some(view) => resources
                .children_ids(id)
                .filter(|document_id| !view.hides(resources, *document_id))
                .count(),
            None => resources.children_ids(id).count(),
        }
    }
}

fn children_count(resources: Option<&GroupwareResources>, id: u32) -> usize {
    resources.map_or(0, |resources| resources.children_ids(id).count())
}

pub(crate) struct FolderRenderer<'t> {
    pub tree: &'t FolderTree,
    pub access: &'t ViewRights,
    pub account_id: u32,
    pub fields: FolderFieldSet,
    pub counts: FolderCounts,
}

impl<'t> FolderRenderer<'t> {
    pub fn render(&self, entry: &'t FolderEntry) -> Folder<'t> {
        let fields = self.fields;
        let mut out = FolderFields::default();
        if fields.has(FolderFieldSet::ID) {
            out.folder_id = Some(folder_id(self.account_id, entry.node, entry.change_id));
        }
        if fields.has(FolderFieldSet::PARENT)
            && let Some(parent) = entry.parent.and_then(|parent| self.tree.get(parent))
        {
            out.parent_folder_id = Some(folder_id(self.account_id, parent.node, parent.change_id));
        }
        if fields.has(FolderFieldSet::CLASS) {
            let class = entry.class.as_str();
            if !class.is_empty() {
                out.folder_class = Some(Cow::Borrowed(class));
            }
        }
        if fields.has(FolderFieldSet::NAME) {
            out.display_name = Some(Cow::Borrowed(&entry.name));
        }
        let kind = FolderVariant::of(entry);
        if fields.needs_counts() {
            let (total, unread) = self.counts.of(entry.node);
            if fields.has(FolderFieldSet::TOTAL) {
                out.total_count = Some(saturating_i32(total));
            }
            if fields.has(FolderFieldSet::UNREAD)
                && matches!(kind, FolderVariant::Folder | FolderVariant::Search)
            {
                out.unread_count = Some(saturating_i32(unread));
            }
        }
        if fields.has(FolderFieldSet::CHILDREN) {
            out.child_folder_count = Some(saturating_i32(self.tree.children(entry.node).count()));
        }
        if fields.has(FolderFieldSet::RIGHTS) {
            out.effective_rights = Some(match self.access {
                ViewRights::Delegate(rights) => delegate_effective_rights(rights.of(entry.node)),
                _ => owner_effective_rights(entry.node),
            });
        }
        if fields.has(FolderFieldSet::DISTINGUISHED) {
            out.distinguished_folder_id = entry.special.and_then(distinguished_of);
        }
        if fields.has(FolderFieldSet::EXTENDED) {
            out.extended_property = Some(Repeated(
                EXTENDED_PROPS
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| fields.has_extended(*index))
                    .filter_map(|(_, (tag, ptype, prop))| {
                        Some(ExtendedProperty {
                            uri: ExtendedFieldUri {
                                target: XPropTarget::Tag(*tag),
                                ptype: *ptype,
                            },
                            value: XPropValue::Single(self.value(entry, *prop)?.to_text()),
                        })
                    })
                    .collect(),
            ))
            .filter(|props| !props.0.is_empty());
        }
        kind.wrap(out)
    }

    pub fn value(&self, entry: &'t FolderEntry, prop: FolderProp) -> Option<PropValue<'t>> {
        Some(match prop {
            FolderProp::DisplayName => PropValue::Text(&entry.name),
            FolderProp::Class => {
                let class = entry.class.as_str();
                if class.is_empty() {
                    return None;
                }
                PropValue::Text(class)
            }
            FolderProp::ChildCount => PropValue::Int(
                i64::try_from(self.tree.children(entry.node).count()).unwrap_or(i64::MAX),
            ),
            FolderProp::Subfolders => {
                PropValue::Bool(self.tree.children(entry.node).next().is_some())
            }
            FolderProp::TotalCount => {
                PropValue::Int(i64::try_from(self.counts.of(entry.node).0).unwrap_or(i64::MAX))
            }
            FolderProp::UnreadCount => {
                PropValue::Int(i64::try_from(self.counts.of(entry.node).1).unwrap_or(i64::MAX))
            }
            FolderProp::CommitTimeMax | FolderProp::LastModified => {
                return change_time(self.counts.change_id(entry));
            }
        })
    }
}

fn owner_effective_rights(node: FolderNode) -> EffectiveRights {
    let writable = Some(matches!(node, FolderNode::Stored(_)));
    EffectiveRights {
        create_associated: writable,
        create_contents: writable,
        create_hierarchy: Some(matches!(
            node,
            FolderNode::Stored(_)
                | FolderNode::Special(
                    SpecialFolder::IpmSubtree | SpecialFolder::Calendar | SpecialFolder::Contacts
                )
        )),
        delete: writable,
        modify: writable,
        read: Some(true),
        view_private_items: Some(true),
    }
}

pub(crate) fn delegate_effective_rights(rights: FolderRights) -> EffectiveRights {
    let owner = Some(rights.contains(FolderRights::FOLDER_OWNER));
    EffectiveRights {
        create_associated: owner,
        create_contents: Some(rights.contains(FolderRights::CREATE)),
        create_hierarchy: Some(rights.contains(FolderRights::CREATE_SUBFOLDER)),
        delete: owner,
        modify: owner,
        read: Some(rights.reads_items()),
        view_private_items: Some(false),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FolderVariant {
    Folder,
    Calendar,
    Contacts,
    Tasks,
    Search,
}

impl FolderVariant {
    fn of(entry: &FolderEntry) -> Self {
        if entry.search {
            return FolderVariant::Search;
        }
        match entry.class {
            ContainerClass::Appointment => FolderVariant::Calendar,
            ContainerClass::Contact => FolderVariant::Contacts,
            ContainerClass::Task => FolderVariant::Tasks,
            _ => FolderVariant::Folder,
        }
    }

    fn wrap(self, fields: FolderFields<'_>) -> Folder<'_> {
        match self {
            FolderVariant::Folder => Folder::Folder(fields),
            FolderVariant::Calendar => Folder::Calendar(fields),
            FolderVariant::Contacts => Folder::Contacts(fields),
            FolderVariant::Tasks => Folder::Tasks(fields),
            FolderVariant::Search => Folder::Search(fields),
        }
    }
}

fn saturating_i32(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/folder/tests.rs"]
mod tests;
