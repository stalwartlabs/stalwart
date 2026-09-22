/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::{VCardParameterName, VCardVersion},
};
use dav_proto::{
    Depth, RequestHeaders, Return,
    schema::{
        Namespace,
        property::{DavProperty, ReportSet, ResourceType},
        request::{
            AddressbookQuery, CalendarQuery, ExpandProperty, Filter, MultiGet, PropFind,
            SyncCollection, Timezone, VCardPropertyWithGroup,
        },
    },
};
use groupware::{
    SizeWriter,
    calendar::{
        ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarEventContent,
        ArchivedCalendarEventNotification, ArchivedCalendarEventNotificationContent, Calendar,
        CalendarEvent, CalendarEventContent, CalendarEventNotification,
        CalendarEventNotificationContent,
    },
    contact::{
        AddressBook, ArchivedAddressBook, ArchivedContactCard, ArchivedContactCardContent,
        ContactCard, ContactCardContent,
    },
    file::{ArchivedFileNode, FileNode},
};
use hyper::StatusCode;
use propfind::PropFindItem;
use rkyv::vec::ArchivedVec;
use store::write::{Archive, ArchiveBytes, AssignedIds, BatchBuilder};
use types::{
    TimeRange,
    acl::{Acl, ArchivedAclGrant},
    collection::Collection,
    dead_property::ArchivedDeadProperty,
};
use uri::{OwnedUri, Urn};

pub mod acl;
pub mod lock;
pub mod propfind;
pub mod uri;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContainerOperation {
    Copy,
    Remove,
}

impl ContainerOperation {
    pub(crate) fn from_move(is_move: bool) -> Self {
        if is_move {
            ContainerOperation::Remove
        } else {
            ContainerOperation::Copy
        }
    }

    pub(crate) fn required_acls(self) -> impl Iterator<Item = Acl> {
        let acls: &'static [Acl] = match self {
            ContainerOperation::Copy => &[Acl::ReadItems],
            ContainerOperation::Remove => &[Acl::Delete],
        };
        acls.iter().copied()
    }
}

pub(crate) fn assert_parent_limit(
    prev_count: usize,
    count: usize,
    max: usize,
) -> crate::Result<()> {
    if count <= max || count <= prev_count {
        Ok(())
    } else {
        Err(crate::DavError::Code(StatusCode::FORBIDDEN))
    }
}

#[derive(Debug)]
pub(crate) struct DavQuery<'x> {
    pub uri: &'x str,
    pub resource: DavQueryResource<'x>,
    pub propfind: PropFind,
    pub sync_type: SyncType,
    pub depth: usize,
    pub limit: Option<u32>,
    pub vcard_version: Option<VCardVersion>,
    pub ret: Return,
    pub depth_no_root: bool,
    pub expand: bool,
}

#[derive(Default, Debug)]
pub(crate) enum SyncType {
    #[default]
    None,
    Initial,
    From {
        id: u64,
        seq: u32,
    },
}

#[derive(Default, Debug)]
pub(crate) enum DavQueryResource<'x> {
    Uri(OwnedUri<'x>),
    Multiget {
        parent_collection: Collection,
        hrefs: Vec<String>,
    },
    Query {
        filter: DavQueryFilter,
        parent_collection: Collection,
        items: Vec<PropFindItem>,
    },
    #[default]
    None,
}

pub(crate) type AddressbookFilter = Vec<Filter<(), VCardPropertyWithGroup, VCardParameterName>>;
pub(crate) type CalendarFilter =
    Vec<Filter<Vec<ICalendarComponentType>, ICalendarProperty, ICalendarParameterName>>;

#[derive(Debug)]
pub(crate) enum DavQueryFilter {
    Addressbook(AddressbookFilter),
    Calendar {
        filter: CalendarFilter,
        max_time_range: Option<TimeRange>,
        timezone: Timezone,
    },
}

pub(crate) trait ETag {
    fn etag(&self) -> String;
}

pub(crate) trait ExtractETag {
    fn etag(&self) -> Option<String>;
}

impl<T> ETag for Archive<T> {
    fn etag(&self) -> String {
        format!("\"{}\"", self.version.hash().unwrap_or_default())
    }
}

impl ExtractETag for BatchBuilder {
    fn etag(&self) -> Option<String> {
        self.last_archive_hash().map(|hash| format!("\"{}\"", hash))
    }
}

impl ExtractETag for AssignedIds {
    fn etag(&self) -> Option<String> {
        self.last_archive_hash().map(|hash| format!("\"{}\"", hash))
    }
}

pub(crate) trait DavCollection {
    fn namespace(&self) -> Namespace;
}

impl DavCollection for Collection {
    fn namespace(&self) -> Namespace {
        match self {
            Collection::Calendar
            | Collection::CalendarEvent
            | Collection::CalendarEventNotification => Namespace::CalDav,
            Collection::AddressBook | Collection::ContactCard => Namespace::CardDav,
            _ => Namespace::Dav,
        }
    }
}

impl<'x> DavQuery<'x> {
    pub fn propfind(
        resource: OwnedUri<'x>,
        propfind: PropFind,
        headers: &RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource: DavQueryResource::Uri(resource),
            propfind,
            depth: match headers.depth {
                Depth::Zero => 0,
                _ => 1,
            },
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
            uri: headers.raw_uri,
            vcard_version: headers.vcard_version,
            sync_type: Default::default(),
            limit: Default::default(),
            expand: Default::default(),
        }
    }

    pub fn multiget(
        multiget: MultiGet,
        collection: Collection,
        headers: &RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource: DavQueryResource::Multiget {
                hrefs: multiget.hrefs,
                parent_collection: collection,
            },
            propfind: multiget.properties,
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
            uri: headers.raw_uri,
            vcard_version: headers.vcard_version,
            sync_type: Default::default(),
            depth: Default::default(),
            limit: Default::default(),
            expand: Default::default(),
        }
    }

    pub fn addressbook_query(
        query: AddressbookQuery,
        items: Vec<PropFindItem>,
        headers: &RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource: DavQueryResource::Query {
                filter: DavQueryFilter::Addressbook(query.filters),
                parent_collection: Collection::AddressBook,
                items,
            },
            propfind: query.properties,
            limit: query.limit,
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
            uri: headers.raw_uri,
            vcard_version: headers.vcard_version,
            sync_type: Default::default(),
            depth: Default::default(),
            expand: Default::default(),
        }
    }

    pub fn calendar_query(
        query: CalendarQuery,
        max_time_range: Option<TimeRange>,
        items: Vec<PropFindItem>,
        headers: &RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource: DavQueryResource::Query {
                filter: DavQueryFilter::Calendar {
                    filter: query.filters,
                    timezone: query.timezone,
                    max_time_range,
                },
                parent_collection: Collection::Calendar,
                items,
            },
            propfind: query.properties,
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
            uri: headers.raw_uri,
            sync_type: Default::default(),
            depth: Default::default(),
            limit: Default::default(),
            vcard_version: Default::default(),
            expand: Default::default(),
        }
    }

    pub fn changes(
        resource: OwnedUri<'x>,
        changes: SyncCollection,
        headers: &RequestHeaders<'x>,
    ) -> Self {
        Self {
            resource: DavQueryResource::Uri(resource),
            propfind: changes.properties,
            sync_type: changes
                .sync_token
                .as_deref()
                .and_then(Urn::parse)
                .and_then(|urn| urn.try_unwrap_sync())
                .map(|(id, seq)| SyncType::From { id, seq })
                .unwrap_or(SyncType::Initial),
            depth: match changes.depth {
                Depth::One => 1,
                Depth::Infinity => usize::MAX,
                _ => 0,
            },
            limit: changes.limit,
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
            expand: false,
            uri: headers.raw_uri,
            vcard_version: headers.vcard_version,
        }
    }

    pub fn expand(
        resource: OwnedUri<'x>,
        expand: ExpandProperty,
        headers: &RequestHeaders<'x>,
    ) -> Self {
        let mut props = Vec::with_capacity(expand.properties.len());
        for item in expand.properties {
            if !matches!(item.property, DavProperty::DeadProperty(_))
                && !props.contains(&item.property)
            {
                props.push(item.property);
            }
        }

        Self {
            resource: DavQueryResource::Uri(resource),
            propfind: PropFind::Prop(props),
            depth: match headers.depth {
                Depth::Zero => 0,
                _ => 1,
            },
            ret: headers.ret,
            depth_no_root: headers.depth_no_root,
            expand: true,
            uri: headers.raw_uri,
            sync_type: Default::default(),
            limit: Default::default(),
            vcard_version: headers.vcard_version,
        }
    }

    pub fn is_minimal(&self) -> bool {
        self.ret == Return::Minimal
    }
}

pub(crate) enum ArchivedResource<'x> {
    Calendar(Archive<&'x ArchivedCalendar>),
    CalendarEvent(Archive<&'x ArchivedCalendarEvent>, Option<EventContent<'x>>),
    CalendarEventNotification(
        Archive<&'x ArchivedCalendarEventNotification>,
        Option<&'x ArchivedCalendarEventNotificationContent>,
    ),
    CalendarEventNotificationCollection(bool),
    AddressBook(Archive<&'x ArchivedAddressBook>),
    ContactCard(
        Archive<&'x ArchivedContactCard>,
        Option<&'x ArchivedContactCardContent>,
    ),
    FileNode(Archive<&'x ArchivedFileNode>),
}

pub(crate) enum EventContent<'x> {
    Stored(&'x ArchivedCalendarEventContent),
    View {
        stored: &'x ArchivedCalendarEventContent,
        view: CalendarEventContent,
        merged_overrides: MergedOverrides,
    },
}

#[derive(Debug, Default)]
pub(crate) struct MergedOverrides {
    base_id: Option<u32>,
    ids: Vec<u32>,
}

impl MergedOverrides {
    pub fn push(&mut self, component_id: u32) {
        self.ids.push(component_id);
    }

    pub fn set_base(&mut self, base_id: Option<u32>) {
        self.base_id = base_id;
        self.ids.sort_unstable();
    }

    pub fn base_of(&self, component_id: u32) -> Option<u32> {
        self.base_id
            .filter(|_| self.ids.binary_search(&component_id).is_ok())
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty() || self.base_id.is_none()
    }
}

impl<'x> EventContent<'x> {
    pub fn attach_view(&mut self, view: CalendarEventContent, merged_overrides: MergedOverrides) {
        *self = EventContent::View {
            stored: self.stored(),
            view,
            merged_overrides,
        };
    }

    pub fn stored(&self) -> &'x ArchivedCalendarEventContent {
        match self {
            EventContent::Stored(stored) | EventContent::View { stored, .. } => stored,
        }
    }

    pub fn view(&self) -> Option<&CalendarEventContent> {
        match self {
            EventContent::Stored(_) => None,
            EventContent::View { view, .. } => Some(view),
        }
    }

    pub fn merged_overrides(&self) -> Option<&MergedOverrides> {
        match self {
            EventContent::Stored(_) => None,
            EventContent::View {
                merged_overrides, ..
            } => Some(merged_overrides),
        }
    }

    pub fn to_ical_string(&self) -> String {
        match self {
            EventContent::Stored(stored) => stored.data.event.to_string(),
            EventContent::View { view, .. } => view.data.event.to_string(),
        }
    }
}

impl<'x> ArchivedResource<'x> {
    pub fn from_archive(
        archive: &'x Archive<ArchiveBytes>,
        content: Option<&'x Archive<ArchiveBytes>>,
        collection: Collection,
    ) -> trc::Result<Self> {
        match collection {
            Collection::Calendar => archive
                .to_unarchived::<Calendar>()
                .map(ArchivedResource::Calendar),
            Collection::CalendarEvent => {
                let content = content
                    .map(|content| content.unarchive::<CalendarEventContent>())
                    .transpose()?
                    .map(EventContent::Stored);
                archive
                    .to_unarchived::<CalendarEvent>()
                    .map(|meta| ArchivedResource::CalendarEvent(meta, content))
            }
            Collection::CalendarEventNotification => {
                let content = content
                    .map(|content| content.unarchive::<CalendarEventNotificationContent>())
                    .transpose()?;
                archive
                    .to_unarchived::<CalendarEventNotification>()
                    .map(|meta| ArchivedResource::CalendarEventNotification(meta, content))
            }
            Collection::AddressBook => archive
                .to_unarchived::<AddressBook>()
                .map(ArchivedResource::AddressBook),
            Collection::FileNode => archive
                .to_unarchived::<FileNode>()
                .map(ArchivedResource::FileNode),
            Collection::ContactCard => {
                let content = content
                    .map(|content| content.unarchive::<ContactCardContent>())
                    .transpose()?;
                archive
                    .to_unarchived::<ContactCard>()
                    .map(|meta| ArchivedResource::ContactCard(meta, content))
            }
            _ => unreachable!(),
        }
    }

    pub fn etag(&self) -> String {
        let hash = match self {
            ArchivedResource::CalendarEvent(archive, _) => archive.inner.etag.to_native(),
            ArchivedResource::ContactCard(archive, _) => archive.inner.etag.to_native(),
            ArchivedResource::CalendarEventNotification(archive, _) => {
                archive.inner.etag.to_native()
            }
            ArchivedResource::Calendar(archive) => archive.version.hash().unwrap_or_default(),
            ArchivedResource::AddressBook(archive) => archive.version.hash().unwrap_or_default(),
            ArchivedResource::FileNode(archive) => archive.version.hash().unwrap_or_default(),
            ArchivedResource::CalendarEventNotificationCollection(_) => 0,
        };

        format!("\"{hash}\"")
    }

    pub fn acls(&self) -> Option<&ArchivedVec<ArchivedAclGrant>> {
        match self {
            Self::Calendar(archive) => Some(&archive.inner.acls),
            Self::AddressBook(archive) => Some(&archive.inner.acls),
            Self::FileNode(archive) => Some(&archive.inner.acls),
            _ => None,
        }
    }

    pub fn created(&self) -> i64 {
        match self {
            ArchivedResource::Calendar(archive) => archive.inner.created.to_native(),
            ArchivedResource::CalendarEvent(archive, _) => archive.inner.created.to_native(),
            ArchivedResource::AddressBook(archive) => archive.inner.created.to_native(),
            ArchivedResource::ContactCard(archive, _) => archive.inner.created.to_native(),
            ArchivedResource::FileNode(archive) => archive.inner.created.to_native(),
            ArchivedResource::CalendarEventNotification(archive, _) => {
                archive.inner.created.to_native()
            }
            ArchivedResource::CalendarEventNotificationCollection(_) => 1634515200,
        }
    }

    pub fn modified(&self) -> i64 {
        match self {
            ArchivedResource::Calendar(archive) => archive.inner.modified.to_native(),
            ArchivedResource::CalendarEvent(archive, _) => archive.inner.modified.to_native(),
            ArchivedResource::AddressBook(archive) => archive.inner.modified.to_native(),
            ArchivedResource::ContactCard(archive, _) => archive.inner.modified.to_native(),
            ArchivedResource::FileNode(archive) => archive.inner.modified.to_native(),
            ArchivedResource::CalendarEventNotification(archive, _) => {
                archive.inner.modified.to_native()
            }
            ArchivedResource::CalendarEventNotificationCollection(_) => 1634515200,
        }
    }

    pub fn dead_properties(&self) -> Option<&ArchivedDeadProperty> {
        match self {
            ArchivedResource::Calendar(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::CalendarEvent(_, content) => content
                .as_ref()
                .map(|content| &content.stored().dead_properties),
            ArchivedResource::AddressBook(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::ContactCard(_, content) => {
                content.map(|content| &content.dead_properties)
            }
            ArchivedResource::FileNode(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::CalendarEventNotification(..)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn content_length(&self) -> Option<u32> {
        match self {
            ArchivedResource::FileNode(archive) => archive.inner.file().map(|f| f.size.to_native()),
            ArchivedResource::CalendarEvent(archive, content) => content
                .as_ref()
                .and_then(EventContent::view)
                .map(|view| SizeWriter::ical(&view.data.event) as u32)
                .or_else(|| archive.inner.size.to_native().into()),
            ArchivedResource::CalendarEventNotification(archive, _) => {
                archive.inner.size.to_native().into()
            }
            ArchivedResource::ContactCard(archive, _) => archive.inner.size.to_native().into(),
            ArchivedResource::AddressBook(_)
            | ArchivedResource::Calendar(_)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn content_type(&self) -> Option<&str> {
        match self {
            ArchivedResource::FileNode(archive) => {
                archive.inner.file().and_then(|f| f.media_type.as_deref())
            }
            ArchivedResource::CalendarEvent(..)
            | ArchivedResource::CalendarEventNotification(..) => "text/calendar".into(),
            ArchivedResource::ContactCard(..) => "text/vcard".into(),
            ArchivedResource::AddressBook(_)
            | ArchivedResource::Calendar(_)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn display_name(&self, account_id: u32) -> Option<&str> {
        match self {
            ArchivedResource::Calendar(archive) => archive
                .inner
                .preferences(account_id)
                .map(|preferences| preferences.name.as_str()),
            ArchivedResource::CalendarEvent(archive, _) => archive.inner.display_name.as_deref(),
            ArchivedResource::AddressBook(archive) => {
                Some(archive.inner.preferences(account_id).name.as_str())
            }
            ArchivedResource::ContactCard(archive, _) => archive.inner.display_name.as_deref(),
            ArchivedResource::FileNode(archive) => archive.inner.display_name.as_deref(),
            ArchivedResource::CalendarEventNotification(..)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn supported_report_set(&self) -> Option<Vec<ReportSet>> {
        match self {
            ArchivedResource::Calendar(_) => vec![
                ReportSet::SyncCollection,
                ReportSet::AclPrincipalPropSet,
                ReportSet::PrincipalMatch,
                ReportSet::ExpandProperty,
                ReportSet::CalendarQuery,
                ReportSet::CalendarMultiGet,
                ReportSet::FreeBusyQuery,
            ]
            .into(),
            ArchivedResource::AddressBook(_) => vec![
                ReportSet::SyncCollection,
                ReportSet::AclPrincipalPropSet,
                ReportSet::PrincipalMatch,
                ReportSet::ExpandProperty,
                ReportSet::AddressbookQuery,
                ReportSet::AddressbookMultiGet,
            ]
            .into(),
            ArchivedResource::FileNode(archive) if archive.inner.is_directory() => vec![
                ReportSet::SyncCollection,
                ReportSet::AclPrincipalPropSet,
                ReportSet::PrincipalMatch,
            ]
            .into(),
            ArchivedResource::CalendarEventNotificationCollection(_) => vec![
                ReportSet::SyncCollection,
                ReportSet::CalendarQuery,
                ReportSet::CalendarMultiGet,
            ]
            .into(),
            _ => None,
        }
    }

    pub fn resource_type(&self) -> Option<Vec<ResourceType>> {
        match self {
            ArchivedResource::Calendar(_) => {
                vec![ResourceType::Collection, ResourceType::Calendar].into()
            }
            ArchivedResource::AddressBook(_) => {
                vec![ResourceType::Collection, ResourceType::AddressBook].into()
            }
            ArchivedResource::FileNode(archive) if archive.inner.is_directory() => {
                vec![ResourceType::Collection].into()
            }
            ArchivedResource::CalendarEventNotificationCollection(true) => {
                vec![ResourceType::Collection, ResourceType::ScheduleInbox].into()
            }
            ArchivedResource::CalendarEventNotificationCollection(false) => {
                vec![ResourceType::Collection, ResourceType::ScheduleOutbox].into()
            }
            _ => None,
        }
    }
}

impl SyncType {
    pub fn is_none(&self) -> bool {
        matches!(self, SyncType::None)
    }

    pub fn is_none_or_initial(&self) -> bool {
        matches!(self, SyncType::None | SyncType::Initial)
    }
}
