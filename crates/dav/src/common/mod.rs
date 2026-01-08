/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::{VCardParameterName, VCardVersion},
};
use common::auth::AccessToken;
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
    calendar::{
        ArchivedCalendar, ArchivedCalendarEvent, ArchivedCalendarEventNotification, Calendar,
        CalendarEvent, CalendarEventNotification,
    },
    contact::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard},
    file::{ArchivedFileNode, FileNode},
};
use propfind::PropFindItem;
use rkyv::vec::ArchivedVec;
use store::write::{AlignedBytes, Archive, BatchBuilder, Operation, ValueClass, ValueOp};
use types::{
    TimeRange, acl::ArchivedAclGrant, collection::Collection, dead_property::ArchivedDeadProperty,
    field::Field,
};
use uri::{OwnedUri, Urn};

pub mod acl;
pub mod lock;
pub mod propfind;
pub mod uri;

#[derive(Debug)]
pub(crate) struct DavQuery<'x> {
    pub uri: &'x str,
    pub resource: DavQueryResource<'x>,
    pub propfind: PropFind,
    pub sync_type: SyncType,
    pub depth: usize,
    pub limit: Option<u32>,
    pub max_vcard_version: Option<VCardVersion>,
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
        let p_value = u8::from(Field::ARCHIVE);
        for op in self.ops().iter().rev() {
            match op {
                Operation::Value {
                    class: ValueClass::Property(p_id),
                    op: ValueOp::Set(value),
                } if *p_id == p_value => {
                    return Archive::<AlignedBytes>::extract_hash(value)
                        .map(|hash| format!("\"{}\"", hash));
                }
                Operation::Value {
                    class: ValueClass::Property(p_id),
                    op: ValueOp::SetFnc(set_fnc),
                } if *p_id == p_value => {
                    return Archive::<AlignedBytes>::extract_hash(set_fnc.params().bytes(0))
                        .map(|hash| format!("\"{}\"", hash));
                }
                _ => {}
            }
        }

        None
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
            uri: headers.uri,
            max_vcard_version: headers.max_vcard_version,
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
            uri: headers.uri,
            max_vcard_version: headers.max_vcard_version,
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
            uri: headers.uri,
            max_vcard_version: headers.max_vcard_version,
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
            uri: headers.uri,
            sync_type: Default::default(),
            depth: Default::default(),
            limit: Default::default(),
            max_vcard_version: Default::default(),
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
            uri: headers.uri,
            max_vcard_version: headers.max_vcard_version,
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
            uri: headers.uri,
            sync_type: Default::default(),
            limit: Default::default(),
            max_vcard_version: headers.max_vcard_version,
        }
    }

    pub fn is_minimal(&self) -> bool {
        self.ret == Return::Minimal
    }
}

pub(crate) enum ArchivedResource<'x> {
    Calendar(Archive<&'x ArchivedCalendar>),
    CalendarEvent(Archive<&'x ArchivedCalendarEvent>),
    CalendarEventNotification(Archive<&'x ArchivedCalendarEventNotification>),
    CalendarEventNotificationCollection(bool),
    AddressBook(Archive<&'x ArchivedAddressBook>),
    ContactCard(Archive<&'x ArchivedContactCard>),
    FileNode(Archive<&'x ArchivedFileNode>),
}

impl<'x> ArchivedResource<'x> {
    pub fn from_archive(
        archive: &'x Archive<AlignedBytes>,
        collection: Collection,
    ) -> trc::Result<Self> {
        match collection {
            Collection::Calendar => archive
                .to_unarchived::<Calendar>()
                .map(ArchivedResource::Calendar),
            Collection::CalendarEvent => archive
                .to_unarchived::<CalendarEvent>()
                .map(ArchivedResource::CalendarEvent),
            Collection::CalendarEventNotification => archive
                .to_unarchived::<CalendarEventNotification>()
                .map(ArchivedResource::CalendarEventNotification),
            Collection::AddressBook => archive
                .to_unarchived::<AddressBook>()
                .map(ArchivedResource::AddressBook),
            Collection::FileNode => archive
                .to_unarchived::<FileNode>()
                .map(ArchivedResource::FileNode),
            Collection::ContactCard => archive
                .to_unarchived::<ContactCard>()
                .map(ArchivedResource::ContactCard),
            _ => unreachable!(),
        }
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
            ArchivedResource::CalendarEvent(archive) => archive.inner.created.to_native(),
            ArchivedResource::AddressBook(archive) => archive.inner.created.to_native(),
            ArchivedResource::ContactCard(archive) => archive.inner.created.to_native(),
            ArchivedResource::FileNode(archive) => archive.inner.created.to_native(),
            ArchivedResource::CalendarEventNotification(archive) => {
                archive.inner.created.to_native()
            }
            ArchivedResource::CalendarEventNotificationCollection(_) => 1634515200,
        }
    }

    pub fn modified(&self) -> i64 {
        match self {
            ArchivedResource::Calendar(archive) => archive.inner.modified.to_native(),
            ArchivedResource::CalendarEvent(archive) => archive.inner.modified.to_native(),
            ArchivedResource::AddressBook(archive) => archive.inner.modified.to_native(),
            ArchivedResource::ContactCard(archive) => archive.inner.modified.to_native(),
            ArchivedResource::FileNode(archive) => archive.inner.modified.to_native(),
            ArchivedResource::CalendarEventNotification(archive) => {
                archive.inner.modified.to_native()
            }
            ArchivedResource::CalendarEventNotificationCollection(_) => 1634515200,
        }
    }

    pub fn dead_properties(&self) -> Option<&ArchivedDeadProperty> {
        match self {
            ArchivedResource::Calendar(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::CalendarEvent(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::AddressBook(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::ContactCard(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::FileNode(archive) => Some(&archive.inner.dead_properties),
            ArchivedResource::CalendarEventNotification(_)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn content_length(&self) -> Option<u32> {
        match self {
            ArchivedResource::FileNode(archive) => {
                archive.inner.file.as_ref().map(|f| f.size.to_native())
            }
            ArchivedResource::CalendarEvent(archive) => archive.inner.size.to_native().into(),
            ArchivedResource::CalendarEventNotification(archive) => {
                archive.inner.size.to_native().into()
            }
            ArchivedResource::ContactCard(archive) => archive.inner.size.to_native().into(),
            ArchivedResource::AddressBook(_)
            | ArchivedResource::Calendar(_)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn content_type(&self) -> Option<&str> {
        match self {
            ArchivedResource::FileNode(archive) => archive
                .inner
                .file
                .as_ref()
                .and_then(|f| f.media_type.as_deref()),
            ArchivedResource::CalendarEvent(_) | ArchivedResource::CalendarEventNotification(_) => {
                "text/calendar".into()
            }
            ArchivedResource::ContactCard(_) => "text/vcard".into(),
            ArchivedResource::AddressBook(_)
            | ArchivedResource::Calendar(_)
            | ArchivedResource::CalendarEventNotificationCollection(_) => None,
        }
    }

    pub fn display_name(&self, access_token: &AccessToken) -> Option<&str> {
        match self {
            ArchivedResource::Calendar(archive) => {
                Some(archive.inner.preferences(access_token).name.as_str())
            }
            ArchivedResource::CalendarEvent(archive) => archive.inner.display_name.as_deref(),
            ArchivedResource::AddressBook(archive) => {
                Some(archive.inner.preferences(access_token).name.as_str())
            }
            ArchivedResource::ContactCard(archive) => archive.inner.display_name.as_deref(),
            ArchivedResource::FileNode(archive) => archive.inner.display_name.as_deref(),
            ArchivedResource::CalendarEventNotification(_)
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
            ArchivedResource::FileNode(archive) if archive.inner.file.is_none() => vec![
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
            ArchivedResource::FileNode(archive) if archive.inner.file.is_none() => {
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
