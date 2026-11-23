/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod find;
pub mod items;
pub mod write;

use super::{
    filter::{Filter, FilterProp, PropValue, UnsupportedFilter},
    item::find::{SortKey, sort_key},
};
use crate::{contact_group::is_archived_group, store::FolderKind};
use bytes::Bytes;
use calcard::{icalendar::ICalendar, vcard::VCard};
use common::Server;
use exchange_proto::{
    convert::{
        ConvertError,
        context::{ConvertOptions, NoDirectory},
        ical::{
            EventOccurrences, EventParts, event_mime_text, event_occurrences,
            event_parts_to_message, task_to_message,
        },
        model::{MessageContent, PropBag},
        vcard::{contact_to_message, distlist_to_message, is_contact_group},
    },
    ews::{
        Status,
        requests::find::FindItem,
        schema::{ItemQueryTraversal, ResponseCode, SortDirection},
        types::{item::Item, restriction::Restriction, shape::ItemShape, view::FieldOrder},
    },
    ids::token::ObjectKind,
};
use groupware::{
    calendar::{
        CalendarEventContent,
        privacy::{EventPrivacy, ICalendarPrivacy},
    },
    contact::ContactCardContent,
};
use items::{GroupwareItems, LoadedItem};
use smallvec::SmallVec;
use std::cmp::Ordering;
use store::{
    dispatch::ReadShape,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, ArchiveVersion},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, ContactField, Field},
    type_state::DataType,
};

const GROUP_BY_UNSUPPORTED: &str = "GroupBy is not supported.";
const SORT_UNSUPPORTED: &str = "The property cannot be used for sorting.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupwareKind {
    Contact,
    Task,
    Event,
}

pub(crate) trait GroupwareFields: Copy + Send + Sync {
    const KIND: GroupwareKind;
    type Prop: FilterProp + Send + Sync;

    fn from_shape(shape: &ItemShape<'_>) -> Self;
    fn for_list(self) -> Self;
    fn needs_content(self) -> bool;
    fn needs_owner(self) -> bool {
        false
    }
    fn needs_kind(self) -> bool {
        false
    }
    fn event_parts(self) -> EventParts {
        EventParts::ALL | EventParts::NO_DATA
    }
    fn value<'p>(
        items: &GroupwareItems<Self>,
        document_id: u32,
        prop: Self::Prop,
        props: &'p PropBag,
    ) -> Option<PropValue<'p>>;
    fn render<'c>(self, items: &GroupwareItems<Self>, loaded: &'c LoadedItem) -> Item<'c>;
}

impl GroupwareKind {
    pub fn of_object(kind: ObjectKind) -> Option<Self> {
        match kind {
            ObjectKind::Contact => Some(GroupwareKind::Contact),
            ObjectKind::Task => Some(GroupwareKind::Task),
            ObjectKind::Event => Some(GroupwareKind::Event),
            _ => None,
        }
    }

    pub const fn object_kind(self) -> ObjectKind {
        match self {
            GroupwareKind::Contact => ObjectKind::Contact,
            GroupwareKind::Task => ObjectKind::Task,
            GroupwareKind::Event => ObjectKind::Event,
        }
    }

    pub const fn sync_collection(self) -> SyncCollection {
        match self {
            GroupwareKind::Contact => SyncCollection::AddressBook,
            GroupwareKind::Task | GroupwareKind::Event => SyncCollection::Calendar,
        }
    }

    const fn data_types(self) -> [DataType; 2] {
        match self {
            GroupwareKind::Contact => [DataType::ContactCard, DataType::AddressBook],
            GroupwareKind::Task | GroupwareKind::Event => {
                [DataType::CalendarEvent, DataType::Calendar]
            }
        }
    }

    const fn collection(self) -> Collection {
        match self {
            GroupwareKind::Contact => Collection::ContactCard,
            GroupwareKind::Task | GroupwareKind::Event => Collection::CalendarEvent,
        }
    }

    fn content(self) -> Field {
        match self {
            GroupwareKind::Contact => ContactField::Content.into(),
            GroupwareKind::Task | GroupwareKind::Event => CalendarEventField::Content.into(),
        }
    }

    const fn folder_kind(self) -> FolderKind {
        match self {
            GroupwareKind::Contact => FolderKind::AddressBook,
            GroupwareKind::Task | GroupwareKind::Event => FolderKind::Calendar,
        }
    }

    fn convert(
        self,
        content: &Archive<ArchiveBytes>,
        view: EventView,
        parts: EventParts,
        options: &ConvertOptions<'_>,
    ) -> Option<Converted> {
        let converted = match self {
            GroupwareKind::Contact => content
                .deserialize::<ContactCardContent>()
                .map(|content| contact_content(&content.card, options).map(Converted::plain)),
            GroupwareKind::Task => content
                .deserialize::<CalendarEventContent>()
                .map(|content| view.apply(content.data.event))
                .map(|ical| task_to_message(&ical, options).map(Converted::plain)),
            GroupwareKind::Event => content
                .deserialize::<CalendarEventContent>()
                .map(|content| view.apply(content.data.event))
                .map(|event| {
                    let ical = &event;
                    event_parts_to_message(ical, None, parts, &NoDirectory, options).map(
                        |message| Converted {
                            content: message,
                            occurrences: parts
                                .has(EventParts::OCCURRENCES)
                                .then(|| {
                                    event_occurrences(ical, parts.occurrence_bounds()).map(Box::new)
                                })
                                .flatten(),
                            mime: parts
                                .has(EventParts::MIME)
                                .then(|| Bytes::from(event_mime_text(ical))),
                        },
                    )
                }),
        };
        match converted {
            Ok(message) => message.ok(),
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                None
            }
        }
    }
}

impl GroupwareKind {
    fn kind_only(self, content: &Archive<ArchiveBytes>) -> Option<MessageContent> {
        let converted = match self {
            GroupwareKind::Contact => content.unarchive::<ContactCardContent>().and_then(|card| {
                if is_archived_group(&card.card) {
                    content
                        .deserialize::<ContactCardContent>()
                        .map(|content| distlist_to_message(&content.card, None).ok())
                } else {
                    Ok(None)
                }
            }),
            GroupwareKind::Task | GroupwareKind::Event => Ok(None),
        };
        converted.unwrap_or_else(|err| {
            trc::error!(err.caused_by(trc::location!()));
            None
        })
    }
}

pub(crate) fn contact_content(
    card: &VCard,
    options: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    if is_contact_group(card) {
        distlist_to_message(card, None)
    } else {
        contact_to_message(card, options)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventView {
    Full,
    Private,
}

impl EventView {
    pub fn of(privacy: EventPrivacy) -> Self {
        match privacy {
            EventPrivacy::Public => EventView::Full,
            EventPrivacy::Private | EventPrivacy::Secret => EventView::Private,
        }
    }

    pub fn apply(self, event: ICalendar) -> ICalendar {
        match self {
            EventView::Full => event,
            EventView::Private => event.into_private_view(),
        }
    }
}

pub(crate) struct Converted {
    pub content: MessageContent,
    pub occurrences: Option<Box<EventOccurrences>>,
    pub mime: Option<Bytes>,
}

impl Converted {
    fn plain(content: MessageContent) -> Self {
        Converted {
            content,
            occurrences: None,
            mime: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct VersionedArchives {
    versions: Vec<(u32, u64)>,
    contents: Vec<(u32, Archive<ArchiveBytes>)>,
}

impl VersionedArchives {
    pub async fn read(
        server: &Server,
        account_id: u32,
        collection: Collection,
        content: Field,
        documents: &RoaringBitmap,
        with_content: bool,
    ) -> trc::Result<Self> {
        let len = usize::try_from(documents.len()).unwrap_or_default();
        let mut archives = VersionedArchives {
            versions: Vec::with_capacity(len),
            contents: Vec::new(),
        };
        if with_content {
            archives.contents.reserve(len);
            server
                .archives_fields(
                    account_id,
                    collection,
                    ReadShape::Keys,
                    &[(content, documents), (Field::ARCHIVE, documents)],
                    |field, document_id, archive| {
                        if field == Field::ARCHIVE {
                            archives
                                .versions
                                .push((document_id, change_id_of(archive.version)));
                        } else {
                            archives.contents.push((document_id, archive));
                        }
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        } else {
            server
                .archives(
                    account_id,
                    collection,
                    Field::ARCHIVE,
                    documents,
                    |document_id, archive| {
                        archives
                            .versions
                            .push((document_id, change_id_of(archive.version)));
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
        archives
            .versions
            .sort_unstable_by_key(|(document_id, _)| *document_id);
        archives
            .contents
            .sort_unstable_by_key(|(document_id, _)| *document_id);
        Ok(archives)
    }

    pub fn change_id(&self, document_id: u32) -> Option<u64> {
        self.versions
            .binary_search_by_key(&document_id, |(document_id, _)| *document_id)
            .ok()
            .and_then(|position| self.versions.get(position))
            .map(|(_, change_id)| *change_id)
    }

    pub fn content(&self, document_id: u32) -> Option<&Archive<ArchiveBytes>> {
        self.contents
            .binary_search_by_key(&document_id, |(document_id, _)| *document_id)
            .ok()
            .and_then(|position| self.contents.get(position))
            .map(|(_, content)| content)
    }
}

pub(crate) fn change_id_of(version: ArchiveVersion) -> u64 {
    match version {
        ArchiveVersion::Versioned { change_id, .. } => change_id,
        _ => 0,
    }
}

pub(crate) enum Selection<'r, 'a, P> {
    Invalid(Status<'static>),
    Empty,
    Members,
    Scan(FindPlan<'r, 'a, P>),
}

pub(crate) struct FindPlan<'r, 'a, P> {
    filter: Option<Filter<'r, 'a, P>>,
    order: SmallVec<[(P, SortDirection); 2]>,
}

pub(crate) struct Candidate<R> {
    pub item: R,
    document_id: u32,
    keys: SmallVec<[SortKey; 2]>,
}

impl<'r, 'a, P: FilterProp> Selection<'r, 'a, P> {
    pub fn new(request: &'r FindItem<'a>) -> Self {
        if request.group_by.is_some() {
            return Selection::Invalid(Status::error(
                ResponseCode::ErrorInvalidOperation,
                GROUP_BY_UNSUPPORTED,
            ));
        }
        if request.traversal != ItemQueryTraversal::Shallow {
            return Selection::Empty;
        }
        match FindPlan::new(request.restriction.as_ref(), request.sort_order.as_deref()) {
            Ok(plan) if plan.filter.is_none() && plan.order.is_empty() => Selection::Members,
            Ok(plan) => Selection::Scan(plan),
            Err(unsupported) => Selection::Invalid(unsupported.status()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsupportedPlan {
    Filter(UnsupportedFilter),
    Sort,
}

impl UnsupportedPlan {
    pub fn status(self) -> Status<'static> {
        match self {
            UnsupportedPlan::Filter(unsupported) => unsupported.status(),
            UnsupportedPlan::Sort => Status::error(
                ResponseCode::ErrorUnsupportedPathForSortGroup,
                SORT_UNSUPPORTED,
            ),
        }
    }
}

impl<'r, 'a, P: FilterProp> FindPlan<'r, 'a, P> {
    pub fn new(
        restriction: Option<&'r Restriction<'a>>,
        sort_order: Option<&[FieldOrder<'_>]>,
    ) -> Result<Self, UnsupportedPlan> {
        let filter = restriction
            .map(Filter::<P>::new)
            .transpose()
            .map_err(UnsupportedPlan::Filter)?;
        let mut order = SmallVec::new();
        for field in sort_order.into_iter().flatten() {
            let prop = P::of_path(&field.path).ok_or(UnsupportedPlan::Sort)?;
            order.push((prop, field.order));
        }
        Ok(FindPlan { filter, order })
    }
}

impl<P: FilterProp> FindPlan<'_, '_, P> {
    pub fn candidate<'t, R>(
        &self,
        item: R,
        document_id: u32,
        value: impl Fn(P) -> Option<PropValue<'t>>,
    ) -> Option<Candidate<R>> {
        self.filter
            .as_ref()
            .is_none_or(|filter| filter.matches(&value))
            .then(|| Candidate {
                item,
                document_id,
                keys: self
                    .order
                    .iter()
                    .map(|(prop, _)| sort_key(value(*prop)))
                    .collect(),
            })
    }

    pub fn sort<R>(&self, candidates: &mut [Candidate<R>]) {
        candidates.sort_unstable_by(|a, b| {
            a.keys
                .iter()
                .zip(&b.keys)
                .zip(&self.order)
                .map(|((a, b), (_, direction))| match direction {
                    SortDirection::Ascending => a.cmp(b),
                    SortDirection::Descending => b.cmp(a),
                })
                .find(|ordering| ordering.is_ne())
                .unwrap_or(Ordering::Equal)
                .then(a.document_id.cmp(&b.document_id))
        });
    }
}
