/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EMPTY_COLLECTION_KEY, Fetched, Job, JobResult, KeyInput, KeyState, LOAD_CONCURRENCY, OutItem,
    ResponseBudget,
    changes::{ItemEntry, ServerChanges, ServerItem},
    email::ItemReply,
    empty_collection,
    estimate::FolderProbe,
    filter_cutoff,
    groupware_write::GroupwareWriter,
    initial_key, missing_reply, resolve_key, server_id,
    state::{ClientView, CollectionOptions, SupportedFields},
    window_size, write_folder,
};
use crate::{
    eas::{
        context::{EasContext, EasDataKind},
        convert::{body::BodyChoice, email::NATIVE_PLAIN},
    },
    folders::{ContainerClass, ExchangeFolders, FolderNode, FolderTree, FolderWrites},
    identity::org_dn,
    store::{
        FolderKind, FolderRef,
        eas::{EasFolderState, EasStore},
    },
};
use calcard::{
    icalendar::{ICalendar, ICalendarComponentType},
    vcard::{VCard, VCardProperty, VCardValue},
};
use common::{GroupwareResources, Server};
use exchange_proto::{
    convert::{
        context::{BodyPreference, ConvertOptions, TnefPolicy},
        ical::eas::{
            event_to_eas, is_event_convertible, is_todo_complete, is_todo_convertible, todo_to_eas,
        },
        vcard::eas::contact_to_eas,
    },
    eas::{
        commands::{
            appdata::{ApplicationData, contact::Contact},
            sync::{ClientCommand, Ghosting, SyncOptions, options::FILTER_INCOMPLETE_TASKS},
        },
        status::SyncStatus,
        tokens::ProtocolVersion,
        types::Class,
    },
    ids::{
        eas::{EasServerId, EasSyncKey},
        essdn::OrgDn,
    },
};
use futures::{StreamExt, TryStreamExt, stream};
use groupware::{
    cache::GroupwareCache, calendar::CalendarEventContent, contact::ContactCardContent,
};
use smallvec::SmallVec;
use std::borrow::Cow;
use store::{
    Store, ValueKey,
    query::log::{Change, Query},
    rand::{self, RngExt},
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, ContactField},
    type_state::DataType,
};
use utils::map::bitmap::Bitmap;

const MAX_DECODED_CARD: u32 = 1 << 20;
const CONFLICT_CLIENT_WINS: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupwareKind {
    Calendar,
    Tasks,
    Contacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemScope {
    All,
    IncompleteTasks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupwareTarget {
    pub kind: GroupwareKind,
    pub container_id: u32,
}

pub struct GroupwareProbe {
    target: GroupwareTarget,
    probe: FolderProbe,
    changed: RoaringBitmap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hierarchy {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LogCursor {
    seen: Option<u64>,
    scanned: Option<u64>,
}

#[derive(Default)]
pub struct GroupwareProbes {
    probes: Vec<GroupwareProbe>,
    calendar: LogCursor,
    contacts: LogCursor,
}

pub struct GroupwareItem {
    pub document_id: u32,
    pub size: u32,
    kind: GroupwareKind,
    content: ItemContent,
    body: BodyChoice,
}

enum ItemContent {
    Event(Box<ICalendar>),
    Card(Box<VCard>),
}

pub struct RenderContext {
    pub addresses: Box<[String]>,
    pub name: Box<str>,
    pub org: OrgDn,
    pub version: ProtocolVersion,
}

impl GroupwareKind {
    pub fn from_class(class: &ContainerClass) -> Option<Self> {
        match class {
            ContainerClass::Appointment => Some(GroupwareKind::Calendar),
            ContainerClass::Task => Some(GroupwareKind::Tasks),
            ContainerClass::Contact => Some(GroupwareKind::Contacts),
            _ => None,
        }
    }

    pub fn class(self) -> Class {
        match self {
            GroupwareKind::Calendar => Class::Calendar,
            GroupwareKind::Tasks => Class::Tasks,
            GroupwareKind::Contacts => Class::Contacts,
        }
    }

    pub fn data_kind(self) -> EasDataKind {
        match self {
            GroupwareKind::Calendar | GroupwareKind::Tasks => EasDataKind::Calendar,
            GroupwareKind::Contacts => EasDataKind::Contacts,
        }
    }

    pub fn collection(self) -> SyncCollection {
        match self {
            GroupwareKind::Calendar | GroupwareKind::Tasks => SyncCollection::Calendar,
            GroupwareKind::Contacts => SyncCollection::AddressBook,
        }
    }

    fn component(self) -> Option<ICalendarComponentType> {
        match self {
            GroupwareKind::Calendar => Some(ICalendarComponentType::VEvent),
            GroupwareKind::Tasks => Some(ICalendarComponentType::VTodo),
            GroupwareKind::Contacts => None,
        }
    }

    pub(super) fn shows(self, event: &ICalendar) -> bool {
        self.component().is_some_and(|component| {
            event
                .components
                .iter()
                .any(|entry| entry.component_type == component)
        }) && match self {
            GroupwareKind::Tasks => is_todo_convertible(event),
            GroupwareKind::Calendar | GroupwareKind::Contacts => is_event_convertible(event),
        }
    }
}

impl GroupwareTarget {
    pub fn resolve(ctx: &EasContext<'_>, tree: &FolderTree, node: FolderNode) -> Option<Self> {
        let FolderNode::Stored(
            folder @ FolderRef {
                kind: FolderKind::Calendar | FolderKind::AddressBook,
                ..
            },
        ) = node
        else {
            return None;
        };
        let kind = GroupwareKind::from_class(&tree.get(node)?.class)?;
        ctx.allows(kind.data_kind()).then_some(GroupwareTarget {
            kind,
            container_id: folder.id,
        })
    }

    pub fn entries(&self, resources: &GroupwareResources) -> Vec<ItemEntry> {
        resources
            .children(self.container_id)
            .filter(|path| !path.is_container())
            .map(|path| {
                let document_id = path.document_id();
                let item = resources.item_by_id(document_id);
                let received_at = match self.kind {
                    GroupwareKind::Calendar | GroupwareKind::Tasks => item
                        .as_ref()
                        .and_then(|item| item.event_time_range())
                        .map(|(_, end)| end),
                    GroupwareKind::Contacts => item.as_ref().and_then(|item| item.modified_at()),
                };
                ItemEntry {
                    document_id,
                    change_id: 0,
                    received_at: received_at.map_or(0, |at| u64::try_from(at).unwrap_or(0)),
                    size: path.size(),
                }
            })
            .collect()
    }
}

impl RenderContext {
    pub fn options(&self) -> ConvertOptions<'_> {
        ConvertOptions {
            org_dn: &self.org,
            store: None,
            body_preference: BodyPreference::Native,
            tnef: TnefPolicy::Decode,
            max_decoded: MAX_DECODED_CARD,
        }
    }
}

impl ItemScope {
    fn of(kind: GroupwareKind, options: Option<&SyncOptions>) -> Self {
        match (kind, options.and_then(|options| options.filter_type)) {
            (GroupwareKind::Tasks, Some(FILTER_INCOMPLETE_TASKS)) => ItemScope::IncompleteTasks,
            _ => ItemScope::All,
        }
    }

    fn includes(self, item: &GroupwareItem) -> bool {
        match (self, &item.content) {
            (ItemScope::IncompleteTasks, ItemContent::Event(ical)) => !is_todo_complete(ical),
            _ => true,
        }
    }
}

impl GroupwareItem {
    pub fn event(&self) -> Option<&ICalendar> {
        match &self.content {
            ItemContent::Event(event) => Some(event),
            ItemContent::Card(_) => None,
        }
    }

    pub fn render<'x>(&'x self, context: &'x RenderContext) -> Option<ApplicationData<'x>> {
        match (&self.content, self.kind) {
            (ItemContent::Event(ical), GroupwareKind::Calendar) => {
                let event = event_to_eas(ical, &context.addresses, context.version)?;
                let mut calendar = event.calendar;
                if calendar.organizer_email.is_none() {
                    calendar.organizer_email = context
                        .addresses
                        .first()
                        .map(|address| Cow::Borrowed(address.as_str()));
                }
                if calendar.organizer_name.is_none()
                    && calendar.organizer_email.as_deref().is_some_and(|email| {
                        context
                            .addresses
                            .iter()
                            .any(|own| own.eq_ignore_ascii_case(email))
                    })
                {
                    calendar.organizer_name = Some(Cow::Borrowed(&context.name));
                }
                calendar.body = event.description.map(|text| self.body.render_text(text));
                if let Some(exceptions) = &mut calendar.exceptions {
                    for (position, text) in event.exception_bodies {
                        if let Some(exception) = exceptions.0.get_mut(position) {
                            exception.body = Some(self.body.render_text(text));
                        }
                    }
                }
                calendar.native_body_type = calendar.body.is_some().then_some(NATIVE_PLAIN);
                Some(ApplicationData::Calendar(Box::new(calendar)))
            }
            (ItemContent::Event(ical), GroupwareKind::Tasks) => {
                let todo = todo_to_eas(ical)?;
                let mut task = todo.task;
                task.body = todo.description.map(|text| self.body.render_text(text));
                Some(ApplicationData::Task(Box::new(task)))
            }
            (ItemContent::Card(card), GroupwareKind::Contacts) => {
                let data = match contact_to_eas(card, &context.options()) {
                    Ok(contact) => {
                        let mut data = contact.contact;
                        data.body = contact.notes.map(|text| match text {
                            Cow::Borrowed(text) => self.body.render_text(text),
                            Cow::Owned(text) => self.body.render_owned(&text),
                        });
                        data
                    }
                    Err(_) => Contact {
                        file_as: card
                            .property(&VCardProperty::Fn)
                            .and_then(|entry| entry.values.first())
                            .and_then(VCardValue::as_text)
                            .map(Cow::Borrowed),
                        ..Default::default()
                    },
                };
                Some(ApplicationData::Contact(Box::new(data)))
            }
            _ => None,
        }
    }
}

pub async fn render_context(
    server: &Server,
    account_id: u32,
    version: ProtocolVersion,
) -> trc::Result<RenderContext> {
    let account = server.account_info(account_id).await?;
    Ok(RenderContext {
        name: account
            .description()
            .unwrap_or_else(|| account.name())
            .into(),
        addresses: account.addresses().into(),
        version,
        org: org_dn().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Exchange organization DN is invalid.")
                .caused_by(trc::location!())
        })?,
    })
}

enum LogItems {
    Rebuild,
    Changed(RoaringBitmap),
}

async fn log_items(
    store: &Store,
    account_id: u32,
    collection: SyncCollection,
    query: Query,
    since: u64,
) -> trc::Result<(LogItems, u64)> {
    let changes = store
        .changes(account_id, collection.into(), query)
        .await
        .caused_by(trc::location!())?;
    let last = changes.to_change_id.max(since);
    if changes.needs_full_rebuild(since) {
        return Ok((LogItems::Rebuild, last));
    }
    let mut changed = RoaringBitmap::new();
    for change in &changes.changes {
        if let Change::UpdateItem(id) | Change::UpdateItemMetadata(id) | Change::InsertItem(id) =
            change
            && let Ok(id) = u32::try_from(*id)
        {
            changed.insert(id);
        }
    }
    Ok((LogItems::Changed(changed), last))
}

impl LogItems {
    fn apply(&self, held: &RoaringBitmap, changed: &mut RoaringBitmap) {
        match self {
            LogItems::Rebuild => *changed |= held,
            LogItems::Changed(items) => *changed |= items & held,
        }
    }
}

pub struct OwnWrites {
    pub documents: RoaringBitmap,
    pub through: Option<u64>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OwnBound {
    #[default]
    Unwritten,
    Through(u64),
    Unbounded,
}

impl OwnBound {
    pub fn record(&mut self, change_id: Option<u64>) {
        *self = match (*self, change_id) {
            (OwnBound::Unbounded, _) | (_, None) => OwnBound::Unbounded,
            (OwnBound::Unwritten, Some(change_id)) => OwnBound::Through(change_id),
            (OwnBound::Through(through), Some(change_id)) => {
                OwnBound::Through(through.max(change_id))
            }
        };
    }

    pub fn through(self, written_after: u64) -> Option<u64> {
        match self {
            OwnBound::Unwritten => Some(written_after),
            OwnBound::Through(through) => Some(through.max(written_after)),
            OwnBound::Unbounded => None,
        }
    }
}

struct PriorChanges {
    changed: RoaringBitmap,
    conflicts: RoaringBitmap,
    last: u64,
}

async fn prior_changes(
    store: &Store,
    account_id: u32,
    collection: SyncCollection,
    since: u64,
    view: &ClientView,
    rescoped: Option<&RoaringBitmap>,
) -> trc::Result<PriorChanges> {
    let (items, last) =
        log_items(store, account_id, collection, Query::Since(since), since).await?;
    let mut changed = RoaringBitmap::new();
    items.apply(&view.held, &mut changed);
    let pending = match rescoped {
        Some(rescoped) => Cow::Owned(&view.pending - rescoped),
        None => Cow::Borrowed(&view.pending),
    };
    let conflicts = match items {
        LogItems::Rebuild => pending.into_owned(),
        LogItems::Changed(_) => &changed | &*pending,
    };
    Ok(PriorChanges {
        changed,
        conflicts,
        last,
    })
}

pub async fn changed_since(
    store: &Store,
    account_id: u32,
    kind: GroupwareKind,
    since: u64,
    held: &RoaringBitmap,
    own: &OwnWrites,
) -> trc::Result<(RoaringBitmap, u64)> {
    let collection = kind.collection();
    let mut changed = RoaringBitmap::new();
    let mut from = since;
    let own_span = match own.through {
        _ if own.documents.is_empty() => None,
        Some(through) if through <= since => None,
        Some(through) => Some(Query::Range(since, through)),
        None => Some(Query::Since(since)),
    };
    if let Some(query) = own_span {
        let (items, last) = log_items(store, account_id, collection, query, since).await?;
        let mut foreign = RoaringBitmap::new();
        items.apply(held, &mut foreign);
        foreign -= &own.documents;
        changed |= foreign;
        match own.through {
            Some(through) => from = through,
            None => return Ok((changed, last)),
        }
    }
    let (items, last) = log_items(store, account_id, collection, Query::Since(from), from).await?;
    items.apply(held, &mut changed);
    Ok((changed, last))
}

pub fn collect(
    entries: &[ItemEntry],
    cutoff: Option<u64>,
    view: &mut ClientView,
    changed: &RoaringBitmap,
    window: usize,
    bytes: usize,
) -> ServerChanges {
    let mut in_scope = RoaringBitmap::new();
    let mut out_of_scope = RoaringBitmap::new();
    for entry in entries {
        if cutoff.is_none_or(|cutoff| entry.received_at >= cutoff) {
            in_scope.insert(entry.document_id);
        } else {
            out_of_scope.insert(entry.document_id);
        }
    }
    let mut changes = ServerChanges::default();
    let mut budget = window;

    let gone_hidden = &view.hidden - &in_scope;
    view.held -= &gone_hidden;
    view.hidden -= &gone_hidden;
    view.pending -= &gone_hidden;
    view.queue_changes(changed);

    let gone = &(&view.held - &in_scope) - &out_of_scope;
    let soft = &view.held & &out_of_scope;
    for (document_id, item) in gone
        .iter()
        .map(|id| (id, ServerItem::Delete(id)))
        .chain(soft.iter().map(|id| (id, ServerItem::SoftDelete(id))))
    {
        if budget == 0 {
            changes.more_available = true;
            return changes;
        }
        budget -= 1;
        view.held.remove(document_id);
        view.pending.remove(document_id);
        view.removed.insert(document_id);
        changes.items.push(item);
    }

    let sending = usize::try_from(view.pending.len()).map_or(budget, |len| len.min(budget));
    changes.items.reserve(sending);
    for document_id in view.pending.iter().take(sending) {
        view.changed.insert(document_id);
        changes.items.push(ServerItem::Change(document_id));
    }
    view.pending.remove_smallest(sending as u64);
    budget -= sending;
    if !view.pending.is_empty() {
        changes.more_available = true;
        return changes;
    }

    let mut added = entries
        .iter()
        .filter(|entry| {
            in_scope.contains(entry.document_id) && !view.held.contains(entry.document_id)
        })
        .map(|entry| (entry.received_at, entry.document_id, entry.size))
        .collect::<Vec<_>>();
    if added.len() > budget {
        changes.more_available = true;
        match budget.checked_sub(1) {
            Some(last) => {
                added.select_nth_unstable(last);
                added.truncate(budget);
            }
            None => added.clear(),
        }
    }
    added.sort_unstable();
    let mut remaining = bytes;
    for (_, document_id, size) in added {
        if remaining == 0 {
            changes.more_available = true;
            break;
        }
        remaining = remaining.saturating_sub(size as usize);
        view.held.insert(document_id);
        view.added.insert(document_id);
        changes.items.push(ServerItem::Add(document_id));
    }
    changes.bytes = bytes - remaining;
    changes
}

impl GroupwareProbe {
    pub fn new(target: GroupwareTarget, mut probe: FolderProbe) -> Self {
        if target.kind != GroupwareKind::Calendar {
            probe.cutoff = None;
        }
        GroupwareProbe {
            target,
            probe,
            changed: RoaringBitmap::new(),
        }
    }

    pub fn kind(&self) -> GroupwareKind {
        self.target.kind
    }

    fn watermark(&self) -> u64 {
        self.probe.watermark.change_id
    }

    fn count(&self, resources: &GroupwareResources) -> u64 {
        count_changes(
            &self.target.entries(resources),
            self.probe.cutoff,
            &self.probe.view,
            &self.changed,
        )
    }
}

fn count_changes(
    entries: &[ItemEntry],
    cutoff: Option<u64>,
    view: &ClientView,
    changed: &RoaringBitmap,
) -> u64 {
    let in_scope = entries
        .iter()
        .filter(|entry| cutoff.is_none_or(|cutoff| entry.received_at >= cutoff))
        .map(|entry| entry.document_id)
        .collect::<RoaringBitmap>();
    let mut hidden = &view.hidden & &in_scope;
    hidden -= changed;
    let mut held = &view.held - &(&view.hidden - &hidden);
    let deleted = held.len() - held.intersection_len(&in_scope);
    held &= &in_scope;
    let mut pending = &view.pending | changed;
    pending &= &held;
    pending -= &hidden;
    let added = entries
        .iter()
        .filter(|entry| in_scope.contains(entry.document_id) && !held.contains(entry.document_id))
        .count() as u64;
    deleted + pending.len() + added
}

async fn advance_changes(
    store: &Store,
    account_id: u32,
    collection: SyncCollection,
    probes: &mut [GroupwareProbe],
    scanned: Option<u64>,
) -> trc::Result<u64> {
    let mut starts = match scanned {
        Some(scanned) => SmallVec::<[u64; 4]>::from_elem(scanned, 1),
        None => probes
            .iter()
            .filter(|probe| probe.target.kind.collection() == collection)
            .map(GroupwareProbe::watermark)
            .collect(),
    };
    starts.sort_unstable();
    starts.dedup();
    let mut last = 0;
    for (index, &from) in starts.iter().enumerate() {
        let query = match starts.get(index + 1) {
            Some(&to) => Query::Range(from, to),
            None => Query::Since(from),
        };
        let (items, end) = log_items(store, account_id, collection, query, from).await?;
        for probe in probes.iter_mut().filter(|probe| {
            probe.target.kind.collection() == collection && probe.watermark() <= from
        }) {
            items.apply(&probe.probe.view.held, &mut probe.changed);
        }
        last = end;
    }
    Ok(last)
}

impl GroupwareProbes {
    pub fn push(&mut self, probe: GroupwareProbe) -> usize {
        self.probes.push(probe);
        self.probes.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    pub fn clear(&mut self) {
        self.probes.clear();
        self.calendar = LogCursor::default();
        self.contacts = LogCursor::default();
    }

    pub async fn scan(
        &mut self,
        server: &Server,
        account_id: u32,
        woken: Bitmap<DataType>,
        mut report: impl FnMut(usize, u64),
    ) -> trc::Result<Hierarchy> {
        let mut hierarchy = Hierarchy::Unchanged;
        for (collection, types, cursor) in [
            (
                SyncCollection::Calendar,
                Bitmap::from_iter([DataType::Calendar, DataType::CalendarEvent]),
                &mut self.calendar,
            ),
            (
                SyncCollection::AddressBook,
                Bitmap::from_iter([DataType::AddressBook, DataType::ContactCard]),
                &mut self.contacts,
            ),
        ] {
            if !self
                .probes
                .iter()
                .any(|probe| probe.target.kind.collection() == collection)
                || (cursor.seen.is_some() && !woken.intersects(&types))
            {
                continue;
            }
            let resources = server
                .fetch_groupware_resources(account_id, account_id, collection)
                .await?;
            if cursor.seen == Some(resources.highest_change_id) {
                continue;
            }
            cursor.seen = Some(resources.highest_change_id);
            cursor.scanned = Some(
                advance_changes(
                    server.store(),
                    account_id,
                    collection,
                    &mut self.probes,
                    cursor.scanned,
                )
                .await?,
            );
            for (index, probe) in self.probes.iter().enumerate() {
                if probe.target.kind.collection() != collection {
                    continue;
                }
                if resources
                    .container_resource_by_id(probe.target.container_id)
                    .is_some()
                {
                    report(index, probe.count(&resources));
                } else {
                    hierarchy = Hierarchy::Changed;
                }
            }
        }
        Ok(hierarchy)
    }
}

pub async fn load_item(
    server: &Server,
    account_id: u32,
    kind: GroupwareKind,
    document_id: u32,
    body: BodyChoice,
) -> trc::Result<Option<GroupwareItem>> {
    let key = match kind {
        GroupwareKind::Calendar | GroupwareKind::Tasks => ValueKey::property(
            account_id,
            Collection::CalendarEvent,
            document_id,
            CalendarEventField::Content,
        ),
        GroupwareKind::Contacts => ValueKey::property(
            account_id,
            Collection::ContactCard,
            document_id,
            ContactField::Content,
        ),
    };
    let Some(archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(key)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let size = u32::try_from(archive.inner.len()).unwrap_or(u32::MAX);
    let content = match kind {
        GroupwareKind::Calendar | GroupwareKind::Tasks => {
            let event = archive
                .deserialize::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .data
                .event;
            if !kind.shows(&event) {
                return Ok(None);
            }
            ItemContent::Event(Box::new(event))
        }
        GroupwareKind::Contacts => ItemContent::Card(Box::new(
            archive
                .deserialize::<ContactCardContent>()
                .caused_by(trc::location!())?
                .card,
        )),
    };
    Ok(Some(GroupwareItem {
        document_id,
        size,
        kind,
        content,
        body,
    }))
}

pub async fn shows_event(
    server: &Server,
    account_id: u32,
    kind: GroupwareKind,
    document_id: u32,
) -> trc::Result<bool> {
    let Some(archive) = server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::CalendarEvent,
            document_id,
            CalendarEventField::Content,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(false);
    };
    Ok(kind.shows(
        &archive
            .deserialize::<CalendarEventContent>()
            .caused_by(trc::location!())?
            .data
            .event,
    ))
}

pub(super) async fn sync_groupware(
    server: &Server,
    ctx: &EasContext<'_>,
    job: &Job<'_>,
    folder: FolderRef,
    mut result: JobResult,
    budget: &mut ResponseBudget,
    tree: &mut Option<FolderTree>,
) -> trc::Result<Option<JobResult>> {
    let node = FolderNode::Stored(folder);
    let tree = match tree {
        Some(tree) => tree,
        None => tree.insert(
            server
                .exchange_folder_tree(ctx.account_id, ctx.data_types)
                .await?,
        ),
    };
    let Some(entry) = tree.get(node) else {
        result.status = SyncStatus::FOLDER_HIERARCHY_CHANGED;
        return Ok(Some(result));
    };
    let Some(kind) = GroupwareKind::from_class(&entry.class) else {
        return Ok(empty_collection(job, result));
    };
    result.class = kind.class();
    if !ctx.allows(kind.data_kind()) {
        result.status = SyncStatus::SERVER_ERROR;
        return Ok(Some(result));
    }
    let target = GroupwareTarget {
        kind,
        container_id: folder.id,
    };
    let mut resources = server
        .fetch_groupware_resources(ctx.account_id, ctx.account_id, kind.collection())
        .await?;
    if resources.container_resource_by_id(folder.id).is_none() {
        result.status = SyncStatus::FOLDER_HIERARCHY_CHANGED;
        return Ok(Some(result));
    }

    let archive = server
        .eas_folder_state(ctx.account_id, ctx.device.slot, folder)
        .await?;
    let state = match &archive {
        Some(archive) => Some(
            archive
                .deserialize::<EasFolderState>()
                .caused_by(trc::location!())?,
        ),
        None => None,
    };
    let stored_options = state
        .as_ref()
        .and_then(|state| CollectionOptions::decode(&state.options))
        .unwrap_or_default();
    let mut view = state
        .as_ref()
        .and_then(|state| ClientView::decode(&state.synced))
        .unwrap_or_default();
    let Some((key_state, key)) = resolve_key(&job.key, state.as_ref(), &view) else {
        result.status = SyncStatus::INVALID_SYNC_KEY;
        result.sync_key = initial_key();
        return Ok(Some(result));
    };
    if matches!(job.key, KeyInput::Current)
        && let Some(current) = key.encode()
    {
        result.sync_key = current;
    }

    let mut options = stored_options.clone();
    if let Some(request) = job.request {
        if request.conversation_mode.is_some()
            || request.options.iter().any(|options| {
                options.has_bad_filter() || options.class.is_some_and(|class| class != kind.class())
            })
        {
            result.status = SyncStatus::PROTOCOL_ERROR;
            return Ok(Some(result));
        }
        if !request.options.is_empty() {
            options.options = request.options.clone();
        }
        if request.window_size.is_some() {
            options.window_size = request.window_size;
        }
    }
    let item_options = options.options.first();
    let body = BodyChoice::select(item_options, false);
    let cutoff = match kind {
        GroupwareKind::Calendar => filter_cutoff(item_options),
        GroupwareKind::Tasks | GroupwareKind::Contacts => None,
    };
    let scope = ItemScope::of(kind, item_options);

    let initial = matches!(key_state, KeyState::Initial);
    let supported = match (initial, job.request) {
        (true, Some(request)) => SupportedFields::new(request.supported.as_deref()),
        (true, None) => SupportedFields::default(),
        (false, _) => state
            .as_ref()
            .map(|state| SupportedFields::decode(&state.supported))
            .unwrap_or_default(),
    };
    let replayed = match (&key_state, &state) {
        (KeyState::Replay, Some(state)) => state.client_ids.as_slice(),
        _ => &[],
    };
    let commands = job
        .request
        .map(|request| request.commands.as_slice())
        .unwrap_or_default();
    let checks_conflicts = !initial
        && item_options.and_then(|options| options.conflict) != Some(CONFLICT_CLIENT_WINS)
        && commands
            .iter()
            .any(|command| matches!(command, ClientCommand::Change { .. }));
    let mut withdrawn = None;
    let (nonce, generation, since) = match key_state {
        KeyState::Initial => {
            view = ClientView::default();
            (rand::rng().random(), 0, resources.highest_change_id)
        }
        KeyState::Replay => {
            let removed = view.rewind();
            withdrawn = checks_conflicts.then_some(removed);
            (key.nonce, key.generation, key.change_id)
        }
        KeyState::Current => {
            view.advance();
            (key.nonce, key.generation, key.change_id)
        }
    };
    let prior_since = match (&key_state, &state) {
        (KeyState::Replay, Some(state)) => state.change_id.max(since),
        _ => since,
    };
    let mut rescoped = None;
    if !initial && scope != ItemScope::of(kind, stored_options.options.first()) {
        view.held -= &view.hidden;
        view.hidden.clear();
        if scope == ItemScope::IncompleteTasks {
            rescoped = Some(&view.held - &view.pending);
            view.pending |= &view.held;
        }
    }

    let prior = if checks_conflicts {
        let mut prior = prior_changes(
            server.store(),
            ctx.account_id,
            kind.collection(),
            prior_since,
            &view,
            rescoped.as_ref(),
        )
        .await?;
        if let Some(withdrawn) = &withdrawn {
            prior.conflicts |= withdrawn;
        }
        Some(prior)
    } else {
        None
    };
    let mut fetches = Vec::new();
    let mut writer = GroupwareWriter::new(
        server,
        ctx,
        target,
        &resources,
        supported.ghosting(),
        replayed,
    )
    .with_conflicts(prior.as_ref().map(|prior| &prior.conflicts));
    let written_after = resources.highest_change_id;
    if !initial {
        for command in commands {
            let reply = match command {
                ClientCommand::Fetch { server_id } => {
                    let document_id = EasServerId::decode(server_id)
                        .filter(|id| id.container == folder.id && view.shows(id.id))
                        .map(|id| id.id);
                    fetches.push((result.replies.len(), document_id));
                    ItemReply::Fetch {
                        server_id: server_id.to_string(),
                        document_id,
                    }
                }
                command => match writer.apply(command, &mut view).await? {
                    Some(reply) => reply,
                    None => continue,
                },
            };
            result.replies.push(reply);
            result.fetched.push(Fetched::Missing);
        }
    }
    let own = OwnWrites {
        documents: writer.own,
        through: writer.bound.through(written_after),
    };
    let client_ids = writer.client_ids;
    if writer.wrote {
        resources = server
            .fetch_groupware_resources(ctx.account_id, ctx.account_id, kind.collection())
            .await?;
    }
    for (index, document_id) in fetches {
        if let Some(document_id) = document_id
            && let Some(item) = load_item(server, ctx.account_id, kind, document_id, body).await?
            && let Some(slot) = result.fetched.get_mut(index)
        {
            *slot = Fetched::Item(Box::new(item));
        }
    }

    let hidden_before = view.hidden.clone();
    let mut change_id = since;
    let mut items = Vec::new();
    let get_changes = job
        .request
        .is_none_or(|request| request.get_changes.unwrap_or(true));
    if !initial && (get_changes || !own.documents.is_empty()) {
        let (mut changed, last) = changed_since(
            server.store(),
            ctx.account_id,
            kind,
            prior.as_ref().map_or(since, |prior| prior.last),
            &view.held,
            &own,
        )
        .await?;
        if let Some(prior) = &prior {
            changed |= &prior.changed - &own.documents;
        }
        change_id = last.max(resources.highest_change_id);
        if get_changes {
            let window = window_size(options.window_size).min(budget.items);
            let entries = target.entries(&resources);
            let changes = collect(&entries, cutoff, &mut view, &changed, window, budget.bytes);
            budget.items = budget.items.saturating_sub(changes.items.len());
            budget.bytes = budget.bytes.saturating_sub(changes.bytes);
            result.more_available = changes.more_available;
            items = changes.items;
        } else {
            view.queue_changes(&changed);
        }
    }

    let mut loaded = stream::iter(items.iter().filter_map(ServerItem::with_data))
        .map(|document_id| load_item(server, ctx.account_id, kind, document_id, body))
        .buffered(LOAD_CONCURRENCY);
    for item in &items {
        result.commands.push(match *item {
            ServerItem::Add(document_id) | ServerItem::Change(document_id) => {
                let added = matches!(item, ServerItem::Add(_));
                match loaded.try_next().await?.flatten() {
                    Some(loaded) if scope.includes(&loaded) => OutItem::Put {
                        server_id: server_id(folder.id, document_id),
                        item: Box::new(loaded),
                        added,
                    },
                    _ if added => {
                        view.added.remove(document_id);
                        view.hidden.insert(document_id);
                        continue;
                    }
                    Some(_) => {
                        view.hide_changed(document_id);
                        OutItem::SoftDelete(server_id(folder.id, document_id))
                    }
                    None => {
                        view.withdraw_changed(document_id);
                        OutItem::Delete(server_id(folder.id, document_id))
                    }
                }
            }
            ServerItem::Delete(document_id) => OutItem::Delete(server_id(folder.id, document_id)),
            ServerItem::SoftDelete(document_id) => {
                OutItem::SoftDelete(server_id(folder.id, document_id))
            }
        });
    }
    drop(loaded);

    let options_changed = options != stored_options;
    let has_output = initial
        || !result.commands.is_empty()
        || !result.replies.is_empty()
        || !commands.is_empty()
        || result.more_available;
    if !has_output {
        let hidden_changed = view.hidden != hidden_before;
        if (options_changed || hidden_changed)
            && matches!(key_state, KeyState::Current)
            && let Some(mut state) = state
        {
            state.options = options.encode();
            state.synced = view.encode();
            if !write_folder(server, ctx, folder, archive.as_ref(), state).await? {
                trc::event!(
                    Store(trc::StoreEvent::AssertValueFailed),
                    AccountId = ctx.account_id,
                    Details = "Exchange ActiveSync collection state not saved.",
                );
            }
        }
        return Ok(None);
    }

    let next_key = EasSyncKey {
        nonce,
        generation: generation.wrapping_add(1),
        change_id,
        page: None,
    };
    let Some(token) = next_key.encode() else {
        result.status = SyncStatus::SERVER_ERROR;
        return Ok(Some(result));
    };
    view.page = None;
    let next_state = EasFolderState {
        nonce,
        generation: next_key.generation,
        change_id,
        previous_change_id: since,
        options: options.encode(),
        supported: supported.encode(),
        synced: view.encode(),
        client_ids,
    };
    if !write_folder(server, ctx, folder, archive.as_ref(), next_state).await? {
        result.status = SyncStatus::RETRY;
        result.commands.clear();
        result.replies.clear();
        result.fetched.clear();
        result.more_available = false;
        return Ok(Some(result));
    }
    result.sync_key = token;
    result.render = Some(render_context(server, ctx.account_id, ctx.version).await?);
    Ok(Some(result))
}

pub(super) async fn sync_virtual_list(
    server: &Server,
    ctx: &EasContext<'_>,
    job: &Job<'_>,
    kind: GroupwareKind,
    mut result: JobResult,
) -> trc::Result<Option<JobResult>> {
    result.class = kind.class();
    let commands = job
        .request
        .map(|request| request.commands.as_slice())
        .unwrap_or_default();
    let KeyInput::Sent(key) = job.key else {
        return Ok(empty_collection(job, result));
    };
    if EasSyncKey::decode(key) != Some(EMPTY_COLLECTION_KEY)
        || !commands
            .iter()
            .any(|command| matches!(command, ClientCommand::Add { .. }))
    {
        return Ok(empty_collection(job, result));
    }
    let folder = match kind {
        GroupwareKind::Calendar => {
            server
                .folder_event_calendar(&ctx.access_token, ctx.account_id)
                .await?
        }
        GroupwareKind::Tasks => {
            server
                .folder_task_list(&ctx.access_token, ctx.account_id)
                .await?
        }
        GroupwareKind::Contacts => return Ok(empty_collection(job, result)),
    };
    let Ok(folder) = folder else {
        return Ok(empty_collection(job, result));
    };
    let resources = server
        .fetch_groupware_resources(ctx.account_id, ctx.account_id, kind.collection())
        .await?;
    let target = GroupwareTarget {
        kind,
        container_id: folder.id,
    };
    let mut writer = GroupwareWriter::new(server, ctx, target, &resources, Ghosting::Off, &[])
        .with_device_uids();
    let mut view = ClientView {
        held: resources.children_ids(folder.id).collect(),
        ..Default::default()
    };
    for command in commands {
        let reply = match command {
            ClientCommand::Add { .. } => writer.apply(command, &mut view).await?,
            _ => None,
        };
        result
            .replies
            .push(reply.unwrap_or_else(|| missing_reply(command)));
        result.fetched.push(Fetched::Missing);
    }
    Ok(Some(result))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/sync/groupware/tests.rs"]
mod tests;
