/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::scan::{Emitter, FolderMark, MAX_EVENTS_PER_BATCH, Place, ScanEvent, ScanObject, Scope};
use crate::{
    folders::{FolderNode, FolderTree},
    store::{FolderKind, FolderRef},
};
use ahash::AHashMap;
use common::{GroupwareResources, Server};
use smallvec::SmallVec;
use std::sync::Arc;
use store::{
    query::log::{CappedChanges, Change, Changes, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{collection::SyncCollection, type_state::DataType};

pub(crate) const GROUPWARE_KINDS: usize = 2;
pub(super) const KINDS: [(FolderKind, SyncCollection, DataType); GROUPWARE_KINDS] = [
    (
        FolderKind::Calendar,
        SyncCollection::Calendar,
        DataType::CalendarEvent,
    ),
    (
        FolderKind::AddressBook,
        SyncCollection::AddressBook,
        DataType::ContactCard,
    ),
];
const MEMBERS_WEIGHT: u64 = 64;
const WINDOW_ENTRIES: usize = 5 * MAX_EVENTS_PER_BATCH;

type Folders = SmallVec<[u32; 4]>;
type Events = SmallVec<[ScanEvent; 4]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Logged {
    Live,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoggedDocuments {
    Truncated,
    Changed(Vec<(u32, Logged)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupwareLog {
    pub to: u64,
    pub documents: LoggedDocuments,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogWindow {
    since: u64,
    upper: u64,
    limit: usize,
}

pub(crate) struct GroupwareScan {
    pub kind: FolderKind,
    pub collection: SyncCollection,
    pub resources: Arc<GroupwareResources>,
    pub log: Option<GroupwareLog>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Report {
    Everything,
    MembershipOnly,
}

struct Target<'x> {
    kind: FolderKind,
    resources: &'x GroupwareResources,
    tree: &'x FolderTree,
    scope: &'x Scope,
}

#[derive(Clone, Copy)]
pub(crate) struct GroupwareInput<'x> {
    pub kind: FolderKind,
    pub resources: &'x GroupwareResources,
    pub log: Option<&'x GroupwareLog>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GroupwareCursor {
    change_id: u64,
    pinned: u64,
    after: Option<u32>,
    zeroed: bool,
    members: AHashMap<u32, RoaringBitmap>,
}

impl GroupwareScan {
    pub fn input(&self) -> GroupwareInput<'_> {
        GroupwareInput {
            kind: self.kind,
            resources: &self.resources,
            log: self.log.as_ref(),
        }
    }

    pub fn is_behind(&self) -> bool {
        self.log
            .as_ref()
            .is_some_and(|log| log.to < self.resources.item_change_id)
    }

    pub async fn load_log(
        &mut self,
        server: &Server,
        account_id: u32,
        windows: impl Iterator<Item = (u64, u64)>,
    ) -> trc::Result<()> {
        let Some(window) = GroupwareLog::window(self.resources.item_change_id, windows) else {
            return Ok(());
        };
        let read = server
            .store()
            .changes_capped(
                account_id,
                self.collection.into(),
                Query::Range(window.since, window.upper),
                window.limit,
            )
            .await
            .caused_by(trc::location!())?;
        self.log = Some(GroupwareLog::read(&read, window));
        Ok(())
    }
}

impl GroupwareLog {
    fn window(high: u64, windows: impl Iterator<Item = (u64, u64)>) -> Option<LogWindow> {
        let (since, upper, pinned) = windows.fold(
            (u64::MAX, high, false),
            |(since, upper, pinned), (from, pin)| {
                (
                    since.min(from),
                    if pin != 0 { upper.min(pin) } else { upper },
                    pinned || pin != 0,
                )
            },
        );
        (since < upper).then_some(LogWindow {
            since,
            upper,
            limit: if pinned { usize::MAX } else { WINDOW_ENTRIES },
        })
    }

    fn read(read: &CappedChanges, window: LogWindow) -> Self {
        let documents = LoggedDocuments::from_changes(&read.changes, window.since);
        let to = if read.has_more && !matches!(documents, LoggedDocuments::Truncated) {
            read.changes.to_change_id
        } else {
            window.upper
        };
        GroupwareLog { to, documents }
    }
}

impl LoggedDocuments {
    fn from_changes(changes: &Changes, since: u64) -> Self {
        if changes.needs_full_rebuild(since) {
            return LoggedDocuments::Truncated;
        }
        let mut documents = changes
            .changes
            .iter()
            .filter_map(|change| match change {
                Change::InsertItem(id)
                | Change::UpdateItem(id)
                | Change::UpdateItemMetadata(id) => {
                    u32::try_from(*id).ok().map(|id| (id, Logged::Live))
                }
                Change::DeleteItem(id) => u32::try_from(*id).ok().map(|id| (id, Logged::Removed)),
                _ => None,
            })
            .collect::<Vec<_>>();
        documents.sort_unstable_by_key(|(id, _)| *id);
        LoggedDocuments::Changed(documents)
    }
}

fn node(kind: FolderKind, id: u32) -> FolderNode {
    FolderNode::Stored(FolderRef { kind, id })
}

fn place(kind: FolderKind, container: u32, document: u32) -> Place {
    Place {
        object: ScanObject::Groupware {
            kind,
            container,
            document,
        },
        parent: node(kind, container),
    }
}

fn scoped_containers<'x>(
    kind: FolderKind,
    tree: &'x FolderTree,
    scope: &'x Scope,
) -> impl Iterator<Item = u32> + 'x {
    tree.iter().filter_map(move |entry| match entry.node {
        FolderNode::Stored(FolderRef {
            kind: entry_kind,
            id,
        }) if entry_kind == kind && scope.contains(entry.node) => Some(id),
        _ => None,
    })
}

impl GroupwareCursor {
    pub(super) fn baseline(gw: &GroupwareInput<'_>, tree: &FolderTree, scope: &Scope) -> Self {
        GroupwareCursor {
            change_id: gw.resources.item_change_id,
            pinned: 0,
            after: None,
            zeroed: false,
            members: scoped_containers(gw.kind, tree, scope)
                .map(|id| (id, gw.resources.children_ids(id).collect()))
                .collect(),
        }
    }

    pub(super) fn window(&self) -> (u64, u64) {
        (self.change_id, self.pinned)
    }

    pub(super) fn is_pending(&self, gw: &GroupwareInput<'_>, scope: &Scope) -> bool {
        scope.holds(gw.kind) && (self.pinned != 0 || gw.resources.item_change_id > self.change_id)
    }

    pub(super) fn weight(&self) -> u64 {
        self.members
            .values()
            .map(|documents| documents.serialized_size() as u64 + MEMBERS_WEIGHT)
            .sum()
    }

    pub(super) fn prepare_truncated(
        &mut self,
        gw: &GroupwareInput<'_>,
        folders: &mut AHashMap<FolderNode, FolderMark>,
    ) {
        let Some(log) = gw.log else {
            return;
        };
        if log.documents != LoggedDocuments::Truncated
            || log.to <= self.change_id
            || self.zeroed
            || (self.pinned != 0 && self.pinned != log.to)
        {
            return;
        }
        self.pinned = log.to;
        self.zeroed = true;
        for (node, mark) in folders.iter_mut() {
            if matches!(node, FolderNode::Stored(FolderRef { kind, .. }) if *kind == gw.kind) {
                mark.change_id = 0;
            }
        }
    }

    pub(super) fn scan(
        &mut self,
        gw: &GroupwareInput<'_>,
        tree: &FolderTree,
        scope: &Scope,
        emitter: &mut Emitter,
    ) {
        let Some(log) = gw.log else {
            return;
        };
        if (self.pinned != 0 && self.pinned != log.to)
            || (self.pinned == 0 && log.to <= self.change_id)
        {
            return;
        }
        let kind = gw.kind;
        let target = Target {
            kind,
            resources: gw.resources,
            tree,
            scope,
        };
        self.members
            .retain(|id, _| tree.get(node(kind, *id)).is_some());
        let complete = match &log.documents {
            LoggedDocuments::Truncated => {
                let mut documents = RoaringBitmap::new();
                for members in self.members.values() {
                    documents |= members;
                }
                for container in scoped_containers(kind, tree, scope) {
                    documents.extend(gw.resources.children_ids(container));
                }
                documents.iter().all(|document| {
                    self.apply(
                        document,
                        Logged::Live,
                        Report::MembershipOnly,
                        &target,
                        emitter,
                    )
                })
            }
            LoggedDocuments::Changed(documents) => documents.iter().all(|(document, logged)| {
                self.apply(*document, *logged, Report::Everything, &target, emitter)
            }),
        };
        if complete {
            self.change_id = self.change_id.max(log.to);
            self.pinned = 0;
            self.after = None;
            self.zeroed = false;
        } else {
            self.pinned = log.to;
        }
    }

    fn apply(
        &mut self,
        document: u32,
        logged: Logged,
        report: Report,
        target: &Target<'_>,
        emitter: &mut Emitter,
    ) -> bool {
        if self.after.is_some_and(|after| document <= after) {
            return true;
        }
        let Target {
            kind,
            resources,
            tree,
            scope,
        } = *target;
        let mut current = Folders::new();
        if logged == Logged::Live
            && let Some(resource) = resources.item_by_id(document)
        {
            current.extend(
                resource
                    .child_names()
                    .iter()
                    .map(|name| name.parent_id)
                    .filter(|&id| {
                        let parent = node(kind, id);
                        scope.contains(parent) && tree.get(parent).is_some()
                    }),
            );
            current.sort_unstable();
            current.dedup();
        }
        let mut prior = self
            .members
            .iter()
            .filter(|(_, documents)| documents.contains(document))
            .map(|(id, _)| *id)
            .collect::<Folders>();
        prior.sort_unstable();

        let lost = prior
            .iter()
            .copied()
            .filter(|id| current.binary_search(id).is_err())
            .collect::<Folders>();
        let gained = current
            .iter()
            .copied()
            .filter(|id| prior.binary_search(id).is_err())
            .collect::<Folders>();
        let mut events = Events::new();
        if report == Report::Everything {
            events.extend(
                current
                    .iter()
                    .filter(|id| prior.binary_search(id).is_ok())
                    .map(|&id| ScanEvent::Modified {
                        place: place(kind, id, document),
                        unread: None,
                    }),
            );
        }
        events.extend(
            lost.iter()
                .zip(&gained)
                .map(|(&from, &to)| ScanEvent::Moved {
                    to: place(kind, to, document),
                    from: place(kind, from, document),
                }),
        );
        let paired = lost.len().min(gained.len());
        events.extend(
            gained
                .iter()
                .skip(paired)
                .map(|&id| ScanEvent::Created(place(kind, id, document))),
        );
        events.extend(
            lost.iter()
                .skip(paired)
                .map(|&id| ScanEvent::Deleted(place(kind, id, document))),
        );
        if !emitter.emit(&events) {
            return false;
        }
        for id in &lost {
            if let Some(documents) = self.members.get_mut(id) {
                documents.remove(document);
            }
        }
        for id in gained {
            self.members.entry(id).or_default().insert(document);
        }
        self.after = Some(document);
        true
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/notify/groupware_log/tests.rs"]
mod tests;
