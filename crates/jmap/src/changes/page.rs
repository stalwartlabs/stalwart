/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::state::max_state;
use jmap_proto::{method::changes::ChangesResponse, object::NullObject, types::state::State};
use store::{
    ahash::{AHashMap, AHashSet},
    query::log::{Change, Changes, Query},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewerChange {
    Shared(Change),
    SharedAndPrivate(Change),
    Private(Change),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataChanges {
    Unsupported,
    Ignored,
    Reported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartialProperties {
    Counts,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UpdatedProperties(u8);

#[derive(Debug, Default)]
pub(crate) struct LogRead {
    pub shared: Option<Changes>,
    pub private: Option<Changes>,
}

#[derive(Debug)]
pub(crate) enum ViewerChanges {
    Shared(Vec<Change>),
    Merged(Vec<ViewerChange>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Page {
    pub has_more: bool,
    pub updated_properties: Option<UpdatedProperties>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogBounds {
    pub first_change_id: u64,
    pub last_change_id: u64,
    pub private_change_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Coverage {
    Latest { viewer_change_id: u64 },
    Range,
}

impl UpdatedProperties {
    pub const COUNTS: UpdatedProperties = UpdatedProperties(1);
    pub const METADATA: UpdatedProperties = UpdatedProperties(1 << 1);
    pub const PRIVATE_METADATA: UpdatedProperties = UpdatedProperties(1 << 2);

    pub fn has_counts(self) -> bool {
        self.0 & Self::COUNTS.0 != 0
    }

    pub fn has_metadata(self) -> bool {
        self.0 & Self::METADATA.0 != 0
    }

    pub fn has_private_metadata(self) -> bool {
        self.0 & Self::PRIVATE_METADATA.0 != 0
    }

    pub(crate) fn union(self, other: UpdatedProperties) -> Self {
        UpdatedProperties(self.0 | other.0)
    }

    fn intersection(self, other: UpdatedProperties) -> Self {
        UpdatedProperties(self.0 & other.0)
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }
}

pub(crate) trait PageChange: Copy {
    fn change(self) -> Change;
    fn is_metadata_only(self) -> bool;
    fn properties(self, partial: PartialProperties) -> Option<UpdatedProperties>;
}

impl PageChange for Change {
    fn change(self) -> Change {
        self
    }

    fn is_metadata_only(self) -> bool {
        Change::is_metadata_only(&self)
    }

    fn properties(self, partial: PartialProperties) -> Option<UpdatedProperties> {
        match self {
            Change::UpdateItemMetadata(_) => Some(UpdatedProperties::METADATA),
            Change::UpdateContainerPartial(_, changed) => {
                let mut properties = UpdatedProperties::default();
                if changed.has_properties() {
                    match partial {
                        PartialProperties::Counts => {
                            properties = properties.union(UpdatedProperties::COUNTS);
                        }
                        PartialProperties::Unknown => return None,
                    }
                }
                if changed.has_metadata() {
                    properties = properties.union(UpdatedProperties::METADATA);
                }
                Some(properties)
            }
            _ => None,
        }
    }
}

impl PageChange for ViewerChange {
    fn change(self) -> Change {
        match self {
            ViewerChange::Shared(change)
            | ViewerChange::SharedAndPrivate(change)
            | ViewerChange::Private(change) => change,
        }
    }

    fn is_metadata_only(self) -> bool {
        match self {
            ViewerChange::Shared(change) | ViewerChange::SharedAndPrivate(change) => {
                Change::is_metadata_only(&change)
            }
            ViewerChange::Private(_) => true,
        }
    }

    fn properties(self, partial: PartialProperties) -> Option<UpdatedProperties> {
        match self {
            ViewerChange::Shared(change) => change.properties(partial),
            ViewerChange::SharedAndPrivate(change) => change
                .properties(partial)
                .map(|shared| shared.union(UpdatedProperties::PRIVATE_METADATA)),
            ViewerChange::Private(_) => Some(UpdatedProperties::PRIVATE_METADATA),
        }
    }
}

fn change_id(change: Change, is_container: bool) -> Option<u64> {
    if is_container {
        change.container_id()
    } else {
        change.item_id()
    }
}

fn is_kind(change: &Change, is_container: bool) -> bool {
    if is_container {
        change.is_container_change()
    } else {
        change.is_item_change()
    }
}

impl LogRead {
    pub(crate) fn is_truncated(&self) -> bool {
        [self.shared.as_ref(), self.private.as_ref()]
            .into_iter()
            .flatten()
            .any(|changes| changes.is_truncated)
    }

    pub(crate) fn is_valid_since(&self) -> bool {
        let mut logs = [self.shared.as_ref(), self.private.as_ref()]
            .into_iter()
            .flatten()
            .peekable();
        logs.peek().is_none() || logs.any(|changes| changes.from_change_id != 0)
    }

    pub(crate) fn is_empty(&self) -> bool {
        [self.shared.as_ref(), self.private.as_ref()]
            .into_iter()
            .flatten()
            .all(|changes| changes.changes.is_empty() && changes.from_change_id == 0)
    }

    pub(crate) fn bounds(&self, is_container: bool) -> LogBounds {
        let logs = || {
            [self.shared.as_ref(), self.private.as_ref()]
                .into_iter()
                .flatten()
        };
        LogBounds {
            first_change_id: logs()
                .map(|changes| changes.from_change_id)
                .filter(|change_id| *change_id != 0)
                .min()
                .unwrap_or_default(),
            last_change_id: logs()
                .map(|changes| {
                    kind_change_id(changes, is_container).unwrap_or(changes.to_change_id)
                })
                .max()
                .unwrap_or_default(),
            private_change_id: self
                .private
                .as_ref()
                .and_then(|changes| kind_change_id(changes, is_container))
                .unwrap_or_default(),
        }
    }

    pub(crate) fn total(&self, is_container: bool) -> usize {
        let shared = self
            .shared
            .as_ref()
            .map(|changes| changes.changes.as_slice())
            .unwrap_or_default();
        let mut total = shared
            .iter()
            .filter(|change| is_kind(change, is_container))
            .count();
        if let Some(private) = &self.private {
            let shared_ids = shared
                .iter()
                .filter_map(|change| change_id(*change, is_container))
                .collect::<AHashSet<_>>();
            total += private
                .changes
                .iter()
                .filter(|change| is_kind(change, is_container) && change.is_metadata_only())
                .filter_map(|change| change_id(*change, is_container))
                .filter(|id| !shared_ids.contains(id))
                .count();
        }
        total
    }

    pub(crate) fn into_changes(self, is_container: bool) -> ViewerChanges {
        let shared = self
            .shared
            .map(|changes| changes.changes)
            .unwrap_or_default();
        match self.private {
            Some(private) => {
                ViewerChanges::Merged(merge_private(shared, private.changes, is_container))
            }
            None => ViewerChanges::Shared(shared),
        }
    }
}

impl LogBounds {
    pub(crate) fn new_state(
        self,
        current: State,
        next_items_sent: Option<usize>,
        coverage: Coverage,
    ) -> State {
        match (next_items_sent, current, coverage) {
            (Some(items_sent), _, _) => {
                State::new_intermediate(self.first_change_id, self.last_change_id, items_sent)
            }
            (None, State::Initial, Coverage::Latest { viewer_change_id }) => {
                State::new_exact(self.last_change_id.max(viewer_change_id))
            }
            (None, State::Initial, Coverage::Range) => State::new_exact(self.last_change_id),
            (None, current, _) => max_state(current, self.private_change_id),
        }
    }
}

pub(crate) fn private_query(
    query: Query,
    shared: Option<&Changes>,
    known_change_id: u64,
) -> Option<Query> {
    let bound = shared
        .map_or(0, |changes| changes.to_change_id)
        .max(known_change_id);
    match query {
        Query::All => Some(Query::RangeInclusive(0, bound)),
        Query::Since(change_id) => change_id
            .checked_add(1)
            .filter(|from| *from <= bound)
            .map(|from| Query::RangeInclusive(from, bound)),
        Query::SinceInclusive(change_id) => {
            (change_id <= bound).then_some(Query::RangeInclusive(change_id, bound))
        }
        Query::RangeInclusive(..) => Some(query),
    }
}

fn kind_change_id(changes: &Changes, is_container: bool) -> Option<u64> {
    if is_container {
        changes.container_change_id
    } else {
        changes.item_change_id
    }
}

pub(crate) fn merge_private(
    shared: Vec<Change>,
    private: Vec<Change>,
    is_container: bool,
) -> Vec<ViewerChange> {
    let mut merged = shared
        .into_iter()
        .filter(|change| is_kind(change, is_container))
        .map(ViewerChange::Shared)
        .collect::<Vec<_>>();
    let positions = merged
        .iter()
        .enumerate()
        .filter_map(|(position, change)| {
            Some((change_id(change.change(), is_container)?, position))
        })
        .collect::<AHashMap<_, _>>();

    for change in private
        .into_iter()
        .filter(|change| is_kind(change, is_container) && change.is_metadata_only())
    {
        let Some(id) = change_id(change, is_container) else {
            continue;
        };
        match positions
            .get(&id)
            .and_then(|position| merged.get_mut(*position))
        {
            Some(entry) => {
                if let ViewerChange::Shared(shared) = *entry
                    && matches!(
                        shared,
                        Change::UpdateItemMetadata(_) | Change::UpdateContainerPartial(..)
                    )
                {
                    *entry = ViewerChange::SharedAndPrivate(shared);
                }
            }
            None => merged.push(ViewerChange::Private(change)),
        }
    }

    merged
}

pub(crate) fn fill_page<C: PageChange>(
    changes: impl Iterator<Item = C>,
    items_sent: usize,
    max_changes: usize,
    metadata: MetadataChanges,
    partial: PartialProperties,
    response: &mut ChangesResponse<NullObject>,
) -> Page {
    let mut changes = changes
        .filter(|change| metadata == MetadataChanges::Reported || !change.is_metadata_only())
        .skip(items_sent)
        .peekable();
    let mask = match metadata {
        MetadataChanges::Unsupported | MetadataChanges::Ignored => UpdatedProperties::COUNTS,
        MetadataChanges::Reported => UpdatedProperties(u8::MAX),
    };
    let mut updated_properties = Some(UpdatedProperties::default());

    for change in (&mut changes).take(max_changes) {
        match change.change() {
            Change::InsertContainer(id) | Change::InsertItem(id) => {
                response.created.push(id.into());
            }
            Change::DeleteContainer(id) | Change::DeleteItem(id) => {
                response.destroyed.push(id.into());
            }
            Change::UpdateContainer(id)
            | Change::UpdateItem(id)
            | Change::UpdateItemMetadata(id)
            | Change::UpdateContainerPartial(id, _) => {
                response.updated.push(id.into());
                updated_properties = updated_properties.and_then(|properties| {
                    change
                        .properties(partial)
                        .map(|changed| properties.union(changed.intersection(mask)))
                });
            }
        }
    }

    Page {
        has_more: changes.peek().is_some(),
        updated_properties: updated_properties
            .filter(|properties| !response.updated.is_empty() && !properties.is_empty()),
    }
}
