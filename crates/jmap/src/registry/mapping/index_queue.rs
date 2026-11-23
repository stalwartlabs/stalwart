/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use common::{Server, storage::search::SearchIndexStatus};
use jmap_proto::{error::set::SetError, object::registry::RegistryComparator, types::state::State};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    schema::{
        enums::{IndexStatusType, IndexType},
        prelude::Property,
        structs::{IndexQueueStatus, IndexStatus, IndexStatusFailed},
    },
    types::{EnumImpl, datetime::UTCDateTime},
};
use store::{
    IterateParams, U32_LEN, ValueKey,
    registry::RegistryFilterOp,
    write::{
        BatchBuilder, QueueNotify, SearchIndex, SearchIndexClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::id::Id;

const MAX_QUEUED_ITEMS: u64 = 10000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueuePartition {
    index: SearchIndex,
    partition: u32,
}

pub(crate) async fn index_queue_status_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        scan_partitions(
            get.server,
            None,
            None,
            None,
            get.server.core.jmap.get_max_objects,
            true,
        )
        .await?
    };

    // Counting the queued documents of every partition is bounded by a single budget
    // shared by the whole request
    let mut budget = MAX_QUEUED_ITEMS;

    for id in ids {
        match QueuePartition::from_id(id) {
            Some(partition) => match build_status(get.server, partition, &mut budget).await? {
                Some(status) => get.insert(id, status.into_value()),
                None => get.not_found(id),
            },
            None => get.not_found(id),
        }
    }

    Ok(get)
}

pub(crate) async fn index_queue_status_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut index = None;
    let mut partition = None;
    let mut status = None;

    req.request
        .extract_filters(|property, op, value| match property {
            Property::Index => {
                if matches!(op, RegistryFilterOp::Equal)
                    && let Some(index_) = value
                        .as_str()
                        .and_then(IndexType::parse)
                        .and_then(search_index)
                {
                    index = Some(index_);
                    true
                } else {
                    false
                }
            }
            Property::Partition => {
                if matches!(op, RegistryFilterOp::Equal)
                    && let Some(partition_) = value
                        .as_str()
                        .and_then(|v| v.parse::<u32>().ok())
                        .or_else(|| value.as_u64().and_then(|v| u32::try_from(v).ok()))
                {
                    partition = Some(partition_);
                    true
                } else {
                    false
                }
            }
            Property::Status => {
                if matches!(op, RegistryFilterOp::Equal)
                    && let Some(status_) = value.as_str().and_then(IndexStatusType::parse)
                {
                    status = Some(status_);
                    true
                } else {
                    false
                }
            }
            _ => false,
        })?;

    if req
        .request
        .sort
        .as_ref()
        .and_then(|sort| sort.first())
        .is_some_and(|comp| !matches!(comp.property, RegistryComparator::Property(Property::Id)))
    {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Only sorting by 'id' is supported for index queues"));
    }

    // Paging by anchor is resolved by the response builder, which needs the full result set
    let has_anchor = req.request.anchor.is_some();
    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;
    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results + 1,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    let max_partitions = match req.request.position {
        _ if has_anchor || response.response.total.is_some() => usize::MAX,
        Some(position) if position < 0 => usize::MAX,
        position => usize::try_from(position.unwrap_or(0))
            .unwrap_or(usize::MAX)
            .saturating_add(response.limit)
            .saturating_add(1),
    };
    let partitions = scan_partitions(
        req.server,
        index,
        partition,
        status,
        max_partitions,
        params.sort_ascending,
    )
    .await?;

    let mut total = 0;
    for id in partitions {
        total += 1;
        if response.response.total.is_some() {
            if !response.is_full() {
                response.add_id(id);
            }
        } else if !response.add_id(id) {
            break;
        }
    }

    if response.response.total.is_some() {
        response.response.total = Some(total);
    }

    if let Some(limit) = response.response.limit
        && total < limit
    {
        response.response.limit = None;
    }

    Ok(response)
}

pub(crate) async fn index_queue_status_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    set.fail_all_create("Index queues cannot be created");
    set.fail_all_destroy("Index queues cannot be deleted");

    let mut batch = BatchBuilder::new();
    let mut has_changes = false;

    'outer: for (id, value) in set.update.drain(..) {
        let Some(partition) = QueuePartition::from_id(id) else {
            set.response.not_updated.append(id, SetError::not_found());
            continue;
        };

        let stored = set
            .server
            .search_index_status(partition.index, partition.partition)
            .await
            .caused_by(trc::location!())?;
        let attempts = stored.as_ref().map_or(0, |stored| stored.attempts);
        let Some(mut status) = status_object(partition, 0, 0, stored) else {
            set.response.not_updated.append(id, SetError::not_found());
            continue;
        };
        let previous = status.status.clone();

        for (key, value) in value.into_expanded_object() {
            let ptr = match key {
                Key::Property(prop) => {
                    JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                }
                Key::Borrowed(other) => JsonPointer::parse(other),
                Key::Owned(other) => JsonPointer::parse(&other),
            };

            if let Err(err) = status.patch(JsonPointerPatch::new(&ptr).with_create(false), value) {
                set.response.not_updated.append(id, err.into());
                continue 'outer;
            }
        }

        if status.status != previous {
            match &status.status {
                IndexStatus::Running => {
                    batch.clear(partition.status_class());
                }
                IndexStatus::Failed(failed) => {
                    batch.set(
                        partition.status_class(),
                        SearchIndexStatus {
                            next_retry: failed.next_retry.timestamp().max(0) as u64,
                            attempts,
                            reason: failed.reason.clone(),
                        }
                        .serialize(),
                    );
                }
            }

            batch.commit_point();
            has_changes = true;
        }

        set.response.updated.append(id, None);
    }

    if has_changes {
        set.server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
        set.server
            .notify_queues(QueueNotify {
                search_index: true,
                ..Default::default()
            })
            .await;
    }

    Ok(set)
}

async fn build_status(
    server: &Server,
    partition: QueuePartition,
    budget: &mut u64,
) -> trc::Result<Option<IndexQueueStatus>> {
    let stored = server
        .search_index_status(partition.index, partition.partition)
        .await
        .caused_by(trc::location!())?;
    let (queued_updates, queued_deletions) = queued_items(server, partition, budget)
        .await
        .caused_by(trc::location!())?;

    if stored.is_none() && queued_updates == 0 && queued_deletions == 0 {
        return Ok(None);
    }

    Ok(status_object(
        partition,
        queued_updates,
        queued_deletions,
        stored,
    ))
}

fn status_object(
    partition: QueuePartition,
    queued_updates: u64,
    queued_deletions: u64,
    stored: Option<SearchIndexStatus>,
) -> Option<IndexQueueStatus> {
    Some(IndexQueueStatus {
        index: index_type(partition.index)?,
        partition: partition.partition as u64,
        queued_updates,
        queued_deletions,
        status: match stored {
            Some(stored) => IndexStatus::Failed(IndexStatusFailed {
                reason: stored.reason,
                next_retry: UTCDateTime::from_timestamp(stored.next_retry as i64),
            }),
            None => IndexStatus::Running,
        },
    })
}

async fn queued_items(
    server: &Server,
    partition: QueuePartition,
    budget: &mut u64,
) -> trc::Result<(u64, u64)> {
    if *budget == 0 {
        return Ok((0, 0));
    }

    let (from_class, to_class) =
        SearchIndexClass::queue_range(partition.index, partition.partition);
    let mut queued_updates = 0;
    let mut queued_deletions = 0;

    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::SearchIndex(from_class)),
                ValueKey::from(ValueClass::SearchIndex(to_class)),
            )
            .limit(usize::try_from(*budget).unwrap_or(usize::MAX)),
            |_, value| {
                if value.first().is_some_and(|flag| *flag != 0) {
                    queued_updates += 1;
                } else {
                    queued_deletions += 1;
                }

                Ok(queued_updates + queued_deletions < *budget)
            },
        )
        .await?;

    *budget -= queued_updates + queued_deletions;

    Ok((queued_updates, queued_deletions))
}

async fn scan_partitions(
    server: &Server,
    index: Option<SearchIndex>,
    partition: Option<u32>,
    status: Option<IndexStatusType>,
    max_results: usize,
    ascending: bool,
) -> trc::Result<Vec<Id>> {
    let (from_key, to_key) = SearchIndexClass::control_range(
        (index.unwrap_or(SearchIndex::Email), partition.unwrap_or(0)),
        index.map(|index| (index, partition.unwrap_or(u32::MAX))),
    );

    // Every partition is stored as a queue index key optionally followed by a status key,
    // so a partition is only emitted once the next key reveals whether it has a status
    let mut ids: Vec<Id> = Vec::new();
    let mut pending: Option<(QueuePartition, bool)> = None;
    let matches_status = |has_status: bool| match status {
        Some(IndexStatusType::Failed) => has_status,
        Some(IndexStatusType::Running) => !has_status,
        None => true,
    };

    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key)
                .set_ascending(ascending)
                .no_values()
                .expect_rows(max_results.saturating_mul(2).saturating_add(2)),
            |key, _| {
                if key.len() != U32_LEN + 3 {
                    return Ok(true);
                }
                let Some(index) = SearchIndex::try_from_u8(key[1]) else {
                    return Ok(true);
                };
                let queue_partition = QueuePartition {
                    index,
                    partition: key.deserialize_be_u32(2)?,
                };
                if partition.is_some_and(|partition| partition != queue_partition.partition) {
                    return Ok(true);
                }
                let is_status = key[U32_LEN + 2] == SearchIndexClass::CONTROL_STATUS;

                match &mut pending {
                    Some((last, has_status)) if *last == queue_partition => {
                        *has_status |= is_status;
                        return Ok(true);
                    }
                    _ => (),
                }

                if let Some((last, has_status)) = pending.replace((queue_partition, is_status))
                    && matches_status(has_status)
                {
                    ids.push(last.to_id());
                    if ids.len() >= max_results {
                        pending = None;
                        return Ok(false);
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if let Some((last, has_status)) = pending
        && matches_status(has_status)
        && ids.len() < max_results
    {
        ids.push(last.to_id());
    }

    Ok(ids)
}

impl QueuePartition {
    fn from_id(id: Id) -> Option<Self> {
        let id = id.id();

        if id >> 40 != 0 {
            return None;
        }

        SearchIndex::try_from_u8((id >> 32) as u8).map(|index| QueuePartition {
            index,
            partition: id as u32,
        })
    }

    fn to_id(self) -> Id {
        Id::from(((self.index.to_u8() as u64) << 32) | self.partition as u64)
    }

    fn status_class(&self) -> ValueClass {
        ValueClass::SearchIndex(SearchIndexClass::QueueStatus {
            index: self.index,
            partition: self.partition,
        })
    }
}

fn index_type(index: SearchIndex) -> Option<IndexType> {
    match index {
        SearchIndex::Email => Some(IndexType::Email),
        SearchIndex::Calendar => Some(IndexType::Calendar),
        SearchIndex::Contacts => Some(IndexType::Contacts),
        SearchIndex::File => Some(IndexType::File),
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        SearchIndex::Tracing | SearchIndex::InMemory => Some(IndexType::Telemetry),
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        SearchIndex::Tracing | SearchIndex::InMemory => None,
    }
}

fn search_index(index: IndexType) -> Option<SearchIndex> {
    match index {
        IndexType::Email => Some(SearchIndex::Email),
        IndexType::Calendar => Some(SearchIndex::Calendar),
        IndexType::Contacts => Some(SearchIndex::Contacts),
        IndexType::File => Some(SearchIndex::File),
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        IndexType::Telemetry => Some(SearchIndex::Tracing),
        // SPDX-SnippetEnd
    }
}
