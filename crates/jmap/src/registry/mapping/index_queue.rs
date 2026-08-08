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
use common::Server;
use jmap_proto::{error::set::SetError, object::registry::RegistryComparator, types::state::State};
use registry::{
    jmap::IntoValue,
    schema::{enums::IndexAction, prelude::Property, structs::IndexQueueEntry},
    types::{EnumImpl, datetime::UTCDateTime},
};
use std::str::FromStr;
use store::{
    IterateParams, U32_LEN, ValueKey,
    registry::RegistryFilterOp,
    write::{
        BatchBuilder, SearchIndex, SearchIndexClass, ValueClass, key::DeserializeBigEndian,
        serialize::RawValue,
    },
};
use trc::AddContext;
use types::id::Id;

const QUEUE_INDEXES: [SearchIndex; 5] = [
    SearchIndex::Email,
    SearchIndex::Calendar,
    SearchIndex::Contacts,
    SearchIndex::File,
    SearchIndex::Tracing,
];

const ACCOUNT_INDEXES: [SearchIndex; 4] = [
    SearchIndex::Email,
    SearchIndex::Calendar,
    SearchIndex::Contacts,
    SearchIndex::File,
];

const TRACING_FLAG: u64 = 1 << 63;
const MAX_SPAN_ID: u64 = TRACING_FLAG - 1;
const MAX_ACCOUNT_ID: u32 = (1 << 29) - 1;
const INDEX_SHIFT: u32 = 61;
const ACCOUNT_ID_SHIFT: u32 = 32;

#[derive(Clone, Copy)]
struct QueueId {
    index: SearchIndex,
    id_prefix: u32,
    id_suffix: u32,
}

pub(crate) async fn index_queue_entry_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    if let Some(ids) = get.ids.take() {
        for id in ids {
            let Some(queue_id) = QueueId::parse(id) else {
                get.not_found(id);
                continue;
            };

            match get
                .server
                .store()
                .get_value::<RawValue>(ValueKey::from(queue_id.class()))
                .await
                .caused_by(trc::location!())?
            {
                Some(value) => {
                    let entry = map_entry(&queue_id, &value.0)?.into_value();
                    get.insert(id, entry);
                }
                None => get.not_found(id),
            }
        }
    } else {
        let limit = get.server.core.jmap.get_max_objects;
        let mut entries = Vec::with_capacity(std::cmp::min(limit, 16));

        scan_queue(
            get.server,
            &QUEUE_INDEXES.map(|index| (index, None)),
            true,
            true,
            |queue_id, value| {
                if let Some(id) = queue_id.to_id() {
                    entries.push((id, map_entry(&queue_id, value)?));
                }

                Ok(entries.len() < limit)
            },
        )
        .await?;

        for (id, entry) in entries {
            get.insert(id, entry.into_value());
        }
    }

    Ok(get)
}

pub(crate) async fn index_queue_entry_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let mut action = None;
    let mut account_id = None;

    req.request.extract_filters(|property, op, value| {
        if !matches!(op, RegistryFilterOp::Equal) {
            return false;
        }

        match property {
            Property::Action => {
                if let Some(value) = value.as_str().and_then(IndexAction::parse) {
                    action = Some(value);
                    true
                } else {
                    false
                }
            }
            Property::AccountId => {
                if let Some(value) = value.as_str().and_then(|value| Id::from_str(value).ok()) {
                    account_id = Some(value.document_id());
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
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
            .details("Only sorting by 'id' is supported for index queue entries".to_string()));
    }

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, None)?;

    let action = action.map(action_index);
    let ranges = match (action, account_id) {
        (Some((index, _)), Some(account_id)) if index != SearchIndex::Tracing => {
            vec![(index, Some(account_id))]
        }
        (Some(_), Some(_)) => vec![],
        (Some((index, _)), None) => vec![(index, None)],
        (None, Some(account_id)) => ACCOUNT_INDEXES
            .iter()
            .map(|index| (*index, Some(account_id)))
            .collect(),
        (None, None) => QUEUE_INDEXES.iter().map(|index| (*index, None)).collect(),
    };
    let expected_flag = action.and_then(|(_, flag)| flag);

    let mut response = QueryResponseBuilder::new(
        req.server.core.jmap.query_max_results,
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );
    let mut total = 0;

    scan_queue(
        req.server,
        &ranges,
        params.sort_ascending,
        expected_flag.is_some(),
        |queue_id, value| {
            if expected_flag
                .is_some_and(|flag| !value.first().is_some_and(|value| (*value != 0) == flag))
            {
                return Ok(true);
            }

            let Some(id) = queue_id.to_id() else {
                return Ok(true);
            };

            total += 1;
            if response.response.total.is_some() {
                if !response.is_full() {
                    response.add_id(id);
                }
                Ok(true)
            } else {
                Ok(response.add_id(id))
            }
        },
    )
    .await?;

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

pub(crate) async fn index_queue_entry_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    set.fail_all_create("Index queue entries cannot be created");
    set.fail_all_update("Index queue entries cannot be modified");

    let mut batch = BatchBuilder::new();
    let mut destroyed = Vec::with_capacity(set.destroy.len());

    for id in std::mem::take(&mut set.destroy) {
        let Some(queue_id) = QueueId::parse(id) else {
            set.response.not_destroyed.append(id, SetError::not_found());
            continue;
        };

        let class = queue_id.class();
        if set
            .server
            .store()
            .key_exists(ValueKey::from(class.clone()))
            .await
            .caused_by(trc::location!())?
        {
            batch.clear(class).commit_point();
            destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    if !batch.is_empty() {
        set.server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        set.response.destroyed.extend(destroyed);
    }

    Ok(set)
}

async fn scan_queue(
    server: &Server,
    ranges: &[(SearchIndex, Option<u32>)],
    ascending: bool,
    with_values: bool,
    mut cb: impl FnMut(QueueId, &[u8]) -> trc::Result<bool> + Sync + Send,
) -> trc::Result<()> {
    let mut ranges = ranges.to_vec();
    if !ascending {
        ranges.reverse();
    }

    for (index, account_id) in ranges {
        let (from_key, to_key) = queue_range(index, account_id);
        let mut is_done = false;

        server
            .store()
            .iterate(
                IterateParams::new(from_key, to_key)
                    .set_ascending(ascending)
                    .set_values(with_values),
                |key, value| {
                    let keep_scanning = cb(QueueId::from_key(index, key)?, value)?;
                    is_done = !keep_scanning;

                    Ok(keep_scanning)
                },
            )
            .await
            .caused_by(trc::location!())?;

        if is_done {
            break;
        }
    }

    Ok(())
}

fn queue_range(
    index: SearchIndex,
    account_id: Option<u32>,
) -> (ValueKey<ValueClass>, ValueKey<ValueClass>) {
    let (from_prefix, to_prefix) = match account_id {
        Some(account_id) => (account_id, account_id),
        None => (0, u32::MAX),
    };

    (
        ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
            index,
            id_prefix: from_prefix,
            id_suffix: 0,
        })),
        ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
            index,
            id_prefix: to_prefix,
            id_suffix: u32::MAX,
        })),
    )
}

fn map_entry(queue_id: &QueueId, value: &[u8]) -> trc::Result<IndexQueueEntry> {
    let is_index = value.first().is_some_and(|flag| *flag != 0);
    let created_at = value.deserialize_be_u64(1)?;
    let is_tracing = queue_id.index == SearchIndex::Tracing;

    Ok(IndexQueueEntry {
        action: index_action(queue_id.index, is_index),
        account_id: (!is_tracing).then(|| Id::from(queue_id.id_prefix)),
        document_id: if is_tracing {
            queue_id.span_id()
        } else {
            queue_id.id_suffix as u64
        },
        created_at: UTCDateTime::from_timestamp(created_at as i64),
    })
}

fn index_action(index: SearchIndex, is_index: bool) -> IndexAction {
    match index {
        SearchIndex::Email if is_index => IndexAction::IndexEmail,
        SearchIndex::Email => IndexAction::UnindexEmail,
        SearchIndex::Calendar if is_index => IndexAction::IndexCalendar,
        SearchIndex::Calendar => IndexAction::UnindexCalendar,
        SearchIndex::Contacts if is_index => IndexAction::IndexContacts,
        SearchIndex::Contacts => IndexAction::UnindexContacts,
        SearchIndex::File if is_index => IndexAction::IndexFile,
        SearchIndex::File => IndexAction::UnindexFile,
        SearchIndex::Tracing | SearchIndex::InMemory => IndexAction::IndexTelemetry,
    }
}

fn action_index(action: IndexAction) -> (SearchIndex, Option<bool>) {
    match action {
        IndexAction::IndexTelemetry => (SearchIndex::Tracing, None),
        IndexAction::IndexEmail => (SearchIndex::Email, Some(true)),
        IndexAction::UnindexEmail => (SearchIndex::Email, Some(false)),
        IndexAction::IndexCalendar => (SearchIndex::Calendar, Some(true)),
        IndexAction::UnindexCalendar => (SearchIndex::Calendar, Some(false)),
        IndexAction::IndexContacts => (SearchIndex::Contacts, Some(true)),
        IndexAction::UnindexContacts => (SearchIndex::Contacts, Some(false)),
        IndexAction::IndexFile => (SearchIndex::File, Some(true)),
        IndexAction::UnindexFile => (SearchIndex::File, Some(false)),
    }
}

impl QueueId {
    fn from_key(index: SearchIndex, key: &[u8]) -> trc::Result<Self> {
        Ok(QueueId {
            index,
            id_prefix: key.deserialize_be_u32(1)?,
            id_suffix: key.deserialize_be_u32(1 + U32_LEN)?,
        })
    }

    fn parse(id: Id) -> Option<Self> {
        let id = id.id();

        Some(if id & TRACING_FLAG != 0 {
            let span_id = id & MAX_SPAN_ID;

            QueueId {
                index: SearchIndex::Tracing,
                id_prefix: (span_id >> 32) as u32,
                id_suffix: span_id as u32,
            }
        } else {
            QueueId {
                index: SearchIndex::try_from_u8((id >> INDEX_SHIFT) as u8)?,
                id_prefix: ((id >> ACCOUNT_ID_SHIFT) as u32) & MAX_ACCOUNT_ID,
                id_suffix: id as u32,
            }
        })
    }

    fn to_id(self) -> Option<Id> {
        if self.index == SearchIndex::Tracing {
            let span_id = self.span_id();

            (span_id <= MAX_SPAN_ID).then(|| Id::from(TRACING_FLAG | span_id))
        } else {
            (self.id_prefix <= MAX_ACCOUNT_ID).then(|| {
                Id::from(
                    ((self.index.to_u8() as u64) << INDEX_SHIFT)
                        | ((self.id_prefix as u64) << ACCOUNT_ID_SHIFT)
                        | self.id_suffix as u64,
                )
            })
        }
    }

    fn span_id(&self) -> u64 {
        ((self.id_prefix as u64) << 32) | self.id_suffix as u64
    }

    fn class(&self) -> ValueClass {
        ValueClass::SearchIndex(SearchIndexClass::Queue {
            index: self.index,
            id_prefix: self.id_prefix,
            id_suffix: self.id_suffix,
        })
    }
}
