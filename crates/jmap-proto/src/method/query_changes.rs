/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    method::query::{Comparator, Filter, FilterWrapper, QueryRequest},
    object::JmapObject,
    request::deserialize::{DeserializeArguments, deserialize_request},
    types::state::State,
};
use serde::{Deserialize, Deserializer};
use types::id::Id;

#[derive(Debug, Clone)]
pub struct QueryChangesRequest<T: JmapObject> {
    pub account_id: Id,
    pub filter: Vec<Filter<T::Filter>>,
    pub sort: Option<Vec<Comparator<T::Comparator>>>,
    pub since_query_state: State,
    pub max_changes: Option<usize>,
    pub up_to_id: Option<Id>,
    pub calculate_total: Option<bool>,
    pub arguments: T::QueryArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryChangesResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldQueryState")]
    pub old_query_state: State,

    #[serde(rename = "newQueryState")]
    pub new_query_state: State,

    #[serde(rename = "total")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    #[serde(rename = "removed")]
    pub removed: Vec<Id>,

    #[serde(rename = "added")]
    pub added: Vec<AddedItem>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AddedItem {
    pub id: Id,
    pub index: usize,
}

impl AddedItem {
    pub fn new(id: Id, index: usize) -> Self {
        Self { id, index }
    }
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for QueryChangesRequest<T> {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"accountId" => {
                self.account_id = map.next_value()?;
            },
            b"filter" => {
                self.filter = map.next_value::<FilterWrapper<T::Filter>>()?.0;
            },
            b"sort" => {
                self.sort = map.next_value()?;
            },
            b"sinceQueryState" => {
                self.since_query_state = map.next_value()?;
            },
            b"maxChanges" => {
                self.max_changes = map.next_value()?;
            },
            b"upToId" => {
                self.up_to_id = map.next_value()?;
            },
            b"calculateTotal" => {
                self.calculate_total = map.next_value()?;
            },
            _ => {
                self.arguments.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T: JmapObject> Deserialize<'de> for QueryChangesRequest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T: JmapObject> Default for QueryChangesRequest<T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            filter: Vec::new(),
            sort: None,
            since_query_state: State::default(),
            max_changes: None,
            up_to_id: None,
            calculate_total: None,
            arguments: T::QueryArguments::default(),
        }
    }
}

impl<T: JmapObject> From<QueryChangesRequest<T>> for QueryRequest<T> {
    fn from(request: QueryChangesRequest<T>) -> Self {
        QueryRequest {
            account_id: request.account_id,
            filter: request.filter,
            sort: request.sort,
            position: None,
            anchor: None,
            anchor_offset: None,
            limit: None,
            calculate_total: request.calculate_total,
            arguments: request.arguments,
        }
    }
}
