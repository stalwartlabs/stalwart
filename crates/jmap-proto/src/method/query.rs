/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::JmapObject,
    request::deserialize::{DeserializeArguments, deserialize_request},
    types::state::State,
};
use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::{
    borrow::Cow,
    fmt::{self},
};
use types::id::Id;

#[derive(Debug, Clone)]
pub struct QueryRequest<T: JmapObject> {
    pub account_id: Id,
    pub filter: Vec<Filter<T::Filter>>,
    pub sort: Option<Vec<Comparator<T::Comparator>>>,
    pub position: Option<i32>,
    pub anchor: Option<Id>,
    pub anchor_offset: Option<i32>,
    pub limit: Option<usize>,
    pub calculate_total: Option<bool>,
    pub arguments: T::QueryArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "queryState")]
    pub query_state: State,

    #[serde(rename = "canCalculateChanges")]
    pub can_calculate_changes: bool,

    #[serde(rename = "position")]
    pub position: i32,

    #[serde(rename = "ids")]
    pub ids: Vec<Id>,

    #[serde(rename = "total")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    #[serde(rename = "limit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum Filter<T>
where
    T: for<'de> DeserializeArguments<'de> + Default,
{
    Property(T),
    And,
    Or,
    Not,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparator<T>
where
    T: for<'de> DeserializeArguments<'de> + Default,
{
    pub is_ascending: bool,
    pub collation: Option<String>,
    pub property: T,
}

impl<'de, T: JmapObject> DeserializeArguments<'de> for QueryRequest<T> {
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
            b"calculateTotal" => {
                self.calculate_total = map.next_value()?;
            },
            b"position" => {
                self.position = map.next_value()?;
            },
            b"anchor" => {
                self.anchor = map.next_value()?;
            },
            b"anchorOffset" => {
                self.anchor_offset = map.next_value()?;
            },
            b"limit" => {
                self.limit = map.next_value()?;
            },
            _ => {
                self.arguments.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T: JmapObject> Deserialize<'de> for QueryRequest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T: JmapObject> Default for QueryRequest<T> {
    fn default() -> Self {
        Self {
            account_id: Id::default(),
            filter: vec![],
            sort: None,
            position: None,
            anchor: None,
            anchor_offset: None,
            limit: None,
            calculate_total: None,
            arguments: T::QueryArguments::default(),
        }
    }
}

struct FilterMapCollector<'x, T: 'x>(&'x mut Vec<Filter<T>>)
where
    T: for<'de> DeserializeArguments<'de> + Default;

struct FilterListCollector<'x, T: 'x>(&'x mut Vec<Filter<T>>)
where
    T: for<'de> DeserializeArguments<'de> + Default;

pub(super) struct FilterWrapper<T>(pub Vec<Filter<T>>)
where
    T: for<'de> DeserializeArguments<'de> + Default;

impl<'de, T> Deserialize<'de> for FilterWrapper<T>
where
    T: for<'de2> DeserializeArguments<'de2> + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut items = Vec::new();
        FilterMapCollector(&mut items)
            .deserialize(deserializer)
            .map(|_| FilterWrapper(items))
    }
}

impl<'de, 'x, T> DeserializeSeed<'de> for FilterMapCollector<'x, T>
where
    T: for<'de2> DeserializeArguments<'de2> + Default,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FilterVisitor<'x, T: 'x>(&'x mut Vec<Filter<T>>)
        where
            T: for<'de2> DeserializeArguments<'de2> + Default;

        impl<'de, 'x, T> Visitor<'de> for FilterVisitor<'x, T>
        where
            T: for<'de2> DeserializeArguments<'de2> + Default,
        {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a filter object")
            }

            fn visit_map<V>(self, mut map: V) -> Result<(), V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut filter = None;
                let mut has_multiple_filters = false;
                let mut has_conditions = None;
                let mut op = None;

                while let Some(key) = map.next_key::<Cow<str>>()? {
                    match key.len() {
                        8 if key == "operator" => {
                            let op_ = hashify::tiny_map!(
                                map.next_value::<&str>()?.as_bytes(),
                                "AND" => Filter::And,
                                "OR" => Filter::Or,
                                "NOT" => Filter::Not,
                            )
                            .ok_or_else(|| {
                                de::Error::custom(format!("Unknown filter operator: {}", key))
                            })?;

                            if let Some(pos) = has_conditions {
                                self.0[pos] = op_;
                            } else {
                                op = Some(op_);
                            }
                        }
                        10 if key == "conditions" => {
                            has_conditions = Some(self.0.len());
                            self.0.push(op.take().unwrap_or(Filter::And));
                            map.next_value_seed(FilterListCollector(self.0))?;
                            self.0.push(Filter::Close);
                        }
                        _ => {
                            if let Some(filter) = filter {
                                if !has_multiple_filters {
                                    self.0.push(Filter::And);
                                    has_multiple_filters = true;
                                }
                                self.0.push(Filter::Property(filter));
                            }
                            let mut new_filter = T::default();
                            new_filter.deserialize_argument(&key, &mut map)?;
                            filter = Some(new_filter);
                        }
                    }
                }

                if let Some(filter) = filter {
                    if has_conditions.is_some() {
                        return Err(de::Error::custom(
                            "Cannot mix conditions with property filters",
                        ));
                    }

                    self.0.push(Filter::Property(filter));
                    if has_multiple_filters {
                        self.0.push(Filter::Close);
                    }
                }

                Ok(())
            }
        }

        deserializer.deserialize_map(FilterVisitor(self.0))
    }
}

impl<'de, 'x, T> DeserializeSeed<'de> for FilterListCollector<'x, T>
where
    T: for<'de2> DeserializeArguments<'de2> + Default,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FilterVisitor<'x, T: 'x>(&'x mut Vec<Filter<T>>)
        where
            T: for<'de2> DeserializeArguments<'de2> + Default;

        impl<'de, 'x, T> Visitor<'de> for FilterVisitor<'x, T>
        where
            T: for<'de2> DeserializeArguments<'de2> + Default,
        {
            type Value = ();

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a filter list")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<(), A::Error>
            where
                A: SeqAccess<'de>,
            {
                while let Some(()) = seq.next_element_seed(FilterMapCollector(self.0))? {}
                Ok(())
            }
        }

        deserializer.deserialize_seq(FilterVisitor(self.0))
    }
}

impl<'de, T> DeserializeArguments<'de> for Comparator<T>
where
    T: for<'de2> DeserializeArguments<'de2> + Default,
{
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"isAscending" => {
                self.is_ascending = map.next_value()?;
            },
            b"collation" => {
                self.collation = map.next_value()?;
            },
            _ => {
                self.property.deserialize_argument(key, map)?;
            }
        );

        Ok(())
    }
}

impl<'de, T> Deserialize<'de> for Comparator<T>
where
    T: for<'de2> DeserializeArguments<'de2> + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_request(deserializer)
    }
}

impl<T> Comparator<T>
where
    T: for<'de> DeserializeArguments<'de> + Default,
{
    pub fn descending(property: T) -> Self {
        Self {
            property,
            is_ascending: false,
            collation: None,
        }
    }

    pub fn ascending(property: T) -> Self {
        Self {
            property,
            is_ascending: true,
            collation: None,
        }
    }
}

impl<T> Default for Comparator<T>
where
    T: for<'de> DeserializeArguments<'de> + Default,
{
    fn default() -> Self {
        Self {
            is_ascending: true,
            collation: None,
            property: T::default(),
        }
    }
}
