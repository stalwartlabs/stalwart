/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, SUBSPACE_REGISTRY_IDX, SUBSPACE_REGISTRY_PK, Store, U16_LEN,
    U64_LEN, ValueKey,
    registry::{
        RegistryFilter, RegistryFilterOp, RegistryFilterValue, RegistryObjectCounter,
        RegistryQuery, RegistryQueryStart,
    },
    write::{
        AnyClass, RegistryClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use ahash::AHashSet;
use registry::{
    schema::prelude::{OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, OBJ_SINGLETON, ObjectType, Property},
    types::{EnumImpl, id::ObjectId},
};
use roaring::RoaringBitmap;
use std::{borrow::Cow, ops::BitAndAssign};
use trc::AddContext;
use types::id::Id;

impl RegistryStore {
    pub async fn query<T: RegistryQueryResults>(&self, query: RegistryQuery) -> trc::Result<T> {
        if query.filters.is_empty() {
            return all_ids::<T>(&self.0.store, query).await;
        }

        let mut u64_buffer;
        let mut u16_buffer;
        let mut bool_buffer = [0u8; 1];

        let mut results = ResultsPagination::<T>::new(&query);
        for filter in &query.filters {
            if filter.op == RegistryFilterOp::TextMatch {
                if let RegistryFilterValue::String(text) = &filter.value {
                    let mut matches = ResultsPagination::<T>::new(&query);

                    for word in text
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|s| s.len() > 1)
                    {
                        let word = if word
                            .chars()
                            .all(|ch| ch.is_lowercase() || !ch.is_alphabetic())
                        {
                            Cow::Borrowed(word)
                        } else {
                            Cow::Owned(word.to_lowercase())
                        };

                        let mut result = ResultsPagination::<T>::new(&query);

                        index_range(
                            &self.0.store,
                            query.object_type,
                            filter.property.to_id(),
                            word.as_bytes(),
                            RegistryFilterOp::Equal,
                            &mut result,
                        )
                        .await?;

                        if !matches.list.has_items() {
                            matches = result;
                        } else {
                            matches.list.intersect(&result.list);
                            if !matches.list.has_items() {
                                break;
                            }
                        }
                    }

                    if !results.list.has_items() {
                        results = matches;
                    } else {
                        results.list.intersect(&matches.list);
                    }
                } else {
                    return Err(trc::EventType::Registry(trc::RegistryEvent::NotSupported)
                        .into_err()
                        .details("TextMatch operator only supports string values"));
                }
            } else {
                let value = match &filter.value {
                    RegistryFilterValue::String(v) => v.as_bytes(),
                    RegistryFilterValue::Bytes(v) => v.as_slice(),
                    RegistryFilterValue::U64(v) => {
                        u64_buffer = v.to_be_bytes();
                        &u64_buffer
                    }
                    RegistryFilterValue::U16(v) => {
                        u16_buffer = v.to_be_bytes();
                        &u16_buffer
                    }
                    RegistryFilterValue::Boolean(v) => {
                        bool_buffer[0] = *v as u8;
                        &bool_buffer
                    }
                };

                let mut result = ResultsPagination::<T>::new(&query);
                if !filter.is_pk {
                    index_range(
                        &self.0.store,
                        query.object_type,
                        filter.property.to_id(),
                        value,
                        filter.op,
                        &mut result,
                    )
                    .await?
                } else {
                    pk_range(
                        &self.0.store,
                        query.object_type,
                        filter.property.to_id(),
                        value,
                        filter.op,
                        &mut result,
                    )
                    .await?
                };

                if !results.list.has_items() {
                    results = result;
                } else {
                    results.list.intersect(&result.list);
                }
            }

            if !results.list.has_items() {
                break;
            }
        }

        Ok(results.finalize())
    }

    pub async fn count_object(&self, object_type: ObjectType) -> trc::Result<usize> {
        if object_type.flags() & OBJ_SINGLETON == 0 {
            self.query::<RegistryObjectCounter>(RegistryQuery::new(object_type))
                .await
                .map(|r| r.0)
        } else {
            self.store()
                .key_exists(ValueKey::from(RegistryClass::Item {
                    object_id: object_type.to_id(),
                    item_id: Id::singleton().id(),
                }))
                .await
                .caused_by(trc::location!())
                .map(|exists| if exists { 1 } else { 0 })
        }
    }

    pub async fn primary_key(
        &self,
        object_type: Option<ObjectType>,
        property: Property,
        key: Vec<u8>,
    ) -> trc::Result<Option<ObjectId>> {
        self.store()
            .get_value::<ObjectId>(ValueKey::from(ValueClass::Registry(
                RegistryClass::PrimaryKey {
                    object_id: object_type.map(|obj| obj.to_id()),
                    index_id: property.to_id(),
                    key,
                },
            )))
            .await
    }

    pub async fn sort_by_index(
        &self,
        object: ObjectType,
        property: Property,
        ids: Option<Vec<Id>>,
        ascending: bool,
    ) -> trc::Result<Vec<Id>> {
        let mut ids = ids.map(|ids| ids.into_iter().collect::<AHashSet<_>>());
        let mut ids_sorted = Vec::with_capacity(ids.as_ref().map_or(0, |ids| ids.len()));

        let object_id = object.to_id();
        let index_id = property.to_id();
        let begin = ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_REGISTRY_IDX,
            key: KeySerializer::new(U16_LEN * 2)
                .write(object_id)
                .write(index_id)
                .finalize(),
        }));
        let end = ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_REGISTRY_IDX,
            key: KeySerializer::new((U16_LEN * 2) + U64_LEN)
                .write(object_id)
                .write(index_id)
                .write(u64::MAX)
                .finalize(),
        }));

        self.0
            .store
            .iterate(
                IterateParams::new(begin, end)
                    .no_values()
                    .set_ascending(ascending),
                |key, _| {
                    let id = Id::from(key.deserialize_be_u64(key.len() - U64_LEN)?);
                    if let Some(ids) = ids.as_mut() {
                        if ids.remove(&id) {
                            ids_sorted.push(id);
                        }
                        Ok(!ids.is_empty())
                    } else {
                        ids_sorted.push(id);
                        Ok(true)
                    }
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| {
                if let Some(mut ids) = ids
                    && !ids.is_empty()
                {
                    ids_sorted.extend(ids.drain());
                }

                ids_sorted
            })
    }

    pub async fn sort_by_pk(
        &self,
        object: ObjectType,
        property: Property,
        ids: Option<Vec<Id>>,
        ascending: bool,
    ) -> trc::Result<Vec<Id>> {
        let mut ids = ids.map(|ids| ids.into_iter().collect::<AHashSet<_>>());
        let mut ids_sorted = Vec::with_capacity(ids.as_ref().map_or(0, |ids| ids.len()));

        let object_id = object.to_id();
        let index_id = property.to_id();
        let begin = ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_REGISTRY_PK,
            key: KeySerializer::new(U16_LEN * 2)
                .write(object_id)
                .write(index_id)
                .finalize(),
        }));
        let end = ValueKey::from(ValueClass::Any(AnyClass {
            subspace: SUBSPACE_REGISTRY_PK,
            key: KeySerializer::new((U16_LEN * 2) + U64_LEN)
                .write(object_id)
                .write(index_id)
                .write(u64::MAX)
                .finalize(),
        }));

        self.0
            .store
            .iterate(
                IterateParams::new(begin, end).set_ascending(ascending),
                |_, value| {
                    let id = Id::from(value.deserialize_be_u64(U16_LEN)?);

                    if let Some(ids) = ids.as_mut() {
                        if ids.remove(&id) {
                            ids_sorted.push(id);
                        }
                        Ok(!ids.is_empty())
                    } else {
                        ids_sorted.push(id);
                        Ok(true)
                    }
                },
            )
            .await
            .caused_by(trc::location!())
            .map(|_| {
                if let Some(mut ids) = ids
                    && !ids.is_empty()
                {
                    ids_sorted.extend(ids.drain());
                }

                ids_sorted
            })
    }
}

async fn all_ids<T: RegistryQueryResults>(store: &Store, query: RegistryQuery) -> trc::Result<T> {
    let mut bm = T::default();
    let object_id = query.object_type.to_id();

    let (item_id, mut offset) = match query.start {
        RegistryQueryStart::Index(index) => (0, index),
        RegistryQueryStart::Anchor(anchor) => (anchor + 1, 0),
        RegistryQueryStart::None => (0, 0),
    };

    store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Registry(RegistryClass::IndexId {
                    object_id,
                    item_id,
                })),
                ValueKey::from(ValueClass::Registry(RegistryClass::IndexId {
                    object_id,
                    item_id: u64::MAX,
                })),
            )
            .no_values()
            .ascending(),
            |key, _| {
                if offset == 0 {
                    bm.push(key.deserialize_be_u64(U16_LEN * 2)?);
                    Ok(query.limit.is_none_or(|limit| bm.count() < limit))
                } else {
                    offset -= 1;
                    Ok(true)
                }
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| bm)
}

async fn index_range<T: RegistryQueryResults>(
    store: &Store,
    object: ObjectType,
    index_id: u16,
    match_value: &[u8],
    op: RegistryFilterOp,
    results: &mut ResultsPagination<T>,
) -> trc::Result<()> {
    let ((from_value, from_doc_id, from_index_id), (end_value, end_doc_id, end_index_id)) = match op
    {
        RegistryFilterOp::LowerThan => ((&[][..], 0, index_id), (match_value, 0, index_id)),
        RegistryFilterOp::LowerEqualThan => {
            ((&[][..], 0, index_id), (match_value, u64::MAX, index_id))
        }
        RegistryFilterOp::GreaterThan => (
            (match_value, u64::MAX, index_id),
            (&[][..], u64::MAX, index_id + 1),
        ),
        RegistryFilterOp::GreaterEqualThan => (
            (match_value, 0, index_id),
            (&[][..], u64::MAX, index_id + 1),
        ),
        RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => (
            (match_value, 0, index_id),
            (match_value, u64::MAX, index_id),
        ),
    };

    let object_id = object.to_id();
    let begin = ValueKey::from(ValueClass::Any(AnyClass {
        subspace: SUBSPACE_REGISTRY_IDX,
        key: KeySerializer::new((U16_LEN * 2) + U64_LEN + from_value.len())
            .write(object_id)
            .write(from_index_id)
            .write(from_value)
            .write(from_doc_id)
            .finalize(),
    }));
    let end = ValueKey::from(ValueClass::Any(AnyClass {
        subspace: SUBSPACE_REGISTRY_IDX,
        key: KeySerializer::new((U16_LEN * 2) + U64_LEN + end_value.len())
            .write(object_id)
            .write(end_index_id)
            .write(end_value)
            .write(end_doc_id)
            .finalize(),
    }));

    let prefix = KeySerializer::new(U16_LEN * 2)
        .write(object_id)
        .write(index_id)
        .finalize();

    store
        .iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                if !key.starts_with(&prefix) {
                    return Ok(false);
                }

                let id_pos = key.len() - U64_LEN;
                let value = key
                    .get(U16_LEN * 2..id_pos)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                let matches = match op {
                    RegistryFilterOp::LowerThan => value < match_value,
                    RegistryFilterOp::LowerEqualThan => value <= match_value,
                    RegistryFilterOp::GreaterThan => value > match_value,
                    RegistryFilterOp::GreaterEqualThan => value >= match_value,
                    RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => value == match_value,
                };

                if matches {
                    Ok(results.push(key.deserialize_be_u64(id_pos)?))
                } else {
                    Ok(true)
                }
            },
        )
        .await
        .caused_by(trc::location!())
        .inspect(|_| results.list.sort())
}

async fn pk_range<T: RegistryQueryResults>(
    store: &Store,
    object: ObjectType,
    index_id: u16,
    match_value: &[u8],
    op: RegistryFilterOp,
    results: &mut ResultsPagination<T>,
) -> trc::Result<()> {
    let ((from_value, from_index_id), (end_value, end_index_id)) = match op {
        RegistryFilterOp::LowerThan => ((&[][..], index_id), (match_value, index_id)),
        RegistryFilterOp::LowerEqualThan => ((&[][..], index_id), (match_value, index_id)),
        RegistryFilterOp::GreaterThan => ((match_value, index_id), (&[][..], index_id + 1)),
        RegistryFilterOp::GreaterEqualThan => ((match_value, index_id), (&[][..], index_id + 1)),
        RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => {
            ((match_value, index_id), (match_value, index_id))
        }
    };

    let object_id = object.to_id();
    let begin = ValueKey::from(ValueClass::Any(AnyClass {
        subspace: SUBSPACE_REGISTRY_PK,
        key: KeySerializer::new((U16_LEN * 2) + from_value.len())
            .write(object_id)
            .write(from_index_id)
            .write(from_value)
            .finalize(),
    }));
    let end = ValueKey::from(ValueClass::Any(AnyClass {
        subspace: SUBSPACE_REGISTRY_PK,
        key: KeySerializer::new((U16_LEN * 2) + end_value.len())
            .write(object_id)
            .write(end_index_id)
            .write(end_value)
            .finalize(),
    }));

    let prefix = KeySerializer::new(U16_LEN * 2)
        .write(object_id)
        .write(index_id)
        .finalize();

    store
        .iterate(IterateParams::new(begin, end).ascending(), |key, value| {
            if !key.starts_with(&prefix) {
                return Ok(false);
            }

            let key = key
                .get(U16_LEN * 2..)
                .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

            let matches = match op {
                RegistryFilterOp::LowerThan => key < match_value,
                RegistryFilterOp::LowerEqualThan => key <= match_value,
                RegistryFilterOp::GreaterThan => key > match_value,
                RegistryFilterOp::GreaterEqualThan => key >= match_value,
                RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => key == match_value,
            };

            if matches {
                Ok(results.push(value.deserialize_be_u64(U16_LEN)?))
            } else {
                Ok(true)
            }
        })
        .await
        .caused_by(trc::location!())
        .inspect(|_| results.list.sort())
}

pub trait RegistryQueryResults: Default + Sized + Sync + Send {
    fn push(&mut self, id: u64);
    fn has_items(&self) -> bool;
    fn intersect(&mut self, other: &Self);
    fn count(&self) -> usize;
    fn sort(&mut self);
    fn into_list(self) -> impl Iterator<Item = u64>;
}

impl RegistryQueryResults for Vec<Id> {
    fn push(&mut self, id: u64) {
        self.push(Id::new(id));
    }

    fn has_items(&self) -> bool {
        !self.is_empty()
    }

    fn intersect(&mut self, other: &Self) {
        let a = self;
        let b = other;
        let mut i = 0;
        let mut j = 0;
        let mut write = 0;

        while i < a.len() && j < b.len() {
            if a[i] < b[j] {
                let target = b[j];
                let remain = &a[i..];
                i += remain.partition_point(|&x| x < target);
            } else if a[i] > b[j] {
                let target = a[i];
                let remain = &b[j..];
                j += remain.partition_point(|&x| x < target);
            } else {
                a[write] = a[i];
                write += 1;
                i += 1;
                j += 1;
            }
        }
        a.truncate(write);
    }

    fn count(&self) -> usize {
        self.len()
    }

    fn sort(&mut self) {
        match self.len() {
            0 | 1 => {}
            ..3000 => self.sort_unstable(),
            _ => radsort::sort_by_key(self, |id| id.id()),
        }
    }

    fn into_list(self) -> impl Iterator<Item = u64> {
        self.into_iter().map(|id| id.id())
    }
}

impl RegistryQueryResults for RoaringBitmap {
    fn push(&mut self, id: u64) {
        self.insert(id as u32);
    }

    fn has_items(&self) -> bool {
        !self.is_empty()
    }

    fn intersect(&mut self, other: &Self) {
        self.bitand_assign(other);
    }

    fn count(&self) -> usize {
        self.len() as usize
    }

    fn sort(&mut self) {}

    fn into_list(self) -> impl Iterator<Item = u64> {
        self.into_iter().map(|id| id as u64)
    }
}

impl RegistryQueryResults for RegistryObjectCounter {
    fn push(&mut self, _: u64) {
        self.0 += 1;
    }

    fn has_items(&self) -> bool {
        self.0 > 0
    }

    fn intersect(&mut self, _: &Self) {
        unimplemented!()
    }

    fn count(&self) -> usize {
        self.0
    }

    fn sort(&mut self) {}

    fn into_list(self) -> impl Iterator<Item = u64> {
        Vec::new().into_iter()
    }
}

struct ResultsPagination<T: RegistryQueryResults> {
    list: T,
    offset: usize,
    anchor: Option<u64>,
    limit: Option<usize>,
    deferred_pagination: bool,
}

impl<T: RegistryQueryResults> ResultsPagination<T> {
    fn new(query: &RegistryQuery) -> Self {
        let (anchor, offset) = match query.start {
            RegistryQueryStart::Index(index) => (None, index),
            RegistryQueryStart::Anchor(anchor) => (Some(anchor), 0),
            RegistryQueryStart::None => (None, 0),
        };

        Self {
            list: T::default(),
            offset: offset as usize,
            anchor,
            limit: query.limit,
            deferred_pagination: query.filters.len() > 1
                || query.filters.first().is_some_and(|f| {
                    if let (RegistryFilterOp::TextMatch, RegistryFilterValue::String(value)) =
                        (&f.op, &f.value)
                    {
                        value.chars().any(|c| !c.is_alphanumeric()) && value.len() > 1
                    } else {
                        false
                    }
                }),
        }
    }

    fn push(&mut self, id: u64) -> bool {
        if !self.deferred_pagination {
            if self.offset > 0 {
                self.offset -= 1;
                true
            } else if let Some(anchor) = self.anchor {
                if id == anchor {
                    self.anchor = None;
                }
                true
            } else {
                self.list.push(id);
                self.limit.is_none_or(|limit| self.list.count() < limit)
            }
        } else {
            self.list.push(id);
            true
        }
    }

    fn finalize(mut self) -> T {
        if self.deferred_pagination
            && self.list.has_items()
            && (self.limit.is_some() || self.anchor.is_some() || self.offset > 0)
        {
            let list = std::mem::take(&mut self.list);
            self.deferred_pagination = false;

            for item in list.into_list() {
                if !self.push(item) {
                    break;
                }
            }
        }
        self.list
    }
}

impl RegistryQuery {
    pub fn new(object_type: ObjectType) -> Self {
        Self {
            object_type,
            filters: Vec::new(),
            start: RegistryQueryStart::None,
            limit: None,
        }
    }

    pub fn with_anchor(mut self, anchor: u64) -> Self {
        self.start = RegistryQueryStart::Anchor(anchor);
        self
    }

    pub fn with_index_start(mut self, index: u64) -> Self {
        self.start = RegistryQueryStart::Index(index);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_account(mut self, account_id: u32) -> Self {
        if self.object_type.flags() & OBJ_FILTER_ACCOUNT != 0 {
            let filter = RegistryFilter::equal(Property::AccountId, account_id, false);
            if self.filters.is_empty() {
                self.filters.push(filter);
            } else {
                self.filters.insert(0, filter);
            }
        }
        self
    }

    pub fn with_account_opt(self, account_id: Option<u32>) -> Self {
        if let Some(account_id) = account_id {
            self.with_account(account_id)
        } else {
            self
        }
    }

    pub fn with_tenant(mut self, tenant_id: Option<u32>) -> Self {
        if let Some(tenant_id) = tenant_id
            && self.object_type.flags() & OBJ_FILTER_TENANT != 0
        {
            let filter = RegistryFilter::equal(Property::MemberTenantId, tenant_id, false);
            if self.filters.is_empty() {
                self.filters.push(filter);
            } else {
                self.filters.insert(0, filter);
            }
        }
        self
    }

    pub fn filter(mut self, filter: RegistryFilter) -> Self {
        self.filters.push(filter);
        self
    }

    pub fn equal(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::equal(property, value, false));
        self
    }

    pub fn equal_pk(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        self.filters
            .push(RegistryFilter::equal(property, value, is_pk));
        self
    }

    pub fn push_equal_pk(
        &mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) {
        self.filters
            .push(RegistryFilter::equal(property, value, is_pk));
    }

    pub fn equal_opt(
        mut self,
        property: Property,
        value: Option<impl Into<RegistryFilterValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.filters
                .push(RegistryFilter::equal(property, value, false));
        }
        self
    }

    pub fn greater_than(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::greater_than(property, value, false));
        self
    }

    pub fn less_than(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::less_than(property, value, false));
        self
    }

    pub fn greater_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters.push(RegistryFilter::greater_than_or_equal(
            property, value, false,
        ));
        self
    }

    pub fn less_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::less_than_or_equal(property, value, false));
        self
    }

    pub fn text(mut self, property: Property, value: impl Into<String>) -> Self {
        self.filters.push(RegistryFilter::text(property, value));
        self
    }

    pub fn text_opt(mut self, property: Property, value: Option<impl Into<String>>) -> Self {
        if let Some(value) = value {
            self.filters.push(RegistryFilter::text(property, value));
        }
        self
    }

    pub fn push_text(&mut self, property: Property, value: impl Into<String>) {
        self.filters.push(RegistryFilter::text(property, value));
    }

    pub fn has_filters(&self) -> bool {
        !self.filters.is_empty()
    }
}

impl RegistryFilter {
    pub fn text(property: Property, value: impl Into<String>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::TextMatch,
            value: RegistryFilterValue::String(value.into()),
            is_pk: false,
        }
    }

    pub fn equal(property: Property, value: impl Into<RegistryFilterValue>, is_pk: bool) -> Self {
        Self {
            property,
            op: RegistryFilterOp::Equal,
            value: value.into(),
            is_pk,
        }
    }

    pub fn greater_than(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterThan,
            value: value.into(),
            is_pk,
        }
    }

    pub fn less_than(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LowerThan,
            value: value.into(),
            is_pk,
        }
    }

    pub fn greater_than_or_equal(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterEqualThan,
            value: value.into(),
            is_pk,
        }
    }

    pub fn less_than_or_equal(
        property: Property,
        value: impl Into<RegistryFilterValue>,
        is_pk: bool,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LowerEqualThan,
            value: value.into(),
            is_pk,
        }
    }
}

impl From<String> for RegistryFilterValue {
    fn from(value: String) -> Self {
        RegistryFilterValue::String(value)
    }
}

impl From<&str> for RegistryFilterValue {
    fn from(value: &str) -> Self {
        RegistryFilterValue::String(value.to_string())
    }
}

impl From<u64> for RegistryFilterValue {
    fn from(value: u64) -> Self {
        RegistryFilterValue::U64(value)
    }
}

impl From<u32> for RegistryFilterValue {
    fn from(value: u32) -> Self {
        RegistryFilterValue::U64(value as u64)
    }
}

impl From<u16> for RegistryFilterValue {
    fn from(value: u16) -> Self {
        RegistryFilterValue::U16(value)
    }
}

impl From<bool> for RegistryFilterValue {
    fn from(value: bool) -> Self {
        RegistryFilterValue::Boolean(value)
    }
}
