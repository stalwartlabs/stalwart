/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, SUBSPACE_REGISTRY_IDX, Store, U16_LEN, U64_LEN, ValueKey,
    registry::{RegistryFilter, RegistryFilterOp, RegistryFilterValue, RegistryQuery},
    write::{
        AnyClass, RegistryClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use ahash::AHashSet;
use registry::{
    schema::prelude::{OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, OBJ_SINGLETON, ObjectType, Property},
    types::EnumImpl,
};
use roaring::RoaringBitmap;
use std::{borrow::Cow, ops::BitAndAssign};
use trc::AddContext;
use types::id::Id;

impl RegistryStore {
    pub async fn query<T: RegistryQueryResults>(&self, query: RegistryQuery) -> trc::Result<T> {
        let flags = query.object_type.flags();
        if flags & OBJ_SINGLETON != 0 {
            if query.filters.is_empty() {
                let mut results = T::default();
                results.push(Id::singleton().id());
                return Ok(results);
            } else {
                return Err(trc::EventType::Registry(trc::RegistryEvent::NotSupported)
                    .into_err()
                    .details("Singletons do not support searching"));
            }
        } else if self.0.local_objects.contains(&query.object_type) {
            if !query.filters.is_empty() {
                trc::event!(
                    Registry(trc::RegistryEvent::NotSupported),
                    Details = "Filtering is not supported for local registry"
                );
            }
            let mut results = T::default();
            for id in self.0.local_registry.read().keys() {
                if id.object() == query.object_type {
                    results.push(id.id().id());
                }
            }
            return Ok(results);
        } else if query.filters.is_empty() {
            return all_ids::<T>(&self.0.store, query.object_type).await;
        }

        let mut u64_buffer;
        let mut u16_buffer;
        let mut bool_buffer = [0u8; 1];

        let mut results = T::default();
        for filter in query.filters {
            if filter.op == RegistryFilterOp::TextMatch {
                if let RegistryFilterValue::String(text) = filter.value {
                    let mut matches = T::default();
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

                        let result = range_to_set(
                            &self.0.store,
                            query.object_type,
                            filter.property.to_id(),
                            word.as_bytes(),
                            RegistryFilterOp::Equal,
                        )
                        .await?;

                        if !matches.has_items() {
                            matches = result;
                        } else {
                            matches.intersect(&result);
                            if !matches.has_items() {
                                break;
                            }
                        }
                    }

                    if !results.has_items() {
                        results = matches;
                    } else {
                        results.intersect(&matches);
                    }
                } else {
                    return Err(trc::EventType::Registry(trc::RegistryEvent::NotSupported)
                        .into_err()
                        .details("TextMatch operator only supports string values"));
                }
            } else {
                let result = range_to_set(
                    &self.0.store,
                    query.object_type,
                    filter.property.to_id(),
                    match &filter.value {
                        RegistryFilterValue::String(v) => v.as_bytes(),
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
                    },
                    filter.op,
                )
                .await?;

                if !results.has_items() {
                    results = result;
                } else {
                    results.intersect(&result);
                }
            }

            if !results.has_items() {
                return Ok(results);
            }
        }

        Ok(results)
    }
}

pub trait RegistryQueryResults: Default + Sized + Sync + Send {
    fn push(&mut self, id: u64);
    fn has_items(&self) -> bool;
    fn intersect(&mut self, other: &Self);
}

impl RegistryQueryResults for AHashSet<u64> {
    fn push(&mut self, id: u64) {
        self.insert(id);
    }

    fn has_items(&self) -> bool {
        !self.is_empty()
    }

    fn intersect(&mut self, other: &Self) {
        self.retain(|id| other.contains(id));
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
}

impl RegistryQuery {
    pub fn new(object_type: ObjectType) -> Self {
        Self {
            object_type,
            filters: Vec::new(),
        }
    }

    pub fn with_account(mut self, account_id: u32) -> Self {
        if self.object_type.flags() & OBJ_FILTER_ACCOUNT != 0 {
            let filter = RegistryFilter::equal(Property::AccountId, account_id);
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
            let filter = RegistryFilter::equal(Property::MemberTenantId, tenant_id);
            if self.filters.is_empty() {
                self.filters.push(filter);
            } else {
                self.filters.insert(0, filter);
            }
        }
        self
    }

    pub fn equal(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters.push(RegistryFilter::equal(property, value));
        self
    }

    pub fn equal_opt(
        mut self,
        property: Property,
        value: Option<impl Into<RegistryFilterValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.filters.push(RegistryFilter::equal(property, value));
        }
        self
    }

    pub fn greater_than(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::greater_than(property, value));
        self
    }

    pub fn less_than(mut self, property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        self.filters
            .push(RegistryFilter::less_than(property, value));
        self
    }

    pub fn greater_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::greater_than_or_equal(property, value));
        self
    }

    pub fn less_than_or_equal(
        mut self,
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        self.filters
            .push(RegistryFilter::less_than_or_equal(property, value));
        self
    }

    pub fn text(mut self, value: impl Into<String>) -> Self {
        self.filters.push(RegistryFilter::text(value));
        self
    }

    pub fn text_opt(mut self, value: Option<impl Into<String>>) -> Self {
        if let Some(value) = value {
            self.filters.push(RegistryFilter::text(value));
        }
        self
    }
}

impl RegistryFilter {
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            property: Property::Contents,
            op: RegistryFilterOp::TextMatch,
            value: RegistryFilterValue::String(value.into()),
        }
    }

    pub fn equal(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::Equal,
            value: value.into(),
        }
    }

    pub fn greater_than(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterThan,
            value: value.into(),
        }
    }

    pub fn less_than(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LowerThan,
            value: value.into(),
        }
    }

    pub fn greater_than_or_equal(
        property: Property,
        value: impl Into<RegistryFilterValue>,
    ) -> Self {
        Self {
            property,
            op: RegistryFilterOp::GreaterEqualThan,
            value: value.into(),
        }
    }

    pub fn less_than_or_equal(property: Property, value: impl Into<RegistryFilterValue>) -> Self {
        Self {
            property,
            op: RegistryFilterOp::LowerEqualThan,
            value: value.into(),
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

async fn all_ids<T: RegistryQueryResults>(store: &Store, object: ObjectType) -> trc::Result<T> {
    let mut bm = T::default();
    let object_id = object.to_id();
    store
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Registry(RegistryClass::Id {
                    object_id,
                    item_id: 0u64,
                })),
                ValueKey::from(ValueClass::Registry(RegistryClass::Id {
                    object_id,
                    item_id: u64::MAX,
                })),
            )
            .no_values()
            .ascending(),
            |key, _| {
                if key.len() == U64_LEN + U16_LEN {
                    bm.push(key.deserialize_be_u64(key.len() - U64_LEN)?);
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    Ok(bm)
}

async fn range_to_set<T: RegistryQueryResults>(
    store: &Store,
    object: ObjectType,
    index_id: u16,
    match_value: &[u8],
    op: RegistryFilterOp,
) -> trc::Result<T> {
    let object_id = object.to_id();
    let ((from_value, from_doc_id, from_index_id), (end_value, end_doc_id, end_index_id)) = match op
    {
        RegistryFilterOp::LowerThan => ((&[][..], 0, object_id), (match_value, 0, object_id)),
        RegistryFilterOp::LowerEqualThan => {
            ((&[][..], 0, object_id), (match_value, u64::MAX, object_id))
        }
        RegistryFilterOp::GreaterThan => (
            (match_value, u64::MAX, object_id),
            (&[][..], u64::MAX, object_id + 1),
        ),
        RegistryFilterOp::GreaterEqualThan => (
            (match_value, 0, object_id),
            (&[][..], u64::MAX, object_id + 1),
        ),
        RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => (
            (match_value, 0, object_id),
            (match_value, u64::MAX, object_id),
        ),
    };

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

    let mut bm = T::default();
    let prefix = KeySerializer::new(U16_LEN * 2)
        .write(object_id)
        .write(index_id)
        .finalize();
    let prefix_len = prefix.len();

    store
        .iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                if !key.starts_with(&prefix) {
                    return Ok(false);
                }

                let id_pos = key.len() - U64_LEN;
                let value = key
                    .get(prefix_len..id_pos)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                let matches = match op {
                    RegistryFilterOp::LowerThan => value < match_value,
                    RegistryFilterOp::LowerEqualThan => value <= match_value,
                    RegistryFilterOp::GreaterThan => value > match_value,
                    RegistryFilterOp::GreaterEqualThan => value >= match_value,
                    RegistryFilterOp::Equal | RegistryFilterOp::TextMatch => value == match_value,
                };

                if matches {
                    bm.push(key.deserialize_be_u64(id_pos)?);
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| bm)
}
