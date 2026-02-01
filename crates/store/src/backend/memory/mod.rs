/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{InMemoryStore, LookupStores, Value, registry::bootstrap::Bootstrap};
use ahash::AHashMap;
use registry::schema::structs;
use utils::glob::{GlobMap, GlobSet};

#[derive(Debug)]
pub enum StaticMemoryStore {
    Map(GlobMap<Value<'static>>),
    Set(GlobSet),
}

impl LookupStores {
    pub async fn parse_static(&mut self, bp: &mut Bootstrap) {
        let mut lookups = AHashMap::new();

        for lookup in bp.list_infallible::<structs::MemoryLookupKeyValue>().await {
            if let StaticMemoryStore::Map(map) = lookups
                .entry(lookup.object.namespace)
                .or_insert_with(|| StaticMemoryStore::Map(Default::default()))
            {
                if lookup.object.is_glob_pattern {
                    map.insert_pattern(&lookup.object.key, Value::from(lookup.object.value));
                } else {
                    map.insert_entry(lookup.object.key, Value::from(lookup.object.value));
                }
            } else {
                bp.build_warning(
                    lookup.id,
                    "Memory lookup has mixed types (key-value and set)",
                );
            }
        }

        for lookup in bp.list_infallible::<structs::MemoryLookupKey>().await {
            if let StaticMemoryStore::Set(set) = lookups
                .entry(lookup.object.namespace)
                .or_insert_with(|| StaticMemoryStore::Set(Default::default()))
            {
                if lookup.object.is_glob_pattern {
                    set.insert_pattern(&lookup.object.key);
                } else {
                    set.insert_entry(lookup.object.key);
                }
            } else {
                bp.build_warning(
                    lookup.id,
                    "Memory lookup has mixed types (key-value and set)",
                );
            }
        }

        for (namespace, store) in lookups {
            self.stores
                .insert(namespace, InMemoryStore::Static(store.into()));
        }
    }
}
