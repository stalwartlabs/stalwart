/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{HttpStore, HttpStoreConfig, HttpStoreFormat};
use crate::{InMemoryStore, LookupStores, registry::bootstrap::Bootstrap};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use registry::schema::structs::{self, HttpLookupFormat};
use std::{
    collections::hash_map::Entry,
    sync::atomic::{AtomicBool, AtomicU64},
};

impl LookupStores {
    pub async fn parse_http(&mut self, bp: &mut Bootstrap) {
        // Parse remote lists
        for http in bp.list_infallible::<structs::HttpLookup>().await {
            let id = http.id;
            let http = http.object;
            if !http.enable {
                continue;
            }

            let http_config = HttpStoreConfig {
                url: http.url,
                retry: http.retry.as_secs(),
                refresh: http.refresh.as_secs(),
                timeout: http.timeout.into_inner(),
                gzipped: http.is_gzipped,
                max_size: http.max_size as usize,
                max_entries: http.max_entries as usize,
                max_entry_size: http.max_entry_size as usize,
                format: match http.format {
                    HttpLookupFormat::List => HttpStoreFormat::List,
                    HttpLookupFormat::Csv(csv) => HttpStoreFormat::Csv {
                        index_key: csv.index_key as u32,
                        index_value: csv.index_value.map(|v| v as u32),
                        separator: csv.separator.chars().next().unwrap_or(','),
                        skip_first: csv.skip_first,
                    },
                },
                id: http.namespace,
            };

            match self.stores.entry(http_config.id.as_str().into()) {
                Entry::Vacant(entry) => {
                    let store = HttpStore {
                        entries: ArcSwap::from_pointee(AHashMap::new()),
                        expires: AtomicU64::new(0),
                        in_flight: AtomicBool::new(false),
                        config: http_config,
                    };

                    entry.insert(InMemoryStore::Http(store.into()));
                }
                Entry::Occupied(_) => {
                    bp.build_error(
                        id,
                        format!(
                            "An lookup store with the {} namespace already exists",
                            http_config.id
                        ),
                    );
                }
            }
        }
    }
}
