/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{account::merge_exchange_account, account_key};
use crate::cache::ExchangeCacheFetch;
use common::{
    Server,
    cache::exchange::{ExchangeAccountCache, NamedPropertyTable},
};
use exchange_proto::mapi::prop::{
    FIRST_NAMED_ID, MAX_NAMED_IDS, NamedPropMap, PropKeyRef,
    seed::{SEED_LEN, seed_entries, seed_id},
    tag::PropId,
};
use std::sync::Arc;
use store::{
    Serialize,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, BatchBuilder, assert::AssertValue,
        metadata::ExchangeClass,
    },
};
use trc::AddContext;
use types::collection::Collection;

const MAX_UPDATE_ATTEMPTS: usize = 5;
const FIRST_ACCOUNT_ID: u16 = FIRST_NAMED_ID.0 + SEED_LEN as u16;
const MAX_ACCOUNT_NAMES: usize = MAX_NAMED_IDS as usize - SEED_LEN;

const _: () = assert!(SEED_LEN < MAX_NAMED_IDS as usize);

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct NamedProperties {
    pub names: Vec<Vec<u8>>,
}

impl ArchiveCompression for NamedProperties {}

pub struct AccountNamedProps<'x> {
    table: &'x NamedPropertyTable,
}

impl<'x> AccountNamedProps<'x> {
    pub fn new(cache: &'x ExchangeAccountCache) -> Self {
        AccountNamedProps {
            table: &cache.named,
        }
    }

    pub fn may_be_newer(&self, id: PropId) -> bool {
        id.0.checked_sub(FIRST_ACCOUNT_ID)
            .map(usize::from)
            .is_some_and(|index| index >= self.table.names.len() && index < MAX_ACCOUNT_NAMES)
    }
}

impl NamedPropMap for AccountNamedProps<'_> {
    fn id(&self, key: PropKeyRef<'_>) -> Option<PropId> {
        seed_id(key).or_else(|| {
            let mut name = Vec::with_capacity(32);
            key.write_canonical(&mut name);
            table_id(self.table, &name)
        })
    }

    fn key(&self, id: PropId) -> Option<PropKeyRef<'_>> {
        let offset = usize::from(id.0.checked_sub(FIRST_NAMED_ID.0)?);
        match offset.checked_sub(SEED_LEN) {
            None => seed_entries().nth(offset).map(|(key, _)| key),
            Some(index) => self
                .table
                .names
                .get(index)
                .and_then(|name| PropKeyRef::read_canonical(name))
                .map(|(key, _)| key),
        }
    }
}

fn table_id(table: &NamedPropertyTable, name: &[u8]) -> Option<PropId> {
    table
        .ids
        .get(name)
        .and_then(|index| FIRST_ACCOUNT_ID.checked_add(*index))
        .map(PropId)
}

pub trait ExchangeNamedProperties: Sync + Send {
    fn named_property_ids(
        &self,
        account_id: u32,
        cache: &ExchangeAccountCache,
        keys: &[PropKeyRef<'_>],
        create: Option<usize>,
    ) -> impl Future<Output = trc::Result<Vec<Option<PropId>>>> + Send;

    fn reload_named_properties(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Arc<ExchangeAccountCache>>> + Send;
}

impl ExchangeNamedProperties for Server {
    async fn named_property_ids(
        &self,
        account_id: u32,
        cache: &ExchangeAccountCache,
        keys: &[PropKeyRef<'_>],
        create: Option<usize>,
    ) -> trc::Result<Vec<Option<PropId>>> {
        let names = AccountNamedProps::new(cache);
        let ids = keys.iter().map(|key| names.id(*key)).collect::<Vec<_>>();
        if ids.iter().all(Option::is_some) {
            return Ok(ids);
        }

        let mut missing = Vec::with_capacity(keys.len());
        for (key, id) in keys.iter().zip(&ids) {
            if id.is_none() {
                let mut name = Vec::with_capacity(32);
                key.write_canonical(&mut name);
                missing.push(name);
            }
        }

        let mut attempts = 0;
        let table = loop {
            let current = read_named_properties(self, account_id).await?;
            let mut stored = match &current {
                Some(current) => current.deserialize::<NamedProperties>()?,
                None => NamedProperties::default(),
            };
            let mut table = NamedPropertyTable::from_names(&stored.names);
            let mut changed = false;
            if let Some(limit) = create {
                let limit = limit.min(MAX_ACCOUNT_NAMES);
                for name in &missing {
                    if !table.ids.contains_key(name.as_slice()) && stored.names.len() < limit {
                        table.push(name.as_slice().into());
                        stored.names.push(name.clone());
                        changed = true;
                    }
                }
            }
            if !changed {
                break table;
            }

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);
            match &current {
                Some(current) => batch.assert_value(ExchangeClass::NamedProperties, current),
                None => batch.assert_value(ExchangeClass::NamedProperties, AssertValue::None),
            };
            let named_count = u32::try_from(stored.names.len()).unwrap_or(u32::MAX);
            batch.set(
                ExchangeClass::NamedProperties,
                Archiver::new(stored)
                    .serialize()
                    .caused_by(trc::location!())?,
            );
            merge_exchange_account(&mut batch, account_id, move |account| {
                account.named_count = account.named_count.max(named_count);
            });
            match self.store().write_batch(&mut batch).await {
                Ok(_) => break table,
                Err(err) if err.is_assertion_failure() && attempts < MAX_UPDATE_ATTEMPTS => {
                    attempts += 1;
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        };

        let mut missing = missing.iter();
        let ids = ids
            .into_iter()
            .map(|id| id.or_else(|| missing.next().and_then(|name| table_id(&table, name))))
            .collect();
        self.publish_named_properties(account_id, table);
        Ok(ids)
    }

    async fn reload_named_properties(
        &self,
        account_id: u32,
    ) -> trc::Result<Arc<ExchangeAccountCache>> {
        let table = match read_named_properties(self, account_id).await? {
            Some(stored) => {
                NamedPropertyTable::from_names(&stored.deserialize::<NamedProperties>()?.names)
            }
            None => NamedPropertyTable::default(),
        };
        self.publish_named_properties(account_id, table);
        self.get_cached_exchange(account_id).await
    }
}

pub(crate) async fn read_named_properties(
    server: &Server,
    account_id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(account_key(account_id, ExchangeClass::NamedProperties))
        .await
        .caused_by(trc::location!())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/named/tests.rs"]
mod tests;
