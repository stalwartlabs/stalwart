/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    QuotaOwner, account_key, exchange_range, folder::FAI_CLIENT_KEY, key_tail,
    object::StoredPlacement,
};
use crate::cache::ExchangeCacheFetch;
use common::{
    Server,
    auth::{AccessToken, BuildAccessToken},
    cache::exchange::{EXCHANGE_GROUPS, MAX_FOREIGN_REPLICAS, foreign_replica_id, foreign_replid},
};
use store::{
    Deserialize, IterateParams, Serialize,
    roaring::RoaringBitmap,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, BatchBuilder, MergeResult,
        assert::{AssertValue, ToAssertValue},
        metadata::ExchangeClass,
    },
};
use trc::AddContext;
use types::collection::Collection;

pub const MAX_UPDATE_ATTEMPTS: usize = 5;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ExchangeAccount {
    pub store_instance: u64,
    pub objects_epoch: u64,
    pub next_change: u64,
    pub next_folder_id: u32,
    pub next_fai_id: u32,
    pub next_device_slot: u16,
    pub devices: Vec<EasDevice>,
    pub named_count: u32,
    pub categories_version: u32,
    pub swept: [u64; EXCHANGE_GROUPS],
    pub swept_change: u64,
    pub replicas: Vec<[u8; 16]>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasDevice {
    pub slot: u16,
    pub device_id: String,
    pub device_type: String,
    pub policy_key: u32,
    pub wipe: u8,
    pub created: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdCounter {
    Folder,
    Fai,
}

impl From<IdCounter> for ExchangeCounter {
    fn from(counter: IdCounter) -> Self {
        match counter {
            IdCounter::Folder => ExchangeCounter::Folder,
            IdCounter::Fai => ExchangeCounter::Fai,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeCounter {
    Change,
    Folder,
    Fai,
}

impl ArchiveCompression for ExchangeAccount {}

pub struct ExchangeIdReservation<const N: usize> {
    account_id: u32,
    current: AssertValue,
    next: Vec<u8>,
    ids: [u64; N],
}

#[derive(Debug, Clone, Copy)]
pub struct ReservedAccount {
    account_id: u32,
    current: AssertValue,
}

impl<const N: usize> ExchangeIdReservation<N> {
    pub fn ids(&self) -> [u64; N] {
        self.ids
    }

    pub fn seal(self, batch: &mut BatchBuilder) -> ReservedAccount {
        batch
            .with_account_id(self.account_id)
            .with_collection(Collection::Principal)
            .with_document(0)
            .assert_value(ExchangeClass::Account, self.current)
            .set(ExchangeClass::Account, self.next);
        ReservedAccount {
            account_id: self.account_id,
            current: self.current,
        }
    }
}

impl ReservedAccount {
    pub async fn is_stale(self, server: &Server) -> trc::Result<bool> {
        server
            .exchange_account(self.account_id)
            .await
            .map(|current| {
                current
                    .as_ref()
                    .map_or(AssertValue::None, ToAssertValue::to_assert_value)
                    != self.current
            })
    }
}

impl ExchangeAccount {
    pub fn replica_id(&self, guid: &[u8; 16]) -> Option<u16> {
        foreign_replica_id(&self.replicas, guid)
    }

    pub fn register_replica(&mut self, guid: [u8; 16], limit: usize) -> Option<u16> {
        match self.replica_id(&guid) {
            Some(replid) => Some(replid),
            None if self.replicas.len() < limit.min(MAX_FOREIGN_REPLICAS) => {
                let index = self.replicas.len();
                self.replicas.push(guid);
                foreign_replid(index)
            }
            None => None,
        }
    }

    fn allocate_set<const N: usize>(
        &mut self,
        requests: [(ExchangeCounter, u32); N],
    ) -> trc::Result<[u64; N]> {
        let mut first = [0; N];
        for (first, (counter, count)) in first.iter_mut().zip(requests) {
            *first = self.allocate(counter, count).ok_or_else(|| {
                trc::StoreEvent::UnexpectedError
                    .into_err()
                    .details("Exchange id counter exhausted.")
                    .caused_by(trc::location!())
            })?;
        }
        Ok(first)
    }

    fn allocate(&mut self, counter: ExchangeCounter, count: u32) -> Option<u64> {
        match counter {
            ExchangeCounter::Change => {
                let first = self.next_change.max(1);
                self.next_change = first.checked_add(u64::from(count))?;
                Some(first)
            }
            ExchangeCounter::Folder => {
                let first = self.next_folder_id.max(1);
                self.next_folder_id = first.checked_add(count)?;
                Some(u64::from(first))
            }
            ExchangeCounter::Fai => {
                let first = self.next_fai_id.max(1);
                self.next_fai_id = first
                    .checked_add(count)
                    .filter(|next| *next <= FAI_CLIENT_KEY)?;
                Some(u64::from(first))
            }
        }
    }
}

pub fn bump_objects_epoch(batch: &mut BatchBuilder, account_id: u32) {
    merge_exchange_account(batch, account_id, |account| account.objects_epoch += 1);
}

pub(crate) fn merge_exchange_account(
    batch: &mut BatchBuilder,
    account_id: u32,
    update: impl Fn(&mut ExchangeAccount) + Send + Sync + 'static,
) {
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0)
        .merge_fnc(ExchangeClass::Account, move |_, bytes| {
            let mut account = match bytes {
                Some(bytes) => <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)?
                    .deserialize::<ExchangeAccount>()?,
                None => ExchangeAccount::default(),
            };
            update(&mut account);
            Archiver::new(account).serialize().map(MergeResult::Update)
        });
}

pub trait ExchangeAccountStore: Sync + Send {
    fn exchange_account(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Archive<ArchiveBytes>>>> + Send;

    fn update_exchange_account<F, R>(
        &self,
        account_id: u32,
        update: F,
    ) -> impl Future<Output = trc::Result<(ExchangeAccount, R)>> + Send
    where
        F: Fn(&mut ExchangeAccount) -> trc::Result<R> + Send + Sync,
        R: Send;

    fn register_exchange_replica(
        &self,
        account_id: u32,
        guid: [u8; 16],
        limit: usize,
    ) -> impl Future<Output = trc::Result<Option<u16>>> + Send;

    fn allocate_exchange_ids(
        &self,
        account_id: u32,
        counter: IdCounter,
        count: u32,
    ) -> impl Future<Output = trc::Result<u64>> + Send;

    fn allocate_exchange_id_set<const N: usize>(
        &self,
        account_id: u32,
        requests: [(IdCounter, u32); N],
    ) -> impl Future<Output = trc::Result<[u64; N]>> + Send;

    fn reserve_exchange_ids<const N: usize>(
        &self,
        account_id: u32,
        requests: [(ExchangeCounter, u32); N],
    ) -> impl Future<Output = trc::Result<ExchangeIdReservation<N>>> + Send;

    fn exchange_quota_owner(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<QuotaOwner>> + Send;

    fn exchange_target_token(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Option<AccessToken>>> + Send;

    fn exchange_object_ids(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Vec<(Collection, RoaringBitmap)>>> + Send;

    fn exchange_aliases<CB>(
        &self,
        account_id: u32,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(Collection, u32, StoredPlacement) -> bool + Send + Sync;
}

impl ExchangeAccountStore for Server {
    async fn exchange_account(
        &self,
        account_id: u32,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(account_key(account_id, ExchangeClass::Account))
            .await
            .caused_by(trc::location!())
    }

    async fn update_exchange_account<F, R>(
        &self,
        account_id: u32,
        update: F,
    ) -> trc::Result<(ExchangeAccount, R)>
    where
        F: Fn(&mut ExchangeAccount) -> trc::Result<R> + Send + Sync,
        R: Send,
    {
        let mut attempts = 0;
        loop {
            let current = self.exchange_account(account_id).await?;
            let mut account = match &current {
                Some(current) => current.deserialize::<ExchangeAccount>()?,
                None => ExchangeAccount::default(),
            };
            let result = update(&mut account)?;
            let archiver = Archiver::new(account);
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0);
            match &current {
                Some(current) => batch.assert_value(ExchangeClass::Account, current),
                None => batch.assert_value(ExchangeClass::Account, AssertValue::None),
            };
            batch.set(
                ExchangeClass::Account,
                archiver.serialize().caused_by(trc::location!())?,
            );
            match self.store().write_batch(&mut batch).await {
                Ok(_) => return Ok((archiver.into_inner(), result)),
                Err(err) if err.is_assertion_failure() && attempts < MAX_UPDATE_ATTEMPTS => {
                    attempts += 1;
                }
                Err(err) => return Err(err.caused_by(trc::location!())),
            }
        }
    }

    async fn register_exchange_replica(
        &self,
        account_id: u32,
        guid: [u8; 16],
        limit: usize,
    ) -> trc::Result<Option<u16>> {
        if let Some(current) = self.exchange_account(account_id).await? {
            let replicas = &current.unarchive::<ExchangeAccount>()?.replicas;
            if let Some(replid) = foreign_replica_id(replicas, &guid) {
                return Ok(Some(replid));
            }
            if replicas.len() >= limit.min(MAX_FOREIGN_REPLICAS) {
                return Ok(None);
            }
        }
        let (_, replid) = self
            .update_exchange_account(account_id, |account| {
                Ok(account.register_replica(guid, limit))
            })
            .await?;
        self.mark_exchange_stale(account_id);
        Ok(replid)
    }

    async fn allocate_exchange_ids(
        &self,
        account_id: u32,
        counter: IdCounter,
        count: u32,
    ) -> trc::Result<u64> {
        self.allocate_exchange_id_set(account_id, [(counter, count)])
            .await
            .map(|[first]| first)
    }

    async fn allocate_exchange_id_set<const N: usize>(
        &self,
        account_id: u32,
        requests: [(IdCounter, u32); N],
    ) -> trc::Result<[u64; N]> {
        let requests = requests.map(|(counter, count)| (ExchangeCounter::from(counter), count));
        self.update_exchange_account(account_id, |account| account.allocate_set(requests))
            .await
            .map(|(_, first)| first)
    }

    async fn reserve_exchange_ids<const N: usize>(
        &self,
        account_id: u32,
        requests: [(ExchangeCounter, u32); N],
    ) -> trc::Result<ExchangeIdReservation<N>> {
        let current = self.exchange_account(account_id).await?;
        let mut account = match &current {
            Some(current) => current.deserialize::<ExchangeAccount>()?,
            None => ExchangeAccount::default(),
        };
        let ids = account.allocate_set(requests)?;
        Ok(ExchangeIdReservation {
            account_id,
            current: current
                .as_ref()
                .map_or(AssertValue::None, ToAssertValue::to_assert_value),
            next: Archiver::new(account)
                .serialize()
                .caused_by(trc::location!())?,
            ids,
        })
    }

    async fn exchange_quota_owner(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<QuotaOwner> {
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        {
            let tenant_id = if access_token.account_id() == account_id {
                access_token.tenant_id()
            } else {
                self.account(account_id)
                    .await
                    .caused_by(trc::location!())?
                    .id_tenant
            };
            Ok(QuotaOwner::new(account_id, tenant_id))
        }
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = access_token;
            Ok(QuotaOwner::new(account_id))
        }
    }

    async fn exchange_target_token(
        &self,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Option<AccessToken>> {
        if access_token.is_account_id(account_id) {
            return Ok(None);
        }
        self.access_token(account_id)
            .await
            .caused_by(trc::location!())
            .map(|inner| Some(inner.build()))
    }

    async fn exchange_object_ids(
        &self,
        account_id: u32,
    ) -> trc::Result<Vec<(Collection, RoaringBitmap)>> {
        let mut ids: Vec<(Collection, RoaringBitmap)> = Vec::new();
        let (from, to) = exchange_range(account_id, ExchangeClass::Object);
        self.store()
            .iterate(IterateParams::new(from, to).no_values(), |key, _| {
                let (collection, document_id) =
                    key_tail(key).map(|(collection, id)| (Collection::from(collection), id))?;
                match ids.last_mut() {
                    Some((last, documents)) if *last == collection => {
                        documents.insert(document_id);
                    }
                    _ => ids.push((collection, RoaringBitmap::from_iter([document_id]))),
                }
                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
        Ok(ids)
    }

    async fn exchange_aliases<CB>(&self, account_id: u32, mut cb: CB) -> trc::Result<()>
    where
        CB: FnMut(Collection, u32, StoredPlacement) -> bool + Send + Sync,
    {
        let (from, to) = exchange_range(account_id, ExchangeClass::Alias);
        self.store()
            .iterate(IterateParams::new(from, to), |key, value| {
                let (collection, document_id) =
                    key_tail(key).map(|(collection, id)| (Collection::from(collection), id))?;
                let placement = StoredPlacement::deserialize(value).ok_or_else(|| {
                    trc::Error::corrupted_key(key, value.into(), trc::location!())
                })?;
                Ok(cb(collection, document_id, placement))
            })
            .await
            .caused_by(trc::location!())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/account/tests.rs"]
mod tests;
