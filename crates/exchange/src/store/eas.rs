/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    FolderRef,
    account::{EasDevice, ExchangeAccount, ExchangeAccountStore},
    account_key, key_tail,
};
use crate::{cache::ExchangeCacheFetch, eas::device::WipeState};
use common::Server;
use smallvec::SmallVec;
use store::{
    Deserialize, IterateParams, Serialize,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, BatchBuilder,
        assert::AssertValue,
        metadata::{ExchangeClass, ExchangeFolder},
    },
};
use trc::AddContext;
use types::collection::Collection;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasDeviceState {
    pub hierarchy: EasHierarchyState,
    pub last_seen: u64,
    pub ping: Option<EasPing>,
    pub sync: Option<EasSyncRequest>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasHierarchyState {
    pub nonce: u32,
    pub generation: u32,
    pub groups: [u64; 4],
    pub previous_groups: [u64; 4],
    pub folders: Vec<StoredFolder>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, Copy, PartialEq, Eq,
)]
pub struct StoredFolder {
    pub kind: u8,
    pub id: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasPing {
    pub heartbeat: u32,
    pub folders: Vec<StoredFolder>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasSyncRequest {
    pub folders: Vec<StoredFolder>,
    pub window_size: u32,
    pub heartbeat: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasFolderState {
    pub nonce: u32,
    pub generation: u32,
    pub change_id: u64,
    pub previous_change_id: u64,
    pub options: Vec<u8>,
    pub supported: Vec<u8>,
    pub synced: Vec<u8>,
    pub client_ids: Vec<EasClientId>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EasClientId {
    pub client_id: String,
    pub server_id: u32,
}

pub const EAS_DEVICE_SEEN_INTERVAL: u64 = 24 * 60 * 60;
pub const EAS_DEVICE_EVICTION_IDLE: u64 = 7 * EAS_DEVICE_SEEN_INTERVAL;

type DevicesSeen = SmallVec<[(u16, u64); 16]>;
type Evicted = SmallVec<[u16; 1]>;

impl ArchiveCompression for EasDeviceState {}
impl ArchiveCompression for EasFolderState {}

pub struct EasDeviceWrite<'x> {
    pub account_id: u32,
    pub slot: u16,
    pub previous: Option<&'x Archive<ArchiveBytes>>,
    pub next: EasDeviceState,
}

impl EasDeviceWrite<'_> {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        let class = ExchangeClass::Device { slot: self.slot };
        batch
            .with_account_id(self.account_id)
            .with_collection(Collection::Principal)
            .with_document(0);
        match self.previous {
            Some(previous) => batch.assert_value(class, previous),
            None => batch.assert_value(class, AssertValue::None),
        };
        batch.set(
            class,
            Archiver::new(self.next)
                .serialize()
                .caused_by(trc::location!())?,
        );
        Ok(())
    }
}

pub struct EasFolderWrite<'x> {
    pub account_id: u32,
    pub slot: u16,
    pub folder: FolderRef,
    pub previous: Option<&'x Archive<ArchiveBytes>>,
    pub next: Option<EasFolderState>,
}

impl EasFolderWrite<'_> {
    pub fn build(self, batch: &mut BatchBuilder) -> trc::Result<()> {
        let class = ExchangeClass::DeviceFolder {
            slot: self.slot,
            folder: self.folder.stored(),
        };
        batch
            .with_account_id(self.account_id)
            .with_collection(Collection::Principal)
            .with_document(0);
        match self.previous {
            Some(previous) => batch.assert_value(class, previous),
            None => batch.assert_value(class, AssertValue::None),
        };
        match self.next {
            Some(next) => batch.set(
                class,
                Archiver::new(next)
                    .serialize()
                    .caused_by(trc::location!())?,
            ),
            None => batch.clear(class),
        };
        Ok(())
    }
}

pub trait EasStore: Sync + Send {
    fn register_eas_device(
        &self,
        account_id: u32,
        device_id: &str,
        device_type: &str,
        max_devices: usize,
    ) -> impl Future<Output = trc::Result<EasDevice>> + Send;

    fn update_eas_device<F>(
        &self,
        account_id: u32,
        slot: u16,
        update: F,
    ) -> impl Future<Output = trc::Result<Option<EasDevice>>> + Send
    where
        F: Fn(&mut EasDevice) + Send + Sync;

    fn eas_device_state(
        &self,
        account_id: u32,
        slot: u16,
    ) -> impl Future<Output = trc::Result<Option<Archive<ArchiveBytes>>>> + Send;

    fn eas_device_state_seen(
        &self,
        account_id: u32,
        slot: u16,
    ) -> impl Future<Output = trc::Result<(Option<Archive<ArchiveBytes>>, EasDeviceState)>> + Send;

    fn eas_folder_state(
        &self,
        account_id: u32,
        slot: u16,
        folder: FolderRef,
    ) -> impl Future<Output = trc::Result<Option<Archive<ArchiveBytes>>>> + Send;

    fn eas_folder_states<CB>(
        &self,
        account_id: u32,
        slot: u16,
        cb: CB,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        CB: FnMut(ExchangeFolder, &ArchivedEasFolderState) -> trc::Result<bool> + Send + Sync;

    fn remove_eas_device(
        &self,
        account_id: u32,
        slot: u16,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl EasStore for Server {
    async fn register_eas_device(
        &self,
        account_id: u32,
        device_id: &str,
        device_type: &str,
        max_devices: usize,
    ) -> trc::Result<EasDevice> {
        let now = store::write::now();
        let seen = devices_seen(self, account_id, device_id, max_devices, now).await?;
        let (_, (device, evicted)) = self
            .update_exchange_account(account_id, |account| {
                if let Some(device) = account
                    .devices
                    .iter()
                    .find(|device| device.device_id == device_id)
                {
                    return Ok((device.clone(), Evicted::new()));
                }
                let Some(evicted) =
                    make_room(&mut account.devices, seen.as_ref(), max_devices, now)
                else {
                    return Err(trc::LimitEvent::TooManyRequests
                        .into_err()
                        .details("Maximum number of Exchange ActiveSync devices reached.")
                        .ctx(trc::Key::Total, max_devices));
                };
                let slot = account.next_device_slot;
                account.next_device_slot = slot.checked_add(1).ok_or_else(|| {
                    trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("Exchange ActiveSync device slots exhausted.")
                        .caused_by(trc::location!())
                })?;
                let device = EasDevice {
                    slot,
                    device_id: device_id.to_string(),
                    device_type: device_type.to_string(),
                    policy_key: 0,
                    wipe: 0,
                    created: now,
                };
                account.devices.push(device.clone());
                Ok((device, evicted))
            })
            .await?;
        self.mark_exchange_stale(account_id);
        for slot in evicted {
            if let Err(err) = delete_device_state(self, account_id, slot).await {
                trc::error!(err);
            }
        }
        Ok(device)
    }

    async fn update_eas_device<F>(
        &self,
        account_id: u32,
        slot: u16,
        update: F,
    ) -> trc::Result<Option<EasDevice>>
    where
        F: Fn(&mut EasDevice) + Send + Sync,
    {
        let (_, device) = self
            .update_exchange_account(account_id, |account| {
                Ok(account
                    .devices
                    .iter_mut()
                    .find(|device| device.slot == slot)
                    .map(|device| {
                        update(device);
                        device.clone()
                    }))
            })
            .await?;
        self.mark_exchange_stale(account_id);
        Ok(device)
    }

    async fn eas_device_state(
        &self,
        account_id: u32,
        slot: u16,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(account_key(
                account_id,
                ExchangeClass::Device { slot },
            ))
            .await
            .caused_by(trc::location!())
    }

    async fn eas_device_state_seen(
        &self,
        account_id: u32,
        slot: u16,
    ) -> trc::Result<(Option<Archive<ArchiveBytes>>, EasDeviceState)> {
        let archive = self.eas_device_state(account_id, slot).await?;
        let mut state = device_state_of(archive.as_ref())?;
        let now = store::write::now();
        if now.saturating_sub(state.last_seen) < EAS_DEVICE_SEEN_INTERVAL {
            return Ok((archive, state));
        }
        state.last_seen = now;
        let mut batch = BatchBuilder::new();
        EasDeviceWrite {
            account_id,
            slot,
            previous: archive.as_ref(),
            next: state,
        }
        .build(&mut batch)?;
        match self.store().write_batch(&mut batch).await {
            Ok(_) => {}
            Err(err) if err.is_assertion_failure() => {}
            Err(err) => return Err(err.caused_by(trc::location!())),
        }
        let archive = self.eas_device_state(account_id, slot).await?;
        let state = device_state_of(archive.as_ref())?;
        Ok((archive, state))
    }

    async fn eas_folder_state(
        &self,
        account_id: u32,
        slot: u16,
        folder: FolderRef,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(account_key(
                account_id,
                ExchangeClass::DeviceFolder {
                    slot,
                    folder: folder.stored(),
                },
            ))
            .await
            .caused_by(trc::location!())
    }

    async fn eas_folder_states<CB>(&self, account_id: u32, slot: u16, mut cb: CB) -> trc::Result<()>
    where
        CB: FnMut(ExchangeFolder, &ArchivedEasFolderState) -> trc::Result<bool> + Send + Sync,
    {
        self.store()
            .iterate(
                IterateParams::new(
                    account_key(account_id, device_folder(slot, 0, 0)),
                    account_key(account_id, device_folder(slot, u8::MAX, u32::MAX)),
                ),
                |key, value| {
                    let (kind, id) = key_tail(key)?;
                    let folder = ExchangeFolder { kind, id };
                    let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                    cb(folder, archive.unarchive::<EasFolderState>()?)
                },
            )
            .await
            .caused_by(trc::location!())
    }

    async fn remove_eas_device(&self, account_id: u32, slot: u16) -> trc::Result<()> {
        self.update_exchange_account(account_id, |account| {
            account.devices.retain(|device| device.slot != slot);
            Ok(())
        })
        .await?;
        self.mark_exchange_stale(account_id);
        delete_device_state(self, account_id, slot).await
    }
}

fn device_state_of(archive: Option<&Archive<ArchiveBytes>>) -> trc::Result<EasDeviceState> {
    match archive {
        Some(archive) => archive
            .deserialize::<EasDeviceState>()
            .caused_by(trc::location!()),
        None => Ok(EasDeviceState::default()),
    }
}

async fn delete_device_state(server: &Server, account_id: u32, slot: u16) -> trc::Result<()> {
    server
        .store()
        .delete_range(
            account_key(account_id, device_folder(slot, 0, 0)),
            account_key(account_id, device_folder(slot, u8::MAX, u32::MAX)),
        )
        .await
        .caused_by(trc::location!())?;
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account_id)
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear(ExchangeClass::Device { slot });
    server
        .store()
        .write_batch(&mut batch)
        .await
        .caused_by(trc::location!())
        .map(|_| ())
}

async fn devices_seen(
    server: &Server,
    account_id: u32,
    device_id: &str,
    max_devices: usize,
    now: u64,
) -> trc::Result<Option<DevicesSeen>> {
    let Some(archive) = server.exchange_account(account_id).await? else {
        return Ok(None);
    };
    let account = archive.unarchive::<ExchangeAccount>()?;
    if account.devices.len() < max_devices
        || account
            .devices
            .iter()
            .any(|device| device.device_id == device_id)
    {
        return Ok(None);
    }
    let mut seen = DevicesSeen::new();
    for device in account.devices.iter() {
        if !WipeState::from_code(device.wipe).is_evictable()
            || now.saturating_sub(device.created.to_native()) < EAS_DEVICE_EVICTION_IDLE
        {
            continue;
        }
        let slot = device.slot.to_native();
        if let Some(state) = server.eas_device_state(account_id, slot).await? {
            seen.push((
                slot,
                state.unarchive::<EasDeviceState>()?.last_seen.to_native(),
            ));
        }
    }
    Ok(Some(seen))
}

fn make_room(
    devices: &mut Vec<EasDevice>,
    seen: Option<&DevicesSeen>,
    max_devices: usize,
    now: u64,
) -> Option<Evicted> {
    let mut evicted = Evicted::new();
    while devices.len() >= max_devices {
        let index = idle_device(devices, seen?, now)?;
        evicted.push(devices.remove(index).slot);
    }
    Some(evicted)
}

fn idle_device(devices: &[EasDevice], seen: &DevicesSeen, now: u64) -> Option<usize> {
    devices
        .iter()
        .enumerate()
        .filter(|(_, device)| WipeState::from_code(device.wipe).is_evictable())
        .map(|(index, device)| {
            let last_seen = seen
                .iter()
                .find(|(slot, _)| *slot == device.slot)
                .map_or(0, |(_, last_seen)| *last_seen);
            (index, last_seen.max(device.created))
        })
        .filter(|(_, last_seen)| now.saturating_sub(*last_seen) >= EAS_DEVICE_EVICTION_IDLE)
        .min_by_key(|(_, last_seen)| *last_seen)
        .map(|(index, _)| index)
}

const fn device_folder(slot: u16, kind: u8, id: u32) -> ExchangeClass {
    ExchangeClass::DeviceFolder {
        slot,
        folder: ExchangeFolder { kind, id },
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/eas/tests.rs"]
mod tests;
