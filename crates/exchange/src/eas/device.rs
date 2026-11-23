/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{ActiveDevice, EasContext},
    response::EasResponse,
};
use crate::{
    cache::ExchangeCacheFetch,
    store::{
        account::{EasDevice, ExchangeAccount, ExchangeAccountStore},
        eas::EasStore,
    },
};
use common::Server;
use exchange_proto::eas::{
    http::Command,
    status::{CommonStatus, HttpOutcome},
};
use store::rand::{self, RngExt};
use trc::AddContext;

const TEMPORARY_KEYS: std::ops::RangeInclusive<u32> = 100_000_000..=999_999_999;
const PERMANENT_KEYS: std::ops::RangeInclusive<u32> = 1_000_000_000..=u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKey {
    None,
    Temporary(u32),
    Permanent(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipeState {
    None,
    Device,
    AccountOnly,
    Wiped,
}

pub enum DeviceGate {
    Allow,
    Refuse(EasResponse),
}

impl PolicyKey {
    pub fn from_stored(key: u32) -> Self {
        if PERMANENT_KEYS.contains(&key) {
            PolicyKey::Permanent(key)
        } else if TEMPORARY_KEYS.contains(&key) {
            PolicyKey::Temporary(key)
        } else {
            PolicyKey::None
        }
    }

    pub fn new_temporary() -> u32 {
        rand::rng().random_range(TEMPORARY_KEYS)
    }

    pub fn new_permanent() -> u32 {
        rand::rng().random_range(PERMANENT_KEYS)
    }
}

impl WipeState {
    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => WipeState::Device,
            2 => WipeState::AccountOnly,
            3 => WipeState::Wiped,
            _ => WipeState::None,
        }
    }

    pub const fn code(self) -> u8 {
        match self {
            WipeState::None => 0,
            WipeState::Device => 1,
            WipeState::AccountOnly => 2,
            WipeState::Wiped => 3,
        }
    }

    pub const fn is_pending(self) -> bool {
        matches!(self, WipeState::Device | WipeState::AccountOnly)
    }

    pub const fn is_evictable(self) -> bool {
        matches!(self, WipeState::None | WipeState::Wiped)
    }
}

pub trait EasDeviceAccess: Sync + Send {
    fn eas_device(
        &self,
        account_id: u32,
        device_id: &str,
        device_type: &str,
    ) -> impl Future<Output = trc::Result<ActiveDevice>> + Send;

    fn eas_gate(
        &self,
        ctx: &EasContext<'_>,
        command: Command,
        policy_key: Option<u32>,
    ) -> impl Future<Output = trc::Result<DeviceGate>> + Send;
}

impl EasDeviceAccess for Server {
    async fn eas_device(
        &self,
        account_id: u32,
        device_id: &str,
        device_type: &str,
    ) -> trc::Result<ActiveDevice> {
        let cache = self.get_cached_exchange(account_id).await?;
        if let Some(device) = cache.device(device_id) {
            return Ok(ActiveDevice::from(device));
        }
        let device = self
            .register_eas_device(
                account_id,
                device_id,
                device_type,
                self.core.exchange.max_devices,
            )
            .await?;
        Ok(ActiveDevice {
            slot: device.slot,
            policy_key: device.policy_key,
            wipe: device.wipe,
        })
    }

    async fn eas_gate(
        &self,
        ctx: &EasContext<'_>,
        command: Command,
        policy_key: Option<u32>,
    ) -> trc::Result<DeviceGate> {
        match WipeState::from_code(ctx.device.wipe) {
            WipeState::Wiped => {
                return Ok(DeviceGate::Refuse(EasResponse::Http(
                    HttpOutcome::Forbidden,
                )));
            }
            state if state.is_pending() && command != Command::Provision => {
                return Ok(DeviceGate::Refuse(EasResponse::status(
                    command,
                    CommonStatus::REMOTE_WIPE_REQUESTED.into(),
                )));
            }
            _ => {}
        }

        if matches!(command, Command::Provision | Command::Ping) {
            return Ok(DeviceGate::Allow);
        }

        match policy_key {
            None | Some(0) => Ok(DeviceGate::Allow),
            Some(key) if key == ctx.device.policy_key && PERMANENT_KEYS.contains(&key) => {
                Ok(DeviceGate::Allow)
            }
            Some(key) => {
                let stored = stored_eas_device(self, ctx.account_id, ctx.device.slot)
                    .await?
                    .map(|device| device.policy_key);
                if stored == Some(key) && PERMANENT_KEYS.contains(&key) {
                    Ok(DeviceGate::Allow)
                } else {
                    Ok(DeviceGate::Refuse(EasResponse::status(
                        command,
                        CommonStatus::INVALID_POLICY_KEY.into(),
                    )))
                }
            }
        }
    }
}

pub(crate) async fn stored_eas_device(
    server: &Server,
    account_id: u32,
    slot: u16,
) -> trc::Result<Option<EasDevice>> {
    let Some(archive) = server.exchange_account(account_id).await? else {
        return Ok(None);
    };
    let account = archive
        .deserialize::<ExchangeAccount>()
        .caused_by(trc::location!())?;
    Ok(account
        .devices
        .into_iter()
        .find(|device| device.slot == slot))
}
