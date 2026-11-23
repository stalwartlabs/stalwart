/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{auth::AccessToken, cache::exchange::ExchangeDevice};
use exchange_proto::eas::{http::RequestParams, tokens::ProtocolVersion};
use http_proto::HttpSessionData;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveDevice {
    pub slot: u16,
    pub policy_key: u32,
    pub wipe: u8,
}

impl From<&ExchangeDevice> for ActiveDevice {
    fn from(device: &ExchangeDevice) -> Self {
        ActiveDevice {
            slot: device.slot,
            policy_key: device.policy_key,
            wipe: device.wipe,
        }
    }
}

pub struct EasContext<'x> {
    pub access_token: AccessToken,
    pub account_id: u32,
    pub device: ActiveDevice,
    pub version: ProtocolVersion,
    pub params: RequestParams<'x>,
    pub data_types: Bitmap<DataType>,
    pub session: &'x HttpSessionData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EasDataKind {
    Mail,
    Calendar,
    Contacts,
}

impl<'x> EasContext<'x> {
    pub fn new(
        access_token: AccessToken,
        device: ActiveDevice,
        version: ProtocolVersion,
        params: RequestParams<'x>,
        session: &'x HttpSessionData,
    ) -> Self {
        let mut data_types = Bitmap::from_iter([
            DataType::Email,
            DataType::EmailDelivery,
            DataType::EmailSubmission,
            DataType::Mailbox,
            DataType::Thread,
            DataType::VacationResponse,
            DataType::Calendar,
            DataType::CalendarEvent,
            DataType::AddressBook,
            DataType::ContactCard,
            DataType::Principal,
        ]);
        access_token.restrict_data_types(&mut data_types);
        EasContext {
            account_id: access_token.account_id(),
            access_token,
            device,
            version,
            params,
            data_types,
            session,
        }
    }

    pub fn allows(&self, kind: EasDataKind) -> bool {
        match kind {
            EasDataKind::Mail => {
                self.data_types.contains(DataType::Email)
                    && self.data_types.contains(DataType::Mailbox)
            }
            EasDataKind::Calendar => self.data_types.contains(DataType::CalendarEvent),
            EasDataKind::Contacts => self.data_types.contains(DataType::ContactCard),
        }
    }

    pub fn allows_type(&self, data_type: DataType) -> bool {
        self.data_types.contains(data_type)
    }
}
