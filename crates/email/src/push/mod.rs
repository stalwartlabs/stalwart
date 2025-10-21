/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Default, Debug, Clone, PartialEq, Eq,
)]
pub struct PushSubscription {
    pub id: u32,
    pub url: String,
    pub device_client_id: String,
    pub expires: u64,
    pub verification_code: String,
    pub verified: bool,
    pub types: Bitmap<DataType>,
    pub keys: Option<Keys>,
    pub email_push: Vec<EmailPush>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Default, Debug, Clone, PartialEq, Eq,
)]
pub struct PushSubscriptions {
    pub subscriptions: Vec<PushSubscription>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Default, Debug, Clone, PartialEq, Eq,
)]
pub struct EmailPush {
    pub account_id: u32,
    pub properties: u64,
    pub filters: Vec<EmailPushFilter>,
    pub flags: u16,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum EmailPushFilter {
    Condition { field: u8, value: EmailPushValue },
    And,
    Or,
    Not,
    End,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum EmailPushValue {
    Text(String),
    Number(u64),
    TextList(Vec<String>),
    NumberList(Vec<u64>),
}
