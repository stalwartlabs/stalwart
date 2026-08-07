/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::method::query::Filter;
use jmap_proto::object::email::EmailFilter;
use jmap_proto::object::push_subscription::EmailPushProperty;
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
    pub properties: Vec<EmailPushProperty>,
    pub filter: Vec<Filter<EmailFilter>>,
    pub urgency: Urgency,
}

#[derive(
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
#[repr(u8)]
pub enum Urgency {
    VeryLow = 0,
    Low = 1,
    #[default]
    Normal = 2,
    High = 3,
}

impl From<&ArchivedUrgency> for Urgency {
    fn from(value: &ArchivedUrgency) -> Self {
        match value {
            ArchivedUrgency::VeryLow => Urgency::VeryLow,
            ArchivedUrgency::Low => Urgency::Low,
            ArchivedUrgency::Normal => Urgency::Normal,
            ArchivedUrgency::High => Urgency::High,
        }
    }
}

impl Urgency {
    pub fn as_str(&self) -> &'static str {
        match self {
            Urgency::VeryLow => "very-low",
            Urgency::Low => "low",
            Urgency::Normal => "normal",
            Urgency::High => "high",
        }
    }
}
