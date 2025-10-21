/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::collection::SyncCollection;
use jmap_tools::{Element, Property, Value};
use serde::Serialize;
use std::{fmt::Display, str::FromStr};
use utils::map::bitmap::{Bitmap, BitmapItem};

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, Serialize, PartialOrd, Ord)]
#[repr(u8)]
pub enum DataType {
    #[serde(rename = "Email")]
    Email = 0,
    #[serde(rename = "EmailDelivery")]
    EmailDelivery = 1,
    #[serde(rename = "EmailSubmission")]
    EmailSubmission = 2,
    #[serde(rename = "Mailbox")]
    Mailbox = 3,
    #[serde(rename = "Thread")]
    Thread = 4,
    #[serde(rename = "Identity")]
    Identity = 5,
    #[serde(rename = "Core")]
    Core = 6,
    #[serde(rename = "PushSubscription")]
    PushSubscription = 7,
    #[serde(rename = "SearchSnippet")]
    SearchSnippet = 8,
    #[serde(rename = "VacationResponse")]
    VacationResponse = 9,
    #[serde(rename = "MDN")]
    Mdn = 10,
    #[serde(rename = "Quota")]
    Quota = 11,
    #[serde(rename = "SieveScript")]
    SieveScript = 12,
    #[serde(rename = "Calendar")]
    Calendar = 13,
    #[serde(rename = "CalendarEvent")]
    CalendarEvent = 14,
    #[serde(rename = "CalendarEventNotification")]
    CalendarEventNotification = 15,
    #[serde(rename = "AddressBook")]
    AddressBook = 16,
    #[serde(rename = "ContactCard")]
    ContactCard = 17,
    #[serde(rename = "FileNode")]
    FileNode = 18,
    #[serde(rename = "Principal")]
    Principal = 19,
    #[serde(rename = "ShareNotification")]
    ShareNotification = 20,
    #[serde(rename = "ParticipantIdentity")]
    ParticipantIdentity = 21,
    #[serde(rename = "CalendarAlert")]
    CalendarAlert = 22,
    None = 23,
}

#[derive(Debug, Clone, Copy)]
pub struct StateChange {
    pub account_id: u32,
    pub change_id: u64,
    pub types: Bitmap<DataType>,
}

impl StateChange {
    pub fn new(account_id: u32) -> Self {
        Self {
            account_id,
            change_id: 0,
            types: Default::default(),
        }
    }

    pub fn set_change(&mut self, type_state: DataType) {
        self.types.insert(type_state);
    }

    pub fn with_change(mut self, type_state: DataType) -> Self {
        self.set_change(type_state);
        self
    }

    pub fn with_change_id(mut self, change_id: u64) -> Self {
        self.change_id = change_id;
        self
    }

    pub fn has_changes(&self) -> bool {
        !self.types.is_empty()
    }
}

impl BitmapItem for DataType {
    fn max() -> u64 {
        DataType::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, DataType::None)
    }
}

impl From<u64> for DataType {
    fn from(value: u64) -> Self {
        match value {
            0 => DataType::Email,
            1 => DataType::EmailDelivery,
            2 => DataType::EmailSubmission,
            3 => DataType::Mailbox,
            4 => DataType::Thread,
            5 => DataType::Identity,
            6 => DataType::Core,
            7 => DataType::PushSubscription,
            8 => DataType::SearchSnippet,
            9 => DataType::VacationResponse,
            10 => DataType::Mdn,
            11 => DataType::Quota,
            12 => DataType::SieveScript,
            13 => DataType::Calendar,
            14 => DataType::CalendarEvent,
            15 => DataType::CalendarEventNotification,
            16 => DataType::AddressBook,
            17 => DataType::ContactCard,
            18 => DataType::FileNode,
            19 => DataType::Principal,
            20 => DataType::ShareNotification,
            21 => DataType::ParticipantIdentity,
            22 => DataType::CalendarAlert,
            _ => {
                debug_assert!(false, "Invalid type_state value: {}", value);
                DataType::None
            }
        }
    }
}

impl From<DataType> for u64 {
    fn from(type_state: DataType) -> u64 {
        type_state as u64
    }
}

impl DataType {
    pub fn try_from_sync(value: SyncCollection, is_container: bool) -> Option<Self> {
        match (value, is_container) {
            (SyncCollection::Email, false) => DataType::Email.into(),
            (SyncCollection::Email, true) => DataType::Mailbox.into(),
            (SyncCollection::Thread, _) => DataType::Thread.into(),
            (SyncCollection::Calendar, true) => DataType::Calendar.into(),
            (SyncCollection::Calendar, false) => DataType::CalendarEvent.into(),
            (SyncCollection::AddressBook, true) => DataType::AddressBook.into(),
            (SyncCollection::AddressBook, false) => DataType::ContactCard.into(),
            (SyncCollection::FileNode, _) => DataType::FileNode.into(),
            (SyncCollection::Identity, _) => DataType::Identity.into(),
            (SyncCollection::EmailSubmission, _) => DataType::EmailSubmission.into(),
            (SyncCollection::SieveScript, _) => DataType::SieveScript.into(),
            _ => None,
        }
    }
}

impl DataType {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"Email" => DataType::Email,
            b"EmailDelivery" => DataType::EmailDelivery,
            b"EmailSubmission" => DataType::EmailSubmission,
            b"Mailbox" => DataType::Mailbox,
            b"Thread" => DataType::Thread,
            b"Identity" => DataType::Identity,
            b"Core" => DataType::Core,
            b"PushSubscription" => DataType::PushSubscription,
            b"SearchSnippet" => DataType::SearchSnippet,
            b"VacationResponse" => DataType::VacationResponse,
            b"MDN" => DataType::Mdn,
            b"Quota" => DataType::Quota,
            b"SieveScript" => DataType::SieveScript,
            b"Calendar" => DataType::Calendar,
            b"CalendarEvent" => DataType::CalendarEvent,
            b"CalendarEventNotification" => DataType::CalendarEventNotification,
            b"AddressBook" => DataType::AddressBook,
            b"ContactCard" => DataType::ContactCard,
            b"FileNode" => DataType::FileNode,
            b"Principal" => DataType::Principal,
            b"ShareNotification" => DataType::ShareNotification,
            b"ParticipantIdentity" => DataType::ParticipantIdentity,
            b"CalendarAlert" => DataType::CalendarAlert,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DataType::Email => "Email",
            DataType::EmailDelivery => "EmailDelivery",
            DataType::EmailSubmission => "EmailSubmission",
            DataType::Mailbox => "Mailbox",
            DataType::Thread => "Thread",
            DataType::Identity => "Identity",
            DataType::Core => "Core",
            DataType::PushSubscription => "PushSubscription",
            DataType::SearchSnippet => "SearchSnippet",
            DataType::VacationResponse => "VacationResponse",
            DataType::Mdn => "MDN",
            DataType::Quota => "Quota",
            DataType::SieveScript => "SieveScript",
            DataType::Calendar => "Calendar",
            DataType::CalendarEvent => "CalendarEvent",
            DataType::CalendarEventNotification => "CalendarEventNotification",
            DataType::AddressBook => "AddressBook",
            DataType::ContactCard => "ContactCard",
            DataType::FileNode => "FileNode",
            DataType::Principal => "Principal",
            DataType::ShareNotification => "ShareNotification",
            DataType::ParticipantIdentity => "ParticipantIdentity",
            DataType::CalendarAlert => "CalendarAlert",
            DataType::None => "",
        }
    }
}

impl FromStr for DataType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DataType::parse(s).ok_or(())
    }
}

impl Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DataType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DataType::parse(<&str>::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("invalid JMAP data type"))
    }
}

impl<'x, P: Property, E: Element + From<DataType>> From<DataType> for Value<'x, P, E> {
    fn from(id: DataType) -> Self {
        Value::Element(E::from(id))
    }
}
