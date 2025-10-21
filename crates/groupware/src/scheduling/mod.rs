/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use calcard::{
    common::{IanaString, PartialDateTime},
    icalendar::{
        ICalendarComponent, ICalendarDuration, ICalendarEntry, ICalendarMethod, ICalendarParameter,
        ICalendarParticipationRole, ICalendarParticipationStatus, ICalendarPeriod,
        ICalendarProperty, ICalendarRecurrenceRule, ICalendarScheduleForceSendValue,
        ICalendarStatus, ICalendarUserTypes, ICalendarValue, Uri,
    },
};
use std::{fmt::Display, hash::Hash};

pub mod attendee;
pub mod event_cancel;
pub mod event_create;
pub mod event_update;
pub mod inbound;
pub mod itip;
pub mod organizer;
pub mod snapshot;

#[derive(Debug)]
pub struct ItipSnapshots<'x> {
    pub organizer: Organizer<'x>,
    pub uid: &'x str,
    pub components: AHashMap<InstanceId, ItipSnapshot<'x>>,
}

#[derive(Debug)]
pub struct ItipSnapshot<'x> {
    pub comp_id: u16,
    pub comp: &'x ICalendarComponent,
    pub attendees: AHashSet<Attendee<'x>>,
    pub dtstamp: Option<&'x PartialDateTime>,
    pub entries: AHashSet<ItipEntry<'x>>,
    pub sequence: Option<i64>,
    pub request_status: Vec<&'x str>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ItipEntry<'x> {
    pub name: &'x ICalendarProperty,
    pub value: ItipEntryValue<'x>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ItipEntryValue<'x> {
    DateTime(ItipDateTime<'x>),
    Period(&'x ICalendarPeriod),
    Duration(&'x ICalendarDuration),
    Status(&'x ICalendarStatus),
    RRule(&'x ICalendarRecurrenceRule),
    Text(&'x str),
    Integer(i64),
}

#[derive(Debug)]
pub struct ItipDateTime<'x> {
    pub date: &'x PartialDateTime,
    pub tz_id: Option<&'x str>,
    pub tz_code: u16,
    pub timestamp: i64,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstanceId {
    Main,
    Recurrence(RecurrenceId),
}

#[derive(Debug, PartialOrd, Ord)]
pub struct RecurrenceId {
    pub entry_id: u16,
    pub date: i64,
    pub this_and_future: bool,
}

#[derive(Debug)]
pub struct Attendee<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub name: Option<&'x str>,
    pub part_stat: Option<&'x ICalendarParticipationStatus>,
    pub delegated_from: Vec<Email>,
    pub delegated_to: Vec<Email>,
    pub role: Option<&'x ICalendarParticipationRole>,
    pub cu_type: Option<&'x ICalendarUserTypes>,
    pub sent_by: Option<Email>,
    pub rsvp: Option<bool>,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Organizer<'x> {
    pub entry_id: u16,
    pub email: Email,
    pub name: Option<&'x str>,
    pub is_server_scheduling: bool,
    pub force_send: Option<&'x ICalendarScheduleForceSendValue>,
}

#[derive(Debug)]
pub struct Email {
    pub email: String,
    pub is_local: bool,
}

#[derive(Debug)]
pub enum ItipError {
    NoSchedulingInfo,
    OtherSchedulingAgent,
    NotOrganizer,
    NotOrganizerNorAttendee,
    NothingToSend,
    MissingUid,
    MultipleUid,
    MultipleOrganizer,
    MultipleObjectTypes,
    MultipleObjectInstances,
    CannotModifyProperty(ICalendarProperty),
    CannotModifyInstance,
    CannotModifyAddress,
    OrganizerMismatch,
    MissingMethod,
    InvalidComponentType,
    OutOfSequence,
    OrganizerIsLocalAddress,
    SenderIsNotOrganizerNorAttendee,
    SenderIsNotParticipant(String),
    UnknownParticipant(String),
    UnsupportedMethod(ICalendarMethod),
    ICalendarParseError,
    EventNotFound,
    EventTooLarge,
    QuotaExceeded,
    NoDefaultCalendar,
    AutoAddDisabled,
}

#[derive(Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct ItipMessage<T> {
    pub from: String,
    pub from_organizer: bool,
    pub to: Vec<String>,
    pub summary: ItipSummary,
    pub message: T,
}

#[derive(Debug, Clone, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub enum ItipSummary {
    Invite(Vec<ItipField>),
    Update {
        method: ICalendarMethod,
        current: Vec<ItipField>,
        previous: Vec<ItipField>,
    },
    Cancel(Vec<ItipField>),
    Rsvp {
        part_stat: ICalendarParticipationStatus,
        current: Vec<ItipField>,
    },
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct ItipField {
    pub name: ICalendarProperty,
    pub value: ItipValue,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub enum ItipValue {
    Text(String),
    Time(ItipTime),
    Rrule(Box<ICalendarRecurrenceRule>),
    Participants(Vec<ItipParticipant>),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct ItipTime {
    pub start: i64,
    pub tz_id: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct ItipParticipant {
    pub email: String,
    pub name: Option<String>,
    pub is_organizer: bool,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct ItipMessages {
    pub messages: Vec<ItipMessage<String>>,
}

impl Attendee<'_> {
    pub fn send_invite_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self.part_stat.is_none_or(|part_stat| {
                    part_stat == &ICalendarParticipationStatus::NeedsAction
                }))
    }

    pub fn send_update_messages(&self) -> bool {
        !self.email.is_local
            && self.is_server_scheduling
            && self.rsvp.is_none_or(|rsvp| rsvp)
            && (self.force_send.is_some()
                || self
                    .part_stat
                    .is_none_or(|part_stat| part_stat != &ICalendarParticipationStatus::Declined))
    }

    pub fn is_delegated_from(&self, attendee: &Attendee<'_>) -> bool {
        self.delegated_from
            .iter()
            .any(|d| d.email == attendee.email.email)
    }

    pub fn is_delegated_to(&self, attendee: &Attendee<'_>) -> bool {
        self.delegated_to
            .iter()
            .any(|d| d.email == attendee.email.email)
    }
}

impl Email {
    pub fn new(email: &str, local_addresses: &[String]) -> Option<Self> {
        email.contains('@').then(|| {
            let email = email.trim().trim_start_matches("mailto:").to_lowercase();
            let is_local = local_addresses.contains(&email);
            Email { email, is_local }
        })
    }

    pub fn from_uri(uri: &Uri, local_addresses: &[String]) -> Option<Self> {
        if let Uri::Location(uri) = uri {
            Email::new(uri.as_str(), local_addresses)
        } else {
            None
        }
    }
}

impl PartialEq for Attendee<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
            && self.part_stat == other.part_stat
            && self.delegated_from == other.delegated_from
            && self.delegated_to == other.delegated_to
            && self.role == other.role
            && self.cu_type == other.cu_type
            && self.sent_by == other.sent_by
    }
}

impl Eq for Attendee<'_> {}

impl Hash for Attendee<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
        self.part_stat.hash(state);
        self.delegated_from.hash(state);
        self.delegated_to.hash(state);
        self.role.hash(state);
        self.cu_type.hash(state);
        self.sent_by.hash(state);
    }
}

impl Display for Email {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mailto:{}", self.email)
    }
}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.email.hash(state);
    }
}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
    }
}

impl Eq for Email {}

impl PartialEq for RecurrenceId {
    fn eq(&self, other: &Self) -> bool {
        self.date == other.date && self.this_and_future == other.this_and_future
    }
}

impl Eq for RecurrenceId {}

impl Hash for RecurrenceId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.date.hash(state);
        self.this_and_future.hash(state);
    }
}

impl PartialEq for ItipDateTime<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp
    }
}
impl Eq for ItipDateTime<'_> {}

impl Hash for ItipDateTime<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.timestamp.hash(state);
    }
}

impl ItipDateTime<'_> {
    pub fn to_entry(&self, name: ICalendarProperty) -> ICalendarEntry {
        ICalendarEntry {
            name,
            params: self
                .tz_id
                .map(|tz_id| vec![ICalendarParameter::tzid(tz_id.to_string())])
                .unwrap_or_default(),
            values: vec![ICalendarValue::PartialDateTime(Box::new(self.date.clone()))],
        }
    }
}

impl ItipError {
    pub fn is_jmap_error(&self) -> bool {
        matches!(
            self,
            ItipError::MultipleOrganizer
                | ItipError::OrganizerIsLocalAddress
                | ItipError::SenderIsNotParticipant(_)
                | ItipError::OrganizerMismatch
                | ItipError::CannotModifyProperty(_)
                | ItipError::CannotModifyInstance
                | ItipError::CannotModifyAddress
                //| ItipError::MissingUid
                | ItipError::MultipleUid
                | ItipError::MultipleObjectTypes
                | ItipError::MultipleObjectInstances
                | ItipError::MissingMethod
                | ItipError::InvalidComponentType
                | ItipError::OutOfSequence
                | ItipError::UnknownParticipant(_)
                | ItipError::UnsupportedMethod(_)
        )
    }
}

impl Display for ItipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ItipError::NoSchedulingInfo => write!(f, "No scheduling information found"),
            ItipError::OtherSchedulingAgent => write!(f, "Other scheduling agent"),
            ItipError::NotOrganizer => write!(f, "Not the organizer of the event"),
            ItipError::NotOrganizerNorAttendee => write!(f, "Not an organizer or attendee"),
            ItipError::NothingToSend => write!(f, "No iTIP messages to send"),
            ItipError::MissingUid => write!(f, "Missing UID in iCalendar object"),
            ItipError::MultipleUid => write!(f, "Multiple UIDs found in iCalendar object"),
            ItipError::MultipleOrganizer => {
                write!(f, "Multiple organizers found in iCalendar object")
            }
            ItipError::MultipleObjectTypes => {
                write!(f, "Multiple object types found in iCalendar object")
            }
            ItipError::MultipleObjectInstances => {
                write!(f, "Multiple object instances found in iCalendar object")
            }
            ItipError::CannotModifyProperty(prop) => {
                write!(f, "Cannot modify property {}", prop.as_str())
            }
            ItipError::CannotModifyInstance => write!(f, "Cannot modify instance of the event"),
            ItipError::CannotModifyAddress => write!(f, "Cannot modify address of the event"),
            ItipError::OrganizerMismatch => write!(f, "Organizer mismatch in iCalendar object"),
            ItipError::MissingMethod => write!(f, "Missing method in the iTIP message"),
            ItipError::InvalidComponentType => {
                write!(f, "Invalid component type in iCalendar object")
            }
            ItipError::OutOfSequence => write!(f, "Old sequence number found"),
            ItipError::OrganizerIsLocalAddress => {
                write!(
                    f,
                    "Organizer matches one of the recipient's account addresses"
                )
            }
            ItipError::SenderIsNotParticipant(participant) => {
                write!(f, "Sender {participant:?} is not a participant")
            }
            ItipError::SenderIsNotOrganizerNorAttendee => {
                write!(f, "Sender is neither organizer nor attendee")
            }
            ItipError::UnknownParticipant(participant) => {
                write!(f, "Unknown participant: {}", participant)
            }
            ItipError::UnsupportedMethod(method) => {
                write!(f, "Unsupported method: {}", method.as_str())
            }
            ItipError::ICalendarParseError => write!(f, "Failed to parse iCalendar object"),
            ItipError::EventNotFound => write!(f, "Event found in index but not in database"),
            ItipError::EventTooLarge => write!(
                f,
                "Applying the iTIP message would exceed the maximum event size"
            ),
            ItipError::QuotaExceeded => write!(f, "Quota exceeded"),
            ItipError::NoDefaultCalendar => write!(f, "No default calendar found for the account"),
            ItipError::AutoAddDisabled => {
                write!(f, "Auto-adding events is disabled for this account")
            }
        }
    }
}
