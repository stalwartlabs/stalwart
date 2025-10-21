/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod alarm;
pub mod dates;
pub mod expand;
pub mod index;
pub mod itip;
pub mod storage;

use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry,
};
use common::{DavName, auth::AccessToken};
use types::{acl::AclGrant, dead_property::DeadProperty};
use utils::map::bitmap::BitmapItem;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Calendar {
    pub name: String,
    pub preferences: Vec<CalendarPreferences>,
    pub acls: Vec<AclGrant>,
    pub supported_components: u64,
    pub dead_properties: DeadProperty,
    pub created: i64,
    pub modified: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedComponent {
    VCalendar,     // [RFC5545, Section 3.4]
    VEvent,        // [RFC5545, Section 3.6.1]
    VTodo,         // [RFC5545, Section 3.6.2]
    VJournal,      // [RFC5545, Section 3.6.3]
    VFreebusy,     // [RFC5545, Section 3.6.4]
    VTimezone,     // [RFC5545, Section 3.6.5]
    VAlarm,        // [RFC5545, Section 3.6.6]
    Standard,      // [RFC5545, Section 3.6.5]
    Daylight,      // [RFC5545, Section 3.6.5]
    VAvailability, // [RFC7953, Section 3.1]
    Available,     // [RFC7953, Section 3.1]
    Participant,   // [RFC9073, Section 7.1]
    VLocation,     // [RFC9073, Section 7.2] [RFC Errata 7381]
    VResource,     // [RFC9073, Section 7.3]
    VStatus,       // draft-ietf-calext-ical-tasks-14
    Other,
}

pub const CALENDAR_SUBSCRIBED: u16 = 1;
pub const CALENDAR_INVISIBLE: u16 = 1 << 1;
pub const CALENDAR_AVAILABILITY_NONE: u16 = 1 << 2;
pub const CALENDAR_AVAILABILITY_ATTENDING: u16 = 1 << 3;
pub const CALENDAR_AVAILABILITY_ALL: u16 = 1 << 4;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarPreferences {
    pub account_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
    pub color: Option<String>,
    pub flags: u16,
    pub time_zone: Timezone,
    pub default_alerts: Vec<DefaultAlert>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct DefaultAlert {
    pub id: String,
    pub offset: ICalendarDuration,
    pub flags: u16,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ParticipantIdentities {
    pub identities: Vec<ParticipantIdentity>,
    pub default_name: String,
    pub default: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ParticipantIdentity {
    pub id: u32,
    pub name: Option<String>,
    pub calendar_address: String,
}

pub const ALERT_WITH_TIME: u16 = 1;
pub const ALERT_EMAIL: u16 = 1 << 1;
pub const ALERT_RELATIVE_TO_END: u16 = 1 << 2;

pub const SCHEDULE_INBOX_ID: u32 = u32::MAX - 1;
pub const SCHEDULE_OUTBOX_ID: u32 = u32::MAX - 2;

pub const EVENT_INVITE_SELF: u16 = 1;
pub const EVENT_INVITE_OTHERS: u16 = 1 << 1;
pub const EVENT_HIDE_ATTENDEES: u16 = 1 << 2;
pub const EVENT_DRAFT: u16 = 1 << 3;

pub const EVENT_NOTIFICATION_IS_DRAFT: u16 = 1;
pub const EVENT_NOTIFICATION_IS_CHANGE: u16 = 1 << 1;

pub const PREF_USE_DEFAULT_ALERTS: u16 = 1;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEvent {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub data: CalendarEventData,
    pub preferences: Vec<EventPreferences>,
    pub flags: u16,
    pub dead_properties: DeadProperty,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
    pub schedule_tag: Option<u32>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventNotification {
    pub event: ICalendar,
    pub event_id: Option<u32>,
    pub changed_by: ChangedBy,
    pub flags: u16,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum ChangedBy {
    PrincipalId(u32),
    CalendarAddress(String),
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventData {
    pub event: ICalendar,
    pub time_ranges: Box<[ComponentTimeRange]>,
    pub alarms: Box<[Alarm]>,
    pub base_offset: i64,
    pub base_time_utc: u32,
    pub duration: u32,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Alarm {
    pub id: u16,
    pub parent_id: u16,
    pub delta: AlarmDelta,
    pub is_email_alert: bool,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum AlarmDelta {
    Start(i64),
    End(i64),
    FixedUtc(i64),
    FixedFloating(i64),
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ComponentTimeRange {
    pub id: u16,
    pub start_tz: u16,
    pub end_tz: u16,
    pub duration: i32,
    pub instances: Box<[u8]>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EventPreferences {
    pub account_id: u32,
    pub flags: u16,
    pub properties: Vec<ICalendarEntry>,
    pub alerts: Vec<ICalendarComponent>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub enum Timezone {
    IANA(u16),
    Custom(ICalendar),
    #[default]
    Default,
}

impl Calendar {
    pub fn preferences(&self, access_token: &AccessToken) -> &CalendarPreferences {
        if self.preferences.len() == 1 {
            &self.preferences[0]
        } else {
            let account_id = access_token.primary_id();
            self.preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or_else(|| self.preferences.first())
                .unwrap()
        }
    }

    pub fn preferences_mut(&mut self, access_token: &AccessToken) -> &mut CalendarPreferences {
        let account_id = access_token.primary_id();
        let idx = if let Some(idx) = self
            .preferences
            .iter()
            .position(|p| p.account_id == account_id)
        {
            idx
        } else {
            let mut preferences = self.preferences[0].clone();
            preferences.account_id = account_id;
            self.preferences.push(preferences);
            self.preferences.len() - 1
        };

        &mut self.preferences[idx]
    }
}

impl ArchivedCalendar {
    pub fn default_alerts(
        &self,
        access_token: &AccessToken,
        with_time: bool,
    ) -> impl Iterator<Item = &ArchivedDefaultAlert> {
        self.preferences(access_token)
            .default_alerts
            .iter()
            .filter(move |a| (a.flags & ALERT_WITH_TIME != 0) == with_time)
    }

    pub fn preferences(&self, access_token: &AccessToken) -> &ArchivedCalendarPreferences {
        if self.preferences.len() == 1 {
            &self.preferences[0]
        } else {
            let account_id = access_token.primary_id();
            self.preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or_else(|| self.preferences.first())
                .unwrap()
        }
    }
}

impl CalendarEvent {
    pub fn preferences(&self, access_token: &AccessToken) -> Option<&EventPreferences> {
        self.preferences
            .iter()
            .find(|p| p.account_id == access_token.primary_id())
    }

    pub fn preferences_mut(&mut self, access_token: &AccessToken) -> &mut EventPreferences {
        let account_id = access_token.primary_id();
        let idx = if let Some(idx) = self
            .preferences
            .iter()
            .position(|p| p.account_id == account_id)
        {
            idx
        } else {
            self.preferences.push(EventPreferences {
                account_id,
                flags: PREF_USE_DEFAULT_ALERTS,
                properties: Vec::new(),
                alerts: Vec::new(),
            });
            self.preferences.len() - 1
        };

        &mut self.preferences[idx]
    }

    pub fn added_calendar_ids(
        &self,
        prev_data: &ArchivedCalendarEvent,
    ) -> impl Iterator<Item = u32> {
        self.names
            .iter()
            .filter(|m| prev_data.names.iter().all(|pm| pm.parent_id != m.parent_id))
            .map(|m| m.parent_id)
    }

    pub fn removed_calendar_ids(
        &self,
        prev_data: &ArchivedCalendarEvent,
    ) -> impl Iterator<Item = u32> {
        prev_data
            .names
            .iter()
            .filter(|m| self.names.iter().all(|pm| pm.parent_id != m.parent_id))
            .map(|m| m.parent_id.to_native())
    }

    pub fn unchanged_calendar_ids(
        &self,
        prev_data: &ArchivedCalendarEvent,
    ) -> impl Iterator<Item = u32> {
        self.names
            .iter()
            .filter(|m| prev_data.names.iter().any(|pm| pm.parent_id == m.parent_id))
            .map(|m| m.parent_id)
    }
}

impl ArchivedCalendarEvent {
    pub fn preferences(&self, access_token: &AccessToken) -> Option<&ArchivedEventPreferences> {
        self.preferences
            .iter()
            .find(|p| p.account_id == access_token.primary_id())
    }
}

impl Default for ChangedBy {
    fn default() -> Self {
        ChangedBy::CalendarAddress("".into())
    }
}

impl From<u64> for SupportedComponent {
    fn from(value: u64) -> Self {
        match value {
            0 => SupportedComponent::VCalendar,
            1 => SupportedComponent::VEvent,
            2 => SupportedComponent::VTodo,
            3 => SupportedComponent::VJournal,
            4 => SupportedComponent::VFreebusy,
            5 => SupportedComponent::VTimezone,
            6 => SupportedComponent::VAlarm,
            7 => SupportedComponent::Standard,
            8 => SupportedComponent::Daylight,
            9 => SupportedComponent::VAvailability,
            10 => SupportedComponent::Available,
            11 => SupportedComponent::Participant,
            12 => SupportedComponent::VLocation,
            13 => SupportedComponent::VResource,
            14 => SupportedComponent::VStatus,
            _ => SupportedComponent::Other,
        }
    }
}

impl From<SupportedComponent> for u64 {
    fn from(value: SupportedComponent) -> Self {
        match value {
            SupportedComponent::VCalendar => 0,
            SupportedComponent::VEvent => 1,
            SupportedComponent::VTodo => 2,
            SupportedComponent::VJournal => 3,
            SupportedComponent::VFreebusy => 4,
            SupportedComponent::VTimezone => 5,
            SupportedComponent::VAlarm => 6,
            SupportedComponent::Standard => 7,
            SupportedComponent::Daylight => 8,
            SupportedComponent::VAvailability => 9,
            SupportedComponent::Available => 10,
            SupportedComponent::Participant => 11,
            SupportedComponent::VLocation => 12,
            SupportedComponent::VResource => 13,
            SupportedComponent::VStatus => 14,
            SupportedComponent::Other => 15,
        }
    }
}

impl BitmapItem for SupportedComponent {
    fn max() -> u64 {
        u64::from(SupportedComponent::Other)
    }

    fn is_valid(&self) -> bool {
        !matches!(self, SupportedComponent::Other)
    }
}

impl From<ICalendarComponentType> for SupportedComponent {
    fn from(value: ICalendarComponentType) -> Self {
        match value {
            ICalendarComponentType::VCalendar => SupportedComponent::VCalendar,
            ICalendarComponentType::VEvent => SupportedComponent::VEvent,
            ICalendarComponentType::VTodo => SupportedComponent::VTodo,
            ICalendarComponentType::VJournal => SupportedComponent::VJournal,
            ICalendarComponentType::VFreebusy => SupportedComponent::VFreebusy,
            ICalendarComponentType::VTimezone => SupportedComponent::VTimezone,
            ICalendarComponentType::VAlarm => SupportedComponent::VAlarm,
            ICalendarComponentType::Standard => SupportedComponent::Standard,
            ICalendarComponentType::Daylight => SupportedComponent::Daylight,
            ICalendarComponentType::VAvailability => SupportedComponent::VAvailability,
            ICalendarComponentType::Available => SupportedComponent::Available,
            ICalendarComponentType::Participant => SupportedComponent::Participant,
            ICalendarComponentType::VLocation => SupportedComponent::VLocation,
            ICalendarComponentType::VResource => SupportedComponent::VResource,
            ICalendarComponentType::VStatus => SupportedComponent::VStatus,
            _ => SupportedComponent::Other,
        }
    }
}

impl From<SupportedComponent> for ICalendarComponentType {
    fn from(value: SupportedComponent) -> Self {
        match value {
            SupportedComponent::VCalendar => ICalendarComponentType::VCalendar,
            SupportedComponent::VEvent => ICalendarComponentType::VEvent,
            SupportedComponent::VTodo => ICalendarComponentType::VTodo,
            SupportedComponent::VJournal => ICalendarComponentType::VJournal,
            SupportedComponent::VFreebusy => ICalendarComponentType::VFreebusy,
            SupportedComponent::VTimezone => ICalendarComponentType::VTimezone,
            SupportedComponent::VAlarm => ICalendarComponentType::VAlarm,
            SupportedComponent::Standard => ICalendarComponentType::Standard,
            SupportedComponent::Daylight => ICalendarComponentType::Daylight,
            SupportedComponent::VAvailability => ICalendarComponentType::VAvailability,
            SupportedComponent::Available => ICalendarComponentType::Available,
            SupportedComponent::Participant => ICalendarComponentType::Participant,
            SupportedComponent::VLocation => ICalendarComponentType::VLocation,
            SupportedComponent::VResource => ICalendarComponentType::VResource,
            SupportedComponent::VStatus => ICalendarComponentType::VStatus,
            SupportedComponent::Other => ICalendarComponentType::Other(Default::default()),
        }
    }
}
