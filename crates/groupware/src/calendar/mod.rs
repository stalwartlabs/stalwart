/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod alarm;
pub mod alerts;
pub mod color;
pub mod compare;
pub mod dates;
pub mod expand;
pub mod identity;
pub mod index;
pub mod instance_filter;
pub mod itip;
pub mod notification;
pub mod participants;
pub mod privacy;
pub mod rights;
pub mod schedule;
pub mod sequence;
pub mod storage;
pub mod user;

use calcard::icalendar::{
    ArchivedICalendar, ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarDuration,
};
use color::CssColor;
use common::{DavName, NO_ID};
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
    pub change_id: u32,
    pub trimmed_change_id: u32,
    pub changes: Vec<ParticipantIdentityChange>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParticipantIdentityChange {
    pub change_id: u32,
    pub id: u32,
    pub change_type: ParticipantIdentityChangeType,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantIdentityChangeType {
    Created,
    Updated,
    Destroyed,
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
pub const DIRECT_NOTIFICATION_PARENT_ID: u32 = u32::MAX - 3;

pub const EVENT_INVITE_SELF: u16 = 1;
pub const EVENT_INVITE_OTHERS: u16 = 1 << 1;
pub const EVENT_HIDE_ATTENDEES: u16 = 1 << 2;
pub const EVENT_DRAFT: u16 = 1 << 3;
pub const EVENT_HAS_DEAD_PROPERTIES: u16 = 1 << 4;
pub const EVENT_HAS_ALARMS: u16 = 1 << 5;
pub const EVENT_PRIVATE: u16 = 1 << 6;
pub const EVENT_SECRET: u16 = 1 << 7;
pub const EVENT_USES_DEFAULT_ALERTS: u16 = 1 << 8;

pub const EVENT_NOTIFICATION_IS_DRAFT: u16 = 1;
pub const EVENT_NOTIFICATION_IS_CHANGE: u16 = 1 << 1;
pub const EVENT_NOTIFICATION_IS_DESTROY: u16 = 1 << 2;
pub const EVENT_NOTIFICATION_IS_DIRECT: u16 = 1 << 3;
pub const EVENT_NOTIFICATION_OWNER_ONLY: u16 = 1 << 4;

pub const PREF_USE_DEFAULT_ALERTS: u16 = 1;
pub const PREF_HAS_USE_DEFAULT_ALERTS: u16 = 1 << 1;
pub const PREF_HAS_COLOR: u16 = 1 << 2;
pub const PREF_HAS_KEYWORDS: u16 = 1 << 3;
pub const PREF_HAS_ALERTS: u16 = 1 << 4;
pub const PREF_HAS_FREE_BUSY: u16 = 1 << 5;
pub const PREF_FREE_BUSY_FREE: u16 = 1 << 6;

pub const MAX_USER_KEYWORDS: usize = 64;
pub const MAX_USER_KEYWORD_LEN: usize = 128;
pub const MAX_USER_ALERTS: usize = 32;
pub const MAX_USER_INSTANCES: usize = 128;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEvent {
    pub names: Vec<DavName>,
    pub uid: String,
    pub display_name: Option<String>,
    pub start: i64,
    pub duration: u32,
    pub created: i64,
    pub modified: i64,
    pub size: u32,
    pub etag: u32,
    pub flags: u16,
    pub schedule_tag: Option<u32>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventContent {
    pub data: CalendarEventData,
    pub preferences: Vec<EventPreferences>,
    pub dead_properties: DeadProperty,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventNotification {
    pub event_id: Option<u32>,
    pub changed_by: ChangedBy,
    pub calendar_ids: Vec<u32>,
    pub dismissed_by: Vec<u32>,
    pub created: i64,
    pub modified: i64,
    pub size: u32,
    pub etag: u32,
    pub flags: u16,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub enum CalendarEventNotificationContent {
    Direct {
        previous: Option<ICalendar>,
        current: Option<ICalendar>,
    },
    Itip {
        message: ICalendar,
        previous: Option<ICalendar>,
        current: Option<ICalendar>,
    },
}

impl ArchivedCalendarEventNotification {
    pub fn changed_by_id(&self) -> u32 {
        match &self.changed_by {
            ArchivedChangedBy::PrincipalId(id) => id.to_native(),
            ArchivedChangedBy::CalendarAddress(_) => NO_ID,
        }
    }

    pub fn dismissed_ids(&self) -> impl Iterator<Item = u32> {
        self.dismissed_by.iter().map(|id| id.to_native())
    }

    pub fn calendar_ids(&self) -> impl Iterator<Item = u32> {
        self.calendar_ids.iter().map(|id| id.to_native())
    }
}

impl CalendarEventNotification {
    pub fn changed_by_id(&self) -> u32 {
        match &self.changed_by {
            ChangedBy::PrincipalId(id) => *id,
            ChangedBy::CalendarAddress(_) => NO_ID,
        }
    }
}

impl Default for CalendarEventNotificationContent {
    fn default() -> Self {
        CalendarEventNotificationContent::Direct {
            previous: None,
            current: None,
        }
    }
}

impl CalendarEventNotificationContent {
    pub fn snapshots(&self) -> [Option<&ICalendar>; 3] {
        match self {
            CalendarEventNotificationContent::Direct { previous, current } => {
                [None, previous.as_ref(), current.as_ref()]
            }
            CalendarEventNotificationContent::Itip {
                message,
                previous,
                current,
            } => [Some(message), previous.as_ref(), current.as_ref()],
        }
    }
}

impl ArchivedCalendarEventNotificationContent {
    pub fn previous(&self) -> Option<&ArchivedICalendar> {
        match self {
            ArchivedCalendarEventNotificationContent::Direct { previous, .. }
            | ArchivedCalendarEventNotificationContent::Itip { previous, .. } => previous.as_ref(),
        }
    }

    pub fn current(&self) -> Option<&ArchivedICalendar> {
        match self {
            ArchivedCalendarEventNotificationContent::Direct { current, .. }
            | ArchivedCalendarEventNotificationContent::Itip { current, .. } => current.as_ref(),
        }
    }

    pub fn calendar_data(&self) -> Option<&ArchivedICalendar> {
        self.itip_message()
            .or_else(|| self.current())
            .or_else(|| self.previous())
    }

    pub fn itip_message(&self) -> Option<&ArchivedICalendar> {
        match self {
            ArchivedCalendarEventNotificationContent::Itip { message, .. } => Some(message),
            ArchivedCalendarEventNotificationContent::Direct { .. } => None,
        }
    }
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
    pub flags: u16,
}

pub const ALARM_EMAIL: u16 = 1;

impl Alarm {
    pub fn is_email(&self) -> bool {
        self.flags & ALARM_EMAIL != 0
    }
}

impl ArchivedAlarm {
    pub fn is_email(&self) -> bool {
        self.flags.to_native() & ALARM_EMAIL != 0
    }
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum AlarmDelta {
    Start(AlarmOffset),
    End(AlarmOffset),
    FixedUtc(i64),
    FixedFloating(i64),
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AlarmOffset {
    pub days: i32,
    pub seconds: i32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ComponentTimeRange {
    pub id: u16,
    pub start_tz: u16,
    pub end_tz: u16,
    pub duration: i32,
    pub flags: u8,
    pub instances: Box<[u8]>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EventPreferences {
    pub account_id: u32,
    pub updated: i64,
    pub instances: Vec<EventUserData>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct EventUserData {
    pub recurrence_key: u32,
    pub flags: u16,
    pub color: Option<CssColor>,
    pub keywords: Vec<String>,
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
    pub fn personal_preferences(&self, account_id: u32) -> Option<&CalendarPreferences> {
        self.preferences.iter().find(|p| p.account_id == account_id)
    }

    pub fn subscribe_member(&mut self, account_id: u32) {
        if self.personal_preferences(account_id).is_none() {
            self.preferences_mut(account_id).flags |= CALENDAR_SUBSCRIBED;
        }
    }

    pub fn preferences(&self, account_id: u32) -> &CalendarPreferences {
        match self.personal_or_first(account_id) {
            Some(preferences) => preferences,
            None => CalendarPreferences::empty(),
        }
    }

    fn personal_or_first(&self, account_id: u32) -> Option<&CalendarPreferences> {
        match self.preferences.as_slice() {
            [preferences] => Some(preferences),
            preferences => preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or(preferences.first()),
        }
    }

    pub fn inherit_owner_preferences(&mut self, account_id: u32, personal_id: u32) {
        if account_id == personal_id || self.personal_preferences(personal_id).is_some() {
            return;
        }
        let Some(owner) = self.personal_preferences(account_id).cloned() else {
            return;
        };
        self.preferences.push(CalendarPreferences {
            account_id: personal_id,
            ..owner
        });
    }

    pub fn sync_owner_preferences(&mut self, account_id: u32, personal_id: u32) {
        if account_id == personal_id {
            return;
        }
        let Some(member) = self
            .preferences
            .iter()
            .find(|preferences| preferences.account_id == personal_id)
            .cloned()
        else {
            return;
        };
        *self.preferences_mut(account_id) = CalendarPreferences {
            account_id,
            ..member
        };
    }

    pub fn preferences_mut(&mut self, account_id: u32) -> &mut CalendarPreferences {
        if let Some(idx) = self
            .preferences
            .iter()
            .position(|p| p.account_id == account_id)
        {
            return &mut self.preferences[idx];
        }

        let inherited = self
            .preferences
            .first()
            .unwrap_or_else(|| CalendarPreferences::empty());
        let preferences = CalendarPreferences {
            account_id,
            name: inherited.name.clone(),
            description: inherited.description.clone(),
            color: inherited.color.clone(),
            time_zone: inherited.time_zone.clone(),
            ..Default::default()
        };
        self.preferences.push(preferences);
        self.preferences
            .last_mut()
            .expect("preferences were just pushed")
    }
}

impl CalendarPreferences {
    pub fn empty() -> &'static Self {
        static EMPTY: CalendarPreferences = CalendarPreferences {
            account_id: NO_ID,
            name: String::new(),
            description: None,
            sort_order: 0,
            color: None,
            flags: 0,
            time_zone: Timezone::Default,
            default_alerts: Vec::new(),
        };

        &EMPTY
    }
}

impl ArchivedCalendar {
    pub fn default_alerts(
        &self,
        account_id: u32,
        with_time: bool,
    ) -> impl Iterator<Item = &ArchivedDefaultAlert> {
        self.personal_preferences(account_id)
            .into_iter()
            .flat_map(|preferences| preferences.default_alerts.iter())
            .filter(move |a| (a.flags & ALERT_WITH_TIME != 0) == with_time)
    }

    pub fn personal_preferences(&self, account_id: u32) -> Option<&ArchivedCalendarPreferences> {
        self.preferences.iter().find(|p| p.account_id == account_id)
    }

    pub fn personal_flags(&self, account_id: u32, is_member: bool) -> u16 {
        self.personal_preferences(account_id)
            .map_or_else(|| default_preference_flags(is_member), |p| p.flags.into())
    }

    pub fn preferences(&self, account_id: u32) -> Option<&ArchivedCalendarPreferences> {
        match self.preferences.as_slice() {
            [preferences] => Some(preferences),
            preferences => preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or(preferences.first()),
        }
    }
}

pub const fn default_preference_flags(is_member: bool) -> u16 {
    if is_member { CALENDAR_SUBSCRIBED } else { 0 }
}

impl CalendarEvent {
    pub fn calendar_ids(&self) -> impl Iterator<Item = u32> {
        self.names.iter().map(DavName::parent_id)
    }

    pub fn all_calendar_ids(&self, prev_data: &ArchivedCalendarEvent) -> Vec<u32> {
        let mut calendar_ids = self.calendar_ids().collect::<Vec<_>>();
        for calendar_id in prev_data.calendar_ids() {
            if !calendar_ids.contains(&calendar_id) {
                calendar_ids.push(calendar_id);
            }
        }
        calendar_ids
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
    pub fn calendar_ids(&self) -> impl Iterator<Item = u32> {
        self.names.iter().map(|name| name.parent_id.to_native())
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

impl store::write::ArchiveCompression for ParticipantIdentities {
    const COMPRESSION: store::write::Compression =
        store::write::Compression::Zstd(Some(store::write::Dictionary::Common));
}
