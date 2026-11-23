/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(super) mod rule;
mod write;

use crate::{
    common::{FileTime, XsDuration, XsZone},
    convert::{
        BlobLimits,
        blob::{
            GlobalObjectId, TzDefinition,
            recur::{
                ALL_DAYS, AppointmentRecur, PatternType, RecurEnd, RecurFrequency,
                RecurrencePattern as RecurrencePatternBlob, WEEKEND_DAYS, WORK_DAYS,
            },
        },
        ical::{
            EventParts, event_recurrence,
            props::{
                BUSY_STATUS, CLASS_APPOINTMENT, CLEAN_GLOBAL_OBJECT_ID, CONFERENCING_TYPE,
                DURATION, END_WHOLE, F_INVITED, IS_EXCEPTION, LOCATION, OWNER_CRITICAL_CHANGE,
                RECIPIENT_FLAG_ORGANIZER, RECIPIENT_TRACK_STATUS, RECUR, RECURRING, REMINDER_DELTA,
                REMINDER_SET, REMINDER_SIGNAL_TIME, REMINDER_TIME, SEQUENCE, START_WHOLE,
                STATE_FLAGS, SUB_TYPE, TZDEF_END, TZDEF_START, busy, state_flags, track_status,
            },
        },
        model::{MessageContent, PropBag},
        tags::{
            BODY, DISPLAY_NAME, IMPORTANCE, KEYWORDS_NAME, MESSAGE_CLASS, NORMALIZED_SUBJECT,
            RECIPIENT_FLAGS, RECIPIENT_TYPE, RESPONSE_REQUESTED, SENSITIVITY, SMTP_ADDRESS,
            recipient_type,
        },
    },
    ews::{
        schema::{
            BaseShape, BodyType, BodyTypeResponse, CalendarItemType, DayOfWeek, DayOfWeekIndex,
            Importance, LegacyFreeBusy, MonthName, ReminderGroup, ResponseType, Sensitivity,
            UnindexedField,
        },
        types::{
            address::{EmailAddress, SingleRecipient},
            common::Body,
            ids::ItemId,
            item::{
                CalendarItem, ItemFields,
                calendar::{Attendee, Attendees, CalendarFields, EnhancedLocation},
            },
            path::Path,
            recurrence::{
                DaysOfWeek, Recurrence, RecurrenceEnd, RecurrencePattern, RecurrenceRange,
                RelativeYearly,
            },
            reminder::Reminder,
            shape::ItemShape,
            value::{DateTime, List, Strings},
        },
    },
    mapi::prop::{OwnedPropValue, PropKeyRef, PropType, sets::PS_PUBLIC_STRINGS},
    xml::value::XsDate,
};
use calcard::icalendar::ICalendar;
use jiff::{Span, civil};
use mail_parser::text_to_html;
use std::borrow::Cow;

pub use write::{CalendarEdit, CalendarEditError};

pub fn legacy_free_busy(status: Option<i32>) -> LegacyFreeBusy {
    match status {
        Some(busy::FREE) => LegacyFreeBusy::Free,
        Some(busy::TENTATIVE) => LegacyFreeBusy::Tentative,
        Some(busy::OOF) => LegacyFreeBusy::Oof,
        Some(busy::WORKING_ELSEWHERE) => LegacyFreeBusy::WorkingElsewhere,
        Some(busy::NO_DATA) => LegacyFreeBusy::NoData,
        _ => LegacyFreeBusy::Busy,
    }
}

pub fn response_type(status: i32) -> ResponseType {
    match status {
        track_status::ORGANIZED => ResponseType::Organizer,
        track_status::ACCEPTED => ResponseType::Accept,
        track_status::DECLINED => ResponseType::Decline,
        track_status::TENTATIVE => ResponseType::Tentative,
        track_status::NOT_RESPONDED => ResponseType::NoResponseReceived,
        _ => ResponseType::Unknown,
    }
}

const KEYWORDS: PropKeyRef<'static> = PropKeyRef::Name {
    set: PS_PUBLIC_STRINGS,
    name: KEYWORDS_NAME,
};
const SMTP: &str = "SMTP";
const SECONDS_PER_MINUTE: u64 = 60;
const MINUTES_PER_DAY: u32 = 1440;
const DAYS_PER_WEEK: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CalendarFieldSet(u64);

impl CalendarFieldSet {
    pub const ID: u64 = 1;
    pub const PARENT: u64 = 1 << 1;
    pub const CLASS: u64 = 1 << 2;
    pub const SUBJECT: u64 = 1 << 3;
    pub const SENSITIVITY: u64 = 1 << 4;
    pub const BODY: u64 = 1 << 5;
    pub const CATEGORIES: u64 = 1 << 6;
    pub const IMPORTANCE: u64 = 1 << 7;
    pub const HAS_ATTACHMENTS: u64 = 1 << 8;
    pub const REMINDER_IS_SET: u64 = 1 << 9;
    pub const REMINDER_MINUTES: u64 = 1 << 10;
    pub const REMINDER_DUE_BY: u64 = 1 << 11;
    pub const UID: u64 = 1 << 12;
    pub const DATE_TIME_STAMP: u64 = 1 << 13;
    pub const START: u64 = 1 << 14;
    pub const END: u64 = 1 << 15;
    pub const IS_ALL_DAY: u64 = 1 << 16;
    pub const FREE_BUSY: u64 = 1 << 17;
    pub const LOCATION: u64 = 1 << 18;
    pub const IS_MEETING: u64 = 1 << 19;
    pub const IS_CANCELLED: u64 = 1 << 20;
    pub const IS_RECURRING: u64 = 1 << 21;
    pub const IS_RESPONSE_REQUESTED: u64 = 1 << 22;
    pub const ITEM_TYPE: u64 = 1 << 23;
    pub const MY_RESPONSE: u64 = 1 << 24;
    pub const ORGANIZER: u64 = 1 << 25;
    pub const REQUIRED: u64 = 1 << 26;
    pub const OPTIONAL: u64 = 1 << 27;
    pub const RESOURCES: u64 = 1 << 28;
    pub const DURATION: u64 = 1 << 29;
    pub const SEQUENCE: u64 = 1 << 30;
    pub const RECURRENCE: u64 = 1 << 31;
    pub const START_TIME_ZONE: u64 = 1 << 32;
    pub const END_TIME_ZONE: u64 = 1 << 33;
    pub const IS_ORGANIZER: u64 = 1 << 34;
    pub const BODY_HTML: u64 = 1 << 35;
    pub const FIRST_OCCURRENCE: u64 = 1 << 36;
    pub const LAST_OCCURRENCE: u64 = 1 << 37;
    pub const MODIFIED_OCCURRENCES: u64 = 1 << 38;
    pub const DELETED_OCCURRENCES: u64 = 1 << 39;
    pub const MIME_CONTENT: u64 = 1 << 40;
    pub const ENHANCED_LOCATION: u64 = 1 << 41;
    pub const APPOINTMENT_STATE: u64 = 1 << 42;
    pub const MEETING_REQUEST_WAS_SENT: u64 = 1 << 43;
    pub const REMINDER_NEXT_TIME: u64 = 1 << 44;
    pub const CONFERENCE_TYPE: u64 = 1 << 45;
    pub const OCCURRENCES: u64 = Self::FIRST_OCCURRENCE
        | Self::LAST_OCCURRENCE
        | Self::MODIFIED_OCCURRENCES
        | Self::DELETED_OCCURRENCES;

    const LAST: u64 = Self::IS_ORGANIZER;
    const ALL: u64 = ((Self::LAST << 1) - 1)
        | Self::OCCURRENCES
        | Self::ENHANCED_LOCATION
        | Self::APPOINTMENT_STATE
        | Self::MEETING_REQUEST_WAS_SENT
        | Self::REMINDER_NEXT_TIME
        | Self::CONFERENCE_TYPE;
    const DEFAULT: u64 = Self::ALL
        & !(Self::BODY
            | Self::START_TIME_ZONE
            | Self::END_TIME_ZONE
            | Self::OCCURRENCES
            | Self::ENHANCED_LOCATION
            | Self::APPOINTMENT_STATE
            | Self::MEETING_REQUEST_WAS_SENT
            | Self::REMINDER_NEXT_TIME
            | Self::CONFERENCE_TYPE);
    const GET_ONLY: u64 = Self::BODY
        | Self::REQUIRED
        | Self::OPTIONAL
        | Self::RESOURCES
        | Self::RECURRENCE
        | Self::OCCURRENCES
        | Self::MIME_CONTENT;

    pub fn from_shape(shape: &ItemShape<'_>) -> Self {
        let mut fields = match shape.base {
            BaseShape::IdOnly => Self::ID,
            BaseShape::Default => Self::DEFAULT,
            BaseShape::AllProperties | BaseShape::PcxPeopleSearch => Self::ALL,
        };
        for path in &shape.additional {
            if let Path::Field(field) = path {
                fields |= Self::of_field(*field);
            }
        }
        if shape.body_type == Some(BodyTypeResponse::Html) {
            fields |= Self::BODY_HTML;
        }
        if shape.include_mime {
            fields |= Self::MIME_CONTENT;
        }
        CalendarFieldSet(fields)
    }

    pub const fn all() -> Self {
        CalendarFieldSet(Self::ALL)
    }

    pub const fn id_only() -> Self {
        CalendarFieldSet(Self::ID)
    }

    pub const fn for_list(self) -> Self {
        CalendarFieldSet(self.0 & !Self::GET_ONLY)
    }

    pub const fn has(self, field: u64) -> bool {
        self.0 & field != 0
    }

    pub fn event_parts(self) -> EventParts {
        let mut parts = EventParts::NO_DATA;
        if self.has(Self::BODY) {
            parts |= EventParts::BODY;
        }
        if self.has(Self::RECURRENCE) {
            parts |= EventParts::RECURRENCE;
        }
        if self.has(Self::START_TIME_ZONE | Self::END_TIME_ZONE) {
            parts |= EventParts::TIME_ZONES;
        }
        if self.has(Self::OCCURRENCES) {
            parts |= EventParts::OCCURRENCES;
        }
        if self.has(Self::LAST_OCCURRENCE) {
            parts |= EventParts::LAST_OCCURRENCE;
        }
        if self.has(Self::MIME_CONTENT) {
            parts |= EventParts::MIME;
        }
        if self.has(
            Self::ORGANIZER
                | Self::REQUIRED
                | Self::OPTIONAL
                | Self::RESOURCES
                | Self::IS_RESPONSE_REQUESTED
                | Self::MY_RESPONSE
                | Self::IS_ORGANIZER
                | Self::APPOINTMENT_STATE
                | Self::MEETING_REQUEST_WAS_SENT,
        ) {
            parts |= EventParts::RECIPIENTS;
        }
        parts
    }

    pub const fn needs_attendance(self) -> bool {
        self.has(
            Self::MY_RESPONSE
                | Self::IS_ORGANIZER
                | Self::APPOINTMENT_STATE
                | Self::MEETING_REQUEST_WAS_SENT,
        )
    }

    pub const fn needs_content(self) -> bool {
        self.0 & !(Self::ID | Self::PARENT | Self::BODY_HTML) != 0
    }

    fn of_field(field: UnindexedField) -> u64 {
        match field {
            UnindexedField::ItemItemId => Self::ID,
            UnindexedField::ItemParentFolderId => Self::PARENT,
            UnindexedField::ItemItemClass => Self::CLASS,
            UnindexedField::ItemSubject => Self::SUBJECT,
            UnindexedField::ItemSensitivity => Self::SENSITIVITY,
            UnindexedField::ItemBody => Self::BODY,
            UnindexedField::ItemMimeContent => Self::MIME_CONTENT,
            UnindexedField::ItemCategories => Self::CATEGORIES,
            UnindexedField::ItemImportance => Self::IMPORTANCE,
            UnindexedField::ItemHasAttachments => Self::HAS_ATTACHMENTS,
            UnindexedField::ItemReminderIsSet => Self::REMINDER_IS_SET,
            UnindexedField::ItemReminderMinutesBeforeStart => Self::REMINDER_MINUTES,
            UnindexedField::ItemReminderDueBy => Self::REMINDER_DUE_BY,
            UnindexedField::ItemReminderNextTime => Self::REMINDER_NEXT_TIME,
            UnindexedField::CalendarUid => Self::UID,
            UnindexedField::CalendarDateTimeStamp => Self::DATE_TIME_STAMP,
            UnindexedField::CalendarStart => Self::START,
            UnindexedField::CalendarEnd => Self::END,
            UnindexedField::CalendarIsAllDayEvent => Self::IS_ALL_DAY,
            UnindexedField::CalendarLegacyFreeBusyStatus => Self::FREE_BUSY,
            UnindexedField::CalendarLocation => Self::LOCATION,
            UnindexedField::CalendarEnhancedLocation => Self::ENHANCED_LOCATION,
            UnindexedField::CalendarIsMeeting => Self::IS_MEETING,
            UnindexedField::CalendarIsCancelled => Self::IS_CANCELLED,
            UnindexedField::CalendarIsRecurring => Self::IS_RECURRING,
            UnindexedField::CalendarMeetingRequestWasSent => Self::MEETING_REQUEST_WAS_SENT,
            UnindexedField::CalendarConferenceType => Self::CONFERENCE_TYPE,
            UnindexedField::CalendarIsResponseRequested => Self::IS_RESPONSE_REQUESTED,
            UnindexedField::CalendarCalendarItemType => Self::ITEM_TYPE,
            UnindexedField::CalendarMyResponseType => Self::MY_RESPONSE,
            UnindexedField::CalendarIsOrganizer => Self::IS_ORGANIZER,
            UnindexedField::CalendarOrganizer => Self::ORGANIZER,
            UnindexedField::CalendarRequiredAttendees => Self::REQUIRED,
            UnindexedField::CalendarOptionalAttendees => Self::OPTIONAL,
            UnindexedField::CalendarResources => Self::RESOURCES,
            UnindexedField::CalendarDuration => Self::DURATION,
            UnindexedField::CalendarAppointmentSequenceNumber => Self::SEQUENCE,
            UnindexedField::CalendarAppointmentState => Self::APPOINTMENT_STATE,
            UnindexedField::CalendarRecurrence => Self::RECURRENCE,
            UnindexedField::CalendarStartTimeZone => Self::START_TIME_ZONE,
            UnindexedField::CalendarEndTimeZone => Self::END_TIME_ZONE,
            UnindexedField::CalendarFirstOccurrence => Self::FIRST_OCCURRENCE,
            UnindexedField::CalendarLastOccurrence => Self::LAST_OCCURRENCE,
            UnindexedField::CalendarModifiedOccurrences => Self::MODIFIED_OCCURRENCES,
            UnindexedField::CalendarDeletedOccurrences => Self::DELETED_OCCURRENCES,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarField {
    ItemClass,
    Subject,
    Importance,
    Start,
    End,
    Location,
    IsAllDayEvent,
    IsRecurring,
    LegacyFreeBusyStatus,
}

impl CalendarField {
    pub fn of_path(path: &Path<'_>) -> Option<Self> {
        match path {
            Path::Field(field) => match field {
                UnindexedField::ItemItemClass => Some(CalendarField::ItemClass),
                UnindexedField::ItemSubject => Some(CalendarField::Subject),
                UnindexedField::ItemImportance => Some(CalendarField::Importance),
                UnindexedField::CalendarStart => Some(CalendarField::Start),
                UnindexedField::CalendarEnd => Some(CalendarField::End),
                UnindexedField::CalendarLocation => Some(CalendarField::Location),
                UnindexedField::CalendarIsAllDayEvent => Some(CalendarField::IsAllDayEvent),
                UnindexedField::CalendarIsRecurring => Some(CalendarField::IsRecurring),
                UnindexedField::CalendarLegacyFreeBusyStatus => {
                    Some(CalendarField::LegacyFreeBusyStatus)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarValue<'p> {
    Text(&'p str),
    Importance(Importance),
    FreeBusy(LegacyFreeBusy),
    Bool(bool),
    Time(FileTime),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Organizer,
    Required,
    Optional,
    Resource,
}

#[derive(Debug, Clone, Copy)]
pub struct CalendarProps<'p> {
    props: &'p PropBag,
    recipients: &'p [PropBag],
}

impl<'p> CalendarProps<'p> {
    pub fn new(content: &'p MessageContent) -> Self {
        CalendarProps {
            props: &content.props,
            recipients: &content.recipients,
        }
    }

    pub fn of_props(props: &'p PropBag) -> Self {
        CalendarProps {
            props,
            recipients: &[],
        }
    }

    pub fn render(self, fields: CalendarFieldSet) -> CalendarItem<'p> {
        let mut item = ItemFields::default();
        let mut calendar = CalendarFields::default();
        if fields.has(CalendarFieldSet::CLASS) {
            item.item_class = Some(Cow::Borrowed(self.class()));
        }
        if fields.has(CalendarFieldSet::SUBJECT) {
            item.subject = self
                .str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                .map(Cow::Borrowed);
        }
        if fields.has(CalendarFieldSet::SENSITIVITY) {
            item.sensitivity = Some(match self.int(PropKeyRef::Tag(SENSITIVITY)) {
                Some(1) => Sensitivity::Personal,
                Some(2) => Sensitivity::Private,
                Some(3) => Sensitivity::Confidential,
                _ => Sensitivity::Normal,
            });
        }
        if fields.has(CalendarFieldSet::IMPORTANCE) {
            item.importance = Some(self.importance());
        }
        if fields.has(CalendarFieldSet::BODY) {
            let text = self.str(PropKeyRef::Tag(BODY)).unwrap_or_default();
            item.body = Some(if fields.has(CalendarFieldSet::BODY_HTML) {
                Body {
                    body_type: BodyType::Html,
                    is_truncated: None,
                    text: Cow::Owned(text_to_html(text)),
                }
            } else {
                Body {
                    body_type: BodyType::Text,
                    is_truncated: None,
                    text: Cow::Borrowed(text),
                }
            });
        }
        if fields.has(CalendarFieldSet::CATEGORIES) {
            item.categories = match self.props.get(KEYWORDS, PropType::MvUnicode) {
                Some(OwnedPropValue::MvUnicode(list)) if !list.is_empty() => Some(Strings(
                    list.iter().map(|text| Cow::Borrowed(&**text)).collect(),
                )),
                _ => None,
            };
        }
        if fields.has(CalendarFieldSet::HAS_ATTACHMENTS) {
            item.has_attachments = Some(false);
        }
        let reminder = self.bool(REMINDER_SET.prop());
        if fields.has(CalendarFieldSet::REMINDER_IS_SET) {
            item.reminder_is_set = Some(reminder);
        }
        if fields.has(CalendarFieldSet::REMINDER_MINUTES) {
            item.reminder_minutes_before_start =
                Some(self.int(REMINDER_DELTA.prop()).unwrap_or_default());
        }
        if fields.has(CalendarFieldSet::REMINDER_DUE_BY) && reminder {
            item.reminder_due_by = self.date_time(REMINDER_TIME.prop());
        }
        if fields.has(CalendarFieldSet::REMINDER_NEXT_TIME) {
            item.reminder_next_time = self.reminder_signal();
        }
        if fields.has(CalendarFieldSet::UID) {
            calendar.uid = self.uid();
        }
        if fields.has(CalendarFieldSet::DATE_TIME_STAMP) {
            calendar.date_time_stamp = self.date_time(OWNER_CRITICAL_CHANGE.prop());
        }
        if fields.has(CalendarFieldSet::START) {
            calendar.start = self.date_time(START_WHOLE.prop());
        }
        if fields.has(CalendarFieldSet::END) {
            calendar.end = self.date_time(END_WHOLE.prop());
        }
        if fields.has(CalendarFieldSet::IS_ALL_DAY) {
            calendar.is_all_day_event = Some(self.bool(SUB_TYPE.prop()));
        }
        if fields.has(CalendarFieldSet::FREE_BUSY) {
            calendar.legacy_free_busy_status = Some(self.free_busy());
        }
        if fields.has(CalendarFieldSet::LOCATION) {
            calendar.location = self.str(LOCATION.prop()).map(Cow::Borrowed);
        }
        if fields.has(CalendarFieldSet::ENHANCED_LOCATION) {
            calendar.enhanced_location = self
                .str(LOCATION.prop())
                .filter(|location| !location.is_empty())
                .map(|location| {
                    Box::new(EnhancedLocation {
                        display_name: Some(Cow::Borrowed(location)),
                        ..Default::default()
                    })
                });
        }
        let state = self.int(STATE_FLAGS.prop()).unwrap_or_default();
        let is_meeting = self.is_meeting();
        if fields.has(CalendarFieldSet::IS_MEETING) {
            calendar.is_meeting = Some(is_meeting);
        }
        if fields.has(CalendarFieldSet::IS_CANCELLED) {
            calendar.is_cancelled = Some(state & state_flags::CANCELED != 0);
        }
        if fields.has(CalendarFieldSet::IS_RECURRING) {
            calendar.is_recurring = Some(self.bool(RECURRING.prop()));
        }
        if fields.has(CalendarFieldSet::MEETING_REQUEST_WAS_SENT) {
            calendar.meeting_request_was_sent =
                Some(state & state_flags::RECEIVED == 0 && self.bool(F_INVITED.prop()));
        }
        if fields.has(CalendarFieldSet::IS_RESPONSE_REQUESTED) {
            calendar.is_response_requested = Some(self.bool(PropKeyRef::Tag(RESPONSE_REQUESTED)));
        }
        if fields.has(CalendarFieldSet::ITEM_TYPE) {
            calendar.calendar_item_type = Some(self.item_type());
        }
        if fields.has(CalendarFieldSet::MY_RESPONSE) && !is_meeting {
            calendar.my_response_type = Some(ResponseType::Organizer);
        }
        if fields.has(CalendarFieldSet::IS_ORGANIZER) && !is_meeting {
            calendar.is_organizer = Some(true);
        }
        if fields.has(CalendarFieldSet::ORGANIZER) {
            calendar.organizer = self
                .recipients_of(Role::Organizer)
                .next()
                .map(|row| SingleRecipient(self.mailbox(row)));
        }
        if fields.has(CalendarFieldSet::REQUIRED) {
            calendar.required_attendees = self.attendees(Role::Required);
        }
        if fields.has(CalendarFieldSet::OPTIONAL) {
            calendar.optional_attendees = self.attendees(Role::Optional);
        }
        if fields.has(CalendarFieldSet::RESOURCES) {
            calendar.resources = self.attendees(Role::Resource);
        }
        if fields.has(CalendarFieldSet::DURATION) {
            calendar.duration = self.duration();
        }
        if fields.has(CalendarFieldSet::SEQUENCE) {
            calendar.appointment_sequence_number = self.int(SEQUENCE.prop());
        }
        if fields.has(CalendarFieldSet::APPOINTMENT_STATE) {
            calendar.appointment_state = Some(state);
        }
        if fields.has(CalendarFieldSet::RECURRENCE) {
            calendar.recurrence = self.recurrence().map(Box::new);
        }
        if fields.has(CalendarFieldSet::CONFERENCE_TYPE) {
            calendar.conference_type = self.int(CONFERENCING_TYPE.prop());
        }
        CalendarItem { item, calendar }
    }

    pub fn value(self, field: CalendarField) -> Option<CalendarValue<'p>> {
        match field {
            CalendarField::ItemClass => Some(CalendarValue::Text(self.class())),
            CalendarField::Subject => self
                .str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                .map(CalendarValue::Text),
            CalendarField::Importance => Some(CalendarValue::Importance(self.importance())),
            CalendarField::Start => self.time(START_WHOLE.prop()).map(CalendarValue::Time),
            CalendarField::End => self.time(END_WHOLE.prop()).map(CalendarValue::Time),
            CalendarField::Location => self.str(LOCATION.prop()).map(CalendarValue::Text),
            CalendarField::IsAllDayEvent => Some(CalendarValue::Bool(self.bool(SUB_TYPE.prop()))),
            CalendarField::IsRecurring => Some(CalendarValue::Bool(self.bool(RECURRING.prop()))),
            CalendarField::LegacyFreeBusyStatus => Some(CalendarValue::FreeBusy(self.free_busy())),
        }
    }

    fn importance(self) -> Importance {
        match self.int(PropKeyRef::Tag(IMPORTANCE)) {
            Some(0) => Importance::Low,
            Some(2) => Importance::High,
            _ => Importance::Normal,
        }
    }

    fn class(self) -> &'p str {
        self.str(PropKeyRef::Tag(MESSAGE_CLASS))
            .unwrap_or(CLASS_APPOINTMENT)
    }

    fn uid(self) -> Option<Cow<'p, str>> {
        let OwnedPropValue::Binary(blob) = self
            .props
            .get(CLEAN_GLOBAL_OBJECT_ID.prop(), PropType::Binary)?
        else {
            return None;
        };
        GlobalObjectId::uid_of(blob)
    }

    fn free_busy(self) -> LegacyFreeBusy {
        legacy_free_busy(self.int(BUSY_STATUS.prop()))
    }

    fn item_type(self) -> CalendarItemType {
        if self.bool(IS_EXCEPTION.prop()) {
            CalendarItemType::Exception
        } else if self.bool(RECURRING.prop()) {
            CalendarItemType::RecurringMaster
        } else {
            CalendarItemType::Single
        }
    }

    pub fn reminder_signal(self) -> Option<DateTime> {
        if self.bool(REMINDER_SET.prop()) {
            self.date_time(REMINDER_SIGNAL_TIME.prop())
        } else {
            None
        }
    }

    pub fn reminder(
        self,
        item_id: ItemId<'static>,
        recurring_master_item_id: Option<ItemId<'static>>,
    ) -> Option<Reminder<'static>> {
        let reminder_time = self.reminder_signal()?;
        let start_date = self.date_time(START_WHOLE.prop())?;
        Some(Reminder {
            subject: Cow::Owned(
                self.str(PropKeyRef::Tag(NORMALIZED_SUBJECT))
                    .unwrap_or_default()
                    .to_owned(),
            ),
            location: self
                .str(LOCATION.prop())
                .map(|location| Cow::Owned(location.to_owned())),
            reminder_time,
            start_date,
            end_date: self.date_time(END_WHOLE.prop()).unwrap_or(start_date),
            item_id,
            recurring_master_item_id,
            reminder_group: Some(ReminderGroup::Calendar),
            uid: Cow::Owned(self.uid().map(Cow::into_owned).unwrap_or_default()),
        })
    }

    pub fn start_time_zone(self) -> Option<TzDefinition> {
        self.time_zone(TZDEF_START.prop())
    }

    pub fn end_time_zone(self) -> Option<TzDefinition> {
        self.time_zone(TZDEF_END.prop())
    }

    fn time_zone(self, key: PropKeyRef<'_>) -> Option<TzDefinition> {
        let OwnedPropValue::Binary(blob) = self.props.get(key, PropType::Binary)? else {
            return None;
        };
        TzDefinition::decode(blob, &BlobLimits::DEFAULT).ok()
    }

    fn recurrence(self) -> Option<Recurrence> {
        let OwnedPropValue::Binary(blob) = self.props.get(RECUR.prop(), PropType::Binary)? else {
            return None;
        };
        let recur = AppointmentRecur::decode(blob, &BlobLimits::DEFAULT).ok()?;
        recurrence_of(&recur.pattern)
    }

    fn duration(self) -> Option<Cow<'p, str>> {
        let minutes = u64::try_from(self.int(DURATION.prop())?).ok()?;
        let mut out = Vec::with_capacity(16);
        XsDuration {
            negative: false,
            seconds: minutes.saturating_mul(SECONDS_PER_MINUTE),
        }
        .write(&mut out);
        String::from_utf8(out).ok().map(Cow::Owned)
    }

    fn recipients_of(self, role: Role) -> impl Iterator<Item = &'p PropBag> {
        self.recipients
            .iter()
            .filter(move |row| Self::role(row) == Some(role))
    }

    fn role(row: &PropBag) -> Option<Role> {
        let flags = Self::row_int(row, PropKeyRef::Tag(RECIPIENT_FLAGS)).unwrap_or_default();
        if flags & RECIPIENT_FLAG_ORGANIZER != 0 {
            return Some(Role::Organizer);
        }
        match Self::row_int(row, PropKeyRef::Tag(RECIPIENT_TYPE))? & recipient_type::MASK {
            recipient_type::TO => Some(Role::Required),
            recipient_type::CC => Some(Role::Optional),
            recipient_type::BCC => Some(Role::Resource),
            _ => None,
        }
    }

    fn attendees(self, role: Role) -> Option<Attendees<'p>> {
        let list = self
            .recipients_of(role)
            .map(|row| Attendee {
                mailbox: Some(self.mailbox(row)),
                response_type: Some(Self::response(row).unwrap_or(ResponseType::Unknown)),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        (!list.is_empty()).then_some(List(list))
    }

    pub fn is_meeting(self) -> bool {
        self.int(STATE_FLAGS.prop())
            .is_some_and(|state| state & state_flags::MEETING != 0)
    }

    pub fn render_attendance(
        self,
        calendar: &mut CalendarFields<'p>,
        fields: CalendarFieldSet,
        owner: &[String],
    ) {
        if !fields.needs_attendance() || !self.is_meeting() {
            return;
        }
        let (response, organizer) = self.attendance(owner);
        if fields.has(CalendarFieldSet::MY_RESPONSE) {
            calendar.my_response_type = Some(response);
        }
        if fields.has(CalendarFieldSet::IS_ORGANIZER) {
            calendar.is_organizer = Some(organizer);
        }
        if !organizer {
            if let Some(state) = &mut calendar.appointment_state {
                *state |= state_flags::RECEIVED;
            }
            if let Some(sent) = &mut calendar.meeting_request_was_sent {
                *sent = false;
            }
        }
    }

    pub fn attendance(self, addresses: &[String]) -> (ResponseType, bool) {
        let mut response = None;
        for row in self.recipients {
            let mine = Self::row_str(row, PropKeyRef::Tag(SMTP_ADDRESS)).is_some_and(|smtp| {
                addresses
                    .iter()
                    .any(|address| address.eq_ignore_ascii_case(smtp))
            });
            if !mine {
                continue;
            }
            match Self::role(row) {
                Some(Role::Organizer) => return (ResponseType::Organizer, true),
                Some(_) if response.is_none() => {
                    response =
                        Some(Self::response(row).unwrap_or(ResponseType::NoResponseReceived));
                }
                _ => {}
            }
        }
        (response.unwrap_or(ResponseType::Unknown), false)
    }

    fn response(row: &PropBag) -> Option<ResponseType> {
        match Self::row_int(row, PropKeyRef::Tag(RECIPIENT_TRACK_STATUS))? {
            track_status::ACCEPTED => Some(ResponseType::Accept),
            track_status::DECLINED => Some(ResponseType::Decline),
            track_status::TENTATIVE => Some(ResponseType::Tentative),
            _ => None,
        }
    }

    fn mailbox(self, row: &'p PropBag) -> EmailAddress<'p> {
        let smtp = Self::row_str(row, PropKeyRef::Tag(SMTP_ADDRESS));
        EmailAddress {
            name: Self::row_str(row, PropKeyRef::Tag(DISPLAY_NAME))
                .or(smtp)
                .map(Cow::Borrowed),
            email_address: smtp.map(Cow::Borrowed),
            routing_type: smtp.map(|_| Cow::Borrowed(SMTP)),
            ..Default::default()
        }
    }

    fn row_str(row: &'p PropBag, key: PropKeyRef<'_>) -> Option<&'p str> {
        match row.get(key, PropType::Unicode) {
            Some(OwnedPropValue::Unicode(text)) => Some(text),
            _ => None,
        }
    }

    fn row_int(row: &PropBag, key: PropKeyRef<'_>) -> Option<i32> {
        match row.get(key, PropType::I32) {
            Some(OwnedPropValue::I32(value)) => Some(*value),
            _ => None,
        }
    }

    fn str(self, key: PropKeyRef<'_>) -> Option<&'p str> {
        Self::row_str(self.props, key)
    }

    fn int(self, key: PropKeyRef<'_>) -> Option<i32> {
        Self::row_int(self.props, key)
    }

    fn bool(self, key: PropKeyRef<'_>) -> bool {
        matches!(
            self.props.get(key, PropType::Bool),
            Some(OwnedPropValue::Bool(true))
        )
    }

    fn time(self, key: PropKeyRef<'_>) -> Option<FileTime> {
        match self.props.get(key, PropType::Time) {
            Some(OwnedPropValue::Time(time)) => Some(*time),
            _ => None,
        }
    }

    fn date_time(self, key: PropKeyRef<'_>) -> Option<DateTime> {
        self.time(key).map(|time| DateTime::utc(time.to_utc().0))
    }
}

pub fn invitation_recurrence(ical: &ICalendar) -> Option<Recurrence> {
    recurrence_of(&event_recurrence(ical)?.pattern)
}

pub(super) fn recurrence_of(pattern: &RecurrencePatternBlob) -> Option<Recurrence> {
    let start = date_of(pattern.start_date)?;
    let interval = i32::try_from(pattern.period).ok()?;
    let yearly = pattern.frequency == RecurFrequency::Yearly;
    let pattern_kind = match pattern.pattern {
        PatternType::Day => RecurrencePattern::Daily {
            interval: i32::try_from(pattern.period / MINUTES_PER_DAY).ok()?,
        },
        PatternType::Week { days } => RecurrencePattern::Weekly {
            interval,
            days_of_week: days_of_week(days),
            first_day_of_week: DayOfWeek::ALL
                .get(usize::try_from(pattern.first_dow).ok()?)
                .copied(),
        },
        PatternType::Month { day } | PatternType::MonthEnd { day } if yearly => {
            RecurrencePattern::AbsoluteYearly {
                day_of_month: i32::try_from(day).ok()?,
                month: month_of(start)?,
            }
        }
        PatternType::Month { day } | PatternType::MonthEnd { day } => {
            RecurrencePattern::AbsoluteMonthly {
                interval,
                day_of_month: i32::try_from(day).ok()?,
            }
        }
        PatternType::MonthNth { days, n } if yearly => {
            RecurrencePattern::RelativeYearly(RelativeYearly {
                days_of_week: relative_day(days)?,
                index: week_index(n)?,
                month: month_of(start)?,
            })
        }
        PatternType::MonthNth { days, n } => RecurrencePattern::RelativeMonthly {
            interval,
            days_of_week: relative_day(days)?,
            index: week_index(n)?,
        },
        PatternType::HjMonth { .. }
        | PatternType::HjMonthNth { .. }
        | PatternType::HjMonthEnd { .. } => {
            return None;
        }
    };
    let end = match pattern.end {
        RecurEnd::ByDate => RecurrenceEnd::EndDate(date_of(pattern.end_date)?),
        RecurEnd::AfterCount => {
            RecurrenceEnd::Numbered(i32::try_from(pattern.occurrence_count).ok()?)
        }
        RecurEnd::Never | RecurEnd::NeverLegacy => RecurrenceEnd::NoEnd,
    };
    Some(Recurrence {
        pattern: pattern_kind,
        range: RecurrenceRange { start, end },
    })
}

fn days_of_week(mask: u32) -> DaysOfWeek {
    DaysOfWeek::from_iter(
        DayOfWeek::ALL
            .iter()
            .take(DAYS_PER_WEEK)
            .enumerate()
            .filter(|(bit, _)| mask & (1 << bit) != 0)
            .map(|(_, day)| *day),
    )
}

fn relative_day(mask: u32) -> Option<DaysOfWeek> {
    let day = match u8::try_from(mask).ok()? {
        ALL_DAYS => DayOfWeek::Day,
        WORK_DAYS => DayOfWeek::Weekday,
        WEEKEND_DAYS => DayOfWeek::WeekendDay,
        single if single.is_power_of_two() => *DayOfWeek::ALL
            .get(..DAYS_PER_WEEK)?
            .get(usize::try_from(single.trailing_zeros()).ok()?)?,
        _ => return None,
    };
    Some(DaysOfWeek::from_iter([day]))
}

fn week_index(n: u32) -> Option<DayOfWeekIndex> {
    DayOfWeekIndex::ALL
        .get(usize::try_from(n.checked_sub(1)?).ok()?)
        .copied()
}

fn month_of(date: XsDate) -> Option<MonthName> {
    MonthName::ALL
        .get(usize::from(date.month.checked_sub(1)?))
        .copied()
}

fn date_of(minutes: u32) -> Option<XsDate> {
    let date = civil::date(1601, 1, 1)
        .checked_add(
            Span::new()
                .try_days(i64::from(minutes / MINUTES_PER_DAY))
                .ok()?,
        )
        .ok()?;
    Some(XsDate {
        year: u16::try_from(date.year()).ok()?,
        month: u8::try_from(date.month()).ok()?,
        day: u8::try_from(date.day()).ok()?,
        zone: XsZone::Floating,
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ews/calendar/tests.rs"]
mod tests;
