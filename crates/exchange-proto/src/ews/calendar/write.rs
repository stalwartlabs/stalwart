/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::rule::{RuleError, SeriesRule, rule_of};
use crate::{
    common::{FileTime, UtcSeconds},
    convert::{
        context::ConvertOptions,
        ical::{
            AttendeeLists, AttendeeRole, Invitee, RecurrenceId, RecurrenceSet,
            clear_event_recurrence, event_duration, event_series_start, event_series_times,
            event_times, patch_event_from_message,
            props::{
                BUSY_STATUS, CONFERENCING_TYPE, END_WHOLE, LOCATION, REMINDER_DELTA, REMINDER_SET,
                REMINDER_SIGNAL_TIME, START_WHOLE, SUB_TYPE, TZDEF_START, busy,
            },
            set_event_attendees, set_event_recurrence, zone_definition_blob,
        },
        model::PropBag,
    },
    ews::{
        item_edit::{
            CommonField, cleared_value, common_field, extended_value, with_appended_categories,
        },
        schema::{LegacyFreeBusy, UnindexedField},
        types::{
            change::ItemChange,
            item::{CalendarItem, Item, calendar::Attendees},
            path::Path,
            recurrence::Recurrence,
            value::DateTime,
            xprop::ExtendedProperty,
        },
    },
    mapi::prop::{OwnedPropValue, PropType},
};
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarProperty,
};
use jiff::{SignedDuration, Timestamp, tz::TimeZone};

const CREATE_FIELDS: [UnindexedField; 14] = [
    UnindexedField::ItemSubject,
    UnindexedField::ItemBody,
    UnindexedField::ItemSensitivity,
    UnindexedField::ItemImportance,
    UnindexedField::ItemCategories,
    UnindexedField::ItemReminderIsSet,
    UnindexedField::ItemReminderMinutesBeforeStart,
    UnindexedField::CalendarStart,
    UnindexedField::CalendarEnd,
    UnindexedField::CalendarIsAllDayEvent,
    UnindexedField::CalendarLegacyFreeBusyStatus,
    UnindexedField::CalendarLocation,
    UnindexedField::CalendarStartTimeZone,
    UnindexedField::CalendarConferenceType,
];

const BUSY: i32 = LegacyFreeBusy::Busy as i32;
const MAX_EVENT_DURATION: SignedDuration = SignedDuration::from_hours(5 * 366 * 24);
const DEFAULT_SLOT_SECONDS: i64 = 30 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarEditError {
    NotACalendarItem,
    InvalidPropertySet,
    InvalidPropertyAppend,
    InvalidRecurrence,
    UnsupportedRecurrence,
    NoOccurrence,
    TooManyAttendees,
    DurationTooLong,
    EndBeforeStart,
    Conversion,
}

#[derive(Debug)]
pub struct CalendarEdit {
    props: PropBag,
    appended_categories: Vec<Box<str>>,
    start_zone: Option<Box<str>>,
    recurrence: Option<RecurrenceEdit>,
    attendees: AttendeeLists,
    max_attendees: usize,
}

#[derive(Debug)]
enum RecurrenceEdit {
    Set(Box<SeriesRule>),
    Clear,
}

enum Source<'v, 'x> {
    Set(&'v CalendarItem<'x>),
    Delete,
}

impl RecurrenceEdit {
    fn set(recurrence: &Recurrence) -> Result<Self, CalendarEditError> {
        rule_of(recurrence)
            .map(|rule| RecurrenceEdit::Set(Box::new(rule)))
            .map_err(|err| match err {
                RuleError::Invalid => CalendarEditError::InvalidRecurrence,
                RuleError::Unsupported => CalendarEditError::UnsupportedRecurrence,
                RuleError::NoOccurrence => CalendarEditError::NoOccurrence,
            })
    }
}

impl CalendarEdit {
    pub fn new(max_attendees: usize) -> Self {
        CalendarEdit {
            props: PropBag::default(),
            appended_categories: Vec::new(),
            start_zone: None,
            recurrence: None,
            attendees: AttendeeLists::default(),
            max_attendees,
        }
    }

    pub fn from_item(
        item: &CalendarItem<'_>,
        max_attendees: usize,
    ) -> Result<Self, CalendarEditError> {
        let mut edit = CalendarEdit::new(max_attendees);
        let source = Source::Set(item);
        for field in CREATE_FIELDS {
            edit.field(field, &source)?;
        }
        if let (None, Some(name)) = (
            &item.calendar.location,
            item.calendar
                .enhanced_location
                .as_ref()
                .and_then(|location| location.display_name.as_deref()),
        ) {
            edit.props
                .set(LOCATION.key(), OwnedPropValue::Unicode(Box::from(name)));
        }
        if item.calendar.organizer.is_some() || item.calendar.is_online_meeting.is_some() {
            return Err(CalendarEditError::InvalidPropertySet);
        }
        for role in [
            AttendeeRole::Required,
            AttendeeRole::Optional,
            AttendeeRole::Resource,
        ] {
            if let Some(list) = attendees_of(item, role) {
                edit.set_attendees(role, Some(list))?;
            }
        }
        if let Some(recurrence) = &item.calendar.recurrence {
            edit.recurrence = Some(RecurrenceEdit::set(recurrence)?);
        }
        for property in item.item.extended_property.iter().flat_map(|list| &list.0) {
            edit.extended_value(property)?;
        }
        Ok(edit)
    }

    fn set_attendees(
        &mut self,
        role: AttendeeRole,
        list: Option<&Attendees<'_>>,
    ) -> Result<(), CalendarEditError> {
        let listed = match list {
            Some(list) if list.0.len() > self.max_attendees => {
                return Err(CalendarEditError::TooManyAttendees);
            }
            Some(list) => invitees(list)?,
            None => Vec::new(),
        };
        self.attendees.set(role, listed);
        if self.attendees.invitee_count() > self.max_attendees {
            Err(CalendarEditError::TooManyAttendees)
        } else {
            Ok(())
        }
    }

    pub fn default_times(&mut self, now: UtcSeconds) -> Result<(), CalendarEditError> {
        match (
            self.props.get(START_WHOLE.prop(), PropType::Time).is_some(),
            self.props.get(END_WHOLE.prop(), PropType::Time).is_some(),
        ) {
            (true, true) => Ok(()),
            (false, false) => {
                let start = now
                    .0
                    .div_euclid(DEFAULT_SLOT_SECONDS)
                    .saturating_add(1)
                    .saturating_mul(DEFAULT_SLOT_SECONDS);
                for (key, seconds) in [
                    (START_WHOLE, start),
                    (END_WHOLE, start.saturating_add(DEFAULT_SLOT_SECONDS)),
                ] {
                    self.props.set(
                        key.key(),
                        OwnedPropValue::Time(FileTime::from_utc(UtcSeconds(seconds), 0)),
                    );
                }
                Ok(())
            }
            _ => Err(CalendarEditError::InvalidPropertySet),
        }
    }

    pub fn change(&mut self, change: &ItemChange<'_>) -> Result<(), CalendarEditError> {
        let based;
        let (path, source) = match change {
            ItemChange::Set {
                path,
                value: Item::Item(fields),
            } => {
                based = CalendarItem {
                    item: fields.as_ref().clone(),
                    ..Default::default()
                };
                (path, Source::Set(&based))
            }
            ItemChange::Set { path, value } => (path, Source::Set(calendar_of(value)?)),
            ItemChange::Append { path, value } => {
                return match path {
                    Path::Field(UnindexedField::ItemCategories) => {
                        let names = calendar_of(value)?
                            .item
                            .categories
                            .as_ref()
                            .ok_or(CalendarEditError::InvalidPropertySet)?;
                        self.appended_categories
                            .extend(names.0.iter().map(|name| Box::from(name.as_ref())));
                        Ok(())
                    }
                    _ => Err(CalendarEditError::InvalidPropertyAppend),
                };
            }
            ItemChange::Delete(path) => (path, Source::Delete),
        };
        match path {
            Path::Field(field) if is_unstored(*field) => Ok(()),
            Path::Field(UnindexedField::CalendarOrganizer) => match source {
                Source::Set(_) => Err(CalendarEditError::InvalidPropertySet),
                Source::Delete => Ok(()),
            },
            Path::Field(
                field @ (UnindexedField::CalendarRequiredAttendees
                | UnindexedField::CalendarOptionalAttendees
                | UnindexedField::CalendarResources),
            ) => {
                let role = match field {
                    UnindexedField::CalendarOptionalAttendees => AttendeeRole::Optional,
                    UnindexedField::CalendarResources => AttendeeRole::Resource,
                    _ => AttendeeRole::Required,
                };
                let list = match source {
                    Source::Set(item) => Some(
                        attendees_of(item, role).ok_or(CalendarEditError::InvalidPropertySet)?,
                    ),
                    Source::Delete => None,
                };
                self.set_attendees(role, list)
            }
            Path::Field(UnindexedField::CalendarRecurrence) => {
                self.recurrence = Some(match source {
                    Source::Delete => RecurrenceEdit::Clear,
                    Source::Set(item) => RecurrenceEdit::set(
                        item.calendar
                            .recurrence
                            .as_ref()
                            .ok_or(CalendarEditError::InvalidPropertySet)?,
                    )?,
                });
                Ok(())
            }
            Path::Field(field) => {
                if self.field(*field, &source)? {
                    Ok(())
                } else {
                    Err(CalendarEditError::InvalidPropertySet)
                }
            }
            Path::Indexed { .. } => Err(CalendarEditError::InvalidPropertySet),
            Path::Extended(uri) => match source {
                Source::Set(item) => {
                    let property = item
                        .item
                        .extended_property
                        .iter()
                        .flat_map(|list| &list.0)
                        .find(|property| property.uri == *uri)
                        .ok_or(CalendarEditError::InvalidPropertySet)?;
                    self.extended_value(property)
                }
                Source::Delete => {
                    let (key, ptype) = uri
                        .to_prop()
                        .map_err(|_| CalendarEditError::InvalidPropertySet)?;
                    self.props.set(key, cleared_value(ptype));
                    Ok(())
                }
            },
        }
    }

    pub fn apply(
        &self,
        ical: &mut ICalendar,
        instance: Option<RecurrenceId>,
        opts: &ConvertOptions<'_>,
    ) -> Result<(), CalendarEditError> {
        if instance.is_some() && self.recurrence.is_some() {
            return Err(CalendarEditError::InvalidPropertySet);
        }
        let recurring = match &self.recurrence {
            Some(RecurrenceEdit::Set(_)) => true,
            Some(RecurrenceEdit::Clear) => false,
            None => {
                instance.is_none()
                    && master_event(ical)
                        .is_some_and(|event| event.property(&ICalendarProperty::Rrule).is_some())
            }
        };
        let mut props =
            with_appended_categories(&self.props, &self.appended_categories, main_event(ical));
        let keys = [START_WHOLE, END_WHOLE];
        let given = keys.map(|key| match props.get(key.prop(), PropType::Time) {
            Some(OwnedPropValue::Time(time)) => Some(*time),
            _ => None,
        });
        let bounds = match given {
            [Some(start), Some(end)] => Some((start, end)),
            [None, None] => None,
            [start, end] => event_times(ical, instance).map(|(stored_start, stored_end)| {
                (start.unwrap_or(stored_start), end.unwrap_or(stored_end))
            }),
        };
        if bounds.is_some_and(|(start, end)| end < start) {
            return Err(CalendarEditError::EndBeforeStart);
        }
        let times = recurring.then_some(given);
        if let Some(times) = times.filter(|times| times.iter().any(Option::is_some)) {
            let stored = event_series_times(ical);
            for ((key, time), stored) in keys
                .into_iter()
                .zip(times)
                .zip([stored.map(|(start, _)| start), stored.map(|(_, end)| end)])
            {
                let Some(time) = time else {
                    continue;
                };
                let minute = time.whole_minute();
                let written = stored
                    .filter(|stored| stored.whole_minute() == minute)
                    .unwrap_or(minute);
                if written != time {
                    props.to_mut().set(key.key(), OwnedPropValue::Time(written));
                }
            }
        }
        if let Some(blob) = self
            .start_zone
            .as_deref()
            .and_then(|name| zone_definition_blob(name, self.start_year()))
        {
            props
                .to_mut()
                .set(TZDEF_START.key(), OwnedPropValue::Binary(blob.into()));
        }
        let previous = match &self.recurrence {
            Some(RecurrenceEdit::Set(_)) => event_series_start(ical),
            _ => None,
        };
        patch_event_from_message(ical, instance, &props, opts)
            .map_err(|_| CalendarEditError::Conversion)?;
        match &self.recurrence {
            None => {}
            Some(RecurrenceEdit::Set(series)) => {
                match set_event_recurrence(ical, &series.rule, series.first, previous) {
                    Ok(RecurrenceSet::Applied) => {}
                    Ok(RecurrenceSet::Unmappable | RecurrenceSet::StartMismatch) => {
                        return Err(CalendarEditError::InvalidRecurrence);
                    }
                    Err(_) => return Err(CalendarEditError::Conversion),
                }
            }
            Some(RecurrenceEdit::Clear) => {
                clear_event_recurrence(ical).map_err(|_| CalendarEditError::Conversion)?;
            }
        }
        if keys
            .iter()
            .any(|key| self.props.get(key.prop(), PropType::Time).is_some())
            && event_duration(ical).is_some_and(|duration| duration > MAX_EVENT_DURATION)
        {
            return Err(CalendarEditError::DurationTooLong);
        }
        if self.attendees.is_empty() {
            Ok(())
        } else {
            set_event_attendees(ical, instance, &self.attendees)
                .map_err(|_| CalendarEditError::Conversion)
        }
    }

    fn start_year(&self) -> i16 {
        let start = match self.props.get(START_WHOLE.prop(), PropType::Time) {
            Some(OwnedPropValue::Time(time)) => Timestamp::from_second(time.to_utc().0.0).ok(),
            _ => None,
        };
        start
            .unwrap_or_else(Timestamp::now)
            .to_zoned(TimeZone::UTC)
            .year()
    }

    fn field(
        &mut self,
        field: UnindexedField,
        source: &Source<'_, '_>,
    ) -> Result<bool, CalendarEditError> {
        let item = match source {
            Source::Set(item) => Some(*item),
            Source::Delete => None,
        };
        match common_field(&mut self.props, field, item.map(|item| &item.item)) {
            CommonField::Applied => return Ok(true),
            CommonField::MissingValue => return Ok(false),
            CommonField::NotCommon => {}
        }
        let (key, value) = match field {
            UnindexedField::ItemReminderIsSet => match item.map(|item| item.item.reminder_is_set) {
                Some(None) => return Ok(false),
                Some(Some(set)) => (REMINDER_SET.prop(), OwnedPropValue::Bool(set)),
                None => (REMINDER_SET.prop(), OwnedPropValue::Bool(false)),
            },
            UnindexedField::ItemReminderMinutesBeforeStart => {
                match item.map(|item| item.item.reminder_minutes_before_start) {
                    Some(None) => return Ok(false),
                    None => return Ok(true),
                    Some(Some(minutes)) if minutes >= 0 => {
                        (REMINDER_DELTA.prop(), OwnedPropValue::I32(minutes))
                    }
                    Some(Some(_)) => return Err(CalendarEditError::InvalidPropertySet),
                }
            }
            UnindexedField::ItemReminderNextTime => {
                match item.map(|item| item.item.reminder_next_time.as_ref()) {
                    Some(None) => return Ok(false),
                    Some(Some(date)) => (REMINDER_SIGNAL_TIME.prop(), time_value(date)?),
                    None => return Err(CalendarEditError::InvalidPropertySet),
                }
            }
            UnindexedField::CalendarStart => match item.map(|item| item.calendar.start.as_ref()) {
                Some(None) => return Ok(false),
                Some(Some(date)) => (START_WHOLE.prop(), time_value(date)?),
                None => return Err(CalendarEditError::InvalidPropertySet),
            },
            UnindexedField::CalendarEnd => match item.map(|item| item.calendar.end.as_ref()) {
                Some(None) => return Ok(false),
                Some(Some(date)) => (END_WHOLE.prop(), time_value(date)?),
                None => return Err(CalendarEditError::InvalidPropertySet),
            },
            UnindexedField::CalendarIsAllDayEvent => {
                match item.map(|item| item.calendar.is_all_day_event) {
                    Some(None) => return Ok(false),
                    Some(Some(all_day)) => (SUB_TYPE.prop(), OwnedPropValue::Bool(all_day)),
                    None => (SUB_TYPE.prop(), OwnedPropValue::Bool(false)),
                }
            }
            UnindexedField::CalendarLegacyFreeBusyStatus => {
                let status = match item.map(|item| item.calendar.legacy_free_busy_status) {
                    Some(None) => return Ok(false),
                    Some(Some(LegacyFreeBusy::NoData)) => busy::NO_DATA,
                    Some(Some(status)) => status as i32,
                    None => BUSY,
                };
                (BUSY_STATUS.prop(), OwnedPropValue::I32(status))
            }
            UnindexedField::CalendarLocation => {
                let text = match item.map(|item| item.calendar.location.as_deref()) {
                    Some(None) => return Ok(false),
                    Some(Some(text)) => text,
                    None => "",
                };
                (LOCATION.prop(), OwnedPropValue::Unicode(Box::from(text)))
            }
            UnindexedField::CalendarConferenceType => {
                match item.map(|item| item.calendar.conference_type) {
                    Some(None) => return Ok(false),
                    Some(Some(kind)) => (CONFERENCING_TYPE.prop(), OwnedPropValue::I32(kind)),
                    None => (CONFERENCING_TYPE.prop(), OwnedPropValue::Null),
                }
            }
            UnindexedField::CalendarStartTimeZone => {
                match item.map(|item| item.calendar.start_time_zone.as_ref()) {
                    Some(None) => return Ok(false),
                    Some(Some(zone)) => {
                        self.start_zone = zone.id.as_deref().map(Box::from);
                    }
                    None => self.start_zone = None,
                }
                return Ok(true);
            }
            _ => return Err(CalendarEditError::InvalidPropertySet),
        };
        self.props.set(key.to_key(), value);
        Ok(true)
    }

    fn extended_value(&mut self, property: &ExtendedProperty<'_>) -> Result<(), CalendarEditError> {
        let (key, value) = extended_value(property).ok_or(CalendarEditError::InvalidPropertySet)?;
        self.props.set(key, value);
        Ok(())
    }
}

fn is_unstored(field: UnindexedField) -> bool {
    (field.is_unstored_groupware_field()
        && !matches!(
            field,
            UnindexedField::ItemReminderIsSet | UnindexedField::ItemReminderMinutesBeforeStart
        ))
        || matches!(
            field,
            UnindexedField::ItemItemClass
                | UnindexedField::CalendarUid
                | UnindexedField::CalendarWhen
                | UnindexedField::CalendarEndTimeZone
                | UnindexedField::CalendarMeetingTimeZone
                | UnindexedField::CalendarTimeZone
                | UnindexedField::CalendarIsResponseRequested
                | UnindexedField::CalendarAllowNewTimeProposal
                | UnindexedField::CalendarMeetingWorkspaceUrl
                | UnindexedField::CalendarNetShowUrl
        )
}

fn attendees_of<'v, 'x>(
    item: &'v CalendarItem<'x>,
    role: AttendeeRole,
) -> Option<&'v Attendees<'x>> {
    let calendar = &item.calendar;
    match role {
        AttendeeRole::Required => calendar.required_attendees.as_ref(),
        AttendeeRole::Optional => calendar.optional_attendees.as_ref(),
        AttendeeRole::Resource => calendar.resources.as_ref(),
    }
}

fn invitees(list: &Attendees<'_>) -> Result<Vec<Invitee>, CalendarEditError> {
    list.0
        .iter()
        .map(|attendee| {
            let mailbox = attendee
                .mailbox
                .as_ref()
                .ok_or(CalendarEditError::InvalidPropertySet)?;
            let email = mailbox
                .email_address
                .as_deref()
                .map(str::trim)
                .filter(|email| email.contains('@') && !has_control(email))
                .ok_or(CalendarEditError::InvalidPropertySet)?;
            let name = mailbox.name.as_deref().map(str::trim).filter(|name| {
                !name.is_empty() && !name.eq_ignore_ascii_case(email) && !has_control(name)
            });
            Ok(Invitee {
                email: Box::from(email),
                name: name.map(Box::from),
            })
        })
        .collect()
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

fn main_event(ical: &ICalendar) -> Option<&ICalendarComponent> {
    ical.components
        .iter()
        .find(|component| component.component_type == ICalendarComponentType::VEvent)
}

fn master_event(ical: &ICalendar) -> Option<&ICalendarComponent> {
    ical.components.iter().find(|component| {
        component.component_type == ICalendarComponentType::VEvent
            && !component.is_recurrence_override()
    })
}

fn time_value(date: &DateTime) -> Result<OwnedPropValue, CalendarEditError> {
    date.to_utc()
        .map(|seconds| OwnedPropValue::Time(FileTime::from_utc(seconds, 0)))
        .ok_or(CalendarEditError::InvalidPropertySet)
}

fn calendar_of<'v, 'x>(value: &'v Item<'x>) -> Result<&'v CalendarItem<'x>, CalendarEditError> {
    match value {
        Item::CalendarItem(item) => Ok(item),
        _ => Err(CalendarEditError::NotACalendarItem),
    }
}
