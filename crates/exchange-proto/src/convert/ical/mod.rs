/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod alarm;
mod attendees;
pub mod eas;
mod forward;
mod itip;
mod meeting;
mod occurrences;
mod participation;
mod patch;
pub(crate) mod props;
mod series;
mod signal;
pub(crate) mod task;
mod to_message;

use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarComponentType, ICalendarMethod, ICalendarParticipationStatus,
        ICalendarRecurrenceRule,
    },
};
use jiff::{SignedDuration, Timestamp, civil::Date};
use std::{
    borrow::Cow,
    ops::{BitOr, BitOrAssign},
    str::FromStr,
};

pub use alarm::{OccurrenceReminder, set_occurrence_reminder};
pub use forward::{EventText, ForwardError, Organizer, event_text, forwarded_event, publish};
pub use occurrences::{EventOccurrence, EventOccurrences, OccurrenceBounds};
pub use task::{
    Advance, TaskInstance, advance_recurring_todo, completed_copy, is_open_recurring_todo,
    next_task_instance, todo_completed_at,
};

pub use meeting::{
    AttendeeLists, AttendeeRole, Invitation, InvitationSpan, Invitee, MeetingRole,
    event_invitation, event_invitation_span, event_meeting_role, event_response_requested,
    set_event_attendees,
};

use crate::{
    common::FileTime,
    convert::{
        ConvertError,
        blob::AppointmentRecur,
        context::{AddressResolver, ConvertOptions, NoDirectory},
        model::{MessageContent, PatchReport, PropBag},
        tags,
    },
    mapi::prop::{OwnedPropValue, PropId, PropKeyRef},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecurrenceId(pub Timestamp);

pub use itip::MeetingMessage;
pub use participation::{
    MeetingProgress, ParticipationError, force_reply, has_recorded_reply, invited_address,
    meeting_progress, set_meeting_state, set_participation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecurrenceSet {
    Applied,
    Unmappable,
    StartMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedInstance {
    Instance(RecurrenceId),
    Deleted,
    OutOfRange,
    NotRecurring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventParts(u8);

impl EventParts {
    pub const BODY: EventParts = EventParts(1);
    pub const RECURRENCE: EventParts = EventParts(1 << 1);
    pub const TIME_ZONES: EventParts = EventParts(1 << 2);
    pub const RECIPIENTS: EventParts = EventParts(1 << 3);
    pub const OCCURRENCES: EventParts = EventParts(1 << 4);
    pub const LAST_OCCURRENCE: EventParts = EventParts(1 << 5);
    pub const MIME: EventParts = EventParts(1 << 6);
    pub const NO_DATA: EventParts = EventParts(1 << 7);
    pub const NONE: EventParts = EventParts(0);
    pub const ALL: EventParts = EventParts(
        Self::BODY.0
            | Self::RECURRENCE.0
            | Self::TIME_ZONES.0
            | Self::RECIPIENTS.0
            | Self::OCCURRENCES.0
            | Self::LAST_OCCURRENCE.0,
    );

    pub const fn has(self, part: EventParts) -> bool {
        self.0 & part.0 != 0
    }

    pub const fn occurrence_bounds(self) -> OccurrenceBounds {
        if self.has(Self::LAST_OCCURRENCE) {
            OccurrenceBounds::FirstAndLast
        } else {
            OccurrenceBounds::First
        }
    }
}

impl BitOr for EventParts {
    type Output = EventParts;

    fn bitor(self, other: EventParts) -> EventParts {
        EventParts(self.0 | other.0)
    }
}

impl BitOrAssign for EventParts {
    fn bitor_assign(&mut self, other: EventParts) {
        self.0 |= other.0;
    }
}

pub fn event_to_message(
    ical: &ICalendar,
    instance: Option<RecurrenceId>,
    resolver: &impl AddressResolver,
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    event_to_message_inner(ical, instance, EventParts::ALL, resolver, opts)
}

pub fn event_parts_to_message(
    ical: &ICalendar,
    instance: Option<RecurrenceId>,
    parts: EventParts,
    resolver: &impl AddressResolver,
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    event_to_message_inner(ical, instance, parts, resolver, opts)
}

fn event_to_message_inner(
    ical: &ICalendar,
    instance: Option<RecurrenceId>,
    parts: EventParts,
    resolver: &dyn AddressResolver,
    _opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    let series = series::Series::new(ical).ok_or(ConvertError::Unsupported)?;
    to_message::event(&series, instance, parts, resolver)
}

pub fn event_mime_text(ical: &ICalendar) -> String {
    let master = series::Series::new(ical)
        .and_then(|series| series.master)
        .and_then(|master| u32::try_from(master).ok());
    let is_event = |id: &u32| {
        ical.components
            .get(*id as usize)
            .is_some_and(|component| component.component_type == ICalendarComponentType::VEvent)
    };
    let Some(root) = ical.components.first() else {
        return ical.to_string();
    };
    match (master, root.component_ids.iter().position(is_event)) {
        (Some(master), Some(first)) if root.component_ids.get(first) != Some(&master) => {
            let mut sorted = ical.clone();
            if let Some(root) = sorted.components.first_mut() {
                root.component_ids.retain(|id| *id != master);
                root.component_ids.insert(first, master);
            }
            sorted.to_string()
        }
        _ => ical.to_string(),
    }
}

pub fn event_override_ical(ical: &ICalendar, instance: RecurrenceId) -> Option<ICalendar> {
    override_ical(ical, series::Series::new(ical)?.find_override(instance)?)
}

fn override_ical(ical: &ICalendar, keep: usize) -> Option<ICalendar> {
    let others = ical
        .components
        .iter()
        .enumerate()
        .filter(|(index, component)| {
            *index != keep && component.component_type == ICalendarComponentType::VEvent
        })
        .filter_map(|(index, _)| u32::try_from(index).ok())
        .collect::<Vec<_>>();
    let mut single = ical.clone();
    single.remove_component_ids(&others).then_some(single)
}

pub fn is_event_override(ical: &ICalendar, instance: RecurrenceId) -> bool {
    series::Series::new(ical).is_some_and(|series| series.find_override(instance).is_some())
}

pub fn event_occurrences(ical: &ICalendar, bounds: OccurrenceBounds) -> Option<EventOccurrences> {
    series::Series::new(ical)?.occurrences(bounds)
}

pub fn is_event_excluded(ical: &ICalendar, instance: RecurrenceId) -> bool {
    series::Series::new(ical).is_some_and(|series| series.excluded(instance))
}

pub fn event_series_times(ical: &ICalendar) -> Option<(FileTime, FileTime)> {
    let series = series::Series::new(ical)?;
    let master = series
        .component(series.master?)
        .filter(|master| master.is_recurrent())?;
    let span = series.span(master)?;
    Some((
        to_message::file_time(span.start.to_timestamp()),
        to_message::file_time(span.end.to_timestamp()),
    ))
}

pub fn event_recurrence(ical: &ICalendar) -> Option<AppointmentRecur> {
    let series = series::Series::new(ical)?;
    let master = series
        .component(series.master?)
        .filter(|master| master.is_recurrent())?;
    to_message::appointment_recur(&series, master, &series.span(master)?)
}

pub fn event_times(
    ical: &ICalendar,
    instance: Option<RecurrenceId>,
) -> Option<(FileTime, FileTime)> {
    let series = series::Series::new(ical)?;
    let (start, end) = match instance {
        None => {
            let span = series.span(series.component(series.main)?)?;
            (span.start.to_timestamp(), span.end.to_timestamp())
        }
        Some(id) => match series.find_override(id) {
            Some(index) => {
                let span = series.span(series.component(index)?)?;
                (span.start.to_timestamp(), span.end.to_timestamp())
            }
            None => {
                let span = series.span(series.component(series.master?)?)?;
                (id.0, id.0.checked_add(span.duration()).ok()?)
            }
        },
    };
    Some((to_message::file_time(start), to_message::file_time(end)))
}

pub fn event_duration(ical: &ICalendar) -> Option<SignedDuration> {
    let series = series::Series::new(ical)?;
    Some(series.span(series.component(series.main)?)?.duration())
}

pub fn event_series_start(ical: &ICalendar) -> Option<Timestamp> {
    let series = series::Series::new(ical)?;
    let master = series.component(series.master?)?;
    Some(series.span(master)?.start.to_timestamp())
}

pub fn set_event_recurrence(
    ical: &mut ICalendar,
    rule: &ICalendarRecurrenceRule,
    first: Date,
    previous: Option<Timestamp>,
) -> Result<RecurrenceSet, ConvertError> {
    patch::set_recurrence(ical, rule, first, previous)
}

pub fn exclude_event_instance(
    ical: &mut ICalendar,
    instance: RecurrenceId,
) -> Result<(), ConvertError> {
    patch::exclude_instance(ical, instance)
}

pub fn clear_event_recurrence(ical: &mut ICalendar) -> Result<(), ConvertError> {
    patch::clear_recurrence(ical)
}

pub fn event_instance_at(ical: &ICalendar, index: usize) -> IndexedInstance {
    let Some(series) = series::Series::new(ical).filter(series::Series::is_recurring) else {
        return IndexedInstance::NotRecurring;
    };
    match series.nth_instance(index) {
        Some(id) if series.excluded(id) => IndexedInstance::Deleted,
        Some(id) => IndexedInstance::Instance(id),
        None => IndexedInstance::OutOfRange,
    }
}

pub fn patch_event_from_message(
    ical: &mut ICalendar,
    instance: Option<RecurrenceId>,
    changes: &PropBag,
    _opts: &ConvertOptions<'_>,
) -> Result<PatchReport, ConvertError> {
    patch::event(
        ical,
        instance,
        changes,
        patch::ReminderMode::Tracked(Timestamp::now()),
    )
}

pub fn recipients_changed(
    staged: &[PropBag],
    stored: &[PropBag],
    resolver: &dyn AddressResolver,
) -> bool {
    attendees::recipients_changed(staged, stored, resolver)
}

pub fn set_attendees_from_recipients(
    ical: &mut ICalendar,
    content: &MessageContent,
    fallback_organizer: &str,
    resolver: &dyn AddressResolver,
) -> Result<(), ConvertError> {
    attendees::set_attendees(ical, content, fallback_organizer, resolver)
}

pub fn clear_event_draft(ical: &mut ICalendar) {
    patch::clear_draft(ical);
}

pub fn drop_unscheduled_event_draft(ical: &mut ICalendar) {
    patch::drop_unscheduled_draft(ical);
}

pub fn meeting_uid(props: &PropBag) -> Option<Cow<'_, str>> {
    itip::message_uid(props)
}

pub fn meeting_instance(props: &PropBag) -> Result<Option<RecurrenceId>, ConvertError> {
    itip::instance_start(props).map(|start| start.map(RecurrenceId))
}

pub fn meeting_response_status(props: &PropBag) -> Option<ICalendarParticipationStatus> {
    itip::response_status(props)
}

pub fn meeting_to_itip(
    ical: &mut ICalendar,
    message: MeetingMessage,
    content: &MessageContent,
    sender: &str,
    resolver: &dyn AddressResolver,
) -> Result<(), ConvertError> {
    itip::to_itip(ical, message, content, sender, resolver)
}

pub fn zone_definition_blob(name: &str, year: i16) -> Option<Vec<u8>> {
    let tz = Tz::from_str(name).ok()?;
    let mut blob = Vec::new();
    to_message::tz_definition(tz, year..=year).encode(&mut blob);
    Some(blob)
}

pub fn task_to_message(
    ical: &ICalendar,
    _opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    task::task_message(ical)
}

pub fn has_unmapped_task_recurrence(ical: &ICalendar) -> bool {
    task::has_unmapped_recurrence(ical)
}

pub fn patch_task_from_message(
    ical: &mut ICalendar,
    changes: &PropBag,
    _opts: &ConvertOptions<'_>,
) -> Result<PatchReport, ConvertError> {
    task::patch_task(ical, changes, Timestamp::now())
}

pub(crate) fn method_class(
    method: Option<&ICalendarMethod>,
    partstat: Option<&ICalendarParticipationStatus>,
) -> Option<&'static str> {
    match method {
        None | Some(ICalendarMethod::Publish) => Some(props::CLASS_APPOINTMENT),
        Some(ICalendarMethod::Request | ICalendarMethod::Add) => Some(props::CLASS_REQUEST),
        Some(ICalendarMethod::Cancel) => Some(props::CLASS_CANCELED),
        Some(ICalendarMethod::Counter) => Some(props::CLASS_RESP_TENT),
        Some(ICalendarMethod::Reply) => Some(match partstat {
            Some(ICalendarParticipationStatus::Accepted) => props::CLASS_RESP_POS,
            Some(ICalendarParticipationStatus::Declined) => props::CLASS_RESP_NEG,
            _ => props::CLASS_RESP_TENT,
        }),
        Some(ICalendarMethod::Refresh | ICalendarMethod::Declinecounter) => None,
    }
}

pub fn calendar_part_class(method: &str, calendar: Option<&str>) -> Option<&'static str> {
    let method = hashify::map_ignore_case!(method.trim().as_bytes(), ICalendarMethod,
        "PUBLISH" => ICalendarMethod::Publish,
        "REQUEST" => ICalendarMethod::Request,
        "REPLY" => ICalendarMethod::Reply,
        "ADD" => ICalendarMethod::Add,
        "CANCEL" => ICalendarMethod::Cancel,
        "REFRESH" => ICalendarMethod::Refresh,
        "COUNTER" => ICalendarMethod::Counter,
        "DECLINECOUNTER" => ICalendarMethod::Declinecounter,
    )?;
    if *method != ICalendarMethod::Reply {
        return method_class(Some(method), None);
    }
    Some(reply_class(calendar))
}

pub(crate) fn merge_meeting_props(calendar: &str, bag: &mut PropBag) {
    let Ok(ical) = ICalendar::parse(calendar) else {
        return;
    };
    let Some(series) = series::Series::new(&ical) else {
        return;
    };
    let instance = match series.master {
        Some(_) => None,
        None => series
            .component(series.main)
            .and_then(|main| series.recurrence_id(main)),
    };
    let parts = EventParts::RECURRENCE | EventParts::TIME_ZONES | EventParts::RECIPIENTS;
    let Ok(content) = to_message::event(&series, instance, parts, &NoDirectory) else {
        return;
    };
    for (key, value) in content.props.into_entries() {
        let carried = match key.as_ref() {
            PropKeyRef::Lid { .. } => true,
            PropKeyRef::Tag(id) => MEETING_MESSAGE_TAGS.contains(&id),
            PropKeyRef::Name { .. } => false,
        };
        if carried {
            bag.set(key, value);
        }
    }
    if instance.is_some() {
        for lid in [props::IS_EXCEPTION, props::IS_RECURRING] {
            bag.set(lid.key(), OwnedPropValue::Bool(true));
        }
    }
}

const MEETING_MESSAGE_TAGS: [PropId; 4] = [
    tags::START_DATE,
    tags::END_DATE,
    tags::RESPONSE_REQUESTED,
    props::REPLY_REQUESTED,
];

pub const REPLY_CLASSES: [&str; 3] = [
    props::CLASS_RESP_POS,
    props::CLASS_RESP_TENT,
    props::CLASS_RESP_NEG,
];

pub fn reply_class(calendar: Option<&str>) -> &'static str {
    let ical = calendar.and_then(|text| ICalendar::parse(text).ok());
    let partstat = ical.as_ref().and_then(|ical| {
        ical.components
            .iter()
            .filter(|component| component.component_type.is_event_or_todo())
            .find_map(to_message::partstat)
    });
    method_class(Some(&ICalendarMethod::Reply), partstat).unwrap_or(props::CLASS_RESP_TENT)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/tests.rs"]
mod tests;
