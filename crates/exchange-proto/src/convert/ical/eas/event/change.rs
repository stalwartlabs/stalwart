/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
        ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarRecurrenceRule, ICalendarStatus, ICalendarUserTypes, ICalendarValue,
    },
};
use jiff::Timestamp;
use smallvec::SmallVec;
use std::{borrow::Cow, iter};

use super::super::NORMAL_SENSITIVITY;
use super::{
    super::{
        EasEvent, Render, attendee as rendered_attendee, attendee_type, component_calendar,
        meeting_status, render_event, same_properties,
        todo::{Edit, class, non_empty},
        utc,
    },
    ALL_DAY, DELETED, ExceptionSlot, MAX_EXCEPTION_ATTENDEES, ONE_DAY, Zone, add_alarm, address,
    attendee_entry, attendee_type_parameter, check_occurrences, exception_attendees,
    exception_start, instant, latest_exceptions, location, organizer_entry, override_exception,
    recurrence_rule, remove_display_alarms, rrule_entry,
};
use crate::{
    convert::{
        ConvertError,
        ical::{
            MeetingRole, RecurrenceId, event_meeting_role,
            patch::{
                TimeTarget, clear_exceptions, clear_recurrence, exclude_instance,
                remove_components, same_rule, set_busy_status, set_disallow_counter, set_text,
                set_value, start_exception, target,
            },
            series::{Series, Span, TimeForm, time_form},
            to_message::{address as entry_address, first_text, reminder as component_reminder},
        },
    },
    eas::{
        commands::{
            appdata::{Attendee, Calendar, CalendarException, List, calendar::Categories},
            sync::Ghosting,
        },
        tokens::{ProtocolVersion, tag::calendar as cal},
        types::EasDateTime,
    },
};

const DEFAULT_BUSY_STATUS: u8 = 2;

pub struct EventChange<'x> {
    pub calendar: &'x Calendar<'x>,
    pub description: Option<&'x str>,
    pub owner: &'x [String],
    pub version: ProtocolVersion,
    pub ghosting: Ghosting<'x>,
    pub now: Timestamp,
}

#[derive(Default)]
struct Plan<'x> {
    summary: Option<Edit<String>>,
    location: Option<Edit<String>>,
    description: Option<Edit<String>>,
    class: Option<Edit<ICalendarValue>>,
    busy_status: Option<u8>,
    disallow_counter: Option<bool>,
    categories: Option<Vec<String>>,
    reminder: Option<Option<u32>>,
    times: Option<Times>,
    recurrence: Option<RecurrenceEdit>,
    attendees: Option<AttendeeEdit>,
    rsvp: Option<bool>,
    cancel: bool,
    exceptions: &'x [CalendarException<'x>],
    inherit: Inherit,
}

#[derive(Default)]
struct Inherit {
    subject: Option<Inherited<Option<String>>>,
    location: Option<Inherited<Option<String>>>,
    sensitivity: Option<Inherited<u8>>,
    categories: Option<Inherited<Vec<String>>>,
}

struct Inherited<T> {
    before: T,
    after: T,
}

struct Times {
    start: ICalendarEntry,
    end: ICalendarEntry,
    start_at: Timestamp,
    end_at: Timestamp,
}

enum RecurrenceEdit {
    Set(Box<ICalendarRecurrenceRule>),
    Clear,
}

struct AttendeeEdit {
    organizer: Option<ICalendarEntry>,
    attendees: Vec<ICalendarEntry>,
    removed: Vec<String>,
    added: Vec<ICalendarEntry>,
    revisions: Vec<Revision>,
}

struct Revision {
    address: String,
    name: Option<String>,
    kind: Option<u8>,
}

#[derive(Clone, Copy)]
enum Target {
    Main,
    Occurrence(RecurrenceId),
}

pub fn event_change_from_eas(
    ical: &mut ICalendar,
    change: &EventChange<'_>,
) -> Result<bool, ConvertError> {
    let plan = Plan::new(ical, change)?;
    if plan.is_empty() {
        return Ok(false);
    }
    plan.apply(ical, Target::Main, change)
}

pub fn occurrence_change_from_eas(
    ical: &mut ICalendar,
    instance: EasDateTime,
    change: &EventChange<'_>,
) -> Result<bool, ConvertError> {
    let given = change.calendar;
    if change.version < ProtocolVersion::V160
        || given.recurrence.is_some()
        || given
            .exceptions
            .as_ref()
            .is_some_and(|exceptions| !exceptions.0.is_empty())
        || given
            .attendees
            .as_ref()
            .is_some_and(|attendees| !attendees.0.is_empty())
        || cancels(given.meeting_status, None)
    {
        return Err(ConvertError::Unsupported);
    }
    let zone = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let all_day = series
            .master
            .and_then(|master| series.component(master))
            .and_then(|master| series.span(master))
            .is_some_and(|span| span.all_day);
        change_zone(ical, given, all_day, change.version)?
    };
    let id = recurring_instance(ical, &zone, instance)?;
    let index = target(ical, Some(id))?;
    let plan = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let component = series.component(index).ok_or(ConvertError::Unsupported)?;
        let span = series.span(component).ok_or(ConvertError::Unsupported)?;
        let current = component_calendar(&series, index, component, &span, change.version);
        let description = first_text(component, &ICalendarProperty::Description);
        Plan::fields(ical, change, &current, description)?
    };
    if plan.is_empty() {
        return Ok(false);
    }
    plan.apply(ical, Target::Occurrence(id), change)
}

pub fn occurrence_delete_from_eas(
    ical: &mut ICalendar,
    instance: EasDateTime,
) -> Result<(), ConvertError> {
    let id = recurring_instance(ical, &stored_zone(ical)?, instance)?;
    exclude_instance(ical, id)
}

impl<'x> EventChange<'x> {
    fn ghosting(&self) -> Ghosting<'x> {
        if self.version >= ProtocolVersion::V160 {
            Ghosting::Except(&[])
        } else {
            self.ghosting
        }
    }
}

impl<'x> Plan<'x> {
    fn new(ical: &ICalendar, change: &EventChange<'x>) -> Result<Self, ConvertError> {
        let EasEvent {
            calendar: current,
            description,
            ..
        } = render_event(ical, change.owner, change.version, Render::Fields)
            .ok_or(ConvertError::Unsupported)?;
        let given = change.calendar;
        let exceptions = given
            .exceptions
            .as_ref()
            .map_or(&[][..], |list| list.0.as_slice());
        let cancel = cancels(given.meeting_status, current.meeting_status);
        if change.version >= ProtocolVersion::V160 && (cancel || !exceptions.is_empty()) {
            return Err(ConvertError::Unsupported);
        }
        let mut plan = Plan::fields(ical, change, &current, description)?;
        plan.cancel = cancel && !is_canceled(ical)?;
        plan.recurrence = recurrence_edit(ical, change, &current, &mut plan.times)?;
        plan.attendees = attendee_edit(ical, change, Target::Main)?;
        plan.rsvp = given.response_requested.filter(|requested| {
            !matches!(
                event_meeting_role(ical, change.owner),
                MeetingRole::Attendee
            ) && event_attendees(ical).any(|entry| rsvp_stale(entry, change.owner, *requested))
        });
        plan.exceptions = exceptions;
        if !exceptions.is_empty() {
            plan.inherit = Inherit::of(&plan, change, &current);
        }
        Ok(plan)
    }

    fn fields(
        ical: &ICalendar,
        change: &EventChange<'x>,
        current: &Calendar<'_>,
        description: Option<&str>,
    ) -> Result<Self, ConvertError> {
        let given = change.calendar;
        let ghosting = change.ghosting();
        let mut plan = Plan {
            summary: text_edit(
                given.subject.as_deref(),
                current.subject.as_deref(),
                ghosting.ghosts(cal::SUBJECT),
            ),
            location: text_edit(
                location(given.location.as_deref(), given.location_details.as_ref())
                    .or(given.location.as_deref())
                    .or(given.location_details.as_ref().map(|_| "")),
                current.location.as_deref(),
                ghosting.ghosts(cal::LOCATION),
            ),
            description: change
                .description
                .and_then(|text| text_edit(Some(text), description, true)),
            ..Default::default()
        };

        if let Some(level) = sensitivity_level(change)
            && level != current.sensitivity.unwrap_or(NORMAL_SENSITIVITY)
        {
            plan.class = class(level);
        }

        let busy = given
            .busy_status
            .or_else(|| (!ghosting.ghosts(cal::BUSY_STATUS)).then_some(DEFAULT_BUSY_STATUS));
        plan.busy_status = busy.filter(|status| Some(*status) != current.busy_status);
        plan.disallow_counter = given
            .disallow_new_time_proposal
            .filter(|disallow| *disallow != current.disallow_new_time_proposal.unwrap_or_default());

        let categories = match &given.categories {
            Some(list) => Some(list.0.as_slice()),
            None if !ghosting.ghosts(cal::CATEGORIES) => Some(&[][..]),
            None => None,
        };
        if let Some(categories) = categories
            && categories
                != current
                    .categories
                    .as_ref()
                    .map_or(&[][..], |list| list.0.as_slice())
        {
            plan.categories = Some(
                categories
                    .iter()
                    .filter(|category| !category.is_empty())
                    .map(|category| category.to_string())
                    .collect(),
            );
        }

        let reminder = match given.reminder {
            Some(reminder) => Some(reminder.0),
            None if !ghosting.ghosts(cal::REMINDER) => Some(None),
            None => None,
        };
        plan.reminder =
            reminder.filter(|minutes| *minutes != current.reminder.and_then(|current| current.0));

        plan.times = times(ical, given, current, change.version)?;
        Ok(plan)
    }

    fn edits(&self) -> bool {
        self.summary.is_some()
            || self.location.is_some()
            || self.description.is_some()
            || self.class.is_some()
            || self.busy_status.is_some()
            || self.disallow_counter.is_some()
            || self.categories.is_some()
            || self.reminder.is_some()
            || self.times.is_some()
            || self.recurrence.is_some()
            || self.attendees.is_some()
            || self.rsvp.is_some()
            || self.cancel
    }

    fn is_empty(&self) -> bool {
        !self.edits() && self.exceptions.is_empty()
    }

    fn apply(
        self,
        ical: &mut ICalendar,
        target: Target,
        change: &EventChange<'_>,
    ) -> Result<bool, ConvertError> {
        let mut changed = self.edits();
        let reset = matches!(target, Target::Main)
            && (self.times.is_some() || matches!(self.recurrence, Some(RecurrenceEdit::Set(_))));
        let kept = if reset { start_exception(ical) } else { None };
        if let Some(edit) = &self.attendees {
            set_attendees(ical, edit, target)?;
        }
        if let Some(requested) = self.rsvp {
            set_rsvp(ical, change.owner, requested);
        }
        if matches!(target, Target::Main) {
            follow_master(
                ical,
                self.description.as_ref(),
                self.reminder,
                self.categories.as_deref(),
            )?;
        }
        let mut index = target.index(ical)?;
        if let Some(minutes) = self.reminder {
            index = remove_display_alarms(ical, index)?;
            if let Some(minutes) = minutes {
                add_alarm(ical, index, minutes)?;
            }
        }
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        for (name, edit) in [
            (ICalendarProperty::Summary, self.summary),
            (ICalendarProperty::Location, self.location),
            (ICalendarProperty::Description, self.description),
        ] {
            match edit {
                Some(Edit::Set(text)) => set_text(component, name, &text),
                Some(Edit::Remove) => remove_all(component, &name),
                None => {}
            }
        }
        match self.class {
            Some(Edit::Set(value)) => set_value(component, ICalendarProperty::Class, value),
            Some(Edit::Remove) => remove_all(component, &ICalendarProperty::Class),
            None => {}
        }
        if let Some(status) = self.busy_status {
            set_busy_status(component, i32::from(status));
        }
        if let Some(disallow) = self.disallow_counter {
            set_disallow_counter(component, disallow);
        }
        if let Some(categories) = self.categories {
            set_categories(component, categories);
        }
        if self.cancel {
            set_value(
                component,
                ICalendarProperty::Status,
                ICalendarValue::Status(ICalendarStatus::Cancelled),
            );
        }
        if let Some(Times { start, end, .. }) = self.times {
            component.entries.retain(|entry| {
                !matches!(
                    entry.name,
                    ICalendarProperty::Dtstart
                        | ICalendarProperty::Dtend
                        | ICalendarProperty::Duration
                )
            });
            component.entries.push(start);
            component.entries.push(end);
        }
        match self.recurrence {
            Some(RecurrenceEdit::Set(rule)) => {
                remove_all(component, &ICalendarProperty::Rrule);
                component.entries.push(rrule_entry(rule));
            }
            Some(RecurrenceEdit::Clear) => clear_recurrence(ical)?,
            None => {}
        }
        if reset {
            clear_exceptions(ical, kept)?;
        }
        changed |= apply_exceptions(ical, change, self.exceptions, &self.inherit)?;
        if changed {
            let index = target.index(ical)?;
            let component = ical
                .components
                .get_mut(index)
                .ok_or(ConvertError::Unsupported)?;
            let stamp = ICalendarValue::PartialDateTime(PartialDateTime::from_utc_timestamp(
                change.now.as_second(),
            ));
            set_value(component, ICalendarProperty::LastModified, stamp.clone());
            set_value(component, ICalendarProperty::Dtstamp, stamp);
        }
        Ok(changed)
    }
}

impl Target {
    fn index(self, ical: &ICalendar) -> Result<usize, ConvertError> {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        self.index_in(&series)
    }

    fn index_in(self, series: &Series<'_>) -> Result<usize, ConvertError> {
        match self {
            Target::Main => Ok(series.main),
            Target::Occurrence(id) => series.find_override(id).ok_or(ConvertError::Unsupported),
        }
    }
}

fn recurring_instance(
    ical: &ICalendar,
    zone: &Zone,
    instance: EasDateTime,
) -> Result<RecurrenceId, ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let span = series
        .master
        .and_then(|master| series.component(master))
        .filter(|master| master.is_recurrent())
        .and_then(|master| series.span(master))
        .ok_or(ConvertError::Unsupported)?;
    let candidates = Candidates::of(zone, &span, instant(instance)?)?;
    let occurrences = Occurrences::new(&series, candidates.iter().collect());
    Ok(candidates.pick(&occurrences))
}

fn is_canceled(ical: &ICalendar) -> Result<bool, ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let main = series
        .component(series.main)
        .ok_or(ConvertError::Unsupported)?;
    Ok(matches!(main.status(), Some(ICalendarStatus::Cancelled)))
}

fn cancels(given: Option<u8>, current: Option<u8>) -> bool {
    let canceled = |status: Option<u8>| {
        status.is_some_and(|status| status & meeting_status::CANCELED_FLAG != 0)
    };
    canceled(given) && !canceled(current)
}

fn recurrence_edit(
    ical: &ICalendar,
    change: &EventChange<'_>,
    current: &Calendar<'_>,
    times: &mut Option<Times>,
) -> Result<Option<RecurrenceEdit>, ConvertError> {
    let given = change.calendar;
    let clear = || {
        current
            .recurrence
            .is_some()
            .then_some(RecurrenceEdit::Clear)
    };
    match &given.recurrence {
        Some(recurrence) if recurrence.recurrence_type.is_some() => {
            let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
            let master = series
                .master
                .and_then(|index| series.component(index))
                .ok_or(ConvertError::Unsupported)?;
            let start_entry = match times {
                Some(times) => &times.start,
                None => master
                    .property(&ICalendarProperty::Dtstart)
                    .ok_or(ConvertError::Unsupported)?,
            };
            let form = time_form(start_entry);
            let start = given
                .start_time
                .or(current.start_time)
                .ok_or(ConvertError::Unsupported)?;
            let all_day = all_day(given, current);
            let zone = change_zone(ical, given, all_day, change.version)?;
            let rule = recurrence_rule(recurrence, start.0, &zone, form)?;
            if same_rule(&series, master, &rule, start_entry) {
                return Ok(None);
            }
            check_occurrences(recurrence)?;
            let (start_at, end_at) = match times {
                Some(times) => (times.start_at, times.end_at),
                None => {
                    let start_at = instant(start.0)?;
                    let end_at = current
                        .end_time
                        .map_or(Ok(start_at), |end| instant(end.0))?;
                    if all_day {
                        (zone.day(start_at)?, zone.day(end_at)?)
                    } else {
                        (start_at, end_at)
                    }
                }
            };
            let rule = match zone.first_occurrence(&rule, start_at, all_day, form) {
                Some(first) if first != start_at => {
                    let end_at = first
                        .checked_add(end_at.duration_since(start_at))
                        .map_err(|_| ConvertError::Unsupported)?;
                    let rule = recurrence_rule(recurrence, utc(first), &zone, form)?;
                    if current.start_time.map(|time| instant(time.0)).transpose()? == Some(first)
                        && current.end_time.map(|time| instant(time.0)).transpose()? == Some(end_at)
                        && current.all_day_event == Some(u8::from(all_day))
                    {
                        *times = None;
                        if master
                            .property(&ICalendarProperty::Dtstart)
                            .is_some_and(|dtstart| same_rule(&series, master, &rule, dtstart))
                        {
                            return Ok(None);
                        }
                    } else {
                        *times = Some(Times {
                            start: zone.time_entry(ICalendarProperty::Dtstart, first, all_day)?,
                            end: zone.time_entry(ICalendarProperty::Dtend, end_at, all_day)?,
                            start_at: first,
                            end_at,
                        });
                    }
                    rule
                }
                _ => rule,
            };
            Ok(Some(RecurrenceEdit::Set(Box::new(rule))))
        }
        Some(_) => Ok(clear()),
        None if !change.ghosting().ghosts(cal::RECURRENCE) => Ok(clear()),
        None => Ok(None),
    }
}

fn attendee_edit(
    ical: &ICalendar,
    change: &EventChange<'_>,
    target: Target,
) -> Result<Option<AttendeeEdit>, ConvertError> {
    let Some(list) = &change.calendar.attendees else {
        return Ok(None);
    };
    let is_owner = |email: &str| {
        change
            .owner
            .iter()
            .any(|own| own.eq_ignore_ascii_case(email))
    };
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let component = series
        .component(target.index_in(&series)?)
        .ok_or(ConvertError::Unsupported)?;
    let stored: Vec<(&str, &ICalendarEntry)> = component
        .properties(&ICalendarProperty::Attendee)
        .filter_map(|entry| Some((entry_address(entry)?, entry)))
        .collect();
    if matches!(target, Target::Occurrence(_)) && stored.len() > MAX_EXCEPTION_ATTENDEES {
        return Ok(None);
    }
    let known = |email: &str| {
        stored
            .iter()
            .find(|(address, _)| address.eq_ignore_ascii_case(email))
            .copied()
    };
    let mut given: Vec<(&str, &Attendee<'_>)> = Vec::with_capacity(list.0.len());
    for attendee in &list.0 {
        if let Some(email) = address(attendee)
            && !is_owner(email)
            && !given
                .iter()
                .any(|(seen, _)| seen.eq_ignore_ascii_case(email))
        {
            given.push((email, attendee));
        }
    }
    let others = stored
        .iter()
        .filter(|(address, _)| !is_owner(address))
        .count();
    let mut membership = given.len() != others;
    let mut revisions = Vec::new();
    for (email, attendee) in &given {
        match known(email) {
            Some((address, entry)) => revisions.extend(Revision::of(entry, address, attendee)),
            None => membership = true,
        }
    }
    if !membership && revisions.is_empty() {
        return Ok(None);
    }
    let organizer_is_owner = component
        .property(&ICalendarProperty::Organizer)
        .and_then(entry_address)
        .is_some_and(is_owner);
    let has_organizer = component.has_property(&ICalendarProperty::Organizer);
    let master_has_organizer = series
        .component(series.main)
        .is_some_and(|main| main.has_property(&ICalendarProperty::Organizer));
    let may_edit = match event_meeting_role(ical, change.owner) {
        MeetingRole::Organizer => true,
        MeetingRole::None => {
            !master_has_organizer || (matches!(target, Target::Occurrence(_)) && organizer_is_owner)
        }
        MeetingRole::Attendee => false,
    };
    if !may_edit {
        return match target {
            Target::Main if membership => Err(ConvertError::Unsupported),
            _ => Ok(None),
        };
    }
    let legacy = change.version < ProtocolVersion::V160;
    let added: Vec<ICalendarEntry> = given
        .iter()
        .filter(|(email, _)| known(email).is_none())
        .filter_map(|(_, attendee)| {
            attendee_entry(attendee, change.calendar.response_requested, legacy)
        })
        .collect();
    let removed = stored
        .iter()
        .filter(|(address, _)| {
            !is_owner(address)
                && !given
                    .iter()
                    .any(|(email, _)| email.eq_ignore_ascii_case(address))
        })
        .map(|(address, _)| address.to_string())
        .collect();
    let attendees = stored
        .iter()
        .filter(|(address, _)| is_owner(address))
        .map(|(_, entry)| (*entry).clone())
        .chain(given.iter().filter_map(|(email, _)| {
            let (address, entry) = known(email)?;
            let mut entry = entry.clone();
            if let Some(revision) = revisions
                .iter()
                .find(|revision| revision.address.eq_ignore_ascii_case(address))
            {
                revision.apply(&mut entry);
            }
            Some(entry)
        }))
        .chain(added.iter().cloned())
        .collect();
    let organizer = if has_organizer || given.is_empty() {
        None
    } else {
        Some(organizer_entry(
            change.calendar,
            change.owner.first().map_or("", String::as_str),
            legacy,
        )?)
    };
    Ok(Some(AttendeeEdit {
        organizer,
        attendees,
        removed,
        added,
        revisions,
    }))
}

impl Revision {
    fn of(entry: &ICalendarEntry, address: &str, given: &Attendee<'_>) -> Option<Self> {
        let current = rendered_attendee(entry, address);
        let name = non_empty(given.name.as_deref().map(str::trim))
            .filter(|name| current.name.as_deref() != Some(*name))
            .map(str::to_string);
        let kind = given.attendee_type.filter(|kind| {
            matches!(
                *kind,
                attendee_type::REQUIRED | attendee_type::OPTIONAL | attendee_type::RESOURCE
            ) && current.attendee_type != Some(*kind)
        });
        (name.is_some() || kind.is_some()).then(|| Revision {
            address: address.to_string(),
            name,
            kind,
        })
    }

    fn apply(&self, entry: &mut ICalendarEntry) {
        if let Some(name) = &self.name {
            entry
                .params
                .retain(|param| param.name != ICalendarParameterName::Cn);
            entry.params.push(ICalendarParameter::cn(name.clone()));
        }
        if self.kind.is_some() {
            entry.params.retain(|param| {
                !matches!(
                    param.value,
                    ICalendarParameterValue::Role(_)
                        | ICalendarParameterValue::Cutype(
                            ICalendarUserTypes::Resource | ICalendarUserTypes::Room
                        )
                )
            });
            entry.params.push(attendee_type_parameter(self.kind));
        }
    }
}

fn set_attendees(
    ical: &mut ICalendar,
    edit: &AttendeeEdit,
    target: Target,
) -> Result<(), ConvertError> {
    let (main, overrides) = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let main = target.index_in(&series)?;
        let overrides: SmallVec<[usize; 4]> = series
            .overrides()
            .map(|(index, _, _)| index)
            .filter(|index| matches!(target, Target::Main) && *index != main)
            .collect();
        (main, overrides)
    };
    let organize = |component: &mut ICalendarComponent| {
        if let Some(organizer) = &edit.organizer
            && !component.has_property(&ICalendarProperty::Organizer)
        {
            component.entries.push(organizer.clone());
        }
    };
    let component = ical
        .components
        .get_mut(main)
        .ok_or(ConvertError::Unsupported)?;
    remove_all(component, &ICalendarProperty::Attendee);
    organize(component);
    component.entries.extend(edit.attendees.iter().cloned());
    for index in overrides {
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        component.entries.retain(|entry| {
            entry.name != ICalendarProperty::Attendee
                || entry_address(entry).is_none_or(|address| {
                    !edit
                        .removed
                        .iter()
                        .any(|removed| removed.eq_ignore_ascii_case(address))
                })
        });
        organize(component);
        if !edit.revisions.is_empty() {
            for entry in component
                .entries
                .iter_mut()
                .filter(|entry| entry.name == ICalendarProperty::Attendee)
            {
                if let Some(revision) = entry_address(entry).and_then(|address| {
                    edit.revisions
                        .iter()
                        .find(|revision| revision.address.eq_ignore_ascii_case(address))
                }) {
                    revision.apply(entry);
                }
            }
        }
        let missing: SmallVec<[ICalendarEntry; 4]> = edit
            .added
            .iter()
            .filter(|added| {
                entry_address(added).is_some_and(|address| {
                    !component
                        .properties(&ICalendarProperty::Attendee)
                        .filter_map(entry_address)
                        .any(|present| present.eq_ignore_ascii_case(address))
                })
            })
            .cloned()
            .collect();
        component.entries.extend(missing);
    }
    Ok(())
}

enum ExceptionEdit<'a, 'c> {
    Exclude,
    Update(&'a CalendarException<'c>),
    Create(Timestamp, &'a CalendarException<'c>),
}

struct Occurrences {
    overrides: Vec<RecurrenceId>,
    excluded: Vec<Timestamp>,
    instances: Vec<RecurrenceId>,
}

struct Candidates {
    direct: RecurrenceId,
    mapped: Option<RecurrenceId>,
}

impl Occurrences {
    fn new(series: &Series<'_>, mut candidates: Vec<RecurrenceId>) -> Self {
        let mut overrides: Vec<RecurrenceId> = series.overrides().map(|(_, _, id)| id).collect();
        overrides.sort_unstable();
        let mut excluded: Vec<Timestamp> =
            series.exdates().map(|zoned| zoned.to_timestamp()).collect();
        excluded.sort_unstable();
        series.retain_instances(&mut candidates);
        Occurrences {
            overrides,
            excluded,
            instances: candidates,
        }
    }

    fn is_override(&self, id: RecurrenceId) -> bool {
        self.overrides.binary_search(&id).is_ok()
    }

    fn is_excluded(&self, id: RecurrenceId) -> bool {
        self.excluded.binary_search(&id.0).is_ok()
    }

    fn is_instance(&self, id: RecurrenceId) -> bool {
        self.instances.binary_search(&id).is_ok()
    }

    fn knows(&self, id: RecurrenceId) -> bool {
        self.is_override(id) || self.is_excluded(id) || self.is_instance(id)
    }
}

impl Candidates {
    fn of(zone: &Zone, span: &Span, original: Timestamp) -> Result<Self, ConvertError> {
        if span.all_day {
            return Ok(Candidates {
                direct: RecurrenceId(zone.day(original)?),
                mapped: None,
            });
        }
        let mapped = zone.series_instant(original, span.start.to_timestamp())?;
        Ok(Candidates {
            direct: RecurrenceId(original),
            mapped: (mapped != original).then_some(RecurrenceId(mapped)),
        })
    }

    fn iter(&self) -> impl Iterator<Item = RecurrenceId> {
        iter::once(self.direct).chain(self.mapped)
    }

    fn pick(&self, occurrences: &Occurrences) -> RecurrenceId {
        match self.mapped {
            Some(mapped) if !occurrences.knows(self.direct) => mapped,
            _ => self.direct,
        }
    }
}

fn apply_exceptions(
    ical: &mut ICalendar,
    change: &EventChange<'_>,
    exceptions: &[CalendarException<'_>],
    inherit: &Inherit,
) -> Result<bool, ConvertError> {
    if exceptions.is_empty() {
        return Ok(false);
    }
    let (zone, master, span, mut edits) = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let master = series.master.ok_or(ConvertError::Unsupported)?;
        let span = series
            .component(master)
            .and_then(|component| series.span(component))
            .ok_or(ConvertError::Unsupported)?;
        let zone = change_zone(ical, change.calendar, span.all_day, change.version)?;
        let mut resolved = Vec::with_capacity(exceptions.len());
        for exception in latest_exceptions(exceptions)? {
            let original = exception_start(exception)?;
            resolved.push((exception, original, Candidates::of(&zone, &span, original)?));
        }
        let occurrences = Occurrences::new(
            &series,
            resolved
                .iter()
                .flat_map(|(_, _, candidates)| candidates.iter())
                .collect(),
        );
        let mut edits = Vec::with_capacity(resolved.len());
        for (exception, original, candidates) in resolved.into_iter().rev() {
            let id = candidates.pick(&occurrences);
            if occurrences.is_excluded(id) {
                continue;
            }
            let edit = if exception.deleted == Some(DELETED) {
                ExceptionEdit::Exclude
            } else if occurrences.is_override(id) {
                ExceptionEdit::Update(exception)
            } else {
                ExceptionEdit::Create(original, exception)
            };
            if occurrences.is_override(id) || occurrences.is_instance(id) {
                edits.push((id, edit));
            }
        }
        (zone, master, span, edits)
    };
    edits.sort_by_key(|(id, _)| *id);
    edits.dedup_by_key(|(id, _)| *id);

    let duration = span.duration();
    let mut changed = false;
    for (id, edit) in &edits {
        if let ExceptionEdit::Create(original, exception) = edit {
            override_exception(
                ical,
                master,
                ExceptionSlot {
                    zone: &zone,
                    all_day: span.all_day,
                    recurrence_id: id.0,
                    original: *original,
                    duration,
                },
                exception,
            )?;
            changed = true;
        }
    }
    for (id, edit) in &edits {
        match edit {
            ExceptionEdit::Update(exception) => {
                changed |= update_override(ical, change, *id, exception, inherit)?;
            }
            ExceptionEdit::Create(_, exception) if exception_attendees(exception).is_some() => {
                changed |= update_override(ical, change, *id, exception, inherit)?;
            }
            _ => {}
        }
    }
    let excluded: SmallVec<[RecurrenceId; 4]> = edits
        .iter()
        .filter(|(_, edit)| matches!(edit, ExceptionEdit::Exclude))
        .map(|(id, _)| *id)
        .collect();
    if !excluded.is_empty() {
        exclude_instances(ical, &excluded)?;
        changed = true;
    }
    Ok(changed)
}

fn update_override(
    ical: &mut ICalendar,
    change: &EventChange<'_>,
    id: RecurrenceId,
    exception: &CalendarException<'_>,
    inherit: &Inherit,
) -> Result<bool, ConvertError> {
    let calendar;
    let description = exception.body.as_ref().and_then(|body| body.description());
    let occurrence;
    let plan = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let index = series.find_override(id).ok_or(ConvertError::Unsupported)?;
        let component = series.component(index).ok_or(ConvertError::Unsupported)?;
        let span = series.span(component).ok_or(ConvertError::Unsupported)?;
        let current = component_calendar(&series, index, component, &span, change.version);
        let location = match (&exception.location, &exception.location_details) {
            (None, None) => inherit.location(current.location.as_deref()),
            (location, _) => location.clone(),
        };
        calendar = Calendar {
            timezone: change.calendar.timezone.clone(),
            subject: exception
                .subject
                .clone()
                .or_else(|| inherit.subject(current.subject.as_deref())),
            start_time: exception.start_time,
            end_time: exception.end_time,
            location,
            location_details: exception.location_details.clone(),
            categories: exception
                .categories
                .clone()
                .or_else(|| inherit.categories(current.categories.as_ref())),
            sensitivity: exception
                .sensitivity
                .or_else(|| inherit.sensitivity(current.sensitivity)),
            busy_status: exception.busy_status,
            all_day_event: exception.all_day_event,
            reminder: exception.reminder,
            attendees: exception_attendees(exception).cloned(),
            organizer_email: change.calendar.organizer_email.clone(),
            organizer_name: change.calendar.organizer_name.clone(),
            ..Default::default()
        };
        occurrence = EventChange {
            calendar: &calendar,
            description: description.as_deref(),
            owner: change.owner,
            version: change.version,
            ghosting: Ghosting::Except(&[]),
            now: change.now,
        };
        let stored = first_text(component, &ICalendarProperty::Description);
        let mut plan = Plan::fields(ical, &occurrence, &current, stored)?;
        plan.attendees = attendee_edit(ical, &occurrence, Target::Occurrence(id))?;
        plan
    };
    if plan.is_empty() {
        return Ok(false);
    }
    plan.apply(ical, Target::Occurrence(id), &occurrence)
}

fn follow_master(
    ical: &mut ICalendar,
    description: Option<&Edit<String>>,
    alarm: Option<Option<u32>>,
    categories: Option<&[String]>,
) -> Result<(), ConvertError> {
    if description.is_none() && alarm.is_none() && categories.is_none() {
        return Ok(());
    }
    let followers: SmallVec<[(RecurrenceId, bool, bool, bool); 4]> = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let main = series
            .component(series.main)
            .ok_or(ConvertError::Unsupported)?;
        let text = first_text(main, &ICalendarProperty::Description);
        let minutes = series
            .span(main)
            .and_then(|span| component_reminder(&series, series.main, &span));
        series
            .overrides()
            .filter_map(|(index, component, id)| {
                let body = description.is_some()
                    && first_text(component, &ICalendarProperty::Description) == text;
                let reminder = alarm.is_some()
                    && series
                        .span(component)
                        .is_some_and(|span| component_reminder(&series, index, &span) == minutes);
                let tags = categories.is_some()
                    && same_properties(component, main, &ICalendarProperty::Categories);
                (body || reminder || tags).then_some((id, body, reminder, tags))
            })
            .collect()
    };
    for (id, body, reminder, tags) in followers {
        let mut index = Target::Occurrence(id).index(ical)?;
        if let Some(minutes) = alarm.filter(|_| reminder) {
            index = remove_display_alarms(ical, index)?;
            if let Some(minutes) = minutes {
                add_alarm(ical, index, minutes)?;
            }
        }
        let component = ical
            .components
            .get_mut(index)
            .ok_or(ConvertError::Unsupported)?;
        if let Some(edit) = description.filter(|_| body) {
            match edit {
                Edit::Set(text) => set_text(component, ICalendarProperty::Description, text),
                Edit::Remove => remove_all(component, &ICalendarProperty::Description),
            }
        }
        if let Some(categories) = categories.filter(|_| tags) {
            set_categories(component, categories.iter().cloned());
        }
    }
    Ok(())
}

fn exclude_instances(ical: &mut ICalendar, ids: &[RecurrenceId]) -> Result<(), ConvertError> {
    let (master, entries, overridden) = {
        let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
        let master = series.master.ok_or(ConvertError::Unsupported)?;
        let start = series
            .component(master)
            .and_then(|component| component.property(&ICalendarProperty::Dtstart))
            .ok_or(ConvertError::Unsupported)?;
        let all_day = time_form(start) == Some(TimeForm::Date);
        let form = TimeTarget::of_start(&series, start);
        let entries: SmallVec<[ICalendarEntry; 4]> = ids
            .iter()
            .map(|id| form.entry(ICalendarProperty::Exdate, id.0, all_day))
            .collect();
        let overridden: SmallVec<[usize; 4]> = series
            .overrides()
            .filter(|(_, _, id)| ids.binary_search(id).is_ok())
            .map(|(index, _, _)| index)
            .collect();
        (master, entries, overridden)
    };
    ical.components
        .get_mut(master)
        .ok_or(ConvertError::Unsupported)?
        .entries
        .extend(entries);
    remove_components(ical, &overridden);
    Ok(())
}

fn all_day(given: &Calendar<'_>, current: &Calendar<'_>) -> bool {
    given
        .all_day_event
        .map_or(current.all_day_event == Some(ALL_DAY), |flag| {
            flag == ALL_DAY
        })
}

fn change_zone(
    ical: &ICalendar,
    given: &Calendar<'_>,
    all_day: bool,
    version: ProtocolVersion,
) -> Result<Zone, ConvertError> {
    if all_day && version >= ProtocolVersion::V160 {
        Ok(Zone::Named(TimeTarget {
            tz: Tz::UTC,
            tzid: None,
        }))
    } else {
        match Zone::decode(given.timezone.as_ref()) {
            Zone::Unstated => stored_zone(ical).map(|zone| match zone {
                Zone::Named(TimeTarget { tzid: None, .. }) if all_day => Zone::Unstated,
                zone => zone,
            }),
            zone @ Zone::Rules(_) => Ok(match stored_zone(ical) {
                Ok(stored @ Zone::Named(TimeTarget { tzid: Some(_), .. })) => stored,
                _ => zone,
            }),
            zone => Ok(zone),
        }
    }
}

fn times(
    ical: &ICalendar,
    given: &Calendar<'_>,
    current: &Calendar<'_>,
    version: ProtocolVersion,
) -> Result<Option<Times>, ConvertError> {
    let current_start = current.start_time.map(|time| instant(time.0)).transpose()?;
    let current_end = current.end_time.map(|time| instant(time.0)).transpose()?;
    let (start, end) = match (given.start_time, given.end_time) {
        (Some(start), Some(end)) => (instant(start.0)?, instant(end.0)?),
        (Some(start), None) => {
            let start = instant(start.0)?;
            let end = match (current_start, current_end) {
                (Some(current_start), Some(current_end)) => start
                    .checked_add(current_end.duration_since(current_start))
                    .map_err(|_| ConvertError::Unsupported)?,
                _ => start,
            };
            (start, end)
        }
        (None, Some(end)) => (
            current_start.ok_or(ConvertError::Unsupported)?,
            instant(end.0)?,
        ),
        (None, None) => match (given.all_day_event, current_start, current_end) {
            (Some(_), Some(start), Some(end)) => (start, end),
            _ => return Ok(None),
        },
    };
    let all_day = all_day(given, current);
    let zone = change_zone(ical, given, all_day, version)?;
    let (start, end) = if all_day {
        (zone.day(start)?, zone.day(end)?)
    } else {
        (start, end)
    };
    if Some(start) == current_start
        && Some(end) == current_end
        && Some(u8::from(all_day)) == current.all_day_event
    {
        return Ok(None);
    }
    let end = if all_day {
        end.max(
            start
                .checked_add(ONE_DAY)
                .map_err(|_| ConvertError::Unsupported)?,
        )
    } else {
        end.max(start)
    };
    Ok(Some(Times {
        start: zone.time_entry(ICalendarProperty::Dtstart, start, all_day)?,
        end: zone.time_entry(ICalendarProperty::Dtend, end, all_day)?,
        start_at: start,
        end_at: end,
    }))
}

fn stored_zone(ical: &ICalendar) -> Result<Zone, ConvertError> {
    let series = Series::new(ical).ok_or(ConvertError::Unsupported)?;
    let entry = series
        .component(series.main)
        .and_then(|component| component.property(&ICalendarProperty::Dtstart))
        .ok_or(ConvertError::Unsupported)?;
    Ok(Zone::Named(TimeTarget {
        tz: series.tz,
        tzid: (time_form(entry) == Some(TimeForm::Zoned))
            .then(|| entry.tz_id().map(str::to_string))
            .flatten(),
    }))
}

impl Inherit {
    fn of(plan: &Plan<'_>, change: &EventChange<'_>, current: &Calendar<'_>) -> Self {
        let text = |edit: &Edit<String>, before: Option<&str>| Inherited {
            before: before.map(str::to_string),
            after: match edit {
                Edit::Set(text) => Some(text.clone()),
                Edit::Remove => None,
            },
        };
        Inherit {
            subject: plan
                .summary
                .as_ref()
                .map(|edit| text(edit, current.subject.as_deref())),
            location: plan
                .location
                .as_ref()
                .map(|edit| text(edit, current.location.as_deref())),
            sensitivity: plan
                .class
                .as_ref()
                .and(sensitivity_level(change))
                .map(|after| Inherited {
                    before: current.sensitivity.unwrap_or(NORMAL_SENSITIVITY),
                    after,
                }),
            categories: plan.categories.as_ref().map(|after| Inherited {
                before: current.categories.as_ref().map_or_else(Vec::new, |list| {
                    list.0.iter().map(|category| category.to_string()).collect()
                }),
                after: after.clone(),
            }),
        }
    }

    fn subject(&self, current: Option<&str>) -> Option<Cow<'_, str>> {
        follow_text(self.subject.as_ref(), current)
    }

    fn location(&self, current: Option<&str>) -> Option<Cow<'_, str>> {
        follow_text(self.location.as_ref(), current)
    }

    fn sensitivity(&self, current: Option<u8>) -> Option<u8> {
        self.sensitivity
            .as_ref()
            .filter(|inherited| inherited.before == current.unwrap_or(NORMAL_SENSITIVITY))
            .map(|inherited| inherited.after)
    }

    fn categories(&self, current: Option<&Categories<'_>>) -> Option<Categories<'_>> {
        let current = current.map_or(&[][..], |list| list.0.as_slice());
        self.categories
            .as_ref()
            .filter(|inherited| {
                inherited
                    .before
                    .iter()
                    .map(String::as_str)
                    .eq(current.iter().map(|category| &**category))
            })
            .map(|inherited| {
                List(
                    inherited
                        .after
                        .iter()
                        .map(|category| Cow::Borrowed(category.as_str()))
                        .collect(),
                )
            })
    }
}

fn follow_text<'i>(
    inherited: Option<&'i Inherited<Option<String>>>,
    current: Option<&str>,
) -> Option<Cow<'i, str>> {
    inherited
        .filter(|inherited| inherited.before.as_deref() == current)
        .map(|inherited| Cow::Borrowed(inherited.after.as_deref().unwrap_or_default()))
}

fn sensitivity_level(change: &EventChange<'_>) -> Option<u8> {
    change
        .calendar
        .sensitivity
        .or_else(|| (!change.ghosting().ghosts(cal::SENSITIVITY)).then_some(NORMAL_SENSITIVITY))
}

fn text_edit(given: Option<&str>, current: Option<&str>, ghosted: bool) -> Option<Edit<String>> {
    match (given, current) {
        (Some(text), _) => match non_empty(Some(text)) {
            Some(text) if Some(text) != current => Some(Edit::Set(text.to_string())),
            Some(_) => None,
            None => current.map(|_| Edit::Remove),
        },
        (None, Some(_)) if !ghosted => Some(Edit::Remove),
        (None, _) => None,
    }
}

fn set_categories(
    component: &mut ICalendarComponent,
    categories: impl IntoIterator<Item = String>,
) {
    remove_all(component, &ICalendarProperty::Categories);
    let values: SmallVec<[ICalendarValue; 1]> =
        categories.into_iter().map(ICalendarValue::Text).collect();
    if !values.is_empty() {
        component.entries.push(ICalendarEntry {
            name: ICalendarProperty::Categories,
            params: Vec::new(),
            values,
        });
    }
}

fn event_attendees(ical: &ICalendar) -> impl Iterator<Item = &ICalendarEntry> {
    ical.components
        .iter()
        .filter(|component| component.component_type == ICalendarComponentType::VEvent)
        .flat_map(|component| component.properties(&ICalendarProperty::Attendee))
}

fn rsvp_stale(entry: &ICalendarEntry, owner: &[String], requested: bool) -> bool {
    let has_rsvp = entry.params.iter().any(|param| {
        param.name == ICalendarParameterName::Rsvp
            && matches!(param.value, ICalendarParameterValue::Bool(true))
    });
    has_rsvp != requested
        && entry_address(entry)
            .is_some_and(|address| !owner.iter().any(|own| own.eq_ignore_ascii_case(address)))
}

fn set_rsvp(ical: &mut ICalendar, owner: &[String], requested: bool) {
    for entry in ical
        .components
        .iter_mut()
        .filter(|component| component.component_type == ICalendarComponentType::VEvent)
        .flat_map(|component| component.entries.iter_mut())
        .filter(|entry| entry.name == ICalendarProperty::Attendee)
        .filter(|entry| rsvp_stale(entry, owner, requested))
    {
        entry
            .params
            .retain(|param| param.name != ICalendarParameterName::Rsvp);
        if requested {
            entry.params.push(ICalendarParameter::rsvp(true));
        }
    }
}

fn remove_all(component: &mut ICalendarComponent, name: &ICalendarProperty) {
    component.entries.retain(|entry| &entry.name != name);
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../../stalwart-tests/unit/exchange-proto/src/convert/ical/eas/event/change/tests.rs"]
mod tests;
