/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarMethod,
        ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarRelated, ICalendarStatus,
        ICalendarTransparency, ICalendarUserTypes, ICalendarValue, utils::strip_mailto_scheme,
    },
};
use jiff::{SignedDuration, Timestamp, civil::DateTime, tz::TimeZone};

use super::{
    EventParts, RecurrenceId,
    alarm::{AlarmState, SIGNAL_NEVER, current_state, is_reminder, occurrence_state},
    method_class,
    props::*,
    series::{Series, Span},
    signal::series_signal,
};
use crate::{
    common::time::{FILETIME_TICKS_PER_MINUTE, FileTime, UtcSeconds},
    convert::{
        BlobLimits, ConvertError,
        address::{Address, SENDER, SENT_REPRESENTING, SmtpRecipient, set_address, smtp_recipient},
        blob::{
            AppointmentRecur, ExceptionInfo, GlobalObjectId, RecurAnchor, RecurFrequency,
            TzDefinition, TzStruct, iana_to_windows, local_from_minutes, local_minutes,
            recur::NO_END_DATE,
        },
        context::AddressResolver,
        model::{AttachData, Attachment, MessageContent, PropBag},
        tags::{self, KEYWORDS_NAME, RECIPIENT_FLAG_SENDABLE, attach_method, recipient_type},
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey, sets::PS_PUBLIC_STRINGS},
};

const SMTP: &str = "SMTP";
const SECONDS_PER_MINUTE: i64 = 60;
const MINUTES_PER_DAY: u32 = 1440;
const CLIP_END_NEVER: FileTime = FileTime(0x0CB2_E579_49B4_7A00);

#[derive(Clone, Copy)]
enum View {
    Master,
    Instance { id: RecurrenceId },
    Exception { id: RecurrenceId },
}

struct Fields<'c> {
    subject: Option<&'c str>,
    body: Option<&'c str>,
    location: Option<&'c str>,
    busy: i32,
    reminder: Option<u32>,
    all_day: bool,
}

struct Writer<'s, 'c> {
    series: &'s Series<'c>,
    parts: EventParts,
    resolver: &'s dyn AddressResolver,
    method: Option<&'c ICalendarMethod>,
    class: &'static str,
}

#[derive(Clone, Copy)]
struct PlannedException<'c> {
    index: usize,
    component: &'c ICalendarComponent,
    id: RecurrenceId,
    span: Span,
    start: u32,
    end: u32,
    original: u32,
}

struct RecurPlan<'c> {
    recur: AppointmentRecur,
    deleted: Vec<u32>,
    exceptions: Vec<PlannedException<'c>>,
}

pub(super) fn event(
    series: &Series<'_>,
    instance: Option<RecurrenceId>,
    parts: EventParts,
    resolver: &dyn AddressResolver,
) -> Result<MessageContent, ConvertError> {
    let method = series
        .ical
        .components
        .first()
        .filter(|root| root.component_type == ICalendarComponentType::VCalendar)
        .and_then(|root| root.property(&ICalendarProperty::Method))
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::Method(method) => Some(method),
            _ => None,
        });
    let main = series
        .component(series.main)
        .ok_or(ConvertError::Unsupported)?;
    let class = method_class(method, partstat(main)).unwrap_or(CLASS_APPOINTMENT);
    let writer = Writer {
        series,
        parts,
        resolver,
        method,
        class,
    };
    match instance {
        None => {
            let span = series.span(main).ok_or(ConvertError::Unsupported)?;
            Ok(writer.message(series.main, span, View::Master))
        }
        Some(id) => {
            let (index, span) = instance_span(series, id).ok_or(ConvertError::Unsupported)?;
            Ok(writer.message(index, span, View::Instance { id }))
        }
    }
}

pub(super) fn instance_span(series: &Series<'_>, id: RecurrenceId) -> Option<(usize, Span)> {
    if let Some(index) = series.find_override(id) {
        if series.excluded(id) {
            return None;
        }
        return Some((index, series.span(series.component(index)?)?));
    }
    if !series.is_instance(id) {
        return None;
    }
    let index = series.master?;
    let span = series.span(series.component(index)?)?;
    let start = series.at(id.0);
    let end = start.checked_add(span.duration())?;
    Some((
        index,
        Span {
            start,
            end,
            all_day: span.all_day,
        },
    ))
}

impl<'c> Writer<'_, 'c> {
    fn message(&self, index: usize, span: Span, view: View) -> MessageContent {
        let mut content = MessageContent::default();
        let Some(component) = self.series.component(index) else {
            return content;
        };
        let fields = self.fields(index, component, &span);
        let bag = &mut content.props;
        match view {
            View::Exception { .. } => text(bag, tags::MESSAGE_CLASS, CLASS_EXCEPTION),
            View::Master | View::Instance { .. } => text(bag, tags::MESSAGE_CLASS, self.class),
        }
        self.fields_into(bag, &fields, view);
        self.times(bag, &span, &fields);
        if !matches!(view, View::Exception { .. }) {
            self.classification(bag, component);
            self.identity(bag, component, view);
            self.meeting(bag, component);
        }
        let recurring = match view {
            View::Master => {
                let recurring = if self.parts.has(EventParts::RECURRENCE) {
                    self.recurrence(&mut content, component, &span, &fields)
                } else {
                    self.plan(component, &span).is_some()
                };
                set_bool(&mut content.props, RECURRING, recurring);
                set_bool(&mut content.props, IS_RECURRING, recurring);
                recurring
            }
            View::Instance { id } | View::Exception { id } => {
                let bag = &mut content.props;
                set_time(bag, EXCEPTION_REPLACE.key(), id.0);
                set_bool(bag, RECURRING, false);
                set_bool(bag, IS_EXCEPTION, self.series.master.is_some());
                false
            }
        };
        if !recurring {
            let state = match view {
                View::Master => current_state(self.series, index, &span),
                View::Instance { .. } => occurrence_state(self.series, index, &span),
                View::Exception { .. } => None,
            };
            reminder_state(&mut content.props, state);
        } else if let Some(signal) = series_signal(self.series) {
            set_file_time(
                &mut content.props,
                REMINDER_SIGNAL_TIME.key(),
                signal.file_time(),
            );
        }
        if !recurring {
            let bag = &mut content.props;
            set_time(bag, CLIP_START.key(), span.start.to_timestamp());
            set_time(bag, CLIP_END.key(), span.end.to_timestamp());
        }
        if self.parts.has(EventParts::RECIPIENTS) {
            self.recipients(&mut content, component);
        }
        content
    }

    fn fields(&self, index: usize, component: &'c ICalendarComponent, span: &Span) -> Fields<'c> {
        Fields {
            subject: first_text(component, &ICalendarProperty::Summary),
            body: first_text(component, &ICalendarProperty::Description),
            location: first_text(component, &ICalendarProperty::Location),
            busy: if self.parts.has(EventParts::NO_DATA) {
                busy_status(component)
            } else {
                ranged_busy_status(component)
            },
            reminder: reminder(self.series, index, span),
            all_day: span.all_day,
        }
    }

    fn fields_into(&self, bag: &mut PropBag, fields: &Fields<'_>, view: View) {
        if let Some(subject) = fields.subject {
            let subject = truncate_chars(subject, MAX_SUBJECT_CHARS);
            text(bag, tags::SUBJECT, subject);
            text(bag, tags::NORMALIZED_SUBJECT, subject);
        }
        if let Some(body) = fields.body.filter(|_| self.parts.has(EventParts::BODY)) {
            text(bag, tags::BODY, body);
        }
        if let View::Exception { .. } = view {
            set_bool(bag, F_EXCEPTIONAL_BODY, fields.body.is_some());
        }
        if let Some(location) = fields.location {
            bag.set(LOCATION.key(), OwnedPropValue::Unicode(location.into()));
            if self.class != CLASS_APPOINTMENT {
                bag.set(WHERE.key(), OwnedPropValue::Unicode(location.into()));
            }
        }
        bag.set(BUSY_STATUS.key(), OwnedPropValue::I32(fields.busy));
        set_bool(bag, SUB_TYPE, fields.all_day);
    }

    fn times(&self, bag: &mut PropBag, span: &Span, fields: &Fields<'_>) {
        let start = span.start.to_timestamp();
        let end = span.end.to_timestamp();
        for key in [
            START_WHOLE.key(),
            COMMON_START.key(),
            PropKey::tag(tags::START_DATE),
        ] {
            set_time(bag, key, start);
        }
        for key in [
            END_WHOLE.key(),
            COMMON_END.key(),
            PropKey::tag(tags::END_DATE),
        ] {
            set_time(bag, key, end);
        }
        let minutes = span.duration().as_secs() / SECONDS_PER_MINUTE;
        bag.set(
            DURATION.key(),
            OwnedPropValue::I32(i32::try_from(minutes).unwrap_or(i32::MAX)),
        );
        if self.parts.has(EventParts::TIME_ZONES) {
            let year = span.start.naive_local().year();
            set_tzdef(
                bag,
                TZDEF_START,
                &tz_definition(span.start.timezone(), year..=year),
            );
            let end_year = span.end.naive_local().year();
            set_tzdef(
                bag,
                TZDEF_END,
                &tz_definition(span.end.timezone(), end_year..=end_year),
            );
        }
        match fields.reminder {
            Some(delta) => {
                set_bool(bag, REMINDER_SET, true);
                bag.set(
                    REMINDER_DELTA.key(),
                    OwnedPropValue::I32(i32::try_from(delta).unwrap_or(i32::MAX)),
                );
                set_time(bag, REMINDER_TIME.key(), start);
                let signal = start
                    .checked_sub(SignedDuration::from_mins(i64::from(delta)))
                    .unwrap_or(start);
                set_time(bag, REMINDER_SIGNAL_TIME.key(), signal);
            }
            None => set_bool(bag, REMINDER_SET, false),
        }
    }

    fn classification(&self, bag: &mut PropBag, component: &ICalendarComponent) {
        if let Some(sensitivity) = component
            .property(&ICalendarProperty::Class)
            .and_then(|entry| entry.values.first())
            .map(sensitivity)
        {
            bag.set(
                PropKey::tag(tags::SENSITIVITY),
                OwnedPropValue::I32(sensitivity),
            );
        }
        if let Some(importance) = importance(component) {
            bag.set(
                PropKey::tag(tags::IMPORTANCE),
                OwnedPropValue::I32(importance),
            );
        }
        let keywords = keywords(component);
        if !keywords.is_empty() {
            bag.set(
                PropKey::name(PS_PUBLIC_STRINGS, KEYWORDS_NAME),
                OwnedPropValue::MvUnicode(keywords.into_boxed_slice()),
            );
        }
        if let Some(sequence) = other_text(component, CDO_SEQUENCE_NAME)
            .and_then(|value| value.trim().parse::<i32>().ok())
            .or_else(|| {
                component
                    .property(&ICalendarProperty::Sequence)
                    .and_then(|entry| entry.values.first())
                    .and_then(ICalendarValue::as_integer)
                    .and_then(|value| i32::try_from(value).ok())
            })
        {
            bag.set(SEQUENCE.key(), OwnedPropValue::I32(sequence));
        }
        if let Some(stamp) = component
            .property(&ICalendarProperty::Dtstamp)
            .and_then(|entry| self.series.resolve_first(entry))
        {
            let lid = match self.method {
                Some(ICalendarMethod::Reply | ICalendarMethod::Counter) => ATTENDEE_CRITICAL_CHANGE,
                _ => OWNER_CRITICAL_CHANGE,
            };
            set_time(bag, lid.key(), stamp.to_timestamp());
        }
        if self.method == Some(&ICalendarMethod::Counter) {
            set_bool(bag, COUNTER_PROPOSAL, true);
        }
    }

    fn identity(&self, bag: &mut PropBag, component: &ICalendarComponent, view: View) {
        let Some(uid) = self.series.uid() else {
            return;
        };
        let mut goid = GlobalObjectId::from_uid(uid);
        let clean = goid.clean();
        if let View::Instance { id } = view
            && goid.instance_date.is_none()
        {
            let local = component
                .property(&ICalendarProperty::RecurrenceId)
                .and_then(|entry| self.series.resolve_first(entry))
                .unwrap_or_else(|| self.series.at(id.0))
                .naive_local();
            goid.instance_date = u16::try_from(local.year())
                .ok()
                .zip(u8::try_from(local.month()).ok())
                .zip(u8::try_from(local.day()).ok())
                .map(|((year, month), day)| (year, month, day));
        }
        for (lid, value) in [(GLOBAL_OBJECT_ID, &goid), (CLEAN_GLOBAL_OBJECT_ID, &clean)] {
            let mut out = Vec::with_capacity(value.encoded_len());
            value.encode(&mut out);
            bag.set(lid.key(), OwnedPropValue::Binary(out.into()));
        }
        let meeting = component.has_property(&ICalendarProperty::Attendee);
        let mut flags = 0;
        if meeting {
            flags |= state_flags::MEETING;
        }
        if self.method == Some(&ICalendarMethod::Cancel)
            || component.status() == Some(&ICalendarStatus::Cancelled)
        {
            flags |= state_flags::CANCELED;
        }
        if matches!(self.class, CLASS_REQUEST | CLASS_CANCELED) {
            flags |= state_flags::RECEIVED;
        }
        bag.set(STATE_FLAGS.key(), OwnedPropValue::I32(flags));
        let main = self.series.component(self.series.main).unwrap_or(component);
        let scheduled = self
            .method
            .is_some_and(|method| *method != ICalendarMethod::Publish);
        set_bool(bag, F_INVITED, meeting && (scheduled || !is_draft(main)));
        if let Some(last) =
            other_text(main, LAST_SEQUENCE_NAME).and_then(|value| value.trim().parse::<i32>().ok())
        {
            bag.set(LAST_SEQUENCE.key(), OwnedPropValue::I32(last));
        }
        if let Some(kind) = other_text(main, CONFERENCING_TYPE_NAME)
            .and_then(|value| value.trim().parse::<i32>().ok())
        {
            bag.set(CONFERENCING_TYPE.key(), OwnedPropValue::I32(kind));
        }
        if let Some(time) = other_text(main, SEQUENCE_TIME_NAME).and_then(|value| {
            DateTime::strptime(SEQUENCE_TIME_FORMAT, value.trim())
                .ok()?
                .to_zoned_datetime(TimeZone::UTC)
                .ok()
        }) {
            set_time(bag, SEQUENCE_TIME.key(), time.timestamp());
        }
    }

    fn meeting(&self, bag: &mut PropBag, component: &ICalendarComponent) {
        let (busy, intended, kind) = match self.class {
            CLASS_REQUEST => {
                let sequence = bag.get_any(SEQUENCE.prop());
                let kind = match sequence {
                    None | Some(OwnedPropValue::I32(0)) => meeting_type::REQUEST,
                    Some(_) => meeting_type::FULL,
                };
                (busy::TENTATIVE, intended_status(component), kind)
            }
            CLASS_CANCELED => (busy::FREE, busy::FREE, meeting_type::EMPTY),
            _ => return,
        };
        bag.set(BUSY_STATUS.key(), OwnedPropValue::I32(busy));
        bag.set(INTENDED_BUSY_STATUS.key(), OwnedPropValue::I32(intended));
        bag.set(MEETING_TYPE.key(), OwnedPropValue::I32(kind));
        bag.set(
            RESPONSE_STATUS.key(),
            OwnedPropValue::I32(track_status::NOT_RESPONDED),
        );
        bag.set(
            APPOINTMENT_MESSAGE_CLASS.key(),
            OwnedPropValue::Unicode(CLASS_APPOINTMENT.into()),
        );
    }

    fn plan(&self, master: &ICalendarComponent, span: &Span) -> Option<RecurPlan<'c>> {
        let recur = appointment_recur(self.series, master, span)?;
        let series = self.series;
        let first = recur.pattern.start_date;
        let mut deleted: Vec<u32> = series
            .exdates()
            .filter_map(|zoned| midnight(series.local(zoned.to_timestamp())))
            .filter(|day| *day >= first)
            .collect();
        let max = usize::from(BlobLimits::DEFAULT.max_exceptions);
        if deleted.len() > max {
            return None;
        }
        let mut exceptions = Vec::new();
        let mut instances: Vec<RecurrenceId> = series.overrides().map(|(_, _, id)| id).collect();
        series.retain_instances(&mut instances);
        for (index, component, id) in series.overrides() {
            if instances.binary_search(&id).is_err() {
                continue;
            }
            if exceptions.len() >= max {
                return None;
            }
            let Some(span) = series.span(component) else {
                continue;
            };
            let Some(original) =
                local_minutes(series.local(id.0)).filter(|minutes| *minutes >= first)
            else {
                continue;
            };
            let Some(start) = local_minutes(series.local(span.start.to_timestamp())) else {
                continue;
            };
            let Some(end) = local_minutes(series.local(span.end.to_timestamp())) else {
                continue;
            };
            exceptions.push(PlannedException {
                index,
                component,
                id,
                span,
                start,
                end,
                original,
            });
        }
        deleted.extend(
            exceptions
                .iter()
                .map(|exception| exception.original - exception.original % MINUTES_PER_DAY),
        );
        deleted.sort_unstable();
        deleted.dedup();
        (deleted.len() <= max).then_some(RecurPlan {
            recur,
            deleted,
            exceptions,
        })
    }

    fn recurrence(
        &self,
        content: &mut MessageContent,
        master: &ICalendarComponent,
        span: &Span,
        fields: &Fields<'_>,
    ) -> bool {
        let Some(RecurPlan {
            mut recur,
            deleted,
            exceptions: planned,
        }) = self.plan(master, span)
        else {
            return false;
        };
        let series = self.series;
        let mut exceptions: Vec<(ExceptionInfo, Attachment)> = planned
            .iter()
            .map(|exception| self.exception(exception, fields))
            .collect();
        exceptions.sort_unstable_by_key(|(info, _)| info.start);
        recur.pattern.deleted_instances = deleted;
        recur.pattern.modified_instances = exceptions
            .iter()
            .map(|(info, _)| info.start - info.start % MINUTES_PER_DAY)
            .collect();
        let (infos, attachments): (Vec<_>, Vec<_>) = exceptions.into_iter().unzip();
        recur.exceptions = infos;
        content.attachments.extend(attachments);
        let bag = &mut content.props;
        let mut blob = Vec::new();
        recur.encode(&mut blob);
        bag.set(RECUR.key(), OwnedPropValue::Binary(blob.into()));
        let recurrence_type = match recur.pattern.frequency {
            RecurFrequency::Daily => 1,
            RecurFrequency::Weekly => 2,
            RecurFrequency::Monthly => 3,
            RecurFrequency::Yearly => 4,
        };
        bag.set(RECURRENCE_TYPE.key(), OwnedPropValue::I32(recurrence_type));
        let clip = |minutes: u32| match minutes {
            NO_END_DATE.. => CLIP_END_NEVER,
            _ => local_from_minutes(minutes)
                .and_then(|local| series.tz.from_local(local))
                .map_or_else(
                    || minutes_file_time(minutes),
                    |zoned| file_time(zoned.to_timestamp()),
                ),
        };
        set_file_time(bag, CLIP_START.key(), clip(recur.pattern.start_date));
        set_file_time(bag, CLIP_END.key(), clip(recur.pattern.end_date));
        let year = span.start.naive_local().year();
        let end_year = local_from_minutes(recur.pattern.end_date)
            .map(|end| end.year())
            .filter(|end| *end >= year)
            .map_or(year, |end| end.min(year.saturating_add(TZ_RECUR_YEARS)));
        let definition = tz_definition(series.tz, year..=end_year);
        if let Some(rule) = definition.effective() {
            let mut out = Vec::new();
            TzStruct::from_rule(rule).encode(&mut out);
            bag.set(TZ_STRUCT.key(), OwnedPropValue::Binary(out.into()));
        }
        bag.set(
            TZ_DESCRIPTION.key(),
            OwnedPropValue::Unicode(definition.key_name.clone()),
        );
        set_tzdef(bag, TZDEF_RECUR, &definition);
        true
    }

    fn exception(
        &self,
        planned: &PlannedException<'c>,
        master: &Fields<'_>,
    ) -> (ExceptionInfo, Attachment) {
        let PlannedException {
            index,
            component,
            id,
            span,
            start,
            end,
            original,
        } = *planned;
        let fields = self.fields(index, component, &span);
        let mut info = ExceptionInfo {
            start,
            end,
            original_start: original,
            ..ExceptionInfo::default()
        };
        if fields.subject != master.subject {
            info.subject = Some(fields.subject.unwrap_or_default().into());
        }
        if fields.location != master.location {
            info.location = Some(fields.location.unwrap_or_default().into());
        }
        if fields.busy != master.busy {
            info.busy_status = u32::try_from(fields.busy).ok();
        }
        if fields.reminder != master.reminder {
            info.reminder_set = Some(u32::from(fields.reminder.is_some()));
            if let Some(delta) = fields.reminder {
                info.reminder_delta = Some(delta);
            }
        }
        if fields.all_day != master.all_day {
            info.sub_type = Some(u32::from(fields.all_day));
        }
        info.exceptional_body = fields.body != master.body;
        let embedded = self.message(index, span, View::Exception { id });
        let mut props = PropBag::new();
        props.set(
            PropKey::tag(tags::ATTACH_METHOD),
            OwnedPropValue::I32(attach_method::EMBEDDED_MESSAGE),
        );
        props.set(
            PropKey::tag(tags::ATTACHMENT_HIDDEN),
            OwnedPropValue::Bool(true),
        );
        props.set(
            PropKey::tag(ATTACHMENT_FLAGS),
            OwnedPropValue::I32(ATTACHMENT_FLAG_EXCEPTION),
        );
        props.set(
            PropKey::tag(tags::RENDERING_POSITION),
            OwnedPropValue::I32(RENDERING_POSITION_HIDDEN),
        );
        if let Some(subject) = fields.subject.or(master.subject) {
            text(
                &mut props,
                tags::DISPLAY_NAME,
                truncate_chars(subject, MAX_SUBJECT_CHARS),
            );
        }
        set_file_time(
            &mut props,
            PropKey::tag(EXCEPTION_START_TIME),
            minutes_file_time(start),
        );
        set_file_time(
            &mut props,
            PropKey::tag(EXCEPTION_END_TIME),
            minutes_file_time(end),
        );
        set_time(&mut props, PropKey::tag(EXCEPTION_REPLACE_TIME), id.0);
        (
            info,
            Attachment {
                props,
                data: AttachData::Embedded(Box::new(embedded)),
            },
        )
    }

    fn recipients(&self, content: &mut MessageContent, component: &ICalendarComponent) {
        let mut rsvp = self.class == CLASS_APPOINTMENT;
        if let Some(organizer) = component.property(&ICalendarProperty::Organizer)
            && let Some(smtp) = address(organizer)
        {
            let name = self.display_name(organizer, smtp);
            content.recipients.push(smtp_recipient(SmtpRecipient {
                kind: recipient_type::TO,
                name: &name,
                smtp,
                display_type: 0,
                flags: RECIPIENT_FLAG_SENDABLE | RECIPIENT_FLAG_ORGANIZER,
            }));
            for target in [&SENT_REPRESENTING, &SENDER] {
                set_address(
                    &mut content.props,
                    target,
                    Address {
                        name: name.as_str().into(),
                        address_type: SMTP.into(),
                        email: smtp.into(),
                    },
                );
            }
        }
        for attendee in component.properties(&ICalendarProperty::Attendee) {
            let Some(smtp) = address(attendee) else {
                continue;
            };
            let mut kind = recipient_type::TO;
            let mut status = track_status::NONE;
            for param in &attendee.params {
                match &param.value {
                    ICalendarParameterValue::Role(role) => {
                        kind = match role {
                            ICalendarParticipationRole::OptParticipant => recipient_type::CC,
                            ICalendarParticipationRole::NonParticipant => recipient_type::BCC,
                            _ => recipient_type::TO,
                        }
                    }
                    ICalendarParameterValue::Cutype(
                        ICalendarUserTypes::Resource | ICalendarUserTypes::Room,
                    ) => kind = recipient_type::BCC,
                    ICalendarParameterValue::Partstat(partstat) => {
                        status = match partstat {
                            ICalendarParticipationStatus::Accepted => track_status::ACCEPTED,
                            ICalendarParticipationStatus::Declined => track_status::DECLINED,
                            ICalendarParticipationStatus::Tentative => track_status::TENTATIVE,
                            _ => track_status::NONE,
                        }
                    }
                    ICalendarParameterValue::Bool(true)
                        if param.name == ICalendarParameterName::Rsvp =>
                    {
                        rsvp = true
                    }
                    _ => {}
                }
            }
            let name = self.display_name(attendee, smtp);
            let mut row = smtp_recipient(SmtpRecipient {
                kind,
                name: &name,
                smtp,
                display_type: 0,
                flags: RECIPIENT_FLAG_SENDABLE,
            });
            row.set(
                PropKey::tag(RECIPIENT_TRACK_STATUS),
                OwnedPropValue::I32(status),
            );
            content.recipients.push(row);
        }
        for id in [tags::RESPONSE_REQUESTED, REPLY_REQUESTED] {
            content
                .props
                .set(PropKey::tag(id), OwnedPropValue::Bool(rsvp));
        }
    }

    fn display_name(&self, entry: &ICalendarEntry, smtp: &str) -> String {
        entry
            .parameter(&ICalendarParameterName::Cn)
            .and_then(ICalendarParameterValue::as_text)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .or_else(|| {
                self.resolver
                    .resolve(smtp)
                    .map(|resolved| resolved.display_name.into_owned())
            })
            .unwrap_or_else(|| smtp.to_string())
    }
}

const TZ_RECUR_YEARS: i16 = 10;

pub(super) fn appointment_recur(
    series: &Series<'_>,
    master: &ICalendarComponent,
    span: &Span,
) -> Option<AppointmentRecur> {
    let rule = master
        .property(&ICalendarProperty::Rrule)
        .and_then(|entry| entry.values.first())
        .and_then(|value| match value {
            ICalendarValue::RecurrenceRule(rule) => Some(rule),
            _ => None,
        })?;
    let anchor = RecurAnchor {
        start: span.start.naive_local(),
        duration_minutes: u32::try_from(span.duration().as_secs() / SECONDS_PER_MINUTE)
            .unwrap_or(u32::MAX),
        tz: series.tz,
    };
    AppointmentRecur::from_rrule(rule, anchor).ok()
}

fn reminder_state(bag: &mut PropBag, state: Option<AlarmState>) {
    match state {
        None | Some(AlarmState::Pending) => {}
        Some(AlarmState::Dismissed) => {
            set_bool(bag, REMINDER_SET, false);
            bag.set(
                REMINDER_SIGNAL_TIME.key(),
                OwnedPropValue::Time(SIGNAL_NEVER),
            );
        }
        Some(AlarmState::Snoozed(at)) => set_time(bag, REMINDER_SIGNAL_TIME.key(), at),
    }
}

pub(super) fn reminder(series: &Series<'_>, index: usize, span: &Span) -> Option<u32> {
    let fire = alarm_fire(series, index, span)?;
    let minutes = span.start.to_timestamp().duration_since(fire).as_secs() / SECONDS_PER_MINUTE;
    Some(u32::try_from(minutes.max(0)).unwrap_or(u32::MAX))
}

pub(super) fn alarm_fire(series: &Series<'_>, index: usize, span: &Span) -> Option<Timestamp> {
    Trigger::of(series, index)?.fire(span)
}

#[derive(Clone, Copy)]
pub(super) enum Trigger {
    Start(SignedDuration),
    End(SignedDuration),
    At(Timestamp),
}

impl Trigger {
    pub fn of(series: &Series<'_>, index: usize) -> Option<Self> {
        let alarm = series
            .ical
            .alarms_for_id(u32::try_from(index).ok()?)
            .find(|alarm| is_reminder(alarm))?;
        let trigger = alarm.property(&ICalendarProperty::Trigger)?;
        match trigger.values.first()? {
            ICalendarValue::Duration(duration) => {
                let offset = SignedDuration::from_secs(duration.as_seconds());
                Some(match trigger.parameter(&ICalendarParameterName::Related) {
                    Some(ICalendarParameterValue::Related(ICalendarRelated::End)) => {
                        Trigger::End(offset)
                    }
                    _ => Trigger::Start(offset),
                })
            }
            ICalendarValue::PartialDateTime(_) => {
                Some(Trigger::At(series.resolve_first(trigger)?.to_timestamp()))
            }
            _ => None,
        }
    }

    pub fn fire(self, span: &Span) -> Option<Timestamp> {
        let (base, offset) = match self {
            Trigger::Start(offset) => (span.start, offset),
            Trigger::End(offset) => (span.end, offset),
            Trigger::At(at) => return Some(at),
        };
        base.to_timestamp().checked_add(offset).ok()
    }
}

pub(super) fn partstat(component: &ICalendarComponent) -> Option<&ICalendarParticipationStatus> {
    component
        .properties(&ICalendarProperty::Attendee)
        .find_map(
            |entry| match entry.parameter(&ICalendarParameterName::Partstat) {
                Some(ICalendarParameterValue::Partstat(partstat)) => Some(partstat),
                _ => None,
            },
        )
}

pub(super) fn address(entry: &ICalendarEntry) -> Option<&str> {
    let value = match entry.values.first()? {
        ICalendarValue::Uri(uri) => uri.as_str(),
        value => value.as_text(),
    }?;
    let smtp = strip_mailto_scheme(value);
    (smtp.contains('@') && !smtp.eq_ignore_ascii_case("invalid:nomail")).then_some(smtp)
}

pub(super) fn first_text<'c>(
    component: &'c ICalendarComponent,
    property: &ICalendarProperty,
) -> Option<&'c str> {
    component
        .property(property)
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_text)
        .filter(|value| !value.is_empty())
}

pub(super) fn other_text<'c>(component: &'c ICalendarComponent, name: &str) -> Option<&'c str> {
    component
        .entries
        .iter()
        .find(|entry| matches!(&entry.name, ICalendarProperty::Other(other) if other.eq_ignore_ascii_case(name)))
        .and_then(|entry| entry.values.first())
        .and_then(ICalendarValue::as_text)
}

pub(super) fn disallows_counter(component: &ICalendarComponent) -> bool {
    other_text(component, DISALLOW_COUNTER_NAME)
        .is_some_and(|value| value.eq_ignore_ascii_case(DISALLOW_COUNTER_TRUE))
}

fn is_draft(component: &ICalendarComponent) -> bool {
    other_text(component, DRAFT_NAME).is_some_and(|value| value.eq_ignore_ascii_case(DRAFT_TRUE))
}

pub(super) fn intended_status(component: &ICalendarComponent) -> i32 {
    match named_status(component, INTENDED_STATUS_NAME) {
        Some(busy::NO_DATA) => busy::BUSY,
        Some(status) => status,
        None => ranged_busy_status(component),
    }
}

fn named_status(component: &ICalendarComponent, name: &str) -> Option<i32> {
    other_text(component, name).and_then(|value| {
        hashify::map_ignore_case!(value.trim().as_bytes(), i32,
            "FREE" => busy::FREE,
            "TENTATIVE" => busy::TENTATIVE,
            "BUSY" => busy::BUSY,
            "OOF" => busy::OOF,
            "WORKINGELSEWHERE" => busy::WORKING_ELSEWHERE,
            "NODATA" => busy::NO_DATA,
        )
        .copied()
    })
}

pub(super) fn busy_status(component: &ICalendarComponent) -> i32 {
    if let Some(status) = named_status(component, BUSY_STATUS_NAME) {
        return status;
    }
    match component.transparency() {
        Some(ICalendarTransparency::Transparent) => return busy::FREE,
        Some(ICalendarTransparency::Opaque) => return busy::BUSY,
        None => {}
    }
    match component.status() {
        Some(ICalendarStatus::Cancelled) => busy::FREE,
        Some(ICalendarStatus::Tentative) => busy::TENTATIVE,
        _ => busy::BUSY,
    }
}

pub(super) fn ranged_busy_status(component: &ICalendarComponent) -> i32 {
    match busy_status(component) {
        busy::NO_DATA => busy::BUSY,
        status => status,
    }
}

pub(super) fn sensitivity(value: &ICalendarValue) -> i32 {
    use calcard::icalendar::ICalendarClassification;
    match value {
        ICalendarValue::Classification(ICalendarClassification::Private) => sensitivity::PRIVATE,
        ICalendarValue::Classification(ICalendarClassification::Confidential) => {
            sensitivity::CONFIDENTIAL
        }
        ICalendarValue::Text(text)
            if hashify::set_ignore_case!(text.as_bytes(), "X-PERSONAL", "PERSONAL") =>
        {
            sensitivity::PERSONAL
        }
        _ => sensitivity::NORMAL,
    }
}

pub(super) fn importance(component: &ICalendarComponent) -> Option<i32> {
    if let Some(value) = other_text(component, CDO_IMPORTANCE_NAME)
        .and_then(|value| value.trim().parse::<i32>().ok())
        .filter(|value| (importance::LOW..=importance::HIGH).contains(value))
    {
        return Some(value);
    }
    match component
        .property(&ICalendarProperty::Priority)?
        .values
        .first()?
        .as_integer()?
    {
        1..=4 => Some(importance::HIGH),
        5 => Some(importance::NORMAL),
        6..=9 => Some(importance::LOW),
        _ => None,
    }
}

pub(super) fn keywords(component: &ICalendarComponent) -> Vec<Box<str>> {
    let mut keywords: Vec<Box<str>> = Vec::new();
    for value in component
        .properties(&ICalendarProperty::Categories)
        .flat_map(|entry| entry.values.iter())
        .filter_map(ICalendarValue::as_text)
    {
        let mut keyword = String::with_capacity(value.len());
        for word in value
            .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
            .filter(|word| !word.is_empty())
        {
            if !keyword.is_empty() {
                keyword.push(' ');
            }
            keyword.push_str(word);
        }
        let keyword = truncate_chars(&keyword, MAX_KEYWORD_CHARS);
        if !keyword.is_empty()
            && !keywords
                .iter()
                .any(|known| known.eq_ignore_ascii_case(keyword))
        {
            keywords.push(keyword.into());
        }
    }
    keywords
}

pub(super) fn tz_definition(tz: Tz, years: std::ops::RangeInclusive<i16>) -> TzDefinition {
    match tz {
        Tz::Iana(_) => match (tz.name(), tz.time_zone()) {
            (Some(name), Some(zone)) => TzDefinition::from_time_zone(
                iana_to_windows(&name).unwrap_or(CUSTOM_KEY_NAME),
                zone,
                years,
            ),
            _ => TzDefinition::from_time_zone(UTC_KEY_NAME, &TimeZone::UTC, years),
        },
        Tz::Fixed(offset) => {
            TzDefinition::from_time_zone(CUSTOM_KEY_NAME, &TimeZone::fixed(offset), years)
        }
        Tz::Floating => TzDefinition::from_time_zone(UTC_KEY_NAME, &TimeZone::UTC, years),
    }
}

fn set_tzdef(bag: &mut PropBag, lid: Lid, definition: &TzDefinition) {
    let mut out = Vec::new();
    definition.encode(&mut out);
    bag.set(lid.key(), OwnedPropValue::Binary(Bytes::from(out)));
}

fn midnight(local: DateTime) -> Option<u32> {
    local_minutes(local.date().to_datetime(jiff::civil::Time::midnight()))
}

fn minutes_file_time(minutes: u32) -> FileTime {
    FileTime(u64::from(minutes).saturating_mul(FILETIME_TICKS_PER_MINUTE))
}

pub(super) fn file_time(instant: Timestamp) -> FileTime {
    FileTime::from_utc(UtcSeconds(instant.as_second()), 0)
}

fn set_time(bag: &mut PropBag, key: PropKey, instant: Timestamp) {
    bag.set(key, OwnedPropValue::Time(file_time(instant)));
}

fn set_file_time(bag: &mut PropBag, key: PropKey, time: FileTime) {
    bag.set(key, OwnedPropValue::Time(time));
}

fn set_bool(bag: &mut PropBag, lid: Lid, value: bool) {
    bag.set(lid.key(), OwnedPropValue::Bool(value));
}

fn text(bag: &mut PropBag, id: PropId, value: &str) {
    bag.set(PropKey::tag(id), OwnedPropValue::Unicode(value.into()));
}

pub(super) fn truncate_chars(value: &str, max: usize) -> &str {
    value
        .char_indices()
        .nth(max)
        .and_then(|(index, _)| value.get(..index))
        .unwrap_or(value)
}
