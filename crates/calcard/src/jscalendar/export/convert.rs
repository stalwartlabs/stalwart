/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::datecalc::rrule::RRule;
use crate::{
    common::{
        IanaParse, PartialDateTime,
        blob::BlobResolver,
        export::{ExportError, RejectedPatch},
        jsprop::text::PointerString,
        timezone::{NominalDuration, Tz, ZonedDateTime},
    },
    icalendar::*,
    jscalendar::{
        export::{ConvertedComponent, ExportContext, ExportOptions, State},
        ext::{JSCalendarKeyExt, JSCalendarMapExt, JSCalendarObjectExt},
        overrides::OverrideTemplate,
        *,
    },
};
use ahash::AHashSet;
use jiff::{civil, tz::Offset};
use jmap_tools::{Key, Map, Value};
use smallvec::smallvec;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JSPropSet {
    Exists,
    Missing,
}

impl JSPropSet {
    fn of(exists: bool) -> Self {
        if exists {
            JSPropSet::Exists
        } else {
            JSPropSet::Missing
        }
    }
}

impl<'x, I: JSCalendarId, B: JSCalendarId> JSCalendar<'x, I, B> {
    pub fn into_icalendar(self) -> Result<ICalendar, ExportError> {
        self.into_icalendar_with(ExportOptions::default())
    }

    pub fn into_icalendar_with<R: BlobResolver<B>>(
        self,
        options: ExportOptions<R>,
    ) -> Result<ICalendar, ExportError> {
        self.into_icalendar_with_report(options)
            .map(|(ical, _)| ical)
    }

    /// Converts to iCalendar, also returning the recurrence override patches
    /// that were rejected, as required by draft-ietf-calext-jscalendarbis-20,
    /// Section 1.5.9. Each rejected override degrades to an `RDATE`.
    pub fn into_icalendar_with_report<R: BlobResolver<B>>(
        self,
        mut options: ExportOptions<R>,
    ) -> Result<(ICalendar, Vec<RejectedPatch>), ExportError> {
        let mut context = options.context::<B>();
        if let Some(blobs) = &mut context.blobs {
            blobs.add_uses(self.blob_ids());
        }
        let entries = self.0.into_object().ok_or(ExportError::NotGroup)?;
        let entries = if entries.is_type_or_untyped(&[JSCalendarType::Group]) {
            entries
        } else if entries.is_type_or_untyped(&[JSCalendarType::Event, JSCalendarType::Task]) {
            Map::from_iter([(
                Key::Property(JSCalendarProperty::Entries),
                Value::Array(vec![Value::Object(entries)]),
            )])
        } else {
            return Err(ExportError::NotGroup);
        };
        let mut ical = ICalendar::default();

        ical.from_jscalendar(
            State {
                tz: Default::default(),
                tz_end: Default::default(),
                tz_rid: Default::default(),
                start: Default::default(),
                recurrence_id: Default::default(),
                uid: Default::default(),
                entries,
                is_date: false,
                default_component_type: ICalendarComponentType::VCalendar,
            },
            None,
            &mut context,
        );

        context.into_result(ical)
    }

    pub fn into_inner(self) -> Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>> {
        self.0
    }
}

impl ICalendar {
    #[allow(clippy::wrong_self_convention)]
    pub(super) fn from_jscalendar<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        mut state: State<'_, I, B>,
        mut parent_component: Option<&mut ICalendarComponent>,
        options: &mut ExportContext<'_, B>,
    ) {
        if options.has_failed() {
            return;
        }
        let mut root_conversions = None;
        let mut locale = None;
        let mut uid = state.uid.map(Cow::Borrowed);
        let mut organizer_address = None;
        let mut organizer_params: Vec<ICalendarParameter> = Vec::new();
        let mut organizer_sent_by = None;
        let mut privacy = None;
        let mut organizer_participant_id = None;
        let mut organizer_unmapped_roles = None;
        let mut organizer_owner = None;
        let mut has_organizer_participant = false;
        let mut alarms_without_text = Vec::new();
        let mut main_location_id = None;
        let mut start = None;
        let mut component_type = None;
        let mut description_content_type = None;
        let mut overrides = None;
        let mut is_show_without_time = false;
        let mut has_time_component = false;
        let mut has_time_zone = false;
        let entry_capacity = state.entry_capacity();
        let mut override_template = match state
            .entries
            .lookup(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
        {
            Some(Value::Object(overrides))
                if matches!(
                    state.default_component_type,
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo
                ) =>
            {
                let instances = OverrideTemplate::uses(&state.entries, overrides);
                (instances > 0).then(|| {
                    let template = OverrideTemplate::new(&state.entries, instances);
                    if let Some(blobs) = &mut options.blobs {
                        blobs.add_uses(template.blob_uses());
                    }
                    template
                })
            }
            _ => None,
        };

        for (key, value) in state.entries.as_mut_vec() {
            match (key, value) {
                (Key::Property(JSCalendarProperty::ICalendar), Value::Object(obj)) => {
                    root_conversions =
                        ConvertedComponent::try_from_object(std::mem::take(obj.as_mut_vec()));
                }
                (Key::Property(JSCalendarProperty::MainLocationId), Value::Str(text)) => {
                    main_location_id = Some(std::mem::take(text));
                }
                (Key::Property(JSCalendarProperty::TimeZone), Value::Str(text)) => {
                    state.tz = Tz::from_str(text.as_ref()).ok();
                    has_time_zone = true;
                }
                (Key::Property(JSCalendarProperty::EndTimeZone), Value::Str(text)) => {
                    state.tz_end = Tz::from_str(text.as_ref()).ok();
                }
                (Key::Property(JSCalendarProperty::RecurrenceIdTimeZone), Value::Str(text)) => {
                    state.tz_rid = Tz::from_str(text.as_ref()).ok();
                }
                (Key::Property(JSCalendarProperty::Uid), Value::Str(text)) => {
                    uid = Some(std::mem::take(text));
                }
                (Key::Property(JSCalendarProperty::Locale), Value::Str(text)) => {
                    locale = Some(std::mem::take(text));
                }
                (Key::Property(JSCalendarProperty::OrganizerCalendarAddress), Value::Str(text)) => {
                    organizer_address = Some(std::mem::take(text));
                }
                (Key::Property(JSCalendarProperty::SentBy), Value::Str(text)) => {
                    organizer_sent_by = Some(std::mem::take(text));
                }
                (
                    Key::Property(JSCalendarProperty::Privacy),
                    Value::Element(JSCalendarValue::Privacy(value)),
                ) => {
                    privacy = Some(*value);
                }
                (Key::Property(JSCalendarProperty::Privacy), Value::Str(_)) => {
                    privacy = Some(JSCalendarPrivacy::Private);
                }
                (Key::Property(JSCalendarProperty::DescriptionContentType), Value::Str(text)) => {
                    description_content_type = Some(std::mem::take(text));
                }
                (
                    Key::Property(JSCalendarProperty::Start),
                    Value::Element(JSCalendarValue::DateTime(dt)),
                ) if matches!(
                    state.default_component_type,
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo
                ) =>
                {
                    has_time_component |= !dt.is_start_of_day();
                    start = dt.to_naive_date_time();
                }
                (
                    Key::Property(JSCalendarProperty::Due | JSCalendarProperty::RecurrenceId),
                    Value::Element(JSCalendarValue::DateTime(dt)),
                ) => {
                    has_time_component |= !dt.is_start_of_day();
                }
                (
                    Key::Property(
                        JSCalendarProperty::Duration | JSCalendarProperty::EstimatedDuration,
                    ),
                    Value::Element(JSCalendarValue::Duration(duration)),
                ) => {
                    has_time_component |=
                        duration.hours != 0 || duration.minutes != 0 || duration.seconds != 0;
                }
                (Key::Property(JSCalendarProperty::ShowWithoutTime), Value::Bool(value)) => {
                    is_show_without_time = *value;
                }
                (Key::Property(JSCalendarProperty::RecurrenceRule), Value::Object(obj)) => {
                    if let Some(Value::Element(JSCalendarValue::DateTime(dt))) =
                        obj.lookup(&Key::Property(JSCalendarProperty::Until))
                    {
                        has_time_component |= !dt.is_start_of_day();
                    }
                }
                (
                    Key::Property(JSCalendarProperty::Type),
                    Value::Element(JSCalendarValue::Type(typ)),
                ) => {
                    component_type = typ.to_icalendar_component_type();
                }
                (Key::Property(JSCalendarProperty::RecurrenceOverrides), Value::Object(obj))
                    if matches!(
                        state.default_component_type,
                        ICalendarComponentType::VEvent | ICalendarComponentType::VTodo
                    ) =>
                {
                    has_time_component |= obj.iter().any(|(key, _)| {
                        matches!(key, Key::Property(JSCalendarProperty::DateTime(dt))
                            if !dt.is_start_of_day())
                    });
                    overrides = Some(std::mem::take(obj));
                }
                _ => (),
            }
        }

        if let Some(overrides) = &mut overrides {
            for (_, value) in overrides.iter_mut() {
                let Value::Object(obj) = value else {
                    continue;
                };

                obj.as_mut_vec().retain(|(key, value)| match key {
                    Key::Property(JSCalendarProperty::Privacy) => {
                        let override_privacy = match value {
                            Value::Element(JSCalendarValue::Privacy(value)) => *value,
                            _ => JSCalendarPrivacy::Private,
                        };
                        if override_privacy > privacy.unwrap_or(JSCalendarPrivacy::Public) {
                            privacy = Some(override_privacy);
                        }
                        false
                    }
                    key => !key.is_forbidden_override_key(),
                });
            }
        }

        /*
         In the iCalendar component, the value data types of the DTSTART, DUE and
         RECURRENCE-ID properties all MUST be of the same form, either DATE, or DATE WITH
         LOCAL TIME, or DATE WITH UTC TIME. It MUST be DATE if the "showWithoutTime"
         property value is "true", the "timeZone" property value is not set, and the time
         component is zero in the values of the "start", "due", "duration",
         "estimatedDuration", "recurrenceId" properties, and the RecurrenceRule object's
         "until" property, and in any key of the "recurrenceOverrides" property value.
        */

        let series_is_date = state.is_date;
        let is_override = state.recurrence_id.is_some();
        state.is_date = (series_is_date && !is_override)
            || (is_show_without_time
                && !has_time_component
                && (!has_time_zone
                    || root_conversions.as_ref().is_some_and(|conversions| {
                        conversions.has_date_value(&JSCalendarProperty::Start)
                    })));
        if is_override
            && (state.is_date != series_is_date
                || state.tz.is_none()
                    != state
                        .recurrence_id
                        .is_some_and(|recurrence_id| recurrence_id.timezone().is_floating()))
            && let Some(conversions) = &mut root_conversions
        {
            conversions.converted_props.retain(|(keys, _)| {
                !matches!(
                    keys.as_slice(),
                    [Key::Property(
                        JSCalendarProperty::Start
                            | JSCalendarProperty::Due
                            | JSCalendarProperty::Duration
                    )]
                )
            });
        }

        // Build component
        let mut component =
            ICalendarComponent::new(component_type.unwrap_or(state.default_component_type));
        component.entries.reserve_exact(entry_capacity);
        if parent_component.is_none() {
            debug_assert!(self.components.is_empty());
            self.components
                .push(ICalendarComponent::new(ICalendarComponentType::VCalendar));
        }

        // Add start date
        if let Some(start) =
            start.and_then(|dt| state.tz.unwrap_or_default().resolve_local_datetime(dt))
        {
            state.start = Some(start);
        }
        if let Some(dt) = state.start {
            component.entries.push(
                ICalendarEntry::new(ICalendarProperty::Dtstart)
                    .import_converted(&[JSCalendarProperty::Start], &mut root_conversions)
                    .with_date(dt, state.is_date),
            );
        }

        // Add UID
        if let Some(uid) = &uid {
            component.entries.push(
                ICalendarEntry::new(ICalendarProperty::Uid)
                    .import_converted(&[JSCalendarProperty::Uid], &mut root_conversions)
                    .with_value(uid.clone().into_owned()),
            );
        }

        let mut show_without_time = None;
        let mut add_recurrence_id = state.recurrence_id.is_some();
        for (key, value) in state.entries.into_vec() {
            let Key::Property(property) = key else {
                component.insert_jsprop(&[key.to_string().as_ref()], value);
                continue;
            };

            match (&property, value, &component.component_type) {
                (
                    JSCalendarProperty::Links,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    component.import_links(obj, &mut root_conversions, options);
                }
                (
                    JSCalendarProperty::Participants,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    for (name, value) in obj.into_vec() {
                        let Value::Object(mut value) = value else {
                            continue;
                        };

                        let mut item_conversions = ConvertedComponent::build(&mut value);
                        let has_address = matches!(
                            value.lookup(&Key::Property(JSCalendarProperty::CalendarAddress)),
                            Some(Value::Str(_))
                        );
                        let mut entry = ICalendarEntry::new(ICalendarProperty::Attendee);
                        entry.params.reserve_exact(value.len() + 1);
                        let mut participant =
                            ICalendarComponent::new(ICalendarComponentType::Participant);
                        let mut participant_name = None;
                        let mut calendar_address = None;
                        let mut status = None;
                        let mut progress = None;
                        let mut description = None;
                        let mut description_content_type = None;
                        let mut is_uuid5_key = false;
                        let mut references_key = false;
                        let mut has_owner_role = false;
                        let mut unmapped_roles = Vec::new();

                        for (sub_property, value) in value.into_vec() {
                            match (sub_property, value) {
                                (
                                    Key::Property(JSCalendarProperty::CalendarAddress),
                                    Value::Str(text),
                                ) => {
                                    is_uuid5_key = name.is_uuid5_of(text.as_bytes());
                                    calendar_address = Some(text);
                                }
                                (
                                    Key::Property(JSCalendarProperty::DelegatedFrom),
                                    Value::Object(obj),
                                ) if has_address => {
                                    for key in obj.into_expanded_boolean_set() {
                                        entry.params.push(ICalendarParameter::delegated_from(
                                            Uri::parse(key.into_string()),
                                        ));
                                    }
                                }
                                (
                                    Key::Property(JSCalendarProperty::DelegatedFrom),
                                    Value::Str(text),
                                ) if has_address => {
                                    entry.params.push(ICalendarParameter::delegated_from(
                                        Uri::parse(text.into_owned()),
                                    ));
                                }
                                (
                                    Key::Property(JSCalendarProperty::DelegatedTo),
                                    Value::Object(obj),
                                ) if has_address => {
                                    for key in obj.into_expanded_boolean_set() {
                                        entry.params.push(ICalendarParameter::delegated_to(
                                            Uri::parse(key.into_string()),
                                        ));
                                    }
                                }
                                (
                                    Key::Property(JSCalendarProperty::DelegatedTo),
                                    Value::Str(text),
                                ) if has_address => {
                                    entry.params.push(ICalendarParameter::delegated_to(
                                        Uri::parse(text.into_owned()),
                                    ));
                                }
                                (Key::Property(JSCalendarProperty::Email), Value::Str(text))
                                    if has_address =>
                                {
                                    entry
                                        .params
                                        .push(ICalendarParameter::email(text.into_owned()));
                                }
                                (
                                    Key::Property(JSCalendarProperty::ExpectReply),
                                    Value::Bool(value),
                                ) if has_address => {
                                    entry.params.push(ICalendarParameter::rsvp(value));
                                }
                                (
                                    Key::Property(JSCalendarProperty::Kind),
                                    Value::Element(JSCalendarValue::ParticipantKind(kind)),
                                ) if has_address => {
                                    entry.params.push(ICalendarParameter::cutype(match kind {
                                        JSCalendarParticipantKind::Individual => {
                                            ICalendarUserTypes::Individual
                                        }
                                        JSCalendarParticipantKind::Group => {
                                            ICalendarUserTypes::Group
                                        }
                                        JSCalendarParticipantKind::Resource => {
                                            ICalendarUserTypes::Resource
                                        }
                                        JSCalendarParticipantKind::Location => {
                                            ICalendarUserTypes::Room
                                        }
                                    }));
                                }
                                (Key::Property(JSCalendarProperty::Kind), Value::Str(text))
                                    if has_address && text.is_param_token() =>
                                {
                                    entry
                                        .params
                                        .push(ICalendarParameter::cutype(text.to_lowercase()));
                                }
                                (
                                    Key::Property(JSCalendarProperty::MemberOf),
                                    Value::Object(obj),
                                ) if has_address => {
                                    for key in obj.into_expanded_boolean_set() {
                                        entry.params.push(ICalendarParameter::member(Uri::parse(
                                            key.into_string(),
                                        )));
                                    }
                                }
                                (Key::Property(JSCalendarProperty::Name), Value::Str(text)) => {
                                    if has_address {
                                        entry.params.push(ICalendarParameter::cn(
                                            ICalendarParameterValue::Null,
                                        ));
                                    }
                                    participant_name = Some(text);
                                }
                                (
                                    Key::Property(JSCalendarProperty::ParticipationStatus),
                                    Value::Element(JSCalendarValue::ParticipationStatus(status_)),
                                ) if has_address => {
                                    if status.is_none() && progress.is_none() {
                                        entry.params.push(ICalendarParameter::partstat(
                                            ICalendarParameterValue::Null,
                                        ));
                                    }
                                    status = Some(status_);
                                }
                                (
                                    Key::Property(JSCalendarProperty::Progress),
                                    Value::Element(JSCalendarValue::Progress(progress_)),
                                ) if has_address => {
                                    if status.is_none() && progress.is_none() {
                                        entry.params.push(ICalendarParameter::partstat(
                                            ICalendarParameterValue::Null,
                                        ));
                                    }
                                    progress = Some(progress_);
                                }
                                (Key::Property(JSCalendarProperty::Roles), Value::Object(obj))
                                    if has_address =>
                                {
                                    for key in obj.into_expanded_boolean_set() {
                                        let ical_role = match &key {
                                            Key::Property(JSCalendarProperty::ParticipantRole(
                                                role,
                                            )) => Some(match role {
                                                JSCalendarParticipantRole::Optional => {
                                                    ICalendarParticipationRole::OptParticipant
                                                }
                                                JSCalendarParticipantRole::Informational => {
                                                    ICalendarParticipationRole::NonParticipant
                                                }
                                                JSCalendarParticipantRole::Chair => {
                                                    ICalendarParticipationRole::Chair
                                                }
                                                JSCalendarParticipantRole::Required => {
                                                    ICalendarParticipationRole::ReqParticipant
                                                }
                                                JSCalendarParticipantRole::Owner => {
                                                    ICalendarParticipationRole::Owner
                                                }
                                            }),
                                            _ => None,
                                        };
                                        if let Some(role) = ical_role {
                                            has_owner_role |=
                                                role == ICalendarParticipationRole::Owner;
                                            entry.params.push(ICalendarParameter::role(role));
                                        } else {
                                            unmapped_roles.push(key.into_owned());
                                        }
                                    }
                                }
                                (Key::Property(JSCalendarProperty::SentBy), Value::Str(text))
                                    if has_address =>
                                {
                                    entry.params.push(ICalendarParameter::sent_by(Uri::parse(
                                        text.into_owned(),
                                    )));
                                }
                                (
                                    Key::Property(JSCalendarProperty::Description),
                                    Value::Str(text),
                                ) => {
                                    description = Some(text);
                                }
                                (
                                    Key::Property(JSCalendarProperty::DescriptionContentType),
                                    Value::Str(text),
                                ) => {
                                    description_content_type = Some(text);
                                }
                                (Key::Property(JSCalendarProperty::Links), Value::Object(obj)) => {
                                    participant.import_links(obj, &mut item_conversions, options);
                                }
                                (
                                    Key::Property(JSCalendarProperty::PercentComplete),
                                    Value::Number(number),
                                ) => match number
                                    .as_i64()
                                    .filter(|percent| (0..=100).contains(percent))
                                {
                                    Some(percent) => {
                                        participant.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::PercentComplete)
                                                .with_value(percent)
                                                .import_converted(
                                                    &[JSCalendarProperty::PercentComplete],
                                                    &mut item_conversions,
                                                ),
                                        );
                                    }
                                    None => {
                                        participant.insert_jsprop::<I, B>(
                                            &[JSCalendarProperty::PercentComplete::<I>
                                                .to_string()
                                                .as_ref()],
                                            Value::Number(number),
                                        );
                                    }
                                },
                                (
                                    Key::Property(
                                        JSCalendarProperty::Type | JSCalendarProperty::ICalendar,
                                    ),
                                    _,
                                ) => {}
                                (sub_property, value) => {
                                    if item_conversions.is_none() && has_address {
                                        references_key |= component.insert_jsprop(
                                            &[
                                                property.to_string().as_ref(),
                                                name.to_string().as_ref(),
                                                sub_property.to_string().as_ref(),
                                            ],
                                            value,
                                        );
                                    } else {
                                        participant.insert_jsprop(
                                            &[sub_property.to_string().as_ref()],
                                            value,
                                        );
                                    }
                                }
                            }
                        }

                        match (description, description_content_type) {
                            (Some(description), Some(content_type)) => {
                                participant.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::StyledDescription)
                                        .with_param(ICalendarParameter::fmttype(
                                            content_type.into_owned(),
                                        ))
                                        .with_value(description.into_owned())
                                        .import_converted(
                                            &[JSCalendarProperty::Description],
                                            &mut item_conversions,
                                        ),
                                );
                            }
                            (Some(description), None) => {
                                participant.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::Description)
                                        .with_value(description.into_owned())
                                        .import_converted(
                                            &[JSCalendarProperty::Description],
                                            &mut item_conversions,
                                        ),
                                );
                            }
                            _ => {}
                        }

                        let mut partstat = match (status, progress) {
                            (
                                Some(JSCalendarParticipationStatus::Accepted) | None,
                                Some(progress),
                            ) => match progress {
                                JSCalendarProgress::NeedsAction => {
                                    Some(ICalendarParticipationStatus::NeedsAction)
                                }
                                JSCalendarProgress::InProcess => {
                                    Some(ICalendarParticipationStatus::InProcess)
                                }
                                JSCalendarProgress::Completed => {
                                    Some(ICalendarParticipationStatus::Completed)
                                }
                                JSCalendarProgress::Failed => {
                                    Some(ICalendarParticipationStatus::Failed)
                                }
                                // Not a valid Participant progress value per section 4.4.5
                                JSCalendarProgress::Cancelled => None,
                            },
                            (Some(status), _) => Some(match status {
                                JSCalendarParticipationStatus::Accepted => {
                                    ICalendarParticipationStatus::Accepted
                                }
                                JSCalendarParticipationStatus::Declined => {
                                    ICalendarParticipationStatus::Declined
                                }
                                JSCalendarParticipationStatus::NeedsAction => {
                                    ICalendarParticipationStatus::NeedsAction
                                }
                                JSCalendarParticipationStatus::Tentative => {
                                    ICalendarParticipationStatus::Tentative
                                }
                                JSCalendarParticipationStatus::Delegated => {
                                    ICalendarParticipationStatus::Delegated
                                }
                            }),
                            _ => None,
                        };

                        let has_component = !has_address
                            || !participant.entries.is_empty()
                            || item_conversions.is_some();
                        let has_entry = has_address
                            && (partstat.is_some()
                                || item_conversions.is_none()
                                || entry.params.iter().any(|param| {
                                    !matches!(param.value, ICalendarParameterValue::Null)
                                }));

                        entry
                            .params
                            .retain_mut(|param| match (&param.name, &param.value) {
                                (
                                    ICalendarParameterName::Partstat,
                                    ICalendarParameterValue::Null,
                                ) => partstat.take().is_some_and(|partstat| {
                                    param.value = ICalendarParameterValue::Partstat(partstat);
                                    true
                                }),
                                (ICalendarParameterName::Cn, ICalendarParameterValue::Null) => {
                                    participant_name.as_ref().filter(|_| has_entry).is_some_and(
                                        |participant_name| {
                                            param.value = ICalendarParameterValue::Text(
                                                participant_name.to_string(),
                                            );
                                            true
                                        },
                                    )
                                }
                                _ => true,
                            });

                        let is_organizer = has_address
                            && organizer_address.is_some()
                            && organizer_address == calendar_address
                            && !has_organizer_participant;
                        has_organizer_participant |= is_organizer;

                        /*
                         The "owner" role needs not convert to the ROLE parameter of the
                         ATTENDEE property if the Participant object converts to both the
                         ATTENDEE and ORGANIZER property.
                        */

                        let stripped_owner = if is_organizer {
                            entry
                                .params
                                .iter()
                                .position(|param| {
                                    matches!(
                                        (&param.name, &param.value),
                                        (
                                            ICalendarParameterName::Role,
                                            ICalendarParameterValue::Role(
                                                ICalendarParticipationRole::Owner
                                            )
                                        )
                                    )
                                })
                                .inspect(|&position| {
                                    entry.params.remove(position);
                                })
                        } else {
                            None
                        };

                        if let Some(calendar_address) = calendar_address {
                            let calendar_address =
                                ICalendarValue::Uri(Uri::parse(calendar_address.into_owned()));

                            if has_component {
                                participant.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::CalendarAddress)
                                        .with_value(calendar_address.clone()),
                                );
                            }
                            if has_entry {
                                entry.values.push(calendar_address);
                            }
                        }

                        if let Some(participant_name) = participant_name
                            && has_component
                        {
                            participant.entries.push(
                                ICalendarEntry::new(ICalendarProperty::Summary)
                                    .with_value(participant_name.into_owned())
                                    .import_converted(
                                        &[JSCalendarProperty::Name],
                                        &mut item_conversions,
                                    ),
                            );
                        }

                        /*
                         The Participant object converts to an ATTENDEE property and PARTICIPANT
                         component, unless it is fully represented by the ORGANIZER property:
                         its "calendarAddress" property value matches the
                         "organizerCalendarAddress" property value, it does not have any role
                         but the "owner" role set, and it only has properties set that convert
                         to ORGANIZER parameters.
                        */

                        let is_organizer_only = is_organizer
                            && !has_component
                            && unmapped_roles.is_empty()
                            && entry.params.iter().all(|param| {
                                matches!(
                                    param.name,
                                    ICalendarParameterName::Cn
                                        | ICalendarParameterName::Email
                                        | ICalendarParameterName::SentBy
                                )
                            });

                        let participant_id = name.into_string();

                        if !unmapped_roles.is_empty() {
                            references_key = true;
                            if entry
                                .params
                                .iter()
                                .any(|param| param.name == ICalendarParameterName::Role)
                            {
                                component.insert_roles_jsprop::<I, B>(
                                    &participant_id,
                                    unmapped_roles,
                                    JSPropSet::Exists,
                                );
                            } else if is_organizer {
                                organizer_unmapped_roles =
                                    Some((participant_id.clone(), unmapped_roles));
                            } else {
                                component.insert_roles_jsprop::<I, B>(
                                    &participant_id,
                                    unmapped_roles,
                                    JSPropSet::Missing,
                                );
                            }
                        }

                        if is_organizer_only {
                            organizer_params.append(&mut entry.params);
                            if !is_uuid5_key || references_key {
                                organizer_params
                                    .push(ICalendarParameter::jsid(participant_id.clone()));
                            }
                            organizer_participant_id = Some(participant_id.clone());
                            organizer_owner =
                                Some(OrganizerOwner::Organizer(participant_id.clone()));
                        } else if is_organizer {
                            organizer_params.extend(
                                entry
                                    .params
                                    .iter()
                                    .filter(|param| {
                                        matches!(
                                            param.name,
                                            ICalendarParameterName::Cn
                                                | ICalendarParameterName::Email
                                                | ICalendarParameterName::SentBy
                                        )
                                    })
                                    .cloned(),
                            );
                            if has_owner_role {
                                organizer_owner =
                                    Some(OrganizerOwner::Organizer(participant_id.clone()));
                            }
                        }

                        if has_component {
                            if !is_uuid5_key || references_key {
                                participant.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::Jsid)
                                        .with_value(participant_id.clone()),
                                );
                            }
                            if let Some(item_conversions) = item_conversions {
                                participant = item_conversions.apply_conversions(participant, self);
                            }
                            component
                                .component_ids
                                .push(self.push_component(participant));
                        }

                        if !entry.values.is_empty() && !is_organizer_only {
                            let mut attendee = entry.import_converted_with_id(
                                &[JSCalendarProperty::Participants],
                                &mut root_conversions,
                                Some(participant_id.as_str()),
                            );
                            if !is_uuid5_key || references_key {
                                attendee.add_param(ICalendarParameter::jsid(participant_id));
                            }
                            if let Some(position) = stripped_owner {
                                organizer_owner = Some(OrganizerOwner::Attendee {
                                    entry: component.entries.len(),
                                    position,
                                });
                            }

                            component.entries.push(attendee);
                        }
                    }
                }
                (
                    JSCalendarProperty::Alerts,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    let mut alerts = Vec::new();
                    let mut has_related_to = false;

                    for (name, value) in obj.into_vec() {
                        let Value::Object(mut value) = value else {
                            continue;
                        };

                        let mut item_conversions = ConvertedComponent::build(&mut value);
                        let mut alert = ICalendarComponent::new(ICalendarComponentType::VAlarm);
                        let mut has_action = false;

                        for (sub_property, value) in value.into_vec() {
                            match (sub_property, value) {
                                (
                                    Key::Property(
                                        JSCalendarProperty::Type | JSCalendarProperty::ICalendar,
                                    ),
                                    _,
                                ) => {}
                                (
                                    Key::Property(JSCalendarProperty::Acknowledged),
                                    Value::Element(JSCalendarValue::DateTime(dt)),
                                ) => {
                                    alert.entries.push(
                                        ICalendarEntry::new(ICalendarProperty::Acknowledged)
                                            .with_value(PartialDateTime::from_utc_timestamp(
                                                dt.timestamp,
                                            ))
                                            .import_converted(
                                                &[JSCalendarProperty::Acknowledged],
                                                &mut item_conversions,
                                            ),
                                    );
                                }
                                (
                                    Key::Property(JSCalendarProperty::Action),
                                    Value::Element(JSCalendarValue::AlertAction(action)),
                                ) => {
                                    has_action = true;
                                    alert.entries.push(
                                        ICalendarEntry::new(ICalendarProperty::Action)
                                            .with_value(ICalendarValue::Action(match action {
                                                JSCalendarAlertAction::Display => {
                                                    ICalendarAction::Display
                                                }
                                                JSCalendarAlertAction::Email => {
                                                    ICalendarAction::Email
                                                }
                                            }))
                                            .import_converted(
                                                &[JSCalendarProperty::Action],
                                                &mut item_conversions,
                                            ),
                                    );
                                }
                                (
                                    Key::Property(JSCalendarProperty::RelatedTo),
                                    Value::Object(obj),
                                ) => {
                                    has_related_to = true;
                                    alert.import_relations(obj, &mut item_conversions);
                                }
                                (
                                    Key::Property(JSCalendarProperty::Trigger),
                                    Value::Object(obj),
                                ) => {
                                    let mut offset = None;
                                    let mut rel_to = None;
                                    let mut when = None;

                                    for (key, value) in obj.into_vec() {
                                        match (key, value) {
                                            (
                                                Key::Property(JSCalendarProperty::Offset),
                                                Value::Element(JSCalendarValue::Duration(value)),
                                            ) => {
                                                offset = Some(value);
                                            }
                                            (
                                                Key::Property(JSCalendarProperty::RelativeTo),
                                                Value::Element(JSCalendarValue::RelativeTo(value)),
                                            ) => {
                                                rel_to = Some(value);
                                            }
                                            (
                                                Key::Property(JSCalendarProperty::When),
                                                Value::Element(JSCalendarValue::DateTime(value)),
                                            ) => {
                                                when = Some(value);
                                            }
                                            (Key::Property(JSCalendarProperty::Type), _) => {}
                                            (key, value) => {
                                                alert.insert_jsprop(
                                                    &[
                                                        JSCalendarProperty::Trigger::<I>
                                                            .to_string()
                                                            .as_ref(),
                                                        key.to_string().as_ref(),
                                                    ],
                                                    value,
                                                );
                                            }
                                        }
                                    }

                                    if let Some(when) = when {
                                        alert.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::Trigger)
                                                .with_param(ICalendarParameter::value(
                                                    ICalendarValueType::DateTime,
                                                ))
                                                .with_value(PartialDateTime::from_utc_timestamp(
                                                    when.timestamp,
                                                ))
                                                .import_converted(
                                                    &[
                                                        JSCalendarProperty::Trigger,
                                                        JSCalendarProperty::When,
                                                    ],
                                                    &mut item_conversions,
                                                ),
                                        );
                                    } else if let Some(offset) = offset {
                                        alert.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::Trigger)
                                                .with_param_opt(rel_to.map(|rel_to| {
                                                    ICalendarParameter::related(match rel_to {
                                                        JSCalendarRelativeTo::Start => {
                                                            ICalendarRelated::Start
                                                        }
                                                        JSCalendarRelativeTo::End => {
                                                            ICalendarRelated::End
                                                        }
                                                    })
                                                }))
                                                .with_value(offset)
                                                .import_converted(
                                                    &[
                                                        JSCalendarProperty::Trigger,
                                                        JSCalendarProperty::Offset,
                                                    ],
                                                    &mut item_conversions,
                                                ),
                                        );
                                    }
                                }
                                (sub_property, value) => {
                                    has_action |= matches!(
                                        sub_property,
                                        Key::Property(JSCalendarProperty::Action)
                                    );
                                    alert
                                        .insert_jsprop(&[sub_property.to_string().as_ref()], value);
                                }
                            }
                        }

                        if let Some(item_conversions) = item_conversions {
                            alert = item_conversions.apply_conversions(alert, self);
                        }

                        if !alert.entries.is_empty() {
                            if !has_action && !alert.has_property(&ICalendarProperty::Action) {
                                alert.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::Action).with_value(
                                        ICalendarValue::Action(ICalendarAction::Display),
                                    ),
                                );
                            }
                            if !alert.has_property(&ICalendarProperty::Trigger) {
                                alert.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::Trigger)
                                        .with_value(ICalendarDuration::default()),
                                );
                            }
                            alert.entries.push(
                                ICalendarEntry::new(ICalendarProperty::Jsid)
                                    .with_value(name.into_string()),
                            );
                            alerts.push(alert);
                        }
                    }

                    // Map RELATED-TO properties
                    let mut alert_mappings = Vec::new();
                    if has_related_to {
                        let related_ids = alerts
                            .iter()
                            .flat_map(|alert| alert.properties(&ICalendarProperty::RelatedTo))
                            .filter_map(|related_to| related_to.values.first())
                            .filter_map(ICalendarValue::as_text)
                            .map(str::to_string)
                            .collect::<AHashSet<_>>();
                        for alert in &mut alerts {
                            if !alert.has_property(&ICalendarProperty::Uid)
                                && let Some(alert_uid) = alert
                                    .jsid()
                                    .filter(|jsid| related_ids.contains(*jsid))
                                    .map(|jsid| {
                                        uuid5(format!(
                                            "{}/{jsid}",
                                            uid.as_deref().unwrap_or_default()
                                        ))
                                    })
                            {
                                alert.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::Uid)
                                        .with_value(alert_uid),
                                );
                            }
                        }
                        alert_mappings = alerts
                            .iter()
                            .filter_map(|alert| {
                                Some((alert.jsid()?.to_string(), alert.uid()?.to_string()))
                            })
                            .collect();
                    }
                    for mut alert in alerts {
                        if has_related_to {
                            for related_to in alert.properties_mut(&ICalendarProperty::RelatedTo) {
                                if let Some(ICalendarValue::Text(related_to)) =
                                    related_to.values.first_mut()
                                    && let Some((_, uid)) =
                                        alert_mappings.iter().find(|(jsid, _)| jsid == related_to)
                                {
                                    *related_to = uid.clone();
                                }
                            }
                        }
                        let needs_text = alert.missing_alarm_text();
                        let alert_id = self.push_component(alert);
                        if needs_text {
                            alarms_without_text.push(alert_id);
                        }
                        component.component_ids.push(alert_id);
                    }
                }
                (
                    JSCalendarProperty::Keywords,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Categories)
                            .with_values(
                                obj.into_expanded_boolean_set()
                                    .map(|v| ICalendarValue::Text(v.into_string())),
                            )
                            .import_converted(
                                &[JSCalendarProperty::Keywords],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Privacy,
                    Value::Element(JSCalendarValue::Privacy(_)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {}
                (
                    JSCalendarProperty::Color,
                    Value::Str(text),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Color)
                            .with_value(text.into_owned())
                            .import_converted(&[JSCalendarProperty::Color], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::Categories,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    for value in obj.into_expanded_boolean_set() {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::Concept)
                                .with_value(ICalendarValue::Text(value.into_string()))
                                .import_converted(
                                    &[JSCalendarProperty::Categories],
                                    &mut root_conversions,
                                ),
                        );
                    }
                }
                (
                    JSCalendarProperty::VirtualLocations,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    for (name, value) in obj.into_vec() {
                        let mut entry = ICalendarEntry::new(ICalendarProperty::Conference);
                        let mut is_uuid5_key = false;
                        let mut references_key = false;

                        for (sub_property, value) in value.into_expanded_object() {
                            match (sub_property, value) {
                                (
                                    Key::Property(JSCalendarProperty::Features),
                                    Value::Object(obj),
                                ) => {
                                    let mut vendor_features = Vec::new();
                                    for key in obj.into_expanded_boolean_set() {
                                        let value = match key {
                                            Key::Property(
                                                JSCalendarProperty::VirtualLocationFeature(feature),
                                            ) => ICalendarParameterValue::Feature(match feature {
                                                JSCalendarVirtualLocationFeature::Audio => {
                                                    ICalendarFeatureType::Audio
                                                }
                                                JSCalendarVirtualLocationFeature::Chat => {
                                                    ICalendarFeatureType::Chat
                                                }
                                                JSCalendarVirtualLocationFeature::Feed => {
                                                    ICalendarFeatureType::Feed
                                                }
                                                JSCalendarVirtualLocationFeature::Moderator => {
                                                    ICalendarFeatureType::Moderator
                                                }
                                                JSCalendarVirtualLocationFeature::Phone => {
                                                    ICalendarFeatureType::Phone
                                                }
                                                JSCalendarVirtualLocationFeature::Screen => {
                                                    ICalendarFeatureType::Screen
                                                }
                                                JSCalendarVirtualLocationFeature::Video => {
                                                    ICalendarFeatureType::Video
                                                }
                                            }),
                                            other if other.to_string().is_param_token() => {
                                                ICalendarParameterValue::Text(other.into_string())
                                            }
                                            other => {
                                                vendor_features.push(other.into_owned());
                                                continue;
                                            }
                                        };
                                        entry.params.push(ICalendarParameter::feature(value));
                                    }
                                    if !vendor_features.is_empty() {
                                        references_key = true;
                                        let features = JSPropSet::of(
                                            entry.has_parameter(&ICalendarParameterName::Feature),
                                        );
                                        component.insert_set_jsprop::<I, B>(
                                            &[
                                                JSCalendarProperty::VirtualLocations::<I>
                                                    .to_string()
                                                    .as_ref(),
                                                name.to_string().as_ref(),
                                                JSCalendarProperty::Features::<I>
                                                    .to_string()
                                                    .as_ref(),
                                            ],
                                            vendor_features,
                                            features,
                                        );
                                    }
                                }
                                (Key::Property(JSCalendarProperty::Name), Value::Str(text)) => {
                                    entry
                                        .params
                                        .push(ICalendarParameter::label(text.into_owned()));
                                }
                                (Key::Property(JSCalendarProperty::Uri), Value::Str(text)) => {
                                    is_uuid5_key = name.is_uuid5_of(text.as_bytes());
                                    entry
                                        .values
                                        .push(ICalendarValue::Uri(Uri::parse(text.into_owned())));
                                }
                                (
                                    Key::Property(
                                        JSCalendarProperty::Type | JSCalendarProperty::ICalendar,
                                    ),
                                    _,
                                ) => {}
                                (sub_property, value) => {
                                    references_key |= component.insert_jsprop(
                                        &[
                                            JSCalendarProperty::VirtualLocations::<I>
                                                .to_string()
                                                .as_ref(),
                                            name.to_string().as_ref(),
                                            sub_property.to_string().as_ref(),
                                        ],
                                        value,
                                    );
                                }
                            }
                        }

                        if !is_uuid5_key || references_key {
                            entry.add_param(ICalendarParameter::jsid(name.into_string()));
                        }

                        component.entries.push(
                            entry
                                .import_converted(
                                    &[JSCalendarProperty::VirtualLocations],
                                    &mut root_conversions,
                                )
                                .with_uri_value_type(),
                        );
                    }
                }
                (
                    JSCalendarProperty::Title,
                    Value::Str(text),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Summary)
                            .with_param_opt(
                                locale
                                    .as_ref()
                                    .map(|locale| ICalendarParameter::language(locale.to_string())),
                            )
                            .with_value(text.into_owned())
                            .import_converted(&[JSCalendarProperty::Title], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::Title,
                    Value::Str(text),
                    ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Name)
                            .with_param_opt(
                                locale
                                    .as_ref()
                                    .map(|locale| ICalendarParameter::language(locale.to_string())),
                            )
                            .with_value(text.into_owned())
                            .import_converted(&[JSCalendarProperty::Title], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::Locations,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    let has_multi_location = obj.len() > 1;
                    for (name, value) in obj.into_vec() {
                        let Value::Object(mut value) = value else {
                            continue;
                        };
                        let mut item_conversions = ConvertedComponent::build(&mut value);
                        let is_main_location = main_location_id
                            .as_ref()
                            .is_some_and(|l| l == &name.to_string());
                        let mut is_uuid5_key = false;
                        let mut references_key = false;
                        let first_entry = component.entries.len();
                        let mut location = (item_conversions
                            .as_ref()
                            .is_some_and(|v| v.name.is_location())
                            || value.iter().any(|(k, v)| match (k, v) {
                                (
                                    Key::Property(
                                        JSCalendarProperty::Links
                                        | JSCalendarProperty::LocationTypes
                                        | JSCalendarProperty::Description,
                                    ),
                                    value,
                                ) => !value.is_null(),
                                (
                                    Key::Property(JSCalendarProperty::Coordinates),
                                    Value::Str(uri),
                                ) => uri.strip_prefix("geo:").is_none_or(|v| {
                                    !v.as_bytes()
                                        .iter()
                                        .all(|b| matches!(b, b'0'..=b'9' | b'.' | b',' | b'-'))
                                }),
                                _ => false,
                            })
                            || (has_multi_location && !is_main_location))
                            .then_some(ICalendarComponent::new(ICalendarComponentType::VLocation));

                        for (sub_property, value) in value.into_vec() {
                            match (sub_property, value) {
                                (
                                    Key::Property(JSCalendarProperty::LocationTypes),
                                    Value::Object(obj),
                                ) => {
                                    if let Some(location) = &mut location {
                                        location.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::LocationType)
                                                .import_converted(
                                                    &[JSCalendarProperty::LocationTypes],
                                                    &mut item_conversions,
                                                )
                                                .with_values(obj.into_expanded_boolean_set().map(
                                                    |v| ICalendarValue::Text(v.into_string()),
                                                )),
                                        );
                                    }
                                }
                                (Key::Property(JSCalendarProperty::Name), Value::Str(text)) => {
                                    is_uuid5_key |= name.is_uuid5_of(text.as_bytes());

                                    if let Some(location) = &mut location {
                                        location.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::Name)
                                                .import_converted(
                                                    &[JSCalendarProperty::Name],
                                                    &mut item_conversions,
                                                )
                                                .with_value(text.clone().into_owned()),
                                        );
                                    }

                                    if location.is_none() || is_main_location {
                                        component.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::Location)
                                                .with_param_opt((!is_uuid5_key).then(|| {
                                                    ICalendarParameter::jsid(
                                                        name.clone().into_string(),
                                                    )
                                                }))
                                                .with_param_opt(
                                                    (has_multi_location)
                                                        .then(|| ICalendarParameter::derived(true)),
                                                )
                                                .with_value(text.into_owned())
                                                .import_converted(
                                                    &[JSCalendarProperty::Locations],
                                                    &mut root_conversions,
                                                ),
                                        );
                                    }
                                }
                                (
                                    Key::Property(JSCalendarProperty::Description),
                                    Value::Str(text),
                                ) => {
                                    if let Some(location) = &mut location {
                                        location.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::Description)
                                                .import_converted(
                                                    &[JSCalendarProperty::Description],
                                                    &mut item_conversions,
                                                )
                                                .with_value(text.into_owned()),
                                        );
                                    }
                                }
                                (
                                    Key::Property(JSCalendarProperty::Coordinates),
                                    Value::Str(text),
                                ) => {
                                    is_uuid5_key |= name.is_uuid5_of(text.as_bytes());
                                    if let Some(location) = &mut location {
                                        let entry =
                                            ICalendarEntry::new(ICalendarProperty::Coordinates)
                                                .import_converted(
                                                    &[JSCalendarProperty::Coordinates],
                                                    &mut item_conversions,
                                                );
                                        location.entries.push(
                                            if entry.name == ICalendarProperty::Geo {
                                                entry.with_values(parse_geo(text))
                                            } else {
                                                entry
                                                    .with_value(Uri::parse(text.into_owned()))
                                                    .with_uri_value_type()
                                            },
                                        );
                                    } else {
                                        component.entries.push(
                                            ICalendarEntry::new(ICalendarProperty::Geo)
                                                .with_param_opt((!is_uuid5_key).then(|| {
                                                    ICalendarParameter::jsid(
                                                        name.clone().into_string(),
                                                    )
                                                }))
                                                .with_values(parse_geo(text))
                                                .import_converted(
                                                    &[JSCalendarProperty::Locations],
                                                    &mut root_conversions,
                                                ),
                                        );
                                    }
                                }
                                (Key::Property(JSCalendarProperty::Links), Value::Object(obj)) => {
                                    if let Some(location) = &mut location {
                                        location.import_links(obj, &mut item_conversions, options);
                                    }
                                }
                                (
                                    Key::Property(
                                        JSCalendarProperty::Type | JSCalendarProperty::ICalendar,
                                    ),
                                    _,
                                ) => {}
                                (sub_property, value) => {
                                    if let Some(location) = &mut location {
                                        location.insert_jsprop(
                                            &[sub_property.to_string().as_ref()],
                                            value,
                                        );
                                    } else {
                                        references_key |= component.insert_jsprop(
                                            &[
                                                JSCalendarProperty::Locations::<I>
                                                    .to_string()
                                                    .as_ref(),
                                                name.to_string().as_ref(),
                                                sub_property.to_string().as_ref(),
                                            ],
                                            value,
                                        );
                                    }
                                }
                            }
                        }

                        if references_key {
                            for entry in
                                component
                                    .entries
                                    .iter_mut()
                                    .skip(first_entry)
                                    .filter(|entry| {
                                        entry.name != ICalendarProperty::Jsprop
                                            && !entry.has_parameter(&ICalendarParameterName::Jsid)
                                    })
                            {
                                entry.add_param(ICalendarParameter::jsid(
                                    name.to_string().into_owned(),
                                ));
                            }
                        }

                        if let Some(mut location) = location {
                            if !is_uuid5_key {
                                location.entries.push(
                                    ICalendarEntry::new(ICalendarProperty::Jsid)
                                        .with_value(name.to_string().into_owned()),
                                );
                            }
                            if let Some(item_conversions) = item_conversions {
                                location = item_conversions.apply_conversions(location, self);
                            }
                            component.component_ids.push(self.push_component(location));
                        }
                    }
                }
                (
                    JSCalendarProperty::Created,
                    Value::Element(JSCalendarValue::DateTime(dt)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Created)
                            .with_value(PartialDateTime::from_utc_timestamp(dt.timestamp))
                            .import_converted(
                                &[JSCalendarProperty::Created],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Description,
                    Value::Str(text),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    if let Some(description_content_type) = description_content_type.take() {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::StyledDescription)
                                .with_value(text.into_owned())
                                .with_param(ICalendarParameter::fmttype(
                                    description_content_type.into_owned(),
                                ))
                                .import_converted(
                                    &[JSCalendarProperty::Description],
                                    &mut root_conversions,
                                ),
                        );
                    } else {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::Description)
                                .with_value(text.into_owned())
                                .import_converted(
                                    &[JSCalendarProperty::Description],
                                    &mut root_conversions,
                                ),
                        );
                    }
                }
                (
                    JSCalendarProperty::RecurrenceRule,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    let mut rrule = ICalendarRecurrenceRule::default();

                    for (key, value) in obj.into_vec() {
                        let Key::Property(key) = key else {
                            continue;
                        };
                        match (key, value) {
                            (
                                JSCalendarProperty::Frequency,
                                Value::Element(JSCalendarValue::Frequency(value)),
                            ) => {
                                rrule.freq = value;
                            }
                            (
                                JSCalendarProperty::Until,
                                Value::Element(JSCalendarValue::DateTime(value)),
                            ) => {
                                rrule.until = value
                                    .to_naive_date_time()
                                    .and_then(|dt| {
                                        state.tz.unwrap_or_default().resolve_local_datetime(dt)
                                    })
                                    .map(|dt| {
                                        if state.is_date {
                                            PartialDateTime::from_date_timestamp(
                                                dt.naive_timestamp(),
                                            )
                                        } else if dt.timezone().is_floating() {
                                            PartialDateTime::from_naive_timestamp(
                                                dt.naive_timestamp(),
                                            )
                                        } else {
                                            PartialDateTime::from_utc_timestamp(dt.timestamp())
                                        }
                                    });
                            }
                            (JSCalendarProperty::Count, Value::Number(value))
                                if value.as_u64().is_some_and(|count| {
                                    count >= 1 && u32::try_from(count).is_ok()
                                }) =>
                            {
                                rrule.count =
                                    value.as_u64().and_then(|count| u32::try_from(count).ok());
                            }
                            (JSCalendarProperty::Interval, Value::Number(value))
                                if value.as_u64().is_some_and(|interval| {
                                    interval >= 1 && u16::try_from(interval).is_ok()
                                }) =>
                            {
                                rrule.interval = value
                                    .as_u64()
                                    .and_then(|interval| u16::try_from(interval).ok());
                            }
                            (JSCalendarProperty::BySecond, Value::Array(value)) => {
                                rrule.bysecond = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| u8::try_from(n).ok()))
                                    .collect();
                            }
                            (JSCalendarProperty::ByMinute, Value::Array(value)) => {
                                rrule.byminute = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| u8::try_from(n).ok()))
                                    .collect();
                            }
                            (JSCalendarProperty::ByHour, Value::Array(value)) => {
                                rrule.byhour = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| u8::try_from(n).ok()))
                                    .collect();
                            }
                            (JSCalendarProperty::ByDay, Value::Array(value))
                                if value.iter().all(|item| {
                                    !matches!(
                                        item.as_object().and_then(|item| item.lookup(
                                            &Key::Property(JSCalendarProperty::NthOfPeriod)
                                        )),
                                        Some(Value::Number(nth)) if nth
                                            .as_i64()
                                            .is_none_or(|nth| i16::try_from(nth).is_err())
                                    )
                                }) =>
                            {
                                for item in value {
                                    let mut weekday = None;
                                    let mut ordwk = None;

                                    for (key, value) in item.into_expanded_object() {
                                        match (key, value) {
                                            (
                                                Key::Property(JSCalendarProperty::Day),
                                                Value::Element(JSCalendarValue::Weekday(value)),
                                            ) => {
                                                weekday = Some(value);
                                            }
                                            (
                                                Key::Property(JSCalendarProperty::NthOfPeriod),
                                                Value::Number(value),
                                            ) => {
                                                ordwk = value
                                                    .as_i64()
                                                    .and_then(|nth| i16::try_from(nth).ok());
                                            }
                                            _ => {}
                                        }
                                    }

                                    if let Some(weekday) = weekday {
                                        rrule.byday.push(ICalendarDay { weekday, ordwk });
                                    }
                                }
                            }
                            (JSCalendarProperty::ByMonthDay, Value::Array(value)) => {
                                rrule.bymonthday = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| i8::try_from(n).ok()))
                                    .collect();
                            }
                            (JSCalendarProperty::ByYearDay, Value::Array(value)) => {
                                rrule.byyearday = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| i16::try_from(n).ok()))
                                    .collect();
                            }
                            (JSCalendarProperty::ByWeekNo, Value::Array(value)) => {
                                rrule.byweekno = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| i8::try_from(n).ok()))
                                    .collect();
                            }
                            (JSCalendarProperty::ByMonth, Value::Array(value)) => {
                                rrule.bymonth = value
                                    .into_iter()
                                    .filter_map(|v| {
                                        v.as_str().and_then(|v| ICalendarMonth::parse(v.as_bytes()))
                                    })
                                    .collect();
                            }
                            (JSCalendarProperty::BySetPosition, Value::Array(value)) => {
                                rrule.bysetpos = value
                                    .into_iter()
                                    .filter_map(|v| v.as_i64().and_then(|n| i32::try_from(n).ok()))
                                    .collect();
                            }
                            (
                                JSCalendarProperty::FirstDayOfWeek,
                                Value::Element(JSCalendarValue::Weekday(value)),
                            ) => {
                                rrule.wkst = Some(value);
                            }
                            (
                                JSCalendarProperty::Rscale,
                                Value::Element(JSCalendarValue::CalendarScale(value)),
                            ) => {
                                rrule.rscale = Some(value);
                            }
                            (
                                JSCalendarProperty::Skip,
                                Value::Element(JSCalendarValue::Skip(value)),
                            ) => {
                                rrule.skip = Some(value);
                            }
                            (JSCalendarProperty::Type | JSCalendarProperty::ICalendar, _) => {}
                            (key, value) => {
                                component.insert_jsprop(
                                    &[
                                        JSCalendarProperty::RecurrenceRule::<I>
                                            .to_string()
                                            .as_ref(),
                                        key.to_string().as_ref(),
                                    ],
                                    value,
                                );
                            }
                        }
                    }

                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Rrule)
                            .with_value(rrule)
                            .import_converted(
                                &[JSCalendarProperty::RecurrenceRule],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Updated,
                    Value::Element(JSCalendarValue::DateTime(dt)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Dtstamp)
                            .with_value(PartialDateTime::from_utc_timestamp(dt.timestamp))
                            .import_converted(
                                &[JSCalendarProperty::Updated],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Updated,
                    Value::Element(JSCalendarValue::DateTime(dt)),
                    ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::LastModified)
                            .with_value(PartialDateTime::from_utc_timestamp(dt.timestamp))
                            .import_converted(
                                &[JSCalendarProperty::Updated],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Due,
                    Value::Element(JSCalendarValue::DateTime(dt)),
                    ICalendarComponentType::VTodo,
                ) => {
                    if let Some(dt) = dt
                        .to_naive_date_time()
                        .and_then(|dt| state.tz.unwrap_or_default().resolve_local_datetime(dt))
                    {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::Due)
                                .import_converted(&[JSCalendarProperty::Due], &mut root_conversions)
                                .with_date(dt, state.is_date),
                        );
                    }
                }
                (
                    JSCalendarProperty::RecurrenceId,
                    Value::Element(JSCalendarValue::DateTime(dt)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    if let Some(dt) = dt.to_naive_date_time().and_then(|dt| {
                        state
                            .tz_rid
                            .or(state.tz)
                            .unwrap_or_default()
                            .resolve_local_datetime(dt)
                    }) {
                        add_recurrence_id = false;
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::RecurrenceId)
                                .import_converted(
                                    &[JSCalendarProperty::RecurrenceId],
                                    &mut root_conversions,
                                )
                                .with_date(dt, state.is_date),
                        );
                    }
                }
                (
                    JSCalendarProperty::Duration,
                    Value::Element(JSCalendarValue::Duration(duration)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    let end_property = if state.tz_end.is_none() {
                        ICalendarProperty::Duration
                    } else {
                        ICalendarProperty::Dtend
                    };
                    let mut entry = ICalendarEntry::new(end_property.clone())
                        .import_converted(&[JSCalendarProperty::Duration], &mut root_conversions);
                    if entry.name == ICalendarProperty::Dtstart {
                        if component.component_type == ICalendarComponentType::VEvent
                            && state.is_date
                            && state.start.is_some()
                            && duration.to_nominal() == Some(NominalDuration::DAY)
                        {
                            continue;
                        }
                        entry = ICalendarEntry::new(end_property);
                    }
                    if entry.name == ICalendarProperty::Dtend {
                        if let Some(end) = state.start.and_then(|start| end_after(start, &duration))
                        {
                            component.entries.push(
                                entry.with_date(
                                    state
                                        .tz_end
                                        .map(|tz_end| end.with_timezone(tz_end))
                                        .unwrap_or(end),
                                    state.is_date,
                                ),
                            );
                        } else {
                            component.insert_jsprop::<I, B>(
                                &[property.to_string().as_ref()],
                                Value::Element(JSCalendarValue::Duration(duration)),
                            );
                        }
                    } else {
                        component.entries.push(entry.with_value(duration));
                    }
                }
                (
                    JSCalendarProperty::EstimatedDuration,
                    Value::Element(JSCalendarValue::Duration(duration)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::EstimatedDuration)
                            .with_value(duration)
                            .import_converted(
                                &[JSCalendarProperty::EstimatedDuration],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Method,
                    Value::Element(JSCalendarValue::Method(method)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    if let Some(parent_component) = &mut parent_component
                        && !parent_component.has_property(&ICalendarProperty::Method)
                    {
                        parent_component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::Method).with_value(method),
                        );
                    }
                }
                (
                    JSCalendarProperty::PercentComplete,
                    Value::Number(number),
                    ICalendarComponentType::VTodo,
                ) => match number
                    .as_i64()
                    .filter(|percent| (0..=100).contains(percent))
                {
                    Some(percent) => {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::PercentComplete)
                                .with_value(percent)
                                .import_converted(
                                    &[JSCalendarProperty::PercentComplete],
                                    &mut root_conversions,
                                ),
                        );
                    }
                    None => {
                        component.insert_jsprop::<I, B>(
                            &[property.to_string().as_ref()],
                            Value::Number(number),
                        );
                    }
                },
                (
                    JSCalendarProperty::Priority,
                    Value::Number(number),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => match number
                    .as_i64()
                    .filter(|priority| (0..=9).contains(priority))
                {
                    Some(priority) => {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::Priority)
                                .with_value(priority)
                                .import_converted(
                                    &[JSCalendarProperty::Priority],
                                    &mut root_conversions,
                                ),
                        );
                    }
                    None => {
                        component.insert_jsprop::<I, B>(
                            &[property.to_string().as_ref()],
                            Value::Number(number),
                        );
                    }
                },
                (
                    JSCalendarProperty::Sequence,
                    Value::Number(number),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => match number
                    .as_i64()
                    .filter(|sequence| (0..=i64::from(i32::MAX)).contains(sequence))
                {
                    Some(sequence) => {
                        component.entries.push(
                            ICalendarEntry::new(ICalendarProperty::Sequence)
                                .with_value(sequence)
                                .import_converted(
                                    &[JSCalendarProperty::Sequence],
                                    &mut root_conversions,
                                ),
                        );
                    }
                    None => {
                        component.insert_jsprop::<I, B>(
                            &[property.to_string().as_ref()],
                            Value::Number(number),
                        );
                    }
                },
                (
                    JSCalendarProperty::ProdId,
                    Value::Str(text),
                    ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Prodid)
                            .with_value(text.into_owned())
                            .import_converted(&[JSCalendarProperty::ProdId], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::RelatedTo,
                    Value::Object(obj),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    component.import_relations(obj, &mut root_conversions);
                }
                (
                    JSCalendarProperty::ShowWithoutTime,
                    Value::Bool(value),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    show_without_time = Some(
                        ICalendarEntry::new(ICalendarProperty::ShowWithoutTime)
                            .with_value(value)
                            .import_converted(
                                &[JSCalendarProperty::ShowWithoutTime],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Progress,
                    Value::Element(JSCalendarValue::Progress(value)),
                    ICalendarComponentType::VTodo,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Status)
                            .with_value(match value {
                                JSCalendarProgress::NeedsAction => ICalendarStatus::NeedsAction,
                                JSCalendarProgress::InProcess => ICalendarStatus::InProcess,
                                JSCalendarProgress::Completed => ICalendarStatus::Completed,
                                JSCalendarProgress::Failed => ICalendarStatus::Failed,
                                JSCalendarProgress::Cancelled => ICalendarStatus::Cancelled,
                            })
                            .import_converted(
                                &[JSCalendarProperty::Progress],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Status,
                    Value::Element(JSCalendarValue::EventStatus(value)),
                    ICalendarComponentType::VEvent,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Status)
                            .with_value(match value {
                                JSCalendarEventStatus::Confirmed => ICalendarStatus::Confirmed,
                                JSCalendarEventStatus::Cancelled => ICalendarStatus::Cancelled,
                                JSCalendarEventStatus::Tentative => ICalendarStatus::Tentative,
                            })
                            .import_converted(&[JSCalendarProperty::Status], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::Status | JSCalendarProperty::Progress,
                    Value::Str(text),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Status)
                            .with_value(
                                ICalendarStatus::parse(text.as_bytes())
                                    .map(ICalendarValue::Status)
                                    .unwrap_or_else(|| ICalendarValue::Text(text.into_owned())),
                            )
                            .import_converted(&[JSCalendarProperty::Status], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::Source,
                    Value::Str(text),
                    ICalendarComponentType::VCalendar,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Source)
                            .with_value(Uri::parse(text.into_owned()))
                            .import_converted(&[JSCalendarProperty::Source], &mut root_conversions),
                    );
                }
                (
                    JSCalendarProperty::FreeBusyStatus,
                    Value::Element(JSCalendarValue::FreeBusyStatus(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    component.entries.push(
                        ICalendarEntry::new(ICalendarProperty::Transp)
                            .with_value(match value {
                                JSCalendarFreeBusyStatus::Free => {
                                    ICalendarTransparency::Transparent
                                }
                                JSCalendarFreeBusyStatus::Busy => ICalendarTransparency::Opaque,
                            })
                            .import_converted(
                                &[JSCalendarProperty::FreeBusyStatus],
                                &mut root_conversions,
                            ),
                    );
                }
                (
                    JSCalendarProperty::Entries,
                    Value::Array(items),
                    ICalendarComponentType::VCalendar,
                ) => {
                    for item in items {
                        if let Some(entries) = item.into_object().filter(|entries| {
                            entries
                                .is_type_or_untyped(&[JSCalendarType::Event, JSCalendarType::Task])
                        }) {
                            self.from_jscalendar(
                                State {
                                    tz: None,
                                    tz_end: None,
                                    tz_rid: None,
                                    start: None,
                                    recurrence_id: None,
                                    uid: None,
                                    entries,
                                    is_date: false,
                                    default_component_type: ICalendarComponentType::VEvent,
                                },
                                Some(&mut component),
                                options,
                            );
                        }
                    }
                }

                // Skip previously processed properties
                (
                    JSCalendarProperty::Type
                    | JSCalendarProperty::ICalendar
                    | JSCalendarProperty::Uid
                    | JSCalendarProperty::MainLocationId
                    | JSCalendarProperty::Start
                    | JSCalendarProperty::TimeZone
                    | JSCalendarProperty::EndTimeZone
                    | JSCalendarProperty::RecurrenceIdTimeZone
                    | JSCalendarProperty::Locale
                    | JSCalendarProperty::OrganizerCalendarAddress
                    | JSCalendarProperty::SentBy
                    | JSCalendarProperty::DescriptionContentType
                    | JSCalendarProperty::Version
                    | JSCalendarProperty::Excluded
                    | JSCalendarProperty::RecurrenceOverrides,
                    _,
                    _,
                )
                | (_, Value::Null, _) => {}
                (property, value, _) => {
                    if !property.is_metadata() {
                        component.insert_jsprop(&[property.to_string().as_ref()], value);
                    }
                }
            }
        }

        if !alarms_without_text.is_empty()
            && let Some(text) = component
                .property(&ICalendarProperty::Summary)
                .and_then(|entry| entry.values.first())
                .and_then(ICalendarValue::as_text)
                .or(uid.as_deref())
                .map(str::to_string)
        {
            for alarm_id in alarms_without_text {
                if let Some(alarm) = self.components.get_mut(alarm_id as usize) {
                    alarm.add_alarm_text(&text);
                }
            }
        }

        // Process recurrence overrides
        if let Some(overrides) = overrides {
            let mut exdates = RecurrenceDates::default();
            let mut rdates = RecurrenceDates::default();
            let converted_props = root_conversions.as_ref().map(|conv| {
                conv.converted_props
                    .iter()
                    .filter_map(|(keys, _)| match (keys.first()?, keys.get(1)?) {
                        (
                            Key::Property(JSCalendarProperty::RecurrenceOverrides),
                            Key::Property(JSCalendarProperty::DateTime(dt)),
                        ) => Some(*dt),
                        _ => None,
                    })
                    .collect::<AHashSet<_>>()
            });

            let non_instances = start.map(|start| {
                component.non_recurrence_instances(
                    start,
                    state.tz.unwrap_or_default(),
                    state.is_date,
                    overrides
                        .as_vec()
                        .iter()
                        .filter_map(|(key, patch)| match (key, patch) {
                            (
                                Key::Property(JSCalendarProperty::DateTime(dt)),
                                Value::Object(patch),
                            ) if !patch
                                .contains_true(&Key::Property(JSCalendarProperty::Excluded)) =>
                            {
                                Some(dt.timestamp)
                            }
                            _ => None,
                        }),
                    options.max_expansions,
                    &mut options.unproductive_budget,
                )
            });

            for (key, value) in overrides.into_vec() {
                if options.has_failed() {
                    break;
                }
                let (Key::Property(JSCalendarProperty::DateTime(jsdt)), Value::Object(mut obj)) =
                    (key, value)
                else {
                    continue;
                };
                obj.as_mut_vec().retain(|(key, value)| {
                    !matches!(key, Key::Property(JSCalendarProperty::Excluded))
                        || matches!(value, Value::Bool(true))
                });
                let Some(dt) = jsdt
                    .to_naive_date_time()
                    .and_then(|dt| state.tz.unwrap_or_default().resolve_local_datetime(dt))
                else {
                    continue;
                };
                let has_converted_prop = converted_props
                    .as_ref()
                    .is_some_and(|props| props.contains(&jsdt));

                // RDATE with value type PERIOD
                if has_converted_prop
                    && obj.len() == 1
                    && let Some(Value::Element(JSCalendarValue::Duration(duration))) =
                        obj.lookup(&Key::Property(JSCalendarProperty::Duration))
                {
                    let duration = duration.clone();
                    let mut entry = ICalendarEntry::new(ICalendarProperty::Rdate)
                        .import_converted(
                            &[
                                JSCalendarProperty::RecurrenceOverrides,
                                JSCalendarProperty::DateTime(jsdt),
                            ],
                            &mut root_conversions,
                        )
                        .with_period(dt, duration);
                    entry.name = ICalendarProperty::Rdate;
                    component.entries.push(entry);
                    continue;
                }

                if !obj.is_empty() {
                    if !obj.contains_true(&Key::Property(JSCalendarProperty::Excluded)) {
                        let Some(template) = &mut override_template else {
                            continue;
                        };
                        let instance = template.instance(jsdt);
                        let mut instance = match template.apply_patch(instance, obj) {
                            Ok(instance) => instance,
                            Err(pointer) => {
                                options.reject_patch(jsdt.to_rfc3339(), pointer);
                                if non_instances
                                    .as_ref()
                                    .is_none_or(|keys| keys.contains(&jsdt.timestamp))
                                {
                                    push_recurrence_date(
                                        &mut rdates,
                                        &mut component,
                                        &mut root_conversions,
                                        jsdt,
                                        dt,
                                        has_converted_prop,
                                    );
                                }
                                continue;
                            }
                        };
                        if non_instances
                            .as_ref()
                            .is_some_and(|keys| keys.contains(&jsdt.timestamp))
                        {
                            rdates.push(dt);
                        }
                        if let Some(privacy) = privacy {
                            instance.upsert(
                                Key::Property(JSCalendarProperty::Privacy),
                                Value::Element(JSCalendarValue::Privacy(privacy)),
                            );
                        }
                        self.from_jscalendar(
                            State {
                                tz: None,
                                tz_end: None,
                                tz_rid: state.tz_rid,
                                start: None,
                                recurrence_id: Some(dt),
                                entries: instance,
                                uid: uid.as_deref(),
                                is_date: state.is_date,
                                default_component_type: component.component_type.clone(),
                            },
                            parent_component.as_deref_mut(),
                            options,
                        );
                    } else {
                        // EXDATE
                        if has_converted_prop {
                            exdates.push_converted(
                                &mut component,
                                ICalendarEntry::new(ICalendarProperty::Exdate).import_converted(
                                    &[
                                        JSCalendarProperty::RecurrenceOverrides,
                                        JSCalendarProperty::DateTime(jsdt),
                                    ],
                                    &mut root_conversions,
                                ),
                                dt,
                            );
                        } else {
                            exdates.push(dt);
                        }
                    }
                } else if non_instances
                    .as_ref()
                    .is_none_or(|keys| keys.contains(&jsdt.timestamp))
                {
                    // RDATE
                    push_recurrence_date(
                        &mut rdates,
                        &mut component,
                        &mut root_conversions,
                        jsdt,
                        dt,
                        has_converted_prop,
                    );
                }
            }

            rdates.write_to(&mut component, ICalendarProperty::Rdate, state.is_date);
            exdates.write_to(&mut component, ICalendarProperty::Exdate, state.is_date);
        }

        // Add organizer, if not present in participants
        if let Some(organizer_address) = organizer_address {
            let mut organizer = ICalendarEntry::new(ICalendarProperty::Organizer);
            if let Some(sent_by) = organizer_sent_by
                && !organizer_params
                    .iter()
                    .any(|param| param.name == ICalendarParameterName::SentBy)
            {
                organizer_params.push(ICalendarParameter::sent_by(Uri::parse(
                    sent_by.into_owned(),
                )));
            }
            organizer.params = organizer_params;
            organizer.values = smallvec![ICalendarValue::Uri(Uri::parse(
                organizer_address.into_owned(),
            ))];

            let mut creates_owner = organizer.params.iter().any(|param| {
                matches!(
                    param.name,
                    ICalendarParameterName::Cn
                        | ICalendarParameterName::Email
                        | ICalendarParameterName::SentBy
                        | ICalendarParameterName::Jsid
                )
            }) || !component.entries.iter().any(|entry| {
                entry.name == ICalendarProperty::Attendee
                    && entry.params.iter().any(|param| {
                        matches!(
                            param.value,
                            ICalendarParameterValue::Role(ICalendarParticipationRole::Owner)
                        )
                    })
            });
            let mut restores_owner = false;
            if !creates_owner {
                match organizer_owner {
                    Some(OrganizerOwner::Attendee { entry, position }) => {
                        if let Some(attendee) = component.entries.get_mut(entry) {
                            attendee.params.insert(
                                position.min(attendee.params.len()),
                                ICalendarParameter::role(ICalendarParticipationRole::Owner),
                            );
                            restores_owner = true;
                        }
                    }
                    Some(OrganizerOwner::Organizer(participant_id)) => {
                        organizer
                            .params
                            .push(ICalendarParameter::jsid(participant_id));
                        creates_owner = true;
                    }
                    None => {}
                }
            }

            if let Some((participant_id, roles)) = organizer_unmapped_roles {
                component.insert_roles_jsprop::<I, B>(
                    &participant_id,
                    roles,
                    JSPropSet::of(creates_owner || restores_owner),
                );
            }

            // Restore the parameters of Participant objects that only convert to ORGANIZER
            if let Some(participant_id) = organizer_participant_id {
                organizer = organizer.import_converted_with_id(
                    &[JSCalendarProperty::Participants],
                    &mut root_conversions,
                    Some(participant_id.as_str()),
                );
                organizer.name = ICalendarProperty::Organizer;
            }

            component.entries.push(organizer);
        }

        // Add parent recurrence ID
        if add_recurrence_id && let Some(dt) = state.recurrence_id {
            component.entries.push(
                ICalendarEntry::new(ICalendarProperty::RecurrenceId)
                    .import_converted(&[JSCalendarProperty::RecurrenceId], &mut root_conversions)
                    .with_date(dt, series_is_date),
            );
        }

        // Add showWithoutTime: true unless there are times with DATE types
        if let Some(show_without_time) = show_without_time
            && matches!(
                show_without_time.values.first(),
                Some(ICalendarValue::Boolean(true))
            )
        {
            let mut has_date = false;
            let mut has_date_time = false;
            for entry in component.entries.iter().filter(|entry| {
                matches!(
                    entry.name,
                    ICalendarProperty::Dtstart | ICalendarProperty::Due
                )
            }) {
                if matches!(
                    entry.parameter(&ICalendarParameterName::Value),
                    Some(ICalendarParameterValue::Value(ICalendarValueType::Date))
                ) {
                    has_date = true;
                } else {
                    has_date_time = true;
                }
            }
            if has_date_time {
                component
                    .entries
                    .push(show_without_time.with_value_type(ICalendarValueType::Boolean));
            } else if !has_date {
                component.insert_jsprop::<I, B>(
                    &[JSCalendarProperty::ShowWithoutTime::<I>
                        .to_string()
                        .as_ref()],
                    Value::Bool(true),
                );
            }
        }

        if matches!(
            component.component_type,
            ICalendarComponentType::VEvent | ICalendarComponentType::VTodo
        ) {
            let has_preserved_class = root_conversions.as_mut().is_some_and(|conversions| {
                conversions.retain_class_property(matches!(
                    privacy,
                    None | Some(JSCalendarPrivacy::Private)
                ))
            });

            if !has_preserved_class && let Some(privacy) = privacy {
                component.entries.push(
                    ICalendarEntry::new(ICalendarProperty::Class)
                        .with_value(match privacy {
                            JSCalendarPrivacy::Public => ICalendarClassification::Public,
                            JSCalendarPrivacy::Private => ICalendarClassification::Private,
                            JSCalendarPrivacy::Secret => ICalendarClassification::Confidential,
                        })
                        .import_converted(&[JSCalendarProperty::Privacy], &mut root_conversions),
                );
            }
        }

        if let Some(root_conversions) = root_conversions {
            component = root_conversions.apply_conversions(component, self);
        }

        // The VERSION property is required by RFC 5545 and has no JSCalendar counterpart
        if component.component_type == ICalendarComponentType::VCalendar
            && !component
                .entries
                .iter()
                .any(|entry| entry.name == ICalendarProperty::Version)
        {
            component.entries.push(
                ICalendarEntry::new(ICalendarProperty::Version).with_value("2.0".to_string()),
            );
        }

        if let Some(parent_component) = parent_component {
            parent_component
                .component_ids
                .push(self.push_component(component));
        } else if let Some(root) = self.components.first_mut() {
            *root = component;
        }
    }

    pub fn push_component(&mut self, component: ICalendarComponent) -> u32 {
        let comp_num = self.components.len();
        self.components.push(component);
        comp_num as u32
    }
}

impl ICalendarComponent {
    fn import_links<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        obj: Map<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
        conversion: &mut Option<ConvertedComponent<'_, I, B>>,
        options: &mut ExportContext<'_, B>,
    ) {
        let mut has_url = self
            .entries
            .iter()
            .any(|entry| entry.name == ICalendarProperty::Url);
        let mut has_links = false;
        let mut jsprop_links = Vec::new();

        for (name, value) in obj.into_vec() {
            let Value::Object(mut link) = value else {
                jsprop_links.push((name.into_owned(), value.into_owned()));
                continue;
            };
            let has_blob = matches!(
                link.lookup(&Key::Property(JSCalendarProperty::BlobId)),
                Some(Value::Element(JSCalendarValue::BlobId(_)) | Value::Str(_))
            );
            if has_blob && options.blobs.is_none() {
                jsprop_links.push((name.into_owned(), Value::Object(link).into_owned()));
                continue;
            }
            let has_rel = match link.lookup(&Key::Property(JSCalendarProperty::Rel)) {
                None => false,
                Some(Value::Element(JSCalendarValue::LinkRelation(_))) => true,
                Some(Value::Str(rel)) if rel.is_link_relation_type() => true,
                Some(_)
                    if has_blob
                        || matches!(
                            link.lookup(&Key::Property(JSCalendarProperty::Display)),
                            Some(Value::Object(_))
                        ) =>
                {
                    true
                }
                Some(_) => {
                    jsprop_links.push((name.into_owned(), Value::Object(link).into_owned()));
                    continue;
                }
            };
            let uri = if has_blob {
                None
            } else {
                let Some(href) =
                    link.as_mut_vec()
                        .iter_mut()
                        .find_map(|(key, value)| match (key, value) {
                            (Key::Property(JSCalendarProperty::Href), Value::Str(href)) => {
                                Some(href)
                            }
                            _ => None,
                        })
                else {
                    jsprop_links.push((name.into_owned(), Value::Object(link).into_owned()));
                    continue;
                };
                match Uri::parse(std::mem::take(href).into_owned()) {
                    Uri::Location(text) if text.is_data_uri() => {
                        *href = Cow::Owned(text);
                        jsprop_links.push((name.into_owned(), Value::Object(link).into_owned()));
                        continue;
                    }
                    uri => Some(uri),
                }
            };
            let mut entry = ICalendarEntry::new(ICalendarProperty::Link);
            let mut link_rel = None;
            let mut rel_text = None;
            let mut title = None;
            let mut has_display = false;
            let mut references_key = false;
            let mut blob = None;

            for (sub_property, value) in link.into_vec() {
                match (sub_property, value) {
                    (
                        Key::Property(JSCalendarProperty::Type | JSCalendarProperty::ICalendar),
                        _,
                    ) => {}
                    (
                        Key::Property(JSCalendarProperty::BlobId),
                        Value::Element(JSCalendarValue::BlobId(blob_id)),
                    ) if has_blob => {
                        blob = Some(
                            options
                                .blobs
                                .as_mut()
                                .and_then(|blobs| blobs.resolve(&blob_id))
                                .ok_or_else(|| blob_id.to_string()),
                        );
                    }
                    (Key::Property(JSCalendarProperty::BlobId), Value::Str(text)) if has_blob => {
                        blob = Some(Err(text.into_owned()));
                    }
                    (Key::Property(JSCalendarProperty::Href | JSCalendarProperty::Size), _)
                        if has_blob => {}
                    (Key::Property(JSCalendarProperty::Href), Value::Str(_)) => {}
                    (Key::Property(JSCalendarProperty::ContentType), Value::Str(text)) => {
                        entry
                            .params
                            .push(ICalendarParameter::fmttype(text.into_owned()));
                    }
                    (Key::Property(JSCalendarProperty::Size), Value::Number(number)) => {
                        match number.as_u64() {
                            Some(size) => entry.params.push(ICalendarParameter::size(size)),
                            None => {
                                references_key |= self.insert_jsprop::<I, B>(
                                    &[
                                        JSCalendarProperty::Links::<I>.to_string().as_ref(),
                                        name.to_string().as_ref(),
                                        JSCalendarProperty::Size::<I>.to_string().as_ref(),
                                    ],
                                    Value::Number(number),
                                );
                            }
                        }
                    }
                    (
                        Key::Property(JSCalendarProperty::Rel),
                        Value::Element(JSCalendarValue::LinkRelation(relation)),
                    ) => {
                        entry
                            .params
                            .push(ICalendarParameter::linkrel(ICalendarParameterValue::Null));
                        link_rel = Some(relation);
                    }
                    (Key::Property(JSCalendarProperty::Rel), Value::Str(text)) => {
                        entry
                            .params
                            .push(ICalendarParameter::linkrel(ICalendarParameterValue::Null));
                        rel_text = Some(text.into_owned());
                    }
                    (Key::Property(JSCalendarProperty::Display), Value::Object(obj)) => {
                        has_display = true;
                        let mut vendor_displays = Vec::new();
                        for key in obj.into_expanded_boolean_set() {
                            let value = match key {
                                Key::Property(JSCalendarProperty::LinkDisplay(display)) => {
                                    ICalendarParameterValue::Display(match display {
                                        JSCalendarLinkDisplay::Badge => ICalendarDisplayType::Badge,
                                        JSCalendarLinkDisplay::Graphic => {
                                            ICalendarDisplayType::Graphic
                                        }
                                        JSCalendarLinkDisplay::Fullsize => {
                                            ICalendarDisplayType::Fullsize
                                        }
                                        JSCalendarLinkDisplay::Thumbnail => {
                                            ICalendarDisplayType::Thumbnail
                                        }
                                    })
                                }
                                other if other.to_string().is_param_token() => {
                                    ICalendarParameterValue::Text(other.into_string())
                                }
                                other => {
                                    vendor_displays.push(other.into_owned());
                                    continue;
                                }
                            };
                            entry.params.push(ICalendarParameter::display(value));
                        }
                        if !vendor_displays.is_empty() {
                            references_key = true;
                            let displays = JSPropSet::of(
                                entry.has_parameter(&ICalendarParameterName::Display),
                            );
                            self.insert_set_jsprop::<I, B>(
                                &[
                                    JSCalendarProperty::Links::<I>.to_string().as_ref(),
                                    name.to_string().as_ref(),
                                    JSCalendarProperty::Display::<I>.to_string().as_ref(),
                                ],
                                vendor_displays,
                                displays,
                            );
                        }
                    }
                    (Key::Property(JSCalendarProperty::Title), Value::Str(text)) => {
                        entry
                            .params
                            .push(ICalendarParameter::filename(ICalendarParameterValue::Null));
                        title = Some(text.into_owned());
                    }
                    (sub_property, value) => {
                        references_key |= self.insert_jsprop(
                            &[
                                JSCalendarProperty::Links::<I>.to_string().as_ref(),
                                name.to_string().as_ref(),
                                sub_property.to_string().as_ref(),
                            ],
                            value,
                        );
                    }
                }
            }

            /*
             Which iCalendar property to choose is implementation-specific. As a guideline,
             stopping at the first matching criteria:

             1. Choose ATTACH if the "rel" property value is "enclosure".
             2. Choose IMAGE if the "rel" property value is "icon".
             3. Choose URL if the "rel" property value is "describedby" and no URL property
                is set in the iCalendar component.
             4. Choose LINK otherwise.
            */

            entry.name = match link_rel {
                Some(LinkRelation::Enclosure) => ICalendarProperty::Attach,
                Some(LinkRelation::Icon) => ICalendarProperty::Image,
                Some(LinkRelation::Describedby) => ICalendarProperty::Url,
                None if has_display => ICalendarProperty::Image,
                None if !has_rel => ICalendarProperty::Attach,
                _ => ICalendarProperty::Link,
            };

            let is_uuid5_key = match (blob, uri) {
                (Some(Ok(bytes)), _) => {
                    if !options.embed(&bytes) {
                        continue;
                    }
                    if !matches!(entry.name, ICalendarProperty::Image) {
                        entry.name = ICalendarProperty::Attach;
                    }
                    let is_uuid5_key = name.is_uuid5_of(&bytes);
                    entry.values = smallvec![ICalendarValue::Binary(bytes)];
                    is_uuid5_key
                }
                (Some(Err(blob_id)), _) => {
                    options.fail(ExportError::UnresolvedBlob { blob_id });
                    continue;
                }
                (None, Some(Uri::Data(data))) => {
                    if !options.embed(&data.data) {
                        continue;
                    }
                    let is_uuid5_key = name.is_uuid5_of(&data.data);
                    entry.values = smallvec![ICalendarValue::Uri(Uri::Data(data))];
                    is_uuid5_key
                }
                (None, Some(Uri::Location(href))) => {
                    let is_uuid5_key = name.is_uuid5_of(href.as_bytes());
                    entry.values = smallvec![ICalendarValue::Uri(Uri::Location(href))];
                    is_uuid5_key
                }
                (None, None) => false,
            };

            let link_id = name.into_string();
            let mut entry = entry.import_converted_with_id(
                &[JSCalendarProperty::Links],
                conversion,
                Some(link_id.as_str()),
            );

            // At most one URL property is allowed per component
            if entry.name == ICalendarProperty::Url {
                if !has_url {
                    has_url = true;
                } else {
                    entry.name = ICalendarProperty::Link;
                }
            }

            /*
             The LINKREL parameter is not specified for the ATTACH, IMAGE and URL properties.
             For interoperability, implementations SHOULD NOT set the LINKREL parameter on
             these properties.
            */

            let is_binary = matches!(entry.values.first(), Some(ICalendarValue::Binary(_)));
            let has_linkrel = match entry.name {
                ICalendarProperty::Link => true,
                ICalendarProperty::Attach | ICalendarProperty::Image => {
                    is_binary
                        && !matches!(link_rel, Some(LinkRelation::Enclosure | LinkRelation::Icon))
                }
                _ => false,
            };
            let mut linkrel = match (link_rel, rel_text) {
                (Some(relation), _) if has_linkrel => {
                    Some(ICalendarParameterValue::Linkrel(relation))
                }
                (None, Some(text)) if has_linkrel && text.is_link_relation_type() => {
                    Some(ICalendarParameterValue::Text(text))
                }
                (None, Some(text)) => {
                    references_key |= self.insert_jsprop::<I, B>(
                        &[
                            JSCalendarProperty::Links::<I>.to_string().as_ref(),
                            link_id.as_str(),
                            JSCalendarProperty::Rel::<I>.to_string().as_ref(),
                        ],
                        Value::Str(text.into()),
                    );
                    None
                }
                _ => None,
            };

            if !is_uuid5_key || references_key {
                entry.add_param(ICalendarParameter::jsid(link_id));
            }

            /*
             The "title" property converts to the FILENAME parameter for the ATTACH and IMAGE
             properties. It converts to the LABEL parameter for the LINK and URL properties.
            */

            let title_name = if matches!(
                entry.name,
                ICalendarProperty::Attach | ICalendarProperty::Image
            ) {
                ICalendarParameterName::Filename
            } else {
                ICalendarParameterName::Label
            };
            entry
                .params
                .retain_mut(|param| match (&param.name, &param.value) {
                    (ICalendarParameterName::Linkrel, ICalendarParameterValue::Null) => {
                        linkrel.take().is_some_and(|linkrel| {
                            param.value = linkrel;
                            true
                        })
                    }
                    (ICalendarParameterName::Filename, ICalendarParameterValue::Null) => {
                        title.take().is_some_and(|title| {
                            param.name = title_name.clone();
                            param.value = ICalendarParameterValue::Text(title);
                            true
                        })
                    }
                    _ => true,
                });

            if entry.name == ICalendarProperty::Link
                && !entry.has_parameter(&ICalendarParameterName::Linkrel)
            {
                entry.add_param(ICalendarParameter::linkrel(LinkRelation::Enclosure));
            }

            let entry = if is_binary {
                entry.with_value_type(ICalendarValueType::Binary)
            } else {
                entry.with_uri_value_type()
            };

            has_links = true;
            self.entries.push(entry);
        }

        if has_links {
            for (name, value) in jsprop_links {
                self.insert_jsprop(
                    &[
                        JSCalendarProperty::Links::<I>.to_string().as_ref(),
                        name.to_string().as_ref(),
                    ],
                    value,
                );
            }
        } else if !jsprop_links.is_empty() {
            self.insert_jsprop(
                &[JSCalendarProperty::Links::<I>.to_string().as_ref()],
                Value::Object(Map::from(jsprop_links)),
            );
        }
    }

    fn import_relations<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        obj: Map<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
        conversion: &mut Option<ConvertedComponent<'_, I, B>>,
    ) {
        for (name, value) in obj.into_vec() {
            let mut entry = ICalendarEntry::new(ICalendarProperty::RelatedTo);

            for (sub_property, value) in value.into_expanded_object() {
                match (sub_property, value) {
                    (Key::Property(JSCalendarProperty::Relation), Value::Object(obj)) => {
                        let mut vendor_relations = Vec::new();
                        for key in obj.into_expanded_boolean_set() {
                            let value = match key {
                                Key::Property(JSCalendarProperty::RelationValue(relation)) => {
                                    ICalendarParameterValue::Reltype(match relation {
                                        JSCalendarRelation::First => {
                                            ICalendarRelationshipType::First
                                        }
                                        JSCalendarRelation::Next => ICalendarRelationshipType::Next,
                                        JSCalendarRelation::Child => {
                                            ICalendarRelationshipType::Child
                                        }
                                        JSCalendarRelation::Parent => {
                                            ICalendarRelationshipType::Parent
                                        }
                                        JSCalendarRelation::Snooze => {
                                            ICalendarRelationshipType::Snooze
                                        }
                                    })
                                }
                                other if other.to_string().is_param_token() => {
                                    ICalendarParameterValue::Text(other.into_string())
                                }
                                other => {
                                    vendor_relations.push(other.into_owned());
                                    continue;
                                }
                            };
                            entry.params.push(ICalendarParameter::reltype(value));
                        }
                        if !vendor_relations.is_empty() {
                            let relations = JSPropSet::of(
                                entry.has_parameter(&ICalendarParameterName::Reltype),
                            );
                            self.insert_set_jsprop::<I, B>(
                                &[
                                    JSCalendarProperty::RelatedTo::<I>.to_string().as_ref(),
                                    name.to_string().as_ref(),
                                    JSCalendarProperty::Relation::<I>.to_string().as_ref(),
                                ],
                                vendor_relations,
                                relations,
                            );
                        }
                    }
                    (
                        Key::Property(JSCalendarProperty::Type | JSCalendarProperty::ICalendar),
                        _,
                    ) => {}
                    (sub_property, value) => {
                        self.insert_jsprop(
                            &[
                                JSCalendarProperty::RelatedTo::<I>.to_string().as_ref(),
                                name.to_string().as_ref(),
                                sub_property.to_string().as_ref(),
                            ],
                            value,
                        );
                    }
                }
            }

            self.entries.push(
                entry
                    .with_value(name.into_string())
                    .import_converted(&[JSCalendarProperty::RelatedTo], conversion),
            );
        }
    }

    fn insert_roles_jsprop<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        participant_id: &str,
        roles: Vec<Key<'_, JSCalendarProperty<I>>>,
        set: JSPropSet,
    ) {
        self.insert_set_jsprop::<I, B>(
            &[
                JSCalendarProperty::Participants::<I>.to_string().as_ref(),
                participant_id,
                JSCalendarProperty::Roles::<I>.to_string().as_ref(),
            ],
            roles,
            set,
        );
    }

    fn insert_set_jsprop<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        path: &[&str],
        keys: Vec<Key<'_, JSCalendarProperty<I>>>,
        set: JSPropSet,
    ) {
        if set == JSPropSet::Exists {
            for key in keys {
                self.insert_encoded_jsprop::<I, B>(
                    String::from_pointer(path.iter().copied().chain([key.to_string().as_ref()])),
                    Value::Bool(true),
                );
            }
        } else {
            self.insert_jsprop::<I, B>(
                path,
                Value::Object(Map::from(
                    keys.into_iter()
                        .map(|key| (key, Value::Bool(true)))
                        .collect::<Vec<_>>(),
                )),
            );
        }
    }

    fn insert_jsprop<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        path: &[&str],
        value: Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> bool {
        if path.last().copied() == Some(JSCalendarProperty::<I>::Excluded.to_string().as_ref()) {
            return false;
        }
        self.insert_encoded_jsprop(String::from_pointer(path.iter().copied()), value)
    }

    fn insert_encoded_jsprop<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        pointer: String,
        value: Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> bool {
        let Some(value) = (!value.is_null())
            .then(|| serde_json::to_string(&value).ok())
            .flatten()
        else {
            return false;
        };
        self.entries.push(
            ICalendarEntry::new(ICalendarProperty::Jsprop)
                .with_param(ICalendarParameter::jsptr(pointer))
                .with_value(value),
        );
        true
    }

    fn missing_alarm_text(&self) -> bool {
        match self
            .property(&ICalendarProperty::Action)
            .and_then(|entry| entry.values.first())
        {
            Some(ICalendarValue::Action(ICalendarAction::Display)) => {
                !self.has_property(&ICalendarProperty::Description)
            }
            Some(ICalendarValue::Action(ICalendarAction::Email)) => {
                !self.has_property(&ICalendarProperty::Description)
                    || !self.has_property(&ICalendarProperty::Summary)
            }
            _ => false,
        }
    }

    fn add_alarm_text(&mut self, text: &str) {
        let is_email = matches!(
            self.property(&ICalendarProperty::Action)
                .and_then(|entry| entry.values.first()),
            Some(ICalendarValue::Action(ICalendarAction::Email))
        );
        if !self.has_property(&ICalendarProperty::Description) {
            self.entries.push(
                ICalendarEntry::new(ICalendarProperty::Description)
                    .with_param(ICalendarParameter::derived(true))
                    .with_value(text.to_string()),
            );
        }
        if is_email && !self.has_property(&ICalendarProperty::Summary) {
            self.entries.push(
                ICalendarEntry::new(ICalendarProperty::Summary)
                    .with_param(ICalendarParameter::derived(true))
                    .with_value(text.to_string()),
            );
        }
    }
}

impl ICalendarEntry {
    fn with_value_type(mut self, value_type: ICalendarValueType) -> Self {
        if !self.has_parameter(&ICalendarParameterName::Value) {
            self.params.push(ICalendarParameter::value(value_type));
        }
        self
    }

    fn with_uri_value_type(self) -> Self {
        if matches!(
            self.name,
            ICalendarProperty::Conference
                | ICalendarProperty::Coordinates
                | ICalendarProperty::Image
                | ICalendarProperty::Link
        ) && matches!(self.values.first(), Some(ICalendarValue::Uri(_)))
        {
            self.with_value_type(ICalendarValueType::Uri)
        } else {
            self
        }
    }
}

enum OrganizerOwner {
    Attendee { entry: usize, position: usize },
    Organizer(String),
}

trait ParameterText {
    fn is_param_token(&self) -> bool;
    fn is_data_uri(&self) -> bool;
    fn is_link_relation_type(&self) -> bool;
}

impl ParameterText for str {
    fn is_param_token(&self) -> bool {
        !self.is_empty()
            && self
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
    }

    fn is_data_uri(&self) -> bool {
        self.get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("data:"))
    }

    fn is_link_relation_type(&self) -> bool {
        self.is_param_token()
            || self.split_once(':').is_some_and(|(scheme, _)| {
                scheme
                    .bytes()
                    .next()
                    .is_some_and(|first| first.is_ascii_alphabetic())
                    && scheme
                        .bytes()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'+' | b'-' | b'.'))
            })
    }
}

/// Returns the end of an event that starts at `start` and lasts `duration`.
///
/// RFC 5545 section 3.3.6 keeps the day and week components of a duration
/// nominal, so the end depends on where the start falls.
fn end_after(start: ZonedDateTime, duration: &ICalendarDuration) -> Option<ZonedDateTime> {
    start.checked_add_nominal(duration.to_nominal()?)
}

fn parse_geo(text: Cow<'_, str>) -> Vec<ICalendarValue> {
    if let Some((a, b)) = text
        .strip_prefix("geo:")
        .and_then(|v| v.trim().split_once(','))
        .and_then(|(a, b)| {
            let a = a.parse::<f64>().ok().filter(|a| a.is_finite())?;
            let b = b.parse::<f64>().ok().filter(|b| b.is_finite())?;
            Some((a, b))
        })
    {
        vec![ICalendarValue::Float(a), ICalendarValue::Float(b)]
    } else {
        vec![ICalendarValue::Text(text.into_owned())]
    }
}

fn push_recurrence_date<I: JSCalendarId, B: JSCalendarId>(
    rdates: &mut RecurrenceDates,
    component: &mut ICalendarComponent,
    conversions: &mut Option<ConvertedComponent<'_, I, B>>,
    jsdt: JSCalendarDateTime,
    dt: ZonedDateTime,
    has_converted_prop: bool,
) {
    if has_converted_prop {
        rdates.push_converted(
            component,
            ICalendarEntry::new(ICalendarProperty::Rdate).import_converted(
                &[
                    JSCalendarProperty::RecurrenceOverrides,
                    JSCalendarProperty::DateTime(jsdt),
                ],
                conversions,
            ),
            dt,
        );
    } else {
        rdates.push(dt);
    }
}

#[derive(Default)]
struct RecurrenceDates {
    dates: Vec<ZonedDateTime>,
    converted: Vec<(usize, Vec<ZonedDateTime>)>,
}

impl RecurrenceDates {
    fn push(&mut self, dt: ZonedDateTime) {
        match self.converted.last_mut() {
            Some((_, dates)) => dates.push(dt),
            None => self.dates.push(dt),
        }
    }

    fn push_converted(
        &mut self,
        component: &mut ICalendarComponent,
        entry: ICalendarEntry,
        dt: ZonedDateTime,
    ) {
        self.converted.push((component.entries.len(), vec![dt]));
        component.entries.push(entry);
    }

    fn write_to(
        self,
        component: &mut ICalendarComponent,
        property: ICalendarProperty,
        is_date: bool,
    ) {
        for (index, dates) in self.converted {
            if let Some(entry) = component.entries.get_mut(index) {
                let converted = std::mem::replace(entry, ICalendarEntry::new(property.clone()));
                *entry = converted.with_dates(dates, is_date);
            }
        }
        if !self.dates.is_empty() {
            component
                .entries
                .push(ICalendarEntry::new(property).with_dates(self.dates, is_date));
        }
    }
}

impl ICalendarComponent {
    /// Returns the candidate wall clock readings the rule does not generate.
    ///
    /// The rule is expanded in `tz` rather than as a floating series, because
    /// an UNTIL value is written in UTC: comparing it against a floating
    /// instance would place the bound an offset away from where it belongs and
    /// drop the last instance of the series. Instances are then compared by
    /// wall clock reading, which is the space the candidates are keyed in.
    fn non_recurrence_instances(
        &self,
        start: civil::DateTime,
        tz: Tz,
        is_date: bool,
        candidates: impl Iterator<Item = i64>,
        max_expansions: usize,
        unproductive_budget: &mut usize,
    ) -> AHashSet<i64> {
        let start_timestamp = Offset::UTC
            .to_timestamp(start)
            .map_or(0, |ts| ts.as_second());
        let mut pending = candidates
            .filter(|candidate| *candidate != start_timestamp)
            .collect::<AHashSet<_>>();

        if let Some(rule) = self
            .entries
            .iter()
            .find_map(|entry| match entry.values.first() {
                Some(ICalendarValue::RecurrenceRule(rule))
                    if entry.name == ICalendarProperty::Rrule =>
                {
                    Some(rule.as_ref())
                }
                _ => None,
            })
            && let Some(zoned_start) = tz.from_local(start)
            && let Ok(rule) = RRule::from_ical(rule, zoned_start, is_date)
            && let Some(last) = pending
                .iter()
                .filter(|candidate| **candidate > start_timestamp)
                .max()
                .copied()
        {
            let mut instances = rule.iter().with_unproductive_budget(*unproductive_budget);
            for date in instances.by_ref().take(max_expansions) {
                let date = date.naive_timestamp();
                if date > last || (pending.remove(&date) && pending.is_empty()) {
                    break;
                }
            }
            *unproductive_budget = instances.unproductive_budget();
        }

        pending
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/calcard/src/jscalendar/export/convert/tests.rs"]
mod tests;
