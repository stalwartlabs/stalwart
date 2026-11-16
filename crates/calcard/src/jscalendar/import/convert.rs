/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        blob::{BlobIdGenerator, NoBlobIds},
        export::ImportError,
        jsprop::{
            JSPropPointer,
            text::{IntoAsciiLowercase, PointerString},
        },
        timezone::{Tz, ZonedDateTime},
    },
    icalendar::{timezone::TzResolver, *},
    jscalendar::{
        ext::JSCalendarObjectExt,
        import::{
            EntryState, ImportContext, ImportOptions, State, params::ExtractParams,
            props::ICalendarBinary,
        },
        *,
    },
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use smallvec::{IntoIter, SmallVec};
use std::mem;

impl ICalendar {
    pub fn into_jscalendar<I: JSCalendarId, B: JSCalendarId>(self) -> JSCalendar<'static, I, B> {
        self.convert_jscalendar::<I, B, NoBlobIds>(ImportOptions::default())
            .0
    }

    pub fn into_jscalendar_with<I: JSCalendarId, B: JSCalendarId, G: BlobIdGenerator<B>>(
        self,
        options: ImportOptions<G>,
    ) -> Result<JSCalendar<'static, I, B>, ImportError> {
        match self.convert_jscalendar(options) {
            (js_calendar, false) => Ok(js_calendar),
            (_, true) => Err(ImportError::BlobIdFailed),
        }
    }

    fn convert_jscalendar<I: JSCalendarId, B: JSCalendarId, G: BlobIdGenerator<B>>(
        mut self,
        mut options: ImportOptions<G>,
    ) -> (JSCalendar<'static, I, B>, bool) {
        let tz_resolver = self.build_owned_tz_resolver();
        let mut context = options.context();
        if let Some(blob_ids) = &mut context.blob_ids {
            blob_ids.expect_sizes(self.binary_link_sizes());
        }
        let js_calendar = JSCalendar(
            self.to_jscalendar(&tz_resolver, 0, &mut context)
                .into_root_object(),
        );
        let has_failed = context
            .blob_ids
            .as_ref()
            .is_some_and(|blob_ids| blob_ids.has_failed());

        (js_calendar, has_failed)
    }
}

impl ICalendar {
    #[allow(clippy::wrong_self_convention)]
    pub(super) fn to_jscalendar<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        tz_resolver: &TzResolver<String>,
        component_id: u32,
        options: &mut ImportContext<'_, B>,
    ) -> State<I, B> {
        let mut state = State {
            include_ical_components: options.include_ical_components,
            ..Default::default()
        };

        // Take component
        let Some(component) = self.components.get_mut(component_id as usize) else {
            return state;
        };
        let mut entries = std::mem::take(&mut component.entries);
        state.component_type = component.component_type.clone();

        // Process subcomponents
        let mut group_components = Vec::new();
        let mut alarm_component_ids = Vec::new();
        let mut alarm_with_related = false;
        let mut unsupported_component_ids = Vec::new();
        let mut uid_jsid_mappings = Vec::new();
        let mut has_locations = false;
        let mut task_anchors = None;
        let component_ids = std::mem::take(&mut component.component_ids);
        if state.component_type == ICalendarComponentType::VCalendar {
            options.task_series = self.task_series(&component_ids);
        }

        for component_id in component_ids {
            let Some(component) = self.components.get_mut(component_id as usize) else {
                continue;
            };
            match (&state.component_type, &component.component_type) {
                (
                    ICalendarComponentType::VCalendar,
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    group_components.push(self.to_jscalendar(tz_resolver, component_id, options));
                }
                (
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                    component_type @ (ICalendarComponentType::Participant
                    | ICalendarComponentType::VLocation),
                ) => {
                    let entries = state.get_mut_object_or_insert(match component_type {
                        ICalendarComponentType::Participant => JSCalendarProperty::Participants,
                        ICalendarComponentType::VLocation => {
                            has_locations = true;
                            JSCalendarProperty::Locations
                        }
                        _ => unreachable!(),
                    });
                    let mut subcomponent_state =
                        self.to_jscalendar(tz_resolver, component_id, options);
                    let jsid = subcomponent_state.jsid.take();
                    let subcomponent = subcomponent_state.into_object();
                    entries.insert_named(jsid, subcomponent);
                }
                (
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                    ICalendarComponentType::VAlarm,
                ) => {
                    if state.component_type == ICalendarComponentType::VTodo
                        && !task_anchors
                            .get_or_insert_with(|| TaskAnchors::new(&entries, &options.task_series))
                            .cover(component)
                    {
                        unsupported_component_ids.push(component_id);
                        continue;
                    }
                    let mut jsid = None;

                    for entry in &mut component.entries {
                        match &entry.name {
                            ICalendarProperty::RelatedTo => {
                                alarm_with_related = true;
                            }
                            ICalendarProperty::Jsid => {
                                jsid = std::mem::take(&mut entry.values)
                                    .pop()
                                    .and_then(|v| v.into_text());
                            }
                            _ => {}
                        }
                    }
                    let jsid = jsid.unwrap_or_else(|| {
                        Cow::Owned(format!("k{}", alarm_component_ids.len() + 1))
                    });
                    if let Some(uid) = component.uid() {
                        uid_jsid_mappings.push((uid.to_string(), jsid.clone()));
                    }
                    alarm_component_ids.push((component_id, jsid));
                }
                _ => {
                    unsupported_component_ids.push(component_id);
                }
            }
        }

        // Process alarms
        if !alarm_component_ids.is_empty() {
            for (component_id, jsid) in alarm_component_ids {
                if alarm_with_related
                    && let Some(alarm) = self.components.get_mut(component_id as usize)
                {
                    for entry in &mut alarm.entries {
                        if matches!(entry.name, ICalendarProperty::RelatedTo) {
                            for value in &mut entry.values {
                                if let Some((_, jsid)) = value.as_text().and_then(|uid| {
                                    uid_jsid_mappings.iter().find(|(u, _)| u == uid)
                                }) {
                                    *value = ICalendarValue::Text(jsid.to_string());
                                }
                            }
                        }
                    }
                }

                state
                    .get_mut_object_or_insert(JSCalendarProperty::Alerts)
                    .insert_unchecked(
                        Key::from(jsid),
                        self.to_jscalendar(tz_resolver, component_id, options)
                            .into_object(),
                    );
            }
        }

        // Build group component list
        let mut group_objects = Vec::with_capacity(group_components.len());
        if !group_components.is_empty() {
            // Order by UID placing the main components first
            group_components.sort_by(|a, b| match a.uid.cmp(&b.uid) {
                std::cmp::Ordering::Equal => a
                    .recurrence_id
                    .is_some()
                    .cmp(&b.recurrence_id.is_some())
                    .then_with(|| a.recurrence_sequence().cmp(&b.recurrence_sequence())),
                other => other,
            });
            let mut group_components = group_components.into_iter().peekable();

            // Bundle recurrence overrides together by UID
            while let Some(mut component) = group_components.next() {
                let mut instances = Vec::new();

                if component.uid.is_some() && component.recurrence_id.is_none() {
                    let mut privacy = component.privacy();

                    while let Some(mut recurrence) = group_components
                        .next_if(|r| r.uid == component.uid && r.recurrence_id.is_some())
                    {
                        let Some(recurrence_id) = recurrence.recurrence_id.take() else {
                            continue;
                        };
                        let recurrence_id =
                            JSCalendarDateTime::local_in(recurrence_id, component.tz_start);
                        let _ = recurrence.uid.take();

                        privacy = privacy.max(recurrence.privacy());
                        recurrence.inherit_time_zone(component.tz_start);
                        recurrence.set_is_recurrence_instance();
                        recurrence.remove_forbidden_override_patches();
                        component
                            .recurrence_overrides
                            .push((recurrence_id, recurrence));
                    }

                    if let Some(privacy) = privacy {
                        component.raise_privacy(privacy);
                    }
                } else if component.uid.is_some() {
                    while let Some(instance) =
                        group_components.next_if(|next| next.uid == component.uid)
                    {
                        instances.push(instance);
                    }

                    if let Some(privacy) = instances
                        .iter()
                        .filter_map(State::privacy)
                        .max()
                        .max(component.privacy())
                    {
                        component.raise_privacy(privacy);
                        for instance in &mut instances {
                            instance.raise_privacy(privacy);
                        }
                    }
                }

                component.start_at_recurrence_id();
                if options.return_first {
                    return component;
                }
                group_objects.push(component.into_object());
                group_objects.extend(instances.into_iter().map(|mut instance| {
                    instance.start_at_recurrence_id();
                    instance.into_object()
                }));
            }
        }

        // Build unsupported component jcal
        if options.include_ical_components && !unsupported_component_ids.is_empty() {
            let mut component_iter = unsupported_component_ids.into_iter();
            let mut component_stack = Vec::with_capacity(4);
            let mut components = vec![];

            loop {
                if let Some(component_id) = component_iter.next() {
                    let Some(component) = self.components.get_mut(component_id as usize) else {
                        continue;
                    };

                    let mut entries = Vec::with_capacity(component.entries.len());
                    for entry in std::mem::take(&mut component.entries) {
                        entries.push(EntryState::new(entry, false).into_jcal());
                    }

                    components.push(Value::Array(vec![
                        Value::Str(
                            mem::take(&mut component.component_type)
                                .into_string()
                                .into_ascii_lowercase()
                                .into(),
                        ),
                        Value::Array(entries),
                        Value::Array(vec![]),
                    ]));

                    if !component.component_ids.is_empty()
                        && component_stack.len() + 1 < MAX_ICAL_COMPONENT_DEPTH
                    {
                        component_stack.push((components, component_iter));
                        component_iter = std::mem::take(&mut component.component_ids).into_iter();
                        components = vec![];
                    }
                } else if let Some((mut parent_components, iter)) = component_stack.pop() {
                    if let Some(parent_component) = parent_components
                        .last_mut()
                        .and_then(|v| v.as_array_mut())
                        .and_then(|v| v.last_mut())
                        .and_then(|v| v.as_array_mut())
                    {
                        if !parent_component.is_empty() {
                            parent_component.extend(components);
                        } else {
                            *parent_component = components;
                        }
                    } else {
                        debug_assert!(false, "Invalid component stack state");
                    }
                    components = parent_components;
                    component_iter = iter;
                } else {
                    break;
                }
            }

            state.ical_components = Some(Value::Array(components));
        }

        let mut main_location_id = None;

        entries.sort_by_key(|entry| match &entry.name {
            ICalendarProperty::Dtstart | ICalendarProperty::Jsid => 0,
            ICalendarProperty::RecurrenceId => 1,
            ICalendarProperty::Dtend
            | ICalendarProperty::Due
            | ICalendarProperty::Location
            | ICalendarProperty::Name
            | ICalendarProperty::Attendee => 2,
            _ => 3,
        });
        let mut start_date = None;
        let mut start_is_date = false;
        let mut has_owner = false;
        let mut has_rrule = false;
        let is_todo = state.component_type == ICalendarComponentType::VTodo;

        for entry in entries {
            let mut entry = EntryState::new(entry, state.include_ical_components);
            state.has_end |= match (&entry.entry.name, entry.entry.values.first()) {
                (ICalendarProperty::Dtend, Some(ICalendarValue::PartialDateTime(value))) => {
                    value.has_date()
                }
                (ICalendarProperty::Due, Some(ICalendarValue::PartialDateTime(value))) => {
                    is_todo && value.has_date()
                }
                (ICalendarProperty::Duration, Some(ICalendarValue::Duration(_))) => true,
                _ => false,
            };
            let mut values = std::mem::take(&mut entry.entry.values).into_iter();
            let mut value = values.next();
            let is_link = matches!(
                entry.entry.name,
                ICalendarProperty::Attach | ICalendarProperty::Image
            ) && state.component_type.converts_links();
            let link_value_type = match &value {
                Some(ICalendarValue::Binary(_)) => ICalendarValueType::Binary,
                _ => ICalendarValueType::Uri,
            };
            let mut link_id = (is_link && entry.entry.jsid().is_none())
                .then(|| {
                    value
                        .as_ref()
                        .and_then(ICalendarValue::binary_bytes)
                        .map(uuid5)
                })
                .flatten();

            if let Some(blob_ids) = options.blob_ids.as_mut()
                && is_link
                && let Some(ICalendarBinary {
                    data,
                    content_type: data_content_type,
                    is_data_uri,
                }) = value
                    .take_if(|value| value.is_binary())
                    .and_then(ICalendarValue::into_binary)
            {
                let content_type = entry
                    .entry
                    .parameter(&ICalendarParameterName::Fmttype)
                    .and_then(|param| param.as_text())
                    .or(data_content_type.as_deref());
                match blob_ids.blob_id(data, content_type) {
                    Ok(generated) => {
                        state.map_blob_link(
                            &mut entry,
                            generated,
                            data_content_type,
                            link_id.take(),
                            link_value_type,
                        );
                        state.add_conversion_props(entry);
                        continue;
                    }
                    Err(data) => {
                        value = Some(
                            ICalendarBinary {
                                data,
                                content_type: data_content_type,
                                is_data_uri,
                            }
                            .into_value(),
                        );
                    }
                }
            }

            let media_type = if is_link && link_value_type == ICalendarValueType::Binary {
                if !entry.entry.has_parameter(&ICalendarParameterName::Value) {
                    entry
                        .entry
                        .add_param(ICalendarParameter::value(ICalendarValueType::Binary));
                }
                entry
                    .entry
                    .parameter(&ICalendarParameterName::Fmttype)
                    .and_then(|param| param.as_text())
                    .map(str::to_string)
            } else {
                None
            };

            match (
                &entry.entry.name,
                value.map(|v| v.uri_to_string(media_type)),
                &state.component_type,
            ) {
                (
                    ICalendarProperty::Acknowledged,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VAlarm,
                ) if value.has_date_and_time() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Acknowledged),
                        Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                            value.to_timestamp().unwrap(),
                            false,
                        ))),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Acknowledged);
                }
                (
                    ICalendarProperty::Action,
                    Some(ICalendarValue::Action(
                        value @ (ICalendarAction::Display | ICalendarAction::Email),
                    )),
                    ICalendarComponentType::VAlarm,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Action),
                        Value::Element(JSCalendarValue::AlertAction(match value {
                            ICalendarAction::Display => JSCalendarAlertAction::Display,
                            ICalendarAction::Email => JSCalendarAlertAction::Email,
                            _ => unreachable!(),
                        })),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Action);
                }
                (
                    ICalendarProperty::Attach,
                    Some(ICalendarValue::Text(uri)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::Participant
                    | ICalendarComponentType::VLocation
                    | ICalendarComponentType::VCalendar,
                ) => {
                    entry.set_map_name();
                    state.map_named_entry_with_id(
                        &mut entry,
                        if link_value_type == ICalendarValueType::Binary {
                            &[
                                ICalendarParameterName::Fmttype,
                                ICalendarParameterName::Filename,
                                ICalendarParameterName::Size,
                                ICalendarParameterName::Linkrel,
                                ICalendarParameterName::Jsid,
                            ]
                        } else {
                            &[
                                ICalendarParameterName::Fmttype,
                                ICalendarParameterName::Filename,
                                ICalendarParameterName::Size,
                                ICalendarParameterName::Jsid,
                            ]
                        },
                        JSCalendarProperty::Links,
                        [
                            (
                                Key::Property(JSCalendarProperty::Href),
                                Value::Str(uri.into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Link)),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Rel),
                                Value::Element(JSCalendarValue::LinkRelation(
                                    LinkRelation::Enclosure,
                                )),
                            ),
                        ],
                        link_id,
                    );
                }
                (
                    ICalendarProperty::Image,
                    Some(ICalendarValue::Text(uri)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::Participant
                    | ICalendarComponentType::VLocation
                    | ICalendarComponentType::VCalendar,
                ) => {
                    entry.set_map_name();
                    state.map_named_entry_with_id(
                        &mut entry,
                        if link_value_type == ICalendarValueType::Binary {
                            &[
                                ICalendarParameterName::Display,
                                ICalendarParameterName::Fmttype,
                                ICalendarParameterName::Filename,
                                ICalendarParameterName::Size,
                                ICalendarParameterName::Linkrel,
                                ICalendarParameterName::Jsid,
                            ]
                        } else {
                            &[
                                ICalendarParameterName::Display,
                                ICalendarParameterName::Fmttype,
                                ICalendarParameterName::Filename,
                                ICalendarParameterName::Size,
                                ICalendarParameterName::Jsid,
                            ]
                        },
                        JSCalendarProperty::Links,
                        [
                            (
                                Key::Property(JSCalendarProperty::Href),
                                Value::Str(uri.into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Link)),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Rel),
                                Value::Element(JSCalendarValue::LinkRelation(LinkRelation::Icon)),
                            ),
                        ],
                        link_id,
                    );
                }
                (
                    ICalendarProperty::Link,
                    Some(ICalendarValue::Text(uri)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::Participant
                    | ICalendarComponentType::VLocation
                    | ICalendarComponentType::VCalendar,
                ) => {
                    entry.set_map_name();
                    state.map_named_entry(
                        &mut entry,
                        &[
                            ICalendarParameterName::Fmttype,
                            ICalendarParameterName::Label,
                            ICalendarParameterName::Linkrel,
                            ICalendarParameterName::Jsid,
                        ],
                        JSCalendarProperty::Links,
                        [
                            (
                                Key::Property(JSCalendarProperty::Href),
                                Value::Str(uri.into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Link)),
                            ),
                        ],
                    );
                }
                (
                    ICalendarProperty::Url,
                    Some(ICalendarValue::Text(uri)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::Participant
                    | ICalendarComponentType::VLocation
                    | ICalendarComponentType::VCalendar,
                ) => {
                    entry.set_map_name();
                    state.map_named_entry(
                        &mut entry,
                        &[ICalendarParameterName::Label, ICalendarParameterName::Jsid],
                        JSCalendarProperty::Links,
                        [
                            (
                                Key::Property(JSCalendarProperty::Href),
                                Value::Str(uri.into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Link)),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Rel),
                                Value::Element(JSCalendarValue::LinkRelation(
                                    LinkRelation::Describedby,
                                )),
                            ),
                        ],
                    );
                }
                (
                    ICalendarProperty::Attendee,
                    Some(ICalendarValue::Text(uri)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    let is_task = matches!(&state.component_type, ICalendarComponentType::VTodo);
                    let mut progress = None;

                    for param in &mut entry.entry.params {
                        match (&param.name, &mut param.value) {
                            (
                                ICalendarParameterName::Partstat,
                                ICalendarParameterValue::Partstat(partstat),
                            ) if is_task => {
                                let status = match partstat {
                                    ICalendarParticipationStatus::Completed => {
                                        JSCalendarProgress::Completed
                                    }
                                    ICalendarParticipationStatus::InProcess => {
                                        JSCalendarProgress::InProcess
                                    }
                                    ICalendarParticipationStatus::Failed => {
                                        JSCalendarProgress::Failed
                                    }
                                    _ => {
                                        continue;
                                    }
                                };
                                *partstat = ICalendarParticipationStatus::Accepted;
                                progress = Some((
                                    Key::Property(JSCalendarProperty::Progress),
                                    Value::Element(JSCalendarValue::Progress(status)),
                                ));
                            }
                            (ICalendarParameterName::Role, ICalendarParameterValue::Role(role)) => {
                                has_owner |= matches!(role, ICalendarParticipationRole::Owner);
                            }
                            _ => {}
                        }
                    }

                    state.map_named_entry(
                        &mut entry,
                        &[
                            ICalendarParameterName::Cn,
                            ICalendarParameterName::Cutype,
                            ICalendarParameterName::DelegatedFrom,
                            ICalendarParameterName::DelegatedTo,
                            ICalendarParameterName::Email,
                            ICalendarParameterName::Member,
                            ICalendarParameterName::Partstat,
                            ICalendarParameterName::Role,
                            ICalendarParameterName::Rsvp,
                            ICalendarParameterName::SentBy,
                            ICalendarParameterName::Jsid,
                        ],
                        JSCalendarProperty::Participants,
                        [
                            Some((
                                Key::Property(JSCalendarProperty::CalendarAddress),
                                Value::Str(uri.into()),
                            )),
                            Some((
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Participant)),
                            )),
                            progress,
                        ]
                        .into_iter()
                        .flatten(),
                    );
                }
                (
                    ICalendarProperty::Organizer,
                    Some(ICalendarValue::Text(uri)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::OrganizerCalendarAddress),
                        Value::Str(uri.clone().into()),
                    );

                    if let Some(sent_by) = entry
                        .entry
                        .params
                        .iter()
                        .find(|param| param.name == ICalendarParameterName::SentBy)
                        .and_then(|param| param.value.as_text())
                    {
                        state.entries.insert(
                            Key::Property(JSCalendarProperty::SentBy),
                            Value::Str(sent_by.to_string().into()),
                        );
                    }

                    /*
                     It also converts to a Participant object in the "participants" property,
                     if any of its parameters convert to a Participant object property, or
                     if none of the ATTENDEE properties in the iCalendar component have
                     the ROLE parameter set to "OWNER"

                     An ORGANIZER property, an ATTENDEE property, and a PARTICIPANT component
                     in the same iCalendar component all convert to the same Participant
                     object, if their converted "calendarAddress" property values are equal.
                    */

                    if !has_owner
                        || entry.entry.params.iter().any(|p| {
                            matches!(
                                p.name,
                                ICalendarParameterName::Cn
                                    | ICalendarParameterName::Email
                                    | ICalendarParameterName::SentBy
                                    | ICalendarParameterName::Jsid
                            )
                        })
                    {
                        let participant_id = state.find_participant_by_address(uri.as_ref());

                        state.map_named_entry_with_id(
                            &mut entry,
                            &[
                                ICalendarParameterName::Cn,
                                ICalendarParameterName::Email,
                                ICalendarParameterName::SentBy,
                                ICalendarParameterName::Jsid,
                            ],
                            JSCalendarProperty::Participants,
                            [
                                (
                                    Key::Property(JSCalendarProperty::CalendarAddress),
                                    Value::Str(uri.into()),
                                ),
                                (
                                    Key::Property(JSCalendarProperty::Type),
                                    Value::Element(JSCalendarValue::Type(
                                        JSCalendarType::Participant,
                                    )),
                                ),
                                (
                                    Key::Property(JSCalendarProperty::Roles),
                                    Value::Object(Map::from(vec![(
                                        Key::Property(JSCalendarProperty::ParticipantRole(
                                            JSCalendarParticipantRole::Owner,
                                        )),
                                        Value::Bool(true),
                                    )])),
                                ),
                            ],
                            participant_id,
                        );
                    } else {
                        continue;
                    }
                }
                (
                    ICalendarProperty::CalendarAddress,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::Participant,
                ) => {
                    if state.jsid.is_none() {
                        state.jsid = Some(uuid5(&value));
                    }
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::CalendarAddress),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::CalendarAddress);
                    entry.set_map_name();
                }
                (
                    ICalendarProperty::Categories,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    let obj = state
                        .entries
                        .entry(Key::Property(JSCalendarProperty::Keywords))
                        .or_insert_with(Value::new_object)
                        .as_object_mut()
                        .unwrap();
                    obj.upsert(Key::Owned(value), Value::Bool(true));
                    for value in values {
                        if let Some(value) = value.into_text() {
                            obj.upsert(Key::from(value), Value::Bool(true));
                        }
                    }
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Keywords);
                }
                (
                    ICalendarProperty::Class,
                    Some(ICalendarValue::Classification(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.merge_privacy(match value {
                        ICalendarClassification::Public => JSCalendarPrivacy::Public,
                        ICalendarClassification::Private => JSCalendarPrivacy::Private,
                        ICalendarClassification::Confidential => JSCalendarPrivacy::Secret,
                    });
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Privacy);
                }
                (
                    ICalendarProperty::Class,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.merge_privacy(JSCalendarPrivacy::Private);
                    entry.entry.values = values.prepend(Some(ICalendarValue::Text(value)));
                }
                (
                    ICalendarProperty::Color,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Color),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Color);
                }
                (
                    ICalendarProperty::Concept,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) => {
                    let obj = state
                        .entries
                        .entry(Key::Property(JSCalendarProperty::Categories))
                        .or_insert_with(Value::new_object)
                        .as_object_mut()
                        .unwrap();
                    obj.upsert(Key::Owned(value), Value::Bool(true));
                    for value in values {
                        if let Some(value) = value.into_text() {
                            obj.upsert(Key::from(value), Value::Bool(true));
                        }
                    }
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Categories);
                }
                (
                    ICalendarProperty::Conference,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            ICalendarParameterName::Jsid,
                            ICalendarParameterName::Feature,
                            ICalendarParameterName::Label,
                        ],
                        JSCalendarProperty::VirtualLocations,
                        [
                            (
                                Key::Property(JSCalendarProperty::Uri),
                                Value::Str(value.into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(
                                    JSCalendarType::VirtualLocation,
                                )),
                            ),
                        ],
                    );
                }
                (
                    ICalendarProperty::Coordinates,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VLocation,
                ) => {
                    if state.jsid.is_none() {
                        state.jsid = Some(uuid5(&value));
                    }
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Coordinates),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Coordinates);
                }
                (
                    ICalendarProperty::Geo,
                    Some(ICalendarValue::Float(coord1)),
                    ICalendarComponentType::VLocation,
                ) if !entry.entry.is_derived() => {
                    let coord2 = values.next().and_then(|v| v.as_float()).unwrap_or_default();

                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Coordinates),
                        Value::Str(format!("geo:{coord1},{coord2}").into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Coordinates);
                    entry.set_map_name();
                }
                (
                    ICalendarProperty::Geo,
                    Some(ICalendarValue::Float(coord1)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if !entry.entry.is_derived() => {
                    let coord2 = values.next().and_then(|v| v.as_float()).unwrap_or_default();
                    if entry.entry.jsid().is_none()
                        && let Some(main_location_id) = main_location_id.take()
                    {
                        entry
                            .entry
                            .add_param(ICalendarParameter::jsid(main_location_id));
                    }

                    entry.set_map_name();
                    state.map_named_entry(
                        &mut entry,
                        &[ICalendarParameterName::Jsid],
                        JSCalendarProperty::Locations,
                        [
                            (
                                Key::Property(JSCalendarProperty::Coordinates),
                                Value::Str(format!("geo:{coord1},{coord2}").into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Location)),
                            ),
                        ],
                    );
                }
                (
                    ICalendarProperty::Name,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VLocation,
                ) => {
                    if state.jsid.is_none() {
                        state.jsid = Some(uuid5(&value));
                    }
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Name),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Name);
                    state.set_map_component();
                }
                (
                    ICalendarProperty::Name,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VCalendar,
                )
                | (
                    ICalendarProperty::Summary,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state
                        .entries
                        .extract_params(&mut entry.entry, &[ICalendarParameterName::Language]);
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Title),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Title);
                }
                (
                    ICalendarProperty::Summary,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::Participant,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Name),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Name);
                    state.set_map_component();
                }
                (
                    ICalendarProperty::Location,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    let location_id = if let Some(location_id) = entry.entry.jsid() {
                        main_location_id = Some(location_id.to_string());
                        location_id
                    } else {
                        main_location_id = Some(uuid5(&value));
                        main_location_id.as_deref().unwrap()
                    };

                    if has_locations {
                        state.entries.insert(
                            Key::Property(JSCalendarProperty::MainLocationId),
                            Value::Str(location_id.to_string().into()),
                        );
                    }

                    state.map_named_entry(
                        &mut entry,
                        &[
                            ICalendarParameterName::Jsid,
                            ICalendarParameterName::Derived,
                        ],
                        JSCalendarProperty::Locations,
                        [
                            (
                                Key::Property(JSCalendarProperty::Name),
                                Value::Str(value.into()),
                            ),
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(JSCalendarType::Location)),
                            ),
                        ],
                    );
                }
                (
                    ICalendarProperty::LocationType,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VLocation,
                ) => {
                    let obj = state
                        .entries
                        .entry(Key::Property(JSCalendarProperty::LocationTypes))
                        .or_insert_with(Value::new_object)
                        .as_object_mut()
                        .unwrap();
                    obj.upsert(Key::Owned(value), Value::Bool(true));
                    for value in values {
                        if let Some(value) = value.into_text() {
                            obj.upsert(Key::from(value), Value::Bool(true));
                        }
                    }
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::LocationTypes);
                }

                (
                    ICalendarProperty::LastModified,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VCalendar,
                ) if value.has_date_and_time() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Updated),
                        Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                            value.to_timestamp().unwrap(),
                            false,
                        ))),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Updated);
                }
                (
                    ICalendarProperty::Created,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VCalendar,
                ) if value.has_date_and_time() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Created),
                        Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                            value.to_timestamp().unwrap(),
                            false,
                        ))),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Created);
                }
                (
                    ICalendarProperty::Description,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::Participant
                    | ICalendarComponentType::VCalendar
                    | ICalendarComponentType::VLocation,
                ) if !entry.entry.is_derived() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Description),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Description);
                    if matches!(state.component_type, ICalendarComponentType::Participant) {
                        state.set_map_component();
                    }
                }
                (
                    ICalendarProperty::StyledDescription,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if !entry.entry.is_derived()
                    && entry
                        .entry
                        .parameter(&ICalendarParameterName::Fmttype)
                        .is_none_or(|v| v.as_text().is_some_and(|v| v.starts_with("text/"))) =>
                {
                    state
                        .entries
                        .extract_params(&mut entry.entry, &[ICalendarParameterName::Fmttype]);
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Description),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Description);
                    if !state
                        .entries
                        .contains_key(&Key::Property(JSCalendarProperty::DescriptionContentType))
                    {
                        entry.set_map_name();
                    }
                }
                (
                    ICalendarProperty::Dtstart,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if value.has_date() => {
                    let tzid = entry.entry.tz_id();
                    state.tz_start = tzid.and_then(|v| tz_resolver.resolve(v));
                    if let Some(dt) = value
                        .to_date_time()
                        .and_then(|dt| dt.resolve_with_tz(state.tz_start.unwrap_or_default()))
                    {
                        state.has_dates = true;
                        state.entries.insert(
                            Key::Property(JSCalendarProperty::Start),
                            Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                                dt.naive_timestamp(),
                                true,
                            ))),
                        );

                        // Remove IANA TZ references
                        if tzid.is_some()
                            && state.tz_start.and_then(|tz| tz.name()).as_deref() == tzid
                        {
                            entry
                                .entry
                                .params
                                .retain(|p| p.name != ICalendarParameterName::Tzid);
                        }

                        if !value.has_time() {
                            state.entries.insert(
                                Key::Property(JSCalendarProperty::ShowWithoutTime),
                                Value::Bool(true),
                            );
                        }
                        entry.set_converted_to_property(&JSCalendarProperty::<I>::Start);
                        start_date = Some(dt);
                        start_is_date = !value.has_time();

                        if state.tz_start.is_none() {
                            state.tz_start = dt.timezone().to_resolved();
                        }
                    } else {
                        state.tz_start = None;
                        entry.entry.values =
                            values.prepend(Some(ICalendarValue::PartialDateTime(value)));
                    }
                }
                (
                    ICalendarProperty::Dtend,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VEvent,
                ) if value.has_date() && start_date.or(state.recurrence_id).is_some() => {
                    let tzid = entry.entry.tz_id();
                    state.tz_end = tzid.and_then(|v| tz_resolver.resolve(v)).or(state.tz_start);
                    if let Some((delta, dt, start)) = value
                        .to_date_time()
                        .and_then(|dt| dt.to_date_time_with_tz(state.tz_end.unwrap_or_default()))
                        .and_then(|dt| {
                            let start = start_date.or(state.recurrence_id)?;
                            let delta = dt.signed_duration_since(start).as_secs();
                            (delta > 0).then_some((delta, dt, start))
                        })
                    {
                        state.has_dates = true;

                        /*
                         If the value type of the DTEND property is DATE, then the duration is
                         the number of days or weeks between the DTSTART and DTEND property
                         values. If the value type is DATE-TIME, then the duration is the
                         timespan between the DTSTART and DTEND property values when converted
                         to UTC time.
                        */

                        let days = if !value.has_time() {
                            i64::from(dt.days_since(start))
                        } else {
                            0
                        };
                        let duration = if days > 0 {
                            ICalendarDuration::from_days(days)
                        } else {
                            ICalendarDuration::from_seconds(delta)
                        };

                        state.entries.insert(
                            Key::Property(JSCalendarProperty::Duration),
                            Value::Element(JSCalendarValue::Duration(duration)),
                        );

                        // Remove IANA TZ references
                        if tzid.is_some()
                            && state.tz_end.and_then(|tz| tz.name()).as_deref() == tzid
                        {
                            entry
                                .entry
                                .params
                                .retain(|p| p.name != ICalendarParameterName::Tzid);
                        }

                        if !value.has_time() {
                            state.entries.insert(
                                Key::Property(JSCalendarProperty::ShowWithoutTime),
                                Value::Bool(true),
                            );
                        }
                        entry.set_converted_to_property(&JSCalendarProperty::<I>::Duration);
                        entry.set_map_name();

                        if state.tz_end.is_none() {
                            state.tz_end = dt.timezone().to_resolved();
                        }
                        if state.tz_start.is_none() {
                            state.tz_start = state.tz_end;
                        }
                    } else {
                        state.tz_end = None;
                        entry.entry.values =
                            values.prepend(Some(ICalendarValue::PartialDateTime(value)));
                    }
                }
                (
                    ICalendarProperty::Due,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VTodo,
                ) if value.has_date() => {
                    let tzid = entry.entry.tz_id();
                    let due_tz = tzid.and_then(|v| tz_resolver.resolve(v)).or(state.tz_start);
                    if let Some(dt) = value
                        .to_date_time()
                        .and_then(|dt| dt.to_date_time_with_tz(due_tz.unwrap_or_default()))
                    {
                        // Remove IANA TZ references
                        if tzid.is_some()
                            && (state.tz_start.is_none() || due_tz == state.tz_start)
                            && due_tz.and_then(|tz| tz.name()).as_deref() == tzid
                        {
                            entry
                                .entry
                                .params
                                .retain(|p| p.name != ICalendarParameterName::Tzid);
                        }

                        state.has_dates = true;
                        if state.tz_start.is_none() {
                            state.tz_start = dt.timezone().to_resolved();
                        }

                        state.entries.insert(
                            Key::Property(JSCalendarProperty::Due),
                            Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                                dt.with_timezone(state.tz_start.unwrap_or_default())
                                    .naive_timestamp(),
                                true,
                            ))),
                        );
                        state.due = value.has_time().then_some(dt);

                        if !value.has_time() {
                            state.entries.insert(
                                Key::Property(JSCalendarProperty::ShowWithoutTime),
                                Value::Bool(true),
                            );
                        }

                        entry.set_converted_to_property(&JSCalendarProperty::<I>::Due);
                    } else {
                        entry.entry.values =
                            values.prepend(Some(ICalendarValue::PartialDateTime(value)));
                    }
                }
                (
                    ICalendarProperty::Dtstamp,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if value.has_date_and_time() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Updated),
                        Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                            value.to_timestamp().unwrap_or_default(),
                            false,
                        ))),
                    );

                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Updated);
                }
                (
                    ICalendarProperty::Duration,
                    Some(ICalendarValue::Duration(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Duration),
                        Value::Element(JSCalendarValue::Duration(value)),
                    );

                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Duration);
                }
                (
                    ICalendarProperty::EstimatedDuration,
                    Some(ICalendarValue::Duration(value)),
                    ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::EstimatedDuration),
                        Value::Element(JSCalendarValue::Duration(value)),
                    );

                    entry.set_converted_to_property(&JSCalendarProperty::<I>::EstimatedDuration);
                }
                (
                    ICalendarProperty::RecurrenceId,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if value.has_date() => {
                    let tzid = entry.entry.tz_id();
                    let rid_tz = tzid.and_then(|v| tz_resolver.resolve(v));

                    if let Some(dt) = value
                        .to_date_time()
                        .and_then(|dt| dt.resolve_with_tz(rid_tz.unwrap_or_default()))
                    {
                        state.has_dates = true;
                        state.recurrence_id = Some(dt);
                        state.recurrence_id_is_date = !value.has_time();
                        if start_date.is_none() && !value.has_time() {
                            state.entries.insert(
                                Key::Property(JSCalendarProperty::ShowWithoutTime),
                                Value::Bool(true),
                            );
                        }

                        // Remove IANA TZ references
                        if tzid.is_some() && rid_tz.and_then(|tz| tz.name()).as_deref() == tzid {
                            entry
                                .entry
                                .params
                                .retain(|p| p.name != ICalendarParameterName::Tzid);
                        }
                        if !value.has_time() {
                            entry
                                .entry
                                .params
                                .retain(|p| p.name != ICalendarParameterName::Value);
                        }

                        entry.set_converted_to_property(&JSCalendarProperty::<I>::RecurrenceId);
                    } else {
                        entry.entry.values =
                            values.prepend(Some(ICalendarValue::PartialDateTime(value)));
                    }
                }
                (
                    ICalendarProperty::Rdate,
                    Some(value @ ICalendarValue::Period(_)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if !is_todo || start_date.is_some() => {
                    /*
                     The property value converts to the key in the "recurrenceOverrides"
                     property value, for values of type PERIOD this only applies to the
                     period start. The duration of a PERIOD converts to the PatchObject's
                     "duration" property.
                    */

                    let tz = entry
                        .entry
                        .tz_id()
                        .and_then(|v| tz_resolver.resolve(v))
                        .or(state.tz_start)
                        .unwrap_or_default();

                    // Restore the values, they are preserved as-is unless every period converts
                    entry.entry.values = values.prepend(Some(value));

                    if let Some((start, _)) = entry
                        .entry
                        .values
                        .first()
                        .and_then(|value| period_to_date_time(value, tz))
                        && entry
                            .entry
                            .values
                            .iter()
                            .skip(1)
                            .all(|value| period_to_date_time(value, tz).is_some())
                    {
                        state.has_dates = true;
                        if state.tz_start.is_none() {
                            state.tz_start = start.timezone().to_resolved();
                        }

                        let tz_start = state.tz_start.unwrap_or_default();
                        let overrides_name =
                            JSCalendarProperty::RecurrenceOverrides::<I>.to_string();

                        // Each period converts to its own recurrence override
                        for pos in 0..entry.entry.values.len() {
                            let (dt, duration) =
                                period_to_date_time(&entry.entry.values[pos], tz).unwrap();
                            let key = Key::Property(JSCalendarProperty::DateTime(
                                JSCalendarDateTime::new(
                                    dt.with_timezone(tz_start).naive_timestamp(),
                                    true,
                                ),
                            ));
                            let key_name = key.to_string().into_owned();

                            state.insert_recurrence_override(
                                key,
                                Value::Object(Map::from(vec![(
                                    Key::Property(JSCalendarProperty::Duration),
                                    Value::Element(JSCalendarValue::Duration(duration)),
                                )])),
                            );

                            if pos == 0 {
                                entry.set_map_name();
                                entry.set_converted_to(|| {
                                    String::from_pointer([
                                        overrides_name.as_ref(),
                                        key_name.as_str(),
                                    ])
                                });
                            } else {
                                state.add_period_conversion_prop(format!(
                                    "{}/{}",
                                    overrides_name.as_ref(),
                                    key_name
                                ));
                            }
                        }
                    }
                }
                (
                    ICalendarProperty::Rdate | ICalendarProperty::Exdate,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if value.has_date() && (!is_todo || start_date.is_some()) => {
                    let tzid = entry.entry.tz_id();
                    let tz = tzid.and_then(|v| tz_resolver.resolve(v)).or(state.tz_start);

                    if let Some(dt) = value
                        .to_date_time()
                        .and_then(|dt| dt.resolve_with_tz(tz.unwrap_or_default()))
                    {
                        state.has_dates = true;

                        // Remove IANA TZ references
                        if tzid.is_some()
                            && tz == state.tz_start
                            && tz.and_then(|tz| tz.name()).as_deref() == tzid
                        {
                            entry
                                .entry
                                .params
                                .retain(|p| p.name != ICalendarParameterName::Tzid);
                        }

                        if state.tz_start.is_none() {
                            state.tz_start = dt.timezone().to_resolved();
                        }

                        let overrides = state
                            .entries
                            .entry(Key::Property(JSCalendarProperty::RecurrenceOverrides))
                            .or_insert_with(Value::new_object)
                            .as_object_mut()
                            .unwrap();
                        let value = Value::Object(Map::from(
                            if matches!(entry.entry.name, ICalendarProperty::Exdate) {
                                vec![(
                                    Key::Property(JSCalendarProperty::Excluded),
                                    Value::Bool(true),
                                )]
                            } else {
                                vec![]
                            },
                        ));

                        for (pos, dt) in [dt]
                            .into_iter()
                            .chain(values.filter_map(|v| {
                                v.into_partial_date_time()
                                    .and_then(|dt| dt.to_date_time())
                                    .and_then(|dt| dt.resolve_with_tz(tz.unwrap_or_default()))
                            }))
                            .enumerate()
                        {
                            let key = Key::Property(JSCalendarProperty::DateTime(
                                JSCalendarDateTime::local_in(dt, state.tz_start),
                            ));

                            if pos == 0 {
                                entry.set_converted_to(|| {
                                    String::from_pointer([
                                        JSCalendarProperty::RecurrenceOverrides::<I>
                                            .to_string()
                                            .as_ref(),
                                        key.to_string().as_ref(),
                                    ])
                                });
                            }

                            overrides.upsert(key, value.clone());
                        }
                    } else {
                        entry.entry.values =
                            values.prepend(Some(ICalendarValue::PartialDateTime(value)));
                    }
                }
                (
                    ICalendarProperty::Rrule,
                    Some(ICalendarValue::RecurrenceRule(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if !has_rrule && (!is_todo || start_date.is_some()) => {
                    has_rrule = true;
                    let mut rrule = Map::from(Vec::with_capacity(4));

                    rrule.insert_unchecked(
                        JSCalendarProperty::Frequency,
                        Value::Element(JSCalendarValue::Frequency(value.freq)),
                    );

                    for (key, value) in [
                        (
                            JSCalendarProperty::Until,
                            value
                                .until
                                .as_ref()
                                .and_then(|v| {
                                    v.to_date_time_with_tz(state.tz_start.unwrap_or_default())
                                })
                                .map(|dt| {
                                    Value::Element(JSCalendarValue::DateTime(
                                        JSCalendarDateTime::new(
                                            dt.with_timezone(state.tz_start.unwrap_or_default())
                                                .naive_timestamp(),
                                            true,
                                        ),
                                    ))
                                }),
                        ),
                        (
                            JSCalendarProperty::Count,
                            value.count.map(|v| Value::Number((v as u64).into())),
                        ),
                        (
                            JSCalendarProperty::Interval,
                            value.interval.map(|v| Value::Number((v as u64).into())),
                        ),
                        (
                            JSCalendarProperty::FirstDayOfWeek,
                            value
                                .wkst
                                .map(|v| Value::Element(JSCalendarValue::Weekday(v))),
                        ),
                        (
                            JSCalendarProperty::Rscale,
                            value
                                .rscale
                                .map(|v| Value::Element(JSCalendarValue::CalendarScale(v))),
                        ),
                        (
                            JSCalendarProperty::Skip,
                            value.skip.map(|v| Value::Element(JSCalendarValue::Skip(v))),
                        ),
                    ] {
                        if let Some(value) = value {
                            rrule.insert_unchecked(key, value);
                        }
                    }

                    for (key, values) in [
                        (
                            JSCalendarProperty::BySecond,
                            (!value.bysecond.is_empty()).then(|| {
                                value
                                    .bysecond
                                    .iter()
                                    .map(|&v| Value::Number((v as u64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByMinute,
                            (!value.byminute.is_empty()).then(|| {
                                value
                                    .byminute
                                    .iter()
                                    .map(|&v| Value::Number((v as u64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByHour,
                            (!value.byhour.is_empty()).then(|| {
                                value
                                    .byhour
                                    .iter()
                                    .map(|&v| Value::Number((v as u64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByDay,
                            (!value.byday.is_empty()).then(|| {
                                value
                                    .byday
                                    .iter()
                                    .map(|v| {
                                        Value::Object(Map::from_iter(
                                            [
                                                Some((
                                                    Key::Property(JSCalendarProperty::Day),
                                                    Value::Element(JSCalendarValue::Weekday(
                                                        v.weekday,
                                                    )),
                                                )),
                                                v.ordwk.map(|v| {
                                                    (
                                                        Key::Property(
                                                            JSCalendarProperty::NthOfPeriod,
                                                        ),
                                                        Value::Number((v as i64).into()),
                                                    )
                                                }),
                                            ]
                                            .into_iter()
                                            .flatten(),
                                        ))
                                    })
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByMonthDay,
                            (!value.bymonthday.is_empty()).then(|| {
                                value
                                    .bymonthday
                                    .iter()
                                    .map(|&v| Value::Number((v as i64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByYearDay,
                            (!value.byyearday.is_empty()).then(|| {
                                value
                                    .byyearday
                                    .iter()
                                    .map(|&v| Value::Number((v as i64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByWeekNo,
                            (!value.byweekno.is_empty()).then(|| {
                                value
                                    .byweekno
                                    .iter()
                                    .map(|&v| Value::Number((v as i64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::ByMonth,
                            (!value.bymonth.is_empty()).then(|| {
                                value
                                    .bymonth
                                    .iter()
                                    .map(|&v| Value::Element(JSCalendarValue::Month(v)))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                        (
                            JSCalendarProperty::BySetPosition,
                            (!value.bysetpos.is_empty()).then(|| {
                                value
                                    .bysetpos
                                    .iter()
                                    .map(|&v| Value::Number((v as i64).into()))
                                    .collect::<Vec<_>>()
                            }),
                        ),
                    ] {
                        if let Some(values) = values {
                            rrule.insert_unchecked(key, Value::Array(values));
                        }
                    }

                    state.entries.insert(
                        Key::Property(JSCalendarProperty::RecurrenceRule),
                        Value::Object(rrule),
                    );

                    entry.set_converted_to_property(&JSCalendarProperty::<I>::RecurrenceRule);
                }
                (
                    ICalendarProperty::Method,
                    Some(ICalendarValue::Method(value)),
                    ICalendarComponentType::VCalendar,
                ) => {
                    for object in &mut group_objects {
                        object.as_object_mut().unwrap().insert_unchecked(
                            Key::Property(JSCalendarProperty::Method),
                            Value::Element(JSCalendarValue::Method(value.clone())),
                        );
                    }
                    continue;
                }
                (
                    ICalendarProperty::PercentComplete,
                    Some(ICalendarValue::Integer(value)),
                    ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::PercentComplete),
                        Value::Number(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::PercentComplete);
                }
                (
                    ICalendarProperty::Priority,
                    Some(ICalendarValue::Integer(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Priority),
                        Value::Number(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Priority);
                }
                (
                    ICalendarProperty::Sequence,
                    Some(ICalendarValue::Integer(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Sequence),
                        Value::Number(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Sequence);
                }
                (
                    ICalendarProperty::Version,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VCalendar,
                ) if value == JSCALENDAR_VERSION && entry.entry.params.is_empty() => {
                    continue;
                }
                (
                    ICalendarProperty::Prodid,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VCalendar,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::ProdId),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::ProdId);
                }
                (
                    ICalendarProperty::RelatedTo,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo
                    | ICalendarComponentType::VAlarm,
                ) => {
                    let mut rels: Map<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>> =
                        Map::from(vec![]);
                    for param in std::mem::take(&mut entry.entry.params) {
                        match (param.name, param.value) {
                            (
                                ICalendarParameterName::Reltype,
                                ICalendarParameterValue::Reltype(value),
                            ) => {
                                rels.upsert(
                                    match value {
                                        ICalendarRelationshipType::Child => {
                                            Key::Property(JSCalendarProperty::RelationValue(
                                                JSCalendarRelation::Child,
                                            ))
                                        }
                                        ICalendarRelationshipType::Parent => {
                                            Key::Property(JSCalendarProperty::RelationValue(
                                                JSCalendarRelation::Parent,
                                            ))
                                        }
                                        ICalendarRelationshipType::Snooze => {
                                            Key::Property(JSCalendarProperty::RelationValue(
                                                JSCalendarRelation::Snooze,
                                            ))
                                        }
                                        ICalendarRelationshipType::First => {
                                            Key::Property(JSCalendarProperty::RelationValue(
                                                JSCalendarRelation::First,
                                            ))
                                        }
                                        ICalendarRelationshipType::Next => {
                                            Key::Property(JSCalendarProperty::RelationValue(
                                                JSCalendarRelation::Next,
                                            ))
                                        }
                                        other => Key::Borrowed(other.as_str()),
                                    },
                                    Value::Bool(true),
                                );
                            }
                            (
                                ICalendarParameterName::Reltype,
                                ICalendarParameterValue::Text(value),
                            ) => {
                                rels.upsert(Key::Owned(value), Value::Bool(true));
                            }
                            (name, value) => {
                                entry.entry.params.push(ICalendarParameter { name, value });
                            }
                        }
                    }

                    entry.set_converted_to(|| {
                        String::from_pointer([
                            JSCalendarProperty::RelatedTo::<I>.to_string().as_ref(),
                            value.as_str(),
                        ])
                    });

                    state
                        .entries
                        .entry(Key::Property(JSCalendarProperty::RelatedTo))
                        .or_insert_with(Value::new_object)
                        .as_object_mut()
                        .unwrap()
                        .upsert(
                            Key::Owned(value),
                            Value::Object(Map::from(if !rels.is_empty() {
                                vec![(
                                    Key::Property(JSCalendarProperty::Relation),
                                    Value::Object(rels),
                                )]
                            } else {
                                vec![]
                            })),
                        );
                }
                (
                    ICalendarProperty::ShowWithoutTime,
                    Some(ICalendarValue::Boolean(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) if !is_todo || state.recurrence_id.is_some() || state.has_start_or_due() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::ShowWithoutTime),
                        Value::Bool(value),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::ShowWithoutTime);
                }
                (
                    ICalendarProperty::Status,
                    Some(ICalendarValue::Status(value)),
                    ICalendarComponentType::VEvent,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Status),
                        match value {
                            ICalendarStatus::Tentative => Value::Element(
                                JSCalendarValue::EventStatus(JSCalendarEventStatus::Tentative),
                            ),
                            ICalendarStatus::Confirmed => Value::Element(
                                JSCalendarValue::EventStatus(JSCalendarEventStatus::Confirmed),
                            ),
                            ICalendarStatus::Cancelled => Value::Element(
                                JSCalendarValue::EventStatus(JSCalendarEventStatus::Cancelled),
                            ),
                            other => Value::Str(other.as_str().into()),
                        },
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Status);
                }
                (
                    ICalendarProperty::Status,
                    Some(ICalendarValue::Status(value)),
                    ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Progress),
                        match value {
                            ICalendarStatus::NeedsAction => Value::Element(
                                JSCalendarValue::Progress(JSCalendarProgress::NeedsAction),
                            ),
                            ICalendarStatus::Completed => Value::Element(
                                JSCalendarValue::Progress(JSCalendarProgress::Completed),
                            ),
                            ICalendarStatus::InProcess => Value::Element(
                                JSCalendarValue::Progress(JSCalendarProgress::InProcess),
                            ),
                            ICalendarStatus::Failed => Value::Element(JSCalendarValue::Progress(
                                JSCalendarProgress::Failed,
                            )),
                            ICalendarStatus::Cancelled => Value::Element(
                                JSCalendarValue::Progress(JSCalendarProgress::Cancelled),
                            ),
                            other => Value::Str(other.as_str().into()),
                        },
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Progress);
                }
                (
                    ICalendarProperty::Status,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VCalendar | ICalendarComponentType::VTodo,
                ) => {
                    let prop = if matches!(state.component_type, ICalendarComponentType::VTodo) {
                        JSCalendarProperty::Progress
                    } else {
                        JSCalendarProperty::Status
                    };

                    entry.set_converted_to_property(&prop);
                    state
                        .entries
                        .insert(Key::Property(prop), Value::Str(value.into()));
                }
                (
                    ICalendarProperty::Source,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VCalendar,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Source),
                        Value::Str(value.into()),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Source);
                }
                (
                    ICalendarProperty::Transp,
                    Some(ICalendarValue::Transparency(value)),
                    ICalendarComponentType::VEvent | ICalendarComponentType::VTodo,
                ) => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::FreeBusyStatus),
                        Value::Element(JSCalendarValue::FreeBusyStatus(match value {
                            ICalendarTransparency::Opaque => JSCalendarFreeBusyStatus::Busy,
                            ICalendarTransparency::Transparent => JSCalendarFreeBusyStatus::Free,
                        })),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::FreeBusyStatus);
                }
                (
                    ICalendarProperty::Trigger,
                    Some(ICalendarValue::Duration(value)),
                    ICalendarComponentType::VAlarm,
                ) => {
                    let mut obj = Map::from(vec![
                        (
                            Key::Property(JSCalendarProperty::Type),
                            Value::Element(JSCalendarValue::Type(JSCalendarType::OffsetTrigger)),
                        ),
                        (
                            Key::Property(JSCalendarProperty::Offset),
                            Value::Element(JSCalendarValue::Duration(value)),
                        ),
                    ]);

                    for param in std::mem::take(&mut entry.entry.params) {
                        match (param.name, param.value) {
                            (
                                ICalendarParameterName::Related,
                                ICalendarParameterValue::Related(value),
                            ) => {
                                obj.upsert(
                                    Key::Property(JSCalendarProperty::RelativeTo),
                                    Value::Element(JSCalendarValue::RelativeTo(match value {
                                        ICalendarRelated::Start => JSCalendarRelativeTo::Start,
                                        ICalendarRelated::End => JSCalendarRelativeTo::End,
                                    })),
                                );
                            }
                            (name, value) => {
                                entry.entry.params.push(ICalendarParameter { name, value });
                            }
                        }
                    }

                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Trigger),
                        Value::Object(obj),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Trigger);
                }
                (
                    ICalendarProperty::Trigger,
                    Some(ICalendarValue::PartialDateTime(value)),
                    ICalendarComponentType::VAlarm,
                ) if value.has_date_and_time() => {
                    state.entries.insert(
                        Key::Property(JSCalendarProperty::Trigger),
                        Value::Object(Map::from(vec![
                            (
                                Key::Property(JSCalendarProperty::Type),
                                Value::Element(JSCalendarValue::Type(
                                    JSCalendarType::AbsoluteTrigger,
                                )),
                            ),
                            (
                                Key::Property(JSCalendarProperty::When),
                                Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                                    value.to_timestamp().unwrap_or_default(),
                                    false,
                                ))),
                            ),
                        ])),
                    );
                    entry.set_converted_to_property(&JSCalendarProperty::<I>::Trigger);
                }
                (
                    ICalendarProperty::Uid,
                    Some(ICalendarValue::Text(value)),
                    ICalendarComponentType::VCalendar
                    | ICalendarComponentType::VEvent
                    | ICalendarComponentType::VTodo,
                ) => {
                    state.uid = Some(value);
                    continue;
                }
                (ICalendarProperty::Jsid, Some(ICalendarValue::Text(value)), _) => {
                    state.jsid = Some(value);
                    continue;
                }
                (ICalendarProperty::Jsid, _, _) => {
                    continue;
                }
                (ICalendarProperty::Jsprop, Some(ICalendarValue::Text(value)), component_type) => {
                    let ptr = entry.entry.params.iter().find_map(|param| match param {
                        ICalendarParameter {
                            name: ICalendarParameterName::Jsptr,
                            value: ICalendarParameterValue::Text(ptr),
                        } => Some(JsonPointer::<JSCalendarProperty<I>>::parse(ptr)),
                        _ => None,
                    });
                    let is_calendar_object = matches!(
                        component_type,
                        ICalendarComponentType::VCalendar
                            | ICalendarComponentType::VEvent
                            | ICalendarComponentType::VTodo
                    );
                    if ptr.as_ref().is_some_and(|ptr| {
                        JSCalendarProperty::sets_misplaced_excluded(ptr)
                            || (is_calendar_object
                                && (JSCalendarProperty::is_metadata_pointer(ptr)
                                    || matches!(
                                        ptr.first(),
                                        Some(JsonPointerItem::Key(Key::Property(
                                            JSCalendarProperty::Version
                                        )))
                                    )))
                    }) {
                        continue;
                    }
                    let is_dateless_task =
                        is_todo && state.recurrence_id.is_none() && !state.has_start_or_due();
                    if let Some(ptr) = ptr.filter(|ptr| {
                        ptr.as_slice().iter().all(|item| {
                            matches!(item, JsonPointerItem::Key(_) | JsonPointerItem::Number(_))
                        }) && !(is_dateless_task
                            && matches!(
                                ptr.first(),
                                Some(JsonPointerItem::Key(Key::Property(
                                    JSCalendarProperty::ShowWithoutTime
                                        | JSCalendarProperty::TimeZone
                                )))
                            ))
                    }) && let Some(patch) = ptr.parse_jsprop_value(&value)
                    {
                        state.patch_objects.push((ptr, patch));
                        continue;
                    }
                    entry.entry.values = values.prepend(Some(ICalendarValue::Text(value)));
                }
                (
                    ICalendarProperty::Description | ICalendarProperty::Summary,
                    _,
                    ICalendarComponentType::VAlarm,
                ) if entry.entry.is_derived() => {
                    continue;
                }
                (ICalendarProperty::Begin | ICalendarProperty::End, _, _) => {
                    continue;
                }

                (_, value, _) => {
                    entry.entry.values = values.prepend(value);
                }
            }

            state.add_conversion_props(entry);
        }

        if start_is_date {
            state.default_to_one_day();
        }

        if state.tz_start.is_none()
            && !state
                .entries
                .contains_key(&Key::Property(JSCalendarProperty::Start))
            && !state
                .entries
                .contains_key(&Key::Property(JSCalendarProperty::Due))
        {
            state.tz_start = state
                .recurrence_id
                .and_then(|recurrence_id| recurrence_id.timezone().to_resolved());
        }

        if !group_objects.is_empty() {
            state.entries.insert(
                Key::Property(JSCalendarProperty::Entries),
                Value::Array(group_objects),
            );
        }

        state
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct TaskAnchors {
    start: bool,
    due: bool,
}

impl TaskAnchors {
    fn new(entries: &[ICalendarEntry], series: &[(String, TaskAnchors)]) -> Self {
        let mut has_start = false;
        let mut has_due = false;
        let mut has_duration = false;
        let mut has_recurrence_id = false;
        let mut uid = None;
        for entry in entries {
            let converts = || {
                matches!(
                    entry.values.first(),
                    Some(ICalendarValue::PartialDateTime(value))
                        if value.has_date() && value.to_date_time().is_some()
                )
            };
            match entry.name {
                ICalendarProperty::Dtstart => has_start |= converts(),
                ICalendarProperty::Due => has_due |= converts(),
                ICalendarProperty::RecurrenceId => has_recurrence_id |= converts(),
                ICalendarProperty::Duration => {
                    has_duration |=
                        matches!(entry.values.first(), Some(ICalendarValue::Duration(_)));
                }
                ICalendarProperty::Uid => {
                    uid = entry.values.first().and_then(ICalendarValue::as_text);
                }
                _ => {}
            }
        }
        if !has_recurrence_id {
            return Self {
                start: has_start,
                due: has_due,
            };
        }
        match uid.and_then(|uid| {
            series
                .binary_search_by(|(series_uid, _)| series_uid.as_str().cmp(uid))
                .ok()
                .and_then(|position| series.get(position))
        }) {
            Some((_, master)) => Self {
                start: has_start || master.start,
                due: has_due || (master.due && !has_start && !has_duration),
            },
            None => Self {
                start: has_start || !has_due,
                due: has_due,
            },
        }
    }

    fn cover(self, alarm: &ICalendarComponent) -> bool {
        alarm
            .entries
            .iter()
            .filter(|entry| {
                entry.name == ICalendarProperty::Trigger
                    && matches!(entry.values.first(), Some(ICalendarValue::Duration(_)))
            })
            .all(|trigger| {
                let related = trigger.params.iter().rev().find_map(|param| match param {
                    ICalendarParameter {
                        name: ICalendarParameterName::Related,
                        value: ICalendarParameterValue::Related(related),
                    } => Some(related),
                    _ => None,
                });
                match related {
                    Some(ICalendarRelated::End) => self.due,
                    _ => self.start,
                }
            })
    }
}

impl ICalendar {
    fn task_series(&self, component_ids: &[u32]) -> Vec<(String, TaskAnchors)> {
        let tasks = || {
            component_ids
                .iter()
                .filter_map(|id| self.components.get(*id as usize))
                .filter(|component| component.component_type == ICalendarComponentType::VTodo)
        };
        if !tasks().any(|task| task.has_property(&ICalendarProperty::RecurrenceId)) {
            return Vec::new();
        }
        let mut series = tasks()
            .filter(|task| !task.has_property(&ICalendarProperty::RecurrenceId))
            .filter_map(|task| {
                Some((
                    task.uid()?.to_string(),
                    TaskAnchors::new(&task.entries, &[]),
                ))
            })
            .collect::<Vec<_>>();
        series.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        series
    }
}

trait PrependValue {
    fn prepend(self, first: Option<ICalendarValue>) -> SmallVec<[ICalendarValue; 1]>;
}

impl PrependValue for IntoIter<[ICalendarValue; 1]> {
    fn prepend(self, first: Option<ICalendarValue>) -> SmallVec<[ICalendarValue; 1]> {
        let mut values = SmallVec::with_capacity(usize::from(first.is_some()) + self.len());
        values.extend(first);
        values.extend(self);
        values
    }
}

fn period_to_date_time(
    value: &ICalendarValue,
    tz: Tz,
) -> Option<(ZonedDateTime, ICalendarDuration)> {
    match value {
        ICalendarValue::Period(period) => match period.as_ref() {
            ICalendarPeriod::Range { start, end } => {
                let start = start.to_date_time()?.to_date_time_with_tz(tz)?;
                let end = end.to_date_time()?.to_date_time_with_tz(tz)?;

                Some((
                    start,
                    ICalendarDuration::from_seconds(end.signed_duration_since(start).as_secs()),
                ))
            }
            ICalendarPeriod::Duration { start, duration } => Some((
                start.to_date_time()?.to_date_time_with_tz(tz)?,
                duration.clone(),
            )),
        },
        _ => None,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/calcard/src/jscalendar/import/convert/tests.rs"]
mod tests;
