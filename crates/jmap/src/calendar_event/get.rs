/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{calendar_event::CalendarSyntheticId, changes::state::JmapCacheState};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarParameter,
        ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole,
        ICalendarProperty, ICalendarValue,
    },
    jscalendar::{
        JSCalendarDateTime, JSCalendarProperty, JSCalendarValue, import::ConversionOptions,
    },
};
use chrono::DateTime;
use common::{Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        CalendarEvent, EVENT_DRAFT, EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS, EVENT_INVITE_SELF,
        PREF_USE_DEFAULT_ALERTS, expand::CalendarEventExpansion,
    },
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::{JmapObjectId, calendar_event},
    request::{IntoValid, reference::MaybeResultReference},
};
use jmap_tools::{Key, Map, Value};
use std::{str::FromStr, sync::Arc};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    id::Id,
};

pub trait CalendarEventGet: Sync + Send {
    fn calendar_event_get(
        &self,
        request: GetRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<calendar_event::CalendarEvent>>> + Send;
}

impl CalendarEventGet for Server {
    async fn calendar_event_get(
        &self,
        mut request: GetRequest<calendar_event::CalendarEvent>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<calendar_event::CalendarEvent>> {
        let return_all_properties = request
            .properties
            .as_ref()
            .is_none_or(|v| matches!(v, MaybeResultReference::Value(v) if v.is_empty()));
        let properties = request.unwrap_properties(&[]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let calendar_event_ids = if access_token.is_member(account_id) {
            cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            cache.shared_items(access_token, [Acl::ReadItems], true)
        };
        let (mut ids, has_synthetic_ids) = if let Some(rr) = request.ids.take() {
            let rr = rr.unwrap();
            if rr.len() > self.core.jmap.get_max_objects {
                return Err(trc::JmapEvent::RequestTooLarge.into_err());
            }
            let mut ids = Vec::with_capacity(rr.len());
            let mut has_synthetic_ids = false;

            for id in rr.into_valid() {
                has_synthetic_ids |= id.is_synthetic();
                ids.push(id);
            }

            (ids, has_synthetic_ids)
        } else {
            (
                calendar_event_ids
                    .iter()
                    .take(self.core.jmap.get_max_objects)
                    .map(Into::into)
                    .collect::<Vec<_>>(),
                false,
            )
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };
        let mut return_converted_props = !return_all_properties;
        let mut return_is_origin = false;
        let mut return_utc_dates = false;

        let (jmap_properties, jscal_properties) = if !return_all_properties {
            let mut jmap_properties = Vec::with_capacity(4);
            let mut jscal_properties = Vec::with_capacity(properties.len());

            for property in properties {
                match property {
                    JSCalendarProperty::Id
                    | JSCalendarProperty::BaseEventId
                    | JSCalendarProperty::CalendarIds
                    | JSCalendarProperty::IsDraft
                    | JSCalendarProperty::UseDefaultAlerts
                    | JSCalendarProperty::MayInviteSelf
                    | JSCalendarProperty::MayInviteOthers
                    | JSCalendarProperty::HideAttendees => {
                        jmap_properties.push(property);
                    }
                    JSCalendarProperty::UtcStart | JSCalendarProperty::UtcEnd => {
                        return_utc_dates = true;
                        jmap_properties.push(property);
                    }
                    JSCalendarProperty::IsOrigin => {
                        return_is_origin = true;
                    }
                    _ => {
                        if matches!(property, JSCalendarProperty::ICalendar) {
                            return_converted_props = true;
                        }

                        jscal_properties.push(property);
                    }
                }
            }
            (jmap_properties, jscal_properties)
        } else {
            return_is_origin = true;
            (
                vec![
                    JSCalendarProperty::Id,
                    JSCalendarProperty::CalendarIds,
                    JSCalendarProperty::IsDraft,
                    JSCalendarProperty::IsOrigin,
                ],
                vec![],
            )
        };
        let return_is_origin = if return_is_origin {
            if access_token.primary_id() == account_id {
                OriginAddresses::Ref(access_token)
            } else {
                OriginAddresses::Owned(self.get_access_token(account_id).await?)
            }
        } else {
            OriginAddresses::None
        };

        // Sort by baseId
        let mut original_order: Option<AHashMap<Id, usize>> = None;
        if has_synthetic_ids {
            original_order = Some(ids.iter().enumerate().map(|(i, id)| (*id, i)).collect());
            ids.sort_unstable_by_key(|id| id.document_id());
        }
        let mut ids = ids.into_iter().peekable();

        // Process arguments
        let override_range = if request.arguments.recurrence_overrides_after.is_some()
            || request.arguments.recurrence_overrides_before.is_some()
        {
            let after = request
                .arguments
                .recurrence_overrides_after
                .map(|v| v.timestamp)
                .unwrap_or(i64::MIN);
            let before = request
                .arguments
                .recurrence_overrides_before
                .map(|v| v.timestamp)
                .unwrap_or(i64::MAX);
            if after < before {
                Some(after..before)
            } else {
                None
            }
        } else {
            None
        };
        let default_tz = request.arguments.time_zone.unwrap_or(Tz::UTC);
        let reduce_participants = request.arguments.reduce_participants.unwrap_or(false);

        'outer: while let Some(id) = ids.next() {
            // Obtain the calendar_event object
            let document_id = id.document_id();
            if !calendar_event_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }

            let Some(_calendar_event) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await?
            else {
                response.not_found.push(id);
                continue;
            };
            let mut calendar_event = _calendar_event
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            // Extract expansion ids from synthetic ids
            let mut expansion_ids = AHashSet::new();
            let mut include_base_event = false;
            if let Some(expansion_id) = id.expansion_id() {
                expansion_ids.insert(expansion_id);
            } else {
                include_base_event = true;
            }
            while let Some(next_id) = ids.peek() {
                if next_id.document_id() == document_id {
                    if let Some(expansion_id) = next_id.expansion_id() {
                        expansion_ids.insert(expansion_id);
                    } else {
                        include_base_event = true;
                    }
                    ids.next();
                } else {
                    break;
                }
            }

            // Reduce participants
            if reduce_participants {
                for component in &mut calendar_event.data.event.components {
                    if component.component_type.is_scheduling_object() {
                        component.entries.retain(|entry| match &entry.name {
                            ICalendarProperty::Attendee => {
                                entry.parameters(&ICalendarParameterName::Role).any(|role| {
                                    matches!(
                                        role,
                                        ICalendarParameterValue::Role(
                                            ICalendarParticipationRole::Owner,
                                        ),
                                    )
                                }) || entry.calendar_address().is_some_and(|addr| {
                                    access_token
                                        .emails
                                        .iter()
                                        .any(|a| a.eq_ignore_ascii_case(addr))
                                })
                            }
                            _ => true,
                        });
                    }
                }
            }

            // Expand synthetic ids
            let mut results = Vec::with_capacity(expansion_ids.len() + 1);
            if !expansion_ids.is_empty() {
                let ical = &calendar_event.data.event;
                if let Some(expansions) = calendar_event
                    .data
                    .expand_from_ids(&mut expansion_ids, default_tz)
                {
                    for expansion in expansions {
                        if !expansion.is_valid() {
                            response.not_found.push(<Id as CalendarSyntheticId>::new(
                                expansion.expansion_id,
                                document_id,
                            ));
                            continue 'outer;
                        }
                        let component = &ical.components[expansion.comp_id as usize];
                        let is_recurrent = component.is_recurrent();
                        let is_recurrent_or_override =
                            is_recurrent || component.is_recurrence_override();
                        let mut has_duration = false;
                        let component_ids = &component.component_ids;
                        let mut tz = None;
                        let mut component = ICalendarComponent {
                            component_type: component.component_type.clone(),
                            component_ids: Vec::new(),
                            entries: component
                                .entries
                                .iter()
                                .filter(|entry| match &entry.name {
                                    ICalendarProperty::Dtstart
                                    | ICalendarProperty::Dtend
                                    | ICalendarProperty::Exdate
                                    | ICalendarProperty::Exrule
                                    | ICalendarProperty::Rdate
                                    | ICalendarProperty::Rrule
                                    | ICalendarProperty::RecurrenceId => {
                                        if let Some(new_tz) = entry
                                            .tz_id()
                                            .and_then(|id| Tz::from_str(id).ok())
                                            .filter(|tz| *tz != Tz::UTC)
                                        {
                                            tz = Some(new_tz);
                                        }
                                        false
                                    }
                                    ICalendarProperty::Due
                                    | ICalendarProperty::Completed
                                    | ICalendarProperty::Created => is_recurrent,
                                    ICalendarProperty::Duration => {
                                        has_duration = true;
                                        true
                                    }
                                    _ => true,
                                })
                                .cloned()
                                .collect::<Vec<_>>(),
                        };

                        let tz = tz.unwrap_or(default_tz);
                        let tz_name = tz.name().unwrap_or_default().to_string();

                        let start_timestamp = DateTime::from_timestamp(expansion.start, 0)
                            .map(|dt| dt.with_timezone(&tz))
                            .map(|dt| dt.naive_local())
                            .map(|dt| dt.and_utc().timestamp())
                            .unwrap_or(expansion.start);

                        let end_timestamp = DateTime::from_timestamp(expansion.end, 0)
                            .map(|dt| dt.with_timezone(&tz))
                            .map(|dt| dt.naive_local())
                            .map(|dt| dt.and_utc().timestamp())
                            .unwrap_or(expansion.end);

                        component.entries.push(ICalendarEntry {
                            name: ICalendarProperty::Dtstart,
                            params: vec![ICalendarParameter::tzid(tz_name.clone())],
                            values: vec![ICalendarValue::PartialDateTime(Box::new(
                                PartialDateTime::from_naive_timestamp(start_timestamp),
                            ))],
                        });

                        if is_recurrent_or_override {
                            component.entries.push(ICalendarEntry {
                                name: ICalendarProperty::RecurrenceId,
                                params: vec![ICalendarParameter::tzid(tz_name.clone())],
                                values: vec![ICalendarValue::PartialDateTime(Box::new(
                                    PartialDateTime::from_naive_timestamp(start_timestamp),
                                ))],
                            });
                        }

                        if !has_duration {
                            component.entries.push(ICalendarEntry {
                                name: ICalendarProperty::Dtend,
                                params: vec![ICalendarParameter::tzid(tz_name)],
                                values: vec![ICalendarValue::PartialDateTime(Box::new(
                                    PartialDateTime::from_naive_timestamp(end_timestamp),
                                ))],
                            });
                        }

                        let mut expanded_ical = ICalendar {
                            components: vec![
                                ICalendarComponent {
                                    component_type: ICalendarComponentType::VCalendar,
                                    entries: vec![],
                                    component_ids: vec![1],
                                },
                                component,
                            ],
                        };

                        if !component_ids.is_empty() {
                            for component_id in component_ids {
                                let mut sub_component =
                                    ical.components[*component_id as usize].clone();
                                sub_component.component_ids.clear();
                                let component_id = expanded_ical.components.len() as u32;
                                expanded_ical.components.push(sub_component);
                                expanded_ical.components[1].component_ids.push(component_id);
                            }
                        }

                        results.push((
                            <Id as CalendarSyntheticId>::new(expansion.expansion_id, document_id),
                            expanded_ical,
                            expansion,
                        ));
                    }
                } else {
                    response
                        .not_found
                        .extend(expansion_ids.into_iter().map(|expansion_id| {
                            <Id as CalendarSyntheticId>::new(expansion_id, document_id)
                        }));
                    continue;
                }
            }

            if include_base_event {
                let mut event = std::mem::take(&mut calendar_event.data.event);

                // Obtain UTC start/end if requested
                let expansion = if return_utc_dates
                    && let Some(expansion) = event
                        .components
                        .iter()
                        .position(|c| {
                            c.component_type.is_scheduling_object() && !c.is_recurrence_override()
                        })
                        .and_then(|comp_id| {
                            calendar_event
                                .data
                                .expand_single(comp_id as u32, default_tz)
                        }) {
                    expansion
                } else {
                    CalendarEventExpansion::default()
                };

                // Remove recurrence ids
                if let Some(range) = &override_range {
                    let remove_ids = event
                        .components
                        .iter()
                        .enumerate()
                        .filter_map(|(comp_id, c)| {
                            if c.is_recurrence_override()
                                && let Some(timestamp) = c
                                    .property(&ICalendarProperty::RecurrenceId)
                                    .and_then(|p| p.values.first())
                                    .and_then(|v| v.as_partial_date_time())
                                    .and_then(|v| v.to_date_time())
                                    .and_then(|v| v.to_date_time_with_tz(default_tz))
                                    .map(|v| v.timestamp())
                                && !range.contains(&timestamp)
                            {
                                Some(comp_id as u32)
                            } else {
                                None
                            }
                        })
                        .collect::<AHashSet<_>>();
                    if !remove_ids.is_empty() {
                        for component in &mut event.components {
                            component
                                .component_ids
                                .retain(|id| !remove_ids.contains(id));
                        }
                    }
                }

                results.push((Id::from(document_id), event, expansion));
            }

            for (id, ical, expansion) in results {
                let is_origin = return_is_origin.addresses().is_some_and(|addresses| {
                    ical.components
                        .iter()
                        .find(|c| c.component_type.is_scheduling_object())
                        .and_then(|c| c.property(&ICalendarProperty::Organizer))
                        .and_then(|v| v.calendar_address())
                        .is_none_or(|v| addresses.iter().any(|a| a.eq_ignore_ascii_case(v)))
                });

                let jscal = ical
                    .into_jscalendar_with_opt::<Id, BlobId>(
                        ConversionOptions::default()
                            .include_ical_components(return_converted_props)
                            .return_first(true),
                    )
                    .into_inner();
                let mut result = if return_all_properties {
                    jscal.into_object().unwrap()
                } else {
                    Map::from_iter(jscal.into_expanded_object().filter(|(k, _)| {
                        k.as_property()
                            .is_some_and(|p| jscal_properties.contains(p))
                    }))
                };

                for property in &jmap_properties {
                    match property {
                        JSCalendarProperty::Id => {
                            result.insert_unchecked(
                                JSCalendarProperty::Id,
                                Value::Element(JSCalendarValue::Id(id)),
                            );
                        }
                        JSCalendarProperty::BaseEventId => {
                            result.insert_unchecked(
                                JSCalendarProperty::BaseEventId,
                                Value::Element(JSCalendarValue::Id(id.document_id().into())),
                            );
                        }
                        JSCalendarProperty::CalendarIds => {
                            let mut obj = Map::with_capacity(calendar_event.names.len());
                            for id in calendar_event.names.iter() {
                                obj.insert_unchecked(
                                    JSCalendarProperty::IdValue(Id::from(id.parent_id)),
                                    true,
                                );
                            }
                            result.insert_unchecked(
                                JSCalendarProperty::CalendarIds,
                                Value::Object(obj),
                            );
                        }
                        JSCalendarProperty::IsDraft => {
                            result.insert_unchecked(
                                JSCalendarProperty::IsDraft,
                                Value::Bool(calendar_event.flags & EVENT_DRAFT != 0),
                            );
                        }
                        JSCalendarProperty::IsOrigin => {
                            result.insert_unchecked(
                                JSCalendarProperty::IsOrigin,
                                Value::Bool(is_origin),
                            );
                        }
                        JSCalendarProperty::MayInviteSelf => {
                            result.insert_unchecked(
                                JSCalendarProperty::MayInviteSelf,
                                Value::Bool(calendar_event.flags & EVENT_INVITE_SELF != 0),
                            );
                        }
                        JSCalendarProperty::MayInviteOthers => {
                            result.insert_unchecked(
                                JSCalendarProperty::MayInviteOthers,
                                Value::Bool(calendar_event.flags & EVENT_INVITE_OTHERS != 0),
                            );
                        }
                        JSCalendarProperty::HideAttendees => {
                            result.insert_unchecked(
                                JSCalendarProperty::HideAttendees,
                                Value::Bool(calendar_event.flags & EVENT_HIDE_ATTENDEES != 0),
                            );
                        }

                        JSCalendarProperty::UtcStart => {
                            result.insert_unchecked(
                                JSCalendarProperty::UtcStart,
                                Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                                    expansion.start,
                                    false,
                                ))),
                            );
                        }
                        JSCalendarProperty::UtcEnd => {
                            result.insert_unchecked(
                                JSCalendarProperty::UtcEnd,
                                Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                                    expansion.end,
                                    false,
                                ))),
                            );
                        }
                        JSCalendarProperty::UseDefaultAlerts => {
                            result.insert_unchecked(
                                JSCalendarProperty::UseDefaultAlerts,
                                Value::Bool(
                                    calendar_event
                                        .preferences(access_token)
                                        .is_none_or(|v| v.flags & PREF_USE_DEFAULT_ALERTS != 0),
                                ),
                            );
                        }

                        _ => {}
                    }
                }

                response.list.push(result.into());
            }
        }

        // Restore original order
        if let Some(original_order) = original_order {
            response.list.sort_by_key(|obj| {
                obj.as_object()
                    .unwrap()
                    .get(&Key::Property(JSCalendarProperty::<Id>::Id))
                    .and_then(|v| v.as_element())
                    .and_then(|v: &JSCalendarValue<Id, BlobId>| v.as_id())
                    .and_then(|id| original_order.get(&id))
                    .cloned()
                    .unwrap_or(usize::MAX)
            });
        }

        Ok(response)
    }
}

enum OriginAddresses<'x> {
    Owned(Arc<AccessToken>),
    Ref(&'x AccessToken),
    None,
}

impl<'x> OriginAddresses<'x> {
    fn addresses(&self) -> Option<&[String]> {
        match self {
            OriginAddresses::Owned(t) if !t.emails.is_empty() => Some(&t.emails),
            OriginAddresses::Ref(t) if !t.emails.is_empty() => Some(&t.emails),
            _ => None,
        }
    }
}
