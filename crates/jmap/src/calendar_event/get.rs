/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::blob::embedded::{EmbeddedBlobIds, import_error};
use crate::{
    calendar_event::{CalendarSyntheticId, EventMap, EventValue, is_origin},
    changes::state::JmapCacheState,
};
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarDuration, ICalendarEntry,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarValue, ICalendarValueType,
    },
    jscalendar::{
        JSCalendar, JSCalendarDateTime, JSCalendarProperty, JSCalendarValue, import::ImportOptions,
    },
};
use common::{
    CachedName, Server,
    auth::{AccessToken, AccountInfo},
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ArchivedCalendarEventContent, CalendarEventContent, CalendarEventData, EVENT_DRAFT,
        EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS, EVENT_INVITE_SELF, EVENT_SECRET,
        alerts::{DefaultAlertsResolver, DefaultAlertsView, ICalendarDefaultAlerts},
        expand::{CalendarEventExpansion, SECONDS_PER_DAY, resolve_local},
        identity::{CalendarAddresses, EventOwnership, ParticipantIdentityAddresses},
        participants::VisibleParticipants,
        privacy::{EventPrivacy, ICalendarPrivacy},
        user::{ICalendarUserData, UserDataEntry, UserDataView},
    },
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::calendar_event,
    request::IntoValid,
};
use jmap_tools::{Key, Map, Value};
use std::{ops::Range, str::FromStr};
use store::{
    ValueKey,
    ahash::AHashSet,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::BlobId,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
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
        let return_all_properties = request.properties.is_none();
        let properties = request.unwrap_properties(&[]);
        let account_id = request.account_id.document_id();
        let default_tz = request.arguments.resolved_time_zone()?;
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let is_account_member = access_token.is_member(account_id);
        let calendar_event_ids = if is_account_member {
            cache.document_ids(false).collect::<RoaringBitmap>()
        } else {
            let mut shared_ids = cache.shared_items(access_token, [Acl::ReadItems], true);
            shared_ids -= cache.event_ids_with_flags(EVENT_SECRET);
            shared_ids
        };
        let mut ids = if let Some(rr) = request.ids.take() {
            let rr = rr.unwrap();
            if rr.len() > self.core.jmap.get_max_objects {
                return Err(trc::JmapEvent::RequestTooLarge.into_err());
            }
            rr.into_valid()
                .enumerate()
                .map(|(index, id)| (id, index))
                .collect::<Vec<_>>()
        } else {
            calendar_event_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Id::from)
                .enumerate()
                .map(|(index, id)| (id, index))
                .collect::<Vec<_>>()
        };
        ids.sort_unstable_by_key(|(id, index)| (id.document_id(), u64::from(*id), *index));
        ids.dedup_by_key(|(id, _)| *id);
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(false).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };
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
            Some(after..before)
        } else {
            None
        };
        let projection = ProjectionRequest::new(
            (!return_all_properties).then_some(properties),
            request.arguments.reduce_participants.unwrap_or(false),
            override_range,
        )?;
        let mut projector =
            EventProjector::new(self, access_token, account_id, &projection).await?;
        let mut results = ProjectionResults::with_capacity(ids.len());

        for group in ids.chunk_by(|(a, _), (b, _)| a.document_id() == b.document_id()) {
            let Some((first_id, _)) = group.first() else {
                continue;
            };
            let document_id = first_id.document_id();
            let Some(resource) = calendar_event_ids
                .contains(document_id)
                .then(|| cache.item_by_id(document_id))
                .flatten()
            else {
                results.push_not_found(group);
                continue;
            };
            let archive = if projector.needs_archive(group) {
                let Some(archive) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await?
                else {
                    results.push_not_found(group);
                    continue;
                };
                Some(archive)
            } else {
                None
            };
            let flags = resource.event_flags().unwrap_or_default();
            projector
                .project(
                    self,
                    access_token,
                    ProjectedEvent {
                        document_id,
                        content: archive
                            .as_ref()
                            .map(|archive| archive.unarchive::<CalendarEventContent>())
                            .transpose()
                            .caused_by(trc::location!())?,
                        flags,
                        privacy: EventPrivacy::from_flags(flags),
                        calendar_ids: resource.child_names(),
                        time_zone: default_tz,
                        ids: group,
                    },
                    &mut results,
                )
                .await?;
        }

        for id in results.not_found {
            response.push_not_found(id);
        }
        let mut results = results.found;
        results.sort_unstable_by_key(|(index, _)| *index);
        response
            .list
            .extend(results.into_iter().map(|(_, result)| result.into()));

        Ok(response)
    }
}

pub(crate) struct ProjectionRequest {
    return_all_properties: bool,
    jmap_properties: Vec<JSCalendarProperty<Id>>,
    jscal_properties: Vec<JSCalendarProperty<Id>>,
    return_utc_dates: bool,
    return_is_origin: bool,
    needs_conversion: bool,
    needs_event: bool,
    needs_content: bool,
    reduce_participants: bool,
    override_range: Option<Range<i64>>,
}

pub(crate) struct EventProjector<'x> {
    request: &'x ProjectionRequest,
    account_id: u32,
    personal_id: u32,
    is_account_member: bool,
    account_info: Option<AccountInfo>,
    identities: Option<CalendarAddresses>,
    default_alerts: DefaultAlertsResolver,
}

pub(crate) struct ProjectedEvent<'x> {
    pub document_id: u32,
    pub content: Option<&'x ArchivedCalendarEventContent>,
    pub flags: u16,
    pub privacy: EventPrivacy,
    pub calendar_ids: &'x [CachedName],
    pub time_zone: Tz,
    pub ids: &'x [(Id, usize)],
}

#[derive(Default)]
pub(crate) struct ProjectionResults {
    pub found: Vec<(usize, EventMap<'static>)>,
    pub not_found: Vec<Id>,
}

impl ProjectionRequest {
    pub(crate) fn new(
        properties: Option<Vec<JSCalendarProperty<Id>>>,
        reduce_participants: bool,
        override_range: Option<Range<i64>>,
    ) -> trc::Result<Self> {
        let return_all_properties = properties.is_none();
        let mut return_is_origin = false;
        let mut return_utc_dates = false;
        let (jmap_properties, jscal_properties) = if let Some(properties) = properties {
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
                        jmap_properties.push(property);
                    }
                    _ => {
                        jscal_properties.push(property);
                    }
                }
            }
            if return_utc_dates
                && jscal_properties.contains(&JSCalendarProperty::RecurrenceOverrides)
            {
                return Err(trc::JmapEvent::InvalidArguments.into_err().details(
                    "recurrenceOverrides cannot be requested together with utcStart or utcEnd",
                ));
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
                    JSCalendarProperty::UseDefaultAlerts,
                    JSCalendarProperty::MayInviteSelf,
                    JSCalendarProperty::MayInviteOthers,
                    JSCalendarProperty::HideAttendees,
                ],
                vec![],
            )
        };
        let needs_conversion = return_all_properties || !jscal_properties.is_empty();
        let needs_event = needs_conversion || return_utc_dates || return_is_origin;
        let needs_content =
            needs_event || jmap_properties.contains(&JSCalendarProperty::UseDefaultAlerts);

        Ok(ProjectionRequest {
            return_all_properties,
            jmap_properties,
            jscal_properties,
            return_utc_dates,
            return_is_origin,
            needs_conversion,
            needs_event,
            needs_content,
            reduce_participants,
            override_range,
        })
    }

    fn requested(&self) -> RequestedProperties<'_> {
        RequestedProperties {
            return_all: self.return_all_properties,
            properties: &self.jscal_properties,
        }
    }
}

impl ProjectionResults {
    fn with_capacity(capacity: usize) -> Self {
        ProjectionResults {
            found: Vec::with_capacity(capacity),
            not_found: Vec::new(),
        }
    }

    fn push_not_found(&mut self, ids: &[(Id, usize)]) {
        self.not_found.extend(ids.iter().map(|(id, _)| *id));
    }

    fn push_metadata(
        &mut self,
        metadata: &EventMetadata<'_>,
        ids: &[(Id, usize)],
        properties: &[JSCalendarProperty<Id>],
    ) {
        self.found.extend(
            ids.iter()
                .map(|(id, index)| (*index, metadata.to_object(*id, properties))),
        );
    }
}

impl<'x> EventProjector<'x> {
    pub(crate) async fn new(
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
        request: &'x ProjectionRequest,
    ) -> trc::Result<Self> {
        Ok(EventProjector {
            request,
            account_id,
            personal_id: access_token.personal_id(account_id, Collection::Calendar),
            is_account_member: access_token.is_member(account_id),
            account_info: if request.return_is_origin {
                Some(
                    server
                        .account_info(account_id)
                        .await
                        .caused_by(trc::location!())?,
                )
            } else {
                None
            },
            identities: None,
            default_alerts: DefaultAlertsResolver::default(),
        })
    }

    pub(crate) fn needs_archive(&self, ids: &[(Id, usize)]) -> bool {
        self.request.needs_content || ids.iter().any(|(id, _)| id.is_synthetic())
    }

    pub(crate) async fn project(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        document: ProjectedEvent<'_>,
        results: &mut ProjectionResults,
    ) -> trc::Result<()> {
        let request = self.request;
        let requested = request.requested();
        let jmap_properties = &request.jmap_properties;
        let jscal_properties = &request.jscal_properties;
        let return_all_properties = request.return_all_properties;
        let return_utc_dates = request.return_utc_dates;
        let needs_conversion = request.needs_conversion;
        let needs_event = request.needs_event;
        let reduce_participants = request.reduce_participants;
        let default_tz = document.time_zone;
        let expansion_tz = if return_utc_dates {
            default_tz
        } else {
            Tz::Floating
        };
        let override_range = request.override_range.as_ref();
        let account_id = self.account_id;
        let personal_id = self.personal_id;
        let is_account_member = self.is_account_member;
        let ProjectedEvent {
            document_id,
            content,
            flags,
            privacy,
            calendar_ids,
            ids: group,
            ..
        } = document;

        let mut recurrence_keys = Vec::with_capacity(group.len());
        let mut base_index = None;
        for (id, index) in group {
            match id.recurrence_key() {
                Some(recurrence_key) => recurrence_keys.push((recurrence_key, *id, *index)),
                None => base_index = Some(*index),
            }
        }

        let Some(is_private_view) = privacy.private_view(is_account_member) else {
            results.push_not_found(group);
            return Ok(());
        };
        let mut metadata = EventMetadata {
            flags,
            calendar_ids,
            is_private_view,
            use_default_alerts: false,
            is_origin: false,
            utc_range: None,
        };

        let Some(archived_content) = content else {
            results.push_metadata(&metadata, group, jmap_properties);
            return Ok(());
        };
        let archived_preferences = archived_content.preferences(personal_id);
        metadata.use_default_alerts =
            archived_preferences.is_some_and(|preferences| preferences.use_default_alerts());
        if !needs_event && recurrence_keys.is_empty() {
            results.push_metadata(&metadata, group, jmap_properties);
            return Ok(());
        }
        let mut content = CalendarEventContent {
            data: rkyv_deserialize(&archived_content.data).caused_by(trc::location!())?,
            preferences: archived_preferences
                .map(rkyv_deserialize)
                .transpose()
                .caused_by(trc::location!())?
                .into_iter()
                .collect(),
            dead_properties: Default::default(),
        };
        let Some(is_private_view) = privacy
            .max(content.data.event.privacy())
            .private_view(is_account_member)
        else {
            results.push_not_found(group);
            return Ok(());
        };

        let personal_updated = if !is_account_member {
            let preferences = content
                .preferences
                .iter()
                .find(|p| p.account_id == personal_id);
            if requested.any(PERSONAL_PROPERTIES) {
                content
                    .data
                    .apply_user_data(preferences, UserDataView::Full);
            }
            preferences
                .map(|p| p.updated)
                .filter(|updated| *updated > 0)
        } else {
            None
        };

        let private_is_origin = if is_private_view {
            let is_origin = self
                .account_info
                .as_ref()
                .is_some_and(|account| is_origin(&content.data.event, account.addresses()));
            content.data.event = std::mem::take(&mut content.data.event).into_private_view();
            Some(is_origin)
        } else {
            None
        };

        if !is_private_view && requested.any(ALERT_PROPERTIES) {
            let default_alerts = self
                .default_alerts
                .resolve_for_content(
                    server,
                    account_id,
                    personal_id,
                    &content,
                    calendar_ids.iter().map(CachedName::calendar_id),
                )
                .await
                .caused_by(trc::location!())?;
            content
                .data
                .event
                .apply_default_alerts(&default_alerts, DefaultAlertsView::Replace);
        }

        let participant_filter = if requested.any(PARTICIPANT_PROPERTIES)
            && (reduce_participants || (!is_account_member && flags & EVENT_HIDE_ATTENDEES != 0))
        {
            if self.identities.is_none() {
                let account_info = server
                    .account_info(access_token.account_id())
                    .await
                    .caused_by(trc::location!())?;
                self.identities = server
                    .identity_addresses(access_token.account_id(), &account_info)
                    .await
                    .caused_by(trc::location!())?
                    .into();
            }
            self.identities.as_ref().filter(|identities| {
                reduce_participants
                    || identities.event_ownership(&content.data.event) != EventOwnership::Owner
            })
        } else {
            None
        };
        let event_is_origin = private_is_origin.unwrap_or_else(|| {
            self.account_info
                .as_ref()
                .is_some_and(|account| is_origin(&content.data.event, account.addresses()))
        });

        let needs_binaries = requested.any(BLOB_PROPERTIES);
        let binaries = if needs_binaries {
            InstanceBinaries::Keep
        } else {
            InstanceBinaries::Skip
        };
        let convert = |ical: ICalendar| {
            let options = ImportOptions::new()
                .include_ical_components(!return_all_properties && !is_private_view)
                .return_first(true);
            if needs_binaries {
                ical.into_jscalendar_with::<Id, BlobId, _>(options.with_blob_id_generator(
                    EmbeddedBlobIds::new(account_id, Collection::CalendarEvent, document_id),
                ))
            } else {
                ical.into_jscalendar_with::<Id, BlobId, _>(options)
            }
            .map(JSCalendar::into_inner)
            .map_err(import_error)
        };
        let mut instances = Vec::with_capacity(recurrence_keys.len() + 1);
        let mut templates: Vec<(u32, EventValue<'static>)> = Vec::new();
        if !recurrence_keys.is_empty() {
            let mut keys = recurrence_keys
                .iter()
                .map(|(recurrence_key, _, _)| *recurrence_key)
                .collect::<AHashSet<_>>();
            for expansion in content
                .data
                .expand_from_ids(&mut keys, expansion_tz)
                .unwrap_or_default()
            {
                let Some(position) = expansion.recurrence_key().and_then(|recurrence_key| {
                    recurrence_keys
                        .iter()
                        .position(|(key, _, _)| *key == recurrence_key)
                }) else {
                    continue;
                };
                let (recurrence_key, id, index) = recurrence_keys.swap_remove(position);
                let jscal = if needs_conversion {
                    let user_data = (!is_account_member)
                        .then(|| {
                            content
                                .data
                                .event
                                .user_data_override(expansion.comp_id, recurrence_key)
                        })
                        .flatten();
                    let is_shared_component = user_data.is_none()
                        && content.data.has_stable_instance_duration(expansion.comp_id);
                    let cached = is_shared_component
                        .then(|| {
                            templates
                                .iter()
                                .position(|(comp_id, _)| *comp_id == expansion.comp_id)
                        })
                        .flatten();
                    match cached {
                        Some(position) => {
                            let mut jscal = templates[position].1.clone();
                            jscal.set_instance_dates(&expansion);
                            Some(jscal)
                        }
                        None => {
                            let Some(ical) = content.data.instance(&expansion, user_data, binaries)
                            else {
                                results.not_found.push(id);
                                continue;
                            };
                            let jscal = convert(ical)?;
                            if is_shared_component {
                                templates.push((expansion.comp_id, jscal.clone()));
                            }
                            Some(jscal)
                        }
                    }
                } else {
                    None
                };
                instances.push(EventInstance {
                    id,
                    index,
                    jscal,
                    utc_range: Some((expansion.start, expansion.end)),
                });
            }

            for (_, id, _) in recurrence_keys {
                results.not_found.push(id);
            }
        }

        if let Some(index) = base_index {
            let utc_range = return_utc_dates
                .then(|| content.data.expand_base(default_tz))
                .flatten()
                .map(|expansion| (expansion.start, expansion.end));
            let ical = needs_conversion.then(|| {
                let mut event = std::mem::take(&mut content.data.event);
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
                                    .and_then(|v| {
                                        v.to_date_time_with_tz(
                                            c.property(&ICalendarProperty::RecurrenceId)
                                                .and_then(|entry| entry.tz_id())
                                                .and_then(|tz| Tz::from_str(tz).ok())
                                                .unwrap_or(default_tz),
                                        )
                                    })
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
                if binaries == InstanceBinaries::Skip {
                    event.strip_binary_entries();
                }
                event
            });
            instances.push(EventInstance {
                id: Id::from(document_id),
                index,
                jscal: ical.map(convert).transpose()?,
                utc_range,
            });
        }

        metadata.is_private_view = is_private_view;
        metadata.is_origin = event_is_origin;
        for instance in instances {
            let mut result = match instance.jscal {
                Some(mut jscal) => {
                    if let Some(identities) = participant_filter {
                        jscal.retain_visible_participants(identities);
                    }
                    if let Some(range) = override_range.filter(|_| !instance.id.is_synthetic()) {
                        jscal.retain_overrides_in(range, default_tz);
                    }

                    if return_all_properties {
                        jscal.into_object().unwrap_or_else(Map::new)
                    } else {
                        let is_synthetic = instance.id.is_synthetic();
                        let is_null_for_synthetic = |property: &JSCalendarProperty<Id>| {
                            is_synthetic
                                && matches!(
                                    property,
                                    JSCalendarProperty::RecurrenceRule
                                        | JSCalendarProperty::RecurrenceOverrides
                                )
                        };
                        let mut result =
                            Map::from_iter(jscal.into_expanded_object().filter(|(k, _)| {
                                k.as_property().is_some_and(|p| {
                                    jscal_properties.contains(p) && !is_null_for_synthetic(p)
                                })
                            }));
                        for property in jscal_properties
                            .iter()
                            .filter(|property| is_null_for_synthetic(property))
                        {
                            result.insert_unchecked(property.clone(), Value::Null);
                        }
                        result
                    }
                }
                None => Map::with_capacity(jmap_properties.len()),
            };

            if let Some(personal_updated) = personal_updated
                && let Some(updated) = result.get_mut(&Key::Property(JSCalendarProperty::Updated))
                && matches!(
                    updated,
                    Value::Element(JSCalendarValue::DateTime(current))
                        if current.timestamp < personal_updated
                )
            {
                *updated = Value::Element(JSCalendarValue::DateTime(JSCalendarDateTime::new(
                    personal_updated,
                    false,
                )));
            }

            metadata.utc_range = instance.utc_range;
            metadata.insert_properties(&mut result, instance.id, jmap_properties);
            results.found.push((instance.index, result));
        }

        Ok(())
    }
}

const PERSONAL_PROPERTIES: &[JSCalendarProperty<Id>] = &[
    JSCalendarProperty::Keywords,
    JSCalendarProperty::Color,
    JSCalendarProperty::FreeBusyStatus,
    JSCalendarProperty::Alerts,
    JSCalendarProperty::RecurrenceOverrides,
    JSCalendarProperty::ICalendar,
];
const ALERT_PROPERTIES: &[JSCalendarProperty<Id>] = &[
    JSCalendarProperty::Alerts,
    JSCalendarProperty::RecurrenceOverrides,
    JSCalendarProperty::ICalendar,
];
const PARTICIPANT_PROPERTIES: &[JSCalendarProperty<Id>] = &[
    JSCalendarProperty::Participants,
    JSCalendarProperty::RecurrenceOverrides,
    JSCalendarProperty::ICalendar,
];
const BLOB_PROPERTIES: &[JSCalendarProperty<Id>] = &[
    JSCalendarProperty::Links,
    JSCalendarProperty::Locations,
    JSCalendarProperty::Participants,
    JSCalendarProperty::RecurrenceOverrides,
    JSCalendarProperty::ICalendar,
];

struct RequestedProperties<'x> {
    return_all: bool,
    properties: &'x [JSCalendarProperty<Id>],
}

impl RequestedProperties<'_> {
    fn any(&self, properties: &[JSCalendarProperty<Id>]) -> bool {
        self.return_all
            || self
                .properties
                .iter()
                .any(|property| properties.contains(property))
    }
}

struct EventInstance {
    id: Id,
    index: usize,
    jscal: Option<EventValue<'static>>,
    utc_range: Option<(i64, i64)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InstanceBinaries {
    Keep,
    Skip,
}

trait InstanceDates {
    fn set_instance_dates(&mut self, expansion: &CalendarEventExpansion);
}

impl InstanceDates for EventValue<'static> {
    fn set_instance_dates(&mut self, expansion: &CalendarEventExpansion) {
        let Some(event) = self.as_object_mut() else {
            return;
        };
        for (property, timestamp) in [
            (JSCalendarProperty::Start, expansion.start_naive),
            (
                JSCalendarProperty::RecurrenceId,
                expansion.recurrence_id().naive,
            ),
        ] {
            if let Some(Value::Element(JSCalendarValue::DateTime(date_time))) =
                event.get_mut(&Key::Property(property))
            {
                date_time.timestamp = timestamp;
            }
        }
    }
}

struct EventMetadata<'x> {
    flags: u16,
    calendar_ids: &'x [CachedName],
    is_private_view: bool,
    use_default_alerts: bool,
    is_origin: bool,
    utc_range: Option<(i64, i64)>,
}

impl EventMetadata<'_> {
    fn to_object(
        &self,
        id: Id,
        properties: &[JSCalendarProperty<Id>],
    ) -> Map<'static, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>> {
        let mut result = Map::with_capacity(properties.len());
        self.insert_properties(&mut result, id, properties);
        result
    }

    fn insert_properties(
        &self,
        result: &mut Map<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
        id: Id,
        properties: &[JSCalendarProperty<Id>],
    ) {
        for property in properties
            .iter()
            .filter(|property| !self.is_private_view || property.is_private_view_property())
        {
            let value = match property {
                JSCalendarProperty::Id => Value::Element(JSCalendarValue::Id(id)),
                JSCalendarProperty::BaseEventId if id.is_synthetic() => {
                    Value::Element(JSCalendarValue::Id(id.document_id().into()))
                }
                JSCalendarProperty::BaseEventId => Value::Null,
                JSCalendarProperty::CalendarIds => {
                    Value::Object(Map::from_iter(self.calendar_ids.iter().map(|name| {
                        (
                            Key::Property(JSCalendarProperty::IdValue(Id::from(name.parent_id))),
                            Value::Bool(true),
                        )
                    })))
                }
                JSCalendarProperty::IsDraft => Value::Bool(self.flags & EVENT_DRAFT != 0),
                JSCalendarProperty::IsOrigin => Value::Bool(self.is_origin),
                JSCalendarProperty::MayInviteSelf => {
                    Value::Bool(self.flags & EVENT_INVITE_SELF != 0)
                }
                JSCalendarProperty::MayInviteOthers => {
                    Value::Bool(self.flags & EVENT_INVITE_OTHERS != 0)
                }
                JSCalendarProperty::HideAttendees => {
                    Value::Bool(self.flags & EVENT_HIDE_ATTENDEES != 0)
                }
                JSCalendarProperty::UseDefaultAlerts => Value::Bool(self.use_default_alerts),
                JSCalendarProperty::UtcStart => match self.utc_range {
                    Some((start, _)) => Value::Element(JSCalendarValue::DateTime(
                        JSCalendarDateTime::new(start, false),
                    )),
                    None => continue,
                },
                JSCalendarProperty::UtcEnd => match self.utc_range {
                    Some((_, end)) => Value::Element(JSCalendarValue::DateTime(
                        JSCalendarDateTime::new(end, false),
                    )),
                    None => continue,
                },
                _ => continue,
            };
            result.insert_unchecked(property.clone(), value);
        }
    }
}

trait CalendarId {
    fn calendar_id(&self) -> u32;
}

impl CalendarId for CachedName {
    fn calendar_id(&self) -> u32 {
        self.parent_id
    }
}

trait EventPrivacyView {
    fn private_view(self, is_account_member: bool) -> Option<bool>;
}

impl EventPrivacyView for EventPrivacy {
    fn private_view(self, is_account_member: bool) -> Option<bool> {
        match self {
            EventPrivacy::Public => Some(false),
            EventPrivacy::Private => Some(!is_account_member),
            EventPrivacy::Secret => is_account_member.then_some(false),
        }
    }
}

trait OverrideRange {
    fn retain_overrides_in(&mut self, range: &Range<i64>, default_tz: Tz);
}

impl OverrideRange for Value<'_, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>> {
    fn retain_overrides_in(&mut self, range: &Range<i64>, default_tz: Tz) {
        let Some(event) = self.as_object_mut() else {
            return;
        };
        let tz = event
            .get(&Key::Property(JSCalendarProperty::TimeZone))
            .and_then(Value::as_str)
            .and_then(|tz| Tz::from_str(&tz).ok())
            .unwrap_or(default_tz);
        let key = Key::Property(JSCalendarProperty::RecurrenceOverrides);
        let Some(overrides) = event.get_mut(&key).and_then(Value::as_object_mut) else {
            return;
        };
        overrides.as_mut_vec().retain(|(key, _)| match key {
            Key::Property(JSCalendarProperty::DateTime(date_time)) => {
                resolve_local(tz, date_time.timestamp)
                    .is_some_and(|timestamp| range.contains(&timestamp))
            }
            _ => true,
        });
        if overrides.is_empty() {
            event.remove(&key);
        }
    }
}

#[derive(Clone, Copy)]
enum InstanceParameters {
    All,
    TimeZone,
}

trait InstanceDateTime {
    fn with_date_time(
        &self,
        name: ICalendarProperty,
        naive: i64,
        fallback_tz: Option<Tz>,
        parameters: InstanceParameters,
    ) -> ICalendarEntry;

    fn with_date_time_in(
        &self,
        name: ICalendarProperty,
        naive: i64,
        tz: Option<Tz>,
    ) -> ICalendarEntry;
}

impl InstanceDateTime for ICalendarEntry {
    fn with_date_time_in(
        &self,
        name: ICalendarProperty,
        naive: i64,
        tz: Option<Tz>,
    ) -> ICalendarEntry {
        let is_date = self
            .values
            .first()
            .and_then(ICalendarValue::as_partial_date_time)
            .is_some_and(|value| !value.has_time());
        let (params, value) = match tz {
            _ if is_date => (
                vec![ICalendarParameter::value(ICalendarValueType::Date)],
                PartialDateTime::from_date_timestamp(naive),
            ),
            Some(tz) if tz.is_utc() => (vec![], PartialDateTime::from_utc_timestamp(naive)),
            tz => (
                tz.and_then(|tz| tz.name())
                    .map(|tz_name| ICalendarParameter::tzid(tz_name.into_owned()))
                    .into_iter()
                    .collect(),
                PartialDateTime::from_naive_timestamp(naive),
            ),
        };
        ICalendarEntry {
            name,
            params,
            values: vec![ICalendarValue::PartialDateTime(Box::new(value))],
        }
    }

    fn with_date_time(
        &self,
        name: ICalendarProperty,
        naive: i64,
        fallback_tz: Option<Tz>,
        parameters: InstanceParameters,
    ) -> ICalendarEntry {
        let value = match self
            .values
            .first()
            .and_then(ICalendarValue::as_partial_date_time)
        {
            Some(value) if !value.has_time() => PartialDateTime::from_date_timestamp(naive),
            Some(value) if value.has_zone() => PartialDateTime::from_utc_timestamp(naive),
            _ => PartialDateTime::from_naive_timestamp(naive),
        };

        ICalendarEntry {
            name,
            params: self
                .params
                .iter()
                .filter(|param| match parameters {
                    InstanceParameters::All => param.name != ICalendarParameterName::Range,
                    InstanceParameters::TimeZone => matches!(
                        param.name,
                        ICalendarParameterName::Tzid | ICalendarParameterName::Value
                    ),
                })
                .map(|param| match (&param.name, &param.value) {
                    (ICalendarParameterName::Tzid, ICalendarParameterValue::Text(tz_id)) => {
                        Tz::from_str(tz_id)
                            .ok()
                            .or(fallback_tz)
                            .and_then(|tz| tz.name())
                            .map_or_else(
                                || param.clone(),
                                |tz_name| ICalendarParameter::tzid(tz_name.into_owned()),
                            )
                    }
                    _ => param.clone(),
                })
                .collect(),
            values: vec![ICalendarValue::PartialDateTime(Box::new(value))],
        }
    }
}

pub(super) trait StableInstanceDuration {
    fn has_stable_instance_duration(&self, comp_id: u32) -> bool;
}

impl StableInstanceDuration for CalendarEventData {
    fn has_stable_instance_duration(&self, comp_id: u32) -> bool {
        let Some(component) = self.event.components.get(comp_id as usize) else {
            return false;
        };
        if component.property(&ICalendarProperty::Duration).is_some()
            || component.property(&ICalendarProperty::Dtend).is_none()
        {
            return true;
        }

        self.time_ranges
            .iter()
            .find(|range| range.id as u32 == comp_id)
            .is_some_and(|range| {
                [range.start_tz, range.end_tz]
                    .into_iter()
                    .all(|tz_id| Tz::from_id(tz_id).is_some_and(|tz| tz.has_fixed_offset()))
            })
    }
}

pub(super) trait EventInstanceBuilder {
    fn instance(
        &self,
        expansion: &CalendarEventExpansion,
        user_data: Option<&ICalendarComponent>,
        binaries: InstanceBinaries,
    ) -> Option<ICalendar>;
}

impl EventInstanceBuilder for CalendarEventData {
    fn instance(
        &self,
        expansion: &CalendarEventExpansion,
        user_data: Option<&ICalendarComponent>,
        binaries: InstanceBinaries,
    ) -> Option<ICalendar> {
        let source = self.event.components.get(expansion.comp_id as usize)?;
        let is_recurrent = source.is_recurrent();
        let range = self
            .time_ranges
            .iter()
            .find(|range| range.id as u32 == expansion.comp_id);
        let start_tz = range.and_then(|range| Tz::from_id(range.start_tz));
        let end_tz = range.and_then(|range| Tz::from_id(range.end_tz));
        let mut dtstart = None;
        let mut dtend = None;
        let mut recurrence_id = None;
        let mut has_duration = false;
        let mut entries = source
            .entries
            .iter()
            .filter(|entry| user_data.is_none() || !entry.is_user_data())
            .chain(user_data.into_iter().flat_map(|component| {
                component
                    .entries
                    .iter()
                    .filter(|entry| entry.is_user_data())
            }))
            .filter(|entry| binaries == InstanceBinaries::Keep || !entry.has_binary_value())
            .filter(|entry| match &entry.name {
                ICalendarProperty::Dtstart => {
                    dtstart = Some(*entry);
                    false
                }
                ICalendarProperty::Dtend => {
                    dtend = Some(*entry);
                    false
                }
                ICalendarProperty::RecurrenceId => {
                    recurrence_id = Some(*entry);
                    false
                }
                ICalendarProperty::Exdate
                | ICalendarProperty::Exrule
                | ICalendarProperty::Rdate
                | ICalendarProperty::Rrule => false,
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
            .collect::<Vec<_>>();

        entries.push(match (dtstart, recurrence_id) {
            (Some(dtstart), _) => dtstart.with_date_time(
                ICalendarProperty::Dtstart,
                expansion.start_naive,
                start_tz,
                InstanceParameters::All,
            ),
            (None, Some(recurrence_id)) => recurrence_id.with_date_time_in(
                ICalendarProperty::Dtstart,
                expansion.start_naive,
                start_tz,
            ),
            (None, None) => ICalendarEntry {
                name: ICalendarProperty::Dtstart,
                params: vec![],
                values: vec![ICalendarValue::PartialDateTime(Box::new(
                    PartialDateTime::from_naive_timestamp(expansion.start_naive),
                ))],
            },
        });

        if is_recurrent || recurrence_id.is_some() {
            let instance_id = expansion.recurrence_id();
            if let Some(entry) = recurrence_id
                .map(|entry| (entry, InstanceParameters::All))
                .or_else(|| dtstart.map(|entry| (entry, InstanceParameters::TimeZone)))
            {
                entries.push(entry.0.with_date_time(
                    ICalendarProperty::RecurrenceId,
                    instance_id.naive,
                    start_tz,
                    entry.1,
                ));
            }
        }

        let rebased_end = if !has_duration
            && let Some(dtend) = dtend
            && let Some(end) = dtend
                .values
                .first()
                .and_then(ICalendarValue::as_partial_date_time)
                .and_then(|value| value.to_date_time())
            && let Some(start) = dtstart
                .and_then(|dtstart| dtstart.values.first())
                .and_then(ICalendarValue::as_partial_date_time)
                .and_then(|value| value.to_date_time())
        {
            Some(dtend.with_date_time(
                ICalendarProperty::Dtend,
                expansion.start_naive + end.date_time.duration_since(start.date_time).as_secs(),
                end_tz,
                InstanceParameters::All,
            ))
        } else {
            None
        };

        if let Some(rebased_end) = rebased_end {
            entries.push(rebased_end);
        } else if !has_duration
            && expansion.end > expansion.start
            && !entries
                .iter()
                .any(|entry| entry.name == ICalendarProperty::Due)
        {
            let is_date = dtstart
                .or(recurrence_id)
                .and_then(|entry| entry.values.first())
                .and_then(ICalendarValue::as_partial_date_time)
                .is_some_and(|value| !value.has_time());
            entries.push(ICalendarEntry {
                name: ICalendarProperty::Duration,
                params: vec![],
                values: vec![ICalendarValue::Duration(if is_date {
                    ICalendarDuration::from_days(
                        (expansion.end_naive - expansion.start_naive) / SECONDS_PER_DAY,
                    )
                } else {
                    ICalendarDuration::from_seconds(expansion.end - expansion.start)
                })],
            });
        }

        let mut components = Vec::with_capacity(2 + source.component_ids.len());
        components.push(ICalendarComponent {
            component_type: ICalendarComponentType::VCalendar,
            entries: vec![],
            component_ids: vec![1],
        });
        components.push(ICalendarComponent {
            component_type: source.component_type.clone(),
            entries,
            component_ids: vec![],
        });
        components.extend(
            user_data
                .unwrap_or(source)
                .component_ids
                .iter()
                .filter_map(|component_id| self.event.components.get(*component_id as usize))
                .map(|component| ICalendarComponent {
                    component_type: component.component_type.clone(),
                    entries: if binaries == InstanceBinaries::Keep
                        || component.component_type == ICalendarComponentType::VAlarm
                    {
                        component.entries.clone()
                    } else {
                        component
                            .entries
                            .iter()
                            .filter(|entry| !entry.has_binary_value())
                            .cloned()
                            .collect()
                    },
                    component_ids: vec![],
                }),
        );
        let child_ids = (2..components.len() as u32).collect();
        if let Some(instance) = components.get_mut(1) {
            instance.component_ids = child_ids;
        }

        Some(ICalendar { components })
    }
}

trait BinaryEntry {
    fn has_binary_value(&self) -> bool;
}

impl BinaryEntry for ICalendarEntry {
    fn has_binary_value(&self) -> bool {
        self.values
            .iter()
            .any(|value| matches!(value, ICalendarValue::Binary(_)))
    }
}

trait StripBinaryEntries {
    fn strip_binary_entries(&mut self);
}

impl StripBinaryEntries for ICalendar {
    fn strip_binary_entries(&mut self) {
        for component in self
            .components
            .iter_mut()
            .filter(|component| component.component_type != ICalendarComponentType::VAlarm)
        {
            component.entries.retain(|entry| !entry.has_binary_value());
        }
    }
}

trait PrivateViewProperty {
    fn is_private_view_property(&self) -> bool;
}

impl PrivateViewProperty for JSCalendarProperty<Id> {
    fn is_private_view_property(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::Id
                | JSCalendarProperty::BaseEventId
                | JSCalendarProperty::CalendarIds
                | JSCalendarProperty::IsDraft
                | JSCalendarProperty::IsOrigin
                | JSCalendarProperty::UtcStart
                | JSCalendarProperty::UtcEnd
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use groupware::calendar::ArchivedCalendarEventData;
    use types::{OverlapRule, TimeRange};

    fn override_instance(occurrence: &str) -> String {
        let data = CalendarEventData::new(
            ICalendar::parse(format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:series\r\n\
                 DTSTART;TZID=America/New_York:20300102T090000\r\nDURATION:PT1H\r\n\
                 RRULE:FREQ=DAILY;COUNT=3\r\nEND:VEVENT\r\n\
                 BEGIN:VEVENT\r\nUID:series\r\n{occurrence}SUMMARY:Moved\r\nEND:VEVENT\r\n\
                 END:VCALENDAR\r\n"
            ))
            .expect("valid iCalendar"),
            Tz::Floating,
            100,
        );
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&data).expect("archive");
        let expansion = rkyv::access::<ArchivedCalendarEventData, rkyv::rancor::Error>(&bytes)
            .expect("access")
            .expand(
                Tz::UTC,
                TimeRange::new(i64::MIN, i64::MAX),
                OverlapRule::Jmap,
            )
            .expect("expansion")
            .into_iter()
            .find(|expansion| expansion.comp_id == 2)
            .expect("override instance");
        data.instance(&expansion, None, InstanceBinaries::Keep)
            .expect("instance")
            .to_string()
    }

    #[test]
    fn an_override_without_dtstart_starts_in_the_time_zone_of_its_instance() {
        for occurrence in [
            "RECURRENCE-ID:20300103T140000Z\r\n",
            "RECURRENCE-ID;TZID=Europe/Berlin:20300103T150000\r\n",
            "RECURRENCE-ID;TZID=America/New_York:20300103T090000\r\n",
        ] {
            let instance = override_instance(occurrence);
            assert!(
                instance.contains("DTSTART;TZID=America/New_York:20300103T090000\r\n")
                    && instance.contains("DURATION:PT1H\r\n"),
                "RFC 5545 Section 3.8.4.4: the occurrence starts as the instance it replaces\n{occurrence}\n{instance}"
            );
        }
    }

    #[test]
    fn an_override_with_dtend_but_no_dtstart_keeps_its_end() {
        let instance = override_instance(
            "RECURRENCE-ID;TZID=America/New_York:20300103T090000\r\n\
             DTEND;TZID=America/New_York:20300103T120000\r\n",
        );
        assert!(
            instance.contains("DTSTART;TZID=America/New_York:20300103T090000\r\n")
                && instance.contains("DURATION:PT3H\r\n"),
            "RFC 5545 Section 3.8.2.2: the occurrence ends at its DTEND\n{instance}"
        );
    }
}
