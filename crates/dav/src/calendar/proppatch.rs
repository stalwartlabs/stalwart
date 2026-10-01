/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod, PropStatBuilder,
    calendar::assert_event_privacy_access,
    common::{
        ETag, ExtractETag,
        dead::{DeadPatch, DeadTarget, DisplayName},
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
};
use calcard::common::timezone::Tz;
use common::{
    Server,
    auth::AccessToken,
    storage::index::{PresenceFlags, RewritePresence},
};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        Namespace,
        property::{CalDavProperty, DavProperty, DavValue, ResourceType, WebDavProperty},
        request::{DavPropertyValue, PropertyUpdate, PropertyUpdateOp},
        response::{BaseCondition, CalCondition, MultiStatus, Response},
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        Calendar, CalendarEvent, SupportedComponent, Timezone,
        alerts::{CalendarAlarmsReschedule, CalendarSettings},
        privacy::EventViewer,
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use std::str::FromStr;
use store::write::BatchBuilder;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};
use utils::map::bitmap::Bitmap;

pub(crate) trait CalendarPropPatchRequestHandler: Sync + Send {
    fn handle_calendar_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;

    fn apply_calendar_properties(
        &self,
        personal_id: u32,
        calendar: &mut Calendar,
        is_update: bool,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    );

    fn apply_event_properties(
        &self,
        event: &mut CalendarEvent,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    );
}

impl CalendarPropPatchRequestHandler for Server {
    async fn handle_calendar_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        mut request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let uri = headers.uri;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|r| resources.by_path(r))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let document_id = resource.document_id();
        let collection = if resource.is_container() {
            Collection::Calendar
        } else {
            Collection::CalendarEvent
        };

        if !request.has_changes() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        // Verify ACL
        let is_owner = access_token.is_member(account_id);
        if !is_owner {
            let (acl, document_id) = if resource.is_container() {
                (Acl::Modify, resource.document_id())
            } else {
                assert_event_privacy_access(
                    resource.resource.event_flags(),
                    EventViewer::new(is_owner),
                )?;
                (
                    Acl::ModifyItems,
                    resource
                        .parent_id()
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?,
                )
            };

            if !resources.has_access_to_container(access_token, document_id, acl) {
                return Err(DavError::Code(StatusCode::FORBIDDEN));
            }
        }

        // Fetch archive
        let archive = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                collection,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let etag = if resource.is_container() {
            archive.etag()
        } else {
            format!(
                "\"{}\"",
                archive
                    .unarchive::<CalendarEvent>()
                    .caused_by(trc::location!())?
                    .etag
                    .to_native()
            )
        };

        // Validate headers
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection,
                document_id: document_id.into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::PROPPATCH,
        )
        .await?;

        let dead = DeadPatch::take(&mut request.ops, DisplayName::Live);
        let has_live_changes = !request.ops.is_empty();
        let mut batch = BatchBuilder::new();
        let mut items = PropStatBuilder::default();

        let (is_success, etag) = if resource.is_container() {
            // Deserialize
            let calendar = archive
                .to_unarchived::<Calendar>()
                .caused_by(trc::location!())?;
            let mut new_calendar = archive
                .deserialize::<Calendar>()
                .caused_by(trc::location!())?;
            let personal_id = access_token.personal_id(account_id, Collection::Calendar);
            let is_member = access_token.is_member(account_id);
            if is_member {
                new_calendar.inherit_owner_preferences(account_id, personal_id);
            }

            // Apply live properties
            for op in request.ops {
                match op {
                    PropertyUpdateOp::Set(value) => self.apply_calendar_properties(
                        personal_id,
                        &mut new_calendar,
                        true,
                        [value],
                        &mut items,
                    ),
                    PropertyUpdateOp::Remove(property) => remove_calendar_properties(
                        personal_id,
                        &mut new_calendar,
                        [property],
                        &mut items,
                    ),
                }
            }

            // Apply dead properties
            let mut dead_write = dead
                .apply(
                    self,
                    DeadTarget::container(
                        account_id,
                        Collection::Calendar,
                        document_id,
                        calendar.inner.metadata_kinds(),
                    ),
                    &mut items,
                )
                .await
                .caused_by(trc::location!())?;

            if items.has_errors() {
                (false, etag)
            } else {
                if has_live_changes {
                    if is_member {
                        new_calendar.sync_owner_preferences(account_id, personal_id);
                    }
                    if let Some(dead_write) = &dead_write {
                        new_calendar.set_metadata_kinds(dead_write.kinds);
                    }
                    self.reschedule_calendar_alarms(
                        &resources,
                        account_id,
                        document_id,
                        CalendarSettings::from(calendar.inner),
                        CalendarSettings::from(&new_calendar),
                        &mut batch,
                    )
                    .await
                    .caused_by(trc::location!())?;
                    if let Some(write) = dead_write.and_then(|dead_write| dead_write.write) {
                        write
                            .build(document_id.into(), &mut batch)
                            .caused_by(trc::location!())?;
                    }
                    new_calendar
                        .update(
                            access_token.account_tenant_ids(),
                            calendar,
                            account_id,
                            document_id,
                            &mut batch,
                        )
                        .caused_by(trc::location!())?;
                } else if let Some(dead_write) = dead_write.as_mut() {
                    if let Some(write) = dead_write.write.take() {
                        write
                            .build(document_id.into(), &mut batch)
                            .caused_by(trc::location!())?;
                    }
                    Calendar::rewrite_presence(
                        &calendar,
                        dead_write.kinds,
                        account_id,
                        document_id,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
                }
                (true, batch.etag().unwrap_or(etag))
            }
        } else {
            // Deserialize
            let event = archive
                .to_unarchived::<CalendarEvent>()
                .caused_by(trc::location!())?;
            let mut new_event = archive
                .deserialize::<CalendarEvent>()
                .caused_by(trc::location!())?;

            // Apply live properties
            for op in request.ops {
                match op {
                    PropertyUpdateOp::Set(value) => {
                        self.apply_event_properties(&mut new_event, [value], &mut items)
                    }
                    PropertyUpdateOp::Remove(property) => {
                        remove_event_properties(&mut new_event, [property], &mut items)
                    }
                }
            }

            // Apply dead properties
            let mut dead_write = dead
                .apply(
                    self,
                    DeadTarget::item(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        event.inner.metadata_kinds(),
                    ),
                    &mut items,
                )
                .await
                .caused_by(trc::location!())?;

            if items.has_errors() {
                (false, etag)
            } else {
                let mut new_etag = None;
                if let Some(write) = dead_write
                    .as_mut()
                    .and_then(|dead_write| dead_write.write.take())
                {
                    write
                        .build(document_id.into(), &mut batch)
                        .caused_by(trc::location!())?;
                }
                if has_live_changes {
                    if let Some(dead_write) = &dead_write {
                        new_event.set_metadata_kinds(dead_write.kinds);
                    }
                    new_etag = new_event
                        .update_meta(
                            access_token.account_tenant_ids(),
                            event,
                            account_id,
                            document_id,
                            None,
                            &mut batch,
                        )
                        .caused_by(trc::location!())?
                        .into();
                } else if let Some(dead_write) = &dead_write {
                    CalendarEvent::rewrite_presence(
                        &event,
                        dead_write.kinds,
                        account_id,
                        document_id,
                        &mut batch,
                    )
                    .caused_by(trc::location!())?;
                }
                (true, new_etag.unwrap_or(etag))
            }
        };

        if is_success {
            if !batch.is_empty() {
                self.commit_batch(batch).await.caused_by(trc::location!())?;
            }
        } else {
            items.fail_dependencies();
        }

        if headers.ret != Return::Minimal || !is_success {
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS)
                .with_xml_body(
                    MultiStatus::new(vec![Response::new_propstat(uri, items.build())])
                        .with_namespace(Namespace::CalDav)
                        .to_string(),
                )
                .with_etag(etag))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT).with_etag(etag))
        }
    }

    fn apply_calendar_properties(
        &self,
        personal_id: u32,
        calendar: &mut Calendar,
        is_update: bool,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) {
        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        calendar.preferences_mut(personal_id).name = name;
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                }
                (
                    DavProperty::CalDav(CalDavProperty::CalendarDescription),
                    DavValue::String(name),
                ) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        calendar.preferences_mut(personal_id).description = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                }
                (
                    DavProperty::CalDav(CalDavProperty::CalendarTimezone),
                    DavValue::ICalendar(ical),
                ) => {
                    if ical.size() > self.core.groupware.max_ical_size {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    } else if !ical.is_timezone() {
                        items.insert_precondition_failed_with_description(
                            property.property,
                            StatusCode::PRECONDITION_FAILED,
                            CalCondition::ValidCalendarData,
                            "Invalid calendar timezone",
                        );
                    } else {
                        calendar.preferences_mut(personal_id).time_zone = Timezone::Custom(ical);
                        items.insert_ok(property.property);
                    }
                }
                (DavProperty::CalDav(CalDavProperty::TimezoneId), DavValue::String(tz_id)) => {
                    if let Ok(tz) = Tz::from_str(&tz_id) {
                        calendar.preferences_mut(personal_id).time_zone =
                            Timezone::IANA(tz.as_id());
                        items.insert_ok(property.property);
                    } else {
                        items.insert_precondition_failed_with_description(
                            property.property,
                            StatusCode::PRECONDITION_FAILED,
                            CalCondition::ValidTimezone,
                            "Invalid timezone ID",
                        );
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    calendar.created = dt;
                    items.insert_ok(property.property);
                }
                (
                    DavProperty::WebDav(WebDavProperty::ResourceType),
                    DavValue::ResourceTypes(types),
                ) => {
                    if !types
                        .0
                        .iter()
                        .all(|rt| matches!(rt, ResourceType::Collection | ResourceType::Calendar))
                    {
                        items.insert_precondition_failed(
                            property.property,
                            StatusCode::FORBIDDEN,
                            BaseCondition::ValidResourceType,
                        );
                    } else {
                        items.insert_ok(property.property);
                    }
                }
                (
                    DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet),
                    DavValue::Components(components),
                ) => {
                    if !is_update {
                        calendar.supported_components = Bitmap::<SupportedComponent>::from_iter(
                            components
                                .0
                                .into_iter()
                                .map(|v| SupportedComponent::from(v.0)),
                        )
                        .into_inner();
                        if calendar.supported_components != 0 {
                            items.insert_ok(property.property);
                        } else {
                            items.insert_precondition_failed_with_description(
                                property.property,
                                StatusCode::PRECONDITION_FAILED,
                                CalCondition::SupportedCalendarComponent,
                                "At least one supported component must be specified",
                            );
                        }
                    } else {
                        items.insert_precondition_failed_with_description(
                            property.property,
                            StatusCode::PRECONDITION_FAILED,
                            CalCondition::SupportedCalendarComponent,
                            "Property cannot be modified",
                        );
                    }
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
                    );
                }
            }
        }
    }

    fn apply_event_properties(
        &self,
        event: &mut CalendarEvent,
        properties: impl IntoIterator<Item = DavPropertyValue>,
        items: &mut PropStatBuilder,
    ) {
        for property in properties {
            match (&property.property, property.value) {
                (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::String(name)) => {
                    if name.len() <= self.core.groupware.live_property_size {
                        event.display_name = Some(name);
                        items.insert_ok(property.property);
                    } else {
                        items.insert_error_with_description(
                            property.property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                }
                (DavProperty::WebDav(WebDavProperty::CreationDate), DavValue::Timestamp(dt)) => {
                    event.created = dt;
                    items.insert_ok(property.property);
                }
                (_, DavValue::Null) => {
                    items.insert_ok(property.property);
                }
                _ => {
                    items.insert_error_with_description(
                        property.property,
                        StatusCode::CONFLICT,
                        "Property cannot be modified",
                    );
                }
            }
        }
    }
}

fn remove_event_properties(
    event: &mut CalendarEvent,
    properties: impl IntoIterator<Item = DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::WebDav(WebDavProperty::DisplayName) => {
                event.display_name = None;
                items.insert_ok(property);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}

fn remove_calendar_properties(
    personal_id: u32,
    calendar: &mut Calendar,
    properties: impl IntoIterator<Item = DavProperty>,
    items: &mut PropStatBuilder,
) {
    for property in properties {
        match &property {
            DavProperty::CalDav(CalDavProperty::CalendarDescription) => {
                calendar.preferences_mut(personal_id).description = None;
                items.insert_ok(property);
            }
            DavProperty::CalDav(CalDavProperty::CalendarTimezone)
            | DavProperty::CalDav(CalDavProperty::TimezoneId) => {
                calendar.preferences_mut(personal_id).time_zone = Timezone::Default;
                items.insert_ok(property);
            }
            _ => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    "Property cannot be deleted",
                );
            }
        }
    }
}
