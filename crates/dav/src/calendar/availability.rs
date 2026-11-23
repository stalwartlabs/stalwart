/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{DavError, PropStatBuilder, common::uri::DavUriResource};
use calcard::icalendar::ICalendar;
use common::{Server, auth::AccessToken};
use dav_proto::{
    RequestHeaders, Return,
    schema::{
        Namespace,
        property::{CalDavProperty, DavProperty, DavValue},
        request::{DavPropertyValue, PropertyUpdate, PropertyUpdateOp},
        response::{CalCondition, MultiStatus, Response},
    },
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        SCHEDULE_INBOX_ID,
        working_hours::{
            WorkingHoursChange, WorkingHoursHandler, WorkingHoursUpdate, WorkingSchedule,
            ical::parse_vavailability,
        },
    },
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::schema::enums::Permission;
use store::write::now;
use trc::AddContext;
use types::collection::SyncCollection;

pub(crate) trait CalendarAvailabilityRequestHandler: Sync + Send {
    fn handle_scheduling_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl CalendarAvailabilityRequestHandler for Server {
    async fn handle_scheduling_proppatch_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        request: PropertyUpdate,
    ) -> crate::Result<HttpResponse> {
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::CalendarEventNotification,
            )
            .await
            .caused_by(trc::location!())?;
        let resource = resource_
            .resource
            .and_then(|path| resources.by_path(path))
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        if !resource.is_container() || resource.document_id() != SCHEDULE_INBOX_ID {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        }
        if !access_token.is_member(account_id)
            || !access_token.has_permission(Permission::SysCalendarSettingsUpdate)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }
        if request.ops.is_empty() {
            return Ok(HttpResponse::new(StatusCode::NO_CONTENT));
        }

        let mut items = PropStatBuilder::default();
        let mut change = None;
        let mut multistatus =
            MultiStatus::new(Vec::with_capacity(1)).with_namespace(Namespace::CalDav);
        for op in request.ops {
            multistatus.set_namespace(match &op {
                PropertyUpdateOp::Set(DavPropertyValue { property, .. })
                | PropertyUpdateOp::Remove(property) => property.namespace(),
            });
            match op {
                PropertyUpdateOp::Set(DavPropertyValue {
                    property:
                        property @ DavProperty::CalDav(CalDavProperty::CalendarAvailability(_)),
                    value,
                }) => match value {
                    DavValue::ICalendar(ical)
                        if ical.size() > self.core.groupware.max_ical_size =>
                    {
                        items.insert_error_with_description(
                            property,
                            StatusCode::INSUFFICIENT_STORAGE,
                            "Property value is too long",
                        );
                    }
                    DavValue::ICalendar(ical) => match working_hours_change(&ical) {
                        Ok(new_change) => {
                            change = Some(new_change);
                            items.insert_ok(property);
                        }
                        Err(description) => {
                            items.insert_precondition_failed_with_description(
                                property,
                                StatusCode::FORBIDDEN,
                                CalCondition::ValidCalendarData,
                                description,
                            );
                        }
                    },
                    _ => {
                        items.insert_precondition_failed_with_description(
                            property,
                            StatusCode::FORBIDDEN,
                            CalCondition::ValidCalendarData,
                            "Invalid calendar data",
                        );
                    }
                },
                PropertyUpdateOp::Remove(
                    property @ DavProperty::CalDav(CalDavProperty::CalendarAvailability(_)),
                ) => {
                    change = Some(WorkingHoursChange::Disable);
                    items.insert_ok(property);
                }
                PropertyUpdateOp::Set(DavPropertyValue { property, .. })
                | PropertyUpdateOp::Remove(property) => {
                    items.insert_error_with_description(
                        property,
                        StatusCode::FORBIDDEN,
                        "Property cannot be modified",
                    );
                }
            }
        }

        let is_success = !items.has_errors();
        if is_success {
            if let Some(change) = change {
                match self
                    .update_working_hours(account_id, change)
                    .await
                    .caused_by(trc::location!())?
                {
                    WorkingHoursUpdate::Updated => {}
                    WorkingHoursUpdate::NotSupported => {
                        return Err(DavError::Code(StatusCode::FORBIDDEN));
                    }
                    WorkingHoursUpdate::Rejected => {
                        return Err(DavError::Code(StatusCode::CONFLICT));
                    }
                }
            }
        } else {
            items.fail_dependencies();
        }

        if headers.ret != Return::Minimal || !is_success {
            multistatus.add_response(Response::new_propstat(headers.uri, items.build()));
            Ok(HttpResponse::new(StatusCode::MULTI_STATUS).with_xml_body(multistatus.to_string()))
        } else {
            Ok(HttpResponse::new(StatusCode::NO_CONTENT))
        }
    }
}

fn working_hours_change(ical: &ICalendar) -> Result<WorkingHoursChange, String> {
    let hours = parse_vavailability(ical, now() as i64).map_err(|err| err.to_string())?;
    if WorkingSchedule::parse(&hours, None)
        .map_err(|err| err.to_string())?
        .covers_whole_week()
    {
        Ok(WorkingHoursChange::Disable)
    } else {
        Ok(WorkingHoursChange::Replace(hours))
    }
}
