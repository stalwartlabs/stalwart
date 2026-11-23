/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod availability;
pub mod copy_move;
pub mod delete;
pub mod filter;
pub mod freebusy;
pub mod get;
pub mod mkcol;
pub mod proppatch;
pub mod query;
pub mod scheduling;
pub mod update;
pub mod view;

use crate::{
    DavError, DavErrorCondition,
    common::{ContainerOperation, MergedOverrides},
};
use calcard::icalendar::{
    ArchivedICalendar, ArchivedICalendarComponentType, ICalendar, ICalendarComponent,
    ICalendarComponentType,
};
use common::{ArchivedDavName, GroupwareResources, Server, auth::AccessToken};
use dav_proto::schema::{
    property::{CalDavProperty, CalendarData, DavProperty, WebDavProperty},
    response::CalCondition,
};
use groupware::calendar::{
    Alarm, ArchivedCalendarEvent, ArchivedCalendarEventContent, CalendarEventContent,
    EVENT_HAS_ALARMS, SupportedComponent,
    alarm::ExpandAlarm,
    alerts::{DefaultAlertsResolver, DefaultAlertsView, ICalendarDefaultAlerts},
    compare::RecurrenceComponents,
    privacy::{EventPrivacy, EventViewer},
    user::{ICalendarUserData, UserDataError, UserDataView},
    write::{
        EventWriteError, SchedulingPrecondition, SupportedComponents, assert_privacy_access,
        assert_unique_uid,
    },
};
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

pub(crate) static CALENDAR_CONTAINER_PROPS: [DavProperty; 31] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::SupportedReportSet),
    DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes),
    DavProperty::WebDav(WebDavProperty::QuotaUsedBytes),
    DavProperty::CalDav(CalDavProperty::CalendarDescription),
    DavProperty::CalDav(CalDavProperty::SupportedCalendarData),
    DavProperty::CalDav(CalDavProperty::SupportedCollationSet),
    DavProperty::CalDav(CalDavProperty::SupportedCalendarComponentSet),
    DavProperty::CalDav(CalDavProperty::CalendarTimezone),
    DavProperty::CalDav(CalDavProperty::MaxResourceSize),
    DavProperty::CalDav(CalDavProperty::MinDateTime),
    DavProperty::CalDav(CalDavProperty::MaxDateTime),
    DavProperty::CalDav(CalDavProperty::MaxInstances),
    DavProperty::CalDav(CalDavProperty::MaxAttendeesPerInstance),
    DavProperty::CalDav(CalDavProperty::TimezoneServiceSet),
    DavProperty::CalDav(CalDavProperty::TimezoneId),
];

pub(crate) static CALENDAR_ITEM_PROPS: [DavProperty; 20] = [
    DavProperty::WebDav(WebDavProperty::CreationDate),
    DavProperty::WebDav(WebDavProperty::DisplayName),
    DavProperty::WebDav(WebDavProperty::GetETag),
    DavProperty::WebDav(WebDavProperty::GetLastModified),
    DavProperty::WebDav(WebDavProperty::ResourceType),
    DavProperty::WebDav(WebDavProperty::LockDiscovery),
    DavProperty::WebDav(WebDavProperty::SupportedLock),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal),
    DavProperty::WebDav(WebDavProperty::SyncToken),
    DavProperty::WebDav(WebDavProperty::Owner),
    DavProperty::WebDav(WebDavProperty::SupportedPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
    DavProperty::WebDav(WebDavProperty::Acl),
    DavProperty::WebDav(WebDavProperty::AclRestrictions),
    DavProperty::WebDav(WebDavProperty::InheritedAclSet),
    DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet),
    DavProperty::WebDav(WebDavProperty::GetContentLanguage),
    DavProperty::WebDav(WebDavProperty::GetContentLength),
    DavProperty::WebDav(WebDavProperty::GetContentType),
    DavProperty::CalDav(CalDavProperty::CalendarData(CalendarData {
        properties: vec![],
        expand: None,
        limit_recurrence: None,
        limit_freebusy: None,
    })),
];

pub(crate) fn assert_is_unique_uid(
    resources: &GroupwareResources,
    access_token: &AccessToken,
    account_id: u32,
    calendar_id: u32,
    uid: Option<&str>,
) -> crate::Result<()> {
    assert_unique_uid(resources, access_token, account_id, calendar_id, uid).map_err(Into::into)
}

impl ContainerOperation {
    pub(crate) fn event_ids(
        self,
        resources: &GroupwareResources,
        path: &str,
        viewer: EventViewer,
    ) -> crate::Result<Vec<u32>> {
        let mut document_ids = Vec::new();
        for resource in resources.subtree(path).filter(|r| !r.is_container()) {
            match EventPrivacy::from_flags(resource.resource.event_flags().unwrap_or_default()) {
                _ if viewer.is_owner() => document_ids.push(resource.document_id()),
                EventPrivacy::Public => document_ids.push(resource.document_id()),
                EventPrivacy::Secret if self == ContainerOperation::Copy => {}
                EventPrivacy::Private | EventPrivacy::Secret => {
                    return Err(DavError::Code(StatusCode::FORBIDDEN));
                }
            }
        }
        Ok(document_ids)
    }
}

trait CalendarObjectComponent {
    fn object_component(&self) -> SupportedComponent;
}

impl CalendarObjectComponent for ArchivedICalendar {
    fn object_component(&self) -> SupportedComponent {
        self.components
            .iter()
            .find_map(|component| match component.component_type {
                ArchivedICalendarComponentType::VEvent => Some(SupportedComponent::VEvent),
                ArchivedICalendarComponentType::VTodo => Some(SupportedComponent::VTodo),
                ArchivedICalendarComponentType::VJournal => Some(SupportedComponent::VJournal),
                ArchivedICalendarComponentType::VFreebusy => Some(SupportedComponent::VFreebusy),
                ArchivedICalendarComponentType::VAvailability => {
                    Some(SupportedComponent::VAvailability)
                }
                _ => None,
            })
            .unwrap_or(SupportedComponent::Other)
    }
}

pub(crate) trait CalendarComponentSupport: Sync + Send {
    fn assert_stored_event_supported(
        &self,
        event_account_id: u32,
        event_document_id: u32,
        account_id: u32,
        calendar_id: u32,
    ) -> impl Future<Output = crate::Result<Option<Archive<ArchiveBytes>>>> + Send;
}

impl CalendarComponentSupport for Server {
    async fn assert_stored_event_supported(
        &self,
        event_account_id: u32,
        event_document_id: u32,
        account_id: u32,
        calendar_id: u32,
    ) -> crate::Result<Option<Archive<ArchiveBytes>>> {
        let supported_components =
            SupportedComponents::fetch(self, account_id, calendar_id).await?;
        if !supported_components.is_restricted() {
            return Ok(None);
        }

        let content = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                event_account_id,
                Collection::CalendarEvent,
                event_document_id,
                CalendarEventField::Content,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        supported_components.assert_supports(
            content
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?
                .data
                .event
                .object_component(),
        )?;
        Ok(Some(content))
    }
}

pub(crate) fn assert_event_privacy_access(
    flags: Option<u16>,
    viewer: EventViewer,
) -> crate::Result<()> {
    assert_privacy_access(flags, viewer).map_err(Into::into)
}

pub(crate) trait CalendarEventView: Sync + Send {
    fn calendar_event_view(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        event: &ArchivedCalendarEvent,
        content: &ArchivedCalendarEventContent,
        default_alerts: &mut DefaultAlertsResolver,
    ) -> impl Future<Output = crate::Result<Option<(CalendarEventContent, MergedOverrides)>>> + Send;
}

impl CalendarEventView for Server {
    async fn calendar_event_view(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        event: &ArchivedCalendarEvent,
        content: &ArchivedCalendarEventContent,
        default_alerts: &mut DefaultAlertsResolver,
    ) -> crate::Result<Option<(CalendarEventContent, MergedOverrides)>> {
        let flags = event.flags.to_native();
        let is_owner = access_token.is_member(account_id);
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);
        let is_private_view = !is_owner && EventPrivacy::from_flags(flags) != EventPrivacy::Public;
        let preferences = content.preferences(personal_id);
        let use_default_alerts = preferences.is_some_and(|p| p.use_default_alerts());
        if !is_private_view
            && !use_default_alerts
            && (is_owner
                || (flags & EVENT_HAS_ALARMS == 0
                    && preferences.is_none()
                    && !content
                        .data
                        .event
                        .components
                        .iter()
                        .any(|component| component.component_type.is_alarm())))
        {
            return Ok(None);
        }

        if is_private_view {
            let mut view = rkyv_deserialize::<_, CalendarEventContent>(content)
                .map(CalendarEventContent::into_private_view)
                .caused_by(trc::location!())?;
            let merged_overrides = view.data.event.blank_unreachable_components();
            return Ok(Some((view, merged_overrides)));
        }

        let resolved_default_alerts = default_alerts
            .resolve_for_ical_view(
                self,
                account_id,
                personal_id,
                content,
                event.names.iter().map(ArchivedDavName::parent_id),
            )
            .await
            .caused_by(trc::location!())?;
        let mut view =
            rkyv_deserialize::<_, CalendarEventContent>(content).caused_by(trc::location!())?;
        if !is_owner {
            let preferences = view
                .preferences
                .iter()
                .find(|p| p.account_id == personal_id);
            view.data
                .event
                .apply_user_data(preferences, UserDataView::AlertsOnly);
        }
        view.data
            .event
            .apply_default_alerts(&resolved_default_alerts, DefaultAlertsView::ICalendar);
        let merged_overrides = view.data.event.blank_unreachable_components();
        view.data.alarms = view.data.event.served_alarms();
        Ok(Some((view, merged_overrides)))
    }
}

trait UnreachableComponents {
    fn blank_unreachable_components(&mut self) -> MergedOverrides;
}

impl UnreachableComponents for ICalendar {
    fn blank_unreachable_components(&mut self) -> MergedOverrides {
        let mut is_reachable = vec![false; self.components.len()];
        let mut pending = vec![0u32];
        while let Some(component_id) = pending.pop() {
            match is_reachable.get_mut(component_id as usize) {
                Some(is_reachable) if !*is_reachable => *is_reachable = true,
                _ => continue,
            }
            if let Some(component) = self.components.get(component_id as usize) {
                pending.extend_from_slice(&component.component_ids);
            }
        }

        let mut merged_overrides = MergedOverrides::default();
        for (component_id, (component, is_reachable)) in
            self.components.iter_mut().zip(&is_reachable).enumerate()
        {
            if *is_reachable {
                continue;
            }
            if component.component_type.is_event_or_todo() && component.is_recurrence_override() {
                merged_overrides.push(component_id as u32);
            }
            *component = ICalendarComponent {
                component_type: ICalendarComponentType::Other(Default::default()),
                entries: vec![],
                component_ids: vec![],
            };
        }
        merged_overrides.set_base(self.base_component_id());
        merged_overrides
    }
}

trait ServedAlarms {
    fn served_alarms(&self) -> Box<[Alarm]>;
}

impl ServedAlarms for ICalendar {
    fn served_alarms(&self) -> Box<[Alarm]> {
        self.components
            .iter()
            .enumerate()
            .filter(|(_, component)| component.component_type.is_event_or_todo())
            .flat_map(|(parent_id, component)| {
                component.component_ids.iter().filter_map(move |alarm_id| {
                    self.components
                        .get(*alarm_id as usize)
                        .filter(|alarm| alarm.component_type.is_alarm())
                        .and_then(|alarm| alarm.expand_alarm(*alarm_id as u16, parent_id as u16))
                })
            })
            .collect()
    }
}

pub(crate) fn user_data_error(err: UserDataError) -> DavError {
    DavError::Condition(
        DavErrorCondition::new(
            StatusCode::PRECONDITION_FAILED,
            CalCondition::ValidCalendarData,
        )
        .with_details(match err {
            UserDataError::TooManyKeywords => "Too many categories",
            UserDataError::KeywordTooLong => "Category too long",
            UserDataError::TooManyAlerts => "Too many alarms",
            UserDataError::TooManyInstances => {
                "Too many recurrence instances with personal properties"
            }
            UserDataError::InvalidColor => "Invalid color",
        }),
    )
}

impl From<EventWriteError> for DavError {
    fn from(err: EventWriteError) -> Self {
        match err {
            EventWriteError::NotFound => DavError::Code(StatusCode::NOT_FOUND),
            EventWriteError::Forbidden
            | EventWriteError::UidChanged(None)
            | EventWriteError::UidConflict { href: None, .. } => {
                DavError::Code(StatusCode::FORBIDDEN)
            }
            EventWriteError::InvalidObject => DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    CalCondition::ValidCalendarObjectResource,
                )
                .with_details("iCalendar must contain exactly one UID and same component types"),
            ),
            EventWriteError::UidChanged(Some(path))
            | EventWriteError::UidConflict {
                href: Some(path), ..
            } => DavError::Condition(DavErrorCondition::new(
                StatusCode::FORBIDDEN,
                CalCondition::NoUidConflict(path.into()),
            )),
            EventWriteError::UnsupportedComponent => DavError::Condition(DavErrorCondition::new(
                StatusCode::FORBIDDEN,
                CalCondition::SupportedCalendarComponent,
            )),
            EventWriteError::ScheduleTagMismatch => DavError::Code(StatusCode::PRECONDITION_FAILED),
            EventWriteError::UserData(err) => user_data_error(err),
            EventWriteError::TooManyRecipients => DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::MaxAttendeesPerInstance,
            )),
            EventWriteError::Scheduling(precondition, err) => DavError::Condition(
                DavErrorCondition::new(
                    StatusCode::PRECONDITION_FAILED,
                    match precondition {
                        SchedulingPrecondition::SameOrganizerInAllComponents => {
                            CalCondition::SameOrganizerInAllComponents
                        }
                        SchedulingPrecondition::ValidOrganizer => CalCondition::ValidOrganizer,
                        SchedulingPrecondition::AllowedAttendeeObjectChange => {
                            CalCondition::AllowedAttendeeObjectChange
                        }
                        SchedulingPrecondition::ValidSchedulingMessage => {
                            CalCondition::ValidSchedulingMessage
                        }
                        SchedulingPrecondition::MaxAttendeesPerInstance => {
                            CalCondition::MaxAttendeesPerInstance
                        }
                    },
                )
                .with_details(err.to_string()),
            ),
            EventWriteError::Store(err) => DavError::Internal(err),
        }
    }
}
