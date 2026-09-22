/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod copy_move;
pub mod delete;
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
use groupware::{
    calendar::{
        Alarm, ArchivedCalendarEvent, ArchivedCalendarEventContent, Calendar, CalendarEventContent,
        EVENT_HAS_ALARMS, SupportedComponent,
        alarm::ExpandAlarm,
        alerts::{DefaultAlertsResolver, DefaultAlertsView, ICalendarDefaultAlerts},
        compare::{ComparisonScope, RecurrenceComponents},
        privacy::{EventPrivacy, EventViewer, ICalendarPrivacy, PrivacyDenied},
        user::{ICalendarUserData, UserDataError, UserDataView},
    },
    scheduling::ItipError,
};
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};
use utils::map::bitmap::Bitmap;

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
    let Some(uid) = uid else {
        return Ok(());
    };
    let hits = resources.uid_matches(uid);
    if hits.is_empty() {
        return Ok(());
    }

    let is_owner = access_token.is_member(account_id);
    let mut has_hidden_conflict = false;
    for path in resources
        .children(calendar_id)
        .filter(|path| hits.contains(path.document_id()))
    {
        if is_owner
            || EventPrivacy::from_flags(path.resource.event_flags().unwrap_or_default())
                != EventPrivacy::Secret
        {
            return Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::PRECONDITION_FAILED,
                CalCondition::NoUidConflict(resources.format_resource(path).into()),
            )));
        }
        has_hidden_conflict = true;
    }

    if has_hidden_conflict {
        Err(DavError::Code(StatusCode::FORBIDDEN))
    } else {
        Ok(())
    }
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

pub(crate) struct SupportedComponents(Bitmap<SupportedComponent>);

impl SupportedComponents {
    fn is_restricted(&self) -> bool {
        !self.0.is_empty()
    }

    pub(crate) fn assert_supports(&self, component: SupportedComponent) -> crate::Result<()> {
        if !self.is_restricted() || self.0.contains(component) {
            Ok(())
        } else {
            Err(DavError::Condition(DavErrorCondition::new(
                StatusCode::FORBIDDEN,
                CalCondition::SupportedCalendarComponent,
            )))
        }
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
    fn supported_components(
        &self,
        account_id: u32,
        calendar_id: u32,
    ) -> impl Future<Output = crate::Result<SupportedComponents>> + Send;

    fn assert_stored_event_supported(
        &self,
        event_account_id: u32,
        event_document_id: u32,
        account_id: u32,
        calendar_id: u32,
    ) -> impl Future<Output = crate::Result<()>> + Send;
}

impl CalendarComponentSupport for Server {
    async fn supported_components(
        &self,
        account_id: u32,
        calendar_id: u32,
    ) -> crate::Result<SupportedComponents> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Calendar,
                calendar_id,
            ))
            .await
            .caused_by(trc::location!())?
            .map(|archive| {
                archive
                    .unarchive::<Calendar>()
                    .map(|calendar| calendar.supported_components.to_native())
            })
            .transpose()
            .caused_by(trc::location!())
            .map(|supported_components| {
                SupportedComponents(Bitmap::from(supported_components.unwrap_or_default()))
            })
            .map_err(Into::into)
    }

    async fn assert_stored_event_supported(
        &self,
        event_account_id: u32,
        event_document_id: u32,
        account_id: u32,
        calendar_id: u32,
    ) -> crate::Result<()> {
        let supported_components = self.supported_components(account_id, calendar_id).await?;
        if !supported_components.is_restricted() {
            return Ok(());
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
        )
    }
}

pub(crate) fn assert_event_privacy_access(
    flags: Option<u16>,
    viewer: EventViewer,
) -> crate::Result<()> {
    flags
        .map(EventPrivacy::from_flags)
        .unwrap_or_default()
        .check_access(viewer)
        .map_err(|denied| {
            DavError::Code(match denied {
                PrivacyDenied::Forbidden => StatusCode::FORBIDDEN,
                PrivacyDenied::NotFound => StatusCode::NOT_FOUND,
            })
        })
}

pub(crate) fn assert_event_privacy_allowed(
    ical: &ICalendar,
    viewer: EventViewer,
) -> crate::Result<()> {
    if ical.privacy().may_be_set_by(viewer) {
        Ok(())
    } else {
        Err(DavError::Code(StatusCode::FORBIDDEN))
    }
}

pub(crate) fn serves_ical(view: &ICalendar, submitted: &ICalendar) -> bool {
    view == submitted || ComparisonScope::SharedData.component_eq(view, 0, submitted, 0)
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

pub(crate) trait ItipPrecondition {
    fn failed_precondition(&self) -> Option<CalCondition>;
}

impl ItipPrecondition for ItipError {
    fn failed_precondition(&self) -> Option<CalCondition> {
        match self {
            ItipError::MultipleOrganizer => Some(CalCondition::SameOrganizerInAllComponents),
            ItipError::OrganizerIsLocalAddress
            | ItipError::SenderIsNotParticipant(_)
            | ItipError::OrganizerMismatch => Some(CalCondition::ValidOrganizer),
            ItipError::CannotModifyProperty(_)
            | ItipError::CannotModifyInstance
            | ItipError::CannotModifyAddress => Some(CalCondition::AllowedAttendeeObjectChange),
            ItipError::MissingUid
            | ItipError::MultipleUid
            | ItipError::MultipleObjectTypes
            | ItipError::MultipleObjectInstances
            | ItipError::MissingMethod
            | ItipError::InvalidComponentType
            | ItipError::OutOfSequence
            | ItipError::UnknownParticipant(_)
            | ItipError::UnsupportedMethod(_) => Some(CalCondition::ValidSchedulingMessage),
            ItipError::TooManyRecipients => Some(CalCondition::MaxAttendeesPerInstance),
            _ => None,
        }
    }
}
