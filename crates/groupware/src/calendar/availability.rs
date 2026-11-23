/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CALENDAR_AVAILABILITY_ALL, CALENDAR_AVAILABILITY_ATTENDING, CALENDAR_AVAILABILITY_NONE,
    CALENDAR_SUBSCRIBED, default_preference_flags, identity::CalendarAddresses,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ArchivedICalendarComponent, ArchivedICalendarParameterValue,
        ArchivedICalendarParticipationStatus, ArchivedICalendarProperty, ArchivedICalendarStatus,
        ArchivedICalendarTransparency, ArchivedICalendarValue, ICalendarParameterName,
    },
};
use common::{CachedName, GroupwareResources, Server, auth::AccessToken};
use store::{ahash::AHashMap, roaring::RoaringBitmap};
#[cfg(feature = "enterprise")]
use trc::AddContext;
use types::acl::Acl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilityPreference {
    All,
    Attending,
    None,
}

impl AvailabilityPreference {
    pub fn from_flags(flags: u16) -> Option<Self> {
        if flags & CALENDAR_AVAILABILITY_ALL != 0 {
            Some(AvailabilityPreference::All)
        } else if flags & CALENDAR_AVAILABILITY_ATTENDING != 0 {
            Some(AvailabilityPreference::Attending)
        } else if flags & CALENDAR_AVAILABILITY_NONE != 0 {
            Some(AvailabilityPreference::None)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalRole {
    Owner,
    Sharee,
}

impl PrincipalRole {
    pub fn of(principal: &AccessToken, account_id: u32) -> Self {
        if principal.is_member(account_id) {
            PrincipalRole::Owner
        } else {
            PrincipalRole::Sharee
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Inclusion {
    Attending,
    All,
}

impl Inclusion {
    pub fn from_flags(flags: u16, role: PrincipalRole) -> Option<Self> {
        if flags & CALENDAR_SUBSCRIBED == 0 {
            return None;
        }
        match (AvailabilityPreference::from_flags(flags), role) {
            (Some(AvailabilityPreference::All), _) | (None, PrincipalRole::Owner) => {
                Some(Inclusion::All)
            }
            (Some(AvailabilityPreference::Attending), _) => Some(Inclusion::Attending),
            (Some(AvailabilityPreference::None), _) | (None, PrincipalRole::Sharee) => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RelevantCalendar {
    pub inclusion: Inclusion,
    pub tz: Tz,
}

impl RelevantCalendar {
    pub fn includes(&self, busy: &ComponentBusy) -> bool {
        self.inclusion == Inclusion::All || busy.is_attending()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultFreeBusy {
    Granted,
    Denied,
}

impl DefaultFreeBusy {
    pub fn of(granted: bool) -> Self {
        if granted {
            DefaultFreeBusy::Granted
        } else {
            DefaultFreeBusy::Denied
        }
    }

    pub async fn resolve(
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<Self> {
        if !server.core.groupware.share_free_busy || access_token.is_member(account_id) {
            return Ok(DefaultFreeBusy::Denied);
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let granted = server
            .try_account(account_id)
            .await
            .caused_by(trc::location!())?
            .is_some_and(|account| account.is_same_tenant(access_token));
        // SPDX-SnippetEnd

        #[cfg(not(feature = "enterprise"))]
        let granted = true;

        Ok(Self::of(granted))
    }
}

enum CalendarAccess {
    All,
    Shared(RoaringBitmap),
}

impl CalendarAccess {
    fn contains(&self, calendar_id: u32) -> bool {
        match self {
            CalendarAccess::All => true,
            CalendarAccess::Shared(calendar_ids) => calendar_ids.contains(calendar_id),
        }
    }
}

pub struct AvailabilityCalendars<'x> {
    resources: &'x GroupwareResources,
    access_token: &'x AccessToken,
    account_id: u32,
    principal_id: u32,
    role: PrincipalRole,
    free_busy: CalendarAccess,
    subscribable: CalendarAccess,
    readable: Option<CalendarAccess>,
    relevance: AHashMap<u32, Option<RelevantCalendar>>,
}

impl<'x> AvailabilityCalendars<'x> {
    pub fn new(
        resources: &'x GroupwareResources,
        account_id: u32,
        access_token: &'x AccessToken,
        principal: &AccessToken,
        default: DefaultFreeBusy,
    ) -> Option<Self> {
        let role = PrincipalRole::of(principal, account_id);
        let default = match role {
            PrincipalRole::Owner => default,
            PrincipalRole::Sharee => DefaultFreeBusy::Denied,
        };
        let free_busy = Self::free_busy_access(resources, account_id, access_token, default)?;
        let subscribable = match role {
            PrincipalRole::Owner => CalendarAccess::All,
            PrincipalRole::Sharee => CalendarAccess::Shared(resources.shared_containers(
                principal,
                [Acl::Read, Acl::ReadItems],
                true,
            )),
        };
        Some(Self::build(
            resources,
            account_id,
            access_token,
            principal.account_id(),
            role,
            free_busy,
            subscribable,
        ))
    }

    pub fn owner(
        resources: &'x GroupwareResources,
        account_id: u32,
        access_token: &'x AccessToken,
        default: DefaultFreeBusy,
    ) -> Option<Self> {
        let free_busy = Self::free_busy_access(resources, account_id, access_token, default)?;
        Some(Self::build(
            resources,
            account_id,
            access_token,
            account_id,
            PrincipalRole::Owner,
            free_busy,
            CalendarAccess::All,
        ))
    }

    pub fn published(
        resources: &'x GroupwareResources,
        account_id: u32,
        access_token: &'x AccessToken,
    ) -> Self {
        Self::build(
            resources,
            account_id,
            access_token,
            account_id,
            PrincipalRole::Owner,
            CalendarAccess::All,
            CalendarAccess::All,
        )
    }

    fn free_busy_access(
        resources: &GroupwareResources,
        account_id: u32,
        access_token: &AccessToken,
        default: DefaultFreeBusy,
    ) -> Option<CalendarAccess> {
        if default == DefaultFreeBusy::Granted || access_token.is_member(account_id) {
            Some(CalendarAccess::All)
        } else {
            let calendar_ids = resources.shared_containers(
                access_token,
                [Acl::ReadItems, Acl::SchedulingReadFreeBusy],
                true,
            );
            (!calendar_ids.is_empty()).then_some(CalendarAccess::Shared(calendar_ids))
        }
    }

    fn build(
        resources: &'x GroupwareResources,
        account_id: u32,
        access_token: &'x AccessToken,
        principal_id: u32,
        role: PrincipalRole,
        free_busy: CalendarAccess,
        subscribable: CalendarAccess,
    ) -> Self {
        AvailabilityCalendars {
            resources,
            access_token,
            account_id,
            principal_id,
            role,
            free_busy,
            subscribable,
            readable: None,
            relevance: AHashMap::new(),
        }
    }

    pub fn role(&self) -> PrincipalRole {
        self.role
    }

    pub fn relevant_calendar(&mut self, names: &[CachedName]) -> Option<RelevantCalendar> {
        names
            .iter()
            .filter_map(|name| self.calendar_relevance(name.parent_id))
            .reduce(|best, calendar| {
                if calendar.inclusion > best.inclusion {
                    calendar
                } else {
                    best
                }
            })
    }

    fn calendar_relevance(&mut self, calendar_id: u32) -> Option<RelevantCalendar> {
        if let Some(relevance) = self.relevance.get(&calendar_id) {
            return *relevance;
        }
        let relevance = self.evaluate(calendar_id);
        self.relevance.insert(calendar_id, relevance);
        relevance
    }

    fn evaluate(&self, calendar_id: u32) -> Option<RelevantCalendar> {
        if !self.free_busy.contains(calendar_id) || !self.subscribable.contains(calendar_id) {
            return None;
        }
        let calendar = self.resources.container_resource_by_id(calendar_id)?;
        let (flags, tz) = match calendar.personal_calendar_preferences(self.principal_id) {
            Some(preferences) => (preferences.flags, preferences.tz),
            None if self.role == PrincipalRole::Owner => (
                default_preference_flags(true),
                calendar.calendar_preferences(self.principal_id)?.tz,
            ),
            None => return None,
        };
        Inclusion::from_flags(flags, self.role).map(|inclusion| RelevantCalendar { inclusion, tz })
    }

    pub fn may_read_items(&mut self, names: &[CachedName]) -> bool {
        let AvailabilityCalendars {
            resources,
            access_token,
            account_id,
            readable,
            ..
        } = self;
        let readable = readable.get_or_insert_with(|| {
            if access_token.is_member(*account_id) {
                CalendarAccess::All
            } else {
                CalendarAccess::Shared(resources.shared_containers(
                    access_token,
                    [Acl::ReadItems],
                    true,
                ))
            }
        });
        names.iter().any(|name| readable.contains(name.parent_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyLevel {
    Confirmed,
    Tentative,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Participation {
    Attendee(ParticipationStatus),
    Organizer,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParticipationStatus {
    Accepted,
    Tentative,
    Declined,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventStatus {
    Confirmed,
    Tentative,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub struct ComponentBusy {
    status: EventStatus,
    participation: Participation,
    has_attendees: bool,
    is_recurrent_or_override: bool,
}

impl ComponentBusy {
    pub fn parse(
        component: &ArchivedICalendarComponent,
        identities: &CalendarAddresses,
        role: PrincipalRole,
    ) -> Option<Self> {
        if !component.component_type.is_event() {
            return None;
        }
        let is_principal = |value: &ArchivedICalendarValue| {
            value
                .as_text()
                .is_some_and(|address| identities.contains(address))
        };
        let mut busy = ComponentBusy {
            status: EventStatus::Confirmed,
            participation: Participation::None,
            has_attendees: false,
            is_recurrent_or_override: false,
        };

        for entry in component.entries.iter() {
            match (&entry.name, entry.values.first()) {
                (
                    ArchivedICalendarProperty::Status,
                    Some(ArchivedICalendarValue::Status(status)),
                ) => {
                    busy.status = match status {
                        ArchivedICalendarStatus::Cancelled => return None,
                        ArchivedICalendarStatus::Confirmed => EventStatus::Confirmed,
                        ArchivedICalendarStatus::Tentative => EventStatus::Tentative,
                        _ => EventStatus::Other,
                    };
                }
                (
                    ArchivedICalendarProperty::Transp,
                    Some(ArchivedICalendarValue::Transparency(
                        ArchivedICalendarTransparency::Transparent,
                    )),
                ) if role == PrincipalRole::Owner => {
                    return None;
                }
                (ArchivedICalendarProperty::Organizer, Some(value)) => {
                    if busy.participation == Participation::None && is_principal(value) {
                        busy.participation = Participation::Organizer;
                    }
                }
                (ArchivedICalendarProperty::Attendee, Some(value)) => {
                    busy.has_attendees = true;
                    if is_principal(value) {
                        busy.participation = Participation::Attendee(
                            match entry.parameters(&ICalendarParameterName::Partstat).next() {
                                Some(ArchivedICalendarParameterValue::Partstat(
                                    ArchivedICalendarParticipationStatus::Accepted,
                                )) => ParticipationStatus::Accepted,
                                Some(ArchivedICalendarParameterValue::Partstat(
                                    ArchivedICalendarParticipationStatus::Tentative,
                                )) => ParticipationStatus::Tentative,
                                Some(ArchivedICalendarParameterValue::Partstat(
                                    ArchivedICalendarParticipationStatus::Declined,
                                )) => ParticipationStatus::Declined,
                                _ => ParticipationStatus::Other,
                            },
                        );
                    }
                }
                (
                    ArchivedICalendarProperty::Rrule
                    | ArchivedICalendarProperty::Rdate
                    | ArchivedICalendarProperty::RecurrenceId,
                    _,
                ) => {
                    busy.is_recurrent_or_override = true;
                }
                _ => (),
            }
        }

        Some(busy)
    }

    pub fn is_attending(&self) -> bool {
        matches!(
            self.participation,
            Participation::Organizer
                | Participation::Attendee(
                    ParticipationStatus::Accepted | ParticipationStatus::Tentative
                )
        )
    }

    pub fn is_recurrent_or_override(&self) -> bool {
        self.is_recurrent_or_override
    }

    fn participation_status(&self) -> ParticipationStatus {
        match self.participation {
            Participation::Attendee(status) => status,
            Participation::Organizer => ParticipationStatus::Accepted,
            Participation::None if !self.has_attendees => ParticipationStatus::Accepted,
            Participation::None => ParticipationStatus::Other,
        }
    }

    pub fn busy_level(&self) -> BusyLevel {
        let participation_status = self.participation_status();
        if self.status == EventStatus::Tentative
            || participation_status == ParticipationStatus::Tentative
        {
            BusyLevel::Tentative
        } else if self.status == EventStatus::Confirmed
            && participation_status == ParticipationStatus::Accepted
        {
            BusyLevel::Confirmed
        } else {
            BusyLevel::Unavailable
        }
    }
}
