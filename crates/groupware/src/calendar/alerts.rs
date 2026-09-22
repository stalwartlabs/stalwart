/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::alarm::{AlarmTarget, CalendarComponentView, CalendarView};
use super::schedule::{EventAlarmContent, EventAlarmScheduler, EventAlarmUsers};
use super::{
    ALERT_EMAIL, ALERT_RELATIVE_TO_END, ALERT_WITH_TIME, AlarmDelta, ArchivedCalendar,
    CALENDAR_SUBSCRIBED, Calendar, CalendarEvent, CalendarEventContent, DefaultAlert,
    EVENT_HAS_ALARMS, EVENT_USES_DEFAULT_ALERTS, default_preference_flags,
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarAction, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameter, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarRelated, ICalendarRelationshipType, ICalendarValue, Uri,
    },
};
use common::{ArchivedDavName, GroupwareResources, Server};
use std::{collections::hash_map::Entry, sync::Arc};
use store::{
    ValueKey,
    ahash::{AHashMap, AHashSet},
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

const MAX_DEFAULT_ALERTS: usize = 1024;
const DEFAULT_ALARM_DESCRIPTION: &str = "Reminder";
const MAILTO_PREFIX: &str = "mailto:";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DefaultAlerts {
    enabled: bool,
    alerts: Vec<DefaultAlert>,
    recipient: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy)]
pub struct DefaultAlarmText<'x> {
    pub description: &'x str,
    pub recipient: Option<&'x str>,
}

impl DefaultAlerts {
    pub fn disabled() -> Self {
        DefaultAlerts::default()
    }

    pub(crate) fn merge<'x>(
        calendars: impl Iterator<Item = &'x CalendarSettings>,
        personal_id: u32,
        inherit_from: Option<u32>,
        with_time: bool,
    ) -> Self {
        let mut alert_ids = AHashSet::new();
        DefaultAlerts {
            enabled: true,
            alerts: calendars
                .filter_map(|settings| settings.user_or_inherited(personal_id, inherit_from))
                .flat_map(|settings| settings.alerts.iter())
                .filter(|alert| {
                    (alert.flags & ALERT_WITH_TIME != 0) == with_time
                        && alert_ids.insert(alert.id.as_str())
                })
                .take(MAX_DEFAULT_ALERTS)
                .cloned()
                .collect(),
            recipient: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn has_alerts(&self) -> bool {
        !self.alerts.is_empty()
    }

    pub fn has_email_alerts(&self) -> bool {
        self.alerts.iter().any(DefaultAlert::is_email)
    }

    pub fn get(&self, index: u16) -> Option<&DefaultAlert> {
        self.alerts.get(index as usize)
    }

    pub fn contains_id(&self, id: &str) -> bool {
        self.alerts.iter().any(|alert| alert.id == id)
    }

    pub fn indexed_alerts(&self) -> impl Iterator<Item = (u16, &DefaultAlert)> {
        self.alerts
            .iter()
            .zip(0u16..)
            .map(|(alert, index)| (index, alert))
    }
}

impl DefaultAlert {
    pub fn is_email(&self) -> bool {
        self.flags & ALERT_EMAIL != 0
    }

    pub fn delta(&self) -> AlarmDelta {
        if self.flags & ALERT_RELATIVE_TO_END != 0 {
            AlarmDelta::End(self.offset.as_seconds())
        } else {
            AlarmDelta::Start(self.offset.as_seconds())
        }
    }

    pub fn to_ical(&self, text: Option<DefaultAlarmText<'_>>) -> ICalendarComponent {
        let mut entries = Vec::with_capacity(6);
        entries.push(
            ICalendarEntry::new(ICalendarProperty::Jsid)
                .with_value(ICalendarValue::Text(self.id.clone())),
        );
        entries.push(ICalendarEntry::new(ICalendarProperty::Action).with_value(
            if self.is_email() {
                ICalendarValue::Action(ICalendarAction::Email)
            } else {
                ICalendarValue::Action(ICalendarAction::Display)
            },
        ));
        entries.push(
            ICalendarEntry::new(ICalendarProperty::Trigger)
                .with_param_opt((self.flags & ALERT_RELATIVE_TO_END != 0).then_some(
                    ICalendarParameter::related(ICalendarParameterValue::Related(
                        ICalendarRelated::End,
                    )),
                ))
                .with_value(ICalendarValue::Duration(self.offset.clone())),
        );
        if let Some(text) = text {
            entries.push(
                ICalendarEntry::new(ICalendarProperty::Description).with_value(text.description),
            );
            if self.is_email() {
                entries.push(
                    ICalendarEntry::new(ICalendarProperty::Summary).with_value(text.description),
                );
                if let Some(recipient) = text.recipient {
                    let mut address = String::with_capacity(MAILTO_PREFIX.len() + recipient.len());
                    address.push_str(MAILTO_PREFIX);
                    address.push_str(recipient);
                    entries.push(
                        ICalendarEntry::new(ICalendarProperty::Attendee)
                            .with_value(Uri::Location(address)),
                    );
                }
            }
        }

        ICalendarComponent {
            component_type: ICalendarComponentType::VAlarm,
            entries,
            component_ids: vec![],
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CalendarSettings(Vec<UserCalendarSettings>);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UserCalendarSettings {
    pub account_id: u32,
    pub is_subscribed: bool,
    pub time_zone: Tz,
    pub alerts: Vec<DefaultAlert>,
}

impl UserCalendarSettings {
    fn differs_only_in_alerts(&self, other: &Self) -> bool {
        self.is_subscribed == other.is_subscribed && self.time_zone == other.time_zone
    }
}

impl CalendarSettings {
    pub fn user(&self, account_id: u32) -> Option<&UserCalendarSettings> {
        self.0
            .iter()
            .find(|settings| settings.account_id == account_id)
    }

    fn user_or_inherited(
        &self,
        account_id: u32,
        inherit_from: Option<u32>,
    ) -> Option<&UserCalendarSettings> {
        self.user(account_id)
            .or_else(|| inherit_from.and_then(|account_id| self.user(account_id)))
    }

    fn changes<'x>(&'x self, other: &'x Self) -> impl Iterator<Item = (u32, bool)> + 'x {
        self.0
            .iter()
            .map(|settings| settings.account_id)
            .chain(
                other
                    .0
                    .iter()
                    .map(|settings| settings.account_id)
                    .filter(|account_id| self.user(*account_id).is_none()),
            )
            .filter_map(move |account_id| {
                let previous = self.user(account_id);
                let current = other.user(account_id);
                (previous != current).then(|| {
                    (
                        account_id,
                        previous.zip(current).is_some_and(|(previous, current)| {
                            previous.differs_only_in_alerts(current)
                        }),
                    )
                })
            })
    }

    async fn fetch(server: &Server, account_id: u32, calendar_id: u32) -> trc::Result<Self> {
        server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Calendar,
                calendar_id,
            ))
            .await
            .caused_by(trc::location!())?
            .map(|archive| archive.unarchive::<Calendar>().map(CalendarSettings::from))
            .transpose()
            .map(Option::unwrap_or_default)
            .caused_by(trc::location!())
    }
}

impl From<&Calendar> for CalendarSettings {
    fn from(calendar: &Calendar) -> Self {
        CalendarSettings(
            calendar
                .preferences
                .iter()
                .map(|preferences| UserCalendarSettings {
                    account_id: preferences.account_id,
                    is_subscribed: preferences.flags & CALENDAR_SUBSCRIBED != 0,
                    time_zone: preferences.time_zone.tz().unwrap_or_default(),
                    alerts: preferences.default_alerts.clone(),
                })
                .collect(),
        )
    }
}

impl From<&ArchivedCalendar> for CalendarSettings {
    fn from(calendar: &ArchivedCalendar) -> Self {
        CalendarSettings(
            calendar
                .preferences
                .iter()
                .map(|preferences| UserCalendarSettings {
                    account_id: preferences.account_id.to_native(),
                    is_subscribed: preferences.flags.to_native() & CALENDAR_SUBSCRIBED != 0,
                    time_zone: preferences.time_zone.tz().unwrap_or_default(),
                    alerts: preferences
                        .default_alerts
                        .iter()
                        .map(|alert| DefaultAlert {
                            id: alert.id.to_string(),
                            offset: alert.offset.to_native(),
                            flags: alert.flags.to_native(),
                        })
                        .collect(),
                })
                .collect(),
        )
    }
}

#[derive(Default)]
pub struct DefaultAlertsResolver {
    calendars: AHashMap<(u32, u32), CalendarSettings>,
    resources: Option<(u32, Arc<GroupwareResources>)>,
    recipients: AHashMap<u32, Option<Arc<str>>>,
    members: AHashMap<(u32, u32), bool>,
}

impl DefaultAlertsResolver {
    pub fn with_resources(account_id: u32, resources: Arc<GroupwareResources>) -> Self {
        DefaultAlertsResolver {
            resources: Some((account_id, resources)),
            ..Default::default()
        }
    }

    pub fn with_calendar(
        mut self,
        account_id: u32,
        calendar_id: u32,
        settings: CalendarSettings,
    ) -> Self {
        self.set_calendar_settings(account_id, calendar_id, settings);
        self
    }

    pub fn set_calendar_settings(
        &mut self,
        account_id: u32,
        calendar_id: u32,
        settings: CalendarSettings,
    ) {
        self.calendars.insert((account_id, calendar_id), settings);
    }

    async fn settings(
        &mut self,
        server: &Server,
        account_id: u32,
        calendar_id: u32,
    ) -> trc::Result<&CalendarSettings> {
        Ok(match self.calendars.entry((account_id, calendar_id)) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                entry.insert(CalendarSettings::fetch(server, account_id, calendar_id).await?)
            }
        })
    }

    fn cached_subscription(
        &self,
        account_id: u32,
        personal_id: u32,
        calendar_id: u32,
    ) -> Option<Option<bool>> {
        if let Some(settings) = self.calendars.get(&(account_id, calendar_id)) {
            return Some(
                settings
                    .user(personal_id)
                    .map(|settings| settings.is_subscribed),
            );
        }
        self.resources
            .as_ref()
            .filter(|(resources_account_id, _)| *resources_account_id == account_id)
            .and_then(|(_, resources)| resources.container_resource_by_id(calendar_id))
            .map(|calendar| {
                calendar
                    .personal_calendar_preferences(personal_id)
                    .map(|preferences| preferences.flags & CALENDAR_SUBSCRIBED != 0)
            })
    }

    async fn is_member(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
    ) -> trc::Result<bool> {
        if personal_id == account_id {
            return Ok(true);
        }
        Ok(match self.members.entry((account_id, personal_id)) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => *entry.insert(
                server
                    .account(personal_id)
                    .await
                    .caused_by(trc::location!())?
                    .id_member_of
                    .contains(&account_id),
            ),
        })
    }

    pub async fn is_subscribed(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        calendar_ids: impl IntoIterator<Item = u32>,
    ) -> trc::Result<bool> {
        let mut default_subscription = None;
        for calendar_id in calendar_ids {
            let is_subscribed = match self.cached_subscription(account_id, personal_id, calendar_id)
            {
                Some(is_subscribed) => is_subscribed,
                None => self
                    .settings(server, account_id, calendar_id)
                    .await?
                    .user(personal_id)
                    .map(|settings| settings.is_subscribed),
            };
            let is_subscribed = match is_subscribed {
                Some(is_subscribed) => is_subscribed,
                None => match default_subscription {
                    Some(is_subscribed) => is_subscribed,
                    None => {
                        let is_member = self.is_member(server, account_id, personal_id).await?;
                        *default_subscription
                            .insert(default_preference_flags(is_member) & CALENDAR_SUBSCRIBED != 0)
                    }
                },
            };
            if is_subscribed {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn time_zone(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        calendar_ids: impl IntoIterator<Item = u32>,
    ) -> trc::Result<Tz> {
        let inherit_from = self
            .is_member(server, account_id, personal_id)
            .await?
            .then_some(account_id);
        for calendar_id in calendar_ids {
            if let Some(time_zone) = self
                .settings(server, account_id, calendar_id)
                .await?
                .user_or_inherited(personal_id, inherit_from)
                .map(|settings| settings.time_zone)
                .filter(|time_zone| !time_zone.is_floating())
            {
                return Ok(time_zone);
            }
        }
        Ok(Tz::Floating)
    }

    pub async fn resolve(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        use_default_alerts: bool,
        calendar_ids: impl IntoIterator<Item = u32> + Clone,
        with_time: bool,
    ) -> trc::Result<DefaultAlerts> {
        if !use_default_alerts {
            return Ok(DefaultAlerts::disabled());
        }

        for calendar_id in calendar_ids.clone() {
            self.settings(server, account_id, calendar_id).await?;
        }
        let inherit_from = self
            .is_member(server, account_id, personal_id)
            .await?
            .then_some(account_id);

        Ok(DefaultAlerts::merge(
            calendar_ids
                .into_iter()
                .filter_map(|calendar_id| self.calendars.get(&(account_id, calendar_id))),
            personal_id,
            inherit_from,
            with_time,
        ))
    }

    async fn recipient(
        &mut self,
        server: &Server,
        personal_id: u32,
    ) -> trc::Result<Option<Arc<str>>> {
        Ok(match self.recipients.entry(personal_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let account = server
                    .account(personal_id)
                    .await
                    .caused_by(trc::location!())?;
                entry
                    .insert((!account.name.is_empty()).then(|| Arc::from(account.name.as_ref())))
                    .clone()
            }
        })
    }
}

impl DefaultAlertsResolver {
    pub async fn resolve_for_content<C: EventAlarmContent + Sync>(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        content: &C,
        calendar_ids: impl IntoIterator<Item = u32> + Clone,
    ) -> trc::Result<DefaultAlerts> {
        self.resolve(
            server,
            account_id,
            personal_id,
            content.uses_default_alerts(personal_id),
            calendar_ids,
            !content.shows_without_time(),
        )
        .await
    }

    pub async fn resolve_for_ical_view<C: EventAlarmContent + Sync>(
        &mut self,
        server: &Server,
        account_id: u32,
        personal_id: u32,
        content: &C,
        calendar_ids: impl IntoIterator<Item = u32> + Clone,
    ) -> trc::Result<DefaultAlerts> {
        let mut default_alerts = self
            .resolve_for_content(server, account_id, personal_id, content, calendar_ids)
            .await?;
        if default_alerts.has_email_alerts() {
            default_alerts.recipient = self.recipient(server, personal_id).await?;
        }
        Ok(default_alerts)
    }
}

pub trait CalendarAlarmsReschedule: Sync + Send {
    #[allow(clippy::too_many_arguments)]
    fn reschedule_calendar_alarms(
        &self,
        resources: &Arc<GroupwareResources>,
        account_id: u32,
        calendar_id: u32,
        previous: CalendarSettings,
        current: CalendarSettings,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl CalendarAlarmsReschedule for Server {
    async fn reschedule_calendar_alarms(
        &self,
        resources: &Arc<GroupwareResources>,
        account_id: u32,
        calendar_id: u32,
        previous: CalendarSettings,
        current: CalendarSettings,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let mut targets = Vec::new();
        let mut required_flags = 0;
        for (changed_id, differs_only_in_alerts) in previous.changes(&current) {
            targets.push(AlarmTarget::for_account(account_id, changed_id));
            required_flags |= if differs_only_in_alerts {
                EVENT_USES_DEFAULT_ALERTS
            } else {
                EVENT_HAS_ALARMS
            };
        }
        if targets.is_empty() {
            return Ok(());
        }

        let mut previous_resolver = DefaultAlertsResolver::with_resources(
            account_id,
            resources.clone(),
        )
        .with_calendar(account_id, calendar_id, previous);
        let mut current_resolver = DefaultAlertsResolver::with_resources(
            account_id,
            resources.clone(),
        )
        .with_calendar(account_id, calendar_id, current);
        let now = now() as i64;

        for document_id in resources
            .children(calendar_id)
            .filter(|resource| {
                resource
                    .resource
                    .event_flags()
                    .is_some_and(|flags| flags & required_flags != 0)
            })
            .map(|resource| resource.document_id())
        {
            let Some(content_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                    CalendarEventField::Content,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                continue;
            };
            let content = content_
                .unarchive::<CalendarEventContent>()
                .caused_by(trc::location!())?;
            let Some(event_) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    document_id,
                ))
                .await
                .caused_by(trc::location!())?
            else {
                continue;
            };
            let event = event_
                .unarchive::<CalendarEvent>()
                .caused_by(trc::location!())?;

            let event_flags = event.flags.to_native();
            let calendar_ids = event
                .names
                .iter()
                .map(ArchivedDavName::parent_id)
                .collect::<Vec<_>>();
            for target in targets.iter().copied() {
                let users = EventAlarmUsers::for_target(account_id, content, target)?
                    .with_event_flags(event_flags);
                let previous_alarm = self
                    .next_event_alarms(
                        account_id,
                        &users,
                        &content.data,
                        &calendar_ids,
                        now,
                        &mut previous_resolver,
                    )
                    .await?
                    .into_alarm();
                let next_alarm = self
                    .next_event_alarms(
                        account_id,
                        &users,
                        &content.data,
                        &calendar_ids,
                        now,
                        &mut current_resolver,
                    )
                    .await?
                    .into_alarm();
                self.replace_user_alarm(account_id, document_id, previous_alarm, next_alarm, batch)
                    .await?;
            }
        }

        Ok(())
    }
}

pub trait ICalendarShowWithoutTime {
    fn shows_without_time(&self) -> bool;
}

impl<T: CalendarView> ICalendarShowWithoutTime for T {
    fn shows_without_time(&self) -> bool {
        self.main_component()
            .is_some_and(CalendarComponentView::is_shown_without_time)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAlertsView {
    Replace,
    Merge,
    ICalendar,
}

pub trait ICalendarDefaultAlerts {
    fn apply_default_alerts(&mut self, defaults: &DefaultAlerts, view: DefaultAlertsView);

    fn strip_default_alerts(&mut self, defaults: &DefaultAlerts);

    fn is_kept_with_default_alerts(
        &self,
        alarm: &ICalendarComponent,
        defaults: &DefaultAlerts,
    ) -> bool;

    fn restore_hidden_alerts(&mut self, previous: &ICalendar, defaults: &DefaultAlerts);
}

impl ICalendarDefaultAlerts for ICalendar {
    fn apply_default_alerts(&mut self, defaults: &DefaultAlerts, view: DefaultAlertsView) {
        if !defaults.is_enabled() {
            return;
        }

        for comp_id in 0..self.components.len() {
            let Some(component) = self.components.get(comp_id) else {
                continue;
            };
            if !component.component_type.is_event_or_todo() {
                continue;
            }

            let text = (view == DefaultAlertsView::ICalendar).then(|| DefaultAlarmText {
                description: component
                    .property(&ICalendarProperty::Summary)
                    .and_then(|entry| entry.values.first())
                    .and_then(|value| value.as_text())
                    .filter(|summary| !summary.is_empty())
                    .unwrap_or(DEFAULT_ALARM_DESCRIPTION),
                recipient: defaults.recipient.as_deref(),
            });
            let mut stored_defaults: Vec<(&str, &[ICalendarEntry])> = Vec::new();
            let mut kept_ids = Vec::new();
            let mut removed_ids = Vec::new();
            for alarm_id in &component.component_ids {
                let Some(alarm) = self
                    .components
                    .get(*alarm_id as usize)
                    .filter(|c| c.component_type == ICalendarComponentType::VAlarm)
                else {
                    continue;
                };
                removed_ids.push(*alarm_id);
                if let Some(jsid) = alarm.jsid().filter(|id| defaults.contains_id(id)) {
                    stored_defaults.push((jsid, &alarm.entries));
                } else if view == DefaultAlertsView::Merge
                    || self.is_kept_with_default_alerts(alarm, defaults)
                {
                    kept_ids.push(*alarm_id);
                }
            }

            let mut new_alarms = Vec::with_capacity(defaults.alerts.len());
            for alert in &defaults.alerts {
                let mut alarm = alert.to_ical(text);
                if let Some((_, entries)) = stored_defaults.iter().find(|(id, _)| *id == alert.id) {
                    let generated = alarm.entries.len();
                    for entry in entries.iter() {
                        if !alarm
                            .entries
                            .iter()
                            .take(generated)
                            .any(|generated| generated.name == entry.name)
                        {
                            alarm.entries.push(entry.clone());
                        }
                    }
                }
                new_alarms.push(alarm);
            }

            let mut new_ids = Vec::with_capacity(new_alarms.len());
            for alarm in new_alarms {
                new_ids.push(self.components.len() as u32);
                self.components.push(alarm);
            }

            if let Some(component) = self.components.get_mut(comp_id) {
                component
                    .component_ids
                    .retain(|id| !removed_ids.contains(id) || kept_ids.contains(id));
                component.component_ids.extend(new_ids);
            }
        }
    }

    fn strip_default_alerts(&mut self, defaults: &DefaultAlerts) {
        if !defaults.is_enabled() {
            return;
        }

        let redundant = (0u32..)
            .zip(&self.components)
            .filter(|(_, c)| {
                c.component_type == ICalendarComponentType::VAlarm
                    && c.jsid().is_some_and(|id| defaults.contains_id(id))
                    && !c.has_property(&ICalendarProperty::Acknowledged)
            })
            .map(|(id, _)| id)
            .collect::<Vec<_>>();

        if !redundant.is_empty() && !self.remove_component_ids(&redundant) {
            for component in &mut self.components {
                component.component_ids.retain(|id| !redundant.contains(id));
            }
        }
    }

    fn is_kept_with_default_alerts(
        &self,
        alarm: &ICalendarComponent,
        defaults: &DefaultAlerts,
    ) -> bool {
        alarm.snoozed_alarms().any(|parent| {
            defaults.contains_id(parent)
                || self.components.iter().any(|c| {
                    c.component_type == ICalendarComponentType::VAlarm
                        && c.uid() == Some(parent)
                        && c.jsid().is_some_and(|id| defaults.contains_id(id))
                })
        })
    }
    fn restore_hidden_alerts(&mut self, previous: &ICalendar, defaults: &DefaultAlerts) {
        if !defaults.is_enabled() {
            return;
        }

        for comp_id in 0..self.components.len() {
            let Some(component) = self
                .components
                .get(comp_id)
                .filter(|c| c.component_type.is_event_or_todo())
            else {
                continue;
            };
            let recurrence_id = component.property(&ICalendarProperty::RecurrenceId);
            let Some(previous_component) = previous.components.iter().find(|c| {
                c.component_type == component.component_type
                    && c.property(&ICalendarProperty::RecurrenceId) == recurrence_id
            }) else {
                continue;
            };
            let hidden = previous_component
                .component_ids
                .iter()
                .filter_map(|id| previous.components.get(*id as usize))
                .filter(|alarm| {
                    alarm.component_type == ICalendarComponentType::VAlarm
                        && alarm.jsid().is_none_or(|id| !defaults.contains_id(id))
                        && !previous.is_kept_with_default_alerts(alarm, defaults)
                        && !component
                            .component_ids
                            .iter()
                            .filter_map(|id| self.components.get(*id as usize))
                            .any(|existing| existing == *alarm)
                })
                .cloned()
                .collect::<Vec<_>>();

            let first_id = self.components.len() as u32;
            let new_ids = first_id..first_id + hidden.len() as u32;
            self.components.extend(hidden);
            if let Some(component) = self.components.get_mut(comp_id) {
                component.component_ids.extend(new_ids);
            }
        }
    }
}

pub trait SnoozeAlarm {
    fn snoozed_alarms(&self) -> impl Iterator<Item = &str>;
}

impl SnoozeAlarm for ICalendarComponent {
    fn snoozed_alarms(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.name == ICalendarProperty::RelatedTo
                    && entry.params.iter().any(|param| {
                        param.name == ICalendarParameterName::Reltype
                            && matches!(
                                param.value,
                                ICalendarParameterValue::Reltype(ICalendarRelationshipType::Snooze)
                            )
                    })
            })
            .filter_map(|entry| entry.values.first().and_then(|value| value.as_text()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::{CalendarEventData, CalendarPreferences, Timezone};
    use calcard::icalendar::ICalendarDuration;

    const EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "DTSTART:20240101T100000Z\r\n",
        "DURATION:PT1H\r\n",
        "BEGIN:VALARM\r\n",
        "JSID:own\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT1M\r\n",
        "END:VALARM\r\n",
        "BEGIN:VALARM\r\n",
        "JSID:default-1\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT99M\r\n",
        "ACKNOWLEDGED:20240101T090000Z\r\n",
        "END:VALARM\r\n",
        "BEGIN:VALARM\r\n",
        "JSID:snooze\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER;VALUE=DATE-TIME:20240101T095500Z\r\n",
        "RELATED-TO;RELTYPE=SNOOZE:default-1\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn default_alert(id: &str, offset: i64, flags: u16) -> DefaultAlert {
        DefaultAlert {
            id: id.to_string(),
            offset: ICalendarDuration::from_seconds(offset),
            flags,
        }
    }

    fn defaults() -> DefaultAlerts {
        DefaultAlerts {
            enabled: true,
            alerts: vec![
                default_alert("default-1", -900, ALERT_WITH_TIME),
                default_alert(
                    "default-2",
                    300,
                    ALERT_WITH_TIME | ALERT_RELATIVE_TO_END | ALERT_EMAIL,
                ),
            ],
            recipient: None,
        }
    }

    fn user_settings(
        account_id: u32,
        is_subscribed: bool,
        alerts: Vec<DefaultAlert>,
    ) -> UserCalendarSettings {
        UserCalendarSettings {
            account_id,
            is_subscribed,
            time_zone: Tz::Floating,
            alerts,
        }
    }

    #[test]
    fn changed_users_are_detected_per_account() {
        let previous = CalendarSettings(vec![
            user_settings(1, true, vec![default_alert("a", -900, ALERT_WITH_TIME)]),
            user_settings(2, true, vec![]),
        ]);
        let current = CalendarSettings(vec![
            user_settings(1, true, vec![default_alert("b", -900, ALERT_WITH_TIME)]),
            user_settings(2, true, vec![]),
            user_settings(3, true, vec![]),
        ]);

        assert_eq!(
            previous.changes(&current).collect::<Vec<_>>(),
            vec![(1, true), (3, false)]
        );
        assert_eq!(current.changes(&current).count(), 0);

        let unsubscribed = CalendarSettings(vec![
            user_settings(1, false, vec![default_alert("a", -900, ALERT_WITH_TIME)]),
            user_settings(2, true, vec![]),
        ]);
        assert_eq!(
            previous.changes(&unsubscribed).collect::<Vec<_>>(),
            vec![(1, false)]
        );
    }

    fn linked_alarm_count(ical: &ICalendar) -> (usize, usize) {
        let linked = ical
            .components
            .iter()
            .flat_map(|component| component.component_ids.iter())
            .filter(|id| {
                ical.components
                    .get(**id as usize)
                    .is_some_and(|c| c.component_type == ICalendarComponentType::VAlarm)
            })
            .count();
        let total = ical
            .components
            .iter()
            .filter(|c| c.component_type == ICalendarComponentType::VAlarm)
            .count();
        (linked, total)
    }

    const UID_SNOOZE_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "SUMMARY:Standup\r\n",
        "DTSTART:20240101T100000Z\r\n",
        "DURATION:PT1H\r\n",
        "BEGIN:VALARM\r\n",
        "UID:original-alarm\r\n",
        "JSID:default-1\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER:-PT15M\r\n",
        "ACKNOWLEDGED:20240101T094500Z\r\n",
        "X-CLIENT-STATE:seen\r\n",
        "END:VALARM\r\n",
        "BEGIN:VALARM\r\n",
        "UID:snooze-alarm\r\n",
        "ACTION:DISPLAY\r\n",
        "TRIGGER;VALUE=DATE-TIME:20240101T095500Z\r\n",
        "RELATED-TO;RELTYPE=SNOOZE:original-alarm\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    #[test]
    fn strip_removes_orphan_alarms() {
        for view in [DefaultAlertsView::Merge, DefaultAlertsView::Replace] {
            let mut resolved = ICalendar::parse(EVENT).unwrap();
            resolved.apply_default_alerts(&defaults(), view);
            let mut ical = ICalendar::parse(resolved.to_string()).unwrap();
            let before = ical.components.len();
            ical.strip_default_alerts(&defaults());
            let (linked, total) = linked_alarm_count(&ical);
            assert_eq!(linked, total, "{ical}");
            assert_eq!(ical.components.len(), before - 1, "{ical}");
            assert!(
                ical.components.iter().all(|c| c
                    .component_ids
                    .iter()
                    .all(|id| (*id as usize) < ical.components.len())),
                "{ical}"
            );
            let text = ical.to_string();
            assert!(!text.contains("JSID:default-2"), "{text}");
            assert!(text.contains("ACKNOWLEDGED:20240101T090000Z"), "{text}");
        }
    }

    #[test]
    fn views_keep_stored_default_alarm_entries() {
        let stored = ICalendar::parse(UID_SNOOZE_EVENT).unwrap();
        let snooze = stored
            .components
            .iter()
            .find(|c| c.uid() == Some("snooze-alarm"))
            .cloned()
            .unwrap();
        assert!(stored.is_kept_with_default_alerts(&snooze, &defaults()));

        for view in [DefaultAlertsView::Replace, DefaultAlertsView::Merge] {
            let mut ical = stored.clone();
            ical.apply_default_alerts(&defaults(), view);
            let text = ical.to_string();
            assert_eq!(text.matches("UID:original-alarm").count(), 1, "{text}");
            assert_eq!(text.matches("X-CLIENT-STATE:seen").count(), 1, "{text}");
            assert_eq!(text.matches("TRIGGER:-PT15M").count(), 1, "{text}");
            assert!(
                text.contains("RELATED-TO;RELTYPE=SNOOZE:original-alarm"),
                "{text}"
            );
            assert!(
                ical.is_kept_with_default_alerts(&snooze, &defaults()),
                "{text}"
            );

            ical.strip_default_alerts(&defaults());
            let text = ical.to_string();
            assert!(text.contains("UID:original-alarm"), "{text}");
            assert!(!text.contains("JSID:default-2"), "{text}");
            assert!(
                ical.is_kept_with_default_alerts(&snooze, &defaults()),
                "{text}"
            );

            let data = CalendarEventData::new_with_default_alerts(ical, Tz::UTC, 10, &defaults());
            assert!(
                data.alarms
                    .iter()
                    .any(|alarm| matches!(alarm.delta, AlarmDelta::FixedUtc(_))),
                "{:?}",
                data.alarms
            );
        }
    }

    #[test]
    fn icalendar_view_alarms_are_complete() {
        let mut defaults = defaults();
        defaults.recipient = Some(Arc::from("jane@example.com"));
        let mut view = ICalendar::parse(UID_SNOOZE_EVENT).unwrap();
        view.apply_default_alerts(&defaults, DefaultAlertsView::ICalendar);
        let text = view.to_string();
        let ical = ICalendar::parse(text.as_str()).unwrap();
        for alarm in ical.components.iter().filter(|c| {
            c.component_type == ICalendarComponentType::VAlarm
                && c.jsid().is_some_and(|id| defaults.contains_id(id))
        }) {
            assert!(
                alarm.has_property(&ICalendarProperty::Description),
                "{text}"
            );
            assert_eq!(
                alarm.properties(&ICalendarProperty::Description).count(),
                1,
                "{text}"
            );
        }
        let email = ical
            .components
            .iter()
            .find(|c| c.jsid() == Some("default-2"))
            .unwrap();
        assert!(email.has_property(&ICalendarProperty::Summary), "{text}");
        assert_eq!(
            email
                .property(&ICalendarProperty::Attendee)
                .and_then(|entry| entry.calendar_address()),
            Some("jane@example.com"),
            "{text}"
        );
        assert!(text.contains("DESCRIPTION:Standup"), "{text}");

        let mut derived = ICalendar::parse(
            UID_SNOOZE_EVENT
                .replace(
                    "JSID:default-1\r\n",
                    "JSID:default-1\r\nDESCRIPTION;DERIVED=TRUE:Standup\r\n",
                )
                .as_str(),
        )
        .unwrap();
        derived.apply_default_alerts(&defaults, DefaultAlertsView::ICalendar);
        let derived_text = derived.to_string();
        assert_eq!(
            ICalendar::parse(derived_text.as_str())
                .unwrap()
                .components
                .iter()
                .filter(|c| c.jsid() == Some("default-1"))
                .map(|alarm| alarm.properties(&ICalendarProperty::Description).count())
                .collect::<Vec<_>>(),
            [1],
            "{derived_text}"
        );

        let mut minimal = ICalendar::parse(UID_SNOOZE_EVENT).unwrap();
        minimal.apply_default_alerts(&defaults, DefaultAlertsView::Replace);
        let minimal_text = minimal.to_string();
        assert!(!minimal_text.contains("ATTENDEE"), "{minimal_text}");

        let mut incoming = ICalendar::parse(text.as_str()).unwrap();
        incoming.strip_default_alerts(&defaults);
        let incoming_text = incoming.to_string();
        assert!(!incoming_text.contains("JSID:default-2"), "{incoming_text}");
        assert!(
            incoming_text.contains("UID:original-alarm"),
            "{incoming_text}"
        );
    }

    #[test]
    fn merged_defaults_are_unique_per_user() {
        let team = CalendarSettings(vec![
            user_settings(
                1,
                true,
                vec![
                    default_alert("shared", -300, ALERT_WITH_TIME),
                    default_alert("owner-day", -3600, 0),
                ],
            ),
            user_settings(2, true, vec![default_alert("jane", -600, ALERT_WITH_TIME)]),
        ]);
        let other = CalendarSettings(vec![user_settings(
            1,
            false,
            vec![
                default_alert("shared", -900, ALERT_WITH_TIME),
                default_alert("other", -60, ALERT_WITH_TIME),
            ],
        )]);

        let owner = DefaultAlerts::merge([&team, &other].into_iter(), 1, None, true);
        assert_eq!(
            owner
                .alerts
                .iter()
                .map(|alert| (alert.id.as_str(), alert.offset.as_seconds()))
                .collect::<Vec<_>>(),
            [("shared", -300), ("other", -60)]
        );
        let owner_without_time = DefaultAlerts::merge([&team, &other].into_iter(), 1, None, false);
        assert_eq!(owner_without_time.alerts.len(), 1);
        let sharee = DefaultAlerts::merge([&team, &other].into_iter(), 2, None, true);
        assert_eq!(
            sharee
                .alerts
                .iter()
                .map(|alert| alert.id.as_str())
                .collect::<Vec<_>>(),
            ["jane"]
        );
        assert!(
            DefaultAlerts::merge([&other].into_iter(), 2, None, true)
                .alerts
                .is_empty()
        );
    }

    #[test]
    fn resolver_keys_settings_by_account() {
        let resolver = DefaultAlertsResolver::default()
            .with_calendar(
                1,
                0,
                CalendarSettings(vec![
                    user_settings(1, true, vec![]),
                    user_settings(3, false, vec![]),
                ]),
            )
            .with_calendar(2, 0, CalendarSettings(vec![user_settings(3, true, vec![])]));
        assert_eq!(resolver.cached_subscription(1, 1, 0), Some(Some(true)));
        assert_eq!(resolver.cached_subscription(1, 3, 0), Some(Some(false)));
        assert_eq!(resolver.cached_subscription(2, 3, 0), Some(Some(true)));
        assert_eq!(resolver.cached_subscription(2, 1, 0), Some(None));
        assert_eq!(resolver.cached_subscription(1, 1, 7), None);
    }

    #[test]
    fn calendar_settings_include_every_user() {
        let calendar = Calendar {
            preferences: vec![
                CalendarPreferences {
                    account_id: 1,
                    flags: CALENDAR_SUBSCRIBED,
                    time_zone: Timezone::IANA(Tz::UTC.as_id()),
                    default_alerts: vec![default_alert("owner", -60, ALERT_WITH_TIME)],
                    ..Default::default()
                },
                CalendarPreferences {
                    account_id: 2,
                    default_alerts: vec![default_alert("jane", -120, ALERT_WITH_TIME)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let settings = CalendarSettings::from(&calendar);
        let owner = settings.user(1).unwrap();
        assert!(owner.is_subscribed);
        assert!(owner.time_zone.is_utc());
        let sharee = settings.user(2).unwrap();
        assert!(!sharee.is_subscribed);
        assert!(sharee.time_zone.is_floating());
        assert_eq!(sharee.alerts.len(), 1);
        assert!(settings.user(3).is_none());
    }

    #[test]
    fn apply_resolves_defaults() {
        let mut ical = ICalendar::parse(EVENT).unwrap();
        ical.apply_default_alerts(&defaults(), DefaultAlertsView::Replace);
        let text = ical.to_string();
        assert!(!text.contains("JSID:own"), "{text}");
        assert!(!text.contains("-PT99M"), "{text}");
        assert!(text.contains("JSID:default-1"), "{text}");
        assert!(text.contains("TRIGGER:-PT15M"), "{text}");
        assert!(text.contains("ACKNOWLEDGED:20240101T090000Z"), "{text}");
        assert!(text.contains("JSID:default-2"), "{text}");
        assert!(text.contains("TRIGGER;RELATED=END:PT5M"), "{text}");
        assert!(text.contains("JSID:snooze"), "{text}");
    }

    #[test]
    fn merge_keeps_event_alerts() {
        let mut ical = ICalendar::parse(EVENT).unwrap();
        ical.apply_default_alerts(&defaults(), DefaultAlertsView::Merge);
        ical.strip_default_alerts(&defaults());
        let text = ical.to_string();
        assert!(text.contains("JSID:own"), "{text}");
        assert!(text.contains("JSID:snooze"), "{text}");
        assert!(text.contains("ACKNOWLEDGED:20240101T090000Z"), "{text}");
        assert!(!text.contains("JSID:default-2"), "{text}");
    }

    #[test]
    fn disabled_defaults_leave_event_untouched() {
        let mut ical = ICalendar::parse(EVENT).unwrap();
        let original = ical.to_string();
        ical.apply_default_alerts(&DefaultAlerts::disabled(), DefaultAlertsView::Replace);
        ical.strip_default_alerts(&DefaultAlerts::disabled());
        assert_eq!(ical.to_string(), original);
    }

    #[test]
    fn strip_keeps_acknowledged_and_snoozes() {
        let mut ical = ICalendar::parse(EVENT).unwrap();
        ical.apply_default_alerts(&defaults(), DefaultAlertsView::Replace);
        ical.strip_default_alerts(&defaults());
        let text = ical.to_string();
        assert!(text.contains("JSID:default-1"), "{text}");
        assert!(text.contains("ACKNOWLEDGED"), "{text}");
        assert!(!text.contains("JSID:default-2"), "{text}");
        assert!(text.contains("JSID:snooze"), "{text}");
    }

    #[test]
    fn restore_keeps_hidden_alarms_once() {
        let stored = ICalendar::parse(EVENT).unwrap();
        let mut view = stored.clone();
        view.apply_default_alerts(&defaults(), DefaultAlertsView::Replace);
        assert!(!view.to_string().contains("JSID:own"));

        let mut incoming = ICalendar::parse(view.to_string()).unwrap();
        incoming.strip_default_alerts(&defaults());
        incoming.restore_hidden_alerts(&stored, &defaults());
        incoming.restore_hidden_alerts(&stored, &defaults());
        let text = incoming.to_string();
        assert_eq!(text.matches("JSID:own").count(), 1, "{text}");
        assert_eq!(text.matches("JSID:snooze").count(), 1, "{text}");
        assert!(text.contains("ACKNOWLEDGED:20240101T090000Z"), "{text}");
        assert!(!text.contains("JSID:default-2"), "{text}");
    }

    #[test]
    fn default_alert_indexes() {
        let defaults = defaults();
        let alerts = defaults.indexed_alerts().collect::<Vec<_>>();
        assert_eq!(
            alerts
                .iter()
                .map(|(index, alert)| (*index, alert.id.as_str()))
                .collect::<Vec<_>>(),
            [(0, "default-1"), (1, "default-2")]
        );
        assert_eq!(
            defaults.get(1).map(|alert| alert.id.as_str()),
            Some("default-2")
        );
        assert!(matches!(alerts[1].1.delta(), AlarmDelta::End(300)));
        assert!(alerts[1].1.is_email());
        assert!(matches!(alerts[0].1.delta(), AlarmDelta::Start(-900)));
        assert!(defaults.get(2).is_none());
        assert!(DefaultAlerts::disabled().get(0).is_none());
    }
}
