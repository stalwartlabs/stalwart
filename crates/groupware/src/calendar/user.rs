/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEventContent, ArchivedEventPreferences, CalendarEventContent,
    CalendarEventData, EventPreferences, EventUserData, MAX_USER_ALERTS, MAX_USER_INSTANCES,
    MAX_USER_KEYWORD_LEN, MAX_USER_KEYWORDS, PREF_FREE_BUSY_FREE, PREF_HAS_ALERTS, PREF_HAS_COLOR,
    PREF_HAS_FREE_BUSY, PREF_HAS_KEYWORDS, PREF_HAS_USE_DEFAULT_ALERTS, PREF_USE_DEFAULT_ALERTS,
    color::CssColor,
    compare::{
        ComparisonScope, EntryList, NaiveDateTime, RecurrenceComponents, RedundantOverrides,
    },
    expand::{ComponentRecurrenceId, RecurrenceKey},
};
use ahash::AHashSet;
use calcard::{
    common::{PartialDateTime, timezone::Tz},
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry,
        ICalendarParameterName, ICalendarProperty, ICalendarTransparency, ICalendarValue,
        timezone::TzResolver,
    },
};

pub const BASE_INSTANCE: u32 = 0;

const DEFAULT_ALERT_FLAGS: u16 = PREF_HAS_USE_DEFAULT_ALERTS | PREF_USE_DEFAULT_ALERTS;
const MAX_COMPONENT_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataError {
    TooManyKeywords,
    KeywordTooLong,
    TooManyAlerts,
    TooManyInstances,
    InvalidColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserDataLookup {
    Inherited,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataView {
    Full,
    AlertsOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataSplit {
    UserDataOnly,
    SharedDataChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatedPolicy {
    Server(i64),
    Client,
}

#[derive(Debug, Clone, Copy)]
pub struct UserDataUpdate<'x> {
    pub account_id: u32,
    pub view: UserDataView,
    pub previous: Option<&'x EventPreferences>,
    pub current: Option<&'x EventPreferences>,
    pub updated: UpdatedPolicy,
}

impl CalendarEventContent {
    pub fn preferences(&self, account_id: u32) -> Option<&EventPreferences> {
        self.preferences.iter().find(|p| p.account_id == account_id)
    }

    pub fn preferences_mut(&mut self, account_id: u32) -> &mut EventPreferences {
        let idx = if let Some(idx) = self
            .preferences
            .iter()
            .position(|p| p.account_id == account_id)
        {
            idx
        } else {
            self.preferences.push(EventPreferences {
                account_id,
                ..Default::default()
            });
            self.preferences.len() - 1
        };

        &mut self.preferences[idx]
    }

    pub fn set_preferences(&mut self, preferences: EventPreferences) {
        let account_id = preferences.account_id;
        if preferences.is_empty() {
            self.preferences.retain(|p| p.account_id != account_id);
        } else if let Some(current) = self
            .preferences
            .iter_mut()
            .find(|p| p.account_id == account_id)
        {
            *current = preferences;
        } else {
            self.preferences.push(preferences);
        }
    }
}

impl ArchivedCalendarEventContent {
    pub fn preferences(&self, account_id: u32) -> Option<&ArchivedEventPreferences> {
        self.preferences.iter().find(|p| p.account_id == account_id)
    }
}

impl CalendarEventData {
    pub fn apply_user_data(&mut self, preferences: Option<&EventPreferences>, view: UserDataView) {
        if let Some(overrides) = self.user_data_overrides(preferences, view) {
            overrides.append_to(&mut self.event);
        }
        self.event.apply_user_data(preferences, view);
    }

    pub fn user_data_view(
        &self,
        preferences: Option<&EventPreferences>,
        view: UserDataView,
    ) -> ICalendar {
        let mut event = self.event.clone();
        if let Some(overrides) = self.user_data_overrides(preferences, view) {
            overrides.append_to(&mut event);
        }
        event.apply_user_data(preferences, view);
        event
    }

    fn user_data_overrides(
        &self,
        preferences: Option<&EventPreferences>,
        view: UserDataView,
    ) -> Option<PersonalOverrides> {
        let preferences = preferences.filter(|_| view == UserDataView::Full)?;
        let mut keys = preferences
            .instances
            .iter()
            .filter_map(|instance| RecurrenceKey::from_prefix(instance.recurrence_key))
            .collect::<AHashSet<_>>();
        let mut instance_keys = InstanceKeys::new(&self.event);
        for key in self
            .event
            .components
            .iter()
            .filter(|component| {
                component.is_user_data_component() && component.is_recurrence_override()
            })
            .filter_map(|component| instance_keys.of(component))
            .filter_map(RecurrenceKey::from_prefix)
            .collect::<Vec<_>>()
        {
            keys.remove(&key);
        }
        if keys.is_empty() {
            return None;
        }
        let base_id = self.event.base_component_id()?;
        let expansions = self.expand_from_ids(&mut keys, Tz::Floating)?;
        let root_id = self
            .event
            .components
            .iter()
            .position(|component| component.component_ids.contains(&base_id))?;
        let mut overrides = OccurrenceOverrides::new(&self.event, base_id)?;
        for expansion in expansions
            .iter()
            .filter(|expansion| expansion.comp_id == base_id)
        {
            overrides.push(expansion.start_naive);
        }
        Some(overrides.into_personal_overrides(root_id))
    }
}

struct PersonalOverrides {
    root_id: usize,
    override_ids: Vec<u32>,
    components: Vec<ICalendarComponent>,
}

impl PersonalOverrides {
    fn append_to(self, event: &mut ICalendar) {
        event.components.extend(self.components);
        if let Some(root) = event.components.get_mut(self.root_id) {
            root.component_ids.extend(self.override_ids);
        }
    }
}

impl EventPreferences {
    pub fn instance(&self, recurrence_key: u32) -> Option<&EventUserData> {
        self.instances
            .binary_search_by_key(&recurrence_key, |i| i.recurrence_key)
            .ok()
            .and_then(|idx| self.instances.get(idx))
    }

    pub fn instance_mut(
        &mut self,
        recurrence_key: u32,
    ) -> Result<&mut EventUserData, UserDataError> {
        let idx = match self
            .instances
            .binary_search_by_key(&recurrence_key, |i| i.recurrence_key)
        {
            Ok(idx) => idx,
            Err(idx) => {
                if self.instances.len() >= MAX_USER_INSTANCES {
                    return Err(UserDataError::TooManyInstances);
                }
                self.instances.insert(
                    idx,
                    EventUserData {
                        recurrence_key,
                        ..Default::default()
                    },
                );
                idx
            }
        };
        self.instances
            .get_mut(idx)
            .ok_or(UserDataError::TooManyInstances)
    }

    pub fn use_default_alerts(&self) -> bool {
        self.instance(BASE_INSTANCE)
            .is_some_and(|i| i.flags & PREF_USE_DEFAULT_ALERTS != 0)
    }

    pub fn set_use_default_alerts(&mut self, value: bool) -> Result<(), UserDataError> {
        let instance = self.instance_mut(BASE_INSTANCE)?;
        instance.flags |= PREF_HAS_USE_DEFAULT_ALERTS;
        if value {
            instance.flags |= PREF_USE_DEFAULT_ALERTS;
        } else {
            instance.flags &= !PREF_USE_DEFAULT_ALERTS;
        }
        Ok(())
    }

    pub fn inherit_default_alerts(
        &mut self,
        current: Option<&EventPreferences>,
    ) -> Result<(), UserDataError> {
        if let Some(flags) = current
            .and_then(|preferences| preferences.instance(BASE_INSTANCE))
            .map(|base| base.flags & DEFAULT_ALERT_FLAGS)
            .filter(|flags| *flags != 0)
        {
            self.instance_mut(BASE_INSTANCE)?.flags |= flags;
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.updated == 0 && self.instances.iter().all(|i| i.flags == 0)
    }

    pub fn size(&self) -> usize {
        self.instances.iter().map(|i| i.size()).sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }

    fn stamp_updated(&mut self, update: &UserDataUpdate<'_>, client_updated: Option<i64>) {
        let previous_updated = update.previous.map_or(0, |previous| previous.updated);
        let is_changed = update
            .previous
            .map_or(!self.instances.is_empty(), |previous| {
                previous.instances != self.instances
            });
        self.updated = match update.updated {
            UpdatedPolicy::Server(now) if is_changed => now,
            UpdatedPolicy::Client => client_updated.unwrap_or(previous_updated),
            UpdatedPolicy::Server(_) => previous_updated,
        };
    }
}

impl ArchivedEventPreferences {
    pub fn use_default_alerts(&self) -> bool {
        self.instances
            .iter()
            .find(|i| i.recurrence_key == BASE_INSTANCE)
            .is_some_and(|i| i.flags & PREF_USE_DEFAULT_ALERTS != 0)
    }

    pub fn is_free(&self, recurrence_key: u32) -> Option<bool> {
        [recurrence_key, BASE_INSTANCE]
            .into_iter()
            .filter_map(|key| {
                self.instances
                    .binary_search_by_key(&key, |i| i.recurrence_key.to_native())
                    .ok()
                    .and_then(|idx| self.instances.get(idx))
            })
            .map(|i| i.flags.to_native())
            .find(|flags| flags & PREF_HAS_FREE_BUSY != 0)
            .map(|flags| flags & PREF_FREE_BUSY_FREE != 0)
    }

    pub fn size(&self) -> usize {
        self.instances
            .iter()
            .map(|i| {
                i.keywords.iter().map(|k| k.len()).sum::<usize>()
                    + i.alerts.iter().map(|a| a.size()).sum::<usize>()
                    + std::mem::size_of::<EventUserData>()
            })
            .sum::<usize>()
            + std::mem::size_of::<EventPreferences>()
    }
}

impl EventUserData {
    pub fn set_color(&mut self, color: Option<CssColor>) {
        self.flags |= PREF_HAS_COLOR;
        self.color = color;
    }

    pub fn set_free_busy(&mut self, is_free: bool) {
        self.flags |= PREF_HAS_FREE_BUSY;
        if is_free {
            self.flags |= PREF_FREE_BUSY_FREE;
        } else {
            self.flags &= !PREF_FREE_BUSY_FREE;
        }
    }

    pub fn set_keywords<'x>(
        &mut self,
        keywords: impl IntoIterator<Item = &'x str>,
    ) -> Result<(), UserDataError> {
        self.keywords.clear();
        for keyword in keywords {
            if keyword.len() > MAX_USER_KEYWORD_LEN {
                return Err(UserDataError::KeywordTooLong);
            }
            if self.keywords.len() >= MAX_USER_KEYWORDS {
                return Err(UserDataError::TooManyKeywords);
            }
            if !self.keywords.iter().any(|k| k == keyword) {
                self.keywords.push(keyword.to_string());
            }
        }
        self.flags |= PREF_HAS_KEYWORDS;
        Ok(())
    }

    pub fn set_alerts(&mut self, alerts: Vec<ICalendarComponent>) -> Result<(), UserDataError> {
        if alerts.len() > MAX_USER_ALERTS {
            return Err(UserDataError::TooManyAlerts);
        }
        self.flags |= PREF_HAS_ALERTS;
        self.alerts = alerts;
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.keywords.iter().map(|k| k.len()).sum::<usize>()
            + self.alerts.iter().map(|a| a.size()).sum::<usize>()
            + std::mem::size_of::<EventUserData>()
    }

    fn clear_alerts(&mut self) {
        self.flags &= !PREF_HAS_ALERTS;
        self.alerts.clear();
    }

    fn remove_inherited(&mut self, base: &EventUserData) {
        for flag in [
            PREF_HAS_COLOR,
            PREF_HAS_KEYWORDS,
            PREF_HAS_FREE_BUSY,
            PREF_HAS_ALERTS,
        ] {
            let (has_self, has_base) = (self.flags & flag != 0, base.flags & flag != 0);
            let is_inherited = match (has_self, has_base) {
                (false, false) => true,
                (true, true) => match flag {
                    PREF_HAS_COLOR => self.color == base.color,
                    PREF_HAS_KEYWORDS => self.keywords == base.keywords,
                    PREF_HAS_FREE_BUSY => {
                        self.flags & PREF_FREE_BUSY_FREE == base.flags & PREF_FREE_BUSY_FREE
                    }
                    _ => self.alerts == base.alerts,
                },
                _ => false,
            };
            if is_inherited {
                self.flags &= !flag;
                match flag {
                    PREF_HAS_COLOR => self.color = None,
                    PREF_HAS_KEYWORDS => self.keywords.clear(),
                    PREF_HAS_FREE_BUSY => self.flags &= !PREF_FREE_BUSY_FREE,
                    _ => self.alerts.clear(),
                }
            } else {
                self.flags |= flag;
            }
        }
    }
}

pub trait UserDataEntry {
    fn is_user_data(&self) -> bool;
}

impl UserDataEntry for ICalendarEntry {
    fn is_user_data(&self) -> bool {
        match &self.name {
            ICalendarProperty::Color
            | ICalendarProperty::Categories
            | ICalendarProperty::Transp => true,
            ICalendarProperty::Jsprop => self
                .parameter(&ICalendarParameterName::Jsptr)
                .and_then(|pointer| pointer.as_text())
                .and_then(|pointer| pointer.split('/').next())
                .is_some_and(|property| {
                    hashify::tiny_set!(
                        property.as_bytes(),
                        "alerts",
                        "color",
                        "freeBusyStatus",
                        "keywords",
                        "useDefaultAlerts"
                    )
                }),
            _ => false,
        }
    }
}

pub trait ICalendarUserData {
    fn validate_user_data(&self) -> Result<(), UserDataError>;

    fn validate_user_data_changes(&self, stored: &ICalendar) -> Result<(), UserDataError>;

    fn apply_user_data(&mut self, preferences: Option<&EventPreferences>, view: UserDataView);

    fn extract_user_data(&self, account_id: u32) -> Result<EventPreferences, UserDataError>;

    fn extract_user_preferences(
        &self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<EventPreferences, UserDataError>;

    fn copy_user_data(&mut self, source: &ICalendar) -> Vec<i64>;

    fn split_user_data(
        &mut self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<(EventPreferences, UserDataSplit), UserDataError>;

    fn user_data_override(
        &self,
        comp_id: u32,
        recurrence_key: RecurrenceKey,
    ) -> Option<&ICalendarComponent>;

    fn has_same_user_data(&self, stored: &ICalendar) -> bool;
}

impl ICalendarUserData for ICalendar {
    fn validate_user_data(&self) -> Result<(), UserDataError> {
        self.components
            .iter()
            .filter(|c| c.is_user_data_component())
            .try_for_each(|component| UserDataUsage::new(self, component).validate(None))
    }

    fn validate_user_data_changes(&self, stored: &ICalendar) -> Result<(), UserDataError> {
        let stored_components = UserDataComponents::new(stored);
        let mut instance_keys = InstanceKeys::new(self);
        self.components
            .iter()
            .filter(|c| c.is_user_data_component())
            .try_for_each(|component| {
                UserDataUsage::new(self, component).validate(
                    instance_keys
                        .of(component)
                        .and_then(|key| {
                            stored_components.counterpart(key, UserDataLookup::Inherited)
                        })
                        .map(|stored_component| UserDataUsage::new(stored, stored_component))
                        .as_ref(),
                )
            })
    }

    fn apply_user_data(&mut self, preferences: Option<&EventPreferences>, view: UserDataView) {
        let base = preferences.and_then(|p| p.instance(BASE_INSTANCE));
        for (comp_id, key) in self.user_data_component_ids() {
            let instance = preferences
                .filter(|_| key != BASE_INSTANCE)
                .and_then(|p| p.instance(key));
            let resolve = |flag: u16| {
                instance
                    .filter(|i| i.flags & flag != 0)
                    .or_else(|| base.filter(|b| b.flags & flag != 0))
            };

            let first_alert_id = self.components.len() as u32;
            self.components.extend(
                resolve(PREF_HAS_ALERTS)
                    .into_iter()
                    .flat_map(|i| i.alerts.iter())
                    .map(ICalendarComponent::detached),
            );
            let alert_ids = first_alert_id..self.components.len() as u32;

            let entries = (view == UserDataView::Full).then(|| {
                [
                    resolve(PREF_HAS_COLOR)
                        .and_then(|i| i.color.as_ref())
                        .map(|color| ICalendarEntry {
                            name: ICalendarProperty::Color,
                            params: vec![],
                            values: vec![ICalendarValue::Text(color.to_string())],
                        }),
                    resolve(PREF_HAS_KEYWORDS)
                        .filter(|i| !i.keywords.is_empty())
                        .map(|i| ICalendarEntry {
                            name: ICalendarProperty::Categories,
                            params: vec![],
                            values: i
                                .keywords
                                .iter()
                                .map(|k| ICalendarValue::Text(k.clone()))
                                .collect(),
                        }),
                    resolve(PREF_HAS_FREE_BUSY).map(|i| ICalendarEntry {
                        name: ICalendarProperty::Transp,
                        params: vec![],
                        values: vec![ICalendarValue::Transparency(
                            if i.flags & PREF_FREE_BUSY_FREE != 0 {
                                ICalendarTransparency::Transparent
                            } else {
                                ICalendarTransparency::Opaque
                            },
                        )],
                    }),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
            });
            self.replace_user_data(comp_id, alert_ids, entries);
        }
    }

    fn extract_user_data(&self, account_id: u32) -> Result<EventPreferences, UserDataError> {
        let mut preferences = EventPreferences {
            account_id,
            ..Default::default()
        };
        let base = match self
            .base_component_id()
            .and_then(|id| self.component_by_id(id))
        {
            Some(component) => self.component_user_data(component)?,
            None => EventUserData::default(),
        };

        let mut instance_keys = InstanceKeys::new(self);
        for component in self
            .components
            .iter()
            .filter(|c| c.is_user_data_component() && c.is_recurrence_override())
        {
            let Some(key) = instance_keys.of(component) else {
                continue;
            };
            let mut data = self.component_user_data(component)?;
            data.remove_inherited(&base);
            if data.flags != 0 {
                *preferences.instance_mut(key)? = EventUserData {
                    recurrence_key: key,
                    ..data
                };
            }
        }
        if base.flags != 0 {
            *preferences.instance_mut(BASE_INSTANCE)? = base;
        }

        Ok(preferences)
    }

    fn extract_user_preferences(
        &self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<EventPreferences, UserDataError> {
        let mut preferences = match update.view {
            UserDataView::Full => {
                let mut preferences = self.extract_user_data(update.account_id)?;
                preferences.inherit_default_alerts(update.current)?;
                preferences
            }
            UserDataView::AlertsOnly => {
                self.extract_alerts(update.current.cloned().unwrap_or_else(|| EventPreferences {
                    account_id: update.account_id,
                    ..Default::default()
                }))?
            }
        };
        preferences.stamp_updated(
            &update,
            self.base_updated()
                .filter(|updated| stored.base_updated() != Some(*updated)),
        );

        Ok(preferences)
    }

    fn copy_user_data(&mut self, source: &ICalendar) -> Vec<i64> {
        let dropped = {
            let stored = UserDataComponents::new(self);
            let mut instance_keys = InstanceKeys::new(source);
            source
                .components
                .iter()
                .filter(|component| component.is_user_data_component())
                .filter_map(|component| {
                    let recurrence_id = instance_keys.recurrence_id(component)?;
                    let key = RecurrenceKey::from_recurrence_id(recurrence_id)?.prefix();
                    (!stored.contains(key)).then_some(recurrence_id)
                })
                .collect::<Vec<_>>()
        };

        self.restore_user_data(
            &UserDataComponents::new(source),
            UserDataView::Full,
            UserDataLookup::Exact,
        );
        self.drop_unreachable_components();
        dropped
    }

    fn split_user_data(
        &mut self,
        stored: &ICalendar,
        update: UserDataUpdate<'_>,
    ) -> Result<(EventPreferences, UserDataSplit), UserDataError> {
        let preferences = self.extract_user_preferences(stored, update)?;
        let stored_components = UserDataComponents::new(stored);
        self.restore_user_data(&stored_components, update.view, UserDataLookup::Inherited);
        self.prune_user_data_overrides(&stored_components);

        let split = if ComparisonScope::SharedData.component_eq(self, 0, stored, 0) {
            UserDataSplit::UserDataOnly
        } else {
            UserDataSplit::SharedDataChanged
        };

        Ok((preferences, split))
    }

    fn user_data_override(
        &self,
        comp_id: u32,
        recurrence_key: RecurrenceKey,
    ) -> Option<&ICalendarComponent> {
        if self
            .component_by_id(comp_id)
            .is_none_or(|c| c.is_recurrence_override())
        {
            return None;
        }
        let mut instance_keys = InstanceKeys::new(self);
        self.components
            .first()?
            .component_ids
            .iter()
            .filter_map(|id| self.component_by_id(*id))
            .find(|c| {
                c.is_user_data_component()
                    && c.is_recurrence_override()
                    && instance_keys.of(c) == Some(recurrence_key.prefix())
            })
    }

    fn has_same_user_data(&self, stored: &ICalendar) -> bool {
        let stored_components = UserDataComponents::new(stored);
        self.user_data_component_ids()
            .into_iter()
            .filter_map(|(comp_id, key)| self.component_by_id(comp_id).map(|c| (c, key)))
            .all(|(component, key)| {
                let entries = component.user_data_entries();
                match stored_components.counterpart(key, UserDataLookup::Inherited) {
                    Some(source) => entries.same_entries(&source.user_data_entries()),
                    None => entries.is_empty(),
                }
            })
    }
}

trait UserDataComponent {
    fn is_user_data_component(&self) -> bool;

    fn user_data_entries(&self) -> Vec<&ICalendarEntry>;

    fn detached(&self) -> ICalendarComponent;
}

impl UserDataComponent for ICalendarComponent {
    fn is_user_data_component(&self) -> bool {
        self.component_type.is_event_or_todo()
    }

    fn user_data_entries(&self) -> Vec<&ICalendarEntry> {
        let mut entries = self
            .entries
            .iter()
            .filter(|entry| entry.is_user_data())
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    fn detached(&self) -> ICalendarComponent {
        ICalendarComponent {
            component_type: self.component_type.clone(),
            entries: self.entries.clone(),
            component_ids: Vec::new(),
        }
    }
}

trait UserDataTree {
    fn user_data_component_ids(&self) -> Vec<(u32, u32)>;

    fn alarms<'x>(
        &'x self,
        component: &'x ICalendarComponent,
    ) -> impl Iterator<Item = (u32, &'x ICalendarComponent)>;

    fn component_user_data(
        &self,
        component: &ICalendarComponent,
    ) -> Result<EventUserData, UserDataError>;

    fn extract_alerts(
        &self,
        preferences: EventPreferences,
    ) -> Result<EventPreferences, UserDataError>;

    fn restore_user_data(
        &mut self,
        stored: &UserDataComponents<'_>,
        view: UserDataView,
        lookup: UserDataLookup,
    );

    fn drop_unreachable_components(&mut self);

    fn prune_user_data_overrides(&mut self, stored: &UserDataComponents<'_>);

    fn replace_user_data(
        &mut self,
        comp_id: u32,
        alert_ids: impl IntoIterator<Item = u32>,
        entries: Option<Vec<ICalendarEntry>>,
    );

    fn base_updated(&self) -> Option<i64>;
}

impl UserDataTree for ICalendar {
    fn user_data_component_ids(&self) -> Vec<(u32, u32)> {
        let mut instance_keys = InstanceKeys::new(self);
        self.components
            .iter()
            .enumerate()
            .filter(|(_, component)| component.is_user_data_component())
            .filter_map(|(id, component)| Some((id as u32, instance_keys.of(component)?)))
            .collect()
    }

    fn alarms<'x>(
        &'x self,
        component: &'x ICalendarComponent,
    ) -> impl Iterator<Item = (u32, &'x ICalendarComponent)> {
        component.component_ids.iter().filter_map(|id| {
            self.component_by_id(*id)
                .filter(|child| child.component_type == ICalendarComponentType::VAlarm)
                .map(|child| (*id, child))
        })
    }

    fn component_user_data(
        &self,
        component: &ICalendarComponent,
    ) -> Result<EventUserData, UserDataError> {
        let mut data = EventUserData::default();
        let mut keywords: Vec<&str> = Vec::new();
        let mut has_keywords = false;

        for entry in &component.entries {
            match &entry.name {
                ICalendarProperty::Color => {
                    if let Some(value) = entry.values.first().and_then(|v| v.as_text()) {
                        data.set_color(Some(
                            CssColor::parse(value).ok_or(UserDataError::InvalidColor)?,
                        ));
                    }
                }
                ICalendarProperty::Categories => {
                    has_keywords = true;
                    keywords.extend(entry.values.iter().filter_map(|v| v.as_text()));
                }
                ICalendarProperty::Transp => {
                    data.set_free_busy(matches!(
                        entry.values.first(),
                        Some(ICalendarValue::Transparency(
                            ICalendarTransparency::Transparent
                        ))
                    ));
                }
                _ => {}
            }
        }
        if has_keywords {
            data.set_keywords(keywords)?;
        }

        let alerts = self
            .alarms(component)
            .map(|(_, alarm)| alarm.detached())
            .collect::<Vec<_>>();
        if !alerts.is_empty() {
            data.set_alerts(alerts)?;
        }

        Ok(data)
    }

    fn extract_alerts(
        &self,
        mut preferences: EventPreferences,
    ) -> Result<EventPreferences, UserDataError> {
        let base_alerts = self
            .base_component_id()
            .and_then(|id| self.component_by_id(id))
            .map(|base| {
                self.alarms(base)
                    .map(|(_, alarm)| alarm.detached())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let mut instance_keys = InstanceKeys::new(self);
        for component in self
            .components
            .iter()
            .filter(|c| c.is_user_data_component() && c.is_recurrence_override())
        {
            let Some(key) = instance_keys.of(component) else {
                continue;
            };
            let alerts = self
                .alarms(component)
                .map(|(_, alarm)| alarm.detached())
                .collect::<Vec<_>>();
            if alerts != base_alerts {
                preferences.instance_mut(key)?.set_alerts(alerts)?;
            } else if let Some(instance) = preferences
                .instances
                .iter_mut()
                .find(|instance| instance.recurrence_key == key)
            {
                instance.clear_alerts();
            }
        }

        if !base_alerts.is_empty() {
            preferences
                .instance_mut(BASE_INSTANCE)?
                .set_alerts(base_alerts)?;
        } else if let Some(base) = preferences
            .instances
            .iter_mut()
            .find(|instance| instance.recurrence_key == BASE_INSTANCE)
        {
            base.clear_alerts();
        }
        preferences.instances.retain(|instance| instance.flags != 0);

        Ok(preferences)
    }

    fn restore_user_data(
        &mut self,
        stored: &UserDataComponents<'_>,
        view: UserDataView,
        lookup: UserDataLookup,
    ) {
        let mut appender = ComponentAppender::new(stored.ical, self.components.len() as u32);
        let replacements = self
            .user_data_component_ids()
            .into_iter()
            .filter_map(|(comp_id, key)| match stored.counterpart(key, lookup) {
                Some(source) => Some((
                    comp_id,
                    stored
                        .ical
                        .alarms(source)
                        .filter_map(|(alarm_id, _)| appender.copy_tree(alarm_id))
                        .collect::<Vec<_>>(),
                    (view == UserDataView::Full).then(|| {
                        source
                            .entries
                            .iter()
                            .filter(|entry| entry.is_user_data())
                            .cloned()
                            .collect::<Vec<_>>()
                    }),
                )),
                None if lookup == UserDataLookup::Exact => None,
                None => Some((
                    comp_id,
                    Vec::new(),
                    (view == UserDataView::Full).then(Vec::new),
                )),
            })
            .collect::<Vec<_>>();

        self.components.extend(appender.into_components());
        for (comp_id, alert_ids, entries) in replacements {
            self.replace_user_data(comp_id, alert_ids, entries);
        }
    }

    fn drop_unreachable_components(&mut self) {
        let mut is_reachable = vec![false; self.components.len()];
        let mut pending = vec![0u32];
        while let Some(comp_id) = pending.pop() {
            match is_reachable.get_mut(comp_id as usize) {
                Some(is_reachable) if !*is_reachable => *is_reachable = true,
                _ => continue,
            }
            if let Some(component) = self.components.get(comp_id as usize) {
                pending.extend_from_slice(&component.component_ids);
            }
        }

        let unreachable = is_reachable
            .into_iter()
            .enumerate()
            .filter(|(_, is_reachable)| !*is_reachable)
            .map(|(comp_id, _)| comp_id as u32)
            .collect::<Vec<_>>();
        if !unreachable.is_empty() && !self.remove_component_ids(&unreachable) {
            for component in &mut self.components {
                component
                    .component_ids
                    .retain(|id| !unreachable.contains(id));
            }
        }
    }

    fn prune_user_data_overrides(&mut self, stored: &UserDataComponents<'_>) {
        let Some(overrides) = RedundantOverrides::new(self) else {
            return;
        };
        let redundant = self
            .user_data_component_ids()
            .into_iter()
            .filter(|(comp_id, key)| {
                *key != BASE_INSTANCE && !stored.contains(*key) && overrides.is_redundant(*comp_id)
            })
            .map(|(comp_id, _)| comp_id)
            .collect::<Vec<_>>();

        if !redundant.is_empty() {
            for component in &mut self.components {
                component.component_ids.retain(|id| !redundant.contains(id));
            }
        }
    }

    fn replace_user_data(
        &mut self,
        comp_id: u32,
        alert_ids: impl IntoIterator<Item = u32>,
        entries: Option<Vec<ICalendarEntry>>,
    ) {
        let Some(mut children) = self
            .components
            .get_mut(comp_id as usize)
            .map(|component| std::mem::take(&mut component.component_ids))
        else {
            return;
        };
        children.retain(|id| {
            self.component_by_id(*id)
                .is_none_or(|child| child.component_type != ICalendarComponentType::VAlarm)
        });
        children.extend(alert_ids);

        if let Some(component) = self.components.get_mut(comp_id as usize) {
            component.component_ids = children;
            if let Some(entries) = entries {
                component.entries.retain(|entry| !entry.is_user_data());
                component.entries.extend(entries);
            }
        }
    }

    fn base_updated(&self) -> Option<i64> {
        self.base_component_id()
            .and_then(|id| self.component_by_id(id))
            .and_then(|component| component.property(&ICalendarProperty::Dtstamp))
            .and_then(|entry| entry.values.first())
            .and_then(|value| value.as_partial_date_time())
            .and_then(|value| value.to_timestamp())
    }
}

struct UserDataComponents<'x> {
    ical: &'x ICalendar,
    ids: Vec<(u32, u32)>,
}

struct UserDataUsage<'x> {
    ical: &'x ICalendar,
    component: &'x ICalendarComponent,
}

impl<'x> UserDataUsage<'x> {
    fn new(ical: &'x ICalendar, component: &'x ICalendarComponent) -> Self {
        UserDataUsage { ical, component }
    }

    fn keywords(&self) -> impl Iterator<Item = &'x str> {
        self.component
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Categories)
            .flat_map(|entry| entry.values.iter())
            .filter_map(|value| value.as_text())
    }

    fn colors(&self) -> impl Iterator<Item = &'x str> {
        self.component
            .entries
            .iter()
            .filter(|entry| entry.name == ICalendarProperty::Color)
            .filter_map(|entry| entry.values.first().and_then(|value| value.as_text()))
    }

    fn alerts(&self) -> usize {
        self.ical.alarms(self.component).count()
    }

    fn validate(&self, stored: Option<&UserDataUsage<'_>>) -> Result<(), UserDataError> {
        let mut keywords = 0;
        for keyword in self.keywords() {
            if keyword.len() > MAX_USER_KEYWORD_LEN
                && stored.is_none_or(|stored| stored.keywords().all(|stored| stored != keyword))
            {
                return Err(UserDataError::KeywordTooLong);
            }
            keywords += 1;
        }
        if keywords > MAX_USER_KEYWORDS
            && stored.is_none_or(|stored| keywords > stored.keywords().count())
        {
            return Err(UserDataError::TooManyKeywords);
        }
        if self.colors().any(|color| {
            CssColor::parse(color).is_none()
                && stored.is_none_or(|stored| stored.colors().all(|stored| stored != color))
        }) {
            return Err(UserDataError::InvalidColor);
        }
        let alerts = self.alerts();
        if alerts > MAX_USER_ALERTS && stored.is_none_or(|stored| alerts > stored.alerts()) {
            return Err(UserDataError::TooManyAlerts);
        }
        Ok(())
    }
}

struct InstanceKeys<'x> {
    ical: &'x ICalendar,
    resolver: Option<TzResolver<&'x str>>,
}

impl<'x> InstanceKeys<'x> {
    fn new(ical: &'x ICalendar) -> Self {
        InstanceKeys {
            ical,
            resolver: None,
        }
    }

    fn of(&mut self, component: &ICalendarComponent) -> Option<u32> {
        match self.recurrence_id(component) {
            Some(recurrence_id) => {
                RecurrenceKey::from_recurrence_id(recurrence_id).map(RecurrenceKey::prefix)
            }
            None if !component.is_recurrence_override() => Some(BASE_INSTANCE),
            None => None,
        }
    }

    fn recurrence_id(&mut self, component: &ICalendarComponent) -> Option<i64> {
        if !component.is_recurrence_override() {
            return None;
        }
        let tz = self.start_tz(component);
        component
            .recurrence_id(tz)
            .map(|recurrence_id| recurrence_id.naive)
    }

    fn start_tz(&mut self, component: &ICalendarComponent) -> Tz {
        let Some(entry) = component.property(&ICalendarProperty::Dtstart) else {
            return Tz::Floating;
        };
        if let Some(tz) = entry
            .values
            .first()
            .and_then(ICalendarValue::as_partial_date_time)
            .and_then(PartialDateTime::to_date_time)
            .and_then(|start| start.tz())
        {
            return tz;
        }
        let ical = self.ical;
        self.resolver
            .get_or_insert_with(|| ical.build_tz_resolver())
            .resolve_or_default(entry.tz_id())
    }
}

impl<'x> UserDataComponents<'x> {
    fn new(ical: &'x ICalendar) -> Self {
        let mut ids = ical
            .user_data_component_ids()
            .into_iter()
            .map(|(comp_id, key)| (key, comp_id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        UserDataComponents { ical, ids }
    }

    fn contains(&self, key: u32) -> bool {
        self.position(key).is_some()
    }

    fn counterpart(&self, key: u32, lookup: UserDataLookup) -> Option<&'x ICalendarComponent> {
        match lookup {
            UserDataLookup::Inherited => {
                self.position(key).or_else(|| self.position(BASE_INSTANCE))
            }
            UserDataLookup::Exact => self.position(key),
        }
        .and_then(|index| self.ids.get(index))
        .and_then(|(_, comp_id)| self.ical.component_by_id(*comp_id))
    }

    fn position(&self, key: u32) -> Option<usize> {
        let index = self
            .ids
            .partition_point(|(stored_key, _)| *stored_key < key);
        self.ids
            .get(index)
            .filter(|(stored_key, _)| *stored_key == key)
            .map(|_| index)
    }
}

struct ComponentAppender<'x> {
    source: &'x ICalendar,
    first_id: u32,
    components: Vec<ICalendarComponent>,
}

impl<'x> ComponentAppender<'x> {
    fn new(source: &'x ICalendar, first_id: u32) -> Self {
        ComponentAppender {
            source,
            first_id,
            components: Vec::new(),
        }
    }

    fn push(&mut self, component: ICalendarComponent) -> u32 {
        let id = self.first_id + self.components.len() as u32;
        self.components.push(component);
        id
    }

    fn copy_tree(&mut self, id: u32) -> Option<u32> {
        self.copy_subtree(id, 0)
    }

    fn copy_subtree(&mut self, id: u32, depth: usize) -> Option<u32> {
        let source = self.source;
        let component = source
            .component_by_id(id)
            .filter(|_| depth < MAX_COMPONENT_DEPTH)?;
        let copy_id = self.push(component.detached());
        let children = component
            .component_ids
            .iter()
            .filter_map(|child_id| self.copy_subtree(*child_id, depth + 1))
            .collect::<Vec<_>>();
        if let Some(copy) = self.components.get_mut((copy_id - self.first_id) as usize) {
            copy.component_ids = children;
        }
        Some(copy_id)
    }

    fn into_components(self) -> Vec<ICalendarComponent> {
        self.components
    }
}

struct OccurrenceOverrides<'x> {
    appender: ComponentAppender<'x>,
    base: &'x ICalendarComponent,
    base_start: i64,
    override_ids: Vec<u32>,
}

impl<'x> OccurrenceOverrides<'x> {
    fn new(ical: &'x ICalendar, base_id: u32) -> Option<Self> {
        let base = ical.component_by_id(base_id)?;
        let base_start = base
            .property(&ICalendarProperty::Dtstart)?
            .values
            .first()?
            .as_partial_date_time()?
            .naive_timestamp()?;
        Some(OccurrenceOverrides {
            appender: ComponentAppender::new(ical, ical.components.len() as u32),
            base,
            base_start,
            override_ids: Vec::new(),
        })
    }

    fn push(&mut self, start: i64) {
        let (base, source) = (self.base, self.appender.source);
        let shift = start - self.base_start;
        let mut entries = Vec::with_capacity(base.entries.len() + 1);
        for entry in &base.entries {
            match entry.name {
                ICalendarProperty::Rrule
                | ICalendarProperty::Rdate
                | ICalendarProperty::Exrule
                | ICalendarProperty::Exdate => {}
                ICalendarProperty::Dtstart => {
                    let Some(start) = entry.shifted(shift) else {
                        return;
                    };
                    entries.push(ICalendarEntry {
                        name: ICalendarProperty::RecurrenceId,
                        params: start
                            .params
                            .iter()
                            .filter(|param| {
                                matches!(
                                    param.name,
                                    ICalendarParameterName::Tzid | ICalendarParameterName::Value
                                )
                            })
                            .cloned()
                            .collect(),
                        values: start.values.clone(),
                    });
                    entries.push(start);
                }
                ICalendarProperty::Dtend | ICalendarProperty::Due => {
                    entries.push(entry.shifted(shift).unwrap_or_else(|| entry.clone()));
                }
                _ => entries.push(entry.clone()),
            }
        }

        let children = base
            .component_ids
            .iter()
            .filter(|id| {
                source
                    .component_by_id(**id)
                    .is_some_and(|child| child.component_type != ICalendarComponentType::VAlarm)
            })
            .filter_map(|id| self.appender.copy_tree(*id))
            .collect();
        let override_id = self.appender.push(ICalendarComponent {
            component_type: base.component_type.clone(),
            entries,
            component_ids: children,
        });
        self.override_ids.push(override_id);
    }

    fn into_personal_overrides(self, root_id: usize) -> PersonalOverrides {
        PersonalOverrides {
            root_id,
            override_ids: self.override_ids,
            components: self.appender.into_components(),
        }
    }
}

trait ShiftedEntry {
    fn shifted(&self, shift: i64) -> Option<ICalendarEntry>;
}

impl ShiftedEntry for ICalendarEntry {
    fn shifted(&self, shift: i64) -> Option<ICalendarEntry> {
        let [ICalendarValue::PartialDateTime(value)] = self.values.as_slice() else {
            return None;
        };
        Some(ICalendarEntry {
            name: self.name.clone(),
            params: self.params.clone(),
            values: vec![ICalendarValue::PartialDateTime(Box::new(
                value.shifted(shift)?,
            ))],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::sequence::ICalendarSequence;
    use calcard::jscalendar::JSCalendar;
    use chrono::NaiveDate;
    use serde_json::{Value, json};

    const EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "DTSTAMP:20240101T000000Z\r\n",
        "DTSTART:20240101T100000Z\r\n",
        "DURATION:PT1H\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\n",
        "SUMMARY:Standup\r\n",
        "COLOR:red\r\n",
        "CATEGORIES:work,daily\r\n",
        "BEGIN:VALARM\r\n",
        "ACTION:DISPLAY\r\n",
        "DESCRIPTION:Owner alarm\r\n",
        "TRIGGER:-PT5M\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:abc\r\n",
        "RECURRENCE-ID:20240102T100000Z\r\n",
        "DTSTART:20240102T110000Z\r\n",
        "DURATION:PT1H\r\n",
        "SUMMARY:Standup moved\r\n",
        "COLOR:red\r\n",
        "CATEGORIES:work,daily\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    const WEEKLY_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:test\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:weekly\r\n",
        "DTSTAMP:20240101T000000Z\r\n",
        "DTSTART;TZID=Europe/Berlin:20240506T090000\r\n",
        "DURATION:PT30M\r\n",
        "RRULE:FREQ=WEEKLY;COUNT=4\r\n",
        "SUMMARY:Team sync\r\n",
        "DESCRIPTION:Details\r\n",
        "LOCATION:Room 1\r\n",
        "COLOR:#00ff00\r\n",
        "BEGIN:VLOCATION\r\n",
        "UID:location-1\r\n",
        "NAME:Main office\r\n",
        "END:VLOCATION\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    const GOOGLE_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "PRODID:-//Google Inc//Google Calendar 70.9054//EN\r\n",
        "VERSION:2.0\r\n",
        "CALSCALE:GREGORIAN\r\n",
        "METHOD:REQUEST\r\n",
        "BEGIN:VEVENT\r\n",
        "DTSTART:20240506T070000Z\r\n",
        "DTEND:20240506T080000Z\r\n",
        "DTSTAMP:20240101T000000Z\r\n",
        "ORGANIZER;CN=Alice Example:mailto:alice@example.com\r\n",
        "UID:abc123@google.com\r\n",
        "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE;",
        "CN=Alice Example;X-NUM-GUESTS=0:mailto:alice@example.com\r\n",
        "ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=",
        "TRUE;CN=bob@example.com;X-NUM-GUESTS=0:mailto:bob@example.com\r\n",
        "X-MICROSOFT-CDO-OWNERAPPTID:-1234567\r\n",
        "CREATED:20240101T000000Z\r\n",
        "DESCRIPTION:Join with Google Meet: https://meet.google.com/abc\r\n",
        "LAST-MODIFIED:20240101T000000Z\r\n",
        "LOCATION:\r\n",
        "SEQUENCE:0\r\n",
        "STATUS:CONFIRMED\r\n",
        "SUMMARY:Planning\r\n",
        "TRANSP:OPAQUE\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    const APPLE_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        "PRODID:-//Apple Inc.//macOS 14.0//EN\r\n",
        "CALSCALE:GREGORIAN\r\n",
        "BEGIN:VTIMEZONE\r\n",
        "TZID:Europe/Berlin\r\n",
        "BEGIN:DAYLIGHT\r\n",
        "TZOFFSETFROM:+0100\r\n",
        "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\n",
        "DTSTART:19810329T020000\r\n",
        "TZNAME:CEST\r\n",
        "TZOFFSETTO:+0200\r\n",
        "END:DAYLIGHT\r\n",
        "BEGIN:STANDARD\r\n",
        "TZOFFSETFROM:+0200\r\n",
        "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\n",
        "DTSTART:19961027T030000\r\n",
        "TZNAME:CET\r\n",
        "TZOFFSETTO:+0100\r\n",
        "END:STANDARD\r\n",
        "END:VTIMEZONE\r\n",
        "BEGIN:VEVENT\r\n",
        "CREATED:20240101T100000Z\r\n",
        "UID:7F1C9F2E-1234-4F1C-9C8E-ABCDEF123456\r\n",
        "DTEND;TZID=Europe/Berlin:20240506T100000\r\n",
        "TRANSP:OPAQUE\r\n",
        "X-APPLE-TRAVEL-ADVISORY-BEHAVIOR:AUTOMATIC\r\n",
        "SUMMARY:Weekly sync\r\n",
        "LAST-MODIFIED:20240102T100000Z\r\n",
        "DTSTAMP:20240102T100000Z\r\n",
        "DTSTART;TZID=Europe/Berlin:20240506T090000\r\n",
        "LOCATION:Room 1\\nMain street 1\r\n",
        "X-APPLE-STRUCTURED-LOCATION;VALUE=URI;X-ADDRESS=Main street 1;",
        "X-APPLE-RADIUS=70;X-TITLE=Room 1:geo:52.5,13.4\r\n",
        "SEQUENCE:1\r\n",
        "RRULE:FREQ=WEEKLY;BYDAY=MO\r\n",
        "EXDATE;TZID=Europe/Berlin:20240520T090000\r\n",
        "URL;VALUE=URI:https://example.com/meet\r\n",
        "BEGIN:VALARM\r\n",
        "X-WR-ALARMUID:2A6D8B0E-0000-4F4F-9E9E-000000000001\r\n",
        "UID:2A6D8B0E-0000-4F4F-9E9E-000000000001\r\n",
        "TRIGGER:-PT15M\r\n",
        "ATTACH;VALUE=URI:Chord\r\n",
        "ACTION:AUDIO\r\n",
        "END:VALARM\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    const THUNDERBIRD_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "PRODID:-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN\r\n",
        "VERSION:2.0\r\n",
        "BEGIN:VTIMEZONE\r\n",
        "TZID:Europe/Berlin\r\n",
        "BEGIN:STANDARD\r\n",
        "DTSTART:19701025T030000\r\n",
        "TZOFFSETFROM:+0200\r\n",
        "TZOFFSETTO:+0100\r\n",
        "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n",
        "TZNAME:CET\r\n",
        "END:STANDARD\r\n",
        "BEGIN:DAYLIGHT\r\n",
        "DTSTART:19700329T020000\r\n",
        "TZOFFSETFROM:+0100\r\n",
        "TZOFFSETTO:+0200\r\n",
        "RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n",
        "TZNAME:CEST\r\n",
        "END:DAYLIGHT\r\n",
        "END:VTIMEZONE\r\n",
        "BEGIN:VEVENT\r\n",
        "CREATED:20260101T000000Z\r\n",
        "LAST-MODIFIED:20260101T000000Z\r\n",
        "DTSTAMP:20260101T000000Z\r\n",
        "UID:tb-1\r\n",
        "SUMMARY:Planning\r\n",
        "ORGANIZER;CN=John Doe:mailto:jdoe@example.com\r\n",
        "ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION;ROLE=REQ-PARTICIPANT;CN=Jane:mailto:",
        "jane@example.com\r\n",
        "ATTENDEE;PARTSTAT=ACCEPTED;ROLE=CHAIR;CN=John Doe:mailto:jdoe@example.com\r\n",
        "DTSTART;VALUE=DATE-TIME;TZID=Europe/Berlin:20260601T090000\r\n",
        "DTEND;TZID=Europe/Berlin:20260601T100000\r\n",
        "SEQUENCE:1\r\n",
        "TRANSP:OPAQUE\r\n",
        "X-MOZ-GENERATION:3\r\n",
        "CATEGORIES:Work\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    fn parse(ical: &str) -> ICalendar {
        ICalendar::parse(ical).expect("valid iCalendar")
    }

    fn to_json(ical: ICalendar) -> Value {
        serde_json::to_value(ical.into_jscalendar::<String, String>())
            .expect("serializable JSCalendar")
    }

    fn from_json(json: &Value) -> ICalendar {
        JSCalendar::<String, String>::parse(&json.to_string())
            .expect("valid JSCalendar")
            .into_icalendar()
            .expect("valid iCalendar")
    }

    fn jmap_view(stored: &ICalendar, preferences: Option<&EventPreferences>) -> Value {
        to_json(
            CalendarEventData::new(stored.clone(), Tz::Floating, 100)
                .user_data_view(preferences, UserDataView::Full),
        )
    }

    fn jmap_update(
        stored: &ICalendar,
        preferences: Option<&EventPreferences>,
        patch: impl FnOnce(&mut Value),
    ) -> ICalendar {
        let mut json = jmap_view(stored, preferences);
        patch(&mut json["entries"][0]);
        from_json(&json)
    }

    fn split(
        incoming: &mut ICalendar,
        stored: &ICalendar,
        view: UserDataView,
        previous: Option<&EventPreferences>,
    ) -> (EventPreferences, UserDataSplit) {
        incoming
            .split_user_data(
                stored,
                UserDataUpdate {
                    account_id: 9,
                    view,
                    previous,
                    current: previous,
                    updated: UpdatedPolicy::Server(1_000_000),
                },
            )
            .expect("valid personal data")
    }

    fn occurrence_key(year: i32, month: u32, day: u32, hour: u32) -> u32 {
        NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|date| date.and_hms_opt(hour, 0, 0))
            .and_then(|date| RecurrenceKey::from_recurrence_id(date.and_utc().timestamp()))
            .expect("valid recurrence key")
            .prefix()
    }

    fn sharee_preferences() -> EventPreferences {
        EventPreferences {
            account_id: 9,
            ..Default::default()
        }
    }

    #[test]
    fn sharee_defaults_hide_owner_values() {
        let mut ical = parse(EVENT);
        ical.apply_user_data(None, UserDataView::Full);
        let text = ical.to_string();
        for removed in ["COLOR", "CATEGORIES", "VALARM", "Owner alarm"] {
            assert!(!text.contains(removed), "{removed} leaked:\n{text}");
        }
        assert!(text.contains("SUMMARY:Standup moved"));
    }

    #[test]
    fn alerts_only_view_keeps_owner_properties() {
        let mut preferences = sharee_preferences();
        preferences
            .instance_mut(BASE_INSTANCE)
            .unwrap()
            .set_alerts(
                parse(&EVENT.replace("Owner alarm", "Sharee alarm"))
                    .components
                    .into_iter()
                    .filter(|c| c.component_type == ICalendarComponentType::VAlarm)
                    .collect(),
            )
            .unwrap();
        let mut ical = parse(EVENT);
        ical.apply_user_data(Some(&preferences), UserDataView::AlertsOnly);
        let text = ical.to_string();
        assert!(text.contains("COLOR:red"), "{text}");
        assert!(text.contains("CATEGORIES:work,daily"), "{text}");
        assert!(text.contains("Sharee alarm"), "{text}");
        assert!(!text.contains("Owner alarm"), "{text}");
    }

    #[test]
    fn apply_and_extract_round_trip() {
        let mut preferences = sharee_preferences();
        let base = preferences.instance_mut(BASE_INSTANCE).unwrap();
        base.set_color(CssColor::parse("#00ff00"));
        base.set_keywords(["mine"]).unwrap();
        base.set_free_busy(true);
        preferences
            .instance_mut(occurrence_key(2024, 1, 2, 10))
            .unwrap()
            .set_color(CssColor::parse("blue"));

        let mut ical = parse(EVENT);
        ical.apply_user_data(Some(&preferences), UserDataView::Full);
        let text = ical.to_string();
        assert!(text.contains("COLOR:#00ff00"), "{text}");
        assert!(text.contains("COLOR:blue"), "{text}");
        assert!(text.contains("CATEGORIES:mine"), "{text}");
        assert!(text.contains("TRANSP:TRANSPARENT"), "{text}");

        let extracted = parse(&text).extract_user_data(9).unwrap();
        assert_eq!(extracted, preferences);
    }

    #[test]
    fn split_restores_owner_values() {
        let stored = parse(EVENT);
        let mut sharee = parse(EVENT);
        sharee.apply_user_data(None, UserDataView::Full);
        let mut preferences = sharee_preferences();
        preferences
            .instance_mut(BASE_INSTANCE)
            .unwrap()
            .set_keywords(["personal"])
            .unwrap();
        sharee.apply_user_data(Some(&preferences), UserDataView::Full);

        let mut incoming = parse(&sharee.to_string());
        let (extracted, result) = split(&mut incoming, &stored, UserDataView::Full, None);
        assert_eq!(result, UserDataSplit::UserDataOnly);
        assert!(
            extracted
                .instance(BASE_INSTANCE)
                .is_some_and(|i| i.keywords == ["personal"])
        );
        let restored = incoming.to_string();
        assert!(restored.contains("CATEGORIES:work,daily"), "{restored}");
        assert!(restored.contains("Owner alarm"), "{restored}");

        let mut changed = parse(
            &sharee
                .to_string()
                .replace("SUMMARY:Standup\r\n", "SUMMARY:Changed\r\n"),
        );
        let (_, result) = split(&mut changed, &stored, UserDataView::Full, None);
        assert_eq!(result, UserDataSplit::SharedDataChanged);
    }

    #[test]
    fn split_prunes_occurrence_override_with_shifted_end() {
        let stored = parse(
            &EVENT
                .replace("DURATION:PT1H\r\n", "DTEND:20240101T110000Z\r\n")
                .replace(
                    concat!(
                        "RECURRENCE-ID:20240102T100000Z\r\n",
                        "DTSTART:20240102T110000Z\r\n",
                        "DTEND:20240101T110000Z\r\n",
                    ),
                    concat!(
                        "RECURRENCE-ID:20240102T100000Z\r\n",
                        "DTSTART:20240102T110000Z\r\n",
                        "DTEND:20240102T120000Z\r\n",
                    ),
                ),
        );
        let mut incoming = jmap_update(&stored, None, |event| {
            event["recurrenceOverrides"]["2024-01-04T10:00:00"] = json!({ "color": "blue" });
        });

        let (extracted, result) = split(&mut incoming, &stored, UserDataView::Full, None);
        assert_eq!(result, UserDataSplit::UserDataOnly, "{incoming}");
        assert!(
            extracted
                .instance(occurrence_key(2024, 1, 4, 10))
                .is_some_and(|i| i.color == CssColor::parse("blue")),
            "{extracted:?}"
        );
    }

    #[test]
    fn client_formatting_round_trip_is_not_a_change() {
        for (client, text) in [
            ("google", GOOGLE_EVENT),
            ("apple", APPLE_EVENT),
            ("thunderbird", THUNDERBIRD_EVENT),
        ] {
            let stored = parse(text);

            let mut owner = to_json(stored.clone());
            owner["entries"][0]["keywords"] = json!({ "personal": true });
            owner["entries"][0]["color"] = json!("blue");
            let owner = from_json(&owner);
            assert!(!owner.has_scheduling_changes(&stored), "{client}:\n{owner}");

            let mut sharee = jmap_update(&stored, None, |event| {
                event["color"] = json!("blue");
                event["keywords"] = json!({ "personal": true });
            });
            let (preferences, result) = split(&mut sharee, &stored, UserDataView::Full, None);
            assert_eq!(result, UserDataSplit::UserDataOnly, "{client}:\n{sharee}");
            assert!(
                preferences
                    .instance(BASE_INSTANCE)
                    .is_some_and(|base| base.color == CssColor::parse("blue")
                        && base.keywords == ["personal"]),
                "{client}: {preferences:?}"
            );

            let mut owner = to_json(stored.clone());
            owner["entries"][0]["title"] = json!("Changed");
            assert!(
                from_json(&owner).has_scheduling_changes(&stored),
                "{client}"
            );
            let mut sharee = jmap_update(&stored, None, |event| {
                event["title"] = json!("Changed");
            });
            let (_, result) = split(&mut sharee, &stored, UserDataView::Full, None);
            assert_eq!(result, UserDataSplit::SharedDataChanged, "{client}");
        }
    }

    #[test]
    fn participant_parameter_order_is_not_a_change() {
        let stored = from_json(&json!({
            "@type": "Group",
            "entries": [{
                "@type": "Event",
                "uid": "u1",
                "title": "Sync",
                "start": "2030-01-01T09:00:00",
                "timeZone": "Europe/Berlin",
                "duration": "PT1H",
                "organizerCalendarAddress": "mailto:john@example.com",
                "participants": {
                    "john": {
                        "@type": "Participant",
                        "calendarAddress": "mailto:john@example.com",
                        "roles": { "owner": true, "attendee": true },
                        "participationStatus": "accepted",
                        "expectReply": false,
                        "name": "John"
                    },
                    "jane": {
                        "@type": "Participant",
                        "calendarAddress": "mailto:jane@example.com",
                        "roles": { "attendee": true, "optional": true },
                        "participationStatus": "needs-action",
                        "expectReply": true,
                        "name": "Jane",
                        "kind": "individual"
                    }
                }
            }]
        }));
        for _ in 0..20 {
            let mut owner = to_json(stored.clone());
            owner["entries"][0]["keywords"] = json!({ "personal": true });
            assert!(!from_json(&owner).has_scheduling_changes(&stored));

            let mut sharee = jmap_update(&stored, None, |event| {
                event["keywords"] = json!({ "personal": true });
            });
            let (_, result) = split(&mut sharee, &stored, UserDataView::Full, None);
            assert_eq!(result, UserDataSplit::UserDataOnly, "{sharee}");
        }
    }

    #[test]
    fn personal_occurrence_override_is_complete() {
        let stored = from_json(&to_json(parse(WEEKLY_EVENT)));
        let mut preferences = sharee_preferences();
        preferences
            .instance_mut(occurrence_key(2024, 5, 13, 9))
            .unwrap()
            .set_color(CssColor::parse("blue"));
        preferences
            .instance_mut(occurrence_key(2024, 5, 14, 9))
            .unwrap()
            .set_color(CssColor::parse("red"));

        let json = jmap_view(&stored, Some(&preferences));
        assert_eq!(
            json["entries"][0]["recurrenceOverrides"],
            json!({ "2024-05-13T09:00:00": { "color": "blue" } }),
            "{json:#}"
        );

        let mut view = CalendarEventData::new(stored.clone(), Tz::Floating, 100);
        view.apply_user_data(Some(&preferences), UserDataView::Full);
        let base_id = view.event.base_component_id().unwrap();
        let key = RecurrenceKey::from_prefix(occurrence_key(2024, 5, 13, 9)).unwrap();
        let instance = view
            .event
            .user_data_override(base_id, key)
            .expect("personal occurrence");
        assert!(
            instance
                .component_ids
                .iter()
                .filter_map(|id| view.event.component_by_id(*id))
                .any(|child| child.component_type == ICalendarComponentType::VLocation),
            "{}",
            view.event
        );

        let mut incoming = from_json(&json);
        let (extracted, result) = split(
            &mut incoming,
            &stored,
            UserDataView::Full,
            Some(&preferences),
        );
        assert_eq!(result, UserDataSplit::UserDataOnly, "{incoming}");
        assert_eq!(
            extracted
                .instances
                .iter()
                .map(|instance| instance.recurrence_key)
                .collect::<Vec<_>>(),
            [occurrence_key(2024, 5, 13, 9)]
        );
    }

    #[test]
    fn occurrence_removal_is_not_redundant() {
        let event = json!({
            "@type": "Event",
            "uid": "abc",
            "updated": "2024-01-01T00:00:00Z",
            "title": "Team sync",
            "start": "2024-05-06T09:00:00",
            "timeZone": "Europe/Berlin",
            "duration": "PT30M",
            "recurrenceRule": { "@type": "RecurrenceRule", "frequency": "weekly", "count": 4 },
            "locations": { "l1": { "@type": "Location", "name": "Room 1" } },
            "organizerCalendarAddress": "mailto:a@example.org",
            "participants": {
                "p1": {
                    "@type": "Participant",
                    "calendarAddress": "mailto:a@example.org",
                    "roles": { "owner": true, "attendee": true }
                },
                "p2": {
                    "@type": "Participant",
                    "calendarAddress": "mailto:b@example.org",
                    "roles": { "attendee": true }
                }
            }
        });
        let stored = from_json(&json!({ "@type": "Group", "entries": [event] }));
        for removal in [
            json!({ "locations": null }),
            json!({ "participants/p2": null }),
            json!({ "locations": null, "participants/p2": null }),
        ] {
            let mut incoming = jmap_update(&stored, None, |event| {
                event["recurrenceOverrides"] = json!({ "2024-05-13T09:00:00": removal });
            });
            let (_, result) = split(&mut incoming, &stored, UserDataView::Full, None);
            assert_eq!(result, UserDataSplit::SharedDataChanged, "{incoming}");
        }
    }

    #[test]
    fn alerts_only_split_keeps_personal_values() {
        let stored = parse(EVENT);
        let mut previous = sharee_preferences();
        previous.updated = 500;
        let base = previous.instance_mut(BASE_INSTANCE).unwrap();
        base.set_color(CssColor::parse("#00ff00"));
        base.set_keywords(["jane"]).unwrap();
        base.set_free_busy(true);
        base.set_alerts(
            parse(&EVENT.replace("Owner alarm", "Sharee alarm"))
                .components
                .into_iter()
                .filter(|c| c.component_type == ICalendarComponentType::VAlarm)
                .collect(),
        )
        .unwrap();
        previous
            .instance_mut(occurrence_key(2024, 1, 2, 10))
            .unwrap()
            .set_color(CssColor::parse("blue"));
        previous
            .instance_mut(occurrence_key(2024, 1, 4, 10))
            .unwrap()
            .set_keywords(["last"])
            .unwrap();

        let mut view = stored.clone();
        view.apply_user_data(Some(&previous), UserDataView::AlertsOnly);
        let view = view.to_string();

        let mut unchanged = parse(&view);
        let (preferences, result) = split(
            &mut unchanged,
            &stored,
            UserDataView::AlertsOnly,
            Some(&previous),
        );
        assert_eq!(result, UserDataSplit::UserDataOnly, "{unchanged}");
        assert_eq!(preferences, previous);

        let mut changed_alarm = parse(&view.replace("Sharee alarm", "Changed alarm"));
        let (preferences, result) = split(
            &mut changed_alarm,
            &stored,
            UserDataView::AlertsOnly,
            Some(&previous),
        );
        assert_eq!(result, UserDataSplit::UserDataOnly, "{changed_alarm}");
        assert_eq!(preferences.updated, 1_000_000);
        let base = preferences.instance(BASE_INSTANCE).unwrap();
        assert_eq!(base.color, CssColor::parse("#00ff00"));
        assert_eq!(base.keywords, ["jane"]);
        assert_ne!(base.flags & PREF_FREE_BUSY_FREE, 0);
        assert!(
            base.alerts
                .iter()
                .flat_map(|alert| alert.entries.iter())
                .any(
                    |entry| entry.values.first().and_then(|v| v.as_text()) == Some("Changed alarm")
                )
        );
        assert_eq!(
            preferences
                .instance(occurrence_key(2024, 1, 2, 10))
                .and_then(|instance| instance.color.as_ref()),
            CssColor::parse("blue").as_ref()
        );
        assert_eq!(
            preferences
                .instance(occurrence_key(2024, 1, 4, 10))
                .map(|instance| instance.keywords.as_slice()),
            Some(["last".to_string()].as_slice())
        );
        assert!(changed_alarm.to_string().contains("Owner alarm"));

        let mut changed_color = parse(&view.replacen("COLOR:red", "COLOR:green", 1));
        assert!(!changed_color.has_same_user_data(&stored));
        assert!(parse(&view).has_same_user_data(&stored));
        let (_, result) = split(
            &mut changed_color,
            &stored,
            UserDataView::AlertsOnly,
            Some(&previous),
        );
        assert_eq!(result, UserDataSplit::SharedDataChanged);
    }

    #[test]
    fn personal_alerts_are_self_contained() {
        let owner = parse(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:owner\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "DTSTART:20240506T090000Z\r\n",
            "DURATION:PT30M\r\n",
            "SUMMARY:Team sync\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:EMAIL\r\n",
            "SUMMARY:Owner private reminder\r\n",
            "DESCRIPTION:Call the lawyer first\r\n",
            "ATTENDEE:mailto:owner-private@example.com\r\n",
            "TRIGGER:-PT1H\r\n",
            "BEGIN:VLOCATION\r\n",
            "UID:owner-location\r\n",
            "NAME:Owner office\r\n",
            "END:VLOCATION\r\n",
            "END:VALARM\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "DESCRIPTION:Owner second alarm\r\n",
            "TRIGGER:-PT5M\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));
        let mut body = parse(concat!(
            "BEGIN:VCALENDAR\r\n",
            "VERSION:2.0\r\n",
            "PRODID:owner\r\n",
            "BEGIN:VEVENT\r\n",
            "UID:abc\r\n",
            "DTSTAMP:20240101T000000Z\r\n",
            "DTSTART:20240506T090000Z\r\n",
            "DURATION:PT30M\r\n",
            "SUMMARY:Team sync\r\n",
            "BEGIN:VALARM\r\n",
            "ACTION:DISPLAY\r\n",
            "DESCRIPTION:Sharee alarm\r\n",
            "TRIGGER;VALUE=DATE-TIME:20240506T085000Z\r\n",
            "PROXIMITY:ARRIVE\r\n",
            "BEGIN:VLOCATION\r\n",
            "UID:loc-1\r\n",
            "URL:geo:52.5,13.4\r\n",
            "END:VLOCATION\r\n",
            "END:VALARM\r\n",
            "END:VEVENT\r\n",
            "END:VCALENDAR\r\n"
        ));

        let (preferences, result) = split(&mut body, &owner, UserDataView::AlertsOnly, None);
        assert_eq!(result, UserDataSplit::UserDataOnly, "{body}");
        let alerts = &preferences.instance(BASE_INSTANCE).unwrap().alerts;
        assert_eq!(alerts.len(), 1);
        assert!(alerts.iter().all(|alert| alert.component_ids.is_empty()));
        let restored = body.to_string();
        assert!(restored.contains("Owner office"), "{restored}");
        assert!(restored.contains("Owner second alarm"), "{restored}");
        assert!(!restored.contains("Sharee alarm"), "{restored}");

        let mut view = owner.clone();
        view.apply_user_data(Some(&preferences), UserDataView::AlertsOnly);
        let text = view.to_string();
        assert!(text.contains("Sharee alarm"), "{text}");
        assert!(!text.contains("Owner"), "{text}");
        assert_eq!(text.matches("BEGIN:VALARM").count(), 1, "{text}");
        assert_eq!(parse(&text).to_string(), text);
    }

    #[test]
    fn personal_jsprop_is_user_data() {
        let entry = |pointer: &str| {
            parse(&format!(
                concat!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\n",
                    "UID:abc\r\nDTSTART:20240506T090000Z\r\nJSPROP;JSPTR=\"{}\":\"x\"\r\n",
                    "END:VEVENT\r\nEND:VCALENDAR\r\n"
                ),
                pointer
            ))
            .components
            .into_iter()
            .flat_map(|component| component.entries)
            .find(|entry| entry.name == ICalendarProperty::Jsprop)
            .expect("JSPROP entry")
        };
        for (pointer, expected) in [
            ("freeBusyStatus", true),
            ("keywords/extra", true),
            ("alerts/a1/x-vendor", true),
            ("example.com:foo", false),
            ("title", false),
        ] {
            assert_eq!(entry(pointer).is_user_data(), expected, "{pointer}");
        }

        let stored = parse(&EVENT.replace(
            "COLOR:red\r\nCATEGORIES:work,daily\r\nBEGIN:VALARM",
            "COLOR:red\r\nJSPROP;JSPTR=freeBusyStatus:\"x-owner\"\r\nBEGIN:VALARM",
        ));
        let mut view = stored.clone();
        view.apply_user_data(None, UserDataView::Full);
        assert!(!view.to_string().contains("x-owner"), "{view}");

        let mut incoming = jmap_update(&stored, None, |event| {
            event["freeBusyStatus"] = json!("x-out-of-office");
        });
        assert!(
            incoming.to_string().contains("x-out-of-office"),
            "{incoming}"
        );
        let (_, result) = split(&mut incoming, &stored, UserDataView::Full, None);
        assert_eq!(result, UserDataSplit::UserDataOnly, "{incoming}");
        let restored = incoming.to_string();
        assert!(restored.contains("x-owner"), "{restored}");
        assert!(!restored.contains("x-out-of-office"), "{restored}");
    }

    #[test]
    fn limits_apply_to_personal_data_only() {
        let categories = (0..70)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let overrides = (1..=130)
            .map(|day| {
                let date = NaiveDate::from_ymd_opt(2024, 1, 1)
                    .and_then(|date| date.checked_add_days(chrono::Days::new(day)))
                    .map(|date| date.format("%Y%m%d").to_string())
                    .expect("valid date");
                format!(
                    concat!(
                        "BEGIN:VEVENT\r\nUID:abc\r\nDTSTAMP:20240101T000000Z\r\n",
                        "RECURRENCE-ID:{date}T100000Z\r\nDTSTART:{date}T100000Z\r\n",
                        "DURATION:PT1H\r\nSUMMARY:Occurrence {day}\r\nEND:VEVENT\r\n"
                    ),
                    date = date,
                    day = day
                )
            })
            .collect::<String>();
        let stored = parse(&format!(
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\n",
                "UID:abc\r\nDTSTAMP:20240101T000000Z\r\nDTSTART:20240101T100000Z\r\n",
                "DURATION:PT1H\r\nRRULE:FREQ=DAILY;COUNT=200\r\nSUMMARY:Daily\r\n",
                "CATEGORIES:{categories}\r\nEND:VEVENT\r\n{overrides}END:VCALENDAR\r\n"
            ),
            categories = categories,
            overrides = overrides
        ));

        let mut incoming = jmap_update(&stored, None, |event| {
            event["color"] = json!("blue");
        });
        let (preferences, result) = split(&mut incoming, &stored, UserDataView::Full, None);
        assert_eq!(result, UserDataSplit::UserDataOnly);
        assert_eq!(preferences.instances.len(), 1);
    }

    #[test]
    fn owner_updates_only_validate_changed_personal_data() {
        let categories = (0..70)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let alarms = (0..40)
            .map(|i| {
                format!(
                    "BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Alarm {i}\r\nTRIGGER:-PT{i}M\r\nEND:VALARM\r\n"
                )
            })
            .collect::<String>();
        let stored = parse(&format!(
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\n",
                "UID:abc\r\nDTSTAMP:20240101T000000Z\r\nDTSTART:20240101T100000Z\r\n",
                "DURATION:PT1H\r\nRRULE:FREQ=DAILY;COUNT=5\r\nSUMMARY:Daily\r\n",
                "CATEGORIES:{categories}\r\nCOLOR:{color}\r\n{alarms}END:VEVENT\r\n",
                "END:VCALENDAR\r\n"
            ),
            categories = categories,
            color = "c".repeat(33),
            alarms = alarms
        ));
        assert_eq!(
            stored.validate_user_data(),
            Err(UserDataError::TooManyKeywords)
        );
        let owner_update = |patch: &dyn Fn(&mut Value)| {
            let mut json = to_json(stored.clone());
            patch(&mut json["entries"][0]);
            from_json(&json)
        };

        for unchanged in [
            owner_update(&|event| event["title"] = json!("Renamed")),
            owner_update(&|event| {
                event["recurrenceOverrides"] =
                    json!({ "2024-01-02T10:00:00": { "title": "Moved" } })
            }),
            owner_update(&|event| {
                event["keywords"]
                    .as_object_mut()
                    .map(|keywords| keywords.remove("c0"));
            }),
        ] {
            assert_eq!(unchanged.validate_user_data_changes(&stored), Ok(()));
        }

        for (changed, error) in [
            (
                owner_update(&|event| event["keywords"]["c70"] = json!(true)),
                UserDataError::TooManyKeywords,
            ),
            (
                owner_update(&|event| event["keywords"]["x".repeat(129)] = json!(true)),
                UserDataError::KeywordTooLong,
            ),
            (
                owner_update(&|event| event["color"] = json!("d".repeat(33))),
                UserDataError::InvalidColor,
            ),
            (
                owner_update(&|event| {
                    event["alerts"]["extra"] = json!({
                        "@type": "Alert",
                        "trigger": { "@type": "OffsetTrigger", "offset": "-PT1H" }
                    })
                }),
                UserDataError::TooManyAlerts,
            ),
        ] {
            assert_eq!(changed.validate_user_data_changes(&stored), Err(error));
        }
    }

    #[test]
    fn personal_updated_rules() {
        let stored = parse(EVENT);
        let mut previous = sharee_preferences();
        previous.updated = 500;
        previous
            .instance_mut(BASE_INSTANCE)
            .unwrap()
            .set_color(CssColor::parse("blue"));

        let update = |view: &ICalendar, current: &EventPreferences, updated: UpdatedPolicy| {
            let mut incoming = view.clone();
            incoming
                .split_user_data(
                    &stored,
                    UserDataUpdate {
                        account_id: 9,
                        view: UserDataView::Full,
                        previous: Some(&previous),
                        current: Some(current),
                        updated,
                    },
                )
                .expect("valid personal data")
                .0
        };
        let mut view = stored.clone();
        view.apply_user_data(Some(&previous), UserDataView::Full);

        assert_eq!(
            update(&view, &previous, UpdatedPolicy::Server(1000)).updated,
            500
        );
        let mut current = previous.clone();
        current.set_use_default_alerts(true).unwrap();
        assert_eq!(
            update(&view, &current, UpdatedPolicy::Server(1000)).updated,
            1000
        );
        assert_eq!(update(&view, &current, UpdatedPolicy::Client).updated, 500);
        let client_view = parse(&view.to_string().replacen(
            "DTSTAMP:20240101T000000Z",
            "DTSTAMP:20240301T000000Z",
            1,
        ));
        assert_eq!(
            update(&client_view, &previous, UpdatedPolicy::Client).updated,
            1_709_251_200
        );

        let mut cleared = parse(&view.to_string().replace("COLOR:blue\r\n", ""));
        cleared.apply_user_data(None, UserDataView::Full);
        let cleared = update(&cleared, &previous, UpdatedPolicy::Server(1000));
        assert_eq!(cleared.updated, 1000);
        assert!(!cleared.is_empty());
    }

    #[test]
    fn limits_are_enforced() {
        let mut data = EventUserData::default();
        let long = "k".repeat(MAX_USER_KEYWORD_LEN + 1);
        assert_eq!(
            data.set_keywords([long.as_str()]),
            Err(UserDataError::KeywordTooLong)
        );
        let many = (0..=MAX_USER_KEYWORDS)
            .map(|i| i.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            data.set_keywords(many.iter().map(String::as_str)),
            Err(UserDataError::TooManyKeywords)
        );
        assert_eq!(
            data.set_alerts(vec![ICalendarComponent::default(); MAX_USER_ALERTS + 1]),
            Err(UserDataError::TooManyAlerts)
        );
        let mut preferences = EventPreferences::default();
        for key in 0..MAX_USER_INSTANCES as u32 {
            preferences.instance_mut(key).unwrap();
        }
        assert_eq!(
            preferences.instance_mut(u32::MAX).err(),
            Some(UserDataError::TooManyInstances)
        );
    }

    const REENCODED_EVENT: &str = concat!(
        "BEGIN:VCALENDAR\r\n",
        "PRODID:-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN\r\n",
        "VERSION:2.0\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:reencoded\r\n",
        "DTSTAMP:20260101T000000Z\r\n",
        "DTSTART;TZID=Europe/Berlin:20300601T090000\r\n",
        "DTEND:20300601T080000Z\r\n",
        "RRULE:FREQ=DAILY;COUNT=5\r\n",
        "SUMMARY:Standup\r\n",
        "COLOR:red\r\n",
        "ORGANIZER:mailto:john@example.com\r\n",
        "ATTENDEE;PARTSTAT=ACCEPTED:mailto:jane@example.com\r\n",
        "END:VEVENT\r\n",
        "BEGIN:VEVENT\r\n",
        "UID:reencoded\r\n",
        "DTSTAMP:20260101T000000Z\r\n",
        "RECURRENCE-ID:20300602T070000Z\r\n",
        "DTSTART;TZID=Europe/Berlin:20300602T110000\r\n",
        "DTEND:20300602T100000Z\r\n",
        "SUMMARY:Standup moved\r\n",
        "COLOR:green\r\n",
        "ORGANIZER:mailto:john@example.com\r\n",
        "ATTENDEE;PARTSTAT=ACCEPTED:mailto:jane@example.com\r\n",
        "END:VEVENT\r\n",
        "END:VCALENDAR\r\n"
    );

    #[test]
    fn owner_personal_change_keeps_the_stored_event() {
        let stored = parse(REENCODED_EVENT);
        assert!(
            from_json(&to_json(stored.clone())).has_scheduling_changes(&stored),
            "the fixture is expected to be re-encoded by the round trip"
        );

        let mut view = to_json(stored.clone());
        view["entries"][0]["color"] = json!("blue");
        view["entries"][0]["keywords"] = json!({ "personal": true });
        view["entries"][0]["recurrenceOverrides"]["2030-06-02T09:00:00"]["color"] = json!("azure");
        let mut event = stored.clone();
        event.copy_user_data(&from_json(&view));

        assert!(!event.has_scheduling_changes(&stored), "{event}");
        let text = event.to_string();
        assert!(text.contains("DTEND:20300601T080000Z"), "{text}");
        assert!(text.contains("COLOR:blue"), "{text}");
        assert!(text.contains("CATEGORIES:personal"), "{text}");
        assert!(text.contains("COLOR:azure"), "{text}");
        assert!(!text.contains("COLOR:green"), "{text}");
    }

    #[test]
    fn owner_personal_values_on_a_rule_occurrence_are_dropped() {
        let stored = parse(REENCODED_EVENT);
        let mut view = to_json(stored.clone());
        view["entries"][0]["recurrenceOverrides"]["2030-06-03T09:00:00"] =
            json!({ "color": "azure" });
        let mut event = stored.clone();
        event.copy_user_data(&from_json(&view));

        assert!(!event.has_scheduling_changes(&stored), "{event}");
        assert_eq!(
            event
                .components
                .iter()
                .filter(|component| component.is_user_data_component())
                .count(),
            2,
            "{event}"
        );
        assert!(!event.to_string().contains("COLOR:azure"), "{event}");
    }

    #[test]
    fn personal_data_matches_overrides_across_recurrence_id_zones() {
        let stored = parse(REENCODED_EVENT);
        assert_eq!(
            stored
                .extract_user_data(9)
                .expect("valid personal data")
                .instances
                .iter()
                .map(|instance| instance.recurrence_key)
                .collect::<Vec<_>>(),
            [BASE_INSTANCE, occurrence_key(2030, 6, 2, 9)]
        );

        let mut sharee = jmap_update(&stored, None, |event| {
            event["recurrenceOverrides"]["2030-06-02T09:00:00"]["color"] = json!("azure");
        });
        let extracted = sharee
            .extract_user_preferences(
                &stored,
                UserDataUpdate {
                    account_id: 9,
                    view: UserDataView::Full,
                    previous: None,
                    current: None,
                    updated: UpdatedPolicy::Server(1_000_000),
                },
            )
            .expect("valid personal data");
        assert_eq!(
            extracted
                .instance(occurrence_key(2030, 6, 2, 9))
                .and_then(|instance| instance.color.as_ref()),
            CssColor::parse("azure").as_ref()
        );
        assert_eq!(
            split(&mut sharee, &stored, UserDataView::Full, None).1,
            UserDataSplit::SharedDataChanged
        );
    }

    #[test]
    fn owner_copy_keeps_overrides_the_export_does_not_carry() {
        let stored = parse(REENCODED_EVENT);
        let source = parse(
            &REENCODED_EVENT
                .replace("COLOR:red", "COLOR:blue")
                .split_once(
                    "BEGIN:VEVENT\r\nUID:reencoded\r\nDTSTAMP:20260101T000000Z\r\nRECURRENCE-ID",
                )
                .map(|(series, _)| format!("{series}END:VCALENDAR\r\n"))
                .expect("series"),
        );
        let mut event = stored.clone();
        assert!(event.copy_user_data(&source).is_empty());

        let text = event.to_string();
        assert!(text.contains("COLOR:blue"), "{text}");
        assert!(text.contains("COLOR:green"), "{text}");
        assert!(!event.has_scheduling_changes(&stored), "{event}");
    }

    #[test]
    fn owner_copies_do_not_accumulate_components() {
        let stored = parse(EVENT);
        let mut event = stored.clone();
        let components = event.components.len();

        for color in ["blue", "red", "green", "azure"] {
            let mut view = to_json(event.clone());
            view["entries"][0]["color"] = json!(color);
            assert!(event.copy_user_data(&from_json(&view)).is_empty());
            assert_eq!(event.components.len(), components, "{event}");
            assert!(
                event.components.iter().all(|component| component
                    .component_ids
                    .iter()
                    .all(|id| (*id as usize) < components)),
                "{event}"
            );
        }

        let text = event.to_string();
        assert!(text.contains("COLOR:azure"), "{text}");
        assert_eq!(text.matches("BEGIN:VALARM").count(), 1, "{text}");
        assert!(text.contains("Owner alarm"), "{text}");
    }

    #[test]
    fn owner_copy_reports_dropped_occurrences() {
        let stored = parse(REENCODED_EVENT);
        let mut view = to_json(stored.clone());
        view["entries"][0]["recurrenceOverrides"]["2030-06-03T09:00:00"] =
            json!({ "color": "azure" });
        let mut event = stored.clone();

        let dropped = event.copy_user_data(&from_json(&view));
        assert_eq!(
            dropped,
            [NaiveDate::from_ymd_opt(2030, 6, 3)
                .and_then(|date| date.and_hms_opt(9, 0, 0))
                .map(|date| date.and_utc().timestamp())
                .expect("valid date")]
        );
        assert!(!event.to_string().contains("COLOR:azure"), "{event}");
    }
}
