/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedCalendarEvent, ArchivedCalendarEventContent, ArchivedEventPreferences,
    CalendarEventContent, EVENT_DRAFT, EVENT_HAS_ALARMS, EventPreferences, PREF_HAS_ALERTS,
    alarm::{AlarmSource, AlarmTarget, CalendarAlarm, EventAlarmData, PersonalAlarms},
    alerts::{DefaultAlerts, DefaultAlertsResolver, ICalendarShowWithoutTime},
};
use calcard::common::timezone::Tz;
use common::{ArchivedDavName, Server};
use registry::schema::structs::Task;
use std::cmp::Ordering;
use store::{
    ValueKey,
    write::{
        Archive, ArchiveBytes, BatchBuilder, TaskId, TaskQueueClass, ValueClass, now,
        serialize::rkyv_deserialize,
    },
};
use trc::AddContext;
use types::{collection::Collection, field::CalendarEventField};

#[derive(Debug, Default)]
pub struct EventAlarmUsers {
    with_time: bool,
    is_draft: bool,
    owner: Option<EventAlarmUser>,
    sharees: Vec<EventAlarmUser>,
}

#[derive(Debug)]
struct EventAlarmUser {
    target: AlarmTarget,
    uses_defaults: bool,
    alarms: PersonalAlarms,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EventAlarms(Vec<CalendarAlarm>);

pub trait EventAlarmPreferences {
    fn account_id(&self) -> u32;

    fn uses_default_alerts(&self) -> bool;

    fn has_stored_alerts(&self) -> bool;

    fn personal_alarms(&self) -> trc::Result<PersonalAlarms>;
}

pub trait EventAlarmContent {
    type Preferences: EventAlarmPreferences;

    fn shows_without_time(&self) -> bool;

    fn user_preferences(&self, account_id: u32) -> Option<&Self::Preferences>;

    fn all_preferences(&self) -> impl Iterator<Item = &Self::Preferences>;

    fn uses_default_alerts(&self, account_id: u32) -> bool {
        self.user_preferences(account_id)
            .is_some_and(EventAlarmPreferences::uses_default_alerts)
    }
}

impl EventAlarmPreferences for EventPreferences {
    fn account_id(&self) -> u32 {
        self.account_id
    }

    fn uses_default_alerts(&self) -> bool {
        EventPreferences::use_default_alerts(self)
    }

    fn has_stored_alerts(&self) -> bool {
        self.instances
            .iter()
            .any(|instance| instance.flags & PREF_HAS_ALERTS != 0)
    }

    fn personal_alarms(&self) -> trc::Result<PersonalAlarms> {
        Ok(PersonalAlarms::new(self))
    }
}

impl EventAlarmPreferences for ArchivedEventPreferences {
    fn account_id(&self) -> u32 {
        self.account_id.to_native()
    }

    fn uses_default_alerts(&self) -> bool {
        ArchivedEventPreferences::use_default_alerts(self)
    }

    fn has_stored_alerts(&self) -> bool {
        self.instances
            .iter()
            .any(|instance| instance.flags & PREF_HAS_ALERTS != 0)
    }

    fn personal_alarms(&self) -> trc::Result<PersonalAlarms> {
        rkyv_deserialize::<_, EventPreferences>(self)
            .caused_by(trc::location!())
            .map(|preferences| PersonalAlarms::new(&preferences))
    }
}

impl EventAlarmContent for CalendarEventContent {
    type Preferences = EventPreferences;

    fn shows_without_time(&self) -> bool {
        self.data.event.shows_without_time()
    }

    fn user_preferences(&self, account_id: u32) -> Option<&Self::Preferences> {
        self.preferences(account_id)
    }

    fn all_preferences(&self) -> impl Iterator<Item = &Self::Preferences> {
        self.preferences.iter()
    }
}

impl EventAlarmContent for ArchivedCalendarEventContent {
    type Preferences = ArchivedEventPreferences;

    fn shows_without_time(&self) -> bool {
        self.data.event.shows_without_time()
    }

    fn user_preferences(&self, account_id: u32) -> Option<&Self::Preferences> {
        self.preferences(account_id)
    }

    fn all_preferences(&self) -> impl Iterator<Item = &Self::Preferences> {
        self.preferences.iter()
    }
}

impl EventAlarmUser {
    fn owner<C: EventAlarmContent>(account_id: u32, content: &C) -> Self {
        EventAlarmUser {
            target: AlarmTarget::Owner,
            uses_defaults: content.uses_default_alerts(account_id),
            alarms: PersonalAlarms::default(),
        }
    }

    fn has_alarms(&self) -> bool {
        match self.target {
            AlarmTarget::Owner => true,
            AlarmTarget::Sharee(_) => self.uses_defaults || !self.alarms.is_empty(),
        }
    }

    fn source<'x>(&'x self, defaults: &'x DefaultAlerts) -> AlarmSource<'x> {
        match self.target {
            AlarmTarget::Owner => AlarmSource::Stored(defaults),
            AlarmTarget::Sharee(_) => AlarmSource::Personal(&self.alarms, defaults),
        }
    }
}

impl EventAlarmUsers {
    pub fn new<C: EventAlarmContent>(account_id: u32, content: &C) -> trc::Result<Self> {
        let mut sharees = Vec::new();
        for preferences in content
            .all_preferences()
            .filter(|preferences| sharee_has_alerts(account_id, *preferences))
        {
            let sharee = EventAlarmUser {
                target: AlarmTarget::Sharee(preferences.account_id()),
                uses_defaults: preferences.uses_default_alerts(),
                alarms: preferences.personal_alarms()?,
            };
            if sharee.has_alarms() {
                sharees.push(sharee);
            }
        }
        sharees.sort_unstable_by_key(|sharee| sharee.target);

        Ok(EventAlarmUsers {
            with_time: !content.shows_without_time(),
            is_draft: false,
            owner: Some(EventAlarmUser::owner(account_id, content)),
            sharees,
        })
    }

    pub fn for_target<C: EventAlarmContent>(
        account_id: u32,
        content: &C,
        target: AlarmTarget,
    ) -> trc::Result<Self> {
        let mut users = EventAlarmUsers {
            with_time: !content.shows_without_time(),
            is_draft: false,
            owner: None,
            sharees: Vec::new(),
        };
        match target {
            AlarmTarget::Owner => {
                users.owner = Some(EventAlarmUser::owner(account_id, content));
            }
            AlarmTarget::Sharee(sharee_id) => {
                if let Some(preferences) = content
                    .user_preferences(sharee_id)
                    .filter(|preferences| sharee_has_alerts(account_id, *preferences))
                {
                    let sharee = EventAlarmUser {
                        target,
                        uses_defaults: preferences.uses_default_alerts(),
                        alarms: preferences.personal_alarms()?,
                    };
                    if sharee.has_alarms() {
                        users.sharees.push(sharee);
                    }
                }
            }
        }

        Ok(users)
    }

    fn users(&self) -> impl Iterator<Item = &EventAlarmUser> {
        self.owner.iter().chain(self.sharees.iter())
    }

    fn is_empty(&self) -> bool {
        self.owner.is_none() && self.sharees.is_empty()
    }

    pub fn targets<C: EventAlarmContent>(
        account_id: u32,
        content: &C,
    ) -> impl Iterator<Item = AlarmTarget> {
        std::iter::once(AlarmTarget::Owner).chain(
            content
                .all_preferences()
                .filter(move |preferences| sharee_has_alerts(account_id, *preferences))
                .map(|preferences| AlarmTarget::Sharee(preferences.account_id())),
        )
    }

    pub fn with_event_flags(mut self, flags: u16) -> Self {
        self.is_draft = flags & EVENT_DRAFT != 0;
        self
    }
}

fn sharee_has_alerts<P: EventAlarmPreferences>(account_id: u32, preferences: &P) -> bool {
    preferences.account_id() != account_id
        && (preferences.uses_default_alerts() || preferences.has_stored_alerts())
}

impl EventAlarms {
    pub fn into_alarm(mut self) -> Option<CalendarAlarm> {
        self.0.pop()
    }
}

impl IntoIterator for EventAlarms {
    type Item = CalendarAlarm;
    type IntoIter = std::vec::IntoIter<CalendarAlarm>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub trait EventAlarmScheduler: Sync + Send {
    fn next_event_alarms<D: EventAlarmData + Sync>(
        &self,
        account_id: u32,
        users: &EventAlarmUsers,
        data: &D,
        calendar_ids: &[u32],
        start_time: i64,
        resolver: &mut DefaultAlertsResolver,
    ) -> impl Future<Output = trc::Result<EventAlarms>> + Send;

    fn reschedule_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        event: &ArchivedCalendarEvent,
        calendar_ids: &[u32],
        resolver: &mut DefaultAlertsResolver,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn replace_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        previous: EventAlarms,
        next: EventAlarms,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn replace_user_alarm(
        &self,
        account_id: u32,
        document_id: u32,
        previous: Option<CalendarAlarm>,
        next: Option<CalendarAlarm>,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    fn clear_event_alarms<T>(
        &self,
        account_id: u32,
        document_id: u32,
        targets: T,
        batch: &mut BatchBuilder,
    ) -> impl Future<Output = trc::Result<()>> + Send
    where
        T: IntoIterator<Item = AlarmTarget> + Send,
        T::IntoIter: Send;

    fn queued_alarm_due(
        &self,
        account_id: u32,
        document_id: u32,
        target: AlarmTarget,
    ) -> impl Future<Output = trc::Result<Option<u64>>> + Send;
}

impl EventAlarmScheduler for Server {
    async fn next_event_alarms<D: EventAlarmData + Sync>(
        &self,
        account_id: u32,
        users: &EventAlarmUsers,
        data: &D,
        calendar_ids: &[u32],
        start_time: i64,
        resolver: &mut DefaultAlertsResolver,
    ) -> trc::Result<EventAlarms> {
        if !self.core.groupware.alarms_enabled || users.is_draft || users.is_empty() {
            return Ok(EventAlarms::default());
        }

        let mut alarms = Vec::new();
        for user in users.users() {
            let target_id = user.target.account_id(account_id);
            if !resolver
                .is_subscribed(self, account_id, target_id, calendar_ids.iter().copied())
                .await?
            {
                continue;
            }
            let defaults = resolver
                .resolve(
                    self,
                    account_id,
                    target_id,
                    user.uses_defaults,
                    calendar_ids.iter().copied(),
                    users.with_time,
                )
                .await?;
            let source = user.source(&defaults);
            let default_tz = if data.needs_default_tz(&source) {
                resolver
                    .time_zone(self, account_id, target_id, calendar_ids.iter().copied())
                    .await?
            } else {
                Tz::Floating
            };
            if let Some(alarm) = data.next_alarm_from(start_time, default_tz, &source) {
                alarms.push(alarm.with_target(user.target));
            }
        }

        Ok(EventAlarms(alarms))
    }

    async fn replace_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        previous: EventAlarms,
        next: EventAlarms,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if previous == next {
            return Ok(());
        }

        let mut previous = previous.0.into_iter().peekable();
        let mut next = next.0.into_iter().peekable();
        loop {
            let (previous_alarm, next_alarm) = match (previous.peek(), next.peek()) {
                (Some(previous_alarm), Some(next_alarm)) => {
                    match previous_alarm.target.cmp(&next_alarm.target) {
                        Ordering::Equal => (previous.next(), next.next()),
                        Ordering::Less => (previous.next(), None),
                        Ordering::Greater => (None, next.next()),
                    }
                }
                (Some(_), None) => (previous.next(), None),
                (None, Some(_)) => (None, next.next()),
                (None, None) => break,
            };
            self.replace_user_alarm(account_id, document_id, previous_alarm, next_alarm, batch)
                .await?;
        }

        Ok(())
    }

    async fn replace_user_alarm(
        &self,
        account_id: u32,
        document_id: u32,
        previous: Option<CalendarAlarm>,
        next: Option<CalendarAlarm>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if previous == next {
            return Ok(());
        }
        let Some(target) = next
            .as_ref()
            .or(previous.as_ref())
            .map(|alarm| alarm.target)
        else {
            return Ok(());
        };

        let queued_due = self
            .queued_alarm_due(account_id, document_id, target)
            .await?
            .or_else(|| previous.map(|previous| previous.alarm_time as u64));
        batch
            .with_account_id(account_id)
            .with_collection(Collection::CalendarEvent)
            .with_document(document_id);
        if let Some(due) = queued_due {
            batch.clear_document_task(target.task_id(), due);
        }
        if let Some(next) = next {
            next.write_task(batch);
        }

        Ok(())
    }

    async fn clear_event_alarms<T>(
        &self,
        account_id: u32,
        document_id: u32,
        targets: T,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()>
    where
        T: IntoIterator<Item = AlarmTarget> + Send,
        T::IntoIter: Send,
    {
        for target in targets {
            if let Some(due) = self
                .queued_alarm_due(account_id, document_id, target)
                .await?
            {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::CalendarEvent)
                    .with_document(document_id)
                    .clear_document_task(target.task_id(), due);
            }
        }

        Ok(())
    }

    async fn queued_alarm_due(
        &self,
        account_id: u32,
        document_id: u32,
        target: AlarmTarget,
    ) -> trc::Result<Option<u64>> {
        self.store()
            .get_value::<Task>(ValueKey::from(ValueClass::TaskQueue(
                TaskQueueClass::Task {
                    id: TaskId::Assigned(target.task_id().resolve(account_id, document_id)),
                },
            )))
            .await
            .map(|task| task.map(|task| task.due_timestamp()))
            .caused_by(trc::location!())
    }

    async fn reschedule_event_alarms(
        &self,
        account_id: u32,
        document_id: u32,
        event: &ArchivedCalendarEvent,
        calendar_ids: &[u32],
        resolver: &mut DefaultAlertsResolver,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        if event.flags.to_native() & EVENT_HAS_ALARMS == 0 {
            return Ok(());
        }
        let Some(content) = self
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
            return Ok(());
        };
        let content = content
            .unarchive::<CalendarEventContent>()
            .caused_by(trc::location!())?;
        let users =
            EventAlarmUsers::new(account_id, content)?.with_event_flags(event.flags.to_native());
        let now = now() as i64;
        let previous_alarms = self
            .next_event_alarms(
                account_id,
                &users,
                &content.data,
                &event
                    .names
                    .iter()
                    .map(ArchivedDavName::parent_id)
                    .collect::<Vec<_>>(),
                now,
                resolver,
            )
            .await?;
        let next_alarms = self
            .next_event_alarms(
                account_id,
                &users,
                &content.data,
                calendar_ids,
                now,
                resolver,
            )
            .await?;

        self.replace_event_alarms(account_id, document_id, previous_alarms, next_alarms, batch)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::id::Id;

    #[test]
    fn draft_flag_is_tracked() {
        let users = EventAlarmUsers::default().with_event_flags(EVENT_DRAFT | EVENT_HAS_ALARMS);
        assert!(users.is_draft);
        assert!(
            !EventAlarmUsers::default()
                .with_event_flags(EVENT_HAS_ALARMS)
                .is_draft
        );
    }

    #[test]
    fn users_are_selected_per_target() {
        let content = CalendarEventContent {
            preferences: vec![
                user_preferences(1, true),
                user_preferences(2, true),
                user_preferences(3, false),
            ],
            ..Default::default()
        };

        assert_eq!(
            EventAlarmUsers::targets(1, &content).collect::<Vec<_>>(),
            vec![AlarmTarget::Owner, AlarmTarget::Sharee(2)]
        );
        assert_eq!(
            EventAlarmUsers::new(1, &content)
                .expect("users")
                .users()
                .map(|user| user.target)
                .collect::<Vec<_>>(),
            vec![AlarmTarget::Owner, AlarmTarget::Sharee(2)]
        );
        for (target, expected) in [
            (AlarmTarget::Owner, vec![AlarmTarget::Owner]),
            (AlarmTarget::Sharee(2), vec![AlarmTarget::Sharee(2)]),
            (AlarmTarget::Sharee(3), vec![]),
            (AlarmTarget::Sharee(9), vec![]),
        ] {
            assert_eq!(
                EventAlarmUsers::for_target(1, &content, target)
                    .expect("users")
                    .users()
                    .map(|user| user.target)
                    .collect::<Vec<_>>(),
                expected,
                "target {target:?}"
            );
        }
    }

    fn user_preferences(account_id: u32, use_default_alerts: bool) -> EventPreferences {
        let mut preferences = EventPreferences {
            account_id,
            ..Default::default()
        };
        preferences
            .set_use_default_alerts(use_default_alerts)
            .expect("preferences");
        preferences
    }

    #[test]
    fn per_user_task_ids_are_distinct() {
        let owner = AlarmTarget::Owner.task_id().resolve(7, 42);
        let sharee = AlarmTarget::Sharee(9).task_id().resolve(7, 42);
        let other_sharee = AlarmTarget::Sharee(10).task_id().resolve(7, 42);
        let other_document = AlarmTarget::Sharee(9).task_id().resolve(7, 43);

        assert_ne!(owner, sharee);
        assert_ne!(sharee, other_sharee);
        assert_ne!(sharee, other_document);
        assert_eq!(sharee, AlarmTarget::Sharee(9).task_id().resolve(7, 42));
        assert_eq!(owner, Id::from_parts(7, 42).id());
        assert_ne!(sharee & (1 << 63), 0);
    }
}
