/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    CalendarEventContent, EVENT_DRAFT, EVENT_HIDE_ATTENDEES, EVENT_INVITE_OTHERS,
    EVENT_INVITE_SELF,
    identity::{CalendarAddresses, EventOwnership},
};
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendar, ICalendarPeriod, ICalendarProperty, ICalendarValue},
    jscalendar::{JSCalendar, JSCalendarParticipantRole, JSCalendarProperty, JSCalendarValue},
};
use common::{GroupwareResources, Server, auth::AccessToken};
use jmap_tools::{JsonPointerItem, Key, Map, Value};
use std::{borrow::Cow, str::FromStr};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{acl::Acl, blob::BlobId, collection::Collection, field::CalendarEventField, id::Id};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRightsError {
    ModifyEvent,
    ModifyPersonalProperties,
    Reply,
    InviteSelf,
    InviteOthers,
}

impl EventRightsError {
    pub fn description(self) -> &'static str {
        match self {
            EventRightsError::ModifyEvent => "You are not allowed to modify this event.",
            EventRightsError::ModifyPersonalProperties => {
                "You are not allowed to modify personal properties of this event."
            }
            EventRightsError::Reply => "You are not allowed to reply to this event.",
            EventRightsError::InviteSelf => "You are not allowed to add yourself to this event.",
            EventRightsError::InviteOthers => "You are not allowed to invite others to this event.",
        }
    }
}

type EventKey<'x> = Key<'x, JSCalendarProperty<Id>>;
type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type MemberChange<'a, 'x> = (
    &'a EventKey<'x>,
    Option<&'a EventValue<'x>>,
    Option<&'a EventValue<'x>>,
);

const SHARED_EVENT_FLAGS: u16 =
    EVENT_DRAFT | EVENT_INVITE_SELF | EVENT_INVITE_OTHERS | EVENT_HIDE_ATTENDEES;
const VENDOR_PROPERTY_PREFIX: &str = "x-";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EventAcl {
    write_all: bool,
    write_own: bool,
    write_own_items: bool,
    update_private: bool,
    rsvp: bool,
}

impl EventAcl {
    pub fn for_calendars(
        cache: &GroupwareResources,
        access_token: &AccessToken,
        calendar_ids: impl IntoIterator<Item = u32>,
    ) -> Self {
        let mut acl: Option<EventAcl> = None;
        for calendar_id in calendar_ids {
            let calendar = EventAcl::for_calendar(cache, access_token, calendar_id);
            acl = Some(match acl {
                Some(acl) => EventAcl {
                    write_all: acl.write_all && calendar.write_all,
                    write_own: acl.write_own && calendar.write_own,
                    write_own_items: acl.write_own_items && calendar.write_own_items,
                    update_private: acl.update_private && calendar.update_private,
                    rsvp: acl.rsvp && calendar.rsvp,
                },
                None => calendar,
            });
        }
        acl.unwrap_or_default()
    }

    pub fn for_calendar(
        cache: &GroupwareResources,
        access_token: &AccessToken,
        calendar_id: u32,
    ) -> Self {
        let grants = cache.container_acl(access_token, calendar_id);
        let write_all = grants.contains(Acl::ModifyItems);
        let write_own_items = grants.contains(Acl::ModifyItemsOwn);
        EventAcl {
            write_all,
            write_own: write_all || write_own_items,
            write_own_items,
            update_private: write_all || grants.contains(Acl::ModifyPrivateProperties),
            rsvp: write_all || grants.contains(Acl::ModifyRSVP),
        }
    }

    pub fn has_any_write(&self) -> bool {
        self.write_all || self.write_own || self.update_private || self.rsvp
    }

    pub fn may_manage_own_items(&self) -> bool {
        self.write_own_items
    }

    pub fn may_write(&self, ownership: EventOwnership) -> bool {
        self.write_all || (self.write_own && ownership.may_write_own())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EventChanges {
    flags: u8,
}

impl EventChanges {
    const PER_USER: u8 = 1;
    const RSVP: u8 = 1 << 1;
    const INVITE_SELF: u8 = 1 << 2;
    const INVITE_OTHERS: u8 = 1 << 3;
    const INVITE_OTHERS_UNLISTED: u8 = 1 << 4;
    const OTHER: u8 = 1 << 5;
    const VENDOR: u8 = 1 << 6;

    pub fn between<'x>(
        before: &JSCalendar<'x, Id, BlobId>,
        after: &JSCalendar<'x, Id, BlobId>,
        before_flags: u16,
        after_flags: u16,
        identities: &CalendarAddresses,
    ) -> Self {
        let mut changes = EventChanges::default();
        if (before_flags ^ after_flags) & SHARED_EVENT_FLAGS != 0 {
            changes.insert(EventChanges::OTHER);
        }
        match (before.0.as_object(), after.0.as_object()) {
            (Some(before), Some(after)) => changes.classify_group(before, after, identities),
            _ if !before.0.same_value(&after.0) => changes.insert(EventChanges::OTHER),
            _ => {}
        }
        changes
    }

    pub fn from_per_user_patch(patch: &EventValue<'_>) -> Option<Self> {
        let patch = patch.as_object()?;
        patch
            .keys()
            .all(EventChanges::is_per_user_key)
            .then(|| EventChanges {
                flags: if patch.is_empty() {
                    0
                } else {
                    EventChanges::PER_USER
                },
            })
    }

    fn is_per_user_key(key: &EventKey<'_>) -> bool {
        match key {
            Key::Property(JSCalendarProperty::Pointer(pointer)) => match pointer.as_slice() {
                [JsonPointerItem::Key(Key::Property(property)), ..] if property.is_per_user() => {
                    true
                }
                [
                    JsonPointerItem::Key(Key::Property(JSCalendarProperty::RecurrenceOverrides)),
                    _,
                    JsonPointerItem::Key(Key::Property(JSCalendarProperty::Pointer(pointer))),
                ] => matches!(
                    pointer.first(),
                    Some(JsonPointerItem::Key(Key::Property(property))) if property.is_per_user()
                ),
                [
                    JsonPointerItem::Key(Key::Property(JSCalendarProperty::RecurrenceOverrides)),
                    _,
                    JsonPointerItem::Key(Key::Property(property)),
                    ..,
                ] => property.is_per_user(),
                _ => false,
            },
            Key::Property(property) => property.is_per_user(),
            _ => false,
        }
    }

    pub fn is_per_user_only(&self) -> bool {
        self.flags & !EventChanges::PER_USER == 0
    }

    pub fn classify_recurrence_sets(&mut self, before: &ICalendar, after: &ICalendar) {
        if !self.contains(EventChanges::OTHER)
            && RecurrenceSet::new(before) != RecurrenceSet::new(after)
        {
            self.insert(EventChanges::OTHER);
        }
    }

    pub fn insert_per_user(&mut self) {
        self.insert(EventChanges::PER_USER);
    }

    pub fn is_empty(&self) -> bool {
        self.flags == 0
    }

    pub fn assert_allowed(
        &self,
        acl: &EventAcl,
        ownership: EventOwnership,
        event_flags: u16,
    ) -> Result<(), EventRightsError> {
        if acl.may_write(ownership) {
            return Ok(());
        }

        let denied = if self.is_empty() {
            (!acl.has_any_write()).then_some(EventRightsError::ModifyEvent)
        } else if self.flags & !EventChanges::VENDOR == 0 {
            (!(acl.update_private || acl.rsvp)).then_some(EventRightsError::ModifyEvent)
        } else if self.contains(EventChanges::OTHER) {
            Some(EventRightsError::ModifyEvent)
        } else if self.contains(EventChanges::PER_USER) && !acl.update_private {
            Some(EventRightsError::ModifyPersonalProperties)
        } else if self.contains(EventChanges::RSVP) && !acl.rsvp {
            Some(EventRightsError::Reply)
        } else if self.contains(EventChanges::INVITE_SELF)
            && !(acl.rsvp && event_flags & EVENT_INVITE_SELF != 0)
        {
            Some(EventRightsError::InviteSelf)
        } else if self.contains(EventChanges::INVITE_OTHERS_UNLISTED)
            || (self.contains(EventChanges::INVITE_OTHERS)
                && !(acl.rsvp && event_flags & EVENT_INVITE_OTHERS != 0))
        {
            Some(EventRightsError::InviteOthers)
        } else {
            None
        };

        denied.map_or(Ok(()), Err)
    }

    fn insert(&mut self, flag: u8) {
        self.flags |= flag;
    }

    fn contains(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    fn classify_group<'x>(
        &mut self,
        before: &EventMap<'x>,
        after: &EventMap<'x>,
        identities: &CalendarAddresses,
    ) {
        for (key, before_value, after_value) in Some(before).changes_to(Some(after)) {
            match key {
                Key::Property(
                    JSCalendarProperty::Entries
                    | JSCalendarProperty::ProdId
                    | JSCalendarProperty::Created
                    | JSCalendarProperty::Updated,
                ) => {}
                Key::Property(JSCalendarProperty::ICalendar)
                    if before_value.same_ical_value(&after_value) =>
                {
                    self.insert(EventChanges::VENDOR)
                }
                _ => self.insert(EventChanges::OTHER),
            }
        }

        let (before_entries, after_entries) = (before.entries(), after.entries());
        if before_entries.is_empty() || after_entries.is_empty() {
            if before_entries.len() != after_entries.len() {
                self.insert(EventChanges::OTHER);
            }
            return;
        }

        let mut matched = vec![false; after_entries.len()];
        for before_entry in before_entries {
            match after_entries
                .iter()
                .zip(matched.iter_mut())
                .find(|(after_entry, is_matched)| {
                    !**is_matched && before_entry.is_same_instance(after_entry)
                }) {
                Some((after_entry, is_matched)) => {
                    *is_matched = true;
                    match (before_entry.as_object(), after_entry.as_object()) {
                        (Some(before_event), Some(after_event)) => {
                            self.classify_event(before_event, after_event, identities)
                        }
                        _ if !before_entry.same_value(after_entry) => {
                            self.insert(EventChanges::OTHER)
                        }
                        _ => {}
                    }
                }
                None => self.insert(EventChanges::OTHER),
            }
        }
        if matched.contains(&false) {
            self.insert(EventChanges::OTHER);
        }
    }

    fn classify_event<'x>(
        &mut self,
        before: &EventMap<'x>,
        after: &EventMap<'x>,
        identities: &CalendarAddresses,
    ) {
        let mut classifier = ChangeClassifier {
            before,
            after,
            identities,
            is_participant: before.participants().is_some_and(|participants| {
                participants
                    .values()
                    .any(|participant| participant.is_identity(identities))
            }),
            changes: EventChanges::default(),
        };
        for (key, before_value, after_value) in Some(before).changes_to(Some(after)) {
            classifier.classify_property(key, before_value, after_value);
        }
        self.flags |= classifier.changes.flags;
    }
}

pub trait StoredEventOwnership: Sync + Send {
    fn stored_event_ownership(
        &self,
        account_id: u32,
        document_id: u32,
        identities: &CalendarAddresses,
    ) -> impl Future<Output = trc::Result<EventOwnership>> + Send;
}

impl StoredEventOwnership for Server {
    async fn stored_event_ownership(
        &self,
        account_id: u32,
        document_id: u32,
        identities: &CalendarAddresses,
    ) -> trc::Result<EventOwnership> {
        let Some(archive) = self
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
            return Ok(EventOwnership::NotOwner);
        };

        archive
            .unarchive::<CalendarEventContent>()
            .and_then(|content| rkyv_deserialize::<_, ICalendar>(&content.data.event))
            .map(|event| identities.event_ownership(&event))
            .caused_by(trc::location!())
    }
}

struct ChangeClassifier<'a, 'x> {
    before: &'a EventMap<'x>,
    after: &'a EventMap<'x>,
    identities: &'a CalendarAddresses,
    is_participant: bool,
    changes: EventChanges,
}

impl<'a, 'x> ChangeClassifier<'a, 'x> {
    fn classify_property(
        &mut self,
        key: &EventKey<'_>,
        before: Option<&EventValue<'x>>,
        after: Option<&EventValue<'x>>,
    ) {
        match key {
            Key::Property(property) if property.is_volatile() => {}
            Key::Property(JSCalendarProperty::ICalendar) => {
                self.classify_ical(before, after);
            }
            Key::Property(property) if property.is_per_user() => {
                self.changes.insert(EventChanges::PER_USER);
            }
            Key::Property(JSCalendarProperty::Participants) => {
                self.classify_participants(
                    before.and_then(Value::as_object),
                    after.and_then(Value::as_object),
                );
            }
            Key::Property(JSCalendarProperty::RecurrenceOverrides) => {
                self.classify_overrides(
                    before.and_then(Value::as_object),
                    after.and_then(Value::as_object),
                );
            }
            _ => self.changes.insert(EventChanges::OTHER),
        }
    }

    fn classify_ical(&mut self, before: Option<&EventValue<'x>>, after: Option<&EventValue<'x>>) {
        self.changes.insert(if before.same_ical_value(&after) {
            EventChanges::VENDOR
        } else {
            EventChanges::OTHER
        });
    }

    fn classify_participants(
        &mut self,
        before: Option<&EventMap<'x>>,
        after: Option<&EventMap<'x>>,
    ) {
        for (_, before_participant, after_participant) in before.changes_to(after) {
            match (before_participant, after_participant) {
                (Some(before_participant), Some(after_participant)) => {
                    self.classify_participant_change(before_participant, after_participant)
                }
                (None, Some(after_participant)) => self.classify_new_participant(after_participant),
                _ => self.changes.insert(EventChanges::OTHER),
            }
        }
    }

    fn classify_participant_change(&mut self, before: &EventValue<'x>, after: &EventValue<'x>) {
        let changes_rsvp_only = match (before.as_object(), after.as_object()) {
            (Some(before_map), Some(after_map)) => Some(before_map)
                .changes_to(Some(after_map))
                .all(|(key, _, _)| matches!(key, Key::Property(property) if property.is_rsvp())),
            _ => false,
        };

        if changes_rsvp_only && before.is_identity(self.identities) {
            self.changes.insert(EventChanges::RSVP);
        } else {
            self.changes.insert(EventChanges::OTHER);
        }
    }

    fn classify_new_participant(&mut self, participant: &EventValue<'x>) {
        let is_attendee_only =
            match participant.as_object_and_get(&Key::Property(JSCalendarProperty::Roles)) {
                None => true,
                Some(Value::Object(roles)) => {
                    roles.len() == 1
                        && roles.get(&Key::Property(JSCalendarProperty::ParticipantRole(
                            JSCalendarParticipantRole::Attendee,
                        ))) == Some(&Value::Bool(true))
                }
                Some(_) => false,
            };

        self.changes.insert(if !is_attendee_only {
            EventChanges::OTHER
        } else if participant.is_identity(self.identities) {
            EventChanges::INVITE_SELF
        } else if self.is_participant {
            EventChanges::INVITE_OTHERS
        } else {
            EventChanges::INVITE_OTHERS_UNLISTED
        });
    }

    fn classify_overrides(&mut self, before: Option<&EventMap<'x>>, after: Option<&EventMap<'x>>) {
        let empty = EventMap::new();

        for (_, before_value, after_value) in before.changes_to(after) {
            let (Some(before_patch), Some(after_patch)) = (
                before_value.map_or(Some(&empty), Value::as_object),
                after_value.map_or(Some(&empty), Value::as_object),
            ) else {
                self.changes.insert(EventChanges::OTHER);
                continue;
            };
            if (before_value.is_none() && after_patch.is_empty())
                || (after_value.is_none() && before_patch.is_empty())
            {
                self.changes.insert(EventChanges::OTHER);
                continue;
            }

            for (entry_key, before_entry, after_entry) in
                Some(before_patch).changes_to(Some(after_patch))
            {
                self.classify_override_entry(entry_key, before_entry, after_entry);
            }
        }
    }

    fn classify_override_entry(
        &mut self,
        key: &EventKey<'_>,
        before: Option<&EventValue<'x>>,
        after: Option<&EventValue<'x>>,
    ) {
        match key {
            Key::Property(JSCalendarProperty::Pointer(pointer)) => {
                self.classify_override_pointer(pointer.as_slice(), before, after)
            }
            Key::Property(JSCalendarProperty::Participants) => {
                let base = self.after.participants();
                self.classify_participants(
                    before.and_then(Value::as_object).or(base),
                    after.and_then(Value::as_object).or(base),
                );
            }
            Key::Property(JSCalendarProperty::ICalendar) => {
                self.classify_ical(before, after);
            }
            Key::Property(property) if property.is_volatile() => {}
            Key::Property(property) if property.is_per_user() => {
                self.changes.insert(EventChanges::PER_USER);
            }
            _ => self.changes.insert(EventChanges::OTHER),
        }
    }

    fn classify_override_pointer(
        &mut self,
        pointer: &[JsonPointerItem<JSCalendarProperty<Id>>],
        before: Option<&EventValue<'x>>,
        after: Option<&EventValue<'x>>,
    ) {
        match pointer {
            [JsonPointerItem::Key(Key::Property(property)), ..] if property.is_volatile() => {}
            [JsonPointerItem::Key(Key::Property(property)), ..] if property.is_per_user() => {
                self.changes.insert(EventChanges::PER_USER);
            }
            [
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
                id,
            ] => {
                let Some(id) = id.as_member_key() else {
                    self.changes.insert(EventChanges::OTHER);
                    return;
                };
                let base = self.base_participant(&id);
                match (before.filter(|value| value.as_object().is_some()), after) {
                    (before, Some(after)) if after.as_object().is_some() => match before.or(base) {
                        Some(before) => self.classify_participant_change(before, after),
                        None => self.classify_new_participant(after),
                    },
                    (Some(before), None) => match base {
                        Some(base) => self.classify_participant_change(before, base),
                        None => self.changes.insert(EventChanges::OTHER),
                    },
                    _ => self.changes.insert(EventChanges::OTHER),
                }
            }
            [
                JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
                id,
                JsonPointerItem::Key(Key::Property(property)),
            ] if property.is_rsvp()
                && id
                    .as_member_key()
                    .and_then(|id| self.base_participant(&id))
                    .is_some_and(|participant| participant.is_identity(self.identities)) =>
            {
                self.changes.insert(EventChanges::RSVP);
            }
            _ => self.changes.insert(EventChanges::OTHER),
        }
    }

    fn base_participant(&self, id: &EventKey<'_>) -> Option<&'a EventValue<'x>> {
        self.after
            .participants()
            .and_then(|participants| participants.get(id))
            .or_else(|| {
                self.before
                    .participants()
                    .and_then(|participants| participants.get(id))
            })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RecurrenceSet {
    dates: Vec<i64>,
    exclusions: Vec<i64>,
}

impl RecurrenceSet {
    fn new(ical: &ICalendar) -> Self {
        let mut set = RecurrenceSet::default();
        let mut resolver = None;
        for entry in ical
            .components
            .iter()
            .filter(|component| {
                component.component_type.is_scheduling_object()
                    && !component.is_recurrence_override()
            })
            .flat_map(|component| component.entries.iter())
        {
            let dates = match entry.name {
                ICalendarProperty::Rdate => &mut set.dates,
                ICalendarProperty::Exdate => &mut set.exclusions,
                _ => continue,
            };
            let tz = resolver
                .get_or_insert_with(|| ical.build_tz_resolver())
                .resolve_or_default(entry.tz_id());
            dates.extend(
                entry
                    .values
                    .iter()
                    .filter_map(|value| match value {
                        ICalendarValue::PartialDateTime(date_time) => Some(date_time.as_ref()),
                        ICalendarValue::Period(
                            ICalendarPeriod::Range { start, .. }
                            | ICalendarPeriod::Duration { start, .. },
                        ) => Some(start),
                        _ => None,
                    })
                    .filter_map(|date_time| date_time.to_date_time_with_tz(tz))
                    .map(|date_time| date_time.timestamp()),
            );
        }
        for dates in [&mut set.dates, &mut set.exclusions] {
            dates.sort_unstable();
            dates.dedup();
        }
        set
    }
}

trait EventMembers<'a, 'x> {
    fn changes_to(
        self,
        after: Option<&'a EventMap<'x>>,
    ) -> impl Iterator<Item = MemberChange<'a, 'x>>;
}

impl<'a, 'x> EventMembers<'a, 'x> for Option<&'a EventMap<'x>> {
    fn changes_to(
        self,
        after: Option<&'a EventMap<'x>>,
    ) -> impl Iterator<Item = MemberChange<'a, 'x>> {
        self.into_iter()
            .flat_map(|before| before.iter())
            .map(move |(key, value)| (key, Some(value), after.and_then(|after| after.get(key))))
            .chain(
                after
                    .into_iter()
                    .flat_map(|after| after.iter())
                    .filter(move |(key, _)| self.is_none_or(|before| !before.contains_key(key)))
                    .map(|(key, value)| (key, None, Some(value))),
            )
            .filter(|(_, before, after)| !before.same_value(after))
    }
}

trait EventObject<'x> {
    fn entries(&self) -> &[EventValue<'x>];

    fn participants(&self) -> Option<&EventMap<'x>>;
}

impl<'x> EventObject<'x> for EventMap<'x> {
    fn entries(&self) -> &[EventValue<'x>] {
        self.get(&Key::Property(JSCalendarProperty::Entries))
            .and_then(Value::as_array)
            .unwrap_or_default()
    }

    fn participants(&self) -> Option<&EventMap<'x>> {
        self.get(&Key::Property(JSCalendarProperty::Participants))
            .and_then(Value::as_object)
    }
}

trait EventValueCompare {
    fn same_value(&self, other: &Self) -> bool;
}

impl EventValueCompare for EventValue<'_> {
    fn same_value(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Object(before), Value::Object(after)) => {
                before.len() == after.len()
                    && before.iter().all(|(key, before)| {
                        after.get(key).is_some_and(|after| before.same_value(after))
                    })
            }
            (Value::Array(before), Value::Array(after)) => {
                before.len() == after.len()
                    && before
                        .iter()
                        .zip(after)
                        .all(|(before, after)| before.same_value(after))
            }
            _ => self == other,
        }
    }
}

impl EventValueCompare for Option<&EventValue<'_>> {
    fn same_value(&self, other: &Self) -> bool {
        match (self, other) {
            (Some(before), Some(after)) => before.same_value(after),
            (before, after) => before.is_none() && after.is_none(),
        }
    }
}

trait ICalendarCompare {
    fn same_ical_value(&self, other: &Self) -> bool;
}

impl ICalendarCompare for Option<&EventValue<'_>> {
    fn same_ical_value(&self, other: &Self) -> bool {
        match (self, other) {
            (None | Some(Value::Null), None | Some(Value::Null)) => true,
            (Some(Value::Object(before)), None | Some(Value::Null)) => {
                before.same_ical_value(&EventMap::new())
            }
            (None | Some(Value::Null), Some(Value::Object(after))) => {
                EventMap::new().same_ical_value(after)
            }
            (Some(Value::Object(before)), Some(Value::Object(after))) => {
                before.same_ical_value(after)
            }
            _ => self.same_value(other),
        }
    }
}

impl ICalendarCompare for EventMap<'_> {
    fn same_ical_value(&self, other: &Self) -> bool {
        Some(self)
            .changes_to(Some(other))
            .all(|(key, before, after)| match key {
                Key::Property(JSCalendarProperty::Name) => before.is_none() || after.is_none(),
                Key::Property(JSCalendarProperty::Properties) => before
                    .and_then(Value::as_array)
                    .unwrap_or_default()
                    .same_properties(after.and_then(Value::as_array).unwrap_or_default()),
                Key::Property(JSCalendarProperty::Components) => before
                    .and_then(Value::as_array)
                    .unwrap_or_default()
                    .same_components(after.and_then(Value::as_array).unwrap_or_default()),
                _ => false,
            })
    }
}

trait ICalendarList {
    fn same_properties(&self, other: &Self) -> bool;

    fn same_components(&self, other: &Self) -> bool;
}

impl ICalendarList for [EventValue<'_>] {
    fn same_properties(&self, other: &Self) -> bool {
        let mut before = self
            .iter()
            .filter(|property| !property.is_volatile_ical_property());
        let mut after = other
            .iter()
            .filter(|property| !property.is_volatile_ical_property());
        loop {
            match (before.next(), after.next()) {
                (Some(before), Some(after)) if before.same_value(after) => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    fn same_components(&self, other: &Self) -> bool {
        let mut before = self
            .iter()
            .filter(|component| !component.is_iana_timezone());
        let mut after = other
            .iter()
            .filter(|component| !component.is_iana_timezone());
        loop {
            match (before.next(), after.next()) {
                (Some(before), Some(after)) if before.same_ical_component(after) => {}
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

trait ICalendarComponentValue {
    fn same_ical_component(&self, other: &Self) -> bool;

    fn is_iana_timezone(&self) -> bool;
}

impl ICalendarComponentValue for EventValue<'_> {
    fn same_ical_component(&self, other: &Self) -> bool {
        match (self.as_array(), other.as_array()) {
            (
                Some([before_name, before_properties, before_components]),
                Some([after_name, after_properties, after_components]),
            ) => {
                before_name.same_value(after_name)
                    && before_properties
                        .as_array()
                        .unwrap_or_default()
                        .same_properties(after_properties.as_array().unwrap_or_default())
                    && before_components
                        .as_array()
                        .unwrap_or_default()
                        .same_components(after_components.as_array().unwrap_or_default())
            }
            _ => self.same_value(other),
        }
    }

    fn is_iana_timezone(&self) -> bool {
        matches!(
            self.as_array(),
            Some([Value::Str(name), Value::Array(properties), ..])
                if name.eq_ignore_ascii_case("vtimezone")
                    && properties.iter().any(|property| matches!(
                        property.as_array(),
                        Some([Value::Str(property), _, _, Value::Str(tz_id), ..])
                            if property.eq_ignore_ascii_case("tzid")
                                && Tz::from_str(tz_id).is_ok()
                    ))
        )
    }
}

trait EventValueProperties {
    fn is_identity(&self, identities: &CalendarAddresses) -> bool;

    fn is_same_instance(&self, other: &Self) -> bool;

    fn is_volatile_ical_property(&self) -> bool;
}

impl EventValueProperties for EventValue<'_> {
    fn is_identity(&self, identities: &CalendarAddresses) -> bool {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::CalendarAddress))
            .and_then(Value::as_str)
            .is_some_and(|address| identities.contains(&address))
    }

    fn is_same_instance(&self, other: &Self) -> bool {
        [JSCalendarProperty::Uid, JSCalendarProperty::RecurrenceId]
            .into_iter()
            .map(Key::Property)
            .all(|key| {
                self.as_object_and_get(&key)
                    .same_value(&other.as_object_and_get(&key))
            })
    }

    fn is_volatile_ical_property(&self) -> bool {
        self.as_array()
            .and_then(|items| items.first())
            .and_then(Value::as_str)
            .is_some_and(|name| {
                name.get(..2)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(VENDOR_PROPERTY_PREFIX))
                    || hashify::tiny_set_ignore_case!(
                        name.as_bytes(),
                        "dtstamp",
                        "last-modified",
                        "created"
                    )
            })
    }
}

trait MemberKey {
    fn as_member_key(&self) -> Option<Cow<'_, EventKey<'static>>>;
}

impl MemberKey for JsonPointerItem<JSCalendarProperty<Id>> {
    fn as_member_key(&self) -> Option<Cow<'_, EventKey<'static>>> {
        match self {
            JsonPointerItem::Key(key) => Some(Cow::Borrowed(key)),
            JsonPointerItem::Number(number) => Some(Cow::Owned(Key::Owned(number.to_string()))),
            JsonPointerItem::Root | JsonPointerItem::Wildcard | JsonPointerItem::Invalid(_) => None,
        }
    }
}

trait PropertyClass {
    fn is_per_user(&self) -> bool;

    fn is_rsvp(&self) -> bool;

    fn is_volatile(&self) -> bool;
}

impl PropertyClass for JSCalendarProperty<Id> {
    fn is_per_user(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::Keywords
                | JSCalendarProperty::Color
                | JSCalendarProperty::FreeBusyStatus
                | JSCalendarProperty::UseDefaultAlerts
                | JSCalendarProperty::Alerts
        )
    }

    fn is_rsvp(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::ParticipationStatus
                | JSCalendarProperty::ExpectReply
                | JSCalendarProperty::ScheduleSequence
                | JSCalendarProperty::ScheduleUpdated
        )
    }

    fn is_volatile(&self) -> bool {
        matches!(
            self,
            JSCalendarProperty::Updated | JSCalendarProperty::Created
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = concat!(
        "BEGIN:VEVENT\r\n",
        "UID:rights\r\n",
        "DTSTAMP:20260101T000000Z\r\n",
        "LAST-MODIFIED:20260101T000000Z\r\n",
        "DTSTART:20260601T090000Z\r\n",
        "DURATION:PT1H\r\n",
        "RRULE:FREQ=DAILY;COUNT=3\r\n",
        "SUMMARY:Standup\r\n",
        "ORGANIZER:mailto:john@example.com\r\n",
        "ATTENDEE;PARTSTAT=ACCEPTED:mailto:john@example.com\r\n",
        "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:jane@example.com\r\n",
        "END:VEVENT\r\n",
    );

    fn calendar(components: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n{components}END:VCALENDAR\r\n")
    }

    fn assert_rsvp(before: &str, after: &str) -> Result<(), EventRightsError> {
        assert_changes(
            before,
            after,
            EventAcl {
                rsvp: true,
                ..Default::default()
            },
        )
    }

    fn assert_changes(before: &str, after: &str, acl: EventAcl) -> Result<(), EventRightsError> {
        let (before, after) = (
            ICalendar::parse(before).expect("valid iCalendar"),
            ICalendar::parse(after).expect("valid iCalendar"),
        );
        let mut changes = EventChanges::between(
            &before.clone().into_jscalendar(),
            &after.clone().into_jscalendar(),
            0,
            0,
            &CalendarAddresses::from_emails(["jane@example.com"]),
        );
        changes.classify_recurrence_sets(&before, &after);
        changes.assert_allowed(&acl, EventOwnership::NotOwner, EVENT_INVITE_OTHERS)
    }

    fn assert_json_rsvp(before: &str, after: &str) -> Result<(), EventRightsError> {
        EventChanges::between(
            &JSCalendar::parse(before).expect("valid JSCalendar"),
            &JSCalendar::parse(after).expect("valid JSCalendar"),
            0,
            0,
            &CalendarAddresses::from_emails(["jane@example.com"]),
        )
        .assert_allowed(
            &EventAcl {
                rsvp: true,
                ..Default::default()
            },
            EventOwnership::NotOwner,
            EVENT_INVITE_OTHERS,
        )
    }

    #[test]
    fn replies_ignore_volatile_properties() {
        let before = calendar(MASTER);
        let after = calendar(
            &MASTER
                .replace(
                    "PARTSTAT=NEEDS-ACTION:mailto:jane",
                    "PARTSTAT=ACCEPTED:mailto:jane",
                )
                .replace("DTSTAMP:20260101T000000Z", "DTSTAMP:20260105T000000Z")
                .replace(
                    "LAST-MODIFIED:20260101T000000Z",
                    "LAST-MODIFIED:20260105T000000Z\r\nCREATED:20260105T000000Z",
                ),
        );
        assert_eq!(assert_rsvp(&before, &after), Ok(()));
        assert_eq!(
            assert_rsvp(
                &before,
                &after.replace("SUMMARY:Standup", "SUMMARY:Changed")
            ),
            Err(EventRightsError::ModifyEvent)
        );
    }

    #[test]
    fn replies_to_existing_occurrences_are_allowed() {
        let before = calendar(MASTER);
        let instance = MASTER
            .replace(
                "DTSTART:20260601T090000Z",
                "RECURRENCE-ID:20260602T090000Z\r\nDTSTART:20260602T090000Z",
            )
            .replace("RRULE:FREQ=DAILY;COUNT=3\r\n", "")
            .replace(
                "PARTSTAT=NEEDS-ACTION:mailto:jane",
                "PARTSTAT=DECLINED:mailto:jane",
            );
        assert_eq!(
            assert_rsvp(&before, &calendar(&format!("{MASTER}{instance}"))),
            Ok(())
        );
    }

    #[test]
    fn added_or_removed_occurrences_require_write_rights() {
        let with_rdate = calendar(&MASTER.replace(
            "RRULE:FREQ=DAILY;COUNT=3\r\n",
            "RRULE:FREQ=DAILY;COUNT=3\r\nRDATE:20260715T090000Z\r\n",
        ));
        let plain = calendar(MASTER);
        for (before, after) in [(&plain, &with_rdate), (&with_rdate, &plain)] {
            assert_eq!(
                assert_rsvp(before, after),
                Err(EventRightsError::ModifyEvent)
            );
        }

        let event = |overrides: &str| {
            format!(
                concat!(
                    "{{\"@type\":\"Group\",\"entries\":[{{\"@type\":\"Event\",\"uid\":\"rights\",",
                    "\"start\":\"2026-06-01T09:00:00\",\"timeZone\":\"Etc/UTC\",",
                    "\"recurrenceRule\":{{\"frequency\":\"daily\",\"count\":3}},",
                    "\"participants\":{{\"jane\":{{\"@type\":\"Participant\",",
                    "\"calendarAddress\":\"mailto:jane@example.com\"}}}}",
                    "{}}}]}}"
                ),
                overrides
            )
        };
        let plain = event("");
        for overrides in [
            ",\"recurrenceOverrides\":{\"2026-07-15T09:00:00\":{}}",
            ",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":{}}",
        ] {
            let changed = event(overrides);
            for (before, after) in [(&plain, &changed), (&changed, &plain)] {
                assert_eq!(
                    assert_json_rsvp(before, after),
                    Err(EventRightsError::ModifyEvent),
                    "{before} -> {after}"
                );
            }
        }
        assert_eq!(
            assert_json_rsvp(
                &plain,
                &event(concat!(
                    ",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":",
                    "{\"participants/jane/participationStatus\":\"declined\"}}"
                ))
            ),
            Ok(())
        );
    }

    #[test]
    fn every_component_is_compared() {
        let journal = calendar(concat!(
            "BEGIN:VJOURNAL\r\nUID:j1\r\nDTSTAMP:20260101T000000Z\r\n",
            "SUMMARY:Journal\r\nEND:VJOURNAL\r\n"
        ));
        assert_eq!(
            assert_rsvp(
                &journal,
                &journal.replace("DTSTAMP:20260101T000000Z", "DTSTAMP:20260102T000000Z")
            ),
            Ok(())
        );
        assert_eq!(
            assert_rsvp(
                &journal,
                &journal.replace("SUMMARY:Journal", "SUMMARY:Changed")
            ),
            Err(EventRightsError::ModifyEvent)
        );

        let instance = |recurrence_id: &str, start: &str| {
            MASTER
                .replace(
                    "DTSTART:20260601T090000Z",
                    &format!("RECURRENCE-ID:{recurrence_id}\r\nDTSTART:{start}"),
                )
                .replace("RRULE:FREQ=DAILY;COUNT=3\r\n", "")
        };
        let instances = calendar(&format!(
            "{}{}",
            instance("20260602T090000Z", "20260602T090000Z"),
            instance("20260603T090000Z", "20260603T090000Z")
        ));
        assert_eq!(
            assert_rsvp(
                &instances,
                &calendar(&format!(
                    "{}{}",
                    instance("20260602T090000Z", "20260602T090000Z"),
                    instance("20260603T090000Z", "20260604T090000Z")
                ))
            ),
            Err(EventRightsError::ModifyEvent)
        );

        let zoned = |offset: &str| {
            calendar(&format!(
                concat!(
                    "BEGIN:VTIMEZONE\r\nTZID:Custom Zone\r\nBEGIN:STANDARD\r\n",
                    "DTSTART:19700101T000000\r\nTZOFFSETFROM:{0}\r\nTZOFFSETTO:{0}\r\n",
                    "END:STANDARD\r\nEND:VTIMEZONE\r\n{1}"
                ),
                offset,
                MASTER.replace(
                    "DTSTART:20260601T090000Z",
                    "DTSTART;TZID=Custom Zone:20260601T090000"
                )
            ))
        };
        assert_eq!(
            assert_rsvp(&zoned("+0200"), &zoned("-0700")),
            Err(EventRightsError::ModifyEvent)
        );

        let berlin = MASTER.replace(
            "DTSTART:20260601T090000Z",
            "DTSTART;TZID=Europe/Berlin:20260601T090000",
        );
        let iana_zoned = |offset: &str| {
            calendar(&format!(
                concat!(
                    "BEGIN:VTIMEZONE\r\nTZID:Europe/Berlin\r\nBEGIN:STANDARD\r\n",
                    "DTSTART:19700101T000000\r\nTZOFFSETFROM:{0}\r\nTZOFFSETTO:{0}\r\n",
                    "END:STANDARD\r\nEND:VTIMEZONE\r\n{1}"
                ),
                offset, berlin
            ))
        };
        for after in [iana_zoned("+0200"), calendar(&berlin)] {
            assert_eq!(assert_rsvp(&iana_zoned("+0100"), &after), Ok(()));
        }
    }

    #[test]
    fn inviting_others_requires_being_a_participant() {
        let event = |participants: &str| {
            format!(
                concat!(
                    "{{\"@type\":\"Group\",\"entries\":[{{\"@type\":\"Event\",\"uid\":\"rights\",",
                    "\"participants\":{{{}}}}}]}}"
                ),
                participants
            )
        };
        let participant = |id: &str, address: &str| {
            format!(
                "\"{id}\":{{\"@type\":\"Participant\",\"calendarAddress\":\"mailto:{address}\"}}"
            )
        };
        let john = participant("john", "john@example.com");
        let jane = participant("jane", "jane@example.com");
        let bill = participant("bill", "bill@example.com");
        assert_eq!(
            assert_json_rsvp(&event(&john), &event(&format!("{john},{bill}"))),
            Err(EventRightsError::InviteOthers)
        );
        assert_eq!(
            assert_json_rsvp(
                &event(&format!("{john},{jane}")),
                &event(&format!("{john},{jane},{bill}"))
            ),
            Ok(())
        );
    }

    fn per_user_patch(patch: &str) -> Option<EventChanges> {
        EventChanges::from_per_user_patch(
            &JSCalendar::<Id, BlobId>::parse(patch)
                .expect("valid patch")
                .0,
        )
    }

    #[test]
    fn per_user_patches_are_classified_without_a_comparison() {
        for patch in [
            r#"{"color": "blue"}"#,
            r#"{"keywords/personal": true}"#,
            r#"{"freeBusyStatus": "free", "useDefaultAlerts": true}"#,
            r#"{"alerts/a1/acknowledged": "2030-06-01T09:00:00Z"}"#,
            r#"{"recurrenceOverrides/2030-06-02T09:00:00/color": "azure"}"#,
            r#"{"recurrenceOverrides/2030-06-02T09:00:00/alerts/a1/acknowledged": "2030-06-01T09:00:00Z"}"#,
            r#"{"recurrenceOverrides/2030-06-02T09:00:00/alerts~1a1~1acknowledged": "2030-06-01T09:00:00Z"}"#,
        ] {
            let changes = per_user_patch(patch).unwrap_or_else(|| panic!("{patch}"));
            assert!(changes.is_per_user_only(), "{patch}");
            assert!(!changes.is_empty(), "{patch}");
        }

        for patch in [
            r#"{"title": "Changed"}"#,
            r#"{"calendarIds/a": true}"#,
            r#"{"isDraft": false}"#,
            r#"{"recurrenceOverrides": {"2030-06-02T09:00:00": {"color": "azure"}}}"#,
            r#"{"recurrenceOverrides/2030-06-02T09:00:00": {"color": "azure"}}"#,
            r#"{"recurrenceOverrides/2030-06-02T09:00:00/title": "Changed"}"#,
            r#"{"color": "blue", "title": "Changed"}"#,
            r#"{"participants/p1/participationStatus": "accepted"}"#,
        ] {
            assert!(per_user_patch(patch).is_none(), "{patch}");
        }

        let empty = per_user_patch("{}").expect("classified");
        assert!(empty.is_empty());
        assert!(empty.is_per_user_only());
    }

    #[test]
    fn other_changes_are_not_per_user_only() {
        let mut changes = EventChanges::default();
        changes.insert_per_user();
        assert!(changes.is_per_user_only());
        changes.insert(EventChanges::RSVP);
        assert!(!changes.is_per_user_only());
    }

    #[test]
    fn vendor_properties_do_not_forbid_a_change() {
        let before = calendar(MASTER);
        let rsvp = calendar(
            &MASTER
                .replace(
                    "PARTSTAT=NEEDS-ACTION:mailto:jane",
                    "PARTSTAT=ACCEPTED:mailto:jane",
                )
                .replace(
                    "SUMMARY:Standup\r\n",
                    "SUMMARY:Standup\r\nX-MOZ-GENERATION:3\r\n",
                ),
        );
        assert_eq!(assert_rsvp(&before, &rsvp), Ok(()));

        let private_acl = EventAcl {
            update_private: true,
            ..Default::default()
        };
        let personal = calendar(&MASTER.replace(
            "SUMMARY:Standup\r\n",
            concat!(
                "SUMMARY:Standup\r\n",
                "COLOR:blue\r\n",
                "X-MOZ-LASTACK:20260601T085500Z\r\n",
                "X-MOZ-SNOOZE-TIME:20260601T090500Z\r\n"
            ),
        ));
        assert_eq!(assert_changes(&before, &personal, private_acl), Ok(()));
        assert_eq!(
            assert_changes(
                &before,
                &personal.replace("SUMMARY:Standup", "SUMMARY:Changed"),
                private_acl
            ),
            Err(EventRightsError::ModifyEvent)
        );
        assert_eq!(
            assert_rsvp(&before, &personal),
            Err(EventRightsError::ModifyPersonalProperties)
        );

        let vendor = calendar(&MASTER.replace(
            "SUMMARY:Standup\r\n",
            "SUMMARY:Standup\r\nX-MOZ-GENERATION:3\r\n",
        ));
        let (parsed_before, parsed_vendor) = (
            ICalendar::parse(&before).expect("valid iCalendar"),
            ICalendar::parse(&vendor).expect("valid iCalendar"),
        );
        let changes = EventChanges::between(
            &parsed_before.into_jscalendar(),
            &parsed_vendor.into_jscalendar(),
            0,
            0,
            &CalendarAddresses::from_emails(["jane@example.com"]),
        );
        assert!(!changes.is_per_user_only());
        assert_eq!(assert_rsvp(&before, &vendor), Ok(()));
        assert_eq!(assert_changes(&before, &vendor, private_acl), Ok(()));
        for acl in [
            EventAcl::default(),
            EventAcl {
                write_own_items: true,
                write_own: true,
                ..Default::default()
            },
        ] {
            assert_eq!(
                assert_changes(&before, &vendor, acl),
                Err(EventRightsError::ModifyEvent)
            );
        }
    }
}
