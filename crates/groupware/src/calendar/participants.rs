/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::identity::CalendarAddresses;
use calcard::{
    icalendar::{
        ArchivedICalendarEntry, ArchivedICalendarParameterValue,
        ArchivedICalendarParticipationRole, ArchivedICalendarProperty, ICalendarEntry,
        ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole,
        ICalendarProperty,
    },
    jscalendar::{JSCalendarParticipantRole, JSCalendarProperty, JSCalendarValue},
};
use jmap_tools::{JsonPointer, JsonPointerHandler, JsonPointerItem, Key, Map, Value};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

type EventKey<'x> = Key<'x, JSCalendarProperty<Id>>;
type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventPointerItem = JsonPointerItem<JSCalendarProperty<Id>>;

pub trait ParticipantVisibility {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool;
}

pub trait VisibleParticipants {
    fn retain_visible_participants(&mut self, identities: &CalendarAddresses);
}

impl ParticipantVisibility for ICalendarEntry {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool {
        self.name != ICalendarProperty::Attendee
            || self.parameters(&ICalendarParameterName::Role).any(|role| {
                matches!(
                    role,
                    ICalendarParameterValue::Role(ICalendarParticipationRole::Owner)
                )
            })
            || self
                .calendar_address()
                .is_some_and(|address| identities.contains(address))
    }
}

impl ParticipantVisibility for ArchivedICalendarEntry {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool {
        !matches!(self.name, ArchivedICalendarProperty::Attendee)
            || self.parameters(&ICalendarParameterName::Role).any(|role| {
                matches!(
                    role,
                    ArchivedICalendarParameterValue::Role(
                        ArchivedICalendarParticipationRole::Owner
                    )
                )
            })
            || self
                .values
                .first()
                .and_then(|value| value.as_text())
                .is_some_and(|address| identities.contains(address))
    }
}

impl ParticipantVisibility for EventValue<'_> {
    fn is_visible_participant(&self, identities: &CalendarAddresses) -> bool {
        self.is_owner()
            || self
                .calendar_address()
                .is_some_and(|address| identities.contains(&address))
    }
}

impl VisibleParticipants for EventValue<'_> {
    fn retain_visible_participants(&mut self, identities: &CalendarAddresses) {
        let Some(event) = self.as_object_mut() else {
            return;
        };
        let participants_key = Key::Property(JSCalendarProperty::Participants);
        let position = event
            .as_vec()
            .iter()
            .position(|(key, _)| key == &participants_key);
        let mut participants = position.map(|position| event.as_mut_vec().remove(position));
        let base = participants
            .as_ref()
            .and_then(|(_, participants)| participants.as_object());
        let base_hidden = base.map_or_else(Vec::new, |base| base.hidden_ids(identities));
        let base_visible = base.map_or_else(Vec::new, |base| base.visible_addresses(identities));

        if let Some(overrides) = event
            .get_mut(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
            .and_then(Value::as_object_mut)
        {
            overrides.as_mut_vec().retain_mut(|(_, patch)| {
                let Some(patch) = patch.as_object_mut() else {
                    return true;
                };
                let is_empty = patch.is_empty();
                patch.retain_visible_patches(base, &base_hidden, identities);
                patch.retain_visible_patch_delegations(&base_visible, identities);
                is_empty || !patch.is_empty()
            });
        }

        if let Some(ical) = event.get_mut(&Key::Property(JSCalendarProperty::ICalendar)) {
            ical.remove_participant_properties(&base_hidden);
        }

        if let (Some(position), Some((key, mut value))) = (position, participants.take()) {
            if let Some(participants) = value.as_object_mut() {
                participants.remove_hidden(identities);
                participants.retain_visible_delegations(identities);
            }
            if value
                .as_object()
                .is_none_or(|participants| !participants.is_empty())
            {
                let position = position.min(event.len());
                event.as_mut_vec().insert(position, (key, value));
            }
        }
    }
}

trait ParticipantObject {
    fn is_owner(&self) -> bool;

    fn calendar_address(&self) -> Option<Cow<'_, str>>;
}

impl ParticipantObject for EventValue<'_> {
    fn is_owner(&self) -> bool {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::Roles))
            .is_some_and(EventValue::has_owner_role)
    }

    fn calendar_address(&self) -> Option<Cow<'_, str>> {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::CalendarAddress))
            .and_then(Value::as_str)
    }
}

trait OwnerRole {
    fn has_owner_role(&self) -> bool;
}

impl OwnerRole for EventValue<'_> {
    fn has_owner_role(&self) -> bool {
        self.as_object_and_get(&Key::Property(JSCalendarProperty::ParticipantRole(
            JSCalendarParticipantRole::Owner,
        )))
        .and_then(Value::as_bool)
        .unwrap_or_default()
    }
}

trait ParticipantMap<'x> {
    fn hidden_ids(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>>;

    fn visible_addresses(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>>;

    fn retain_visible_delegations(&mut self, identities: &CalendarAddresses);

    fn remove_hidden(&mut self, identities: &CalendarAddresses);

    fn participant(&self, id: &str) -> Option<&EventValue<'x>>;
}

impl<'x> ParticipantMap<'x> for EventMap<'x> {
    fn hidden_ids(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>> {
        self.iter()
            .filter(|(_, participant)| !participant.is_visible_participant(identities))
            .map(|(key, _)| key.to_string())
            .collect()
    }

    fn visible_addresses(&self, identities: &CalendarAddresses) -> Vec<Cow<'_, str>> {
        self.iter()
            .filter(|(_, participant)| participant.is_visible_participant(identities))
            .filter_map(|(_, participant)| participant.calendar_address())
            .collect()
    }

    fn retain_visible_delegations(&mut self, identities: &CalendarAddresses) {
        if !self.values().any(EventValue::has_delegates) {
            return;
        }
        let participants = self.as_mut_vec();
        for index in 0..participants.len() {
            let (before, rest) = participants.split_at_mut(index);
            let Some(((_, participant), after)) = rest.split_first_mut() else {
                break;
            };
            participant.retain_visible_delegations(|address| {
                identities.contains(address) || {
                    let address = CalendarAddresses::normalize(address);
                    before
                        .iter()
                        .chain(after.iter())
                        .filter_map(|(_, participant)| participant.calendar_address())
                        .any(|own| CalendarAddresses::normalize(&own) == address)
                }
            });
        }
    }

    fn remove_hidden(&mut self, identities: &CalendarAddresses) {
        self.as_mut_vec()
            .retain(|(_, participant)| participant.is_visible_participant(identities));
    }

    fn participant(&self, id: &str) -> Option<&EventValue<'x>> {
        self.as_vec()
            .iter()
            .find(|(key, _)| key.to_string() == id)
            .map(|(_, participant)| participant)
    }
}

trait ParticipantDelegations {
    fn has_delegates(&self) -> bool;

    fn retain_visible_delegations(&mut self, is_visible: impl Fn(&str) -> bool + Copy);

    fn retain_visible_delegates(&mut self, is_visible: impl Fn(&str) -> bool + Copy) -> bool;
}

impl ParticipantDelegations for EventValue<'_> {
    fn has_delegates(&self) -> bool {
        self.as_object()
            .is_some_and(|participant| participant.keys().any(EventKey::is_delegation))
    }

    fn retain_visible_delegations(&mut self, is_visible: impl Fn(&str) -> bool + Copy) {
        if let Some(participant) = self.as_object_mut() {
            participant.as_mut_vec().retain_mut(|(key, value)| {
                !key.is_delegation() || value.retain_visible_delegates(is_visible)
            });
        }
    }

    fn retain_visible_delegates(&mut self, is_visible: impl Fn(&str) -> bool + Copy) -> bool {
        match self {
            Value::Str(address) => is_visible(address),
            Value::Array(addresses) => {
                addresses
                    .retain(|address| address.as_str().is_none_or(|address| is_visible(&address)));
                !addresses.is_empty()
            }
            Value::Object(addresses) => {
                addresses
                    .as_mut_vec()
                    .retain(|(address, _)| is_visible(&address.to_string()));
                !addresses.is_empty()
            }
            _ => true,
        }
    }
}

trait VisibleAddress {
    fn is_visible_address(&self, visible: &[Cow<'_, str>], identities: &CalendarAddresses) -> bool;
}

impl VisibleAddress for str {
    fn is_visible_address(&self, visible: &[Cow<'_, str>], identities: &CalendarAddresses) -> bool {
        let address = CalendarAddresses::normalize(self);
        visible
            .iter()
            .any(|visible| CalendarAddresses::normalize(visible) == address)
            || identities.contains(&address)
    }
}

trait ParticipantPatch<'x> {
    fn retain_visible_patches(
        &mut self,
        base: Option<&EventMap<'x>>,
        base_hidden: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    );

    fn retain_visible_patch_delegations(
        &mut self,
        base_visible: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    );

    fn participant_patches<'y>(
        &'y self,
        id: &'y str,
    ) -> impl Iterator<Item = (&'y [EventPointerItem], &'y EventValue<'x>)>
    where
        'x: 'y;
}

impl<'x> ParticipantPatch<'x> for EventMap<'x> {
    fn retain_visible_patches(
        &mut self,
        base: Option<&EventMap<'x>>,
        base_hidden: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    ) {
        if let Some(participants) = self.get_mut(&Key::Property(JSCalendarProperty::Participants))
            && let Some(map) = participants.as_object_mut()
        {
            map.remove_hidden(identities);
            if map.is_empty() {
                *participants = Value::Null;
            }
        }

        let mut ids = self
            .iter()
            .filter_map(|(key, _)| key.participant_pointer())
            .map(|(id, _)| id.into_owned())
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();

        let mut hidden = Cow::Borrowed(base_hidden);
        for id in ids {
            let base_participant = base.and_then(|base| base.participant(&id));
            let is_base_visible = base_participant
                .is_some_and(|participant| participant.is_visible_participant(identities));
            let replacement = self
                .participant_patches(&id)
                .find(|(pointer, _)| pointer.is_empty())
                .map(|(_, value)| value);
            let is_visible = match replacement {
                Some(replacement) => replacement.is_visible_participant(identities),
                None => base_participant.is_some_and(|participant| {
                    participant.is_patched_visible(self.participant_patches(&id), identities)
                }),
            };
            let new_patch = match (is_base_visible, is_visible) {
                (true, true) => continue,
                (false, true) if replacement.is_some() => {
                    hidden
                        .to_mut()
                        .retain(|hidden_id| hidden_id.as_ref() != id.as_str());
                    continue;
                }
                (false, true) => base_participant.map(|participant| {
                    let mut participant = participant.clone();
                    for (pointer, value) in self.participant_patches(&id) {
                        participant.patch_jptr(pointer.iter().peekable(), value.clone());
                    }
                    participant
                }),
                (true, false) => Some(Value::Null),
                (false, false) => None,
            };

            self.as_mut_vec().retain(|(key, _)| {
                key.participant_pointer()
                    .is_none_or(|(patch_id, _)| patch_id != id.as_str())
            });
            if new_patch.as_ref().is_some_and(|patch| !patch.is_null()) {
                hidden
                    .to_mut()
                    .retain(|hidden_id| hidden_id.as_ref() != id.as_str());
            } else if !hidden
                .iter()
                .any(|hidden_id| hidden_id.as_ref() == id.as_str())
            {
                hidden.to_mut().push(Cow::Owned(id.clone()));
            }
            if let Some(new_patch) = new_patch {
                self.insert_unchecked(
                    Key::Property(JSCalendarProperty::Pointer(JsonPointer::new(vec![
                        JsonPointerItem::Key(Key::Property(JSCalendarProperty::Participants)),
                        JsonPointerItem::Key(Key::Owned(id)),
                    ]))),
                    new_patch,
                );
            }
        }

        if let Some(ical) = self.get_mut(&Key::Property(JSCalendarProperty::ICalendar)) {
            ical.remove_participant_properties(&hidden);
        }
    }

    fn retain_visible_patch_delegations(
        &mut self,
        base_visible: &[Cow<'_, str>],
        identities: &CalendarAddresses,
    ) {
        let participants_key = Key::Property(JSCalendarProperty::Participants);
        if !self.iter().any(|(key, value)| {
            if key == &participants_key {
                value.as_object().is_some_and(|participants| {
                    participants.values().any(EventValue::has_delegates)
                })
            } else {
                match key.participant_pointer() {
                    Some((_, [])) => value.has_delegates(),
                    Some((_, [delegation, ..])) => delegation.is_delegation(),
                    _ => false,
                }
            }
        }) {
            return;
        }

        let mut visible = Cow::Borrowed(base_visible);
        for (key, value) in self.iter() {
            if key == &participants_key {
                if let Some(participants) = value.as_object() {
                    visible.to_mut().extend(
                        participants
                            .visible_addresses(identities)
                            .into_iter()
                            .map(|address| Cow::Owned(address.into_owned())),
                    );
                }
            } else if matches!(key.participant_pointer(), Some((_, [])))
                && value.is_visible_participant(identities)
                && let Some(address) = value.calendar_address()
            {
                visible.to_mut().push(Cow::Owned(address.into_owned()));
            }
        }

        let is_visible = |address: &str| address.is_visible_address(&visible, identities);
        self.as_mut_vec().retain_mut(|(key, value)| {
            if key == &participants_key {
                if let Some(participants) = value.as_object_mut() {
                    participants.retain_visible_delegations(identities);
                }
            } else if let Some((_, pointer)) = key.participant_pointer() {
                match pointer {
                    [] => value.retain_visible_delegations(is_visible),
                    [delegation] if delegation.is_delegation() => {
                        if !value.retain_visible_delegates(is_visible) {
                            *value = Value::Null;
                        }
                    }
                    [delegation, delegate] if delegation.is_delegation() => {
                        return delegate.as_address().is_none_or(|delegate| {
                            delegate.is_visible_address(&visible, identities)
                        });
                    }
                    _ => {}
                }
            }
            true
        });
    }

    fn participant_patches<'y>(
        &'y self,
        id: &'y str,
    ) -> impl Iterator<Item = (&'y [EventPointerItem], &'y EventValue<'x>)>
    where
        'x: 'y,
    {
        self.iter().filter_map(move |(key, value)| {
            key.participant_pointer()
                .filter(|(patch_id, _)| patch_id == id)
                .map(|(_, pointer)| (pointer, value))
        })
    }
}

trait PatchedParticipant {
    fn is_patched_visible<'a, 'v: 'a>(
        &'a self,
        patches: impl Iterator<Item = (&'a [EventPointerItem], &'a EventValue<'v>)>,
        identities: &CalendarAddresses,
    ) -> bool;
}

impl PatchedParticipant for EventValue<'_> {
    fn is_patched_visible<'a, 'v: 'a>(
        &'a self,
        patches: impl Iterator<Item = (&'a [EventPointerItem], &'a EventValue<'v>)>,
        identities: &CalendarAddresses,
    ) -> bool {
        let mut is_owner = self.is_owner();
        let mut address = self.calendar_address();

        for (pointer, value) in patches {
            match pointer {
                [roles] if roles.is_property(&JSCalendarProperty::Roles) => {
                    is_owner = value.has_owner_role();
                }
                [roles, role]
                    if roles.is_property(&JSCalendarProperty::Roles)
                        && role.is_property(&JSCalendarProperty::ParticipantRole(
                            JSCalendarParticipantRole::Owner,
                        )) =>
                {
                    is_owner = value.as_bool().unwrap_or_default();
                }
                [calendar_address]
                    if calendar_address.is_property(&JSCalendarProperty::CalendarAddress) =>
                {
                    address = value.as_str();
                }
                _ => {}
            }
        }

        is_owner || address.is_some_and(|address| identities.contains(&address))
    }
}

trait ParticipantPointer {
    fn participant_pointer(&self) -> Option<(Cow<'_, str>, &[EventPointerItem])>;
}

impl ParticipantPointer for EventKey<'_> {
    fn participant_pointer(&self) -> Option<(Cow<'_, str>, &[EventPointerItem])> {
        let Key::Property(JSCalendarProperty::Pointer(pointer)) = self else {
            return None;
        };
        match pointer.as_slice() {
            [participants, id, rest @ ..]
                if participants.is_property(&JSCalendarProperty::Participants) =>
            {
                let id = match id {
                    JsonPointerItem::Key(key) => key.to_string(),
                    JsonPointerItem::Number(number) => Cow::Owned(number.to_string()),
                    JsonPointerItem::Root
                    | JsonPointerItem::Wildcard
                    | JsonPointerItem::Invalid(_) => return None,
                };
                Some((id, rest))
            }
            _ => None,
        }
    }
}

trait PointerProperty {
    fn is_property(&self, property: &JSCalendarProperty<Id>) -> bool;

    fn as_address(&self) -> Option<Cow<'_, str>>;
}

impl PointerProperty for EventPointerItem {
    fn is_property(&self, property: &JSCalendarProperty<Id>) -> bool {
        matches!(self, JsonPointerItem::Key(Key::Property(item)) if item == property)
    }

    fn as_address(&self) -> Option<Cow<'_, str>> {
        match self {
            JsonPointerItem::Key(key) => Some(key.to_string()),
            _ => None,
        }
    }
}

trait DelegationKey {
    fn is_delegation(&self) -> bool;
}

impl DelegationKey for EventKey<'_> {
    fn is_delegation(&self) -> bool {
        matches!(
            self,
            Key::Property(JSCalendarProperty::DelegatedTo | JSCalendarProperty::DelegatedFrom)
        )
    }
}

impl DelegationKey for EventPointerItem {
    fn is_delegation(&self) -> bool {
        self.is_property(&JSCalendarProperty::DelegatedTo)
            || self.is_property(&JSCalendarProperty::DelegatedFrom)
    }
}

trait ICalendarProperties {
    fn remove_participant_properties(&mut self, hidden: &[Cow<'_, str>]);
}

impl ICalendarProperties for EventValue<'_> {
    fn remove_participant_properties(&mut self, hidden: &[Cow<'_, str>]) {
        if hidden.is_empty() {
            return;
        }
        if let Some(converted_properties) = self
            .as_object_mut()
            .and_then(|ical| ical.get_mut(&Key::Property(JSCalendarProperty::ConvertedProperties)))
            .and_then(Value::as_object_mut)
        {
            converted_properties.as_mut_vec().retain(|(key, _)| {
                key.to_string()
                    .strip_prefix("participants/")
                    .and_then(|pointer| pointer.split('/').next())
                    .is_none_or(|id| {
                        let id = if id.contains('~') {
                            Cow::Owned(id.replace("~1", "/").replace("~0", "~"))
                        } else {
                            Cow::Borrowed(id)
                        };
                        !hidden
                            .iter()
                            .any(|hidden_id| hidden_id.as_ref() == id.as_ref())
                    })
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::jscalendar::{JSCalendar, import::ImportOptions};
    use serde_json::json;

    const EVENT: &str = r#"{
  "@type": "Group",
  "entries": [{
    "@type": "Event",
    "uid": "hidden-attendees",
    "title": "Board meeting",
    "start": "2026-05-04T09:00:00",
    "timeZone": "Europe/Madrid",
    "duration": "PT1H",
    "organizerCalendarAddress": "mailto:jdoe@example.com",
    "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily", "count": 5},
    "participants": {
      "owner": {
        "@type": "Participant",
        "calendarAddress": "mailto:jdoe@example.com",
        "roles": {"owner": true, "attendee": true}
      },
      "jane": {
        "@type": "Participant",
        "calendarAddress": "mailto:jane.smith@example.com",
        "roles": {"attendee": true}
      },
      "bill": {
        "@type": "Participant",
        "name": "Bill Secret",
        "calendarAddress": "mailto:bill@example.com",
        "description": "Bill is interviewing for a job elsewhere",
        "links": {"l1": {"@type": "Link", "href": "https://example.com/bill"}},
        "roles": {"attendee": true}
      }
    },
    "recurrenceOverrides": {
      "2026-05-05T09:00:00": {
        "participants/jane/participationStatus": "accepted",
        "participants/bill/participationStatus": "declined"
      },
      "2026-05-06T09:00:00": {
        "participants/bill": null
      },
      "2026-05-07T09:00:00": {
        "participants/bill/roles/owner": true
      },
      "2026-05-08T09:00:00": {
        "participants/carol": {
          "@type": "Participant",
          "calendarAddress": "mailto:carol@example.com",
          "roles": {"attendee": true}
        },
        "participants/dave": {
          "@type": "Participant",
          "calendarAddress": "mailto:dave@example.com",
          "roles": {"owner": true}
        }
      }
    }
  }]
}"#;

    fn reduce_jscalendar(json: &str, identities: &[&str]) -> serde_json::Value {
        let mut event = JSCalendar::<Id, BlobId>::parse(json)
            .expect("valid JSCalendar")
            .into_inner();
        event.retain_visible_participants(&CalendarAddresses::from_emails(
            identities.iter().copied(),
        ));
        serde_json::to_value(&event).expect("serializable")
    }

    fn reduce_icalendar(ical: &str, identities: &[&str]) -> serde_json::Value {
        let calcard::Entry::ICalendar(ical) = calcard::Parser::new(ical).entry() else {
            panic!("failed to parse iCalendar");
        };
        let mut event = ical
            .into_jscalendar_with::<Id, BlobId, _>(
                ImportOptions::new()
                    .include_ical_components(true)
                    .return_first(true),
            )
            .expect("converts")
            .into_inner();
        event.retain_visible_participants(&CalendarAddresses::from_emails(
            identities.iter().copied(),
        ));
        serde_json::to_value(&event).expect("serializable")
    }

    fn participant_by_address<'x>(
        event: &'x serde_json::Value,
        address: &str,
    ) -> &'x serde_json::Value {
        event["participants"]
            .as_object()
            .expect("participants")
            .values()
            .find(|participant| participant["calendarAddress"] == json!(address))
            .unwrap_or_else(|| panic!("no participant for {address}: {event}"))
    }

    fn reduce(json: &str, identities: &[&str]) -> serde_json::Value {
        let ical = JSCalendar::<Id, BlobId>::parse(json)
            .expect("valid JSCalendar")
            .into_icalendar()
            .expect("iCalendar");
        let mut event = ical
            .into_jscalendar_with::<Id, BlobId, _>(
                ImportOptions::new()
                    .include_ical_components(true)
                    .return_first(true),
            )
            .expect("converts")
            .into_inner();
        event.retain_visible_participants(&CalendarAddresses::from_emails(
            identities.iter().copied(),
        ));
        serde_json::to_value(&event).expect("serializable")
    }

    #[test]
    fn hidden_participants_are_removed_from_base_and_overrides() {
        let event = reduce(EVENT, &["jane.smith@example.com"]);
        let participants = event["participants"].as_object().expect("participants");
        let mut ids = participants.keys().map(String::as_str).collect::<Vec<_>>();
        ids.sort_unstable();
        assert_eq!(ids, ["jane", "owner"]);
        assert!(
            !event["participants"]
                .to_string()
                .contains("bill@example.com"),
            "{event}"
        );
        assert!(!event.to_string().contains("carol@example.com"), "{event}");

        let overrides = &event["recurrenceOverrides"];
        for date in ["2026-05-05T09:00:00", "2026-05-08T09:00:00"] {
            assert!(
                !overrides[date].to_string().contains("bill"),
                "{date}: {event}"
            );
        }
        assert_eq!(
            overrides["2026-05-05T09:00:00"],
            json!({"participants/jane/participationStatus": "accepted"})
        );
        assert_eq!(overrides.get("2026-05-06T09:00:00"), None);
        assert_eq!(
            overrides["2026-05-07T09:00:00"]["participants/bill"]["roles"]["owner"],
            json!(true)
        );
        assert_eq!(
            overrides["2026-05-07T09:00:00"]["participants/bill"]["calendarAddress"],
            json!("mailto:bill@example.com")
        );
        assert_eq!(
            overrides["2026-05-08T09:00:00"]["participants/dave"]["calendarAddress"],
            json!("mailto:dave@example.com")
        );
        assert_eq!(
            overrides["2026-05-08T09:00:00"].get("participants/carol"),
            None
        );
    }

    #[test]
    fn participants_hidden_in_an_occurrence_are_removed_from_it() {
        let event = reduce(
            r#"{
  "@type": "Group",
  "entries": [{
    "@type": "Event",
    "uid": "moved-participant",
    "title": "Review",
    "start": "2026-05-04T09:00:00",
    "timeZone": "Europe/Madrid",
    "duration": "PT1H",
    "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily", "count": 3},
    "participants": {
      "owner": {"@type": "Participant", "calendarAddress": "mailto:jdoe@example.com", "roles": {"owner": true}},
      "jane": {"@type": "Participant", "calendarAddress": "mailto:jane.smith@example.com", "roles": {"attendee": true}}
    },
    "recurrenceOverrides": {
      "2026-05-05T09:00:00": {
        "participants": {
          "jane": {"@type": "Participant", "calendarAddress": "mailto:bill@example.com", "roles": {"attendee": true}}
        }
      }
    }
  }]
}"#,
            &["jane.smith@example.com"],
        );
        let patch = &event["recurrenceOverrides"]["2026-05-05T09:00:00"];
        assert!(!patch.to_string().contains("bill@example.com"), "{event}");
        assert!(
            patch
                .get("participants")
                .is_none_or(|value| value.is_null() || value.get("jane").is_none()),
            "{event}"
        );
    }

    #[test]
    fn converted_properties_of_hidden_participants_are_removed() {
        let ical = concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
            "BEGIN:VEVENT\r\nUID:u1\r\nDTSTAMP:20300101T000000Z\r\n",
            "DTSTART;TZID=Europe/Madrid:20300301T090000\r\nDURATION:PT30M\r\n",
            "RRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:Standup\r\n",
            "ATTENDEE;X-FOO=one;JSID=bill:mailto:bill@example.com\r\n",
            "ATTENDEE;X-FOO=two;JSID=jane:mailto:jane.smith@example.com\r\n",
            "ORGANIZER;JSID=owner:mailto:jdoe@example.com\r\n",
            "END:VEVENT\r\n",
            "BEGIN:VEVENT\r\nUID:u1\r\nDTSTAMP:20300101T000000Z\r\n",
            "RECURRENCE-ID;TZID=Europe/Madrid:20300302T090000\r\n",
            "DTSTART;TZID=Europe/Madrid:20300302T090000\r\nDURATION:PT30M\r\n",
            "SUMMARY:Standup\r\n",
            "ATTENDEE;X-FOO=three;JSID=bill:mailto:bill@example.com\r\n",
            "ATTENDEE;X-FOO=two;JSID=jane:mailto:jane.smith@example.com\r\n",
            "ORGANIZER;JSID=owner:mailto:jdoe@example.com\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let calcard::Entry::ICalendar(ical) = calcard::Parser::new(ical).entry() else {
            panic!("failed to parse iCalendar");
        };
        let mut event = ical
            .into_jscalendar_with::<Id, BlobId, _>(
                ImportOptions::new()
                    .include_ical_components(true)
                    .return_first(true),
            )
            .expect("converts")
            .into_inner();
        event.retain_visible_participants(&CalendarAddresses::from_emails([
            "jane.smith@example.com",
        ]));
        let event = serde_json::to_value(&event).expect("serializable");
        assert!(!event.to_string().contains("bill"), "{event}");
        assert_eq!(
            event["iCalendar"]["convertedProperties"]["participants/jane/calendarAddress"]["parameters"]
                ["x-foo"],
            json!("two")
        );
    }

    #[test]
    fn attendee_entries_follow_the_same_rule() {
        let ical = concat!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
            "BEGIN:VEVENT\r\nUID:u1\r\nDTSTAMP:20300101T000000Z\r\n",
            "DTSTART:20300301T090000Z\r\nSUMMARY:Standup\r\n",
            "ORGANIZER:mailto:jdoe@example.com\r\n",
            "ATTENDEE;ROLE=OWNER:mailto:co@example.com\r\n",
            "ATTENDEE:mailto:jane.smith@example.com\r\n",
            "ATTENDEE:mailto:bill@example.com\r\n",
            "END:VEVENT\r\nEND:VCALENDAR\r\n"
        );
        let calcard::Entry::ICalendar(ical) = calcard::Parser::new(ical).entry() else {
            panic!("failed to parse iCalendar");
        };
        let identities = CalendarAddresses::from_emails(["jane.smith@example.com"]);
        let native = ical
            .components
            .iter()
            .flat_map(|component| component.entries.iter())
            .filter(|entry| {
                matches!(
                    entry.name,
                    ICalendarProperty::Organizer | ICalendarProperty::Attendee
                )
            })
            .map(|entry| entry.is_visible_participant(&identities))
            .collect::<Vec<_>>();
        assert_eq!(native, [true, true, true, false]);

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ical).expect("archive");
        let archived = rkyv::access::<
            <calcard::icalendar::ICalendar as rkyv::Archive>::Archived,
            rkyv::rancor::Error,
        >(&bytes)
        .expect("access");
        let archived = archived
            .components
            .iter()
            .flat_map(|component| component.entries.iter())
            .filter(|entry| {
                matches!(
                    entry.name,
                    ArchivedICalendarProperty::Organizer | ArchivedICalendarProperty::Attendee
                )
            })
            .map(|entry| entry.is_visible_participant(&identities))
            .collect::<Vec<_>>();
        assert_eq!(archived, [true, true, true, false]);
    }

    #[test]
    fn delegation_addresses_naming_hidden_participants_are_stripped() {
        let event = reduce_icalendar(
            concat!(
                "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
                "BEGIN:VEVENT\r\nUID:u1\r\nDTSTAMP:20300101T000000Z\r\n",
                "DTSTART:20300301T090000Z\r\nSUMMARY:Standup\r\n",
                "ORGANIZER:mailto:jdoe@example.com\r\n",
                "ATTENDEE;PARTSTAT=DELEGATED",
                ";DELEGATED-TO=\"mailto:bill@example.com\",\"mailto:jdoe@example.com\"",
                ";DELEGATED-FROM=\"mailto:jdoe@example.com\":mailto:jane.smith@example.com\r\n",
                "ATTENDEE;DELEGATED-TO=\"mailto:bill@example.com\":mailto:jdoe@example.com\r\n",
                "ATTENDEE;DELEGATED-FROM=\"mailto:jane.smith@example.com\":mailto:bill@example.com\r\n",
                "END:VEVENT\r\nEND:VCALENDAR\r\n"
            ),
            &["jane.smith@example.com"],
        );

        assert!(!event.to_string().contains("bill@example.com"), "{event}");
        let jane = participant_by_address(&event, "mailto:jane.smith@example.com");
        assert_eq!(
            jane["delegatedTo"],
            json!({"mailto:jdoe@example.com": true}),
            "{event}"
        );
        assert_eq!(
            jane["delegatedFrom"],
            json!({"mailto:jdoe@example.com": true}),
            "{event}"
        );
        assert_eq!(jane["participationStatus"], json!("delegated"), "{event}");
        let owner = participant_by_address(&event, "mailto:jdoe@example.com");
        assert_eq!(owner.get("delegatedTo"), None, "{event}");
    }

    #[test]
    fn delegation_sets_keep_only_visible_addresses() {
        let event = reduce_jscalendar(
            r#"{
  "@type": "Event",
  "uid": "delegation-sets",
  "title": "Standup",
  "start": "2026-05-04T09:00:00",
  "timeZone": "Europe/Madrid",
  "duration": "PT1H",
  "participants": {
    "owner": {
      "@type": "Participant",
      "calendarAddress": "mailto:jdoe@example.com",
      "roles": {"owner": true},
      "delegatedFrom": {"mailto:bill@example.com": true}
    },
    "jane": {
      "@type": "Participant",
      "calendarAddress": "mailto:jane.smith@example.com",
      "roles": {"attendee": true},
      "delegatedTo": {"mailto:bill@example.com": true, "MAILTO:JDoe@Example.com": true}
    },
    "bill": {
      "@type": "Participant",
      "calendarAddress": "mailto:bill@example.com",
      "roles": {"attendee": true}
    }
  }
}"#,
            &["jane.smith@example.com"],
        );

        assert!(!event.to_string().contains("bill@example.com"), "{event}");
        let owner = participant_by_address(&event, "mailto:jdoe@example.com");
        assert_eq!(owner.get("delegatedFrom"), None, "{event}");
        let jane = participant_by_address(&event, "mailto:jane.smith@example.com");
        assert_eq!(
            jane["delegatedTo"],
            json!({"MAILTO:JDoe@Example.com": true}),
            "{event}"
        );
    }

    #[test]
    fn delegation_addresses_in_overrides_are_stripped() {
        let event = reduce_jscalendar(
            r#"{
  "@type": "Event",
  "uid": "delegation-overrides",
  "title": "Review",
  "start": "2026-05-04T09:00:00",
  "timeZone": "Europe/Madrid",
  "duration": "PT1H",
  "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily", "count": 4},
  "participants": {
    "owner": {"@type": "Participant", "calendarAddress": "mailto:jdoe@example.com", "roles": {"owner": true}},
    "jane": {"@type": "Participant", "calendarAddress": "mailto:jane.smith@example.com", "roles": {"attendee": true}},
    "bill": {"@type": "Participant", "calendarAddress": "mailto:bill@example.com", "roles": {"attendee": true}}
  },
  "recurrenceOverrides": {
    "2026-05-05T09:00:00": {
      "participants/jane/delegatedTo": {"mailto:bill@example.com": true},
      "participants/owner/delegatedTo": "mailto:jane.smith@example.com"
    },
    "2026-05-06T09:00:00": {
      "participants/jane/delegatedFrom": {"mailto:bill@example.com": true, "mailto:jdoe@example.com": true}
    },
    "2026-05-07T09:00:00": {
      "participants/jane/delegatedTo/mailto:bill@example.com": true,
      "participants/jane/delegatedTo/mailto:jdoe@example.com": true
    }
  }
}"#,
            &["jane.smith@example.com"],
        );

        assert!(!event.to_string().contains("bill@example.com"), "{event}");
        let overrides = &event["recurrenceOverrides"];
        assert_eq!(
            overrides["2026-05-05T09:00:00"],
            json!({
                "participants/jane/delegatedTo": null,
                "participants/owner/delegatedTo": "mailto:jane.smith@example.com"
            }),
            "{event}"
        );
        assert_eq!(
            overrides["2026-05-06T09:00:00"],
            json!({"participants/jane/delegatedFrom": {"mailto:jdoe@example.com": true}}),
            "{event}"
        );
        assert_eq!(
            overrides["2026-05-07T09:00:00"],
            json!({"participants/jane/delegatedTo/mailto:jdoe@example.com": true}),
            "{event}"
        );
    }

    #[test]
    fn delegation_addresses_of_participants_added_by_an_override_are_kept() {
        let event = reduce_jscalendar(
            r#"{
  "@type": "Event",
  "uid": "delegation-override-owner",
  "title": "Review",
  "start": "2026-05-04T09:00:00",
  "timeZone": "Europe/Madrid",
  "duration": "PT1H",
  "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily", "count": 3},
  "participants": {
    "owner": {"@type": "Participant", "calendarAddress": "mailto:jdoe@example.com", "roles": {"owner": true}},
    "jane": {"@type": "Participant", "calendarAddress": "mailto:jane.smith@example.com", "roles": {"attendee": true}}
  },
  "recurrenceOverrides": {
    "2026-05-05T09:00:00": {
      "participants/dave": {"@type": "Participant", "calendarAddress": "mailto:dave@example.com", "roles": {"owner": true}},
      "participants/carol": {"@type": "Participant", "calendarAddress": "mailto:carol@example.com", "roles": {"attendee": true}},
      "participants/jane/delegatedTo": {"mailto:dave@example.com": true},
      "participants/jane/delegatedFrom": {"mailto:carol@example.com": true}
    }
  }
}"#,
            &["jane.smith@example.com"],
        );

        assert!(!event.to_string().contains("carol@example.com"), "{event}");
        let patch = &event["recurrenceOverrides"]["2026-05-05T09:00:00"];
        assert_eq!(
            patch["participants/jane/delegatedTo"],
            json!({"mailto:dave@example.com": true}),
            "{event}"
        );
        assert_eq!(
            patch["participants/jane/delegatedFrom"],
            json!(null),
            "{event}"
        );
    }
}
