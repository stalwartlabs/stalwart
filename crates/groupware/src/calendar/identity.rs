/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ParticipantIdentities, ParticipantIdentityChange, ParticipantIdentityChangeType,
    participants::ArchivedParticipantEntry,
};
use calcard::icalendar::{
    ArchivedICalendar, ArchivedICalendarComponentType, ArchivedICalendarEntry,
    ArchivedICalendarProperty, ICalendar, ICalendarComponent, ICalendarComponentType,
    ICalendarEntry, ICalendarParameterName, ICalendarParameterValue, ICalendarParticipationRole,
    ICalendarProperty,
};
use common::{Server, auth::AccountInfo};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Null, Value};
use std::borrow::Cow;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField};

const MAILTO_SCHEME: &str = "mailto";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CalendarAddresses(Vec<String>);

impl CalendarAddresses {
    pub fn from_emails<'x>(emails: impl IntoIterator<Item = &'x str>) -> Self {
        let mut addresses = CalendarAddresses::default();
        for email in emails {
            addresses.push(CalendarAddresses::normalize(email));
        }
        addresses
    }

    pub fn contains(&self, calendar_address: &str) -> bool {
        let normalized = CalendarAddresses::normalize(calendar_address);
        self.0.iter().any(|address| address == normalized.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn push(&mut self, address: Cow<'_, str>) {
        if !self.0.iter().any(|existing| existing == address.as_ref()) {
            self.0.push(address.into_owned());
        }
    }

    pub fn normalize(calendar_address: &str) -> Cow<'_, str> {
        let calendar_address = calendar_address.trim();
        let (scheme, rest) = match calendar_address.split_once(':') {
            Some((scheme, rest)) if is_scheme(scheme) => (scheme, rest),
            _ => {
                let mut address =
                    String::with_capacity(MAILTO_SCHEME.len() + 1 + calendar_address.len());
                address.push_str(MAILTO_SCHEME);
                address.push(':');
                address.push_str(&normalize_percent_encoding(calendar_address).to_lowercase());
                return Cow::Owned(address);
            }
        };

        if scheme == MAILTO_SCHEME
            && !rest
                .bytes()
                .any(|b| b.is_ascii_uppercase() || b == b'%' || !b.is_ascii())
        {
            return Cow::Borrowed(calendar_address);
        }

        let scheme = scheme.to_ascii_lowercase();
        let rest = normalize_percent_encoding(rest);
        let rest = if scheme == MAILTO_SCHEME {
            rest.to_lowercase()
        } else {
            normalize_hierarchical_part(&rest)
        };
        let mut address = String::with_capacity(scheme.len() + 1 + rest.len());
        address.push_str(&scheme);
        address.push(':');
        address.push_str(&rest);
        Cow::Owned(address)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOwnership {
    NoOwner,
    Owner,
    NotOwner,
}

impl CalendarAddresses {
    pub fn event_ownership(&self, ical: &ICalendar) -> EventOwnership {
        let is_series = |component: &ICalendarComponent| !component.is_recurrence_override();
        let scheduling_components = || {
            ical.components
                .iter()
                .filter(|component| component.component_type.is_scheduling_object())
        };
        let has_series = scheduling_components().any(is_series);
        let mut ownership = EventOwnership::NoOwner;
        for component in
            scheduling_components().filter(|component| is_series(component) == has_series)
        {
            for entry in component
                .entries
                .iter()
                .filter(|entry| entry.is_owner_entry())
            {
                if entry
                    .calendar_address()
                    .is_some_and(|address| self.contains(address))
                {
                    return EventOwnership::Owner;
                }
                ownership = EventOwnership::NotOwner;
            }
            if ownership == EventOwnership::NoOwner {
                for participant in component
                    .component_ids
                    .iter()
                    .filter_map(|id| ical.components.get(*id as usize))
                    .filter(|sub| sub.component_type == ICalendarComponentType::Participant)
                    .filter(|sub| {
                        sub.entries
                            .iter()
                            .any(|entry| entry.sets_owner_role(PARTICIPANT_OWNER_PATH))
                    })
                {
                    if participant.entries.iter().any(|entry| {
                        entry.name == ICalendarProperty::CalendarAddress
                            && entry
                                .calendar_address()
                                .is_some_and(|address| self.contains(address))
                    }) {
                        return EventOwnership::Owner;
                    }
                    ownership = EventOwnership::NotOwner;
                }
                if component
                    .entries
                    .iter()
                    .any(|entry| entry.sets_owner_role(EVENT_OWNER_PATH))
                {
                    ownership = EventOwnership::NotOwner;
                }
            }
        }

        ownership
    }

    pub fn archived_event_ownership(&self, ical: &ArchivedICalendar) -> EventOwnership {
        let scheduling_components = || {
            ical.components
                .iter()
                .filter(|component| component.component_type.is_scheduling_object())
        };
        let has_series =
            scheduling_components().any(|component| !component.is_recurrence_override());
        let mut ownership = EventOwnership::NoOwner;
        for component in scheduling_components()
            .filter(|component| component.is_recurrence_override() != has_series)
        {
            for entry in component.entries.iter().filter(|entry| match entry.name {
                ArchivedICalendarProperty::Organizer => true,
                ArchivedICalendarProperty::Attendee => entry.has_owner_role(),
                _ => false,
            }) {
                if entry
                    .values
                    .first()
                    .and_then(|value| value.as_text())
                    .is_some_and(|address| self.contains(address))
                {
                    return EventOwnership::Owner;
                }
                ownership = EventOwnership::NotOwner;
            }
            if ownership == EventOwnership::NoOwner {
                for participant in component
                    .component_ids
                    .iter()
                    .filter_map(|id| ical.components.get(id.to_native() as usize))
                    .filter(|sub| {
                        matches!(
                            sub.component_type,
                            ArchivedICalendarComponentType::Participant
                        )
                    })
                    .filter(|sub| {
                        sub.entries
                            .iter()
                            .any(|entry| entry.sets_owner_role(PARTICIPANT_OWNER_PATH))
                    })
                {
                    if participant.entries.iter().any(|entry| {
                        matches!(entry.name, ArchivedICalendarProperty::CalendarAddress)
                            && entry
                                .values
                                .first()
                                .and_then(|value| value.as_text())
                                .is_some_and(|address| self.contains(address))
                    }) {
                        return EventOwnership::Owner;
                    }
                    ownership = EventOwnership::NotOwner;
                }
                if component
                    .entries
                    .iter()
                    .any(|entry| entry.sets_owner_role(EVENT_OWNER_PATH))
                {
                    ownership = EventOwnership::NotOwner;
                }
            }
        }

        ownership
    }
}

impl EventOwnership {
    pub fn may_write_own(self) -> bool {
        self != EventOwnership::NotOwner
    }
}

pub(crate) trait OwnerEntry {
    fn is_owner_entry(&self) -> bool;
}

impl OwnerEntry for ICalendarEntry {
    fn is_owner_entry(&self) -> bool {
        match self.name {
            ICalendarProperty::Organizer => true,
            ICalendarProperty::Attendee => {
                self.parameters(&ICalendarParameterName::Role).any(|role| {
                    matches!(
                        role,
                        ICalendarParameterValue::Role(ICalendarParticipationRole::Owner)
                    )
                })
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
enum OwnerPathItem {
    Key(&'static str),
    AnyKey,
}

const PARTICIPANT_OWNER_PATH: &[OwnerPathItem] =
    &[OwnerPathItem::Key("roles"), OwnerPathItem::Key("owner")];
const EVENT_OWNER_PATH: &[OwnerPathItem] = &[
    OwnerPathItem::Key("participants"),
    OwnerPathItem::AnyKey,
    OwnerPathItem::Key("roles"),
    OwnerPathItem::Key("owner"),
];

trait OwnerRoleJsprop {
    fn sets_owner_role(&self, path: &[OwnerPathItem]) -> bool;
}

impl OwnerRoleJsprop for ICalendarEntry {
    fn sets_owner_role(&self, path: &[OwnerPathItem]) -> bool {
        self.name == ICalendarProperty::Jsprop
            && self
                .parameter(&ICalendarParameterName::Jsptr)
                .and_then(|pointer| pointer.as_text())
                .zip(self.values.first().and_then(|value| value.as_text()))
                .is_some_and(|(pointer, value)| jsprop_sets_owner_role(pointer, value, path))
    }
}

impl OwnerRoleJsprop for ArchivedICalendarEntry {
    fn sets_owner_role(&self, path: &[OwnerPathItem]) -> bool {
        matches!(self.name, ArchivedICalendarProperty::Jsprop)
            && self
                .parameters(&ICalendarParameterName::Jsptr)
                .next()
                .and_then(|pointer| pointer.as_text())
                .zip(self.values.first().and_then(|value| value.as_text()))
                .is_some_and(|(pointer, value)| jsprop_sets_owner_role(pointer, value, path))
    }
}

fn jsprop_sets_owner_role(pointer: &str, value: &str, path: &[OwnerPathItem]) -> bool {
    let Some(OwnerPathItem::Key(first)) = path.first() else {
        return false;
    };
    if !pointer
        .strip_prefix('/')
        .unwrap_or(pointer)
        .starts_with(first)
    {
        return false;
    }

    let pointer = JsonPointer::<Null>::parse(pointer);
    let mut rest = path;
    for item in pointer.as_slice() {
        let Some((expected, tail)) = rest.split_first() else {
            return false;
        };
        let matches = match (expected, item) {
            (OwnerPathItem::Key(name), JsonPointerItem::Key(key)) => key == name,
            (OwnerPathItem::AnyKey, JsonPointerItem::Key(_) | JsonPointerItem::Number(_)) => true,
            _ => false,
        };
        if !matches {
            return false;
        }
        rest = tail;
    }

    Value::<Null, Null>::parse_json(value).is_ok_and(|value| value_sets_owner_role(&value, rest))
}

fn value_sets_owner_role(value: &Value<'_, Null, Null>, path: &[OwnerPathItem]) -> bool {
    match path.split_first() {
        None => value.as_bool() == Some(true),
        Some((OwnerPathItem::Key(name), rest)) => value
            .as_object_and_get(&Key::Borrowed(name))
            .is_some_and(|value| value_sets_owner_role(value, rest)),
        Some((OwnerPathItem::AnyKey, rest)) => value.as_object().is_some_and(|object| {
            object
                .values()
                .any(|value| value_sets_owner_role(value, rest))
        }),
    }
}

const MAX_IDENTITY_CHANGES: usize = 16;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IdentityChanges {
    pub created: Vec<u32>,
    pub updated: Vec<u32>,
    pub destroyed: Vec<u32>,
    pub new_change_id: u32,
    pub has_more_changes: bool,
}

struct PendingIdentityChange {
    id: u32,
    first: ParticipantIdentityChangeType,
    last: ParticipantIdentityChangeType,
}

impl ParticipantIdentities {
    pub fn begin_changes(&mut self) {
        self.change_id += 1;
    }

    pub fn record_change(&mut self, id: u32, change_type: ParticipantIdentityChangeType) {
        self.changes.push(ParticipantIdentityChange {
            change_id: self.change_id,
            id,
            change_type,
        });
        while self.changes.len() > MAX_IDENTITY_CHANGES {
            let Some(oldest) = self.changes.first().map(|change| change.change_id) else {
                break;
            };
            self.changes.retain(|change| change.change_id != oldest);
            self.trimmed_change_id = oldest;
        }
    }

    pub fn changes_since(&self, since: u32, max_changes: usize) -> Option<IdentityChanges> {
        if since > self.change_id || since < self.trimmed_change_id {
            return None;
        }

        let mut changes = IdentityChanges {
            new_change_id: since,
            ..Default::default()
        };
        let mut pending: Vec<PendingIdentityChange> = Vec::new();
        let mut total = 0;
        for group in self
            .changes
            .chunk_by(|a, b| a.change_id == b.change_id)
            .filter(|group| group.first().is_some_and(|change| change.change_id > since))
        {
            if total + group.len() > max_changes {
                if total == 0 {
                    return None;
                }
                changes.has_more_changes = true;
                break;
            }
            total += group.len();
            for change in group {
                match pending.iter_mut().find(|pending| pending.id == change.id) {
                    Some(pending) => pending.last = change.change_type,
                    None => pending.push(PendingIdentityChange {
                        id: change.id,
                        first: change.change_type,
                        last: change.change_type,
                    }),
                }
            }
            if let Some(change) = group.first() {
                changes.new_change_id = change.change_id;
            }
        }
        if !changes.has_more_changes {
            changes.new_change_id = self.change_id.max(changes.new_change_id);
        }

        for pending in pending {
            match (pending.first, pending.last) {
                (
                    ParticipantIdentityChangeType::Created,
                    ParticipantIdentityChangeType::Destroyed,
                ) => {}
                (ParticipantIdentityChangeType::Created, _) => changes.created.push(pending.id),
                (_, ParticipantIdentityChangeType::Destroyed) => changes.destroyed.push(pending.id),
                _ => changes.updated.push(pending.id),
            }
        }

        Some(changes)
    }

    pub fn calendar_addresses(&self, allowed: &CalendarAddresses) -> CalendarAddresses {
        let mut addresses = CalendarAddresses::default();
        for address in self
            .identities
            .iter()
            .map(|identity| CalendarAddresses::normalize(&identity.calendar_address))
        {
            if allowed.0.iter().any(|allowed| allowed == address.as_ref()) {
                addresses.push(address);
            }
        }
        addresses
    }
}

pub trait ParticipantIdentityAddresses: Sync + Send {
    fn account_identity_addresses(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<CalendarAddresses>> + Send;

    fn identity_addresses(
        &self,
        account_id: u32,
        account_info: &AccountInfo,
    ) -> impl Future<Output = trc::Result<CalendarAddresses>> + Send;
}

impl ParticipantIdentityAddresses for Server {
    async fn account_identity_addresses(&self, account_id: u32) -> trc::Result<CalendarAddresses> {
        let account_info = self
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        self.identity_addresses(account_id, &account_info).await
    }

    async fn identity_addresses(
        &self,
        account_id: u32,
        account_info: &AccountInfo,
    ) -> trc::Result<CalendarAddresses> {
        let allowed =
            CalendarAddresses::from_emails(account_info.addresses().iter().map(String::as_str));
        let Some(archive) = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::ParticipantIdentities,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(allowed);
        };

        archive
            .deserialize::<ParticipantIdentities>()
            .map(|identities| identities.calendar_addresses(&allowed))
            .caused_by(trc::location!())
    }
}

fn is_scheme(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

fn normalize_percent_encoding(value: &str) -> Cow<'_, str> {
    if !value.contains('%') {
        return Cow::Borrowed(value);
    }

    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        let mut lookahead = bytes.clone();
        match (
            lookahead.next().and_then(hex_value),
            lookahead.next().and_then(hex_value),
        ) {
            (Some(high), Some(low)) => {
                bytes = lookahead;
                let decoded = (high << 4) | low;
                if decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~') {
                    out.push(decoded);
                } else {
                    out.push(b'%');
                    out.push(hex_digit(high));
                    out.push(hex_digit(low));
                }
            }
            _ => out.push(byte),
        }
    }

    String::from_utf8(out).map_or(Cow::Borrowed(value), Cow::Owned)
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).map(|digit| digit as u8)
}

fn hex_digit(value: u8) -> u8 {
    b"0123456789ABCDEF"
        .get(value as usize)
        .copied()
        .unwrap_or(b'0')
}

fn normalize_hierarchical_part(rest: &str) -> String {
    let path_len = rest
        .bytes()
        .take_while(|b| !matches!(b, b'?' | b'#'))
        .count();
    let (before_query, query) = rest.split_at_checked(path_len).unwrap_or((rest, ""));
    let mut out = String::with_capacity(rest.len());
    let path = if let Some(authority_and_path) = before_query.strip_prefix("//") {
        let authority_len = authority_and_path
            .bytes()
            .take_while(|b| *b != b'/')
            .count();
        let (authority, path) = authority_and_path
            .split_at_checked(authority_len)
            .unwrap_or((authority_and_path, ""));
        out.push_str("//");
        match authority.rsplit_once('@') {
            Some((user_info, host)) => {
                out.push_str(user_info);
                out.push('@');
                out.push_str(&host.to_ascii_lowercase());
            }
            None => out.push_str(&authority.to_ascii_lowercase()),
        }
        path
    } else {
        before_query
    };

    if path.starts_with('/') || rest.starts_with("//") {
        remove_dot_segments(path, &mut out);
    } else {
        out.push_str(path);
    }
    out.push_str(query);
    out
}

fn remove_dot_segments(path: &str, out: &mut String) {
    let is_absolute = path.starts_with('/');
    let mut segments = Vec::new();
    let mut has_trailing_slash = false;
    let mut iter = path.split('/');
    if is_absolute {
        iter.next();
    }
    for segment in iter {
        match segment {
            "." => has_trailing_slash = true,
            ".." => {
                segments.pop();
                has_trailing_slash = true;
            }
            segment => {
                segments.push(segment);
                has_trailing_slash = false;
            }
        }
    }

    if is_absolute {
        out.push('/');
    }
    for (idx, segment) in segments.iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        out.push_str(segment);
    }
    if has_trailing_slash && !segments.is_empty() {
        out.push('/');
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/groupware/src/calendar/identity/tests.rs"]
mod tests;
