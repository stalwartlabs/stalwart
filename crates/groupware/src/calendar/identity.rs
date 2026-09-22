/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ParticipantIdentities, ParticipantIdentityChange, ParticipantIdentityChangeType};
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarEntry, ICalendarParameterName, ICalendarParameterValue,
    ICalendarParticipationRole, ICalendarProperty,
};
use common::{Server, auth::AccountInfo};
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
        for entry in scheduling_components()
            .filter(|component| is_series(component) == has_series)
            .flat_map(|component| component.entries.iter())
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

        ownership
    }
}

impl EventOwnership {
    pub fn may_write_own(self) -> bool {
        self != EventOwnership::NotOwner
    }
}

trait OwnerEntry {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mailto_addresses() {
        for (input, expected) in [
            ("mailto:jdoe@example.com", "mailto:jdoe@example.com"),
            ("MAILTO:JDoe@Example.COM", "mailto:jdoe@example.com"),
            ("jdoe@example.com", "mailto:jdoe@example.com"),
            ("mailto:j%64oe@example.com", "mailto:jdoe@example.com"),
            ("mailto:j%2bdoe@example.com", "mailto:j%2bdoe@example.com"),
            (" mailto:jdoe@example.com ", "mailto:jdoe@example.com"),
        ] {
            assert_eq!(CalendarAddresses::normalize(input), expected, "{input}");
        }
    }

    #[test]
    fn normalizes_other_uris() {
        for (input, expected) in [
            (
                "HTTPS://Cal.Example.COM/a/./b/../c",
                "https://cal.example.com/a/c",
            ),
            (
                "https://User@Host.example/%7euser/",
                "https://User@host.example/~user/",
            ),
            ("https://host.example/a/b/.", "https://host.example/a/b/"),
            (
                "https://host.example/p?Q=%2f",
                "https://host.example/p?Q=%2F",
            ),
            ("urn:uuid:ABC", "urn:uuid:ABC"),
        ] {
            assert_eq!(CalendarAddresses::normalize(input), expected, "{input}");
        }
    }

    #[test]
    fn identity_changes_are_tracked() {
        let mut identities = ParticipantIdentities::default();
        identities.begin_changes();
        identities.record_change(1, ParticipantIdentityChangeType::Created);
        identities.record_change(2, ParticipantIdentityChangeType::Created);
        identities.begin_changes();
        identities.record_change(1, ParticipantIdentityChangeType::Updated);
        identities.record_change(2, ParticipantIdentityChangeType::Destroyed);
        identities.begin_changes();
        identities.record_change(3, ParticipantIdentityChangeType::Created);

        let changes = identities.changes_since(0, usize::MAX).unwrap();
        assert_eq!(changes.created, [1, 3]);
        assert!(changes.destroyed.is_empty() && changes.updated.is_empty());
        assert_eq!(changes.new_change_id, 3);

        let changes = identities.changes_since(1, usize::MAX).unwrap();
        assert_eq!(changes.updated, [1]);
        assert_eq!(changes.destroyed, [2]);
        assert_eq!(changes.created, [3]);

        let changes = identities.changes_since(1, 2).unwrap();
        assert!(changes.has_more_changes);
        assert_eq!(changes.new_change_id, 2);
        assert!(changes.created.is_empty());
        assert!(identities.changes_since(0, 1).is_none());
        assert!(identities.changes_since(1, 1).is_none());

        assert!(identities.changes_since(3, 10).unwrap().created.is_empty());
        assert!(identities.changes_since(4, 10).is_none());

        for id in 0..20 {
            identities.begin_changes();
            identities.record_change(id, ParticipantIdentityChangeType::Updated);
        }
        assert!(identities.changes.len() <= MAX_IDENTITY_CHANGES);
        assert!(identities.changes_since(1, usize::MAX).is_none());
        assert!(
            identities
                .changes_since(identities.change_id - 2, usize::MAX)
                .is_some()
        );
    }

    #[test]
    fn ownership_follows_the_series_participants() {
        let jane = CalendarAddresses::from_emails(["jane@example.com"]);
        let event = |master: &str, instance: &str| {
            ICalendar::parse(format!(
                concat!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n",
                    "{}",
                    "BEGIN:VEVENT\r\nUID:own\r\nRECURRENCE-ID:20260602T090000Z\r\n",
                    "DTSTART:20260602T100000Z\r\n{}END:VEVENT\r\n",
                    "END:VCALENDAR\r\n"
                ),
                master, instance
            ))
            .expect("valid iCalendar")
        };
        let master = |entries: &str| {
            format!(
                concat!(
                    "BEGIN:VEVENT\r\nUID:own\r\nDTSTART:20260601T090000Z\r\n",
                    "RRULE:FREQ=DAILY;COUNT=3\r\n{}END:VEVENT\r\n"
                ),
                entries
            )
        };
        let jane_owner = "ATTENDEE;ROLE=OWNER:mailto:jane@example.com\r\n";
        let john_organizer = "ORGANIZER:mailto:john@example.com\r\n";

        assert_eq!(
            jane.event_ownership(&event(&master(john_organizer), jane_owner)),
            EventOwnership::NotOwner
        );
        assert_eq!(
            jane.event_ownership(&event(&master(""), jane_owner)),
            EventOwnership::NoOwner
        );
        assert_eq!(
            jane.event_ownership(&event(&master(jane_owner), john_organizer)),
            EventOwnership::Owner
        );
        assert_eq!(
            jane.event_ownership(&event("", jane_owner)),
            EventOwnership::Owner
        );
        assert_eq!(
            jane.event_ownership(&event("", john_organizer)),
            EventOwnership::NotOwner
        );
    }

    #[test]
    fn identities_are_limited_to_allowed_addresses() {
        let allowed = CalendarAddresses::from_emails(["jdoe@example.com", "sales@example.com"]);
        let identities = ParticipantIdentities {
            identities: ["mailto:JDoe@example.com", "mailto:old@example.com"]
                .into_iter()
                .enumerate()
                .map(|(id, address)| super::super::ParticipantIdentity {
                    id: id as u32,
                    name: None,
                    calendar_address: address.to_string(),
                })
                .collect(),
            ..Default::default()
        };
        let addresses = identities.calendar_addresses(&allowed);
        assert!(addresses.contains("mailto:jdoe@EXAMPLE.com"));
        assert!(!addresses.contains("mailto:old@example.com"));
        assert!(!addresses.contains("mailto:sales@example.com"));
    }
}
