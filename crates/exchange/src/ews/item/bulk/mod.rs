/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod associated;
mod email;
mod export;
mod native;
mod upload;

pub(crate) use associated::{AssociatedId, delete_associated, find_associated, get_associated};
pub(crate) use export::export_items;
pub(crate) use upload::upload_items;

use super::ItemError;
use crate::{
    ews::groupware::{GroupwareKind, items::GroupwareRef},
    identity::org_dn,
};
use calcard::{
    Entry, Parser,
    icalendar::{ICalendar, ICalendarComponentType},
    vcard::VCard,
};
use common::Server;
use exchange_proto::{
    ews::{
        bulk::{BulkRecord, MAX_RECORD_ENVELOPE, RawProperty},
        types::ids::ItemId,
    },
    ids::{
        essdn::OrgDn,
        ews::{EwsChangeKey, EwsObjectId},
        token::ObjectKind,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parsed {
    Mail,
    Groupware(GroupwareKind, u32, GroupwareRef),
    Associated(AssociatedId),
}

impl Parsed {
    fn of(id: &ItemId<'_>) -> Result<Self, ItemError> {
        let text = id.id.as_str();
        if text.is_empty() {
            return Err(ItemError::IdEmpty);
        }
        if id
            .change_key
            .as_ref()
            .is_some_and(|key| EwsChangeKey::decode(key.as_str()).is_none())
        {
            return Err(ItemError::InvalidChangeKey);
        }
        let object = EwsObjectId::decode(text).ok_or(ItemError::Malformed)?;
        if let Some(associated) = AssociatedId::of(&object) {
            return associated.map(Parsed::Associated);
        }
        match object {
            EwsObjectId::Item {
                kind: ObjectKind::Email,
                ..
            } => Ok(Parsed::Mail),
            EwsObjectId::Item {
                account,
                kind,
                container,
                id,
            } => GroupwareKind::of_object(kind)
                .map(|kind| {
                    Parsed::Groupware(
                        kind,
                        account,
                        GroupwareRef {
                            container,
                            document_id: id,
                        },
                    )
                })
                .ok_or(ItemError::InvalidId),
            EwsObjectId::Occurrence { .. } => Err(ItemError::NotStored),
            _ => Err(ItemError::InvalidId),
        }
    }
}

fn record_limit(server: &Server) -> usize {
    MAX_RECORD_ENVELOPE
        .saturating_add(server.core.email.mail_max_size)
        .saturating_add(server.core.exchange.max_object_size)
}

#[derive(Debug, Clone, Copy)]
struct RecordLimits {
    object: usize,
    ical: usize,
    vcard: usize,
}

impl RecordLimits {
    fn new(server: &Server) -> Self {
        RecordLimits {
            object: server.core.exchange.max_object_size,
            ical: server.core.groupware.max_ical_size,
            vcard: server.core.groupware.max_vcard_size,
        }
    }

    fn check(&self, record: &BulkRecord<'_>) -> Result<(), ItemError> {
        let (size, max) = match record {
            BulkRecord::Email { properties, .. } => (envelope(properties), self.object),
            BulkRecord::Event { ical } | BulkRecord::Task { ical } => (ical.len(), self.ical),
            BulkRecord::Contact { vcard } => (vcard.len(), self.vcard),
            BulkRecord::Associated {
                message_class,
                properties,
                recipients,
            } => (
                recipients.iter().fold(
                    envelope(properties).saturating_add(message_class.len()),
                    |size, recipient| size.saturating_add(envelope(recipient)),
                ),
                self.object,
            ),
        };
        if size > max {
            Err(ItemError::TooLarge)
        } else {
            Ok(())
        }
    }
}

fn envelope(properties: &[RawProperty<'_>]) -> usize {
    properties
        .iter()
        .map(|property| property.key.len() + property.value.len())
        .sum()
}

fn parse_ical(text: &str, component: &ICalendarComponentType) -> Result<ICalendar, ItemError> {
    match Parser::new(text).entry() {
        Entry::ICalendar(ical)
            if ical
                .components
                .iter()
                .any(|entry| &entry.component_type == component) =>
        {
            Ok(ical)
        }
        _ => Err(ItemError::CorruptData),
    }
}

fn parse_vcard(text: &str) -> Result<VCard, ItemError> {
    match Parser::new(text).strict().entry() {
        Entry::VCard(card) => Ok(card),
        _ => Err(ItemError::CorruptData),
    }
}

fn organization() -> trc::Result<OrgDn> {
    org_dn().ok_or_else(|| {
        trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Exchange organization DN is invalid.")
            .caused_by(trc::location!())
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/ews/item/bulk/tests.rs"]
mod tests;
