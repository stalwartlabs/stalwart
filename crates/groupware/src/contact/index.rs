/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AddressBook, ArchivedAddressBook, ArchivedContactCard, ContactCard};
use calcard::vcard::VCardProperty;
use common::storage::index::{
    IndexItem, IndexValue, IndexableAndSerializableObject, IndexableObject,
};
use std::collections::HashSet;
use types::{acl::AclGrant, collection::SyncCollection, field::ContactField};
use utils::sanitize_email;

impl IndexableObject for AddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: (&self.acls).into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.description.as_ref().map_or(0, |n| n.len() as u32)
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::AddressBook,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedAddressBook {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Acl {
                value: self
                    .acls
                    .iter()
                    .map(AclGrant::from)
                    .collect::<Vec<_>>()
                    .into(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.description.as_ref().map_or(0, |n| n.len() as u32)
                    + self.name.len() as u32,
            },
            IndexValue::LogContainer {
                sync_collection: SyncCollection::AddressBook,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for AddressBook {
    fn is_versioned() -> bool {
        true
    }
}

impl IndexableObject for ContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: ContactField::Uid.into(),
                value: self.card.uid().into(),
            },
            IndexValue::IndexList {
                field: ContactField::Email.into(),
                value: self
                    .emails()
                    .map(Into::into)
                    .collect::<HashSet<IndexItem>>()
                    .into_iter()
                    .collect(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableObject for &ArchivedContactCard {
    fn index_values(&self) -> impl Iterator<Item = IndexValue<'_>> {
        [
            IndexValue::Index {
                field: ContactField::Uid.into(),
                value: self.card.uid().into(),
            },
            IndexValue::IndexList {
                field: ContactField::Email.into(),
                value: self
                    .emails()
                    .map(Into::into)
                    .collect::<HashSet<IndexItem>>()
                    .into_iter()
                    .collect(),
            },
            IndexValue::Quota {
                used: self.dead_properties.size() as u32
                    + self.display_name.as_ref().map_or(0, |n| n.len() as u32)
                    + self.names.iter().map(|n| n.name.len() as u32).sum::<u32>()
                    + self.size,
            },
            IndexValue::LogItem {
                sync_collection: SyncCollection::AddressBook,
                prefix: None,
            },
        ]
        .into_iter()
    }
}

impl IndexableAndSerializableObject for ContactCard {
    fn is_versioned() -> bool {
        true
    }
}

impl ContactCard {
    pub fn emails(&self) -> impl Iterator<Item = String> {
        self.card.properties(&VCardProperty::Email).flat_map(|e| {
            e.values
                .iter()
                .filter_map(|v| v.as_text().and_then(sanitize_email))
        })
    }
}

impl ArchivedContactCard {
    pub fn emails(&self) -> impl Iterator<Item = String> {
        self.card.properties(&VCardProperty::Email).flat_map(|e| {
            e.values
                .iter()
                .filter_map(|v| v.as_text().and_then(sanitize_email))
        })
    }
}
