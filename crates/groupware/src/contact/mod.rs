/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;
pub mod storage;

use calcard::vcard::VCard;
use common::{DavName, auth::AccessToken};
use types::{acl::AclGrant, dead_property::DeadProperty};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct AddressBook {
    pub name: String,
    pub preferences: Vec<AddressBookPreferences>,
    pub subscribers: Vec<u32>,
    pub dead_properties: DeadProperty,
    pub acls: Vec<AclGrant>,
    pub created: i64,
    pub modified: i64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct AddressBookPreferences {
    pub account_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct ContactCard {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub card: VCard,
    pub dead_properties: DeadProperty,
    pub created: i64,
    pub modified: i64,
    pub size: u32,
}

impl AddressBook {
    pub fn preferences(&self, access_token: &AccessToken) -> &AddressBookPreferences {
        if self.preferences.len() == 1 {
            &self.preferences[0]
        } else {
            let account_id = access_token.primary_id();
            self.preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or_else(|| self.preferences.first())
                .unwrap()
        }
    }

    pub fn preferences_mut(&mut self, access_token: &AccessToken) -> &mut AddressBookPreferences {
        let account_id = access_token.primary_id();
        let idx = if let Some(idx) = self
            .preferences
            .iter()
            .position(|p| p.account_id == account_id)
        {
            idx
        } else {
            let mut preferences = self.preferences[0].clone();
            preferences.account_id = account_id;
            self.preferences.push(preferences);
            self.preferences.len() - 1
        };

        &mut self.preferences[idx]
    }
}

impl ArchivedAddressBook {
    pub fn preferences(&self, access_token: &AccessToken) -> &ArchivedAddressBookPreferences {
        if self.preferences.len() == 1 {
            &self.preferences[0]
        } else {
            let account_id = access_token.primary_id();
            self.preferences
                .iter()
                .find(|p| p.account_id == account_id)
                .or_else(|| self.preferences.first())
                .unwrap()
        }
    }
}

impl ContactCard {
    pub fn added_addressbook_ids(
        &self,
        prev_data: &ArchivedContactCard,
    ) -> impl Iterator<Item = u32> {
        self.names
            .iter()
            .filter(|m| prev_data.names.iter().all(|pm| pm.parent_id != m.parent_id))
            .map(|m| m.parent_id)
    }

    pub fn removed_addressbook_ids(
        &self,
        prev_data: &ArchivedContactCard,
    ) -> impl Iterator<Item = u32> {
        prev_data
            .names
            .iter()
            .filter(|m| self.names.iter().all(|pm| pm.parent_id != m.parent_id))
            .map(|m| m.parent_id.to_native())
    }

    pub fn unchanged_addressbook_ids(
        &self,
        prev_data: &ArchivedContactCard,
    ) -> impl Iterator<Item = u32> {
        self.names
            .iter()
            .filter(|m| prev_data.names.iter().any(|pm| pm.parent_id == m.parent_id))
            .map(|m| m.parent_id)
    }
}
