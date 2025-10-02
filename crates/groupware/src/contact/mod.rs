/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;
pub mod storage;

use calcard::vcard::VCard;
use common::{DavName, auth::AccessToken};
use dav_proto::schema::request::DeadProperty;
use types::acl::AclGrant;

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
    pub is_default: bool,
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
        if self.preferences.len() == 1 {
            &mut self.preferences[0]
        } else {
            let account_id = access_token.primary_id();
            let idx = self
                .preferences
                .iter()
                .position(|p| p.account_id == account_id)
                .unwrap_or(0);
            &mut self.preferences[idx]
        }
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
