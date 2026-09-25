/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{jmap::RegistryValue, schema::prelude::Property, types::EnumImpl};
use jmap_tools::Key;
use serde::{Serialize, Serializer};
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id, text::Text};

impl jmap_tools::Property for Property {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        Property::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.as_str().into()
    }

    fn key_eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl FromStr for Property {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Property::parse(s).ok_or(())
    }
}

impl jmap_tools::Element for RegistryValue {
    type Property = Property;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                Property::Id
                | Property::MemberGroupIds
                | Property::MemberTenantId
                | Property::RoleIds
                | Property::DnsServerId
                | Property::DirectoryId
                | Property::DomainId
                | Property::AccountId
                | Property::DefaultDomainId
                | Property::DefaultCertificateId
                | Property::DefaultUserRoleIds
                | Property::DefaultGroupRoleIds
                | Property::DefaultTenantRoleIds
                | Property::DefaultAdminRoleIds
                | Property::ListenerIds
                | Property::PublicKey
                | Property::QueueId
                | Property::ModelId
                | Property::AcmeProviderId => {
                    if let Some(reference) = value.strip_prefix('#') {
                        Some(RegistryValue::IdReference(reference.to_string()))
                    } else {
                        Id::from_str(value).map(RegistryValue::Id).ok()
                    }
                }
                Property::BlobId => {
                    if let Some(reference) = value.strip_prefix('#') {
                        Some(RegistryValue::IdReference(reference.to_string()))
                    } else {
                        BlobId::from_str(value).map(RegistryValue::BlobId).ok()
                    }
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.text().to_cow()
    }

    fn serialize_text<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.text().serialize(serializer)
    }
}

impl RegistryValue {
    pub fn text(&self) -> Text<'_> {
        match self {
            RegistryValue::Id(id) => Text::Id(*id),
            RegistryValue::BlobId(blob_id) => Text::Display(blob_id),
            RegistryValue::IdReference(r) => Text::Reference(r),
        }
    }
}

impl From<Id> for RegistryValue {
    fn from(id: Id) -> Self {
        RegistryValue::Id(id)
    }
}

impl From<BlobId> for RegistryValue {
    fn from(id: BlobId) -> Self {
        RegistryValue::BlobId(id)
    }
}
