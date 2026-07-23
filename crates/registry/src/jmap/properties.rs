/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{jmap::RegistryValue, schema::prelude::Property, types::EnumImpl};
use jmap_tools::Key;
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id};

impl jmap_tools::Property for Property {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        Property::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        self.as_str().into()
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
                | Property::DefaultUserRoleIds
                | Property::DefaultGroupRoleIds
                | Property::DefaultTenantRoleIds
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
        match self {
            RegistryValue::Id(id) => id.to_string().into(),
            RegistryValue::BlobId(blob_id) => blob_id.to_string().into(),
            RegistryValue::IdReference(r) => format!("#{r}").into(),
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
