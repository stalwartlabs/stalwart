/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::request::deserialize::DeserializeArguments;
use jmap_tools::{Element, Null, Property};
use serde::Serialize;
use std::{fmt::Debug, str::FromStr};
use types::{acl::Acl, blob::BlobId, id::Id};

pub mod addressbook;
pub mod blob;
pub mod calendar;
pub mod calendar_event;
pub mod calendar_event_notification;
pub mod contact;
pub mod email;
pub mod email_submission;
pub mod file_node;
pub mod identity;
pub mod mailbox;
pub mod participant_identity;
pub mod principal;
pub mod push_subscription;
pub mod quota;
pub mod search_snippet;
pub mod share_notification;
pub mod sieve;
pub mod thread;
pub mod vacation_response;

pub trait JmapObject: std::fmt::Debug {
    type Property: Property + JmapObjectId + FromStr + Debug + Sync + Send;
    type Element: Element<Property = Self::Property> + JmapObjectId + Debug + Sync + Send;
    type Id: FromStr + TryFrom<AnyId> + Into<Self::Element> + Serialize + Debug + Sync + Send;

    type Filter: Default + for<'de> DeserializeArguments<'de> + Debug + Sync + Send;
    type Comparator: Default + for<'de> DeserializeArguments<'de> + Debug + Sync + Send;

    type GetArguments: Default + for<'de> DeserializeArguments<'de> + Debug + Sync + Send;
    type SetArguments<'de>: Default + DeserializeArguments<'de> + Debug + Sync + Send;
    type QueryArguments: Default + for<'de> DeserializeArguments<'de> + Debug + Sync + Send;
    type CopyArguments: Default + for<'de> DeserializeArguments<'de> + Debug + Sync + Send;
    type ParseArguments: Default + for<'de> DeserializeArguments<'de> + Debug + Sync + Send;

    const ID_PROPERTY: Self::Property;
}

pub trait JmapSharedObject: JmapObject {
    type Right: JmapRight + Into<Self::Property> + Debug + Clone + Copy + Sync + Send;

    const SHARE_WITH_PROPERTY: Self::Property;
}

pub trait JmapRight: Clone + Copy + Sized + 'static {
    fn all_rights() -> &'static [Self];
    fn to_acl(&self) -> &'static [Acl];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AnyId {
    Id(Id),
    BlobId(BlobId),
}

pub trait JmapObjectId {
    fn as_id(&self) -> Option<Id>;
    fn as_any_id(&self) -> Option<AnyId>;
    fn as_id_ref(&self) -> Option<&str>;
    fn try_set_id(&mut self, new_id: AnyId) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MaybeReference<T: FromStr> {
    Value(T),
    Reference(String),
    ParseError,
}

fn parse_ref<T: FromStr>(value: &str) -> MaybeReference<T> {
    if let Some(reference) = value.strip_prefix('#') {
        MaybeReference::Reference(reference.to_string())
    } else {
        T::from_str(value)
            .map(MaybeReference::Value)
            .unwrap_or(MaybeReference::ParseError)
    }
}

impl From<Id> for AnyId {
    fn from(value: Id) -> Self {
        AnyId::Id(value)
    }
}

impl From<BlobId> for AnyId {
    fn from(value: BlobId) -> Self {
        AnyId::BlobId(value)
    }
}

impl TryFrom<AnyId> for Id {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        if let AnyId::Id(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl TryFrom<AnyId> for BlobId {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        if let AnyId::BlobId(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl<'de> serde::Deserialize<'de> for AnyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;
        if let Some(blob_id) = BlobId::from_base32(value) {
            Ok(AnyId::BlobId(blob_id))
        } else if let Ok(id) = Id::from_str(value) {
            Ok(AnyId::Id(id))
        } else {
            Err(serde::de::Error::custom(format!(
                "Invalid AnyId: {}",
                value
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct NullObject;

impl JmapObject for NullObject {
    type Property = Null;
    type Element = Null;
    type Id = Null;

    type Filter = ();
    type Comparator = ();

    type GetArguments = ();
    type SetArguments<'de> = ();
    type QueryArguments = ();
    type CopyArguments = ();
    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = Null;
}

impl JmapRight for Null {
    fn all_rights() -> &'static [Self] {
        unreachable!()
    }

    fn to_acl(&self) -> &'static [Acl] {
        unreachable!()
    }
}

impl FromStr for NullObject {
    type Err = ();

    fn from_str(_: &str) -> Result<Self, Self::Err> {
        unreachable!()
    }
}

impl JmapObjectId for Null {
    fn as_id(&self) -> Option<Id> {
        unreachable!()
    }

    fn as_any_id(&self) -> Option<AnyId> {
        unreachable!()
    }

    fn as_id_ref(&self) -> Option<&str> {
        unreachable!()
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        unreachable!()
    }
}

impl TryFrom<AnyId> for Null {
    type Error = ();

    fn try_from(_: AnyId) -> Result<Self, Self::Error> {
        unreachable!()
    }
}
