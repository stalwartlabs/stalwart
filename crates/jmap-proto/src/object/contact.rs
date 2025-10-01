/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::deserialize::DeserializeArguments,
    types::date::UTCDate,
};
use calcard::jscontact::{JSContactProperty, JSContactValue};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct ContactCard;

impl JmapObject for ContactCard {
    type Property = JSContactProperty<Id>;

    type Element = JSContactValue<Id, BlobId>;

    type Id = Id;

    type Filter = ContactFilter;

    type Comparator = ContactComparator;

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = JSContactProperty::Id;
}

impl JmapObjectId for JSContactValue<Id, BlobId> {
    fn as_id(&self) -> Option<Id> {
        if let JSContactValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            JSContactValue::Id(id) => Some(AnyId::Id(*id)),
            JSContactValue::BlobId(id) => Some(AnyId::BlobId(id.clone())),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }
}

impl TryFrom<AnyId> for JSContactValue<Id, BlobId> {
    type Error = ();

    fn try_from(value: AnyId) -> Result<Self, Self::Error> {
        match value {
            AnyId::Id(id) => Ok(JSContactValue::Id(id)),
            AnyId::BlobId(id) => Ok(JSContactValue::BlobId(id)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactFilter {
    InAddressBook(Id),
    Uid(String),
    HasMember(String),
    Kind(String),
    CreatedBefore(UTCDate),
    CreatedAfter(UTCDate),
    UpdatedBefore(UTCDate),
    UpdatedAfter(UTCDate),
    Text(String),
    Name(String),
    NameGiven(String),
    NameSurname(String),
    NameSurname2(String),
    Nickname(String),
    Organization(String),
    Email(String),
    Phone(String),
    OnlineService(String),
    Address(String),
    Note(String),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactComparator {
    Created,
    Updated,
    NameGiven,
    NameSurname,
    NameSurname2,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for ContactFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"inAddressBook" => {
                *self = ContactFilter::InAddressBook(map.next_value()?);
            },
            b"uid" => {
                *self = ContactFilter::Uid(map.next_value()?);
            },
            b"hasMember" => {
                *self = ContactFilter::HasMember(map.next_value()?);
            },
            b"kind" => {
                *self = ContactFilter::Kind(map.next_value()?);
            },
            b"createdBefore" => {
                *self = ContactFilter::CreatedBefore(map.next_value()?);
            },
            b"createdAfter" => {
                *self = ContactFilter::CreatedAfter(map.next_value()?);
            },
            b"updatedBefore" => {
                *self = ContactFilter::UpdatedBefore(map.next_value()?);
            },
            b"updatedAfter" => {
                *self = ContactFilter::UpdatedAfter(map.next_value()?);
            },
            b"text" => {
                *self = ContactFilter::Text(map.next_value()?);
            },
            b"name" => {
                *self = ContactFilter::Name(map.next_value()?);
            },
            b"name/given" => {
                *self = ContactFilter::NameGiven(map.next_value()?);
            },
            b"name/surname" => {
                *self = ContactFilter::NameSurname(map.next_value()?);
            },
            b"name/surname2" => {
                *self = ContactFilter::NameSurname2(map.next_value()?);
            },
            b"nickname" => {
                *self = ContactFilter::Nickname(map.next_value()?);
            },
            b"organization" => {
                *self = ContactFilter::Organization(map.next_value()?);
            },
            b"email" => {
                *self = ContactFilter::Email(map.next_value()?);
            },
            b"phone" => {
                *self = ContactFilter::Phone(map.next_value()?);
            },
            b"onlineService" => {
                *self = ContactFilter::OnlineService(map.next_value()?);
            },
            b"address" => {
                *self = ContactFilter::Address(map.next_value()?);
            },
            b"note" => {
                *self = ContactFilter::Note(map.next_value()?);
            },
            _ => {
                *self = ContactFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for ContactComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<Cow<str>>()?;
            hashify::fnc_map!(value.as_bytes(),
                b"created" => {
                    *self = ContactComparator::Created;
                },
                b"updated" => {
                    *self = ContactComparator::Updated;
                },
                b"name/given" => {
                    *self = ContactComparator::NameGiven;
                },
                b"name/surname" => {
                    *self = ContactComparator::NameSurname;
                },
                b"name/surname2" => {
                    *self = ContactComparator::NameSurname2;
                },
                _ => {
                    *self = ContactComparator::_T(value.to_string());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl Default for ContactFilter {
    fn default() -> Self {
        ContactFilter::_T(String::new())
    }
}

impl Default for ContactComparator {
    fn default() -> Self {
        ContactComparator::_T(String::new())
    }
}
