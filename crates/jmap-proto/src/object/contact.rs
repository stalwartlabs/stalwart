/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        AnyId, JmapObject, JmapObjectId,
        metadata::{MetadataFilter, MetadataProperty, MetadataRoot},
    },
    request::{
        MaybeInvalid,
        deserialize::{CowStr, DeserializeArguments, next_lowercase_value},
    },
    types::date::UTCDate,
};
use calcard::jscontact::{JSContactProperty, JSContactValue};
use jmap_tools::{JsonPointer, JsonPointerItem, Key};
use std::borrow::Cow;
use types::{blob::BlobId, id::Id};

#[derive(Debug, Clone, Default)]
pub struct ContactCard;

impl JmapObject for ContactCard {
    type Property = JSContactProperty<Id>;

    type Element = JSContactValue<Id, BlobId>;

    type Id = Id;

    type Filter = ContactCardFilter;

    type Comparator = ContactCardComparator;

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
        match self {
            JSContactValue::IdReference(r) => Some(r),
            _ => None,
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        match new_id {
            AnyId::Id(id) => {
                *self = JSContactValue::Id(id);
            }
            AnyId::BlobId(id) => {
                *self = JSContactValue::BlobId(id);
            }
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactCardFilter {
    InAddressBook(MaybeInvalid<Id>),
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
    Metadata(MetadataFilter),
    _T(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactCardComparator {
    Created,
    Updated,
    NameGiven,
    NameSurname,
    NameSurname2,
    _T(String),
}

impl<'de> DeserializeArguments<'de> for ContactCardFilter {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"inAddressBook" => {
                *self = ContactCardFilter::InAddressBook(map.next_value()?);
            },
            b"uid" => {
                *self = ContactCardFilter::Uid(map.next_value()?);
            },
            b"hasMember" => {
                *self = ContactCardFilter::HasMember(map.next_value()?);
            },
            b"kind" => {
                *self = ContactCardFilter::Kind(map.next_value()?);
            },
            b"createdBefore" => {
                *self = ContactCardFilter::CreatedBefore(map.next_value()?);
            },
            b"createdAfter" => {
                *self = ContactCardFilter::CreatedAfter(map.next_value()?);
            },
            b"updatedBefore" => {
                *self = ContactCardFilter::UpdatedBefore(map.next_value()?);
            },
            b"updatedAfter" => {
                *self = ContactCardFilter::UpdatedAfter(map.next_value()?);
            },
            b"text" => {
                *self = ContactCardFilter::Text(next_lowercase_value(map)?);
            },
            b"name" => {
                *self = ContactCardFilter::Name(next_lowercase_value(map)?);
            },
            b"name/given" => {
                *self = ContactCardFilter::NameGiven(next_lowercase_value(map)?);
            },
            b"name/surname" => {
                *self = ContactCardFilter::NameSurname(next_lowercase_value(map)?);
            },
            b"name/surname2" => {
                *self = ContactCardFilter::NameSurname2(next_lowercase_value(map)?);
            },
            b"nickname" => {
                *self = ContactCardFilter::Nickname(next_lowercase_value(map)?);
            },
            b"organization" => {
                *self = ContactCardFilter::Organization(next_lowercase_value(map)?);
            },
            b"email" => {
                *self = ContactCardFilter::Email(next_lowercase_value(map)?);
            },
            b"phone" => {
                *self = ContactCardFilter::Phone(next_lowercase_value(map)?);
            },
            b"onlineService" => {
                *self = ContactCardFilter::OnlineService(next_lowercase_value(map)?);
            },
            b"address" => {
                *self = ContactCardFilter::Address(next_lowercase_value(map)?);
            },
            b"note" => {
                *self = ContactCardFilter::Note(next_lowercase_value(map)?);
            },
            _ => {
                *self = match MetadataFilter::try_deserialize(key, map)? {
                    Some(filter) => ContactCardFilter::Metadata(filter),
                    None => {
                        let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        ContactCardFilter::_T(key.to_string())
                    }
                };
            }
        );
        Ok(())
    }
}

impl<'de> DeserializeArguments<'de> for ContactCardComparator {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        if key == "property" {
            let value = map.next_value::<CowStr>()?.0;
            hashify::fnc_map!(value.as_bytes(),
                b"created" => {
                    *self = ContactCardComparator::Created;
                },
                b"updated" => {
                    *self = ContactCardComparator::Updated;
                },
                b"name/given" => {
                    *self = ContactCardComparator::NameGiven;
                },
                b"name/surname" => {
                    *self = ContactCardComparator::NameSurname;
                },
                b"name/surname2" => {
                    *self = ContactCardComparator::NameSurname2;
                },
                _ => {
                    *self = ContactCardComparator::_T(value.into_owned());
                }
            );
        } else {
            let _ = map.next_value::<serde::de::IgnoredAny>()?;
        }
        Ok(())
    }
}

impl ContactCardFilter {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ContactCardFilter::InAddressBook(_) => "inAddressBook",
            ContactCardFilter::Uid(_) => "uid",
            ContactCardFilter::HasMember(_) => "hasMember",
            ContactCardFilter::Kind(_) => "kind",
            ContactCardFilter::CreatedBefore(_) => "createdBefore",
            ContactCardFilter::CreatedAfter(_) => "createdAfter",
            ContactCardFilter::UpdatedBefore(_) => "updatedBefore",
            ContactCardFilter::UpdatedAfter(_) => "updatedAfter",
            ContactCardFilter::Text(_) => "text",
            ContactCardFilter::Name(_) => "name",
            ContactCardFilter::NameGiven(_) => "name/given",
            ContactCardFilter::NameSurname(_) => "name/surname",
            ContactCardFilter::NameSurname2(_) => "name/surname2",
            ContactCardFilter::Nickname(_) => "nickname",
            ContactCardFilter::Organization(_) => "organization",
            ContactCardFilter::Email(_) => "email",
            ContactCardFilter::Phone(_) => "phone",
            ContactCardFilter::OnlineService(_) => "onlineService",
            ContactCardFilter::Address(_) => "address",
            ContactCardFilter::Note(_) => "note",
            ContactCardFilter::Metadata(filter) => filter.as_str(),
            ContactCardFilter::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl ContactCardComparator {
    pub fn into_string(self) -> Cow<'static, str> {
        match self {
            ContactCardComparator::Created => "created",
            ContactCardComparator::Updated => "updated",
            ContactCardComparator::NameGiven => "name/given",
            ContactCardComparator::NameSurname => "name/surname",
            ContactCardComparator::NameSurname2 => "name/surname2",
            ContactCardComparator::_T(s) => return Cow::Owned(s),
        }
        .into()
    }
}

impl Default for ContactCardFilter {
    fn default() -> Self {
        ContactCardFilter::_T(String::new())
    }
}

impl Default for ContactCardComparator {
    fn default() -> Self {
        ContactCardComparator::_T(String::new())
    }
}

impl MetadataProperty for JSContactProperty<Id> {
    fn as_metadata_root(&self) -> Option<MetadataRoot> {
        match self {
            JSContactProperty::Metadata => Some(MetadataRoot::Shared),
            JSContactProperty::PrivateMetadata => Some(MetadataRoot::Private),
            _ => None,
        }
    }

    fn as_pointer(&self) -> Option<&JsonPointer<Self>> {
        match self {
            JSContactProperty::Pointer(pointer) => Some(pointer),
            _ => None,
        }
    }

    fn from_metadata_root(root: MetadataRoot) -> Self {
        match root {
            MetadataRoot::Shared => JSContactProperty::Metadata,
            MetadataRoot::Private => JSContactProperty::PrivateMetadata,
        }
    }
}

impl JmapObjectId for JSContactProperty<Id> {
    fn as_id(&self) -> Option<Id> {
        if let JSContactProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let JSContactProperty::IdValue(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        match self {
            JSContactProperty::IdReference(r) => Some(r),
            JSContactProperty::Pointer(value) => {
                let value = value.as_slice();
                match (value.first(), value.get(1)) {
                    (
                        Some(JsonPointerItem::Key(Key::Property(
                            JSContactProperty::AddressBookIds,
                        ))),
                        Some(JsonPointerItem::Key(Key::Property(JSContactProperty::IdReference(
                            r,
                        )))),
                    ) => Some(r),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            if let JSContactProperty::Pointer(value) = self {
                let value = value.as_mut_slice();
                if let Some(value) = value.get_mut(1) {
                    *value = JsonPointerItem::Key(Key::Property(JSContactProperty::IdValue(id)));
                    return true;
                }
            } else {
                *self = JSContactProperty::IdValue(id);
                return true;
            }
        }
        false
    }
}
