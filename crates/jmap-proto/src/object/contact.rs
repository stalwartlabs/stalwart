/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    request::{MaybeInvalid, deserialize::DeserializeArguments},
    types::date::UTCDate,
};
use calcard::jscontact::{JSContactProperty, JSContactValue};
use jmap_tools::{JsonPointerItem, Key};
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
                *self = ContactCardFilter::Text(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"name" => {
                *self = ContactCardFilter::Name(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"name/given" => {
                *self = ContactCardFilter::NameGiven(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"name/surname" => {
                *self = ContactCardFilter::NameSurname(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"name/surname2" => {
                *self = ContactCardFilter::NameSurname2(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"nickname" => {
                *self = ContactCardFilter::Nickname(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"organization" => {
                *self = ContactCardFilter::Organization(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"email" => {
                *self = ContactCardFilter::Email(map.next_value()?);
            },
            b"phone" => {
                *self = ContactCardFilter::Phone(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"onlineService" => {
                *self = ContactCardFilter::OnlineService(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"address" => {
                *self = ContactCardFilter::Address(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            b"note" => {
                *self = ContactCardFilter::Note(map.next_value::<Cow<str>>()?.to_lowercase());
            },
            _ => {
                *self = ContactCardFilter::_T(key.to_string());
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
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
            let value = map.next_value::<Cow<str>>()?;
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
                    *self = ContactCardComparator::_T(value.to_string());
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
