/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::object::{AnyId, JmapObject, JmapObjectId};
use crate::types::date::UTCDate;
use jmap_tools::{Element, JsonPointer, JsonPointerItem};
use jmap_tools::{Key, Property};
use std::borrow::Cow;
use std::str::FromStr;
use types::{id::Id, type_state::DataType};

#[derive(Debug, Clone, Default)]
pub struct PushSubscription;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PushSubscriptionProperty {
    Id,
    DeviceClientId,
    Url,
    Keys,
    P256dh,
    Auth,
    VerificationCode,
    Expires,
    Types,

    // Other
    Pointer(JsonPointer<PushSubscriptionProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PushSubscriptionValue {
    Id(Id),
    Date(UTCDate),
    Types(DataType),
}

impl Property for PushSubscriptionProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        PushSubscriptionProperty::parse(value, key.is_none())
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PushSubscriptionProperty::DeviceClientId => "deviceClientId",
            PushSubscriptionProperty::Expires => "expires",
            PushSubscriptionProperty::Id => "id",
            PushSubscriptionProperty::Keys => "keys",
            PushSubscriptionProperty::Types => "types",
            PushSubscriptionProperty::Url => "url",
            PushSubscriptionProperty::VerificationCode => "verificationCode",
            PushSubscriptionProperty::P256dh => "p256dh",
            PushSubscriptionProperty::Auth => "auth",
            PushSubscriptionProperty::Pointer(json_pointer) => {
                return json_pointer.to_string().into();
            }
        }
        .into()
    }
}

impl PushSubscriptionProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => PushSubscriptionProperty::Id,
            b"deviceClientId" => PushSubscriptionProperty::DeviceClientId,
            b"url" => PushSubscriptionProperty::Url,
            b"keys" => PushSubscriptionProperty::Keys,
            b"p256dh" => PushSubscriptionProperty::P256dh,
            b"auth" => PushSubscriptionProperty::Auth,
            b"verificationCode" => PushSubscriptionProperty::VerificationCode,
            b"expires" => PushSubscriptionProperty::Expires,
            b"types" => PushSubscriptionProperty::Types,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                PushSubscriptionProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &PushSubscriptionProperty {
        if let PushSubscriptionProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

impl Element for PushSubscriptionValue {
    type Property = PushSubscriptionProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                PushSubscriptionProperty::Id => {
                    Id::from_str(value).ok().map(PushSubscriptionValue::Id)
                }
                PushSubscriptionProperty::Types => {
                    DataType::parse(value).map(PushSubscriptionValue::Types)
                }
                PushSubscriptionProperty::Expires => UTCDate::from_str(value)
                    .ok()
                    .map(PushSubscriptionValue::Date),
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            PushSubscriptionValue::Id(id) => id.to_string().into(),
            PushSubscriptionValue::Date(utcdate) => utcdate.to_string().into(),
            PushSubscriptionValue::Types(data_type) => data_type.as_str().into(),
        }
    }
}

impl FromStr for PushSubscriptionProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PushSubscriptionProperty::parse(s, false).ok_or(())
    }
}

impl JmapObject for PushSubscription {
    type Property = PushSubscriptionProperty;

    type Element = PushSubscriptionValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = PushSubscriptionProperty::Id;
}

impl From<Id> for PushSubscriptionValue {
    fn from(id: Id) -> Self {
        PushSubscriptionValue::Id(id)
    }
}

impl JmapObjectId for PushSubscriptionValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            PushSubscriptionValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            PushSubscriptionValue::Id(id) => Some(AnyId::Id(*id)),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = PushSubscriptionValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for PushSubscriptionProperty {
    fn as_id(&self) -> Option<Id> {
        None
    }

    fn as_any_id(&self) -> Option<AnyId> {
        None
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, _: AnyId) -> bool {
        false
    }
}
