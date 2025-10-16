/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        AnyId, JmapObject, JmapObjectId, JmapRight, JmapSharedObject, MaybeReference, parse_ref,
    },
    request::{deserialize::DeserializeArguments, reference::MaybeIdReference},
    types::date::UTCDate,
};
use calcard::{
    common::{IanaParse, timezone::Tz},
    icalendar::ICalendarDuration,
    jscalendar::{JSCalendarAlertAction, JSCalendarRelativeTo, JSCalendarType},
};
use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property};
use std::{borrow::Cow, fmt::Display, str::FromStr};
use types::{acl::Acl, id::Id};

#[derive(Debug, Clone, Default)]
pub struct Calendar;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarProperty {
    Id,
    Name,
    Description,
    Color,
    SortOrder,
    IsSubscribed,
    IsVisible,
    IsDefault,
    IncludeInAvailability,
    DefaultAlertsWithTime,
    DefaultAlertsWithoutTime,
    TimeZone,
    ShareWith,
    MyRights,

    // Alert object properties
    When,
    Trigger,
    Offset,
    RelativeTo,
    Action,
    Type,

    // Other
    IdValue(Id),
    Rights(CalendarRight),
    Pointer(JsonPointer<CalendarProperty>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarRight {
    MayReadFreeBusy,
    MayReadItems,
    MayWriteAll,
    MayWriteOwn,
    MayUpdatePrivate,
    MayRSVP,
    MayShare,
    MayDelete,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CalendarValue {
    Id(Id),
    IdReference(String),
    IncludeInAvailability(IncludeInAvailability),
    Date(UTCDate),
    Timezone(Tz),
    Action(JSCalendarAlertAction),
    RelativeTo(JSCalendarRelativeTo),
    Type(JSCalendarType),
    Duration(ICalendarDuration),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IncludeInAvailability {
    #[default]
    All,
    Attending,
    None,
}

impl Property for CalendarProperty {
    fn try_parse(key: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        let allow_patch = key.is_none();
        if let Some(Key::Property(key)) = key {
            match key.patch_or_prop() {
                CalendarProperty::ShareWith => {
                    Id::from_str(value).ok().map(CalendarProperty::IdValue)
                }
                _ => CalendarProperty::parse(value, allow_patch),
            }
        } else {
            CalendarProperty::parse(value, allow_patch)
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CalendarProperty::Id => "id",
            CalendarProperty::Name => "name",
            CalendarProperty::Description => "description",
            CalendarProperty::Color => "color",
            CalendarProperty::SortOrder => "sortOrder",
            CalendarProperty::IsSubscribed => "isSubscribed",
            CalendarProperty::IsVisible => "isVisible",
            CalendarProperty::IsDefault => "isDefault",
            CalendarProperty::IncludeInAvailability => "includeInAvailability",
            CalendarProperty::DefaultAlertsWithTime => "defaultAlertsWithTime",
            CalendarProperty::DefaultAlertsWithoutTime => "defaultAlertsWithoutTime",
            CalendarProperty::TimeZone => "timeZone",
            CalendarProperty::ShareWith => "shareWith",
            CalendarProperty::MyRights => "myRights",
            CalendarProperty::When => "when",
            CalendarProperty::Trigger => "trigger",
            CalendarProperty::Offset => "offset",
            CalendarProperty::RelativeTo => "relativeTo",
            CalendarProperty::Action => "action",
            CalendarProperty::Type => "@type",
            CalendarProperty::Rights(calendar_right) => calendar_right.as_str(),
            CalendarProperty::Pointer(json_pointer) => return json_pointer.to_string().into(),
            CalendarProperty::IdValue(id) => return id.to_string().into(),
        }
        .into()
    }
}

impl CalendarRight {
    pub fn as_str(&self) -> &'static str {
        match self {
            CalendarRight::MayReadFreeBusy => "mayReadFreeBusy",
            CalendarRight::MayReadItems => "mayReadItems",
            CalendarRight::MayWriteAll => "mayWriteAll",
            CalendarRight::MayWriteOwn => "mayWriteOwn",
            CalendarRight::MayUpdatePrivate => "mayUpdatePrivate",
            CalendarRight::MayRSVP => "mayRSVP",
            CalendarRight::MayShare => "mayShare",
            CalendarRight::MayDelete => "mayDelete",
        }
    }
}

impl IncludeInAvailability {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"all" => IncludeInAvailability::All,
            b"attending" => IncludeInAvailability::Attending,
            b"none" => IncludeInAvailability::None,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            IncludeInAvailability::All => "all",
            IncludeInAvailability::Attending => "attending",
            IncludeInAvailability::None => "none",
        }
    }
}

impl Element for CalendarValue {
    type Property = CalendarProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop.patch_or_prop() {
                CalendarProperty::Id => match parse_ref(value) {
                    MaybeReference::Value(v) => Some(CalendarValue::Id(v)),
                    MaybeReference::Reference(v) => Some(CalendarValue::IdReference(v)),
                    MaybeReference::ParseError => None,
                },
                CalendarProperty::TimeZone => Tz::from_str(value).ok().map(CalendarValue::Timezone),
                CalendarProperty::IncludeInAvailability => {
                    IncludeInAvailability::parse(value).map(CalendarValue::IncludeInAvailability)
                }
                CalendarProperty::Action => JSCalendarAlertAction::from_str(value)
                    .ok()
                    .map(CalendarValue::Action),
                CalendarProperty::RelativeTo => JSCalendarRelativeTo::from_str(value)
                    .ok()
                    .map(CalendarValue::RelativeTo),
                CalendarProperty::When => UTCDate::from_str(value).ok().map(CalendarValue::Date),
                CalendarProperty::Offset => {
                    ICalendarDuration::parse(value.as_bytes()).map(CalendarValue::Duration)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            CalendarValue::Id(id) => id.to_string().into(),
            CalendarValue::IdReference(r) => format!("#{r}").into(),
            CalendarValue::IncludeInAvailability(include) => include.as_str().into(),
            CalendarValue::Date(date) => date.to_string().into(),
            CalendarValue::Action(action) => action.as_str().into(),
            CalendarValue::RelativeTo(relative) => relative.as_str().into(),
            CalendarValue::Type(typ) => typ.as_str().into(),
            CalendarValue::Duration(dur) => dur.to_string().into(),
            CalendarValue::Timezone(tz) => tz.name().unwrap_or_default(),
        }
    }
}

impl CalendarProperty {
    fn parse(value: &str, allow_patch: bool) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => CalendarProperty::Id,
            b"name" => CalendarProperty::Name,
            b"description" => CalendarProperty::Description,
            b"color" => CalendarProperty::Color,
            b"sortOrder" => CalendarProperty::SortOrder,
            b"isSubscribed" => CalendarProperty::IsSubscribed,
            b"isVisible" => CalendarProperty::IsVisible,
            b"isDefault" => CalendarProperty::IsDefault,
            b"includeInAvailability" => CalendarProperty::IncludeInAvailability,
            b"defaultAlertsWithTime" => CalendarProperty::DefaultAlertsWithTime,
            b"defaultAlertsWithoutTime" => CalendarProperty::DefaultAlertsWithoutTime,
            b"timeZone" => CalendarProperty::TimeZone,
            b"shareWith" => CalendarProperty::ShareWith,
            b"myRights" => CalendarProperty::MyRights,
            b"mayReadFreeBusy" => CalendarProperty::Rights(CalendarRight::MayReadFreeBusy),
            b"mayReadItems" => CalendarProperty::Rights(CalendarRight::MayReadItems),
            b"mayWriteAll" => CalendarProperty::Rights(CalendarRight::MayWriteAll),
            b"mayWriteOwn" => CalendarProperty::Rights(CalendarRight::MayWriteOwn),
            b"mayUpdatePrivate" => CalendarProperty::Rights(CalendarRight::MayUpdatePrivate),
            b"mayRSVP" => CalendarProperty::Rights(CalendarRight::MayRSVP),
            b"mayShare" => CalendarProperty::Rights(CalendarRight::MayShare),
            b"mayDelete" => CalendarProperty::Rights(CalendarRight::MayDelete),
            b"@type" => CalendarProperty::Type,
            b"when" => CalendarProperty::When,
            b"trigger" => CalendarProperty::Trigger,
            b"offset" => CalendarProperty::Offset,
            b"relativeTo" => CalendarProperty::RelativeTo,
            b"action" => CalendarProperty::Action,
        )
        .or_else(|| {
            if allow_patch && value.contains('/') {
                CalendarProperty::Pointer(JsonPointer::parse(value)).into()
            } else {
                None
            }
        })
    }

    fn patch_or_prop(&self) -> &CalendarProperty {
        if let CalendarProperty::Pointer(ptr) = self
            && let Some(JsonPointerItem::Key(Key::Property(prop))) = ptr.last()
        {
            prop
        } else {
            self
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CalendarSetArguments {
    pub on_destroy_remove_events: Option<bool>,
    pub on_success_set_is_default: Option<MaybeIdReference<Id>>,
}

impl<'de> DeserializeArguments<'de> for CalendarSetArguments {
    fn deserialize_argument<A>(&mut self, key: &str, map: &mut A) -> Result<(), A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"onDestroyRemoveEvents" => {
                self.on_destroy_remove_events = map.next_value()?;
            },
            b"onSuccessSetIsDefault" => {
                self.on_success_set_is_default = map.next_value()?;
            },
            _ => {
                let _ = map.next_value::<serde::de::IgnoredAny>()?;
            }
        );

        Ok(())
    }
}

impl FromStr for CalendarProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CalendarProperty::parse(s, false).ok_or(())
    }
}

impl JmapObject for Calendar {
    type Property = CalendarProperty;

    type Element = CalendarValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = CalendarSetArguments;

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = CalendarProperty::Id;
}

impl JmapSharedObject for Calendar {
    type Right = CalendarRight;

    const SHARE_WITH_PROPERTY: Self::Property = CalendarProperty::ShareWith;
}

impl From<Id> for CalendarProperty {
    fn from(id: Id) -> Self {
        CalendarProperty::IdValue(id)
    }
}

impl TryFrom<CalendarProperty> for Id {
    type Error = ();

    fn try_from(value: CalendarProperty) -> Result<Self, Self::Error> {
        if let CalendarProperty::IdValue(id) = value {
            Ok(id)
        } else {
            Err(())
        }
    }
}

impl TryFrom<CalendarProperty> for CalendarRight {
    type Error = ();

    fn try_from(value: CalendarProperty) -> Result<Self, Self::Error> {
        if let CalendarProperty::Rights(right) = value {
            Ok(right)
        } else {
            Err(())
        }
    }
}

impl From<Id> for CalendarValue {
    fn from(id: Id) -> Self {
        CalendarValue::Id(id)
    }
}

impl JmapObjectId for CalendarValue {
    fn as_id(&self) -> Option<Id> {
        if let CalendarValue::Id(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let CalendarValue::Id(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        if let CalendarValue::IdReference(r) = self {
            Some(r)
        } else {
            None
        }
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(new_id) = new_id {
            *self = CalendarValue::Id(new_id);
            return true;
        }
        false
    }
}

impl JmapRight for CalendarRight {
    fn to_acl(&self) -> &'static [Acl] {
        match self {
            CalendarRight::MayReadFreeBusy => &[Acl::SchedulingReadFreeBusy],
            CalendarRight::MayReadItems => &[Acl::Read, Acl::ReadItems],
            CalendarRight::MayWriteAll => &[
                Acl::Modify,
                Acl::AddItems,
                Acl::ModifyItems,
                Acl::RemoveItems,
            ],
            CalendarRight::MayWriteOwn => &[Acl::ModifyItemsOwn],
            CalendarRight::MayUpdatePrivate => &[Acl::ModifyPrivateProperties],
            CalendarRight::MayRSVP => &[Acl::ModifyRSVP],
            CalendarRight::MayShare => &[Acl::Share],
            CalendarRight::MayDelete => &[Acl::Delete, Acl::RemoveItems],
        }
    }

    fn all_rights() -> &'static [Self] {
        &[
            CalendarRight::MayReadFreeBusy,
            CalendarRight::MayReadItems,
            CalendarRight::MayWriteAll,
            CalendarRight::MayWriteOwn,
            CalendarRight::MayUpdatePrivate,
            CalendarRight::MayRSVP,
            CalendarRight::MayShare,
            CalendarRight::MayDelete,
        ]
    }
}

impl From<CalendarRight> for CalendarProperty {
    fn from(right: CalendarRight) -> Self {
        CalendarProperty::Rights(right)
    }
}

impl JmapObjectId for CalendarProperty {
    fn as_id(&self) -> Option<Id> {
        if let CalendarProperty::IdValue(id) = self {
            Some(*id)
        } else {
            None
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        if let CalendarProperty::IdValue(id) = self {
            Some(AnyId::Id(*id))
        } else {
            None
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(new_id) = new_id {
            *self = CalendarProperty::IdValue(new_id);
            return true;
        }
        false
    }
}

impl Display for CalendarProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_cow())
    }
}
