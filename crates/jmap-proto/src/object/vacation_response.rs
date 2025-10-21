/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObject, JmapObjectId},
    types::date::UTCDate,
};
use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

#[derive(Debug, Clone, Default)]
pub struct VacationResponse;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VacationResponseProperty {
    Id,
    IsEnabled,
    FromDate,
    ToDate,
    Subject,
    TextBody,
    HtmlBody,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VacationResponseValue {
    Id(Id),
    Date(UTCDate),
}

impl Property for VacationResponseProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        VacationResponseProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            VacationResponseProperty::HtmlBody => "htmlBody",
            VacationResponseProperty::Id => "id",
            VacationResponseProperty::TextBody => "textBody",
            VacationResponseProperty::FromDate => "fromDate",
            VacationResponseProperty::IsEnabled => "isEnabled",
            VacationResponseProperty::ToDate => "toDate",
            VacationResponseProperty::Subject => "subject",
        }
        .into()
    }
}

impl Element for VacationResponseValue {
    type Property = VacationResponseProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(prop) = key {
            match prop {
                VacationResponseProperty::Id => {
                    Id::from_str(value).ok().map(VacationResponseValue::Id)
                }
                VacationResponseProperty::FromDate | VacationResponseProperty::ToDate => {
                    UTCDate::from_str(value)
                        .ok()
                        .map(VacationResponseValue::Date)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            VacationResponseValue::Id(id) => id.to_string().into(),
            VacationResponseValue::Date(utcdate) => utcdate.to_string().into(),
        }
    }
}

impl VacationResponseProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => VacationResponseProperty::Id,
            b"isEnabled" => VacationResponseProperty::IsEnabled,
            b"fromDate" => VacationResponseProperty::FromDate,
            b"toDate" => VacationResponseProperty::ToDate,
            b"textBody" => VacationResponseProperty::TextBody,
            b"htmlBody" => VacationResponseProperty::HtmlBody,
            b"subject" => VacationResponseProperty::Subject,
        )
    }
}

impl FromStr for VacationResponseProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        VacationResponseProperty::parse(s).ok_or(())
    }
}

impl JmapObject for VacationResponse {
    type Property = VacationResponseProperty;

    type Element = VacationResponseValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = VacationResponseProperty::Id;
}

impl From<Id> for VacationResponseValue {
    fn from(id: Id) -> Self {
        VacationResponseValue::Id(id)
    }
}

impl JmapObjectId for VacationResponseValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            VacationResponseValue::Id(id) => Some(*id),
            _ => None,
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        match self {
            VacationResponseValue::Id(id) => Some(AnyId::Id(*id)),
            _ => None,
        }
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = VacationResponseValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for VacationResponseProperty {
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
