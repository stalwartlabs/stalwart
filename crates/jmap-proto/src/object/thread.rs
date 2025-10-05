/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Key, Property};
use std::{borrow::Cow, str::FromStr};
use types::id::Id;

use crate::object::{AnyId, JmapObject, JmapObjectId};

#[derive(Debug, Clone, Default)]
pub struct Thread;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreadProperty {
    Id,
    EmailIds,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreadValue {
    Id(Id),
}

impl Property for ThreadProperty {
    fn try_parse(_: Option<&Key<'_, Self>>, value: &str) -> Option<Self> {
        ThreadProperty::parse(value)
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ThreadProperty::Id => "id",
            ThreadProperty::EmailIds => "emailIds",
        }
        .into()
    }
}

impl Element for ThreadValue {
    type Property = ThreadProperty;

    fn try_parse<P>(key: &Key<'_, Self::Property>, value: &str) -> Option<Self> {
        if let Key::Property(_) = key {
            Id::from_str(value).ok().map(ThreadValue::Id)
        } else {
            None
        }
    }

    fn to_cow(&self) -> Cow<'static, str> {
        match self {
            ThreadValue::Id(id) => id.to_string().into(),
        }
    }
}

impl ThreadProperty {
    fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            b"id" => ThreadProperty::Id,
            b"emailIds" => ThreadProperty::EmailIds,
        )
    }
}

impl FromStr for ThreadProperty {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ThreadProperty::parse(s).ok_or(())
    }
}

impl JmapObject for Thread {
    type Property = ThreadProperty;

    type Element = ThreadValue;

    type Id = Id;

    type Filter = ();

    type Comparator = ();

    type GetArguments = ();

    type SetArguments<'de> = ();

    type QueryArguments = ();

    type CopyArguments = ();

    type ParseArguments = ();

    const ID_PROPERTY: Self::Property = ThreadProperty::Id;
}

impl From<Id> for ThreadValue {
    fn from(id: Id) -> Self {
        ThreadValue::Id(id)
    }
}

impl JmapObjectId for ThreadValue {
    fn as_id(&self) -> Option<Id> {
        match self {
            ThreadValue::Id(id) => Some(*id),
        }
    }

    fn as_any_id(&self) -> Option<AnyId> {
        self.as_id().map(AnyId::Id)
    }

    fn as_id_ref(&self) -> Option<&str> {
        None
    }

    fn try_set_id(&mut self, new_id: AnyId) -> bool {
        if let AnyId::Id(id) = new_id {
            *self = ThreadValue::Id(id);
            true
        } else {
            false
        }
    }
}

impl JmapObjectId for ThreadProperty {
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
