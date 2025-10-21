/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    property::{DavProperty, DavValue, LockScope, LockType},
    response::Ace,
    Collation, MatchType,
};
use crate::Depth;
use calcard::{
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::{VCardParameterName, VCardProperty},
};
use types::{
    dead_property::{ArchivedDeadProperty, ArchivedDeadPropertyTag, DeadElementTag, DeadProperty},
    TimeRange,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum PropFind {
    #[default]
    PropName,
    AllProp(Vec<DavProperty>),
    Prop(Vec<DavProperty>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PropertyUpdate {
    pub set: Vec<DavPropertyValue>,
    pub remove: Vec<DavProperty>,
    pub set_first: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct DavPropertyValue {
    pub property: DavProperty,
    pub value: DavValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct MkCol {
    pub is_mkcalendar: bool,
    pub props: Vec<DavPropertyValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct LockInfo {
    pub lock_scope: LockScope,
    pub lock_type: LockType,
    pub owner: Option<DeadProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type"))]
pub enum Report {
    AddressbookQuery(AddressbookQuery),
    AddressbookMultiGet(MultiGet),
    CalendarQuery(CalendarQuery),
    CalendarMultiGet(MultiGet),
    FreeBusyQuery(FreeBusyQuery),
    SyncCollection(SyncCollection),
    ExpandProperty(ExpandProperty),
    AclPrincipalPropSet(AclPrincipalPropSet),
    PrincipalMatch(PrincipalMatch),
    PrincipalPropertySearch(PrincipalPropertySearch),
    PrincipalSearchPropertySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct ExpandProperty {
    pub properties: Vec<ExpandPropertyItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct ExpandPropertyItem {
    pub property: DavProperty,
    pub depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct AddressbookQuery {
    pub properties: PropFind,
    pub filters: Vec<Filter<(), VCardPropertyWithGroup, VCardParameterName>>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct VCardPropertyWithGroup {
    pub name: VCardProperty,
    pub group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct CalendarQuery {
    pub properties: PropFind,
    pub filters:
        Vec<Filter<Vec<ICalendarComponentType>, ICalendarProperty, ICalendarParameterName>>,
    pub timezone: Timezone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type"))]
pub enum Timezone {
    Name(String),
    Id(String),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct FreeBusyQuery {
    pub range: Option<TimeRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct MultiGet {
    pub properties: PropFind,
    pub hrefs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct SyncCollection {
    pub sync_token: Option<String>,
    pub properties: PropFind,
    pub depth: Depth,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type"))]
pub enum Filter<A, B, C> {
    AnyOf,
    AllOf,
    Component {
        comp: A,
        op: FilterOp,
    },
    Property {
        comp: A,
        prop: B,
        op: FilterOp,
    },
    Parameter {
        comp: A,
        prop: B,
        param: C,
        op: FilterOp,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type", content = "data"))]
pub enum FilterOp {
    Exists,
    Undefined,
    TimeRange(TimeRange),
    TextMatch(TextMatch),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, serde(tag = "type"))]
pub struct TextMatch {
    pub match_type: MatchType,
    pub value: String,
    pub collation: Collation,
    pub negate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct Acl {
    pub aces: Vec<Ace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct AclPrincipalPropSet {
    pub properties: Vec<DavProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PrincipalMatch {
    pub principal_properties: PrincipalMatchProperties,
    pub properties: Vec<DavProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum PrincipalMatchProperties {
    Properties(Vec<DavProperty>),
    Self_,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PrincipalPropertySearch {
    pub property_search: Vec<PropertySearch>,
    pub properties: Vec<DavProperty>,
    pub apply_to_principal_collection_set: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct PropertySearch {
    pub property: DavProperty,
    pub match_: String,
}

impl PropertyUpdate {
    pub fn has_changes(&self) -> bool {
        !self.set.is_empty() || !self.remove.is_empty()
    }
}

impl FreeBusyQuery {
    pub fn new(start: i64, end: i64) -> Self {
        FreeBusyQuery {
            range: Some(TimeRange { start, end }),
        }
    }
}

pub trait DavDeadProperty {
    fn to_dav_values(&self, output: &mut Vec<DavPropertyValue>);
}

impl DavDeadProperty for ArchivedDeadProperty {
    fn to_dav_values(&self, output: &mut Vec<DavPropertyValue>) {
        let mut depth: u32 = 0;
        let mut tags = Vec::new();
        let mut tag_start = None;

        for tag in self.0.iter() {
            match tag {
                ArchivedDeadPropertyTag::ElementStart(start) => {
                    if depth == 0 {
                        tag_start = Some(DeadElementTag::from(start));
                    } else {
                        tags.push(tag.into());
                    }

                    depth += 1;
                }
                ArchivedDeadPropertyTag::ElementEnd => {
                    depth = depth.saturating_sub(1);

                    if depth > 0 {
                        tags.push(tag.into());
                    } else if let Some(tag_start) = tag_start.take() {
                        output.push(DavPropertyValue::new(
                            DavProperty::DeadProperty(tag_start),
                            DavValue::DeadProperty(DeadProperty(std::mem::take(&mut tags))),
                        ));
                    }
                }
                ArchivedDeadPropertyTag::Text(_) => {
                    if tag_start.is_some() {
                        tags.push(tag.into());
                    }
                }
            }
        }
    }
}
