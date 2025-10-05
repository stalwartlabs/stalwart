/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    method::{
        PropertyWrapper,
        availability::{BusyPeriod, GetAvailabilityResponse},
        changes::ChangesResponse,
        get::GetResponse,
        query::QueryResponse,
        query_changes::{AddedItem, QueryChangesResponse},
    },
    object::{
        AnyId, JmapObject, JmapObjectId,
        calendar_event_notification::{
            CalendarEventNotificationGetResponse, CalendarEventNotificationObject,
        },
    },
    request::reference::ResultReference,
};
use compact_str::format_compact;
use jmap_tools::{Element, JsonPointerItem, JsonPointerIter, Key, Null, Property, Value};
use std::{borrow::Cow, str::FromStr};
use types::{blob::BlobId, id::Id};

pub(crate) trait ResponsePtr {
    fn eval_jptr(&self, pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool;
}

#[derive(Debug, Default)]
#[repr(transparent)]
pub(crate) struct EvalResults(Vec<EvalResult>);

#[derive(Debug)]
pub(crate) enum EvalResult {
    Id(AnyId),
    Property(Cow<'static, str>),
}

impl<T> ResponsePtr for Vec<T>
where
    T: ResponsePtr,
{
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next() {
            Some(JsonPointerItem::Number(n)) => {
                if let Some(v) = self.get(*n as usize) {
                    v.eval_jptr(pointer, results);
                }
            }
            Some(JsonPointerItem::Wildcard | JsonPointerItem::Root) | None => {
                for v in self {
                    v.eval_jptr(pointer.clone(), results);
                }
            }
            _ => (),
        }

        true
    }
}

impl<'ctx, P, E> ResponsePtr for Value<'ctx, P, E>
where
    P: Property,
    E: Element<Property = P> + JmapObjectId,
{
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next() {
            Some(JsonPointerItem::Key(key)) => {
                if let Some(key) = key.as_string_key()
                    && let Value::Object(map) = self
                    && let Some(v) = map.get(&Key::Borrowed(key))
                {
                    v.eval_jptr(pointer, results);
                }
            }
            Some(JsonPointerItem::Number(n)) => match self {
                Value::Array(values) => {
                    if let Some(v) = values.get(*n as usize) {
                        v.eval_jptr(pointer, results);
                    }
                }
                Value::Object(map) => {
                    let n = Key::Owned(n.to_string());
                    if let Some(v) = map.get(&n) {
                        v.eval_jptr(pointer, results);
                    }
                }
                _ => {}
            },
            Some(JsonPointerItem::Wildcard) => match self {
                Value::Array(values) => {
                    for v in values {
                        v.eval_jptr(pointer.clone(), results);
                    }
                }
                Value::Object(map) => {
                    for v in map.values() {
                        v.eval_jptr(pointer.clone(), results);
                    }
                }
                _ => {}
            },
            Some(JsonPointerItem::Root) | None => match self {
                Value::Element(e) => {
                    if let Some(id) = e.as_any_id() {
                        results.0.push(EvalResult::Id(id));
                    }
                }
                Value::Array(list) => {
                    for item in list {
                        if let Value::Element(e) = item
                            && let Some(id) = e.as_any_id()
                        {
                            results.0.push(EvalResult::Id(id));
                        }
                    }
                }
                _ => (),
            },
        }

        true
    }
}

impl ResponsePtr for Id {
    fn eval_jptr(&self, _pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        results.0.push(EvalResult::Id(AnyId::Id(*self)));
        true
    }
}

impl ResponsePtr for BlobId {
    fn eval_jptr(&self, _pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        results.0.push(EvalResult::Id(AnyId::BlobId(self.clone())));
        true
    }
}

impl<T: Property> ResponsePtr for PropertyWrapper<T> {
    fn eval_jptr(&self, _: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        results.0.push(EvalResult::Property(self.0.to_cow()));
        true
    }
}

impl<T: JmapObject> ResponsePtr for GetResponse<T> {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("list") => {
                self.list.eval_jptr(pointer, results);
                true
            }
            _ => false,
        }
    }
}

impl<T: JmapObject> ResponsePtr for ChangesResponse<T> {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        if let Some(property) = pointer.next().and_then(|item| item.as_string_key()) {
            hashify::fnc_map!(property.as_bytes(),
                "created" => {
                    self.created.eval_jptr(pointer, results);
                },
                "updated" => {
                    self.updated.eval_jptr(pointer, results);
                },
                "updatedProperties" => {
                    if let Some(props) = &self.updated_properties {
                        props.eval_jptr(pointer, results);
                    }
                },
                _ => {
                    return false;
                }
            );

            true
        } else {
            false
        }
    }
}

impl ResponsePtr for QueryResponse {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("ids") => {
                self.ids.eval_jptr(pointer, results);
                true
            }
            _ => false,
        }
    }
}

impl ResponsePtr for QueryChangesResponse {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("added") => {
                self.added.eval_jptr(pointer, results);
                true
            }
            _ => false,
        }
    }
}

impl ResponsePtr for AddedItem {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("id") => {
                results.0.push(EvalResult::Id(AnyId::Id(self.id)));
                true
            }
            _ => false,
        }
    }
}

impl ResponsePtr for CalendarEventNotificationGetResponse {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("list") => {
                self.list.eval_jptr(pointer, results);
                true
            }
            _ => false,
        }
    }
}

impl ResponsePtr for CalendarEventNotificationObject {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("id") => {
                results.0.push(EvalResult::Id(AnyId::Id(self.id)));
                true
            }
            Some("calendarEventId") => {
                if let Some(id) = &self.calendar_event_id {
                    results.0.push(EvalResult::Id(AnyId::Id(*id)));
                }
                true
            }
            Some("event") => {
                if let Some(event) = &self.event {
                    event.0.eval_jptr(pointer, results);
                }
                true
            }
            _ => false,
        }
    }
}

impl ResponsePtr for GetAvailabilityResponse {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("list") => {
                self.list.eval_jptr(pointer, results);
                true
            }
            _ => false,
        }
    }
}

impl ResponsePtr for BusyPeriod {
    fn eval_jptr(&self, mut pointer: JsonPointerIter<'_, Null>, results: &mut EvalResults) -> bool {
        match pointer.next().and_then(|item| item.as_string_key()) {
            Some("event") => {
                if let Some(event) = &self.event {
                    event.0.eval_jptr(pointer, results);
                }
                true
            }
            _ => false,
        }
    }
}

impl EvalResults {
    pub fn into_ids<T: TryFrom<AnyId>>(
        self,
        rr: &ResultReference,
    ) -> impl Iterator<Item = trc::Result<T>> {
        self.0.into_iter().map(move |id| {
            if let EvalResult::Id(any_id) = id {
                T::try_from(any_id).map_err(|_| {
                    trc::JmapEvent::InvalidResultReference
                        .into_err()
                        .details(format_compact!(
                            "Failed to evaluate {rr} result reference: Invalid Id type."
                        ))
                })
            } else {
                Err(trc::JmapEvent::InvalidResultReference
                    .into_err()
                    .details(format_compact!(
                        "Failed to evaluate {rr} result reference: Invalid Id type."
                    )))
            }
        })
    }

    pub fn into_properties<T: Property + FromStr>(
        self,
        rr: &ResultReference,
    ) -> impl Iterator<Item = trc::Result<T>> {
        self.0.into_iter().map(move |prop| {
            if let EvalResult::Property(prop) = prop {
                T::from_str(&prop).map_err(|_| {
                    trc::JmapEvent::InvalidResultReference
                        .into_err()
                        .details(format_compact!(
                            "Failed to evaluate {rr} result reference: Invalid property."
                        ))
                })
            } else {
                Err(trc::JmapEvent::InvalidResultReference
                    .into_err()
                    .details(format_compact!(
                        "Failed to evaluate {rr} result reference: Invalid property."
                    )))
            }
        })
    }
}
