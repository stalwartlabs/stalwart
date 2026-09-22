/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::calendar_event::CalendarSyntheticId;
use calcard::{
    icalendar::ICalendar,
    jscalendar::{JSCalendarPrivacy, JSCalendarProperty, JSCalendarValue},
};
use common::GroupwareResources;
use groupware::calendar::privacy::{EventPrivacy, EventViewer, ICalendarPrivacy, PrivacyDenied};
use jmap_proto::{error::set::SetError, request::MaybeInvalid};
use jmap_tools::{Key, Value};
use store::{
    ahash::{AHashMap, AHashSet},
    roaring::RoaringBitmap,
};
use types::{blob::BlobId, id::Id};
use utils::map::vec_map::VecMap;

type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;

pub(super) fn assert_privacy_access(
    privacy: EventPrivacy,
    viewer: EventViewer,
) -> Result<(), SetError<JSCalendarProperty<Id>>> {
    privacy.check_access(viewer).map_err(|denied| match denied {
        PrivacyDenied::Forbidden => SetError::forbidden()
            .with_description("Private events can only be modified by the calendar owner."),
        PrivacyDenied::NotFound => SetError::not_found(),
    })
}

pub(super) fn assert_privacy_allowed(
    ical: &ICalendar,
    viewer: EventViewer,
) -> Result<(), SetError<JSCalendarProperty<Id>>> {
    if ical.privacy().may_be_set_by(viewer) {
        Ok(())
    } else {
        Err(SetError::invalid_properties()
            .with_property(JSCalendarProperty::Privacy)
            .with_description("Only the calendar owner can set a privacy other than public."))
    }
}

pub(super) fn uid_privacy_conflict() -> SetError<JSCalendarProperty<Id>> {
    SetError::invalid_properties()
        .with_property(JSCalendarProperty::Privacy)
        .with_description("All events with the same UID must have the same privacy.")
}

#[derive(Default)]
pub(super) struct UidPrivacyConflicts {
    pub creates: AHashSet<String>,
    pub updates: RoaringBitmap,
}

impl UidPrivacyConflicts {
    pub fn new(
        cache: &GroupwareResources,
        creates: Option<&VecMap<String, EventValue<'_>>>,
        updates: Option<&VecMap<MaybeInvalid<Id>, EventValue<'_>>>,
        will_destroy: &[Id],
    ) -> Self {
        let mut touched: AHashMap<&str, UidEvents<'_>> = AHashMap::new();

        for (create_id, object) in creates.into_iter().flat_map(|creates| creates.iter()) {
            if let Some(Value::Str(uid)) = object_property(object, JSCalendarProperty::Uid) {
                let events = touched.entry(uid).or_default();
                events.create_ids.push(create_id);
                events
                    .create_privacies
                    .push(patched_privacy(object).unwrap_or_default());
            }
        }

        let mut patched: AHashMap<u32, EventPrivacy> = AHashMap::new();
        for (id, object) in updates.into_iter().flat_map(|updates| updates.iter()) {
            if let MaybeInvalid::Value(id) = id
                && !id.is_synthetic()
                && let Some(privacy) = patched_privacy(object)
                && let Some(uid) = cache
                    .resources
                    .find(id.document_id(), false)
                    .and_then(|resource| resource.uid())
            {
                patched.insert(id.document_id(), privacy);
                touched.entry(uid).or_default();
            }
        }

        let mut conflicts = UidPrivacyConflicts::default();
        if touched.is_empty() {
            return conflicts;
        }
        for resource in cache.resources.iter() {
            if let Some(events) = resource.uid().and_then(|uid| touched.get_mut(uid)) {
                events.documents.push((
                    resource.document_id(),
                    resource
                        .event_flags()
                        .map(EventPrivacy::from_flags)
                        .unwrap_or_default(),
                ));
            }
        }

        for events in touched.into_values() {
            let mut privacies = events.create_privacies.iter().copied().chain(
                events
                    .documents
                    .iter()
                    .filter(|(document_id, _)| {
                        !will_destroy
                            .iter()
                            .any(|id| !id.is_synthetic() && id.document_id() == *document_id)
                    })
                    .map(|(document_id, privacy)| {
                        patched.get(document_id).copied().unwrap_or(*privacy)
                    }),
            );
            if privacies
                .next()
                .is_some_and(|first| privacies.any(|privacy| privacy != first))
            {
                conflicts
                    .creates
                    .extend(events.create_ids.into_iter().cloned());
                conflicts.updates.extend(
                    events
                        .documents
                        .iter()
                        .map(|(document_id, _)| *document_id)
                        .filter(|document_id| patched.contains_key(document_id)),
                );
            }
        }

        conflicts
    }
}

#[derive(Default)]
struct UidEvents<'x> {
    create_ids: Vec<&'x String>,
    create_privacies: Vec<EventPrivacy>,
    documents: Vec<(u32, EventPrivacy)>,
}

fn object_property<'x, 'y>(
    object: &'y EventValue<'x>,
    property: JSCalendarProperty<Id>,
) -> Option<&'y EventValue<'x>> {
    object
        .as_object()
        .and_then(|object| object.get(&Key::Property(property)))
}

fn patched_privacy(object: &EventValue<'_>) -> Option<EventPrivacy> {
    match object_property(object, JSCalendarProperty::Privacy)? {
        Value::Element(JSCalendarValue::Privacy(privacy)) => Some(match privacy {
            JSCalendarPrivacy::Public => EventPrivacy::Public,
            JSCalendarPrivacy::Private => EventPrivacy::Private,
            JSCalendarPrivacy::Secret => EventPrivacy::Secret,
        }),
        Value::Null => Some(EventPrivacy::Public),
        _ => None,
    }
}
