/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarValue};
use jmap_tools::{Key, Map, Value};
use types::{blob::BlobId, id::Id};

type EventMap = Map<'static, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;

pub trait JSCalendarPatch {
    fn patch_to(&self, after: &Self) -> Self;
}

impl JSCalendarPatch for JSCalendar<'static, Id, BlobId> {
    fn patch_to(&self, after: &Self) -> Self {
        let empty = EventMap::new();
        let mut patch = EventMap::new();
        diff_objects(
            &mut String::new(),
            self.0.as_object().unwrap_or(&empty),
            after.0.as_object().unwrap_or(&empty),
            &mut patch,
        );
        JSCalendar(Value::Object(patch))
    }
}

fn diff_objects(prefix: &mut String, before: &EventMap, after: &EventMap, patch: &mut EventMap) {
    for (key, before_value) in before.iter() {
        match after.get(key) {
            Some(after_value) if after_value == before_value => {}
            Some(Value::Object(after_object))
                if let Value::Object(before_object) = before_value
                    && !after_object.adds_null(before_object) =>
            {
                let len = prefix.len();
                prefix.push_segment(&key.to_string());
                prefix.push('/');
                diff_objects(prefix, before_object, after_object, patch);
                prefix.truncate(len);
            }
            Some(after_value) => {
                patch.insert_unchecked(prefix.patch_key(key), after_value.clone());
            }
            None => {
                patch.insert_unchecked(prefix.patch_key(key), Value::Null);
            }
        }
    }
    for (key, after_value) in after.iter().filter(|(key, _)| !before.contains_key(key)) {
        patch.insert_unchecked(prefix.patch_key(key), after_value.clone());
    }
}

trait NullMembers {
    fn adds_null(&self, before: &Self) -> bool;
}

impl NullMembers for EventMap {
    fn adds_null(&self, before: &Self) -> bool {
        self.iter().any(|(key, value)| {
            matches!(value, Value::Null) && !matches!(before.get(key), Some(Value::Null))
        })
    }
}

trait PatchPointer {
    fn patch_key(
        &self,
        key: &Key<'static, JSCalendarProperty<Id>>,
    ) -> Key<'static, JSCalendarProperty<Id>>;

    fn push_segment(&mut self, segment: &str);
}

impl PatchPointer for String {
    fn patch_key(
        &self,
        key: &Key<'static, JSCalendarProperty<Id>>,
    ) -> Key<'static, JSCalendarProperty<Id>> {
        let segment = key.to_string();
        if self.is_empty() && !segment.contains(['~', '/']) {
            key.clone()
        } else {
            let mut pointer = String::with_capacity(self.len() + segment.len() + 2);
            pointer.push_str(self);
            pointer.push_segment(&segment);
            Key::Owned(pointer)
        }
    }

    fn push_segment(&mut self, segment: &str) {
        for ch in segment.chars() {
            match ch {
                '~' => self.push_str("~0"),
                '/' => self.push_str("~1"),
                ch => self.push(ch),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &'static str) -> JSCalendar<'static, Id, BlobId> {
        JSCalendar::parse(json).expect("valid JSCalendar")
    }

    #[test]
    fn patch_uses_pointers_for_nested_changes() {
        let before = parse(
            r#"{"@type":"Event","title":"A","participants":{"p1":{"@type":"Participant","name":"X","participationStatus":"needs-action"}},"description":"D"}"#,
        );
        let after = parse(
            r#"{"@type":"Event","title":"B","participants":{"p1":{"@type":"Participant","name":"X","participationStatus":"accepted"},"p/2":{"@type":"Participant","name":"Y"}}}"#,
        );
        let patch = serde_json::to_value(before.patch_to(&after)).unwrap();
        assert_eq!(
            patch,
            serde_json::json!({
                "title": "B",
                "participants/p1/participationStatus": "accepted",
                "participants/p~12": {"@type": "Participant", "name": "Y"},
                "description": null
            })
        );
    }

    fn apply_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
        for (pointer, value) in patch.as_object().expect("patch object") {
            let segments = pointer
                .split('/')
                .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
                .collect::<Vec<_>>();
            let (last, parents) = segments.split_last().expect("non-empty pointer");
            let parent = parents
                .iter()
                .fold(&mut *target, |node, segment| {
                    node.get_mut(segment).expect("existing parent")
                })
                .as_object_mut()
                .expect("object parent");
            if value.is_null() {
                parent.remove(last);
            } else {
                parent.insert(last.clone(), value.clone());
            }
        }
    }

    #[test]
    fn patch_applied_to_before_gives_after() {
        let event = |overrides: &str| {
            format!(
                concat!(
                    "{{\"@type\":\"Event\",\"title\":\"A\",\"vendor\":\"v1\",",
                    "\"participants\":{{\"bill\":{{\"@type\":\"Participant\",",
                    "\"calendarAddress\":\"mailto:bill@example.com\"}}}},",
                    "\"localizations\":{{\"de\":{{\"title\":\"B\"}}}}{}}}"
                ),
                overrides
            )
        };
        for (before, after) in [
            (
                event(concat!(
                    ",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":",
                    "{\"participants/bill/participationStatus\":\"declined\"}}"
                )),
                event(concat!(
                    ",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":",
                    "{\"participants/bill\":null}}"
                )),
            ),
            (
                event(",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":{\"title\":\"C\"}}"),
                event(concat!(
                    ",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":{\"title\":\"C\"},",
                    "\"2026-06-03T09:00:00\":{\"participants/bill\":null}}"
                )),
            ),
            (
                event(",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":{\"title\":null}}"),
                event(",\"recurrenceOverrides\":{\"2026-06-02T09:00:00\":{}}"),
            ),
            (
                event(""),
                event("")
                    .replace("\"v1\"", "\"v2\"")
                    .replace("{\"title\":\"B\"}", "{\"title\":null}"),
            ),
        ] {
            let (before, after) = (parse_owned(&before), parse_owned(&after));
            let patch = serde_json::to_value(before.patch_to(&after)).unwrap();
            let mut applied = serde_json::to_value(&before).unwrap();
            apply_patch(&mut applied, &patch);
            assert_eq!(
                applied,
                serde_json::to_value(&after).unwrap(),
                "patch: {patch}"
            );
        }
    }

    fn parse_owned(json: &str) -> JSCalendar<'static, Id, BlobId> {
        let mut event = JSCalendar::<Id, BlobId>::parse(json)
            .expect("valid JSCalendar")
            .0
            .into_owned();
        if let Some(event) = event.as_object_mut()
            && let Some(vendor) = event.remove(&Key::Owned("vendor".to_string()))
        {
            event.insert_unchecked(Key::Owned("example.com:a/b~c".to_string()), vendor);
        }
        JSCalendar(event)
    }
}
