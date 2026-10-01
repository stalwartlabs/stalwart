/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, JsonPointer, JsonPointerItem, Property, Value};
use serde::de::{Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::{borrow::Cow, fmt, str::FromStr};

macro_rules! property_names {
    ($property:ident, $($name:literal => $value:expr,)*) => {
        fn parse_name(value: &str) -> Option<Self> {
            hashify::fnc_map!(value.as_bytes(),
                $($name => Some($value),)*
                "metadata" => Some($property::Metadata),
                "privateMetadata" => Some($property::PrivateMetadata),
                _ => None,
            )
        }

        fn parse_nested_name(value: &str) -> Option<Self> {
            hashify::fnc_map!(value.as_bytes(),
                $($name => Some($value),)*
                _ => None,
            )
        }
    };
}

pub(crate) use property_names;

#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
pub enum MetadataRoot {
    Shared,
    Private,
}

pub trait MetadataProperty: Property {
    fn as_metadata_root(&self) -> Option<MetadataRoot>;

    fn as_pointer(&self) -> Option<&JsonPointer<Self>>;

    fn from_metadata_root(root: MetadataRoot) -> Self;

    fn metadata_pointer(&self) -> Option<(MetadataRoot, &JsonPointer<Self>)> {
        let pointer = self.as_pointer()?;
        let root = pointer.first()?.as_property_key()?.as_metadata_root()?;
        Some((root, pointer))
    }

    fn metadata_root(&self) -> Option<MetadataRoot> {
        self.as_metadata_root()
            .or_else(|| self.metadata_pointer().map(|(root, _)| root))
    }

    fn has_metadata<E: Element<Property = Self>>(object: &Value<'_, Self, E>) -> bool {
        object.as_object().is_some_and(|object| {
            object
                .keys()
                .any(|key| key.as_property().and_then(Self::metadata_root).is_some())
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Selection {
    #[default]
    None,
    All,
    Namespaces(Vec<Box<str>>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataSelection {
    pub shared: Selection,
    pub private: Selection,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetadataPath {
    pub namespace: Box<str>,
    pub key: Option<Box<str>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataFilter {
    Condition {
        root: MetadataRoot,
        path: MetadataPath,
        condition: MetadataCondition,
    },
    Invalid {
        root: MetadataRoot,
        name: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataCondition {
    Exists,
    TextContains(String),
    TextEquals(String),
}

enum FilterArgument<'de> {
    String(Cow<'de, str>),
    TextMatch(Result<(MetadataPath, String), &'static str>),
    Other,
}

struct FilterArgumentVisitor;

impl MetadataRoot {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::fnc_map!(value.as_bytes(),
            b"metadata" => Some(MetadataRoot::Shared),
            b"privateMetadata" => Some(MetadataRoot::Private),
            _ => None,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetadataRoot::Shared => "metadata",
            MetadataRoot::Private => "privateMetadata",
        }
    }

    pub fn from_selector(value: &str) -> Option<Self> {
        value
            .split_once('/')
            .and_then(|(root, _)| MetadataRoot::parse(root))
    }
}

impl Selection {
    pub fn is_none(&self) -> bool {
        matches!(self, Selection::None)
    }

    pub fn contains(&self, namespace: &str) -> bool {
        match self {
            Selection::None => false,
            Selection::All => true,
            Selection::Namespaces(namespaces) => namespaces
                .binary_search_by(|ns| (**ns).cmp(namespace))
                .is_ok(),
        }
    }

    fn select_all(&mut self) {
        *self = Selection::All;
    }

    fn select_namespace(&mut self, namespace: Box<str>) {
        match self {
            Selection::None => *self = Selection::Namespaces(vec![namespace]),
            Selection::All => {}
            Selection::Namespaces(namespaces) => namespaces.push(namespace),
        }
    }

    fn normalize(&mut self) {
        if let Selection::Namespaces(namespaces) = self {
            namespaces.sort_unstable();
            namespaces.dedup();
        }
    }
}

impl MetadataSelection {
    pub fn all() -> Self {
        MetadataSelection {
            shared: Selection::All,
            private: Selection::All,
        }
    }

    pub fn is_none(&self) -> bool {
        self.shared.is_none() && self.private.is_none()
    }

    pub fn extract<P: MetadataProperty>(properties: &mut Vec<P>) -> trc::Result<Self> {
        let mut selection = MetadataSelection::default();
        let mut result = Ok(());

        properties.retain(|property| {
            if let Some(root) = property.as_metadata_root() {
                selection.root_mut(root).select_all();
                false
            } else if let Some((root, pointer)) = property.metadata_pointer() {
                match MetadataSelection::namespace(pointer) {
                    Ok(namespace) => selection.root_mut(root).select_namespace(namespace),
                    Err(err) => result = Err(err),
                }
                false
            } else {
                true
            }
        });

        result.map(|_| {
            selection.shared.normalize();
            selection.private.normalize();
            selection
        })
    }

    pub fn root(&self, root: MetadataRoot) -> &Selection {
        match root {
            MetadataRoot::Shared => &self.shared,
            MetadataRoot::Private => &self.private,
        }
    }

    fn root_mut(&mut self, root: MetadataRoot) -> &mut Selection {
        match root {
            MetadataRoot::Shared => &mut self.shared,
            MetadataRoot::Private => &mut self.private,
        }
    }

    fn namespace<P: Property>(pointer: &JsonPointer<P>) -> trc::Result<Box<str>> {
        let [_, namespace] = pointer.as_slice() else {
            return Err(trc::JmapEvent::InvalidArguments.into_err().details(format!(
                "Metadata subselector {pointer} must have exactly two segments"
            )));
        };
        let JsonPointerItem::Key(key) = namespace else {
            return Err(trc::JmapEvent::InvalidArguments
                .into_err()
                .details(format!("Invalid metadata subselector {pointer}")));
        };

        Ok(key.to_string().into())
    }
}

impl MetadataPath {
    fn unescape(segment: &str) -> Option<Box<str>> {
        let Some((literal, mut rest)) = segment.split_once('~') else {
            return Some(segment.into());
        };
        let mut unescaped = String::with_capacity(segment.len());
        unescaped.push_str(literal);

        loop {
            let (escaped, tail) = rest
                .strip_prefix('0')
                .map(|tail| ('~', tail))
                .or_else(|| rest.strip_prefix('1').map(|tail| ('/', tail)))?;
            unescaped.push(escaped);
            rest = tail;

            match rest.split_once('~') {
                Some((literal, tail)) => {
                    unescaped.push_str(literal);
                    rest = tail;
                }
                None => {
                    unescaped.push_str(rest);
                    return Some(unescaped.into_boxed_str());
                }
            }
        }
    }
}

impl FromStr for MetadataPath {
    type Err = &'static str;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let (namespace, key) = match path.split_once('/') {
            Some((_, key)) if key.contains('/') => {
                return Err("metadata path must have at most two segments");
            }
            Some((namespace, key)) => (namespace, Some(key)),
            None => (path, None),
        };

        Ok(MetadataPath {
            namespace: MetadataPath::unescape(namespace)
                .ok_or("invalid escape in metadata path")?,
            key: key
                .map(|key| MetadataPath::unescape(key).ok_or("invalid escape in metadata path"))
                .transpose()?,
        })
    }
}

impl MetadataFilter {
    pub fn try_deserialize<'de, A>(key: &str, map: &mut A) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"metadataExists" => MetadataFilter::deserialize_exists(
                MetadataRoot::Shared,
                "metadataExists",
                map,
            ),
            b"privateMetadataExists" => MetadataFilter::deserialize_exists(
                MetadataRoot::Private,
                "privateMetadataExists",
                map,
            ),
            b"metadataTextContains" => MetadataFilter::deserialize_text(
                MetadataRoot::Shared,
                "metadataTextContains",
                MetadataCondition::TextContains,
                map,
            ),
            b"privateMetadataTextContains" => MetadataFilter::deserialize_text(
                MetadataRoot::Private,
                "privateMetadataTextContains",
                MetadataCondition::TextContains,
                map,
            ),
            b"metadataTextEquals" => MetadataFilter::deserialize_text(
                MetadataRoot::Shared,
                "metadataTextEquals",
                MetadataCondition::TextEquals,
                map,
            ),
            b"privateMetadataTextEquals" => MetadataFilter::deserialize_text(
                MetadataRoot::Private,
                "privateMetadataTextEquals",
                MetadataCondition::TextEquals,
                map,
            ),
            _ => Ok(None),
        )
    }

    fn deserialize_exists<'de, A>(
        root: MetadataRoot,
        name: &'static str,
        map: &mut A,
    ) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        let filter = match map.next_value::<FilterArgument>()? {
            FilterArgument::String(path) => {
                MetadataPath::from_str(&path).map(|path| MetadataFilter::Condition {
                    root,
                    path,
                    condition: MetadataCondition::Exists,
                })
            }
            FilterArgument::TextMatch(_) | FilterArgument::Other => {
                Err("expected a metadata path string")
            }
        };
        Ok(Some(filter.unwrap_or_else(|reason| {
            MetadataFilter::Invalid { root, name, reason }
        })))
    }

    fn deserialize_text<'de, A>(
        root: MetadataRoot,
        name: &'static str,
        condition: fn(String) -> MetadataCondition,
        map: &mut A,
    ) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        let filter = match map.next_value::<FilterArgument>()? {
            FilterArgument::TextMatch(text_match) => {
                text_match.map(|(path, value)| MetadataFilter::Condition {
                    root,
                    path,
                    condition: condition(value),
                })
            }
            FilterArgument::String(_) | FilterArgument::Other => {
                Err("expected a MetadataTextMatch object")
            }
        };
        Ok(Some(filter.unwrap_or_else(|reason| {
            MetadataFilter::Invalid { root, name, reason }
        })))
    }

    pub fn root(&self) -> MetadataRoot {
        match self {
            MetadataFilter::Condition { root, .. } | MetadataFilter::Invalid { root, .. } => *root,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MetadataFilter::Invalid { name, .. } => name,
            MetadataFilter::Condition {
                root, condition, ..
            } => match (root, condition) {
                (MetadataRoot::Shared, MetadataCondition::Exists) => "metadataExists",
                (MetadataRoot::Shared, MetadataCondition::TextContains(_)) => {
                    "metadataTextContains"
                }
                (MetadataRoot::Shared, MetadataCondition::TextEquals(_)) => "metadataTextEquals",
                (MetadataRoot::Private, MetadataCondition::Exists) => "privateMetadataExists",
                (MetadataRoot::Private, MetadataCondition::TextContains(_)) => {
                    "privateMetadataTextContains"
                }
                (MetadataRoot::Private, MetadataCondition::TextEquals(_)) => {
                    "privateMetadataTextEquals"
                }
            },
        }
    }
}

impl<'de> serde::Deserialize<'de> for FilterArgument<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(FilterArgumentVisitor)
    }
}

impl<'de> Visitor<'de> for FilterArgumentVisitor {
    type Value = FilterArgument<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a metadata filter argument")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(FilterArgument::String(Cow::Borrowed(value)))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(FilterArgument::String(Cow::Owned(value.into())))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(FilterArgument::String(Cow::Owned(value)))
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(FilterArgument::Other)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        IgnoredAny.visit_seq(seq).map(|_| FilterArgument::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut path = None;
        let mut value = None;
        let mut error = None;

        while let Some(key) = map.next_key::<FilterArgument>()? {
            let argument = map.next_value::<FilterArgument>()?;
            let field = match &key {
                FilterArgument::String(key) => hashify::fnc_map!(key.as_bytes(),
                    b"path" => Some(&mut path),
                    b"value" => Some(&mut value),
                    _ => None,
                ),
                FilterArgument::TextMatch(_) | FilterArgument::Other => None,
            };
            match (field, argument) {
                (Some(field), FilterArgument::String(text)) if field.is_none() => {
                    *field = Some(text);
                }
                (Some(field), _) if field.is_none() => {
                    error.get_or_insert("MetadataTextMatch path and value must be strings");
                }
                _ => {
                    error.get_or_insert("unexpected or duplicate MetadataTextMatch field");
                }
            }
        }

        Ok(FilterArgument::TextMatch(match (error, path, value) {
            (Some(reason), _, _) => Err(reason),
            (None, Some(path), Some(value)) => {
                MetadataPath::from_str(&path).map(|path| (path, value.into_owned()))
            }
            (None, _, _) => Err("MetadataTextMatch requires a path and a value"),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MetadataCondition, MetadataFilter, MetadataPath, MetadataProperty, MetadataRoot,
        MetadataSelection, Selection,
    };
    use crate::{
        method::{
            get::GetRequest,
            query::{Filter, QueryRequest},
        },
        object::{
            addressbook::{AddressBook, AddressBookFilter, AddressBookProperty},
            calendar::{Calendar, CalendarFilter, CalendarProperty},
            calendar_event::CalendarEvent,
            contact::ContactCard,
            email::{Email, EmailFilter, EmailProperty, EmailQueryFilter},
            file_node::FileNodeProperty,
            mailbox::{Mailbox, MailboxFilter, MailboxProperty, MailboxValue},
            sieve::SieveProperty,
        },
        request::{QueryRequestMethod, Request, RequestMethod},
    };
    use calcard::{
        jscalendar::{JSCalendarProperty, JSCalendarValue},
        jscontact::{JSContactProperty, JSContactValue},
    };
    use jmap_tools::{Element, JsonPointer, JsonPointerItem, Key, Property, Value};
    use std::{fmt::Debug, str::FromStr};
    use types::{blob::BlobId, id::Id};

    fn path(namespace: &str, key: Option<&str>) -> MetadataPath {
        MetadataPath {
            namespace: namespace.into(),
            key: key.map(Into::into),
        }
    }

    fn properties<P: FromStr>(names: &[&str]) -> Vec<P> {
        names
            .iter()
            .map(|name| P::from_str(name).unwrap_or_else(|_| panic!("invalid property {name:?}")))
            .collect()
    }

    fn assert_metadata_property<P: MetadataProperty + FromStr + Debug>() {
        for (name, root) in [
            ("metadata", MetadataRoot::Shared),
            ("privateMetadata", MetadataRoot::Private),
        ] {
            let property = P::from_str(name).unwrap_or_else(|_| panic!("{name}"));
            assert_eq!(property.as_metadata_root(), Some(root), "{name}");
            assert_eq!(property.metadata_root(), Some(root), "{name}");
            assert_eq!(property.to_cow(), name);

            let selector = format!("{name}/x.example");
            let property = P::from_str(&selector).unwrap_or_else(|_| panic!("{selector}"));
            assert_eq!(property.as_metadata_root(), None, "{selector}");
            assert_eq!(
                property.metadata_pointer().map(|(root, _)| root),
                Some(root),
                "{selector}"
            );
            assert_eq!(property.to_cow(), selector);
        }

        for invalid in ["id/x", "metadataX/y", "/metadata/x"] {
            assert!(P::from_str(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn metadata_properties() {
        assert_metadata_property::<EmailProperty>();
        assert_metadata_property::<MailboxProperty>();
        assert_metadata_property::<SieveProperty>();
        assert_metadata_property::<CalendarProperty>();
        assert_metadata_property::<AddressBookProperty>();
        assert_metadata_property::<FileNodeProperty>();
        assert_metadata_property::<JSCalendarProperty<Id>>();
        assert_metadata_property::<JSContactProperty<Id>>();
    }

    #[test]
    fn metadata_get_properties_for_events_and_cards() {
        let mut request = serde_json::from_str::<GetRequest<CalendarEvent>>(
            r#"{"accountId": "a", "properties": ["title", "metadata/x.example", "privateMetadata", "metadata/y.example", "metadataX/y"]}"#,
        )
        .unwrap();
        let mut list = request.unwrap_properties(&[]);
        let selection = MetadataSelection::extract(&mut list).unwrap();
        assert_eq!(
            list,
            vec![JSCalendarProperty::Title, JSCalendarProperty::Id]
        );
        assert_eq!(
            selection.shared,
            Selection::Namespaces(vec!["x.example".into(), "y.example".into()])
        );
        assert_eq!(selection.private, Selection::All);

        let mut request = serde_json::from_str::<GetRequest<ContactCard>>(
            r#"{"accountId": "a", "properties": ["id", "metadata", "privateMetadata/z.example"]}"#,
        )
        .unwrap();
        let mut list = request.unwrap_properties(&[]);
        let selection = MetadataSelection::extract(&mut list).unwrap();
        assert_eq!(list, vec![JSContactProperty::Id]);
        assert_eq!(selection.shared, Selection::All);
        assert_eq!(
            selection.private,
            Selection::Namespaces(vec!["z.example".into()])
        );

        let mut list = properties::<JSCalendarProperty<Id>>(&["metadata/x.example/key"]);
        assert!(MetadataSelection::extract(&mut list).is_err());
        let mut list = properties::<JSContactProperty<Id>>(&["privateMetadata/a~2"]);
        assert!(MetadataSelection::extract(&mut list).is_err());
    }

    fn assert_untyped_metadata<P: MetadataProperty, E: Element<Property = P>>(
        json: &str,
        expected_keys: usize,
    ) {
        let value = Value::<P, E>::parse_json(json).unwrap();
        assert_eq!(
            serde_json::to_value(&value).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
        assert!(P::has_metadata(&value));

        let mut metadata_keys = 0;
        for (key, value) in value.as_object().unwrap().iter() {
            let Key::Property(property) = key else {
                panic!("untyped top-level key {key:?}");
            };
            if property.metadata_root().is_none() {
                continue;
            }
            metadata_keys += 1;
            match value {
                Value::Object(object) => {
                    for (key, value) in object.iter() {
                        assert!(matches!(key, Key::Borrowed(_)), "{key:?}");
                        assert!(!matches!(value, Value::Element(_)), "{value:?}");
                    }
                }
                value => assert!(matches!(value, Value::Str(_)), "{value:?}"),
            }
        }
        assert_eq!(metadata_keys, expected_keys);
    }

    #[test]
    fn metadata_values_of_events_and_cards_are_not_typed() {
        assert_untyped_metadata::<JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>(
            r#"{
                "title": "Meeting",
                "metadata": {"title": {"k": "v"}, "calendarIds": {}, "start": "2024-01-01T00:00:00+00:00"},
                "metadata/x.example": {"start": "2024-01-01T00:00:00+00:00", "id": "abc"},
                "privateMetadata/x.example/start": "2024-01-01T00:00:00+00:00"
            }"#,
            3,
        );
        assert_untyped_metadata::<JSContactProperty<Id>, JSContactValue<Id, BlobId>>(
            r#"{
                "uid": "u1",
                "privateMetadata": {"name": {"k": "v"}, "addressBookIds": {}, "created": "2024-01-01T00:00:00+00:00"},
                "metadata/x.example": {"updated": "2024-01-01T00:00:00+00:00", "id": "abc"},
                "metadata/x.example/created": "2024-01-01T00:00:00+00:00"
            }"#,
            3,
        );
    }

    #[test]
    fn metadata_detection_in_objects() {
        for (json, expected) in [
            (r#"{"title": "Meeting", "calendarIds": {"a": true}}"#, false),
            (r#"{"title": "Meeting", "metadata": {}}"#, true),
            (r#"{"privateMetadata/x.example": null}"#, true),
            (
                r#"{"recurrenceOverrides/2024-01-01T00:00:00/metadata": {}}"#,
                false,
            ),
            (r#""metadata""#, false),
        ] {
            let value =
                Value::<JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>::parse_json(json)
                    .unwrap();
            assert_eq!(JSCalendarProperty::has_metadata(&value), expected, "{json}");

            let value =
                Value::<JSContactProperty<Id>, JSContactValue<Id, BlobId>>::parse_json(json)
                    .unwrap();
            assert_eq!(JSContactProperty::has_metadata(&value), expected, "{json}");
        }

        let value = Value::<MailboxProperty, MailboxValue>::parse_json(
            r#"{"name": "Inbox", "metadata/x.example/key": 1}"#,
        )
        .unwrap();
        assert!(MailboxProperty::has_metadata(&value));
    }

    #[test]
    fn metadata_path_parse() {
        for (input, expected) in [
            ("x.example", Some(path("x.example", None))),
            ("x.example/color", Some(path("x.example", Some("color")))),
            ("a~1b/c~0d", Some(path("a/b", Some("c~d")))),
            ("~0~1/~1~0", Some(path("~/", Some("/~")))),
            ("ns/", Some(path("ns", Some("")))),
            ("", Some(path("", None))),
            ("a/b/c", None),
            ("a~1b/c/d", None),
            ("a~2", None),
            ("a~", None),
            ("ns/key~", None),
        ] {
            assert_eq!(MetadataPath::from_str(input).ok(), expected, "{input:?}");
        }
    }

    #[test]
    fn metadata_selection() {
        let mut list = properties::<MailboxProperty>(&[
            "id",
            "metadata/x.example",
            "metadata/y.example",
            "metadata/x.example",
            "privateMetadata",
            "name",
            "metadata/123",
        ]);
        let selection = MetadataSelection::extract(&mut list).unwrap();
        assert_eq!(list, vec![MailboxProperty::Id, MailboxProperty::Name]);
        assert_eq!(
            selection.shared,
            Selection::Namespaces(vec!["123".into(), "x.example".into(), "y.example".into()])
        );
        assert_eq!(selection.private, Selection::All);
        assert_eq!(selection.root(MetadataRoot::Private), &Selection::All);
        assert!(selection.shared.contains("y.example"));
        assert!(!selection.shared.contains("z.example"));
        assert!(selection.private.contains("z.example"));

        let mut list = properties::<EmailProperty>(&[
            "metadata/x.example",
            "metadata",
            "privateMetadata/z.example",
            "metadata/y.example",
        ]);
        let selection = MetadataSelection::extract(&mut list).unwrap();
        assert!(list.is_empty());
        assert_eq!(selection.shared, Selection::All);
        assert_eq!(
            selection.private,
            Selection::Namespaces(vec!["z.example".into()])
        );

        let mut list = properties::<SieveProperty>(&["id", "name"]);
        let selection = MetadataSelection::extract(&mut list).unwrap();
        assert_eq!(list.len(), 2);
        assert!(selection.is_none());
        assert!(!MetadataSelection::all().is_none());

        for invalid in [
            "metadata/x.example/key",
            "privateMetadata/a/b/c",
            "metadata/a~2",
        ] {
            let mut list = properties::<FileNodeProperty>(&["id", invalid]);
            assert!(MetadataSelection::extract(&mut list).is_err(), "{invalid}");
        }
    }

    #[test]
    fn metadata_selection_scales_linearly() {
        const NAMESPACES: usize = 20_000;
        let mut list = (0..NAMESPACES)
            .chain(0..NAMESPACES)
            .map(|namespace| {
                MailboxProperty::from_str(&format!("metadata/n{namespace}.example"))
                    .expect("valid subselector")
            })
            .collect::<Vec<_>>();
        let selection = MetadataSelection::extract(&mut list).expect("valid selection");
        assert!(list.is_empty());
        let Selection::Namespaces(namespaces) = &selection.shared else {
            panic!("unexpected selection {:?}", selection.shared);
        };
        assert_eq!(namespaces.len(), NAMESPACES);
        assert!(namespaces.is_sorted());
        assert!(selection.shared.contains("n19999.example"));
        assert!(!selection.shared.contains("n20000.example"));
    }

    #[test]
    fn pointers_above_the_segment_cap_are_invalid() {
        let over = format!(
            "metadata/x.example{}",
            "/a".repeat(JsonPointer::<MailboxProperty>::MAX_SEGMENTS)
        );
        let at_cap = format!(
            "metadata/x.example{}",
            "/a".repeat(JsonPointer::<MailboxProperty>::MAX_SEGMENTS - 2)
        );

        for selector in [&over, &at_cap] {
            let mut list = properties::<MailboxProperty>(&["id", selector]);
            let error = MetadataSelection::extract(&mut list).expect_err("selector");
            assert!(
                error.matches(trc::EventType::Jmap(trc::JmapEvent::InvalidArguments)),
                "{error:?}"
            );
            assert_eq!(list, vec![MailboxProperty::Id]);
        }

        let json = format!(r#"{{"{over}": 1, "metadata/x.example/a~2": 2}}"#);
        let value = Value::<MailboxProperty, MailboxValue>::parse_json(&json).expect("valid JSON");
        let keys = value
            .as_object()
            .expect("an object")
            .keys()
            .collect::<Vec<_>>();
        let [Key::Property(capped), Key::Property(escaped)] = keys.as_slice() else {
            panic!("untyped keys {keys:?}");
        };
        for (property, invalid) in [(capped, ""), (escaped, "a~2")] {
            let Some((MetadataRoot::Shared, pointer)) = property.metadata_pointer() else {
                panic!("not a metadata patch: {property:?}");
            };
            assert!(
                matches!(
                    pointer.as_slice().last(),
                    Some(JsonPointerItem::Invalid(text)) if text == invalid
                ),
                "{pointer:?}"
            );
        }
        assert_eq!(capped.to_cow(), "metadata/");
    }

    #[test]
    fn root_pointer_is_a_metadata_root() {
        let value = Value::<MailboxProperty, MailboxValue>::parse_json(
            r#"{"/metadata": {}, "/privateMetadata/x.example": {}}"#,
        )
        .expect("valid JSON");
        let roots = value
            .as_object()
            .expect("an object")
            .keys()
            .map(|key| {
                let Key::Property(property) = key else {
                    panic!("untyped key {key:?}");
                };
                (
                    property.as_metadata_root(),
                    property.metadata_root(),
                    property
                        .metadata_pointer()
                        .map(|(_, pointer)| pointer.len()),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            roots,
            vec![
                (None, Some(MetadataRoot::Shared), Some(1)),
                (None, Some(MetadataRoot::Private), Some(2)),
            ]
        );
    }

    #[test]
    fn metadata_values_are_not_typed() {
        let value = Value::<MailboxProperty, MailboxValue>::parse_json(
            r#"{
                "metadata": {"name": {"k": "v"}, "parentId": {}},
                "metadata/role": {"role": "inbox"},
                "metadata/x.example/parentId": "abc"
            }"#,
        )
        .unwrap();
        let mut entries = value.as_object().unwrap().iter();

        let (key, metadata) = entries.next().unwrap();
        assert!(matches!(key, Key::Property(MailboxProperty::Metadata)));
        assert!(
            metadata
                .as_object()
                .unwrap()
                .keys()
                .all(|key| matches!(key, Key::Borrowed(_)))
        );

        let (key, namespace) = entries.next().unwrap();
        assert!(matches!(key, Key::Property(property) if property.metadata_pointer().is_some()));
        let (key, value) = namespace.as_object().unwrap().iter().next().unwrap();
        assert!(matches!(key, Key::Borrowed("role")));
        assert!(matches!(value, Value::Str(_)));

        let (key, value) = entries.next().unwrap();
        assert!(matches!(key, Key::Property(property) if property.metadata_pointer().is_some()));
        assert!(matches!(value, Value::Str(_)));
    }

    #[test]
    fn metadata_filters() {
        let request = serde_json::from_str::<QueryRequest<Mailbox>>(
            r#"{
                "accountId": "a",
                "filter": {
                    "operator": "AND",
                    "conditions": [
                        {"metadataExists": "x.example/color"},
                        {"privateMetadataExists": "x.example"},
                        {"metadataTextContains": {"path": "x.example/memo", "value": "Follow Up"}},
                        {"privateMetadataTextEquals": {"path": "x~1y", "value": "blue"}},
                        {"privateMetadataTextContains": {"path": "x.example/a~0b", "value": "c"}},
                        {"metadataTextEquals": {"path": "x.example", "value": "d"}},
                        {"metadataUnknown": "x.example"},
                        {"name": "Inbox"}
                    ]
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            request.filter,
            vec![
                Filter::And,
                Filter::Property(MailboxFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Shared,
                    path: path("x.example", Some("color")),
                    condition: MetadataCondition::Exists,
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Private,
                    path: path("x.example", None),
                    condition: MetadataCondition::Exists,
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Shared,
                    path: path("x.example", Some("memo")),
                    condition: MetadataCondition::TextContains("Follow Up".into()),
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Private,
                    path: path("x/y", None),
                    condition: MetadataCondition::TextEquals("blue".into()),
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Private,
                    path: path("x.example", Some("a~b")),
                    condition: MetadataCondition::TextContains("c".into()),
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Shared,
                    path: path("x.example", None),
                    condition: MetadataCondition::TextEquals("d".into()),
                })),
                Filter::Property(MailboxFilter::_T("metadataUnknown".into())),
                Filter::Property(MailboxFilter::Name("Inbox".into())),
                Filter::Close,
            ]
        );

        let names = request
            .filter
            .iter()
            .filter_map(|filter| match filter {
                Filter::Property(MailboxFilter::Metadata(filter)) => Some(filter.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "metadataExists",
                "privateMetadataExists",
                "metadataTextContains",
                "privateMetadataTextEquals",
                "privateMetadataTextContains",
                "metadataTextEquals"
            ]
        );

        let request = serde_json::from_str::<QueryRequest<Email>>(
            r#"{"accountId": "a", "filter": {"metadataTextEquals": {"path": "a.b/c", "value": "d"}, "minSize": 10}}"#,
        )
        .unwrap();
        assert_eq!(
            request.filter,
            vec![
                Filter::And,
                Filter::Property(EmailQueryFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Shared,
                    path: path("a.b", Some("c")),
                    condition: MetadataCondition::TextEquals("d".into()),
                })),
                Filter::Property(EmailQueryFilter::Email(EmailFilter::MinSize(10))),
                Filter::Close,
            ]
        );
        assert!(!request.filter[1].is_immutable());
        assert!(request.filter[2].is_immutable());

        let request = serde_json::from_str::<QueryRequest<Calendar>>(
            r#"{"accountId": "a", "filter": {"metadataExists": "a.b", "name": "x"}}"#,
        )
        .unwrap();
        assert_eq!(
            request.filter,
            vec![
                Filter::And,
                Filter::Property(CalendarFilter::Metadata(MetadataFilter::Condition {
                    root: MetadataRoot::Shared,
                    path: path("a.b", None),
                    condition: MetadataCondition::Exists,
                })),
                Filter::Property(CalendarFilter::_T("name".into())),
                Filter::Close,
            ]
        );

        let request = serde_json::from_str::<QueryRequest<AddressBook>>(
            r#"{"accountId": "a", "filter": {"privateMetadataExists": "a.b"}}"#,
        )
        .unwrap();
        assert_eq!(
            request.filter,
            vec![Filter::Property(AddressBookFilter::Metadata(
                MetadataFilter::Condition {
                    root: MetadataRoot::Private,
                    path: path("a.b", None),
                    condition: MetadataCondition::Exists,
                }
            ))]
        );

        for (invalid, root, name, reason) in [
            (
                r#"{"metadataExists": "a/b/c"}"#,
                MetadataRoot::Shared,
                "metadataExists",
                TOO_DEEP,
            ),
            (
                r#"{"privateMetadataExists": "a~2"}"#,
                MetadataRoot::Private,
                "privateMetadataExists",
                BAD_ESCAPE,
            ),
            (
                r#"{"metadataExists": 1}"#,
                MetadataRoot::Shared,
                "metadataExists",
                NOT_A_PATH,
            ),
            (
                r#"{"metadataExists": {"path": "a", "value": "b"}}"#,
                MetadataRoot::Shared,
                "metadataExists",
                NOT_A_PATH,
            ),
            (
                r#"{"metadataExists": [["a"], {"b": null}]}"#,
                MetadataRoot::Shared,
                "metadataExists",
                NOT_A_PATH,
            ),
            (
                r#"{"metadataTextContains": "a"}"#,
                MetadataRoot::Shared,
                "metadataTextContains",
                NOT_A_TEXT_MATCH,
            ),
            (
                r#"{"privateMetadataTextContains": null}"#,
                MetadataRoot::Private,
                "privateMetadataTextContains",
                NOT_A_TEXT_MATCH,
            ),
            (
                r#"{"metadataTextContains": {"path": "a", "value": "b", "other": 1}}"#,
                MetadataRoot::Shared,
                "metadataTextContains",
                UNEXPECTED_FIELD,
            ),
            (
                r#"{"metadataTextContains": {"path": "a", "path": "b", "value": "c"}}"#,
                MetadataRoot::Shared,
                "metadataTextContains",
                UNEXPECTED_FIELD,
            ),
            (
                r#"{"privateMetadataTextEquals": {"path": "a"}}"#,
                MetadataRoot::Private,
                "privateMetadataTextEquals",
                MISSING_FIELD,
            ),
            (
                r#"{"metadataTextEquals": {"path": "a", "value": 1.5}}"#,
                MetadataRoot::Shared,
                "metadataTextEquals",
                NOT_A_STRING,
            ),
            (
                r#"{"metadataTextEquals": {"path": {"path": "a", "value": "b"}, "value": "c"}}"#,
                MetadataRoot::Shared,
                "metadataTextEquals",
                NOT_A_STRING,
            ),
            (
                r#"{"metadataTextEquals": {"path": "a/b/c", "value": "d"}}"#,
                MetadataRoot::Shared,
                "metadataTextEquals",
                TOO_DEEP,
            ),
        ] {
            let request = serde_json::from_str::<QueryRequest<Mailbox>>(&format!(
                r#"{{"accountId": "a", "filter": {invalid}, "limit": 3}}"#
            ))
            .unwrap_or_else(|err| panic!("{invalid}: {err}"));
            assert_eq!(request.limit, Some(3), "{invalid}");
            assert_eq!(
                request.filter,
                vec![Filter::Property(MailboxFilter::Metadata(invalid_filter(
                    root, name, reason
                )))],
                "{invalid}"
            );
            let [Filter::Property(MailboxFilter::Metadata(filter))] = request.filter.as_slice()
            else {
                panic!("{invalid}: unexpected filter {:?}", request.filter);
            };
            assert_eq!(filter.as_str(), name, "{invalid}");
        }

        let request = serde_json::from_str::<QueryRequest<Mailbox>>(
            r#"{"accountId": "a", "filter": {"metadataTextEquals": {"pa\u0074h": "a\u002fb", "value": "\u0063"}}}"#,
        )
        .expect("escaped keys and values");
        assert_eq!(
            request.filter,
            vec![Filter::Property(MailboxFilter::Metadata(
                MetadataFilter::Condition {
                    root: MetadataRoot::Shared,
                    path: path("a", Some("b")),
                    condition: MetadataCondition::TextEquals("c".into()),
                }
            ))]
        );
    }

    const TOO_DEEP: &str = "metadata path must have at most two segments";
    const BAD_ESCAPE: &str = "invalid escape in metadata path";
    const NOT_A_PATH: &str = "expected a metadata path string";
    const NOT_A_TEXT_MATCH: &str = "expected a MetadataTextMatch object";
    const NOT_A_STRING: &str = "MetadataTextMatch path and value must be strings";
    const UNEXPECTED_FIELD: &str = "unexpected or duplicate MetadataTextMatch field";
    const MISSING_FIELD: &str = "MetadataTextMatch requires a path and a value";

    fn invalid_filter(
        root: MetadataRoot,
        name: &'static str,
        reason: &'static str,
    ) -> MetadataFilter {
        MetadataFilter::Invalid { root, name, reason }
    }

    fn email_query(condition: &str) -> QueryRequest<Email> {
        let json = format!(
            r#"{{
                "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
                "methodCalls": [
                    ["Email/query", {{"accountId": "a", "filter": {condition}, "limit": 7}}, "c0"],
                    ["Mailbox/get", {{"accountId": "a"}}, "c1"]
                ]
            }}"#
        );
        let request = Request::parse(json.as_bytes(), 10, 1 << 20)
            .unwrap_or_else(|err| panic!("{condition}: request rejected: {err:?}"));
        let [first, second] = <[_; 2]>::try_from(request.method_calls)
            .unwrap_or_else(|calls| panic!("{condition}: unexpected calls {calls:?}"));
        assert_eq!(second.id, "c1", "{condition}");
        assert!(
            matches!(second.method, RequestMethod::Get(_)),
            "{condition}: {:?}",
            second.method
        );
        assert_eq!(first.id, "c0", "{condition}");
        let RequestMethod::Query(QueryRequestMethod::Email(query)) = first.method else {
            panic!("{condition}: not an Email/query: {:?}", first.method);
        };
        assert_eq!(query.limit, Some(7), "{condition}");
        *query
    }

    #[test]
    fn invalid_metadata_filters_are_method_arguments() {
        let mailbox = Id::new(1).to_string();
        let in_mailbox =
            || Filter::Property(EmailQueryFilter::Email(EmailFilter::InMailbox(Id::new(1))));
        let min_size = || Filter::Property(EmailQueryFilter::Email(EmailFilter::MinSize(10)));
        let invalid = |name, reason| {
            Filter::Property(EmailQueryFilter::Metadata(invalid_filter(
                MetadataRoot::Shared,
                name,
                reason,
            )))
        };
        let exists = || invalid("metadataExists", TOO_DEEP);
        let contains = |reason| invalid("metadataTextContains", reason);

        for (condition, expected) in [
            (
                format!(r#"{{"metadataExists": "a/b/c", "inMailbox": "{mailbox}"}}"#),
                vec![Filter::And, exists(), in_mailbox(), Filter::Close],
            ),
            (
                format!(
                    r#"{{"inMailbox": "{mailbox}", "metadataExists": "a/b/c", "minSize": 10}}"#
                ),
                vec![
                    Filter::And,
                    in_mailbox(),
                    exists(),
                    min_size(),
                    Filter::Close,
                ],
            ),
            (
                format!(r#"{{"inMailbox": "{mailbox}", "metadataExists": "a/b/c"}}"#),
                vec![Filter::And, in_mailbox(), exists(), Filter::Close],
            ),
            (
                format!(
                    r#"{{"metadataTextContains": {{"path": "x.example/a/b", "value": "x"}}, "inMailbox": "{mailbox}"}}"#
                ),
                vec![Filter::And, contains(TOO_DEEP), in_mailbox(), Filter::Close],
            ),
            (
                format!(
                    r#"{{"minSize": 10, "metadataTextContains": {{"value": "x", "path": "x.example/a/b"}}, "inMailbox": "{mailbox}"}}"#
                ),
                vec![
                    Filter::And,
                    min_size(),
                    contains(TOO_DEEP),
                    in_mailbox(),
                    Filter::Close,
                ],
            ),
            (
                format!(
                    r#"{{"inMailbox": "{mailbox}", "metadataTextContains": {{"value": "x", "path": "x.example/a/b"}}}}"#
                ),
                vec![Filter::And, in_mailbox(), contains(TOO_DEEP), Filter::Close],
            ),
            (
                format!(
                    r#"{{"metadataTextContains": {{"other": {{"a": [1, {{"b": "c"}}]}}, "path": "x.example", "value": "x"}}, "inMailbox": "{mailbox}"}}"#
                ),
                vec![
                    Filter::And,
                    contains(UNEXPECTED_FIELD),
                    in_mailbox(),
                    Filter::Close,
                ],
            ),
            (
                format!(
                    r#"{{"metadataTextContains": {{"path": "x.example", "other": [], "value": "x"}}, "inMailbox": "{mailbox}"}}"#
                ),
                vec![
                    Filter::And,
                    contains(UNEXPECTED_FIELD),
                    in_mailbox(),
                    Filter::Close,
                ],
            ),
            (
                format!(
                    r#"{{"metadataTextContains": {{"path": "x.example", "value": "x", "other": null}}, "inMailbox": "{mailbox}"}}"#
                ),
                vec![
                    Filter::And,
                    contains(UNEXPECTED_FIELD),
                    in_mailbox(),
                    Filter::Close,
                ],
            ),
            (
                format!(
                    r#"{{"operator": "OR", "conditions": [{{"metadataExists": "a/b/c"}}, {{"inMailbox": "{mailbox}"}}]}}"#
                ),
                vec![Filter::Or, exists(), in_mailbox(), Filter::Close],
            ),
        ] {
            assert_eq!(email_query(&condition).filter, expected, "{condition}");
        }
    }
}
