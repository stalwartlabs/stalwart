/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{JsonPointer, JsonPointerItem, Property};
use serde::de::{Error, MapAccess};
use std::{borrow::Cow, str::FromStr};

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

    fn metadata_pointer(&self) -> Option<(MetadataRoot, &JsonPointer<Self>)> {
        let pointer = self.as_pointer()?;
        let root = pointer.first()?.as_property_key()?.as_metadata_root()?;
        Some((root, pointer))
    }

    fn metadata_root(&self) -> Option<MetadataRoot> {
        self.as_metadata_root()
            .or_else(|| self.metadata_pointer().map(|(root, _)| root))
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

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MetadataFilter {
    pub root: MetadataRoot,
    pub path: MetadataPath,
    pub condition: MetadataCondition,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum MetadataCondition {
    Exists,
    TextContains(String),
    TextEquals(String),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataTextMatch {
    path: MetadataPath,
    value: String,
}

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
            Selection::Namespaces(namespaces) => namespaces.iter().any(|ns| &**ns == namespace),
        }
    }

    fn select_all(&mut self) {
        *self = Selection::All;
    }

    fn select_namespace(&mut self, namespace: Box<str>) {
        match self {
            Selection::None => *self = Selection::Namespaces(vec![namespace]),
            Selection::All => {}
            Selection::Namespaces(namespaces) => {
                if !namespaces.contains(&namespace) {
                    namespaces.push(namespace);
                }
            }
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

        result.map(|_| selection)
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

        match namespace {
            JsonPointerItem::Key(key) => Ok(key.to_string().into()),
            JsonPointerItem::Number(number) => Ok(number.to_string().into()),
            JsonPointerItem::Wildcard => Ok("*".into()),
            JsonPointerItem::Invalid(_) | JsonPointerItem::Root => {
                Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details(format!("Invalid metadata subselector {pointer}")))
            }
        }
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

impl<'de> serde::Deserialize<'de> for MetadataPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <Cow<'de, str>>::deserialize(deserializer)
            .and_then(|path| MetadataPath::from_str(&path).map_err(D::Error::custom))
    }
}

impl MetadataFilter {
    pub fn try_deserialize<'de, A>(key: &str, map: &mut A) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        hashify::fnc_map!(key.as_bytes(),
            b"metadataExists" => MetadataFilter::deserialize_exists(MetadataRoot::Shared, map),
            b"privateMetadataExists" => {
                MetadataFilter::deserialize_exists(MetadataRoot::Private, map)
            },
            b"metadataTextContains" => MetadataFilter::deserialize_text(
                MetadataRoot::Shared,
                MetadataCondition::TextContains,
                map,
            ),
            b"privateMetadataTextContains" => MetadataFilter::deserialize_text(
                MetadataRoot::Private,
                MetadataCondition::TextContains,
                map,
            ),
            b"metadataTextEquals" => MetadataFilter::deserialize_text(
                MetadataRoot::Shared,
                MetadataCondition::TextEquals,
                map,
            ),
            b"privateMetadataTextEquals" => MetadataFilter::deserialize_text(
                MetadataRoot::Private,
                MetadataCondition::TextEquals,
                map,
            ),
            _ => Ok(None),
        )
    }

    fn deserialize_exists<'de, A>(root: MetadataRoot, map: &mut A) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        Ok(Some(MetadataFilter {
            root,
            path: map.next_value()?,
            condition: MetadataCondition::Exists,
        }))
    }

    fn deserialize_text<'de, A>(
        root: MetadataRoot,
        condition: fn(String) -> MetadataCondition,
        map: &mut A,
    ) -> Result<Option<Self>, A::Error>
    where
        A: MapAccess<'de>,
    {
        let text_match = map.next_value::<MetadataTextMatch>()?;
        Ok(Some(MetadataFilter {
            root,
            path: text_match.path,
            condition: condition(text_match.value),
        }))
    }

    pub fn as_str(&self) -> &'static str {
        match (self.root, &self.condition) {
            (MetadataRoot::Shared, MetadataCondition::Exists) => "metadataExists",
            (MetadataRoot::Shared, MetadataCondition::TextContains(_)) => "metadataTextContains",
            (MetadataRoot::Shared, MetadataCondition::TextEquals(_)) => "metadataTextEquals",
            (MetadataRoot::Private, MetadataCondition::Exists) => "privateMetadataExists",
            (MetadataRoot::Private, MetadataCondition::TextContains(_)) => {
                "privateMetadataTextContains"
            }
            (MetadataRoot::Private, MetadataCondition::TextEquals(_)) => {
                "privateMetadataTextEquals"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MetadataCondition, MetadataFilter, MetadataPath, MetadataProperty, MetadataRoot,
        MetadataSelection, Selection,
    };
    use crate::{
        method::query::{Filter, QueryRequest},
        object::{
            addressbook::{AddressBook, AddressBookFilter, AddressBookProperty},
            calendar::{Calendar, CalendarFilter, CalendarProperty},
            email::{Email, EmailFilter, EmailProperty, EmailQueryFilter},
            file_node::FileNodeProperty,
            mailbox::{Mailbox, MailboxFilter, MailboxProperty, MailboxValue},
            sieve::SieveProperty,
        },
    };
    use jmap_tools::{Key, Value};
    use std::{fmt::Debug, str::FromStr};

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
            Selection::Namespaces(vec!["x.example".into(), "y.example".into(), "123".into()])
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
                Filter::Property(MailboxFilter::Metadata(MetadataFilter {
                    root: MetadataRoot::Shared,
                    path: path("x.example", Some("color")),
                    condition: MetadataCondition::Exists,
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter {
                    root: MetadataRoot::Private,
                    path: path("x.example", None),
                    condition: MetadataCondition::Exists,
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter {
                    root: MetadataRoot::Shared,
                    path: path("x.example", Some("memo")),
                    condition: MetadataCondition::TextContains("Follow Up".into()),
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter {
                    root: MetadataRoot::Private,
                    path: path("x/y", None),
                    condition: MetadataCondition::TextEquals("blue".into()),
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter {
                    root: MetadataRoot::Private,
                    path: path("x.example", Some("a~b")),
                    condition: MetadataCondition::TextContains("c".into()),
                })),
                Filter::Property(MailboxFilter::Metadata(MetadataFilter {
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
                Filter::Property(EmailQueryFilter::Metadata(MetadataFilter {
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
                Filter::Property(CalendarFilter::Metadata(MetadataFilter {
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
                MetadataFilter {
                    root: MetadataRoot::Private,
                    path: path("a.b", None),
                    condition: MetadataCondition::Exists,
                }
            ))]
        );

        for invalid in [
            r#"{"metadataExists": "a/b/c"}"#,
            r#"{"metadataExists": "a~2"}"#,
            r#"{"metadataExists": 1}"#,
            r#"{"metadataTextContains": "a"}"#,
            r#"{"metadataTextContains": {"path": "a", "value": "b", "other": 1}}"#,
            r#"{"privateMetadataTextEquals": {"path": "a"}}"#,
            r#"{"metadataTextEquals": {"path": "a/b/c", "value": "d"}}"#,
        ] {
            assert!(
                serde_json::from_str::<QueryRequest<Mailbox>>(&format!(
                    r#"{{"accountId": "a", "filter": {invalid}}}"#
                ))
                .is_err(),
                "{invalid}"
            );
        }
    }
}
