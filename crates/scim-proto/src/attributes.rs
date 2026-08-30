/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use serde_json::Value;

use crate::{
    filter::AttrPath,
    message::error::Error,
    schema::{Attribute, Schema},
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AttributeSelection<'x> {
    #[default]
    Default,
    Include(Vec<AttrPath<'x>>),
    Exclude(Vec<AttrPath<'x>>),
}

impl<'x> AttributeSelection<'x> {
    pub fn parse(
        attributes: Option<&'x str>,
        excluded_attributes: Option<&'x str>,
    ) -> Result<Self, Error> {
        match (attributes, excluded_attributes) {
            (Some(_), Some(_)) => Err(Error::invalid_value(
                "The 'attributes' and 'excludedAttributes' parameters are mutually exclusive",
            )),
            (Some(attributes), None) => parse_list(attributes.split(',')).map(Self::from_include),
            (None, Some(excluded)) => parse_list(excluded.split(',')).map(Self::from_exclude),
            (None, None) => Ok(Self::Default),
        }
    }

    pub fn from_lists(
        attributes: Option<&'x [Cow<'x, str>]>,
        excluded_attributes: Option<&'x [Cow<'x, str>]>,
    ) -> Result<Self, Error> {
        match (attributes, excluded_attributes) {
            (Some(attributes), Some(excluded))
                if !attributes.is_empty() && !excluded.is_empty() =>
            {
                Err(Error::invalid_value(
                    "The 'attributes' and 'excludedAttributes' parameters are mutually exclusive",
                ))
            }
            (Some(attributes), _) if !attributes.is_empty() => {
                parse_list(attributes.iter().map(Cow::as_ref)).map(Self::from_include)
            }
            (_, Some(excluded)) if !excluded.is_empty() => {
                parse_list(excluded.iter().map(Cow::as_ref)).map(Self::from_exclude)
            }
            _ => Ok(Self::Default),
        }
    }

    fn from_include(paths: Vec<AttrPath<'x>>) -> Self {
        if paths.is_empty() {
            Self::Default
        } else {
            Self::Include(paths)
        }
    }

    fn from_exclude(paths: Vec<AttrPath<'x>>) -> Self {
        if paths.is_empty() {
            Self::Default
        } else {
            Self::Exclude(paths)
        }
    }

    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    pub fn excludes(&self, schema: &Schema, attr: &str) -> bool {
        match self {
            Self::Default => false,
            _ if schema
                .attribute(attr)
                .is_some_and(Attribute::is_returned_always) =>
            {
                false
            }
            Self::Include(paths) => !paths.iter().any(|path| path.matches_attr(attr)),
            Self::Exclude(paths) => paths
                .iter()
                .any(|path| path.matches_attr(attr) && path.sub_attr.is_none()),
        }
    }

    pub fn apply(&self, schema: &Schema, resource: &mut Value) {
        let Some(object) = resource.as_object_mut() else {
            return;
        };

        object.retain(|name, value| {
            let Some(attribute) = schema.attribute(name) else {
                return true;
            };

            if attribute.is_returned_never() {
                return false;
            } else if attribute.is_returned_always() {
                return true;
            }

            match self {
                Self::Default => true,
                Self::Include(paths) => {
                    let mut sub_attrs = Vec::new();

                    for path in paths.iter().filter(|path| path.matches_attr(name)) {
                        match path.sub_attr.as_deref() {
                            Some(sub_attr) => sub_attrs.push(sub_attr),
                            None => return true,
                        }
                    }

                    if sub_attrs.is_empty() {
                        false
                    } else {
                        retain_sub_attributes(value, &sub_attrs, true);
                        true
                    }
                }
                Self::Exclude(paths) => {
                    let mut sub_attrs = Vec::new();

                    for path in paths.iter().filter(|path| path.matches_attr(name)) {
                        match path.sub_attr.as_deref() {
                            Some(sub_attr) => sub_attrs.push(sub_attr),
                            None => return false,
                        }
                    }

                    if !sub_attrs.is_empty() {
                        retain_sub_attributes(value, &sub_attrs, false);
                    }

                    true
                }
            }
        });
    }
}

fn parse_list<'x>(values: impl Iterator<Item = &'x str>) -> Result<Vec<AttrPath<'x>>, Error> {
    let mut result = Vec::new();

    for value in values {
        let value = value.trim();

        if !value.is_empty() {
            result.push(AttrPath::parse(value).map_err(|err| {
                Error::invalid_value(format!(
                    "Invalid attribute name '{value}'{}",
                    err.detail
                        .as_deref()
                        .map(|detail| format!(": {detail}"))
                        .unwrap_or_default()
                ))
            })?);
        }
    }

    Ok(result)
}

fn retain_sub_attributes(value: &mut Value, names: &[&str], keep: bool) {
    match value {
        Value::Object(object) => {
            object.retain(|name, _| {
                names
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(name))
                    == keep
            });
        }
        Value::Array(items) => {
            for item in items {
                retain_sub_attributes(item, names, keep);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::user::USER_SCHEMA;

    fn resource() -> Value {
        serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "abc",
            "userName": "bjensen@example.com",
            "displayName": "Babs Jensen",
            "active": true,
            "name": {"formatted": "Barbara Jensen"},
            "emails": [
                {"value": "bjensen@example.com", "type": "work", "primary": true},
                {"value": "babs@jensen.org", "type": "home"}
            ],
            "groups": [{"value": "g1", "display": "Sales"}],
            "meta": {"resourceType": "User", "created": "2010-01-23T04:56:22Z"}
        })
    }

    #[test]
    fn default_selection_keeps_everything() {
        let mut value = resource();
        AttributeSelection::Default.apply(&USER_SCHEMA, &mut value);

        assert_eq!(value, resource());
    }

    #[test]
    fn include_named_attributes() {
        let mut value = resource();
        AttributeSelection::parse(Some("userName,active"), None)
            .unwrap()
            .apply(&USER_SCHEMA, &mut value);

        assert_eq!(
            value,
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "abc",
                "userName": "bjensen@example.com",
                "active": true
            })
        );
    }

    #[test]
    fn include_sub_attributes() {
        let mut value = resource();
        AttributeSelection::parse(Some("emails.value"), None)
            .unwrap()
            .apply(&USER_SCHEMA, &mut value);

        assert_eq!(
            value["emails"],
            serde_json::json!([{"value": "bjensen@example.com"}, {"value": "babs@jensen.org"}])
        );
        assert!(value.get("displayName").is_none());
    }

    #[test]
    fn exclude_named_attributes() {
        let mut value = resource();
        AttributeSelection::parse(None, Some("groups,emails"))
            .unwrap()
            .apply(&USER_SCHEMA, &mut value);

        assert!(value.get("groups").is_none());
        assert!(value.get("emails").is_none());
        assert_eq!(value["userName"], "bjensen@example.com");
    }

    #[test]
    fn exclude_sub_attributes() {
        let mut value = resource();
        AttributeSelection::parse(None, Some("emails.type"))
            .unwrap()
            .apply(&USER_SCHEMA, &mut value);

        assert_eq!(
            value["emails"],
            serde_json::json!([
                {"value": "bjensen@example.com", "primary": true},
                {"value": "babs@jensen.org"}
            ])
        );
    }

    #[test]
    fn always_returned_attributes_survive_exclusion() {
        let mut value = resource();
        AttributeSelection::parse(None, Some("id"))
            .unwrap()
            .apply(&USER_SCHEMA, &mut value);

        assert_eq!(value["id"], "abc");
    }

    #[test]
    fn always_returned_attributes_survive_inclusion() {
        let mut value = resource();
        AttributeSelection::parse(Some("displayName"), None)
            .unwrap()
            .apply(&USER_SCHEMA, &mut value);

        assert_eq!(value["id"], "abc");
        assert_eq!(value["schemas"][0], crate::SCHEMA_USER);
    }

    #[test]
    fn mutually_exclusive_parameters() {
        let error = AttributeSelection::parse(Some("userName"), Some("groups")).unwrap_err();

        assert_eq!(error.status, 400);
        assert_eq!(
            error.scim_type,
            Some(crate::message::error::ScimType::InvalidValue)
        );
    }

    #[test]
    fn invalid_attribute_names_are_rejected() {
        assert!(AttributeSelection::parse(Some("user name"), None).is_err());
        assert!(AttributeSelection::parse(Some("1user"), None).is_err());
    }

    #[test]
    fn excludes_reports_membership() {
        let schema = &crate::schema::group::GROUP_SCHEMA;
        let selection = AttributeSelection::parse(None, Some("members")).unwrap();
        assert!(selection.excludes(schema, "members"));
        assert!(selection.excludes(schema, "MEMBERS"));
        assert!(!selection.excludes(schema, "displayName"));

        let selection = AttributeSelection::parse(Some("displayName"), None).unwrap();
        assert!(selection.excludes(schema, "members"));
        assert!(!selection.excludes(schema, "displayName"));
        assert!(!selection.excludes(schema, "id"));

        assert!(!AttributeSelection::Default.excludes(schema, "members"));
    }

    #[test]
    fn empty_parameters_are_the_default_selection() {
        assert!(
            AttributeSelection::parse(Some(""), None)
                .unwrap()
                .is_default()
        );
        assert!(
            AttributeSelection::parse(None, Some(""))
                .unwrap()
                .is_default()
        );
        assert!(
            AttributeSelection::from_lists(Some(&[]), None)
                .unwrap()
                .is_default()
        );
    }

    #[test]
    fn from_lists_matches_query_parsing() {
        let attributes = [Cow::Borrowed("userName"), Cow::Borrowed("active")];
        let selection = AttributeSelection::from_lists(Some(&attributes), None).unwrap();

        assert_eq!(
            selection,
            AttributeSelection::parse(Some("userName,active"), None).unwrap()
        );
    }
}
