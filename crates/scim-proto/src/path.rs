/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{borrow::Cow, fmt};

use crate::{
    filter::{AttrPath, Filter, Parser},
    message::error::{Error, ScimType},
};

#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath<'x> {
    pub schema: Option<Cow<'x, str>>,
    pub attr: Cow<'x, str>,
    pub filter: Option<Filter<'x>>,
    pub sub_attr: Option<Cow<'x, str>>,
}

impl<'x> PatchPath<'x> {
    pub fn new(attr: impl Into<Cow<'x, str>>) -> Self {
        PatchPath {
            schema: None,
            attr: attr.into(),
            filter: None,
            sub_attr: None,
        }
    }

    pub fn with_schema(mut self, schema: impl Into<Cow<'x, str>>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    pub fn with_sub_attr(mut self, sub_attr: impl Into<Cow<'x, str>>) -> Self {
        self.sub_attr = Some(sub_attr.into());
        self
    }

    pub fn with_filter(mut self, filter: Filter<'x>) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn parse(input: &'x str) -> Result<Self, Error> {
        let mut parser = Parser::new(input);
        let path = parser.parse_attr_path().map_err(as_invalid_path)?;
        let mut result = PatchPath {
            schema: path.schema,
            attr: path.attr,
            filter: None,
            sub_attr: path.sub_attr,
        };

        if parser.peek() == Some(b'[') {
            if result.sub_attr.is_some() {
                return Err(Error::invalid_path(format!(
                    "Value filters may only follow an attribute, found '{input}'"
                )));
            }

            parser.bump();
            result.filter = Some(parser.parse_filter(0, true).map_err(as_invalid_path)?);
            parser.skip_ws();
            parser.expect(b']').map_err(as_invalid_path)?;

            if parser.peek() == Some(b'.') {
                parser.bump();
                result.sub_attr =
                    Some(Cow::Borrowed(parser.parse_name().map_err(as_invalid_path)?));
            }
        }

        if parser.is_eof() {
            Ok(result)
        } else {
            Err(Error::invalid_path(format!(
                "Unexpected character at position {} of path '{input}'",
                parser.position()
            )))
        }
    }

    pub fn as_attr_path(&self) -> AttrPath<'_> {
        AttrPath {
            schema: self.schema.as_deref().map(Cow::Borrowed),
            attr: Cow::Borrowed(self.attr.as_ref()),
            sub_attr: self.sub_attr.as_deref().map(Cow::Borrowed),
        }
    }

    pub fn targets_element(&self) -> bool {
        self.filter.is_some() && self.sub_attr.is_none()
    }

    pub fn matches(&self, attr: &str, sub_attr: Option<&str>) -> bool {
        self.attr.eq_ignore_ascii_case(attr)
            && match (self.sub_attr.as_deref(), sub_attr) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                (None, None) => true,
                _ => false,
            }
    }

    pub fn has_schema(&self, schema: &str) -> bool {
        self.schema
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(schema))
    }

    pub fn into_owned(self) -> PatchPath<'static> {
        PatchPath {
            schema: self.schema.map(|value| Cow::Owned(value.into_owned())),
            attr: Cow::Owned(self.attr.into_owned()),
            filter: self.filter.map(Filter::into_owned),
            sub_attr: self.sub_attr.map(|value| Cow::Owned(value.into_owned())),
        }
    }
}

fn as_invalid_path(error: Error) -> Error {
    Error {
        scim_type: Some(ScimType::InvalidPath),
        ..error
    }
}

impl fmt::Display for PatchPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(schema) = &self.schema {
            write!(f, "{schema}:")?;
        }
        f.write_str(self.attr.as_ref())?;
        if let Some(filter) = &self.filter {
            write!(f, "[{filter}]")?;
        }
        if let Some(sub_attr) = &self.sub_attr {
            write!(f, ".{sub_attr}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{CompValue, CompareOp};

    #[test]
    fn parse_rfc_examples() {
        for path in [
            "members",
            "name.familyName",
            r#"addresses[type eq "work"]"#,
            r#"members[value eq "2819c223-7f76-453a-919d-413861904646"]"#,
            r#"members[value eq "2819c223-7f76-453a-919d-413861904646"].displayName"#,
            r#"emails[type eq "work"].value"#,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.displayName",
        ] {
            let parsed = PatchPath::parse(path).unwrap_or_else(|err| panic!("{path}: {err}"));
            assert_eq!(parsed.to_string(), path);
        }
    }

    #[test]
    fn parse_attribute() {
        assert_eq!(
            PatchPath::parse("members").unwrap(),
            PatchPath::new("members")
        );
        assert_eq!(
            PatchPath::parse("name.formatted").unwrap(),
            PatchPath::new("name").with_sub_attr("formatted")
        );
    }

    #[test]
    fn parse_value_path_with_sub_attribute() {
        let path = PatchPath::parse(r#"emails[type eq "work"].value"#).unwrap();

        assert_eq!(path.attr, "emails");
        assert_eq!(path.sub_attr.as_deref(), Some("value"));
        assert_eq!(
            path.filter,
            Some(Filter::Compare {
                path: AttrPath::new("type"),
                op: CompareOp::Eq,
                value: CompValue::String("work".into()),
            })
        );
        assert!(!path.targets_element());
    }

    #[test]
    fn value_path_without_sub_attribute_targets_an_element() {
        let path = PatchPath::parse(r#"members[value eq "abc"]"#).unwrap();

        assert!(path.targets_element());
    }

    #[test]
    fn parse_schema_qualified_path() {
        let path = PatchPath::parse(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
        )
        .unwrap();

        assert_eq!(
            path.schema.as_deref(),
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
        );
        assert_eq!(path.attr, "employeeNumber");
        assert!(!path.has_schema(crate::SCHEMA_USER));
        assert!(PatchPath::new("userName").has_schema(crate::SCHEMA_USER));
    }

    #[test]
    fn reject_malformed_paths() {
        for path in [
            "",
            "1nvalid",
            "emails[",
            r#"emails[type eq "work""#,
            r#"emails.value[type eq "work"]"#,
            r#"emails[type eq "work"]."#,
            r#"emails[type eq "work"]value"#,
            "name..formatted",
            "name.formatted.extra",
        ] {
            let error = PatchPath::parse(path).unwrap_err();

            assert_eq!(error.status, 400, "{path}");
            assert_eq!(error.scim_type, Some(ScimType::InvalidPath), "{path}");
        }
    }

    #[test]
    fn into_owned_detaches_from_input() {
        let owned = {
            let input = String::from(r#"emails[type eq "work"].value"#);
            PatchPath::parse(&input).unwrap().into_owned()
        };

        assert_eq!(owned.to_string(), r#"emails[type eq "work"].value"#);
    }
}
