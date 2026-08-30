/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use serde::{Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;

use crate::{MESSAGE_PATCH_OP, json::scim_object, message::error::Error, path::PatchPath};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PatchRequest<'x> {
    pub operations: Vec<PatchOperation<'x>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PatchOperation<'x> {
    pub op: PatchOp,
    pub path: PatchPath<'x>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchOp {
    Add,
    Remove,
    Replace,
}

scim_object!(PatchBody<'x>, Some(MESSAGE_PATCH_OP), {
    "Operations" => any operations: Option<Vec<PatchOperationBody<'x>>>,
});

scim_object!(PatchOperationBody<'x>, None::<&'static str>, {
    "op" => str op: Option<Cow<'x, str>>,
    "path" => str path: Option<Cow<'x, str>>,
    "value" => any value: Option<Value>,
});

impl PatchOp {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map_ignore_case!(value.as_bytes(),
            "add" => PatchOp::Add,
            "remove" => PatchOp::Remove,
            "replace" => PatchOp::Replace,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PatchOp::Add => "add",
            PatchOp::Remove => "remove",
            PatchOp::Replace => "replace",
        }
    }
}

impl<'x> PatchRequest<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        let body = serde_json::from_slice::<PatchBody<'x>>(body)
            .map_err(|err| Error::invalid_syntax(err.to_string()))?;
        let operations = body
            .operations
            .ok_or_else(|| Error::invalid_syntax("Missing 'Operations' attribute"))?;

        if operations.is_empty() {
            return Err(Error::invalid_syntax(
                "The 'Operations' attribute must contain at least one operation",
            ));
        }

        let mut result = Vec::with_capacity(operations.len());

        for operation in operations {
            let op = operation
                .op
                .as_deref()
                .ok_or_else(|| Error::invalid_syntax("Missing 'op' attribute"))
                .and_then(|op| {
                    PatchOp::parse(op).ok_or_else(|| {
                        Error::invalid_syntax(format!("Unknown patch operation '{op}'"))
                    })
                })?;

            match operation.path {
                Some(Cow::Borrowed(path)) => {
                    push(op, PatchPath::parse(path)?, operation.value, &mut result)?
                }
                Some(Cow::Owned(path)) => push(
                    op,
                    PatchPath::parse(&path)?.into_owned(),
                    operation.value,
                    &mut result,
                )?,
                None => expand(op, operation.value, &mut result)?,
            }
        }

        Ok(PatchRequest { operations: result })
    }
}

fn push<'x>(
    op: PatchOp,
    path: PatchPath<'x>,
    value: Option<Value>,
    result: &mut Vec<PatchOperation<'x>>,
) -> Result<(), Error> {
    if op != PatchOp::Remove {
        if path.targets_element() {
            return Err(Error::invalid_path(format!(
                "Path '{path}' must target a sub-attribute of the matched element"
            )));
        } else if value.as_ref().is_none_or(Value::is_null) {
            return Err(Error::invalid_syntax(format!(
                "Missing 'value' attribute for operation '{}' on path '{path}'",
                op.as_str()
            )));
        }
    }

    result.push(PatchOperation { op, path, value });

    Ok(())
}

fn expand<'x>(
    op: PatchOp,
    value: Option<Value>,
    result: &mut Vec<PatchOperation<'x>>,
) -> Result<(), Error> {
    if op == PatchOp::Remove {
        return Err(Error::no_target(
            "A 'remove' operation requires a 'path' attribute",
        ));
    }

    let Some(Value::Object(value)) = value else {
        return Err(Error::invalid_syntax(
            "An operation without a 'path' requires an object 'value'",
        ));
    };

    if value.is_empty() {
        return Err(Error::invalid_syntax(
            "An operation without a 'path' requires at least one attribute",
        ));
    }

    for (name, value) in value {
        if name.contains(':') {
            let Value::Object(value) = value else {
                return Err(Error::invalid_syntax(format!(
                    "Schema extension '{name}' requires an object value"
                )));
            };

            if value.is_empty() {
                return Err(Error::invalid_syntax(format!(
                    "Schema extension '{name}' requires at least one attribute"
                )));
            }

            for (sub_name, value) in value {
                if sub_name.contains(':') {
                    return Err(Error::invalid_syntax(format!(
                        "Invalid attribute '{sub_name}' within schema extension '{name}'"
                    )));
                }

                push(
                    op,
                    PatchPath::parse(&sub_name)?
                        .into_owned()
                        .with_schema(name.clone()),
                    Some(value),
                    result,
                )?;
            }
        } else {
            push(
                op,
                PatchPath::parse(&name)?.into_owned(),
                Some(value),
                result,
            )?;
        }
    }

    Ok(())
}

impl PatchOperation<'_> {
    pub fn value_as_str(&self) -> Option<&str> {
        self.value.as_ref().and_then(Value::as_str)
    }

    pub fn value_as_bool(&self) -> Option<bool> {
        match self.value.as_ref()? {
            Value::Bool(value) => Some(*value),
            Value::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
            Value::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        }
    }

    pub fn value_as_array(&self) -> Option<&[Value]> {
        self.value
            .as_ref()
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    }
}

impl Serialize for PatchRequest<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[MESSAGE_PATCH_OP])?;
        map.serialize_entry("Operations", &self.operations)?;
        map.end()
    }
}

impl Serialize for PatchOperation<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("op", self.op.as_str())?;
        map.serialize_entry("path", &Displayed(&self.path))?;
        if let Some(value) = &self.value {
            map.serialize_entry("value", value)?;
        }
        map.end()
    }
}

struct Displayed<'a, T: std::fmt::Display>(&'a T);

impl<T: std::fmt::Display> Serialize for Displayed<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::error::ScimType;

    #[test]
    fn parse_deactivation() {
        let request = PatchRequest::parse(
            br#"{
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "path": "active", "value": false}]
            }"#,
        )
        .unwrap();

        assert_eq!(request.operations.len(), 1);
        assert_eq!(request.operations[0].op, PatchOp::Replace);
        assert!(request.operations[0].path.matches("active", None));
        assert_eq!(request.operations[0].value_as_bool(), Some(false));
    }

    #[test]
    fn operations_are_case_insensitive() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                {"op": "Replace", "path": "active", "value": false},
                {"OP": "Add", "PATH": "displayName", "VALUE": "Babs"},
                {"op": "REMOVE", "path": "members[value eq \"abc\"]"}
            ]}"#,
        )
        .unwrap();

        assert_eq!(request.operations[0].op, PatchOp::Replace);
        assert_eq!(request.operations[1].op, PatchOp::Add);
        assert_eq!(request.operations[1].value_as_str(), Some("Babs"));
        assert_eq!(request.operations[2].op, PatchOp::Remove);
    }

    #[test]
    fn path_less_operations_are_expanded() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                 "Operations": [{"op": "replace", "value": {"active": false}}]}"#,
        )
        .unwrap();

        assert_eq!(request.operations.len(), 1);
        assert!(request.operations[0].path.matches("active", None));
        assert_eq!(request.operations[0].value_as_bool(), Some(false));
    }

    #[test]
    fn path_less_operations_expand_every_key() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                {"op": "replace", "value": {"active": false, "displayName": "Babs"}}
            ]}"#,
        )
        .unwrap();

        assert_eq!(request.operations.len(), 2);
        assert!(
            request
                .operations
                .iter()
                .any(|op| op.path.matches("active", None))
        );
        assert!(
            request
                .operations
                .iter()
                .any(|op| op.path.matches("displayName", None))
        );
    }

    #[test]
    fn path_less_extension_values_are_expanded() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{
                "op": "add",
                "value": {
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "department": "Sales"
                    }
                }
            }]}"#,
        )
        .unwrap();

        assert_eq!(request.operations.len(), 1);
        assert_eq!(
            request.operations[0].path.schema.as_deref(),
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
        );
        assert!(request.operations[0].path.matches("department", None));
    }

    #[test]
    fn parse_value_filter_paths() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                {"op": "replace", "path": "emails[type eq \"work\"].value", "value": "a@b.c"}
            ]}"#,
        )
        .unwrap();

        let path = &request.operations[0].path;
        assert_eq!(path.to_string(), r#"emails[type eq "work"].value"#);
        assert!(!path.targets_element());
    }

    #[test]
    fn remove_may_target_an_element() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                {"op": "remove", "path": "members[value eq \"2819c223\"]"}
            ]}"#,
        )
        .unwrap();

        assert!(request.operations[0].path.targets_element());
        assert!(request.operations[0].value.is_none());
    }

    #[test]
    fn add_and_replace_may_not_target_an_element() {
        for op in ["add", "replace"] {
            let body = format!(
                r#"{{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                    {{"op": "{op}", "path": "emails[type eq \"work\"]", "value": {{"value": "a"}}}}
                ]}}"#
            );
            let error = PatchRequest::parse(body.as_bytes()).unwrap_err();

            assert_eq!(error.status, 400);
            assert_eq!(error.scim_type, Some(ScimType::InvalidPath), "{op}");
        }
    }

    #[test]
    fn path_less_remove_has_no_target() {
        let error = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "value": {"active": false}}]}"#,
        )
        .unwrap_err();

        assert_eq!(error.status, 400);
        assert_eq!(error.scim_type, Some(ScimType::NoTarget));
    }

    #[test]
    fn path_less_operations_obey_the_same_guards() {
        for body in [
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                 {"op": "add", "value": {"emails[type eq \"work\"]": {"value": "x"}}}]}"#
                .as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                 {"op": "replace", "value": {"displayName": null}}]}"#
                .as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                 {"op": "replace", "value": {}}]}"#
                .as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                 {"op": "add", "value": {"urn:x:y": {}}}]}"#
                .as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                 {"op": "add", "value": {"urn:x:y": {"urn:p:q:a": "v"}}}]}"#
                .as_slice(),
        ] {
            let error = PatchRequest::parse(body).unwrap_err();

            assert_eq!(error.status, 400, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn paths_are_borrowed_when_unescaped() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                 "Operations": [{"op": "replace", "path": "active", "value": false}]}"#,
        )
        .unwrap();

        assert!(matches!(request.operations[0].path.attr, Cow::Borrowed(_)));
    }

    #[test]
    fn reject_malformed_requests() {
        for body in [
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "value": false}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "value": "active"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"path": "active", "value": false}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "merge", "path": "active", "value": false}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                 "Operations": []}"#
                .as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "value": {"urn:x:y": "not an object"}}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                 "Operations": []}"#
                .as_slice(),
            br#"{"Operations": [{"op": "replace", "path": "active", "value": false}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                 {"op": "replace", "op": "add", "path": "active", "value": false}]}"#
                .as_slice(),
            br#"{}"#.as_slice(),
            br#"not json"#.as_slice(),
        ] {
            let error = PatchRequest::parse(body).unwrap_err();

            assert_eq!(error.status, 400, "{}", String::from_utf8_lossy(body));
        }
    }

    #[test]
    fn parse_rfc_multi_operation_request() {
        let request = PatchRequest::parse(
            br#"{
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "add", "path": "members", "value": [
                        {"display": "Babs Jensen", "$ref": "https://example.com/v2/Users/2819c223",
                         "value": "2819c223"}
                    ]},
                    {"op": "remove", "path": "members[value eq \"2819c223\"]"},
                    {"op": "replace", "path": "name.formatted", "value": "Babs Jensen"}
                ]
            }"#,
        )
        .unwrap();

        assert_eq!(request.operations.len(), 3);
        assert_eq!(request.operations[0].value_as_array().unwrap().len(), 1);
        assert!(
            request.operations[2]
                .path
                .matches("name", Some("formatted"))
        );
    }

    #[test]
    fn serialize_round_trip() {
        let request = PatchRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [
                {"op": "replace", "path": "emails[type eq \"work\"].value", "value": "a@b.c"}
            ]}"#,
        )
        .unwrap();
        let json = serde_json::to_vec(&request).unwrap();

        assert_eq!(PatchRequest::parse(&json).unwrap(), request);
    }
}
