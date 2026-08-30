/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{
    borrow::Cow,
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor};
use serde_json::Value;

use crate::{
    MESSAGE_BULK_REQUEST, MESSAGE_BULK_RESPONSE, ResourceType,
    json::scim_object,
    message::error::{Error, StatusCode},
};

pub const BULK_ID_PREFIX: &str = "bulkId:";

scim_object!(pub BulkRequest<'x>, Some(MESSAGE_BULK_REQUEST), {
    "failOnErrors" => any fail_on_errors: Option<usize>,
    "Operations" => any operations: Option<Vec<BulkOperation<'x>>>,
});

scim_object!(pub BulkOperation<'x>, None::<&'static str>, {
    "method" => any method: Option<BulkMethod>,
    "bulkId" => str bulk_id: Option<Cow<'x, str>>,
    "version" => str version: Option<Cow<'x, str>>,
    "path" => str path: Option<Cow<'x, str>>,
    "data" => any data: Option<Value>,
});

scim_object!(pub BulkResponse<'x>, Some(MESSAGE_BULK_RESPONSE), {
    "Operations" => any operations: Option<Vec<BulkOperationResponse<'x>>>,
});

scim_object!(pub BulkOperationResponse<'x>, None::<&'static str>, {
    "method" => any method: Option<BulkMethod>,
    "bulkId" => str bulk_id: Option<Cow<'x, str>>,
    "version" => str version: Option<Cow<'x, str>>,
    "location" => str location: Option<Cow<'x, str>>,
    "status" => any status: Option<StatusCode>,
    "response" => any response: Option<Error>,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BulkMethod {
    Post,
    Put,
    Patch,
    Delete,
}

impl BulkMethod {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map_ignore_case!(value.as_bytes(),
            "POST" => BulkMethod::Post,
            "PUT" => BulkMethod::Put,
            "PATCH" => BulkMethod::Patch,
            "DELETE" => BulkMethod::Delete,
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BulkMethod::Post => "POST",
            BulkMethod::Put => "PUT",
            BulkMethod::Patch => "PATCH",
            BulkMethod::Delete => "DELETE",
        }
    }

    pub fn requires_data(&self) -> bool {
        matches!(self, BulkMethod::Post | BulkMethod::Put | BulkMethod::Patch)
    }
}

impl<'x> BulkRequest<'x> {
    pub fn parse(body: &'x [u8], max_operations: usize) -> Result<Self, Error> {
        let request = serde_json::from_slice::<BulkRequest<'x>>(body)
            .map_err(|err| Error::invalid_syntax(err.to_string()))?;
        let operations = request
            .operations
            .as_deref()
            .ok_or_else(|| Error::invalid_syntax("Missing 'Operations' attribute"))?;

        if operations.is_empty() {
            return Err(Error::invalid_syntax(
                "The 'Operations' attribute must contain at least one operation",
            ));
        } else if operations.len() > max_operations {
            return Err(Error::max_operations_exceeded(max_operations));
        }

        let mut bulk_ids = HashSet::with_capacity(operations.len());

        for operation in operations {
            operation.validate()?;

            if let Some(bulk_id) = operation.bulk_id.as_deref()
                && !bulk_ids.insert(bulk_id)
            {
                return Err(Error::invalid_value(format!(
                    "Duplicate 'bulkId' value '{bulk_id}'"
                )));
            }
        }

        Ok(request)
    }

    pub fn operations(&self) -> &[BulkOperation<'x>] {
        self.operations.as_deref().unwrap_or_default()
    }

    pub fn processing_order(&self) -> Result<Vec<usize>, Error> {
        let operations = self.operations();
        let mut dependents = vec![Vec::new(); operations.len()];
        let mut pending = vec![0usize; operations.len()];

        for (idx, operation) in operations.iter().enumerate() {
            for reference in operation.references() {
                if let Some(target) = operations.iter().position(|operation| {
                    operation
                        .bulk_id
                        .as_deref()
                        .is_some_and(|bulk_id| bulk_id == reference)
                }) && target != idx
                {
                    dependents[target].push(idx);
                    pending[idx] += 1;
                }
            }
        }

        let mut ready = (0..operations.len())
            .filter(|idx| pending[*idx] == 0)
            .map(Reverse)
            .collect::<BinaryHeap<_>>();
        let mut order = Vec::with_capacity(operations.len());

        while let Some(Reverse(idx)) = ready.pop() {
            order.push(idx);

            for dependent in &dependents[idx] {
                pending[*dependent] -= 1;

                if pending[*dependent] == 0 {
                    ready.push(Reverse(*dependent));
                }
            }
        }

        if order.len() == operations.len() {
            Ok(order)
        } else {
            Err(Error::conflict(
                "Circular 'bulkId' references could not be resolved",
            ))
        }
    }
}

impl<'x> BulkOperation<'x> {
    pub fn method(&self) -> Result<BulkMethod, Error> {
        self.method
            .ok_or_else(|| Error::invalid_syntax("Missing 'method' attribute"))
    }

    pub fn validate(&self) -> Result<(), Error> {
        let method = self.method()?;
        let (resource_type, id) = self.resource_path()?;

        match method {
            BulkMethod::Post => {
                if id.is_some() {
                    return Err(Error::invalid_value(format!(
                        "A 'POST' operation must target the '{}' endpoint",
                        resource_type.endpoint()
                    )));
                } else if self.bulk_id.as_deref().is_none_or(str::is_empty) {
                    return Err(Error::invalid_syntax(
                        "A 'POST' operation requires a 'bulkId' attribute",
                    ));
                }
            }
            _ => {
                if id.is_none() {
                    return Err(Error::invalid_value(format!(
                        "A '{}' operation must target a specific resource",
                        method.as_str()
                    )));
                }
            }
        }

        if method.requires_data() && self.data.is_none() {
            return Err(Error::invalid_syntax(format!(
                "A '{}' operation requires a 'data' attribute",
                method.as_str()
            )));
        }

        Ok(())
    }

    pub fn resource_path(&self) -> Result<(ResourceType, Option<&str>), Error> {
        let path = self
            .path
            .as_deref()
            .ok_or_else(|| Error::invalid_syntax("Missing 'path' attribute"))?;
        let unknown_path = || Error::invalid_value(format!("Unknown path '{path}'"));
        let endpoint = path.strip_prefix('/').ok_or_else(unknown_path)?;
        let (resource_type, id) = match endpoint.split_once('/') {
            Some((resource_type, id)) => (resource_type, Some(id)),
            None => (endpoint, None),
        };

        match (ResourceType::from_endpoint(resource_type), id) {
            (Some(resource_type), None) => Ok((resource_type, None)),
            (Some(resource_type), Some(id)) if !id.is_empty() && !id.contains('/') => {
                Ok((resource_type, Some(id)))
            }
            _ => Err(unknown_path()),
        }
    }

    pub fn references(&self) -> Vec<&str> {
        let mut references = Vec::new();

        if let Some(data) = &self.data {
            collect_bulk_id_refs(data, &mut references);
        }

        references
    }
}

impl<'x> BulkResponse<'x> {
    pub fn new(operations: Vec<BulkOperationResponse<'x>>) -> Self {
        BulkResponse {
            operations: Some(operations),
        }
    }
}

impl<'x> BulkOperationResponse<'x> {
    pub fn new(method: BulkMethod, status: u16) -> Self {
        BulkOperationResponse {
            method: Some(method),
            status: Some(StatusCode(status)),
            ..Default::default()
        }
    }

    pub fn with_bulk_id(mut self, bulk_id: impl Into<Cow<'x, str>>) -> Self {
        self.bulk_id = Some(bulk_id.into());
        self
    }

    pub fn with_location(mut self, location: impl Into<Cow<'x, str>>) -> Self {
        self.location = Some(location.into());
        self
    }

    pub fn with_version(mut self, version: impl Into<Cow<'x, str>>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_error(mut self, error: Error) -> Self {
        self.status = Some(StatusCode(error.status));
        self.response = Some(error);
        self
    }

    pub fn is_error(&self) -> bool {
        self.status.is_some_and(|status| status.0 >= 400)
    }
}

pub fn bulk_id_reference(value: &str) -> Option<&str> {
    value.strip_prefix(BULK_ID_PREFIX)
}

pub fn collect_bulk_id_refs<'a>(value: &'a Value, references: &mut Vec<&'a str>) {
    match value {
        Value::String(value) => {
            if let Some(reference) = bulk_id_reference(value) {
                references.push(reference);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_bulk_id_refs(item, references);
            }
        }
        Value::Object(entries) => {
            for value in entries.values() {
                collect_bulk_id_refs(value, references);
            }
        }
        _ => {}
    }
}

pub fn resolve_bulk_id_refs(
    value: &mut Value,
    resolve: &impl Fn(&str) -> Option<String>,
) -> Result<(), Error> {
    match value {
        Value::String(text) => {
            if let Some(reference) = bulk_id_reference(text) {
                match resolve(reference) {
                    Some(resolved) => *text = resolved,
                    None => {
                        return Err(Error::invalid_value(format!(
                            "Unresolved 'bulkId' reference '{reference}'"
                        )));
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                resolve_bulk_id_refs(item, resolve)?;
            }
        }
        Value::Object(entries) => {
            for value in entries.values_mut() {
                resolve_bulk_id_refs(value, resolve)?;
            }
        }
        _ => {}
    }

    Ok(())
}

impl Serialize for BulkMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BulkMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MethodVisitor;

        impl<'de> Visitor<'de> for MethodVisitor {
            type Value = BulkMethod;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an HTTP method")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                BulkMethod::parse(v)
                    .ok_or_else(|| E::custom(format!("Unsupported bulk method '{v}'")))
            }
        }

        deserializer.deserialize_str(MethodVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_REQUEST: &[u8] = br#"{
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "failOnErrors": 1,
        "Operations": [
            {
                "method": "POST",
                "path": "/Users",
                "bulkId": "qwerty",
                "data": {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "Alice"
                }
            },
            {
                "method": "POST",
                "path": "/Groups",
                "bulkId": "ytrewq",
                "data": {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "displayName": "Tour Guides",
                    "members": [{"type": "User", "value": "bulkId:qwerty"}]
                }
            }
        ]
    }"#;

    #[test]
    fn parse_rfc_request() {
        let request = BulkRequest::parse(RFC_REQUEST, 1000).unwrap();

        assert_eq!(request.fail_on_errors, Some(1));
        assert_eq!(request.operations().len(), 2);

        let operation = &request.operations()[0];
        assert_eq!(operation.method, Some(BulkMethod::Post));
        assert_eq!(operation.bulk_id.as_deref(), Some("qwerty"));
        assert_eq!(
            operation.resource_path().unwrap(),
            (ResourceType::User, None)
        );
        assert_eq!(request.operations()[1].references(), ["qwerty"]);
    }

    #[test]
    fn methods_are_case_insensitive() {
        let request = BulkRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "patch", "path": "/Users/abc", "data": {}}]}"#,
            1000,
        )
        .unwrap();

        assert_eq!(request.operations()[0].method, Some(BulkMethod::Patch));
    }

    #[test]
    fn parse_resource_paths() {
        for (path, expected) in [
            ("/Users", Some((ResourceType::User, None))),
            ("/Groups", Some((ResourceType::Group, None))),
            ("/Users/abc", Some((ResourceType::User, Some("abc")))),
            ("/Devices", None),
            ("Users", None),
            ("/Users/abc/emails", None),
            ("/Users/", None),
        ] {
            let operation = BulkOperation {
                path: Some(path.into()),
                ..Default::default()
            };

            assert_eq!(operation.resource_path().ok(), expected, "{path}");
        }
    }

    #[test]
    fn reject_invalid_operations() {
        for body in [
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"path": "/Users", "bulkId": "a", "data": {}}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "POST", "bulkId": "a", "data": {}}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "POST", "path": "/Users", "data": {}}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "POST", "path": "/Users", "bulkId": "a"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "POST", "path": "/Users/abc", "bulkId": "a",
                 "data": {}}]}"#
                .as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "DELETE", "path": "/Users"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "PUT", "path": "/Users/abc"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [{"method": "HEAD", "path": "/Users/abc"}]}"#.as_slice(),
            br#"{}"#.as_slice(),
        ] {
            assert!(
                BulkRequest::parse(body, 1000).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn duplicate_bulk_ids_are_rejected() {
        let error = BulkRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [
                {"method": "POST", "path": "/Users", "bulkId": "a", "data": {"userName": "x"}},
                {"method": "POST", "path": "/Users", "bulkId": "a", "data": {"userName": "y"}}
            ]}"#,
            1000,
        )
        .unwrap_err();

        assert_eq!(error.status, 400);
        assert!(
            error.detail.as_deref().unwrap().contains("bulkId"),
            "{error}"
        );
    }

    #[test]
    fn empty_and_unidentified_requests_are_rejected() {
        for body in [
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
                 "Operations": []}"#
                .as_slice(),
            br#"{"Operations": [{"method": "DELETE", "path": "/Users/abc"}]}"#.as_slice(),
        ] {
            assert!(
                BulkRequest::parse(body, 1000).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn endpoints_are_matched_exactly() {
        for path in ["/user/abc", "/USERS", "/User/abc", "/users"] {
            let operation = BulkOperation {
                path: Some(path.into()),
                ..Default::default()
            };

            assert!(operation.resource_path().is_err(), "{path}");
        }
    }

    #[test]
    fn max_operations_is_enforced() {
        let error = BulkRequest::parse(RFC_REQUEST, 1).unwrap_err();

        assert_eq!(error.status, 413);
        assert!(
            error.detail.as_deref().unwrap().contains("maxOperations"),
            "{error}"
        );
    }

    #[test]
    fn forward_references_are_ordered() {
        let request = BulkRequest::parse(RFC_REQUEST, 1000).unwrap();
        let order = request.processing_order().unwrap();

        assert_eq!(order, [0, 1]);
    }

    #[test]
    fn dependencies_are_processed_first() {
        let request = BulkRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [
                {"method": "POST", "path": "/Groups", "bulkId": "g",
                 "data": {"members": [{"value": "bulkId:u"}]}},
                {"method": "POST", "path": "/Users", "bulkId": "u", "data": {"userName": "a"}}
            ]}"#,
            1000,
        )
        .unwrap();

        assert_eq!(request.processing_order().unwrap(), [1, 0]);
    }

    #[test]
    fn circular_references_are_detected() {
        let request = BulkRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [
                {"method": "POST", "path": "/Groups", "bulkId": "qwerty",
                 "data": {"members": [{"value": "bulkId:ytrewq"}]}},
                {"method": "POST", "path": "/Groups", "bulkId": "ytrewq",
                 "data": {"members": [{"value": "bulkId:qwerty"}]}}
            ]}"#,
            1000,
        )
        .unwrap();

        let error = request.processing_order().unwrap_err();
        assert_eq!(error.status, 409);
    }

    #[test]
    fn self_references_are_ignored() {
        let request = BulkRequest::parse(
            br#"{"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"], "Operations": [
                {"method": "POST", "path": "/Groups", "bulkId": "a",
                 "data": {"members": [{"value": "bulkId:a"}]}}
            ]}"#,
            1000,
        )
        .unwrap();

        assert_eq!(request.processing_order().unwrap(), [0]);
    }

    #[test]
    fn resolve_references() {
        let mut request = BulkRequest::parse(RFC_REQUEST, 1000).unwrap();
        let mut operations = request.operations.take().unwrap();

        resolve_bulk_id_refs(operations[1].data.as_mut().unwrap(), &|reference| {
            (reference == "qwerty").then(|| "2819c223".to_string())
        })
        .unwrap();

        assert_eq!(
            operations[1].data.as_ref().unwrap()["members"][0]["value"],
            "2819c223"
        );
    }

    #[test]
    fn unresolved_references_are_an_error() {
        let mut value = serde_json::json!({"members": [{"value": "bulkId:missing"}]});
        let error = resolve_bulk_id_refs(&mut value, &|_| None).unwrap_err();

        assert_eq!(error.status, 400);
        assert!(
            error.detail.as_deref().unwrap().contains("missing"),
            "{error}"
        );
    }

    #[test]
    fn extension_references_are_found() {
        let value = serde_json::json!({
            "userName": "Bob",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "manager": {"value": "bulkId:qwerty"}
            }
        });
        let mut references = Vec::new();
        collect_bulk_id_refs(&value, &mut references);

        assert_eq!(references, ["qwerty"]);
    }

    #[test]
    fn serialize_response() {
        let response = BulkResponse::new(vec![
            BulkOperationResponse::new(BulkMethod::Post, 201)
                .with_bulk_id("qwerty")
                .with_location("https://example.com/scim/v2/Users/92b725cd")
                .with_version("W/\"oY4m4wn58tkVjJxK\""),
            BulkOperationResponse::new(BulkMethod::Patch, 200)
                .with_error(Error::invalid_syntax("Request is unparsable")),
        ]);

        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
                "Operations": [
                    {
                        "method": "POST",
                        "bulkId": "qwerty",
                        "version": "W/\"oY4m4wn58tkVjJxK\"",
                        "location": "https://example.com/scim/v2/Users/92b725cd",
                        "status": "201"
                    },
                    {
                        "method": "PATCH",
                        "status": "400",
                        "response": {
                            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                            "scimType": "invalidSyntax",
                            "detail": "Request is unparsable",
                            "status": "400"
                        }
                    }
                ]
            })
        );
    }

    #[test]
    fn response_errors_are_detected() {
        assert!(
            BulkOperationResponse::new(BulkMethod::Post, 201)
                .with_error(Error::not_found())
                .is_error()
        );
        assert!(!BulkOperationResponse::new(BulkMethod::Post, 201).is_error());
    }
}
