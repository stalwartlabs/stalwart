/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::{borrow::Cow, fmt};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{MapAccess, Visitor},
    ser::SerializeMap,
};

use crate::{MESSAGE_ERROR, json::Str};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub status: u16,
    pub scim_type: Option<ScimType>,
    pub detail: Option<Cow<'static, str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScimType {
    InvalidFilter,
    TooMany,
    Uniqueness,
    Mutability,
    InvalidSyntax,
    InvalidPath,
    NoTarget,
    InvalidValue,
    InvalidVers,
    Sensitive,
    InvalidCursor,
    ExpiredCursor,
    InvalidCount,
}

impl ScimType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScimType::InvalidFilter => "invalidFilter",
            ScimType::TooMany => "tooMany",
            ScimType::Uniqueness => "uniqueness",
            ScimType::Mutability => "mutability",
            ScimType::InvalidSyntax => "invalidSyntax",
            ScimType::InvalidPath => "invalidPath",
            ScimType::NoTarget => "noTarget",
            ScimType::InvalidValue => "invalidValue",
            ScimType::InvalidVers => "invalidVers",
            ScimType::Sensitive => "sensitive",
            ScimType::InvalidCursor => "invalidCursor",
            ScimType::ExpiredCursor => "expiredCursor",
            ScimType::InvalidCount => "invalidCount",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map!(value.as_bytes(),
            "invalidFilter" => ScimType::InvalidFilter,
            "tooMany" => ScimType::TooMany,
            "uniqueness" => ScimType::Uniqueness,
            "mutability" => ScimType::Mutability,
            "invalidSyntax" => ScimType::InvalidSyntax,
            "invalidPath" => ScimType::InvalidPath,
            "noTarget" => ScimType::NoTarget,
            "invalidValue" => ScimType::InvalidValue,
            "invalidVers" => ScimType::InvalidVers,
            "sensitive" => ScimType::Sensitive,
            "invalidCursor" => ScimType::InvalidCursor,
            "expiredCursor" => ScimType::ExpiredCursor,
            "invalidCount" => ScimType::InvalidCount,
        )
    }
}

impl Error {
    pub fn new(status: u16) -> Self {
        Error {
            status,
            scim_type: None,
            detail: None,
        }
    }

    pub fn with_scim_type(mut self, scim_type: ScimType) -> Self {
        self.scim_type = Some(scim_type);
        self
    }

    pub fn with_detail(mut self, detail: impl Into<Cow<'static, str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn bad_request(scim_type: ScimType, detail: impl Into<Cow<'static, str>>) -> Self {
        Error {
            status: 400,
            scim_type: Some(scim_type),
            detail: Some(detail.into()),
        }
    }

    pub fn invalid_filter(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidFilter, detail)
    }

    pub fn invalid_syntax(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidSyntax, detail)
    }

    pub fn invalid_path(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidPath, detail)
    }

    pub fn invalid_value(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidValue, detail)
    }

    pub fn invalid_vers(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidVers, detail)
    }

    pub fn mutability(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::Mutability, detail)
    }

    pub fn no_target(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::NoTarget, detail)
    }

    pub fn too_many(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::TooMany, detail)
    }

    pub fn sensitive(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::Sensitive, detail)
    }

    pub fn invalid_cursor(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidCursor, detail)
    }

    pub fn expired_cursor(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::ExpiredCursor, detail)
    }

    pub fn invalid_count(detail: impl Into<Cow<'static, str>>) -> Self {
        Self::bad_request(ScimType::InvalidCount, detail)
    }

    pub fn uniqueness(detail: impl Into<Cow<'static, str>>) -> Self {
        Error {
            status: 409,
            scim_type: Some(ScimType::Uniqueness),
            detail: Some(detail.into()),
        }
    }

    pub fn unauthorized() -> Self {
        Error::new(401)
    }

    pub fn forbidden(detail: impl Into<Cow<'static, str>>) -> Self {
        Error::new(403).with_detail(detail)
    }

    pub fn not_found() -> Self {
        Error::new(404)
    }

    pub fn conflict(detail: impl Into<Cow<'static, str>>) -> Self {
        Error::new(409).with_detail(detail)
    }

    pub fn precondition_failed() -> Self {
        Error::new(412)
    }

    pub fn max_operations_exceeded(max_operations: usize) -> Self {
        Error::new(413).with_detail(format!(
            "The number of operations in the bulk request exceeds the maxOperations ({max_operations})."
        ))
    }

    pub fn max_payload_size_exceeded(max_payload_size: usize) -> Self {
        Error::new(413).with_detail(format!(
            "The size of the bulk operation exceeds the maxPayloadSize ({max_payload_size})."
        ))
    }

    pub fn internal_error() -> Self {
        Error::new(500)
    }

    pub fn not_implemented() -> Self {
        Error::new(501)
    }

    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[MESSAGE_ERROR])?;
        if let Some(scim_type) = &self.scim_type {
            map.serialize_entry("scimType", scim_type.as_str())?;
        }
        if let Some(detail) = &self.detail {
            map.serialize_entry("detail", detail)?;
        }
        map.serialize_entry("status", &StatusCode(self.status))?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Error {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorVisitor;

        impl<'de> Visitor<'de> for ErrorVisitor {
            type Value = Error;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a SCIM error")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut error = Error::new(0);

                while let Some(key) = map.next_key::<Str<'_>>()? {
                    match key.0.as_ref() {
                        "status" => {
                            error.status = map.next_value::<StatusCode>()?.0;
                        }
                        "scimType" => {
                            error.scim_type = map
                                .next_value::<Option<Str<'_>>>()?
                                .and_then(|value| ScimType::parse(&value.0));
                        }
                        "detail" => {
                            error.detail = map
                                .next_value::<Option<Str<'_>>>()?
                                .map(|value| Cow::Owned(value.0.into_owned()));
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                Ok(error)
            }
        }

        deserializer.deserialize_map(ErrorVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(pub u16);

impl Serialize for StatusCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for StatusCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusVisitor;

        impl<'de> Visitor<'de> for StatusVisitor {
            type Value = StatusCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an HTTP status code")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.trim()
                    .parse::<u16>()
                    .map(StatusCode)
                    .map_err(|_| E::custom(format!("Invalid status code '{v}'")))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                u16::try_from(v)
                    .map(StatusCode)
                    .map_err(|_| E::custom(format!("Invalid status code '{v}'")))
            }
        }

        deserializer.deserialize_any(StatusVisitor)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.status)?;
        if let Some(scim_type) = &self.scim_type {
            write!(f, " ({})", scim_type.as_str())?;
        }
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_error() {
        let error = Error::uniqueness("A user with userName 'alice@corp.example' already exists");

        assert_eq!(
            serde_json::to_value(&error).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "scimType": "uniqueness",
                "detail": "A user with userName 'alice@corp.example' already exists",
                "status": "409"
            })
        );
    }

    #[test]
    fn status_is_serialized_as_a_string() {
        let json = serde_json::to_string(&Error::not_found()).unwrap();

        assert!(json.contains(r#""status":"404""#), "{json}");
        assert!(!json.contains("scimType"), "{json}");
        assert!(!json.contains("detail"), "{json}");
    }

    #[test]
    fn round_trip() {
        for error in [
            Error::not_found(),
            Error::invalid_filter("Unsupported operator 'co'"),
            Error::uniqueness("duplicate"),
            Error::max_payload_size_exceeded(1048576),
        ] {
            let json = serde_json::to_string(&error).unwrap();
            assert_eq!(serde_json::from_str::<Error>(&json).unwrap(), error);
        }
    }

    #[test]
    fn deserialize_numeric_status() {
        let error =
            serde_json::from_str::<Error>(r#"{"status": 404, "scimType": "invalidPath"}"#).unwrap();

        assert_eq!(error.status, 404);
        assert_eq!(error.scim_type, Some(ScimType::InvalidPath));
    }

    #[test]
    fn scim_type_names() {
        for scim_type in [
            ScimType::InvalidFilter,
            ScimType::TooMany,
            ScimType::Uniqueness,
            ScimType::Mutability,
            ScimType::InvalidSyntax,
            ScimType::InvalidPath,
            ScimType::NoTarget,
            ScimType::InvalidValue,
            ScimType::InvalidVers,
            ScimType::Sensitive,
            ScimType::InvalidCursor,
            ScimType::ExpiredCursor,
            ScimType::InvalidCount,
        ] {
            assert_eq!(ScimType::parse(scim_type.as_str()), Some(scim_type));
        }
    }
}
