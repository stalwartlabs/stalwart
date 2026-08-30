/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use serde::{Serialize, Serializer, ser::SerializeMap};

use crate::{
    ResourceType, SCHEMA_GROUP, SCHEMA_RESOURCE_TYPE, SCHEMA_SERVICE_PROVIDER_CONFIG, SCHEMA_USER,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceProviderConfig<'a> {
    pub documentation_uri: Option<&'a str>,
    pub patch: bool,
    pub bulk: BulkSupport,
    pub filter: FilterSupport,
    pub change_password: bool,
    pub sort: bool,
    pub etag: bool,
    pub pagination: Option<PaginationSupport>,
    pub authentication_schemes: &'a [AuthenticationScheme<'a>],
    pub interop_profile_conformant: bool,
    pub location: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkSupport {
    pub supported: bool,
    pub max_operations: usize,
    pub max_payload_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterSupport {
    pub supported: bool,
    pub max_results: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaginationSupport {
    pub cursor: bool,
    pub index: bool,
    pub default_pagination_method: Option<PaginationMethod>,
    pub default_page_size: Option<usize>,
    pub max_page_size: Option<usize>,
    pub cursor_timeout: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginationMethod {
    Cursor,
    Index,
}

impl PaginationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaginationMethod::Cursor => "cursor",
            PaginationMethod::Index => "index",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationScheme<'a> {
    pub scheme_type: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub spec_uri: Option<&'a str>,
    pub documentation_uri: Option<&'a str>,
    pub primary: Option<bool>,
}

pub const OAUTH_BEARER_TOKEN: AuthenticationScheme<'static> = AuthenticationScheme {
    scheme_type: "oauthbearertoken",
    name: "OAuth Bearer Token",
    description: "Authentication using a Stalwart API key presented as an HTTP bearer token",
    spec_uri: Some("https://www.rfc-editor.org/info/rfc6750"),
    documentation_uri: None,
    primary: Some(true),
};

impl ServiceProviderConfig<'static> {
    pub const DEFAULT: ServiceProviderConfig<'static> = ServiceProviderConfig {
        documentation_uri: Some("https://stalw.art/docs/"),
        patch: true,
        bulk: BulkSupport {
            supported: true,
            max_operations: 1000,
            max_payload_size: 1048576,
        },
        filter: FilterSupport {
            supported: true,
            max_results: 200,
        },
        change_password: false,
        sort: true,
        etag: true,
        pagination: Some(PaginationSupport {
            cursor: true,
            index: true,
            default_pagination_method: Some(PaginationMethod::Index),
            default_page_size: Some(100),
            max_page_size: Some(200),
            cursor_timeout: None,
        }),
        authentication_schemes: &[OAUTH_BEARER_TOKEN],
        interop_profile_conformant: false,
        location: None,
    };
}

impl<'a> ServiceProviderConfig<'a> {
    pub fn with_location(mut self, location: &'a str) -> Self {
        self.location = Some(location);
        self
    }
}

impl Serialize for ServiceProviderConfig<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[SCHEMA_SERVICE_PROVIDER_CONFIG])?;
        if let Some(documentation_uri) = self.documentation_uri {
            map.serialize_entry("documentationUri", documentation_uri)?;
        }
        map.serialize_entry("patch", &Supported(self.patch))?;
        map.serialize_entry("bulk", &self.bulk)?;
        map.serialize_entry("filter", &self.filter)?;
        map.serialize_entry("changePassword", &Supported(self.change_password))?;
        map.serialize_entry("sort", &Supported(self.sort))?;
        map.serialize_entry("etag", &Supported(self.etag))?;
        if let Some(pagination) = &self.pagination {
            map.serialize_entry("pagination", pagination)?;
        }
        map.serialize_entry("authenticationSchemes", &self.authentication_schemes)?;
        map.serialize_entry("interopProfileConformant", &self.interop_profile_conformant)?;
        if let Some(location) = self.location {
            map.serialize_entry(
                "meta",
                &Meta {
                    resource_type: "ServiceProviderConfig",
                    location,
                },
            )?;
        }
        map.end()
    }
}

struct Supported(bool);

impl Serialize for Supported {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("supported", &self.0)?;
        map.end()
    }
}

struct Meta<'a> {
    resource_type: &'a str,
    location: &'a str,
}

impl Serialize for Meta<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("resourceType", self.resource_type)?;
        map.serialize_entry("location", self.location)?;
        map.end()
    }
}

impl Serialize for BulkSupport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("supported", &self.supported)?;
        map.serialize_entry("maxOperations", &self.max_operations)?;
        map.serialize_entry("maxPayloadSize", &self.max_payload_size)?;
        map.end()
    }
}

impl Serialize for FilterSupport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("supported", &self.supported)?;
        map.serialize_entry("maxResults", &self.max_results)?;
        map.end()
    }
}

impl Serialize for PaginationSupport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("cursor", &self.cursor)?;
        map.serialize_entry("index", &self.index)?;
        if let Some(default_pagination_method) = self.default_pagination_method {
            map.serialize_entry(
                "defaultPaginationMethod",
                default_pagination_method.as_str(),
            )?;
        }
        if let Some(default_page_size) = self.default_page_size {
            map.serialize_entry("defaultPageSize", &default_page_size)?;
        }
        if let Some(max_page_size) = self.max_page_size {
            map.serialize_entry("maxPageSize", &max_page_size)?;
        }
        if let Some(cursor_timeout) = self.cursor_timeout {
            map.serialize_entry("cursorTimeout", &cursor_timeout)?;
        }
        map.end()
    }
}

impl Serialize for AuthenticationScheme<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", self.scheme_type)?;
        map.serialize_entry("name", self.name)?;
        map.serialize_entry("description", self.description)?;
        if let Some(spec_uri) = self.spec_uri {
            map.serialize_entry("specUri", spec_uri)?;
        }
        if let Some(documentation_uri) = self.documentation_uri {
            map.serialize_entry("documentationUri", documentation_uri)?;
        }
        if let Some(primary) = self.primary {
            map.serialize_entry("primary", &primary)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceTypeDef<'a> {
    pub id: &'static str,
    pub name: &'static str,
    pub endpoint: &'static str,
    pub description: &'static str,
    pub schema: &'static str,
    pub schema_extensions: &'static [SchemaExtension],
    pub location: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaExtension {
    pub schema: &'static str,
    pub required: bool,
}

pub const USER_RESOURCE_TYPE: ResourceTypeDef<'static> = ResourceTypeDef {
    id: "User",
    name: "User",
    endpoint: "/Users",
    description: "User Account",
    schema: SCHEMA_USER,
    schema_extensions: &[],
    location: None,
};

pub const GROUP_RESOURCE_TYPE: ResourceTypeDef<'static> = ResourceTypeDef {
    id: "Group",
    name: "Group",
    endpoint: "/Groups",
    description: "Group",
    schema: SCHEMA_GROUP,
    schema_extensions: &[],
    location: None,
};

impl<'a> ResourceTypeDef<'a> {
    pub fn new(resource_type: ResourceType) -> Self {
        match resource_type {
            ResourceType::User => USER_RESOURCE_TYPE,
            ResourceType::Group => GROUP_RESOURCE_TYPE,
        }
    }

    pub fn with_location(mut self, location: &'a str) -> Self {
        self.location = Some(location);
        self
    }
}

impl Serialize for ResourceTypeDef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schemas", &[SCHEMA_RESOURCE_TYPE])?;
        map.serialize_entry("id", self.id)?;
        map.serialize_entry("name", self.name)?;
        map.serialize_entry("endpoint", self.endpoint)?;
        map.serialize_entry("description", self.description)?;
        map.serialize_entry("schema", self.schema)?;
        if !self.schema_extensions.is_empty() {
            map.serialize_entry("schemaExtensions", &self.schema_extensions)?;
        }
        if let Some(location) = self.location {
            map.serialize_entry(
                "meta",
                &Meta {
                    resource_type: "ResourceType",
                    location,
                },
            )?;
        }
        map.end()
    }
}

impl Serialize for SchemaExtension {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("schema", self.schema)?;
        map.serialize_entry("required", &self.required)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_service_provider_config() {
        assert_eq!(
            serde_json::to_value(ServiceProviderConfig::DEFAULT).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
                "documentationUri": "https://stalw.art/docs/",
                "patch": {"supported": true},
                "bulk": {"supported": true, "maxOperations": 1000, "maxPayloadSize": 1048576},
                "filter": {"supported": true, "maxResults": 200},
                "changePassword": {"supported": false},
                "sort": {"supported": true},
                "etag": {"supported": true},
                "pagination": {
                    "cursor": true,
                    "index": true,
                    "defaultPaginationMethod": "index",
                    "defaultPageSize": 100,
                    "maxPageSize": 200
                },
                "authenticationSchemes": [{
                    "type": "oauthbearertoken",
                    "name": "OAuth Bearer Token",
                    "description":
                        "Authentication using a Stalwart API key presented as an HTTP bearer token",
                    "specUri": "https://www.rfc-editor.org/info/rfc6750",
                    "primary": true
                }],
                "interopProfileConformant": false
            })
        );
    }

    #[test]
    fn bulk_block_is_always_published() {
        let config = ServiceProviderConfig {
            bulk: BulkSupport {
                supported: false,
                max_operations: 0,
                max_payload_size: 0,
            },
            ..ServiceProviderConfig::DEFAULT
        };
        let value = serde_json::to_value(config).unwrap();

        assert_eq!(value["bulk"]["supported"], false);
        assert_eq!(value["bulk"]["maxOperations"], 0);
        assert_eq!(value["bulk"]["maxPayloadSize"], 0);
    }

    #[test]
    fn service_provider_config_meta() {
        let value = serde_json::to_value(
            ServiceProviderConfig::DEFAULT
                .with_location("https://example.com/scim/v2/ServiceProviderConfig"),
        )
        .unwrap();

        assert_eq!(value["meta"]["resourceType"], "ServiceProviderConfig");
        assert_eq!(
            value["meta"]["location"],
            "https://example.com/scim/v2/ServiceProviderConfig"
        );
    }

    #[test]
    fn resource_type_id_equals_name() {
        for resource_type in [ResourceType::User, ResourceType::Group] {
            let definition = ResourceTypeDef::new(resource_type);

            assert_eq!(definition.id, definition.name);
            assert_eq!(definition.name, resource_type.as_str());
            assert_eq!(definition.endpoint, resource_type.endpoint());
            assert_eq!(definition.schema, resource_type.schema_urn());
            assert!(definition.schema_extensions.is_empty());
        }
    }

    #[test]
    fn serialize_resource_type() {
        assert_eq!(
            serde_json::to_value(
                USER_RESOURCE_TYPE.with_location("https://example.com/scim/v2/ResourceTypes/User")
            )
            .unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "description": "User Account",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
                "meta": {
                    "resourceType": "ResourceType",
                    "location": "https://example.com/scim/v2/ResourceTypes/User"
                }
            })
        );
    }
}
