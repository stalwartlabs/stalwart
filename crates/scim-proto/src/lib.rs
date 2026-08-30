/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub mod attributes;
pub mod etag;
pub mod filter;
pub(crate) mod json;
pub mod message;
pub mod path;
pub mod schema;

use schema::{Schema, group::GROUP_SCHEMA, user::USER_SCHEMA};

pub const CONTENT_TYPE: &str = "application/scim+json";
pub const BASE_PATH: &str = "/scim/v2";
pub const PROTOCOL_VERSION: &str = "v2";

pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_SERVICE_PROVIDER_CONFIG: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const SCHEMA_RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

pub const MESSAGE_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const MESSAGE_ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub const MESSAGE_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const MESSAGE_SEARCH_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
pub const MESSAGE_BULK_REQUEST: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
pub const MESSAGE_BULK_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    User,
    Group,
}

impl ResourceType {
    pub fn parse(value: &str) -> Option<Self> {
        hashify::tiny_map_ignore_case!(value.as_bytes(),
            "User" => ResourceType::User,
            "Users" => ResourceType::User,
            "Group" => ResourceType::Group,
            "Groups" => ResourceType::Group,
        )
    }

    pub fn from_endpoint(endpoint: &str) -> Option<Self> {
        match endpoint.strip_prefix('/').unwrap_or(endpoint) {
            "Users" => Some(ResourceType::User),
            "Groups" => Some(ResourceType::Group),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::User => "User",
            ResourceType::Group => "Group",
        }
    }

    pub fn endpoint(&self) -> &'static str {
        match self {
            ResourceType::User => "/Users",
            ResourceType::Group => "/Groups",
        }
    }

    pub fn schema_urn(&self) -> &'static str {
        match self {
            ResourceType::User => SCHEMA_USER,
            ResourceType::Group => SCHEMA_GROUP,
        }
    }

    pub fn schema(&self) -> &'static Schema {
        match self {
            ResourceType::User => &USER_SCHEMA,
            ResourceType::Group => &GROUP_SCHEMA,
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_type_parse() {
        for (input, expected) in [
            ("User", Some(ResourceType::User)),
            ("users", Some(ResourceType::User)),
            ("GROUPS", Some(ResourceType::Group)),
            ("Group", Some(ResourceType::Group)),
            ("Device", None),
            ("", None),
        ] {
            assert_eq!(ResourceType::parse(input), expected, "{input}");
        }
    }

    #[test]
    fn resource_type_from_endpoint() {
        assert_eq!(
            ResourceType::from_endpoint("Users"),
            Some(ResourceType::User)
        );
        assert_eq!(
            ResourceType::from_endpoint("/Groups"),
            Some(ResourceType::Group)
        );
        assert_eq!(ResourceType::from_endpoint("users"), None);
        assert_eq!(ResourceType::from_endpoint("User"), None);
        assert_eq!(ResourceType::from_endpoint(""), None);
    }

    #[test]
    fn resource_type_endpoints() {
        assert_eq!(ResourceType::User.endpoint(), "/Users");
        assert_eq!(ResourceType::Group.endpoint(), "/Groups");
        assert_eq!(ResourceType::User.schema_urn(), SCHEMA_USER);
        assert_eq!(ResourceType::Group.schema().id, SCHEMA_GROUP);
    }
}
