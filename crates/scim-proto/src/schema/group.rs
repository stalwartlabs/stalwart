/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    SCHEMA_GROUP,
    json::scim_object,
    message::error::Error,
    schema::{
        Attribute, AttributeType, EXTERNAL_ID_ATTRIBUTE, ID_ATTRIBUTE, META_ATTRIBUTE, Meta,
        Mutability, Schema, Uniqueness,
    },
};

pub const TOLERATED_GROUP_ATTRIBUTES: &[&str] = &["description"];

scim_object!(pub Group<'x>, Some(SCHEMA_GROUP), TOLERATED_GROUP_ATTRIBUTES, &[], {
    "id" => str id: Option<Cow<'x, str>>,
    "externalId" => str external_id: Option<Cow<'x, str>>,
    "displayName" => str display_name: Option<Cow<'x, str>>,
    "members" => any members: Option<Vec<Member<'x>>>,
    "meta" => any meta: Option<Meta<'x>>,
});

scim_object!(pub Member<'x>, None::<&'static str>, {
    "value" => str value: Option<Cow<'x, str>>,
    "$ref" => str ref_: Option<Cow<'x, str>>,
    "display" => str display: Option<Cow<'x, str>>,
    "type" => str r#type: Option<Cow<'x, str>>,
});

pub const MEMBER_TYPE_USER: &str = "User";

impl<'x> Group<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        serde_json::from_slice(body).map_err(|err| Error::invalid_syntax(err.to_string()))
    }
}

impl Member<'_> {
    pub fn is_user(&self) -> bool {
        self.r#type
            .as_deref()
            .is_none_or(|value| value.eq_ignore_ascii_case(MEMBER_TYPE_USER))
    }
}

pub const GROUP_SCHEMA: Schema = Schema {
    id: SCHEMA_GROUP,
    name: "Group",
    description: "Group",
    attributes: &[
        ID_ATTRIBUTE,
        EXTERNAL_ID_ATTRIBUTE,
        Attribute {
            name: "displayName",
            description: "A human-readable name for the Group.",
            required: true,
            uniqueness: Uniqueness::Server,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "members",
            attr_type: AttributeType::Complex,
            multi_valued: true,
            description: "A list of members of the Group. Only User members are supported.",
            sub_attributes: &[
                Attribute {
                    name: "value",
                    description: "The identifier of a member of this Group.",
                    case_exact: true,
                    mutability: Mutability::Immutable,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "$ref",
                    attr_type: AttributeType::Reference,
                    reference_types: &["User"],
                    description: "The URI corresponding to a member of this Group.",
                    case_exact: true,
                    mutability: Mutability::Immutable,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "display",
                    description: "A human-readable name for the member.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "type",
                    description: "A label indicating the type of resource, for example User.",
                    canonical_values: &[MEMBER_TYPE_USER],
                    mutability: Mutability::Immutable,
                    ..Attribute::DEFAULT
                },
            ],
            ..Attribute::DEFAULT
        },
        META_ATTRIBUTE,
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_group() {
        let group = Group::parse(
            br#"{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
                "externalId": "grp-1",
                "displayName": "Tour Guides",
                "members": [
                    {
                        "value": "2819c223-7f76-453a-919d-413861904646",
                        "$ref": "https://example.com/v2/Users/2819c223",
                        "display": "Babs Jensen",
                        "type": "User"
                    }
                ],
                "meta": {"resourceType": "Group", "created": "2010-01-23T04:56:22Z"}
            }"#,
        )
        .unwrap();

        assert_eq!(group.display_name.as_deref(), Some("Tour Guides"));
        assert_eq!(group.external_id.as_deref(), Some("grp-1"));

        let members = group.members.as_ref().unwrap();
        assert_eq!(members.len(), 1);
        assert!(members[0].is_user());
        assert_eq!(
            members[0].value.as_deref(),
            Some("2819c223-7f76-453a-919d-413861904646")
        );
        assert_eq!(
            members[0].ref_.as_deref(),
            Some("https://example.com/v2/Users/2819c223")
        );
    }

    #[test]
    fn nested_groups_are_detectable() {
        let group = Group::parse(
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                 "displayName": "a", "members": [{"value": "g", "type": "Group"}]}"#,
        )
        .unwrap();

        assert!(!group.members.unwrap()[0].is_user());
    }

    #[test]
    fn unpublished_attributes_are_rejected() {
        let error = Group::parse(
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                 "displayName": "a", "owner": "b"}"#,
        )
        .unwrap_err();

        assert_eq!(error.status, 400);
        assert_eq!(
            error.scim_type,
            Some(crate::message::error::ScimType::InvalidSyntax)
        );
    }

    #[test]
    fn serialize_group() {
        let group = Group {
            id: Some("g1".into()),
            display_name: Some("Tour Guides".into()),
            members: Some(vec![Member {
                value: Some("u1".into()),
                ref_: Some("https://example.com/scim/v2/Users/u1".into()),
                r#type: Some("User".into()),
                ..Default::default()
            }]),
            meta: Some(Meta::new(crate::ResourceType::Group)),
            ..Default::default()
        };

        assert_eq!(
            serde_json::to_value(&group).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": "g1",
                "displayName": "Tour Guides",
                "members": [{
                    "value": "u1",
                    "$ref": "https://example.com/scim/v2/Users/u1",
                    "type": "User"
                }],
                "meta": {"resourceType": "Group"}
            })
        );
    }

    #[test]
    fn published_schema_matches_the_parser() {
        for attribute in GROUP_SCHEMA.attributes {
            let body = format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "{}": null}}"#,
                attribute.name
            );

            Group::parse(body.as_bytes()).unwrap_or_else(|err| panic!("{}: {err}", attribute.name));
        }
    }

    #[test]
    fn members_are_immutable_and_only_users() {
        let members = GROUP_SCHEMA.attribute("members").unwrap();

        assert_eq!(
            members.sub_attribute("value").unwrap().mutability,
            Mutability::Immutable
        );
        assert_eq!(
            members.sub_attribute("type").unwrap().canonical_values,
            &["User"]
        );
        assert!(GROUP_SCHEMA.attribute("displayName").unwrap().required);
    }
}
