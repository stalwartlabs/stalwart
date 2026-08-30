/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    SCHEMA_USER,
    json::scim_object,
    message::error::Error,
    schema::{
        Attribute, AttributeType, EXTERNAL_ID_ATTRIBUTE, ID_ATTRIBUTE, META_ATTRIBUTE, Meta,
        Mutability, Schema, Uniqueness,
    },
};

pub const SCHEMA_ENTERPRISE_USER: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

pub const TOLERATED_USER_ATTRIBUTES: &[&str] = &[
    "password",
    "nickName",
    "profileUrl",
    "title",
    "userType",
    "phoneNumbers",
    "ims",
    "photos",
    "addresses",
    "entitlements",
    "roles",
    "x509Certificates",
    SCHEMA_ENTERPRISE_USER,
];

pub const TOLERATED_USER_SCHEMAS: &[&str] = &[SCHEMA_ENTERPRISE_USER];

pub const TOLERATED_NAME_ATTRIBUTES: &[&str] =
    &["middleName", "honorificPrefix", "honorificSuffix"];

scim_object!(pub User<'x>, Some(SCHEMA_USER), TOLERATED_USER_ATTRIBUTES, TOLERATED_USER_SCHEMAS, {
    "id" => str id: Option<Cow<'x, str>>,
    "externalId" => str external_id: Option<Cow<'x, str>>,
    "userName" => str user_name: Option<Cow<'x, str>>,
    "name" => any name: Option<Name<'x>>,
    "displayName" => str display_name: Option<Cow<'x, str>>,
    "active" => any active: Option<bool>,
    "emails" => any emails: Option<Vec<Email<'x>>>,
    "locale" => str locale: Option<Cow<'x, str>>,
    "preferredLanguage" => str preferred_language: Option<Cow<'x, str>>,
    "timezone" => str timezone: Option<Cow<'x, str>>,
    "groups" => any groups: Option<Vec<GroupRef<'x>>>,
    "meta" => any meta: Option<Meta<'x>>,
});

scim_object!(pub Name<'x>, None::<&'static str>, TOLERATED_NAME_ATTRIBUTES, &[], {
    "formatted" => str formatted: Option<Cow<'x, str>>,
    "givenName" => input given_name: Option<Cow<'x, str>>,
    "familyName" => input family_name: Option<Cow<'x, str>>,
});

impl Name<'_> {
    pub fn composed(&self) -> Option<String> {
        if let Some(formatted) = self.formatted.as_deref().filter(|value| !value.is_empty()) {
            return Some(formatted.to_string());
        }

        let mut composed = String::new();
        for part in [self.given_name.as_deref(), self.family_name.as_deref()]
            .into_iter()
            .flatten()
            .filter(|part| !part.is_empty())
        {
            if !composed.is_empty() {
                composed.push(' ');
            }
            composed.push_str(part);
        }

        Some(composed).filter(|composed| !composed.is_empty())
    }
}

scim_object!(pub Email<'x>, None::<&'static str>, {
    "value" => str value: Option<Cow<'x, str>>,
    "display" => str display: Option<Cow<'x, str>>,
    "type" => str r#type: Option<Cow<'x, str>>,
    "primary" => any primary: Option<bool>,
});

scim_object!(pub GroupRef<'x>, None::<&'static str>, {
    "value" => str value: Option<Cow<'x, str>>,
    "$ref" => str ref_: Option<Cow<'x, str>>,
    "display" => str display: Option<Cow<'x, str>>,
    "type" => str r#type: Option<Cow<'x, str>>,
});

impl<'x> User<'x> {
    pub fn parse(body: &'x [u8]) -> Result<Self, Error> {
        serde_json::from_slice(body).map_err(|err| Error::invalid_syntax(err.to_string()))
    }

    pub fn primary_email(&self) -> Option<&Email<'x>> {
        self.emails.as_ref().and_then(|emails| {
            emails
                .iter()
                .find(|email| email.primary.unwrap_or_default())
                .or_else(|| emails.first())
        })
    }
}

pub const USER_SCHEMA: Schema = Schema {
    id: SCHEMA_USER,
    name: "User",
    description: "User Account",
    attributes: &[
        ID_ATTRIBUTE,
        EXTERNAL_ID_ATTRIBUTE,
        Attribute {
            name: "userName",
            description: "Unique identifier for the User, used by the user to authenticate to \
                           the service provider. Each User MUST include a non-empty userName \
                           value.",
            required: true,
            uniqueness: Uniqueness::Server,
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "name",
            attr_type: AttributeType::Complex,
            description: "The components of the user's name.",
            sub_attributes: &[Attribute {
                name: "formatted",
                description: "The full name, formatted for display.",
                ..Attribute::DEFAULT
            }],
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "displayName",
            description: "The name of the User, suitable for display to end-users.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "active",
            attr_type: AttributeType::Boolean,
            description: "A Boolean value indicating the User's administrative status. A value \
                           of false suspends the account and prevents authentication.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "emails",
            attr_type: AttributeType::Complex,
            multi_valued: true,
            description: "Email addresses for the User. The primary email address is the \
                           address the User authenticates with.",
            sub_attributes: &[
                Attribute {
                    name: "value",
                    description: "The email address.",
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "display",
                    description: "A human-readable name, primarily used for display purposes.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "type",
                    description: "A label indicating the attribute's function. Every address is \
                                   of type 'work'.",
                    canonical_values: &["work"],
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "primary",
                    attr_type: AttributeType::Boolean,
                    description: "A Boolean value indicating the preferred email address. The \
                                   primary address is the User's userName and cannot be removed.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
            ],
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "locale",
            description: "Indicates the User's default location, used to select a localized \
                           representation, for example 'en-US'.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "preferredLanguage",
            description: "Indicates the User's preferred written or spoken language. Backed by \
                           the same value as locale.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "timezone",
            description: "The User's time zone, in IANA Time Zone database format, for example \
                           'America/Los_Angeles'.",
            ..Attribute::DEFAULT
        },
        Attribute {
            name: "groups",
            attr_type: AttributeType::Complex,
            multi_valued: true,
            description: "A list of groups to which the user belongs. Membership is managed \
                           through the Group resource.",
            mutability: Mutability::ReadOnly,
            sub_attributes: &[
                Attribute {
                    name: "value",
                    description: "The identifier of the User's group.",
                    case_exact: true,
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "$ref",
                    attr_type: AttributeType::Reference,
                    reference_types: &["Group"],
                    description: "The URI of the corresponding Group resource.",
                    case_exact: true,
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "display",
                    description: "A human-readable name for the group.",
                    mutability: Mutability::ReadOnly,
                    ..Attribute::DEFAULT
                },
                Attribute {
                    name: "type",
                    description: "A label indicating the attribute's function.",
                    canonical_values: &["direct"],
                    mutability: Mutability::ReadOnly,
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
    use crate::schema::Returned;

    #[test]
    fn parse_minimal_user() {
        let user = User::parse(
            br#"{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "2819c223-7f76-453a-919d-413861904646",
                "userName": "bjensen@example.com",
                "meta": {
                    "resourceType": "User",
                    "created": "2010-01-23T04:56:22Z",
                    "location": "https://example.com/v2/Users/2819c223",
                    "version": "W/\"3694e05e9dff590\""
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            user.id.as_deref(),
            Some("2819c223-7f76-453a-919d-413861904646")
        );
        assert_eq!(user.user_name.as_deref(), Some("bjensen@example.com"));
        assert_eq!(
            user.meta.as_ref().unwrap().version.as_deref(),
            Some("W/\"3694e05e9dff590\"")
        );
    }

    #[test]
    fn parse_full_user() {
        let user = User::parse(
            br#"{
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "externalId": "701984",
                "userName": "bjensen@example.com",
                "name": {"formatted": "Ms. Barbara J Jensen, III"},
                "displayName": "Babs Jensen",
                "active": true,
                "emails": [
                    {"value": "bjensen@example.com", "type": "work", "primary": true},
                    {"value": "babs@jensen.org", "type": "home"}
                ],
                "locale": "en-US",
                "preferredLanguage": "en-US",
                "timezone": "America/Los_Angeles"
            }"#,
        )
        .unwrap();

        assert_eq!(user.external_id.as_deref(), Some("701984"));
        assert_eq!(
            user.name.as_ref().unwrap().formatted.as_deref(),
            Some("Ms. Barbara J Jensen, III")
        );
        assert_eq!(user.active, Some(true));
        assert_eq!(user.emails.as_ref().unwrap().len(), 2);
        assert_eq!(
            user.primary_email().unwrap().value.as_deref(),
            Some("bjensen@example.com")
        );
        assert_eq!(user.locale.as_deref(), Some("en-US"));
        assert_eq!(user.timezone.as_deref(), Some("America/Los_Angeles"));
    }

    #[test]
    fn attribute_names_are_case_insensitive() {
        let user = User::parse(
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                 "USERNAME": "bjensen", "Active": false}"#,
        )
        .unwrap();

        assert_eq!(user.user_name.as_deref(), Some("bjensen"));
        assert_eq!(user.active, Some(false));
    }

    #[test]
    fn values_are_borrowed_from_the_request() {
        let body = br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                     "userName": "bjensen@example.com"}"#;
        let user = User::parse(body).unwrap();

        assert!(matches!(user.user_name, Some(Cow::Borrowed(_))));
    }

    #[test]
    fn unimplemented_core_attributes_are_ignored() {
        for body in [
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "title": "Vice President"}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "password": "secret"}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "nickName": "Babs"}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "phoneNumbers": [{"value": "555", "type": "work"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "addresses": [{"streetAddress": "1 Main St"}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "roles": [], "entitlements": [], "x509Certificates": []}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"], "userName": "a", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Sales"}}"#.as_slice(),
        ] {
            let user = User::parse(body)
                .unwrap_or_else(|err| panic!("{err}: {}", String::from_utf8_lossy(body)));

            assert_eq!(user.user_name.as_deref(), Some("a"));
        }
    }

    #[test]
    fn structured_names_compose_into_a_display_name() {
        let user = User::parse(
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a",
                 "name": {"givenName": "Barbara", "familyName": "Jensen",
                          "middleName": "J", "honorificPrefix": "Ms."}}"#,
        )
        .unwrap();

        assert_eq!(
            user.name.as_ref().unwrap().composed().as_deref(),
            Some("Barbara Jensen")
        );

        let user = User::parse(
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a",
                 "name": {"formatted": "Ms. Barbara J Jensen, III", "givenName": "Barbara"}}"#,
        )
        .unwrap();

        assert_eq!(
            user.name.as_ref().unwrap().composed().as_deref(),
            Some("Ms. Barbara J Jensen, III")
        );

        assert_eq!(Name::default().composed(), None);
    }

    #[test]
    fn unknown_attributes_and_schemas_are_still_rejected() {
        for body in [
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "dispalyName": "typo"}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "emails": [{"value": "a@b.c", "unknown": 1}]}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "a", "name": {"nosuch": "x"}}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Device"], "userName": "a"}"#.as_slice(),
            br#"{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:example:custom:2.0:User"], "userName": "a"}"#.as_slice(),
        ] {
            let error = User::parse(body)
                .unwrap_err();

            assert_eq!(error.status, 400, "{}", String::from_utf8_lossy(body));
            assert_eq!(
                error.scim_type,
                Some(crate::message::error::ScimType::InvalidSyntax),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn serialize_user() {
        let user = User {
            id: Some("abc".into()),
            user_name: Some("bjensen@example.com".into()),
            active: Some(true),
            emails: Some(vec![Email {
                value: Some("bjensen@example.com".into()),
                r#type: Some("work".into()),
                primary: Some(true),
                ..Default::default()
            }]),
            groups: Some(vec![GroupRef {
                value: Some("g1".into()),
                ref_: Some("https://example.com/scim/v2/Groups/g1".into()),
                display: Some("Sales".into()),
                r#type: Some("direct".into()),
            }]),
            meta: Some(Meta::new(crate::ResourceType::User)),
            ..Default::default()
        };

        assert_eq!(
            serde_json::to_value(&user).unwrap(),
            serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "id": "abc",
                "userName": "bjensen@example.com",
                "active": true,
                "emails": [{"value": "bjensen@example.com", "type": "work", "primary": true}],
                "groups": [{
                    "value": "g1",
                    "$ref": "https://example.com/scim/v2/Groups/g1",
                    "display": "Sales",
                    "type": "direct"
                }],
                "meta": {"resourceType": "User"}
            })
        );
    }

    #[test]
    fn round_trip() {
        let body = br#"{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "externalId": "AbC-123",
            "userName": "bjensen@example.com",
            "name": {"formatted": "Barbara Jensen"},
            "displayName": "Barbara Jensen",
            "active": false,
            "locale": "en-US"
        }"#;
        let user = User::parse(body).unwrap();

        assert_eq!(
            serde_json::to_value(&user).unwrap(),
            serde_json::from_slice::<serde_json::Value>(body).unwrap()
        );
    }

    #[test]
    fn published_schema_matches_the_parser() {
        for attribute in USER_SCHEMA.attributes {
            let body = format!(
                r#"{{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "{}": null}}"#,
                attribute.name
            );

            User::parse(body.as_bytes()).unwrap_or_else(|err| panic!("{}: {err}", attribute.name));
        }
    }

    #[test]
    fn name_publishes_only_formatted() {
        let name = USER_SCHEMA.attribute("name").unwrap();

        assert_eq!(name.sub_attributes.len(), 1);
        assert_eq!(name.sub_attributes[0].name, "formatted");
    }

    #[test]
    fn schema_characteristics() {
        let user_name = USER_SCHEMA.attribute("userName").unwrap();
        assert!(!user_name.case_exact);
        assert!(user_name.required);
        assert_eq!(user_name.uniqueness, Uniqueness::Server);

        let id = USER_SCHEMA.attribute("id").unwrap();
        assert!(id.case_exact);
        assert_eq!(id.mutability, Mutability::ReadOnly);
        assert_eq!(id.returned, Returned::Always);

        let external_id = USER_SCHEMA.attribute("externalId").unwrap();
        assert!(external_id.case_exact);
        assert_eq!(external_id.mutability, Mutability::ReadWrite);

        let groups = USER_SCHEMA.attribute("groups").unwrap();
        assert_eq!(groups.mutability, Mutability::ReadOnly);

        let emails = USER_SCHEMA.attribute("emails").unwrap();
        assert_eq!(
            emails.sub_attribute("type").unwrap().canonical_values,
            &["work"]
        );
        for sub_attribute in ["type", "display", "primary"] {
            assert_eq!(
                emails.sub_attribute(sub_attribute).unwrap().mutability,
                Mutability::ReadOnly,
                "{sub_attribute}"
            );
        }
    }

    #[test]
    fn password_is_not_published() {
        assert!(USER_SCHEMA.attribute("password").is_none());
        assert!(USER_SCHEMA.attribute("givenName").is_none());
        assert!(USER_SCHEMA.attribute("phoneNumbers").is_none());
    }
}
