/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    scim::{SCIM_DOMAIN, ScimClient, ScimTest, api_key, group_body, patch_body, query, user_body},
    utils::{account::Account, server::TestServer},
};
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            self, Action, CertificateManagement, DkimManagement, DnsManagement, Domain,
            PasswordCredential, Permissions, PermissionsList, Tenant, UserAccount,
        },
    },
    types::{EnumImpl, list::List, map::Map},
};
use scim_proto::{MESSAGE_BULK_REQUEST, SCHEMA_USER};
use serde_json::json;
use types::id::Id;

const TENANT_DOMAIN: &str = "acme.example.com";
const TENANT_PRINCIPAL: &str = "scim-svc@acme.example.com";
const TENANT_SECRET: &str = "these_pretzels_are_making_me_thirsty";

pub async fn test(test: &TestServer, scim: &ScimTest) {
    println!("Running SCIM tenant isolation tests...");

    let fixture = TenantFixture::new(test).await;

    a_tenant_client_only_sees_its_own_tenant(&fixture, scim).await;
    a_tenant_client_cannot_reach_another_tenant(&fixture, scim).await;
    a_tenant_client_cannot_provision_outside_its_domains(&fixture).await;
    a_tenant_client_provisions_inside_its_own_domain(&fixture).await;

    fixture.cleanup(test).await;
}

struct TenantFixture {
    client: ScimClient,
    tenant_id: Id,
    domain_id: Id,
    principal_id: Id,
    resident_id: Id,
}

impl TenantFixture {
    async fn new(test: &TestServer) -> Self {
        let admin = test.account("admin");
        let tenant_id = admin
            .registry_create_object(Tenant {
                name: "acme".to_string(),
                permissions: Permissions::Merge(PermissionsList {
                    disabled_permissions: Default::default(),
                    enabled_permissions: Map::new(vec![
                        Permission::ScimAccess,
                        Permission::UnlimitedRequests,
                    ]),
                }),
                ..Default::default()
            })
            .await;

        let domain_id = admin
            .registry_create_object(Domain {
                is_enabled: true,
                name: TENANT_DOMAIN.to_string(),
                certificate_management: CertificateManagement::Manual,
                dns_management: DnsManagement::Manual,
                dkim_management: DkimManagement::Manual,
                member_tenant_id: Some(tenant_id),
                allow_scim_provisioning: true,
                ..Default::default()
            })
            .await;

        let principal_id = create_account(
            admin,
            "scim-svc",
            domain_id,
            tenant_id,
            "Tenant SCIM Service Principal",
            vec![
                Permission::ScimAccess,
                Permission::SysAccountGet,
                Permission::SysAccountCreate,
                Permission::SysAccountUpdate,
                Permission::SysAccountDestroy,
                Permission::UnlimitedRequests,
            ],
        )
        .await;
        let resident_id = create_account(
            admin,
            "resident",
            domain_id,
            tenant_id,
            "Tenant Resident",
            vec![],
        )
        .await;

        admin
            .registry_update_object(
                ObjectType::Account,
                principal_id,
                json!({ Property::Quotas: { StorageQuota::MaxApiKeys.as_str(): 20 } }),
            )
            .await;
        admin.registry_create_object(Action::InvalidateCaches).await;

        let mut principal = Account::new(TENANT_PRINCIPAL, TENANT_SECRET, &[], "", principal_id);
        principal.http_listener_port = crate::scim::HTTP_PORT;
        let token = api_key(admin, &principal, json!({ "@type": "Inherit" })).await;

        TenantFixture {
            client: ScimClient::bearer(&token),
            tenant_id,
            domain_id,
            principal_id,
            resident_id,
        }
    }

    async fn cleanup(&self, test: &TestServer) {
        let admin = test.account("admin");
        for id in [self.resident_id, self.principal_id] {
            admin.registry_destroy(ObjectType::Account, [id]).await;
        }
        admin
            .registry_destroy(ObjectType::Domain, [self.domain_id])
            .await;
        admin
            .registry_destroy(ObjectType::Tenant, [self.tenant_id])
            .await;
        admin.registry_create_object(Action::InvalidateCaches).await;
    }
}

async fn a_tenant_client_only_sees_its_own_tenant(fixture: &TenantFixture, scim: &ScimTest) {
    let outsider = scim.create_user("tenant.outsider@scim.example.com").await;

    let listing = fixture.client.get("/Users?count=200").await;
    listing.assert_status(200);
    listing.assert_contains_id(&fixture.resident_id.to_string());
    listing.assert_contains_id(&fixture.principal_id.to_string());
    listing.assert_lacks_id(&outsider);
    assert_eq!(
        listing.total_results(),
        2,
        "A tenant client must see only its own accounts: {}",
        listing.body
    );

    for filter in [
        "userName eq \"tenant.outsider@scim.example.com\"",
        &format!("id eq \"{outsider}\""),
        "emails eq \"tenant.outsider@scim.example.com\"",
    ] {
        let response = fixture.client.get(&query("/Users", filter)).await;
        response.assert_status(200);
        assert_eq!(response.total_results(), 0, "{filter}: {}", response.body);
    }

    let searched = fixture
        .client
        .post(
            "/.search",
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
                "count": 200,
            }),
        )
        .await;
    searched.assert_status(200);
    searched.assert_lacks_id(&outsider);

    scim.destroy(&format!("/Users/{outsider}")).await;
}

async fn a_tenant_client_cannot_reach_another_tenant(fixture: &TenantFixture, scim: &ScimTest) {
    let outsider = scim.create_user("tenant.target@scim.example.com").await;
    let outsider_group = scim.create_group("Untenanted Team").await;
    let path = format!("/Users/{outsider}");

    fixture.client.get(&path).await.assert_error(404, None);
    fixture
        .client
        .patch(
            &path,
            patch_body(json!([{"op": "replace", "path": "displayName", "value": "Crossed"}])),
        )
        .await
        .assert_error(404, None);
    fixture
        .client
        .put(&path, user_body("tenant.target@scim.example.com"))
        .await
        .assert_error(404, None);
    fixture.client.delete(&path).await.assert_error(404, None);

    fixture
        .client
        .get(&format!("/Groups/{outsider_group}"))
        .await
        .assert_error(404, None);
    fixture
        .client
        .delete(&format!("/Groups/{outsider_group}"))
        .await
        .assert_error(404, None);

    let bulk = fixture
        .client
        .post(
            "/Bulk",
            json!({
                "schemas": [MESSAGE_BULK_REQUEST],
                "Operations": [
                    {"method": "DELETE", "path": path},
                    {"method": "PATCH", "path": path, "data": patch_body(
                        json!([{"op": "replace", "path": "active", "value": false}])
                    )},
                ],
            }),
        )
        .await;
    bulk.assert_status(200);
    for operation in bulk.json["Operations"].as_array().unwrap() {
        assert_eq!(operation["status"], json!("404"), "{operation}");
    }

    let group = fixture
        .client
        .post("/Groups", group_body("Tenant Team"))
        .await
        .assert_status(201)
        .id();
    fixture
        .client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": outsider}]}])),
        )
        .await
        .assert_error(400, Some("invalidValue"));
    fixture.client.delete(&format!("/Groups/{group}")).await;

    let survivor = scim.client.get(&path).await;
    survivor.assert_status(200);
    assert!(
        survivor.json.get("displayName").is_none(),
        "The cross tenant patch was applied: {}",
        survivor.body
    );

    scim.destroy(&format!("/Groups/{outsider_group}")).await;
    scim.destroy(&path).await;
}

async fn a_tenant_client_cannot_provision_outside_its_domains(fixture: &TenantFixture) {
    let response = fixture
        .client
        .post("/Users", user_body(&format!("intruder@{SCIM_DOMAIN}")))
        .await;
    response.assert_error(404, None);
    response.assert_detail_contains(SCIM_DOMAIN);

    let response = fixture
        .client
        .post(
            "/Users",
            json!({
                "schemas": [SCHEMA_USER],
                "userName": format!("aliased@{TENANT_DOMAIN}"),
                "emails": [{"value": format!("intruder@{SCIM_DOMAIN}")}],
            }),
        )
        .await;
    response.assert_error(404, None);
    response.assert_detail_contains(SCIM_DOMAIN);
}

async fn a_tenant_client_provisions_inside_its_own_domain(fixture: &TenantFixture) {
    let response = fixture
        .client
        .post("/Users", user_body(&format!("newcomer@{TENANT_DOMAIN}")))
        .await;
    response.assert_status(201);
    let id = response.id();

    fixture
        .client
        .get(&format!("/Users/{id}"))
        .await
        .assert_status(200);

    let group = fixture
        .client
        .post("/Groups", group_body("Acme Team"))
        .await
        .assert_status(201)
        .id();
    fixture
        .client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "add", "path": "members", "value": [{"value": id}]}])),
        )
        .await
        .assert_status(200);
    fixture
        .client
        .patch(
            &format!("/Groups/{group}"),
            patch_body(json!([{"op": "remove", "path": "members"}])),
        )
        .await
        .assert_status(200);

    fixture
        .client
        .delete(&format!("/Groups/{group}"))
        .await
        .assert_status(204);
    fixture
        .client
        .delete(&format!("/Users/{id}"))
        .await
        .assert_status(204);
}

async fn create_account(
    admin: &Account,
    name: &str,
    domain_id: Id,
    tenant_id: Id,
    description: &str,
    permissions: Vec<Permission>,
) -> Id {
    admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: name.to_string(),
            domain_id,
            member_tenant_id: Some(tenant_id),
            description: Some(description.to_string()),
            credentials: List::from_iter([structs::Credential::Password(PasswordCredential {
                secret: TENANT_SECRET.to_string(),
                ..Default::default()
            })]),
            permissions: Permissions::Merge(PermissionsList {
                disabled_permissions: Default::default(),
                enabled_permissions: Map::new(permissions),
            }),
            ..Default::default()
        }))
        .await
}
