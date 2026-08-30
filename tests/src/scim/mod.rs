/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::utils::{account::Account, server::TestServerBuilder};
use ahash::AHashMap;
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, Method, StatusCode, header};
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
        structs::Action,
    },
    types::EnumImpl,
};
use scim_proto::{CONTENT_TYPE, MESSAGE_ERROR, SCHEMA_GROUP, SCHEMA_USER};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub mod auth;
pub mod bulk;
pub mod conformance;
pub mod discovery;
pub mod groups;
pub mod limits;
pub mod oidc;
pub mod query;
pub mod tenant;
pub mod users;

pub const SCIM_DOMAIN: &str = "scim.example.com";
pub const ALIAS_DOMAIN: &str = "alias.example.com";
pub const PLAIN_DOMAIN: &str = "plain.example.com";
pub const SERVICE_PRINCIPAL: &str = "scim-svc@scim.example.com";
pub const HTTP_PORT: u16 = 8899;

#[tokio::test(flavor = "multi_thread")]
pub async fn scim_tests() {
    let mut test = TestServerBuilder::new("scim_tests")
        .await
        .with_default_listeners()
        .await
        .build()
        .await;

    let admin = test.create_admin_account("admin@example.com").await;
    let scim = ScimTest::new(&admin).await;
    test.insert_account(admin);

    let start_time = Instant::now();
    discovery::test(&scim).await;
    auth::test(&test, &scim).await;
    users::test(&test, &scim).await;
    groups::test(&scim).await;
    query::test(&scim).await;
    bulk::test(&scim).await;
    tenant::test(&test, &scim).await;
    oidc::test(&test, &scim).await;
    if conformance::is_enabled() {
        conformance::test(&scim).await;
    }
    limits::test(&test, &scim).await;

    let elapsed = start_time.elapsed();
    println!(
        "Elapsed: {}.{:03}s",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );

    if test.is_reset() {
        test.temp_dir.delete();
    }
}

pub struct ScimTest {
    pub client: ScimClient,
    pub no_scim: ScimClient,
    pub no_get: ScimClient,
    pub no_create: ScimClient,
    pub no_update: ScimClient,
    pub no_destroy: ScimClient,
    pub anonymous: ScimClient,
    pub basic: ScimClient,
    pub service_principal_id: String,
    pub base_url: String,
    pub token: String,
}

impl ScimTest {
    pub async fn new(admin: &Account) -> Self {
        let service_principal = admin
            .create_user_account(
                SERVICE_PRINCIPAL,
                "these_pretzels_are_making_me_thirsty",
                "SCIM Service Principal",
                &[],
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

        for (domain, allow_scim) in [
            (SCIM_DOMAIN, true),
            (ALIAS_DOMAIN, true),
            (PLAIN_DOMAIN, false),
        ] {
            let domain_id = admin.find_or_create_domain(domain).await;
            admin
                .registry_update_object(
                    ObjectType::Domain,
                    domain_id,
                    json!({ Property::AllowScimProvisioning: allow_scim }),
                )
                .await;
        }
        admin
            .registry_update_object(
                ObjectType::Account,
                service_principal.id(),
                json!({ Property::Quotas: { StorageQuota::MaxApiKeys.as_str(): 20 } }),
            )
            .await;
        admin.registry_create_object(Action::InvalidateCaches).await;

        let full = api_key(admin, &service_principal, json!({ "@type": "Inherit" })).await;
        let no_scim = api_key(
            admin,
            &service_principal,
            disable(&[Permission::ScimAccess]),
        )
        .await;
        let no_get = api_key(
            admin,
            &service_principal,
            disable(&[Permission::SysAccountGet]),
        )
        .await;
        let no_create = api_key(
            admin,
            &service_principal,
            disable(&[Permission::SysAccountCreate]),
        )
        .await;
        let no_update = api_key(
            admin,
            &service_principal,
            disable(&[Permission::SysAccountUpdate]),
        )
        .await;
        let no_destroy = api_key(
            admin,
            &service_principal,
            disable(&[Permission::SysAccountDestroy]),
        )
        .await;

        ScimTest {
            client: ScimClient::bearer(&full),
            no_scim: ScimClient::bearer(&no_scim),
            no_get: ScimClient::bearer(&no_get),
            no_create: ScimClient::bearer(&no_create),
            no_update: ScimClient::bearer(&no_update),
            no_destroy: ScimClient::bearer(&no_destroy),
            anonymous: ScimClient::anonymous(),
            basic: ScimClient::basic(SERVICE_PRINCIPAL, "these_pretzels_are_making_me_thirsty"),
            service_principal_id: service_principal.id().to_string(),
            base_url: format!("https://127.0.0.1:{HTTP_PORT}/scim/v2"),
            token: full,
        }
    }

    pub async fn create_user(&self, user_name: &str) -> String {
        self.client
            .post("/Users", user_body(user_name))
            .await
            .assert_status(201)
            .id()
    }

    pub async fn create_group(&self, display_name: &str) -> String {
        self.client
            .post("/Groups", group_body(display_name))
            .await
            .assert_status(201)
            .id()
    }

    pub async fn destroy(&self, path: &str) {
        self.client.delete(path).await.assert_status(204);
    }

    pub fn location(&self, endpoint: &str, id: &str) -> String {
        format!("{}{endpoint}/{id}", self.base_url)
    }
}

pub async fn api_key(admin: &Account, account: &Account, permissions: Value) -> String {
    admin
        .jmap_create_account(
            account,
            "x:ApiKey",
            [json!({ "description": "SCIM integration", "permissions": permissions })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)["secret"]
        .as_str()
        .expect("The API key response did not carry a secret")
        .to_string()
}

pub fn disable(permissions: &[Permission]) -> Value {
    let mut list = serde_json::Map::new();
    for permission in permissions {
        list.insert(permission.as_str().to_string(), json!(true));
    }
    json!({ "@type": "Disable", "permissions": Value::Object(list) })
}

pub fn user_body(user_name: &str) -> Value {
    json!({ "schemas": [SCHEMA_USER], "userName": user_name })
}

pub fn group_body(display_name: &str) -> Value {
    json!({ "schemas": [SCHEMA_GROUP], "displayName": display_name })
}

pub async fn jmap_session_status(authorization: &str) -> u16 {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:{HTTP_PORT}/jmap/session"))
        .header(header::AUTHORIZATION, authorization)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

pub fn query(endpoint: &str, filter: &str) -> String {
    format!(
        "{endpoint}?filter={}",
        form_urlencoded::byte_serialize(filter.as_bytes()).collect::<String>()
    )
}

pub fn patch_body(operations: Value) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    })
}

pub struct ScimClient {
    authorization: Option<String>,
}

#[derive(Debug)]
pub struct ScimResponse {
    pub status: StatusCode,
    pub headers: AHashMap<String, String>,
    pub body: String,
    pub json: Value,
}

impl ScimClient {
    pub fn bearer(token: &str) -> Self {
        ScimClient {
            authorization: Some(format!("Bearer {token}")),
        }
    }

    pub fn basic(name: &str, secret: &str) -> Self {
        ScimClient {
            authorization: Some(format!(
                "Basic {}",
                STANDARD.encode(format!("{name}:{secret}").as_bytes())
            )),
        }
    }

    pub fn anonymous() -> Self {
        ScimClient {
            authorization: None,
        }
    }

    pub async fn get(&self, path: &str) -> ScimResponse {
        self.request("GET", path, None).await
    }

    pub async fn post(&self, path: &str, body: Value) -> ScimResponse {
        self.request("POST", path, Some(body.to_string())).await
    }

    pub async fn put(&self, path: &str, body: Value) -> ScimResponse {
        self.request("PUT", path, Some(body.to_string())).await
    }

    pub async fn patch(&self, path: &str, body: Value) -> ScimResponse {
        self.request("PATCH", path, Some(body.to_string())).await
    }

    pub async fn delete(&self, path: &str) -> ScimResponse {
        self.request("DELETE", path, None).await
    }

    pub async fn request(&self, method: &str, path: &str, body: Option<String>) -> ScimResponse {
        self.request_with_headers(method, path, [], body).await
    }

    pub async fn request_with_headers(
        &self,
        method: &str,
        path: &str,
        headers: impl IntoIterator<Item = (&'static str, String)>,
        body: Option<String>,
    ) -> ScimResponse {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(
                Method::from_bytes(method.as_bytes()).unwrap(),
                format!("https://127.0.0.1:{HTTP_PORT}/scim/v2{path}"),
            );

        let mut request_headers = HeaderMap::new();
        if let Some(authorization) = &self.authorization {
            request_headers.insert(header::AUTHORIZATION, authorization.parse().unwrap());
        }
        for (key, value) in headers {
            request_headers.insert(key, value.parse().unwrap());
        }
        if let Some(body) = body {
            request_headers.insert(header::CONTENT_TYPE, CONTENT_TYPE.parse().unwrap());
            request = request.body(body);
        }

        let response = request.headers(request_headers).send().await.unwrap();
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(key, value)| {
                (
                    key.to_string().to_lowercase(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = String::from_utf8(response.bytes().await.unwrap().to_vec()).unwrap();
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);

        ScimResponse {
            status,
            headers,
            body,
            json,
        }
    }
}

impl ScimResponse {
    #[track_caller]
    pub fn assert_status(&self, status: u16) -> &Self {
        if self.status.as_u16() != status {
            panic!(
                "Expected status {status} but got {}: {}",
                self.status, self.body
            );
        }
        if self.status != StatusCode::NOT_MODIFIED {
            self.assert_scim_content_type();
        }
        self
    }

    #[track_caller]
    pub fn assert_scim_content_type(&self) -> &Self {
        let content_type = self
            .header(header::CONTENT_TYPE.as_str())
            .unwrap_or_default();
        if !content_type.starts_with(CONTENT_TYPE) {
            panic!("Expected content type {CONTENT_TYPE} but got {content_type:?}");
        }
        self
    }

    #[track_caller]
    pub fn assert_error(&self, status: u16, scim_type: Option<&str>) -> &Self {
        self.assert_status(status);

        if self.json["schemas"][0] != json!(MESSAGE_ERROR) {
            panic!("Expected a SCIM Error body but got {}", self.body);
        }
        if self.json["status"] != json!(status.to_string()) {
            panic!("Expected status {status} in the body of {}", self.body);
        }
        match (scim_type, self.json.get("scimType")) {
            (Some(expected), Some(Value::String(found))) if expected == found => {}
            (None, None) => {}
            _ => panic!("Expected scimType {scim_type:?} in {}", self.body),
        }
        self
    }

    #[track_caller]
    pub fn assert_detail_contains(&self, text: &str) -> &Self {
        let detail = self.json["detail"].as_str().unwrap_or_default();
        if !detail.contains(text) {
            panic!("Expected the detail to contain {text:?} but got {detail:?}");
        }
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    #[track_caller]
    pub fn etag(&self) -> String {
        self.header("etag")
            .unwrap_or_else(|| panic!("Missing ETag header in {}", self.body))
            .to_string()
    }

    #[track_caller]
    pub fn version(&self) -> String {
        self.json["meta"]["version"]
            .as_str()
            .unwrap_or_else(|| panic!("Missing meta.version in {}", self.body))
            .to_string()
    }

    #[track_caller]
    pub fn location(&self) -> String {
        self.header("location")
            .unwrap_or_else(|| panic!("Missing Location header in {}", self.body))
            .to_string()
    }

    #[track_caller]
    pub fn id(&self) -> String {
        self.json["id"]
            .as_str()
            .unwrap_or_else(|| panic!("Missing id in {}", self.body))
            .to_string()
    }

    #[track_caller]
    pub fn str(&self, pointer: &str) -> &str {
        self.json
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("Missing {pointer} in {}", self.body))
    }

    #[track_caller]
    pub fn resources(&self) -> &[Value] {
        self.json["Resources"]
            .as_array()
            .unwrap_or_else(|| panic!("Missing Resources in {}", self.body))
    }

    #[track_caller]
    pub fn total_results(&self) -> usize {
        self.json["totalResults"]
            .as_u64()
            .unwrap_or_else(|| panic!("Missing totalResults in {}", self.body)) as usize
    }

    #[track_caller]
    pub fn resource_ids(&self) -> Vec<String> {
        self.resources()
            .iter()
            .map(|resource| {
                resource["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("Missing id in {resource}"))
                    .to_string()
            })
            .collect()
    }

    #[track_caller]
    pub fn assert_contains_id(&self, id: &str) -> &Self {
        if !self.resource_ids().iter().any(|found| found == id) {
            panic!("Expected {id} in {}", self.body);
        }
        self
    }

    #[track_caller]
    pub fn assert_lacks_id(&self, id: &str) -> &Self {
        if self.resource_ids().iter().any(|found| found == id) {
            panic!("Did not expect {id} in {}", self.body);
        }
        self
    }
}
