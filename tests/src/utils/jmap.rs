/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::account::Account;
use base64::{Engine, engine::general_purpose};
use hyper::header;
use jmap_proto::error::set::SetErrorType;
use registry::types::error::ValidationError;
use registry::types::id::ObjectId;
use serde_json::{Value, json};
use std::{fmt::Display, str::FromStr, time::Duration};
use types::id::Id;

pub struct JmapResponse(pub Value);

pub struct RawResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub body: Vec<u8>,
}

impl RawResponse {
    async fn from_response(response: reqwest::Response) -> Self {
        RawResponse {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.bytes().await.unwrap().to_vec(),
        }
    }

    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChangeType<'x> {
    Created(&'x str),
    Updated(&'x str),
    Destroyed(&'x str),
}

impl Account {
    pub async fn jmap_get(
        &self,
        object: impl Display,
        properties: impl IntoIterator<Item = impl Display>,
        ids: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        self.jmap_get_account(self, object, properties, ids).await
    }

    pub async fn jmap_get_account(
        &self,
        account: &Account,
        object: impl Display,
        properties: impl IntoIterator<Item = impl Display>,
        ids: impl IntoIterator<Item = impl Display>,
    ) -> JmapResponse {
        let ids = ids
            .into_iter()
            .map(|id| Value::String(id.to_string()))
            .collect::<Vec<Value>>();
        let properties = properties
            .into_iter()
            .map(|p| Value::String(p.to_string()))
            .collect::<Vec<_>>();
        let properties = if properties.is_empty() {
            Value::Null
        } else {
            Value::Array(properties)
        };

        if account.id().document_id() != u32::MAX {
            self.jmap_method_calls(json!([[
                format!("{object}/get"),
                {
                    "accountId": account.id_string(),
                    "properties": properties,
                    "ids": if !ids.is_empty() { Some(ids) } else { None }
                },
                "0"
            ]]))
            .await
        } else {
            self.jmap_method_calls(json!([[
                format!("{object}/get"),
                {
                    "properties": properties,
                    "ids": if !ids.is_empty() { Some(ids) } else { None }
                },
                "0"
            ]]))
            .await
        }
    }

    pub async fn jmap_query(
        &self,
        object: impl Display,
        filter: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
        sort_by: impl IntoIterator<Item = impl Display>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let filter = filter
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into()))
            .collect::<serde_json::Map<_, _>>();
        let sort_by = sort_by
            .into_iter()
            .map(|id| {
                json! ({
                    "property": id.to_string()
                })
            })
            .collect::<Vec<Value>>();
        let arguments = [
            ("accountId".to_string(), self.id_string().into()),
            ("filter".to_string(), Value::Object(filter)),
            ("sort".to_string(), Value::Array(sort_by)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/query"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_create(
        &self,
        object: impl Display,
        items: impl IntoIterator<Item = Value>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        self.jmap_create_account(self, object, items, arguments)
            .await
    }

    pub async fn jmap_create_account(
        &self,
        account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = Value>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let create = items
            .into_iter()
            .enumerate()
            .map(|(i, item)| (format!("i{i}"), item))
            .collect::<serde_json::Map<_, _>>();
        let arguments = [
            (
                "accountId".to_string(),
                Value::String(account.id_string().to_string()),
            ),
            ("create".to_string(), Value::Object(create)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/set"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_update(
        &self,
        object: impl Display,
        items: impl IntoIterator<Item = (impl Display, Value)>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        self.jmap_update_account(self, object, items, arguments)
            .await
    }

    pub async fn jmap_update_account(
        &self,
        account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = (impl Display, Value)>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let update = items
            .into_iter()
            .map(|(i, item)| (i.to_string(), item))
            .collect::<serde_json::Map<_, _>>();
        let arguments = [
            (
                "accountId".to_string(),
                Value::String(account.id_string().to_string()),
            ),
            ("update".to_string(), Value::Object(update)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/set"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_destroy(
        &self,
        object: impl Display,
        items: impl IntoIterator<Item = impl Display>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        self.jmap_destroy_account(self, object, items, arguments)
            .await
    }

    pub async fn jmap_destroy_account(
        &self,
        account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = impl Display>,
        arguments: impl IntoIterator<Item = (impl Display, impl Into<Value>)>,
    ) -> JmapResponse {
        let destroy = items
            .into_iter()
            .map(|id| Value::String(id.to_string()))
            .collect::<Vec<_>>();
        let arguments = [
            (
                "accountId".to_string(),
                Value::String(account.id_string().to_string()),
            ),
            ("destroy".to_string(), Value::Array(destroy)),
        ]
        .into_iter()
        .chain(
            arguments
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.into())),
        )
        .collect::<serde_json::Map<_, _>>();

        self.jmap_method_calls(json!([[format!("{object}/set"), arguments, "0"]]))
            .await
    }

    pub async fn jmap_copy(
        &self,
        from_account: &Account,
        to_account: &Account,
        object: impl Display,
        items: impl IntoIterator<Item = (impl Display, Value)>,
        on_success_destroy: bool,
    ) -> JmapResponse {
        self.jmap_method_calls(json!([[
            format!("{object}/copy"),
            {
                "fromAccountId": from_account.id_string(),
                "accountId": to_account.id_string(),
                "onSuccessDestroyOriginal": on_success_destroy,
                "create": items
                        .into_iter()
                        .map(|(i, item)| (i.to_string(), item)).collect::<serde_json::Map<_, _>>()
            },
            "0"
        ]]))
        .await
    }

    pub async fn jmap_changes(&self, object: impl Display, state: impl Display) -> JmapResponse {
        self.jmap_method_calls(json!([[
            format!("{object}/changes"),
            {
                "accountId": self.id_string(),
                "sinceState": state.to_string()
            },
            "0"
        ]]))
        .await
    }

    pub async fn jmap_method_call(&self, method_name: &str, body: Value) -> JmapResponse {
        self.jmap_method_calls(json!([[method_name, body, "0"]]))
            .await
    }

    pub fn basic_auth(&self) -> String {
        format!(
            "Basic {}",
            general_purpose::STANDARD.encode(format!("{}:{}", self.name(), self.secret()))
        )
    }

    pub fn base_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.http_listener_port)
    }

    pub fn api_url(&self) -> String {
        format!("{}/jmap", self.base_url())
    }

    fn http_client(&self, timeout_ms: u64) -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .unwrap()
    }

    pub async fn http_get_raw(&self, url: &str, accept: Option<&str>) -> RawResponse {
        let mut req = self
            .http_client(5000)
            .get(url)
            .header(header::AUTHORIZATION, self.basic_auth());
        if let Some(accept) = accept {
            req = req.header(header::ACCEPT, accept);
        }
        RawResponse::from_response(req.send().await.unwrap()).await
    }

    pub async fn http_post_raw(
        &self,
        url: &str,
        content_type: &str,
        body: impl Into<Vec<u8>>,
    ) -> RawResponse {
        RawResponse::from_response(
            self.http_client(5000)
                .post(url)
                .header(header::AUTHORIZATION, self.basic_auth())
                .header(header::CONTENT_TYPE, content_type)
                .body(body.into())
                .send()
                .await
                .unwrap(),
        )
        .await
    }

    pub async fn jmap_raw_post(&self, body: impl Into<Vec<u8>>, content_type: &str) -> RawResponse {
        let url = self.api_url();
        self.http_post_raw(&url, content_type, body).await
    }

    pub async fn jmap_request(&self, using: &[&str], calls: Value) -> JmapResponse {
        let body = json!({
            "using": using,
            "methodCalls": calls
        });
        let raw = self
            .jmap_raw_post(body.to_string(), "application/json")
            .await;
        JmapResponse(
            raw.json()
                .unwrap_or_else(|| panic!("Response was not valid JSON: {}", raw.text())),
        )
    }

    pub async fn jmap_method_calls(&self, calls: Value) -> JmapResponse {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&self.basic_auth()).unwrap(),
        );

        let body = json!({
          "using": [
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:mail",
            "urn:ietf:params:jmap:submission",
            "urn:ietf:params:jmap:vacationresponse",
            "urn:ietf:params:jmap:contacts",
            "urn:ietf:params:jmap:contacts:parse",
            "urn:ietf:params:jmap:calendars",
            "urn:ietf:params:jmap:calendars:parse",
            "urn:ietf:params:jmap:websocket",
            "urn:ietf:params:jmap:sieve",
            "urn:ietf:params:jmap:blob",
            "urn:ietf:params:jmap:quota",
            "urn:ietf:params:jmap:principals",
            "urn:ietf:params:jmap:principals:owner",
            "urn:ietf:params:jmap:principals:availability",
            "urn:ietf:params:jmap:filenode",
            "urn:ietf:params:jmap:mail:share",
            "urn:stalwart:jmap"
          ],
          "methodCalls": calls
        });

        JmapResponse(
            serde_json::from_slice(
                &reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_millis(5000))
                    .default_headers(headers)
                    .build()
                    .unwrap()
                    .post(format!(
                        "https://127.0.0.1:{}/jmap",
                        self.http_listener_port
                    ))
                    .body(body.to_string())
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    pub async fn jmap_session_object(&self) -> JmapResponse {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", self.name(), self.secret()))
            ))
            .unwrap(),
        );

        JmapResponse(
            serde_json::from_slice(
                &reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_millis(1000))
                    .default_headers(headers)
                    .build()
                    .unwrap()
                    .get(format!(
                        "https://127.0.0.1:{}/jmap/session",
                        self.http_listener_port
                    ))
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    pub async fn destroy_all_addressbooks(&self) {
        self.jmap_method_calls(json!([[
            "AddressBook/get",
            {
              "accountId": self.id_string(),
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            "AddressBook/set",
            {
              "accountId": self.id_string(),
              "#destroy" : {
                    "resultOf": "R1",
                    "name": "AddressBook/get",
                    "path": "/list/*/id"
                },
              "onDestroyRemoveContents" : true
            },
            "R2"
          ]
        ]))
        .await;
    }

    pub async fn destroy_all_calendars(&self) {
        self.jmap_method_calls(json!([[
            "Calendar/get",
            {
              "accountId": self.id_string(),
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            "Calendar/set",
            {
              "accountId": self.id_string(),
              "#destroy" : {
                    "resultOf": "R1",
                    "name": "Calendar/get",
                    "path": "/list/*/id"
                },
              "onDestroyRemoveEvents" : true
            },
            "R2"
          ]
        ]))
        .await;
    }

    pub async fn destroy_all_event_notifications(&self) {
        self.jmap_method_calls(json!([[
            "CalendarEventNotification/get",
            {
              "accountId": self.id_string(),
              "ids" : (),
              "properties" : [
                "id"
              ]
            },
            "R1"
          ],
          [
            "CalendarEventNotification/set",
            {
              "accountId": self.id_string(),
              "#destroy" : {
                    "resultOf": "R1",
                    "name": "CalendarEventNotification/get",
                    "path": "/list/*/id"
                }
            },
            "R2"
          ]
        ]))
        .await;
    }
}

impl JmapResponse {
    pub fn created(&self, item_idx: u32) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/created/i{item_idx}"))
            .unwrap_or_else(|| panic!("Missing created item {item_idx}: {self:?}"))
    }

    pub fn created_id(&self, item_idx: u32) -> Id {
        Id::from_str(self.created(item_idx).id()).unwrap_or_else(|_| {
            panic!("Created item {item_idx} does not have a valid id: {self:?}")
        })
    }

    pub fn not_created(&self, item_idx: u32) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notCreated/i{item_idx}"))
            .unwrap_or_else(|| panic!("Missing not created item {item_idx}: {self:?}"))
    }

    pub fn updated(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/updated/{id}"))
            .unwrap_or_else(|| panic!("Missing updated item {id}: {self:?}"))
    }

    pub fn updated_id(&self, id: Id) -> &Value {
        self.updated(&id.to_string())
    }

    pub fn not_updated(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notUpdated/{id}"))
            .unwrap_or_else(|| panic!("Missing not updated item {id}: {self:?}"))
    }

    pub fn copied(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/created/{id}"))
            .unwrap_or_else(|| panic!("Missing created item {id}: {self:?}"))
    }

    pub fn method_response(&self) -> &Value {
        self.0
            .pointer("/methodResponses/0/1")
            .unwrap_or_else(|| panic!("Missing method response in response: {self:?}"))
    }

    pub fn num_responses(&self) -> usize {
        self.0
            .pointer("/methodResponses")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    }

    pub fn name_at(&self, n: usize) -> &str {
        self.0
            .pointer(&format!("/methodResponses/{n}/0"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing method name at {n}: {self:?}"))
    }

    pub fn response_at(&self, n: usize) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/{n}/1"))
            .unwrap_or_else(|| panic!("Missing method response at {n}: {self:?}"))
    }

    pub fn call_id_at(&self, n: usize) -> &str {
        self.0
            .pointer(&format!("/methodResponses/{n}/2"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing call id at {n}: {self:?}"))
    }

    pub fn is_error_at(&self, n: usize) -> bool {
        self.0
            .pointer(&format!("/methodResponses/{n}/0"))
            .and_then(|v| v.as_str())
            == Some("error")
    }

    pub fn error_type_at(&self, n: usize) -> Option<&str> {
        self.0
            .pointer(&format!("/methodResponses/{n}/1/type"))
            .and_then(|v| v.as_str())
    }

    pub fn session_state(&self) -> Option<&str> {
        self.0.pointer("/sessionState").and_then(|v| v.as_str())
    }

    pub fn list_array(&self) -> &Value {
        self.0
            .pointer("/methodResponses/0/1/list")
            .unwrap_or_else(|| panic!("Missing list in response: {self:?}"))
    }

    pub fn list(&self) -> &[Value] {
        self.0
            .pointer("/methodResponses/0/1/list")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing list in response: {self:?}"))
    }

    pub fn not_found(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/notFound")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing notFound in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/ids")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing ids in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn object_ids(&self) -> impl Iterator<Item = Id> {
        self.ids().map(move |id| {
            Id::from_str(id).unwrap_or_else(|_| panic!("Invalid id {id} in response: {self:?}"))
        })
    }

    pub fn destroyed(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/destroyed")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing destroyed in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn destroyed_ids(&self) -> impl Iterator<Item = Id> {
        self.destroyed().map(move |id| {
            Id::from_str(id).unwrap_or_else(|_| panic!("Invalid id {id} in response: {self:?}"))
        })
    }

    pub fn assert_destroyed(&self, expected: &[Id]) -> &Self {
        let destroyed_ids = self.destroyed_ids().collect::<Vec<_>>();
        for expected in expected {
            if !destroyed_ids.contains(expected) {
                panic!(
                    "Expected id {expected} to be destroyed but got destroyed ids {destroyed_ids:?}: {self:?}"
                );
            }
        }
        self
    }

    pub fn not_destroyed(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notDestroyed/{id}"))
            .unwrap_or_else(|| panic!("Missing not destroyed item {id}: {self:?}"))
    }

    pub fn state(&self) -> &str {
        self.0
            .pointer("/methodResponses/0/1/state")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing state in response: {self:?}"))
    }

    pub fn new_state(&self) -> &str {
        self.0
            .pointer("/methodResponses/0/1/newState")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing new state in response: {self:?}"))
    }

    pub fn changes(&self) -> impl Iterator<Item = ChangeType<'_>> {
        self.changes_by_type("created")
            .map(ChangeType::Created)
            .chain(self.changes_by_type("updated").map(ChangeType::Updated))
            .chain(self.changes_by_type("destroyed").map(ChangeType::Destroyed))
    }

    fn changes_by_type(&self, typ: &str) -> impl Iterator<Item = &str> {
        self.0
            .pointer(&format!("/methodResponses/0/1/{typ}"))
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing {typ} changes in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
    }

    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        self.0.pointer(pointer)
    }

    pub fn into_inner(self) -> Value {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
pub struct JmapSetError {
    #[serde(rename = "type")]
    pub type_: SetErrorType,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub properties: Option<Vec<String>>,

    #[serde(rename = "existingId")]
    #[serde(default)]
    pub existing_id: Option<Id>,

    #[serde(rename = "objectId")]
    #[serde(default)]
    pub object_id: Option<ObjectId>,

    #[serde(default)]
    #[serde(rename = "linkedObjects")]
    pub linked_objects: Vec<ObjectId>,

    #[serde(default)]
    #[serde(rename = "validationErrors")]
    pub validation_errors: Vec<ValidationError>,
}

impl JmapSetError {
    pub fn assert_type(&self, expected: SetErrorType) -> &Self {
        if self.type_ != expected {
            panic!("Expected error type {expected:?} but got {self:?}");
        }
        self
    }

    pub fn assert_description_contains(&self, expected: &str) -> &Self {
        if let Some(description) = &self.description {
            if !description.contains(expected) {
                panic!("Expected error description to contain {expected} but got {description}");
            }
        } else {
            panic!("Expected error description to contain {expected} but got no description");
        }
        self
    }

    pub fn assert_properties(&self, expected: &[&str]) -> &Self {
        let properties = self.properties.as_ref().unwrap_or_else(|| {
            panic!("Expected error to have properties {expected:?} but got no properties: {self:?}")
        });
        for expected in expected {
            if !properties.contains(&expected.to_string()) {
                panic!(
                    "Expected error to have property {expected} but got properties {properties:?}: {self:?}"
                );
            }
        }
        self
    }
}

pub trait JmapUtils {
    fn id(&self) -> &str {
        self.text_field("id")
    }

    fn object_id(&self) -> Id {
        self.id()
            .parse()
            .unwrap_or_else(|_| panic!("Invalid id {} in object", self.id()))
    }

    fn blob_id(&self) -> &str {
        self.text_field("blobId")
    }

    fn typ(&self) -> &str {
        self.text_field("type")
    }

    fn description(&self) -> &str {
        self.text_field("description")
    }

    fn to_set_error(&self) -> JmapSetError;

    fn with_property(self, field: impl Display, value: impl Into<Value>) -> Self;

    fn text_field(&self, field: &str) -> &str;

    fn integer_field(&self, field: &str) -> i64;

    fn assert_is_equal(&self, other: Value);
}

impl JmapUtils for Value {
    fn text_field(&self, field: &str) -> &str {
        self.pointer(&format!("/{field}"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing {field} in object: {self:?}"))
    }

    fn integer_field(&self, field: &str) -> i64 {
        self.pointer(&format!("/{field}"))
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| panic!("Missing {field} in object: {self:?}"))
    }

    fn to_set_error(&self) -> JmapSetError {
        serde_json::from_str(&self.to_string()).expect("Failed to deserialize set error")
    }

    fn assert_is_equal(&self, expected: Value) {
        if self != &expected {
            panic!(
                "Values are not equal:\ngot: {}\nexpected: {}",
                serde_json::to_string_pretty(self).unwrap(),
                serde_json::to_string_pretty(&expected).unwrap()
            );
        }
    }

    fn with_property(mut self, field: impl Display, value: impl Into<Value>) -> Self {
        if let Value::Object(map) = &mut self {
            map.insert(field.to_string(), value.into());
        } else {
            panic!("Not an object: {self:?}");
        }
        self
    }
}

impl<'x> ChangeType<'x> {
    pub fn as_created(&self) -> &str {
        match self {
            ChangeType::Created(id) => id,
            _ => panic!("Not a created change: {self:?}"),
        }
    }

    pub fn as_updated(&self) -> &str {
        match self {
            ChangeType::Updated(id) => id,
            _ => panic!("Not an updated change: {self:?}"),
        }
    }

    pub fn as_destroyed(&self) -> &str {
        match self {
            ChangeType::Destroyed(id) => id,
            _ => panic!("Not a destroyed change: {self:?}"),
        }
    }
}

impl Display for JmapResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::fmt::Debug for JmapResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_string_pretty(&self.0)
            .map_err(|_| std::fmt::Error)
            .and_then(|s| std::fmt::Display::fmt(&s, f))
    }
}

pub trait IntoJmapSet {
    fn into_jmap_set(self) -> Value;
}

impl<T: IntoIterator<Item = impl Display>> IntoJmapSet for T {
    fn into_jmap_set(self) -> Value {
        Value::Object(
            self.into_iter()
                .map(|id| (id.to_string(), Value::Bool(true)))
                .collect::<serde_json::Map<String, Value>>(),
        )
    }
}
