/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig, add_test_certs,
    directory::internal::TestInternalDirectory,
    jmap::server::{
        enterprise::{EnterpriseCore, insert_test_metrics},
        webhooks::{MockWebhookEndpoint, spawn_mock_webhook_endpoint},
    },
    store::{
        TempDir, build_store_config,
        cleanup::{search_store_destroy, store_assert_is_empty, store_destroy},
    },
};
use ahash::AHashMap;
use base64::{
    Engine,
    engine::general_purpose::{self, STANDARD},
};
use common::{
    Caches, Core, Data, Inner, Server,
    config::{
        server::{Listeners, ServerProtocol},
        telemetry::Telemetry,
    },
    core::BuildServer,
    manager::{
        boot::build_ipc,
        config::{ConfigManager, Patterns},
    },
};
use http::HttpSessionManager;
use hyper::{Method, header::AUTHORIZATION};
use imap::core::ImapSessionManager;
use jmap_client::client::{Client, Credentials};
use jmap_proto::error::request::RequestError;
use managesieve::core::ManageSieveSessionManager;
use pop3::Pop3SessionManager;
use reqwest::header;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use services::{
    SpawnServices,
    task_manager::{Task, TaskAction},
};
use smtp::{SpawnQueueManager, core::SmtpSessionManager};
use std::{
    fmt::{Debug, Display},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use store::{
    IterateParams, SUBSPACE_TASK_QUEUE, Stores, U32_LEN, U64_LEN,
    write::{AnyKey, TaskEpoch, key::DeserializeBigEndian},
};
use tokio::sync::watch;
use types::id::Id;
use utils::config::Config;

pub mod auth;
pub mod calendar;
pub mod contacts;
pub mod core;
pub mod files;
pub mod mail;
pub mod principal;
pub mod server;

#[tokio::test(flavor = "multi_thread")]
async fn jmap_tests() {
    let delete = std::env::var("NO_DELETE").is_err();
    let mut params = init_jmap_tests(delete).await;

    server::webhooks::test(&mut params).await;

    mail::get::test(&mut params).await;
    mail::set::test(&mut params).await;
    mail::parse::test(&mut params).await;
    mail::query::test(&mut params, delete).await;
    mail::search_snippet::test(&mut params).await;
    mail::changes::test(&mut params).await;
    mail::query_changes::test(&mut params).await;
    mail::copy::test(&mut params).await;
    mail::thread_get::test(&mut params).await;
    mail::thread_merge::test(&mut params).await;
    mail::mailbox::test(&mut params).await;
    mail::delivery::test(&mut params).await;
    mail::acl::test(&mut params).await;
    mail::sieve_script::test(&mut params).await;
    mail::vacation_response::test(&mut params).await;
    mail::submission::test(&mut params).await;
    mail::crypto::test(&mut params).await;
    mail::antispam::test(&mut params).await;

    core::event_source::test(&mut params).await;
    core::websocket::test(&mut params).await;
    core::push_subscription::test(&mut params).await;
    core::blob::test(&mut params).await;

    auth::limits::test(&mut params).await;
    auth::oauth::test(&mut params).await;
    auth::quota::test(&mut params).await;
    auth::permissions::test(&params).await;

    contacts::addressbook::test(&mut params).await;
    contacts::contact::test(&mut params).await;
    contacts::acl::test(&mut params).await;

    files::node::test(&mut params).await;
    files::acl::test(&mut params).await;

    calendar::calendars::test(&mut params).await;
    calendar::event::test(&mut params).await;
    calendar::notification::test(&mut params).await;
    calendar::alarm::test(&mut params).await;

    calendar::identity::test(&mut params).await;
    calendar::acl::test(&mut params).await;

    principal::get::test(&mut params).await;
    principal::availability::test(&mut params).await;

    server::purge::test(&mut params).await;
    server::enterprise::test(&mut params).await;

    assert_is_empty(&params.server).await;

    if delete {
        params.temp_dir.delete();
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
pub async fn jmap_metric_tests() {
    let params = init_jmap_tests(false).await;

    insert_test_metrics(params.server.core.clone()).await;
}

#[allow(dead_code)]
pub struct JMAPTest {
    server: Server,
    accounts: AHashMap<&'static str, Account>,
    temp_dir: TempDir,
    webhook: Arc<MockWebhookEndpoint>,
    shutdown_tx: watch::Sender<bool>,
}

pub struct Account {
    name: &'static str,
    secret: &'static str,
    emails: &'static [&'static str],
    id: Id,
    id_string: String,
    client: Client,
}

impl JMAPTest {
    pub fn account(&self, name: &str) -> &Account {
        self.accounts.get(name).unwrap()
    }

    pub async fn assert_is_empty(&self) {
        assert_is_empty(&self.server).await;
    }
}

impl Account {
    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn id_string(&self) -> &str {
        &self.id_string
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn secret(&self) -> &'static str {
        self.secret
    }

    pub fn emails(&self) -> &'static [&'static str] {
        self.emails
    }

    pub async fn client_owned(&self) -> Client {
        Client::new()
            .credentials(Credentials::basic(self.name(), self.secret()))
            .timeout(Duration::from_secs(3600))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap()
    }
}

pub async fn wait_for_index(server: &Server) {
    let mut count = 0;
    loop {
        let mut has_index_tasks = None;
        server
            .core
            .storage
            .data
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace: SUBSPACE_TASK_QUEUE,
                        key: vec![0u8],
                    },
                    AnyKey {
                        subspace: SUBSPACE_TASK_QUEUE,
                        key: vec![u8::MAX; 16],
                    },
                )
                .ascending(),
                |key, value| {
                    has_index_tasks = Some(
                        Task::<TaskAction>::deserialize(key, value).unwrap_or_else(|_| Task {
                            due: TaskEpoch::from_inner(
                                key.deserialize_be_u64(key.len() - U64_LEN).unwrap(),
                            ),
                            account_id: key.deserialize_be_u32(U64_LEN).unwrap(),
                            document_id: key.deserialize_be_u32(U64_LEN + U32_LEN + 1).unwrap(),
                            action: TaskAction::SendImip,
                        }),
                    );

                    Ok(false)
                },
            )
            .await
            .unwrap();

        if let Some(task) = has_index_tasks {
            count += 1;
            if count % 10 == 0 {
                println!("Waiting for pending task {:?}...", task);
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        } else {
            break;
        }
    }
}

pub async fn assert_is_empty(server: &Server) {
    // Wait for pending index tasks
    wait_for_index(server).await;

    // Assert is empty
    store_assert_is_empty(server.store(), server.core.storage.blob.clone(), false).await;
    search_store_destroy(server.search_store()).await;

    // Clean caches
    for cache in [
        &server.inner.cache.events,
        &server.inner.cache.contacts,
        &server.inner.cache.files,
        &server.inner.cache.scheduling,
    ] {
        cache.clear();
    }
    server.inner.cache.messages.clear();
}

async fn init_jmap_tests(delete_if_exists: bool) -> JMAPTest {
    // Load and parse config
    let temp_dir = TempDir::new("jmap_tests", delete_if_exists);
    let mut config = Config::new(
        add_test_certs(&(build_store_config(&temp_dir.path.to_string_lossy()) + SERVER))
            .replace("{TMP}", &temp_dir.path.display().to_string())
            .replace(
                "{LEVEL}",
                &std::env::var("LOG").unwrap_or_else(|_| "disable".to_string()),
            ),
    )
    .unwrap();
    config.resolve_all_macros().await;

    // Parse servers
    let mut servers = Listeners::parse(&mut config);

    // Bind ports and drop privileges
    servers.bind_and_drop_priv(&mut config);

    // Build stores
    let stores = Stores::parse_all(&mut config, false).await;

    // Parse core
    let config_manager = ConfigManager {
        cfg_local: Default::default(),
        cfg_local_path: PathBuf::new(),
        cfg_local_patterns: Patterns::parse(&mut config).into(),
        cfg_store: config
            .value("storage.data")
            .and_then(|id| stores.stores.get(id))
            .cloned()
            .unwrap_or_default(),
    };
    let tracers = Telemetry::parse(&mut config, &stores);
    let core = Core::parse(&mut config, stores, config_manager)
        .await
        .enable_enterprise();
    let data = Data::parse(&mut config);
    let cache = Caches::parse(&mut config);
    let store = core.storage.data.clone();
    let search_store = core.storage.fts.clone();
    let (ipc, mut ipc_rxs) = build_ipc(false);
    let inner = Arc::new(Inner {
        shared_core: core.into_shared(),
        data,
        ipc,
        cache,
    });

    if delete_if_exists {
        store_destroy(&store).await;
        search_store_destroy(&search_store).await;
    }

    // Parse acceptors
    servers.parse_tcp_acceptors(&mut config, inner.clone());

    // Enable tracing
    tracers.enable(true);

    // Start services
    config.assert_no_errors();
    ipc_rxs.spawn_queue_manager(inner.clone());
    ipc_rxs.spawn_services(inner.clone());

    // Spawn servers
    let (shutdown_tx, _) = servers.spawn(|server, acceptor, shutdown_rx| {
        match &server.protocol {
            ServerProtocol::Smtp | ServerProtocol::Lmtp => server.spawn(
                SmtpSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Http => server.spawn(
                HttpSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Imap => server.spawn(
                ImapSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::Pop3 => server.spawn(
                Pop3SessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
            ServerProtocol::ManageSieve => server.spawn(
                ManageSieveSessionManager::new(inner.clone()),
                inner.clone(),
                acceptor,
                shutdown_rx,
            ),
        };
    });

    // Create tables
    let server = inner.build_server();
    let mut accounts = AHashMap::new();

    for (name, secret, description, emails) in [
        ("admin", "secret", "Superuser", &[][..]),
        (
            "jdoe@example.com",
            "12345",
            "John Doe",
            &["jdoe@example.com", "john.doe@example.com"][..],
        ),
        (
            "jane.smith@example.com",
            "abcde",
            "Jane Smith",
            &["jane.smith@example.com"],
        ),
        (
            "bill@example.com",
            "098765",
            "Bill Foobar",
            &["bill@example.com"],
        ),
        (
            "robert@example.com",
            "aabbcc",
            "Robert Foobar",
            &["robert@example.com"][..],
        ),
    ] {
        let id: Id = server
            .store()
            .create_test_user(name, secret, description, emails)
            .await
            .into();
        let id_string = id.to_string();

        let mut client = Client::new()
            .credentials(Credentials::basic(name, secret))
            .timeout(Duration::from_secs(3600))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap();
        client.set_default_account_id(id_string.clone());

        accounts.insert(
            name,
            Account {
                name,
                secret,
                emails,
                id,
                id_string,
                client,
            },
        );
    }

    for (name, description, emails) in
        [("sales@example.com", "Sales Group", &["sales@example.com"])]
    {
        let id: Id = server
            .store()
            .create_test_group(name, description, emails)
            .await
            .into();
        let id_string = id.to_string();

        let mut client = Client::new()
            .credentials(Credentials::basic("admin", "secret"))
            .timeout(Duration::from_secs(3600))
            .accept_invalid_certs(true)
            .follow_redirects(["127.0.0.1"])
            .connect("https://127.0.0.1:8899")
            .await
            .unwrap();
        client.set_default_account_id(id_string.clone());

        accounts.insert(
            name,
            Account {
                name,
                secret: "",
                emails,
                id,
                id_string,
                client,
            },
        );
    }

    JMAPTest {
        server,
        temp_dir,
        accounts,
        shutdown_tx,
        webhook: spawn_mock_webhook_endpoint(),
    }
}

pub struct JmapResponse(pub Value);

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
        self.jmap_method_calls(json!([[
            format!("{object}/get"),
            {
                "accountId": account.id_string(),
                "properties": properties
                .into_iter()
                .map(|p| Value::String(p.to_string()))
                .collect::<Vec<_>>(),
                "ids": if !ids.is_empty() { Some(ids) } else { None }
            },
            "0"
        ]]))
        .await
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

    pub async fn jmap_method_calls(&self, calls: Value) -> JmapResponse {
        let mut headers = header::HeaderMap::new();

        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!(
                "Basic {}",
                general_purpose::STANDARD.encode(format!("{}:{}", self.name(), self.secret()))
            ))
            .unwrap(),
        );

        let body = json!({
          "using": [ "urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:quota" ],
          "methodCalls": calls
        });

        JmapResponse(
            serde_json::from_slice(
                &reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .timeout(Duration::from_millis(1000))
                    .default_headers(headers)
                    .build()
                    .unwrap()
                    .post("https://127.0.0.1:8899/jmap")
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
                    .get("https://127.0.0.1:8899/jmap/session")
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

    pub fn not_updated(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/notUpdated/{id}"))
            .unwrap_or_else(|| panic!("Missing not updated item {id}: {self:?}"))
    }

    pub fn copied(&self, id: &str) -> &Value {
        self.0
            .pointer(&format!("/methodResponses/0/1/created/{id}"))
            .unwrap_or_else(|| panic!("Missing updated item {id}: {self:?}"))
    }

    pub fn method_response(&self) -> &Value {
        self.0
            .pointer("/methodResponses/0/1")
            .unwrap_or_else(|| panic!("Missing method response in response: {self:?}"))
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

    pub fn destroyed(&self) -> impl Iterator<Item = &str> {
        self.0
            .pointer("/methodResponses/0/1/destroyed")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("Missing destroyed in response: {self:?}"))
            .iter()
            .map(|v| v.as_str().unwrap())
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

pub trait JmapUtils {
    fn id(&self) -> &str {
        self.text_field("id")
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

    fn with_property(self, field: impl Display, value: impl Into<Value>) -> Self;

    fn text_field(&self, field: &str) -> &str;

    fn assert_is_equal(&self, other: Value);
}

impl JmapUtils for Value {
    fn text_field(&self, field: &str) -> &str {
        self.pointer(&format!("/{field}"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing {field} in object: {self:?}"))
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChangeType<'x> {
    Created(&'x str),
    Updated(&'x str),
    Destroyed(&'x str),
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

impl Debug for JmapResponse {
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

pub fn find_values(string: &str, name: &str) -> Vec<String> {
    let mut last_pos = 0;
    let mut values = Vec::new();

    while let Some(pos) = string[last_pos..].find(name) {
        let mut value = string[last_pos + pos + name.len()..]
            .split('"')
            .nth(1)
            .unwrap();
        if value.ends_with('\\') {
            value = &value[..value.len() - 1];
        }
        values.push(value.to_string());
        last_pos += pos + name.len();
    }

    values
}

pub fn replace_values(mut string: String, find: &[String], replace: &[String]) -> String {
    for (find, replace) in find.iter().zip(replace.iter()) {
        string = string.replace(find, replace);
    }
    string
}

pub fn replace_boundaries(string: String) -> String {
    let values = find_values(&string, "boundary=");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("boundary_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}

pub fn replace_blob_ids(string: String) -> String {
    let values = find_values(&string, "blobId\":");
    if !values.is_empty() {
        replace_values(
            string,
            &values,
            &(0..values.len())
                .map(|i| format!("blob_{}", i))
                .collect::<Vec<_>>(),
        )
    } else {
        string
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum Response<T> {
    RequestError(RequestError<'static>),
    Error {
        error: String,
        details: Option<String>,
        item: Option<String>,
        reason: Option<String>,
    },
    Data {
        data: T,
    },
}

pub struct ManagementApi {
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for ManagementApi {
    fn default() -> Self {
        Self {
            port: 9980,
            username: "admin".to_string(),
            password: "secret".to_string(),
        }
    }
}

impl ManagementApi {
    pub fn new(port: u16, username: &str, password: &str) -> Self {
        Self {
            port,
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        query: &str,
        body: &impl Serialize,
    ) -> Result<Response<T>, String> {
        self.request_raw(
            Method::POST,
            query,
            Some(serde_json::to_string(body).unwrap()),
        )
        .await
        .map(|result| {
            serde_json::from_str::<Response<T>>(&result)
                .unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn patch<T: DeserializeOwned>(
        &self,
        query: &str,
        body: &impl Serialize,
    ) -> Result<Response<T>, String> {
        self.request_raw(
            Method::PATCH,
            query,
            Some(serde_json::to_string(body).unwrap()),
        )
        .await
        .map(|result| {
            serde_json::from_str::<Response<T>>(&result)
                .unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    pub async fn delete<T: DeserializeOwned>(&self, query: &str) -> Result<Response<T>, String> {
        self.request_raw(Method::DELETE, query, None)
            .await
            .map(|result| {
                serde_json::from_str::<Response<T>>(&result)
                    .unwrap_or_else(|err| panic!("{err}: {result}"))
            })
    }

    pub async fn get<T: DeserializeOwned>(&self, query: &str) -> Result<Response<T>, String> {
        self.request_raw(Method::GET, query, None)
            .await
            .map(|result| {
                serde_json::from_str::<Response<T>>(&result)
                    .unwrap_or_else(|err| panic!("{err}: {result}"))
            })
    }
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        query: &str,
    ) -> Result<Response<T>, String> {
        self.request_raw(method, query, None).await.map(|result| {
            serde_json::from_str::<Response<T>>(&result)
                .unwrap_or_else(|err| panic!("{err}: {result}"))
        })
    }

    async fn request_raw(
        &self,
        method: Method,
        query: &str,
        body: Option<String>,
    ) -> Result<String, String> {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(method, format!("https://127.0.0.1:{}{query}", self.port));

        if let Some(body) = body {
            request = request.body(body);
        }

        request
            .header(
                AUTHORIZATION,
                format!(
                    "Basic {}",
                    STANDARD.encode(format!("{}:{}", self.username, self.password).as_bytes())
                ),
            )
            .send()
            .await
            .map_err(|err| err.to_string())?
            .bytes()
            .await
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .map_err(|err| err.to_string())
    }
}

impl<T: Debug> Response<T> {
    pub fn unwrap_data(self) -> T {
        match self {
            Response::Data { data } => data,
            Response::Error {
                error,
                details,
                reason,
                ..
            } => {
                panic!("Expected data, found error {error:?}: {details:?} {reason:?}")
            }
            Response::RequestError(err) => {
                panic!("Expected data, found error {err:?}")
            }
        }
    }

    pub fn try_unwrap_data(self) -> Option<T> {
        match self {
            Response::Data { data } => Some(data),
            Response::RequestError(error) if error.status == 404 => None,
            Response::Error {
                error,
                details,
                reason,
                ..
            } => {
                panic!("Expected data, found error {error:?}: {details:?} {reason:?}")
            }
            Response::RequestError(err) => {
                panic!("Expected data, found error {err:?}")
            }
        }
    }

    pub fn unwrap_error(self) -> (String, Option<String>, Option<String>) {
        match self {
            Response::Error {
                error,
                details,
                reason,
                ..
            } => (error, details, reason),
            Response::Data { data } => panic!("Expected error, found data: {data:?}"),
            Response::RequestError(err) => {
                panic!("Expected error, found request error {err:?}")
            }
        }
    }

    pub fn unwrap_request_error(self) -> RequestError<'static> {
        match self {
            Response::Error {
                error,
                details,
                reason,
                ..
            } => {
                panic!("Expected request error, found error {error:?}: {details:?} {reason:?}")
            }
            Response::Data { data } => panic!("Expected request error, found data: {data:?}"),
            Response::RequestError(err) => err,
        }
    }

    pub fn expect_request_error(self, value: &str) {
        let err = self.unwrap_request_error();
        if !err.detail.contains(value) && !err.title.as_ref().is_some_and(|t| t.contains(value)) {
            panic!("Expected request error containing {value:?}, found {err:?}")
        }
    }

    pub fn expect_error(self, value: &str) {
        let (error, details, reason) = self.unwrap_error();
        if !error.contains(value)
            && !details.as_ref().is_some_and(|d| d.contains(value))
            && !reason.as_ref().is_some_and(|r| r.contains(value))
        {
            panic!("Expected error containing {value:?}, found {error:?}: {details:?} {reason:?}")
        }
    }
}

const SERVER: &str = r#"
[server]
hostname = "'jmap.example.org'"

[http]
url = "'https://127.0.0.1:8899'"

[server.listener.jmap]
bind = ["127.0.0.1:8899"]
protocol = "http"
max-connections = 81920
tls.implicit = true

[server.listener.imap]
bind = ["127.0.0.1:9991"]
protocol = "imap"
max-connections = 81920

[server.listener.lmtp-debug]
bind = ['127.0.0.1:11200']
greeting = 'Test LMTP instance'
protocol = 'lmtp'
tls.implicit = false

[server.listener.pop3]
bind = ["127.0.0.1:4110"]
protocol = "pop3"
max-connections = 81920
tls.implicit = true

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = "default"

[server.fail2ban]
authentication = "100/5s"

[authentication]
rate-limit = "100/2s"

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = [ { if = "!is_empty(authenticated_as)", then = true }, 
          { else = false } ]

[session.rcpt.errors]
total = 5
wait = "1ms"

[session.auth]
mechanisms = "[plain, login, oauthbearer]"

[session.data]
spam-filter = "recipients[0] != 'robert@example.com'"

[session.data.add-headers]
delivered-to = false

[queue]
path = "{TMP}"
hash = 64

[report]
path = "{TMP}"
hash = 64

[resolver]
type = "system"

[queue.strategy]
route = [ { if = "rcpt_domain == 'example.com'", then = "'local'" }, 
             { if = "contains(['remote.org', 'foobar.com', 'test.com', 'other_domain.com'], rcpt_domain)", then = "'mock-smtp'" },
             { else = "'mx'" } ]

[queue.route."mock-smtp"]
type = "relay"
address = "localhost"
port = 9999
protocol = "smtp"

[queue.route."mock-smtp".tls]
implicit = false
allow-invalid-certs = true

[session.extensions]
future-release = [ { if = "!is_empty(authenticated_as)", then = "99999999d"},
                   { else = false } ]

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[jmap.protocol.get]
max-objects = 100000

[jmap.protocol.set]
max-objects = 100000

[jmap.protocol.request]
max-concurrent = 8

[jmap.protocol.upload]
max-size = 5000000
max-concurrent = 4
ttl = "1m"

[jmap.protocol.upload.quota]
files = 3
size = 50000

[jmap.rate-limit]
account = "1000/1m"
anonymous = "100/1m"

[jmap.event-source]
throttle = "500ms"

[jmap.web-sockets]
throttle = "500ms"

[jmap.push]
throttle = "500ms"
attempts.interval = "500ms"

[email]
auto-expunge = "1s"

[changes]
max-history = "1"

[store."auth"]
type = "sqlite"
path = "{TMP}/auth.db"

[store."auth".query]
name = "SELECT name, type, secret, description, quota FROM accounts WHERE name = ? AND active = true"
members = "SELECT member_of FROM group_members WHERE name = ?"
recipients = "SELECT name FROM emails WHERE address = ?"
emails = "SELECT address FROM emails WHERE name = ? AND type != 'list' ORDER BY type DESC, address ASC"
verify = "SELECT address FROM emails WHERE address LIKE '%' || ? || '%' AND type = 'primary' ORDER BY address LIMIT 5"
expand = "SELECT p.address FROM emails AS p JOIN emails AS l ON p.name = l.name WHERE p.type = 'primary' AND l.address = ? AND l.type = 'list' ORDER BY p.address LIMIT 50"
domains = "SELECT 1 FROM emails WHERE address LIKE '%@' || ? LIMIT 1"

[imap.auth]
allow-plain-text = true

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"

[oauth.client-registration]
anonymous = true
require = true

[oauth.oidc]
signature-key = '''-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDMXJI1bL3z8gaF
Ze/6493VjL+jHkFMP2Pc7fLwRF1fhkuIdYTp69LabzrSEJCRCz0UI2NHqPOgtOta
+zRHKAMr7c7Z6uKO0K+aXiQYHw4Y70uSG8CnmNl7kb4OM/CAcoO6fePmvBsyESfn
TmkJ5bfHEZQFDQEAoDlDjtjxuwYsAQQVQXuAydi8j8pyTWKAJ1RDgnUT+HbOub7j
JrQ7sPe6MPCjXv5N76v9RMHKktfYwRNMlkLkxImQU55+vlvghNztgFlIlJDFfNiy
UQPV5FTEZJli9BzMoj1JQK3sZyV8WV0W1zN41QQ+glAAC6+K7iTDPRMINBSwbHyn
6Lb9Q6U7AgMBAAECggEAB93qZ5xrhYgEFeoyKO4mUdGsu4qZyJB0zNeWGgdaXCfZ
zC4l8zFM+R6osix0EY6lXRtC95+6h9hfFQNa5FWseupDzmIQiEnim1EowjWef87l
Eayi0nDRB8TjqZKjR/aLOUhzrPlXHKrKEUk/RDkacCiDklwz9S0LIfLOSXlByBDM
/n/eczfX2gUATexMHSeIXs8vN2jpuiVv0r+FPXcRvqdzDZnYSzS8BJ9k6RYXVQ4o
NzCbfqgFIpVryB7nHgSTrNX9G7299If8/dXmesXWSFEJvvDSSpcBoINKbfgSlrxd
6ubjiotcEIBUSlbaanRrydwShhLHnXyupNAb7tlvyQKBgQDsIipSK4+H9FGl1rAk
Gg9DLJ7P/94sidhoq1KYnj/CxwGLoRq22khZEUYZkSvYXDu1Qkj9Avi3TRhw8uol
l2SK1VylL5FQvTLKhWB7b2hjrUd5llMRgS3/NIdLhOgDMB7w3UxJnCA/df/Rj+dM
WhkyS1f0x3t7XPLwWGurW0nJcwKBgQDdjhrNfabrK7OQvDpAvNJizuwZK9WUL7CD
rR0V0MpDGYW12BTEOY6tUK6XZgiRitAXf4EkEI6R0Q0bFzwDDLrg7TvGdTuzNeg/
8vm8IlRlOkrdihtHZI4uRB7Ytmz24vzywEBE0p6enA7v4oniscUks/KKmDGr0V90
yT9gIVrjGQKBgQCjnWC5otlHGLDiOgm+WhgtMWOxN9dYAQNkMyF+Alinu4CEoVKD
VGhA3sk1ufMpbW8pvw4X0dFIITFIQeift3DBCemxw23rBc2FqjkaDi3EszINO22/
eUTHyjvcxfCFFPi7aHsNnhJyJm7lY9Kegudmg/Ij93zGE7d5darVBuHvpQKBgBBY
YovUgFMLR1UfPeD2zUKy52I4BKrJFemxBNtOKw3mPSIcTfPoFymcMTVENs+eARoq
svlZK1uAo8ni3e+Pqd3cQrOyhHQFPxwwrdH+amGJemp7vOV4erDZH7l3Q/S27Fhw
bI1nSIKFGukBupB58wRxLiyha9C0QqmYC0/pRg5JAn8Rbj5tP26oVCXjZEfWJL8J
axxSxsGA4Vol6i6LYnVgZG+1ez2rP8vUORo1lRzmdeP4o1BSJf9TPwXkuppE5J+t
UZVKtYGlEn1RqwGNd8I9TiWvU84rcY9nsxlDR86xwKRWFvYqVOiGYtzRyewYRdjU
rTs9aqB3v1+OVxGxR6Na
-----END PRIVATE KEY-----
'''
signature-algorithm = "RS256"

[oauth.oidc-ignore]
signature-key = '''-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggybcqc86ulFFiOon
WiYrLO4z8/kmkqvA7wGElBok9IqhRANCAAQxZK68FnQtHC0eyh8CA05xRIvxhVHn
0ymka6XBh9aFtW4wfeoKhTkSKjHc/zjh9Rr2dr3kvmYe80fMGhW4ycGA
-----END PRIVATE KEY-----
'''
signature-algorithm = "ES256"

[session.extensions]
expn = true
vrfy = true

[spam-filter]
enable = true

[spam-filter.list]
scores = {"GTUBE_TEST" = "1000.0"}

[sharing]
allow-directory-query = true

[calendar.alarms]
minimum-interval = "1s"

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
#disabled-events = ["network.*", "telemetry.webhook-error"]
disabled-events = ["network.*", "telemetry.webhook-error", "http.request-body"]

[webhook."test"]
url = "http://127.0.0.1:8821/hook"
events = ["auth.*", "delivery.dsn*", "message-ingest.*", "security.authentication-ban"]
signature-key = "ovos-moles"
throttle = "100ms"

[sieve.untrusted.scripts."common"]
contents = '''
require "reject";

reject "Rejected from a global script.";
stop;
'''
"#;
