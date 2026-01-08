/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig, TEST_USERS, add_test_certs,
    directory::internal::TestInternalDirectory,
    jmap::{assert_is_empty, wait_for_index},
    store::{
        TempDir, build_store_config,
        cleanup::{search_store_destroy, store_destroy},
    },
};
use ::managesieve::core::ManageSieveSessionManager;
use ::store::Stores;
use ahash::{AHashMap, AHashSet};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{
    Caches, Core, Data, DavResource, DavResources, Inner, Server,
    config::{
        server::{Listeners, ServerProtocol},
        telemetry::Telemetry,
    },
    core::BuildServer,
    manager::boot::build_ipc,
};
use dav_proto::{
    schema::property::{DavProperty, WebDavProperty},
    xml_pretty_print,
};
use directory::Permission;
use email::message::metadata::MessageMetadata;
use groupware::{DavResourceName, cache::GroupwareCache};
use http::HttpSessionManager;
use hyper::{HeaderMap, Method, StatusCode, header::AUTHORIZATION};
use imap::core::ImapSessionManager;
use pop3::Pop3SessionManager;
use quick_xml::Reader;
use quick_xml::events::Event;
use services::SpawnServices;
use smtp::{SpawnQueueManager, core::SmtpSessionManager};
use std::{borrow::Cow, str};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use store::{
    ValueKey,
    rand::{Rng, distr::Alphanumeric, rng},
    write::{AlignedBytes, Archive},
};
use tokio::sync::watch;
use types::{collection::Collection, field::EmailField};
use utils::config::Config;

pub mod acl;
pub mod basic;
pub mod cal_alarm;
pub mod cal_itip;
pub mod cal_query;
pub mod cal_scheduling;
pub mod card_query;
pub mod copy_move;
pub mod lock;
pub mod mkcol;
pub mod multiget;
pub mod principals;
pub mod prop;
pub mod put_get;
pub mod sync;

#[test]
fn webdav_tests() {
    //test_build_itip_templates(&handle.server).await;

    tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(8 * 1024 * 1024) // 8MB stack
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // Prepare settings
            let assisted_discovery = std::env::var("ASSISTED_DISCOVERY").unwrap_or_default() == "1";
            let start_time = Instant::now();
            let delete = true;
            let handle = init_webdav_tests(assisted_discovery, delete).await;

            basic::test(&handle).await;
            put_get::test(&handle).await;
            mkcol::test(&handle).await;
            copy_move::test(&handle, assisted_discovery).await;
            prop::test(&handle, assisted_discovery).await;
            multiget::test(&handle).await;
            sync::test(&handle).await;
            lock::test(&handle).await;
            principals::test(&handle, assisted_discovery).await;
            acl::test(&handle).await;
            card_query::test(&handle).await;
            cal_query::test(&handle).await;
            cal_alarm::test(&handle).await;
            cal_itip::test();
            cal_scheduling::test(&handle).await;

            // Print elapsed time
            let elapsed = start_time.elapsed();
            println!(
                "Elapsed: {}.{:03}s",
                elapsed.as_secs(),
                elapsed.subsec_millis()
            );

            // Remove test data
            if delete {
                handle.temp_dir.delete();
            }
        });
}

#[allow(dead_code)]
pub struct WebDavTest {
    server: Server,
    clients: AHashMap<&'static str, DummyWebDavClient>,
    temp_dir: TempDir,
    shutdown_tx: watch::Sender<bool>,
}

async fn init_webdav_tests(assisted_discovery: bool, delete_if_exists: bool) -> WebDavTest {
    // Load and parse config
    let temp_dir = TempDir::new("webdav_tests", delete_if_exists);
    let mut config = Config::new(
        add_test_certs(&(build_store_config(&temp_dir.path.to_string_lossy()) + SERVER))
            .replace("{TMP}", &temp_dir.path.display().to_string())
            .replace("{ASSISTED_DISCOVERY}", &assisted_discovery.to_string())
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
    let tracers = Telemetry::parse(&mut config, &stores);
    let core = Core::parse(&mut config, stores, Default::default()).await;
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

    if delete_if_exists {
        store_destroy(&store).await;
        search_store_destroy(&search_store).await;
    }

    // Create test accounts
    let mut clients = AHashMap::new();
    for (account, secret, name, email) in TEST_USERS {
        let account_id = store
            .create_test_user(account, secret, name, &[email])
            .await;
        clients.insert(
            *account,
            DummyWebDavClient::new(account_id, account, secret, email),
        );
        store
            .add_permissions(
                account,
                [Permission::DavPrincipalList, Permission::DavPrincipalSearch],
            )
            .await;
        if *account == "mike" {
            store.set_test_quota(account, 1024).await;
        }
    }
    store
        .create_test_group("support", "Support Group", &["support@example.com"])
        .await;
    store.add_to_group("jane", "support").await;

    WebDavTest {
        server: inner.build_server(),
        clients,
        temp_dir,
        shutdown_tx,
    }
}

impl WebDavTest {
    pub fn client(&self, name: &'static str) -> &DummyWebDavClient {
        self.clients.get(name).unwrap()
    }

    pub async fn resources(&self, name: &'static str, collection: Collection) -> Arc<DavResources> {
        let account_id = self.client(name).account_id;
        let access_token = self.server.get_access_token(account_id).await.unwrap();
        self.server
            .fetch_dav_resources(&access_token, account_id, collection.into())
            .await
            .unwrap()
    }

    pub fn clear_cache(&self) {
        for cache in [
            &self.server.inner.cache.events,
            &self.server.inner.cache.contacts,
            &self.server.inner.cache.files,
        ] {
            cache.clear();
        }
    }

    pub async fn assert_is_empty(&self) {
        assert_is_empty(&self.server).await;
        self.clear_cache();
    }

    pub async fn wait_for_index(&self) {
        wait_for_index(&self.server).await;
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DummyWebDavClient {
    account_id: u32,
    name: &'static str,
    email: &'static str,
    credentials: String,
}

#[derive(Debug)]
pub struct DavResponse {
    headers: AHashMap<String, String>,
    status: StatusCode,
    body: Result<String, String>,
    xml: Vec<(String, String)>,
}

impl DummyWebDavClient {
    pub fn new(
        account_id: u32,
        name: &'static str,
        secret: &'static str,
        email: &'static str,
    ) -> Self {
        Self {
            account_id,
            name,
            email,
            credentials: format!(
                "Basic {}",
                STANDARD.encode(format!("{name}:{secret}").as_bytes())
            ),
        }
    }

    pub async fn request(&self, method: &str, query: &str, body: impl Into<String>) -> DavResponse {
        self.request_with_headers(method, query, [].into_iter(), body)
            .await
    }

    pub async fn request_with_headers(
        &self,
        method: &str,
        query: &str,
        headers: impl IntoIterator<Item = (&'static str, &str)>,
        body: impl Into<String>,
    ) -> DavResponse {
        let mut request = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
            .request(
                Method::from_bytes(method.as_bytes()).unwrap(),
                format!("https://127.0.0.1:8899{query}"),
            );

        let body = body.into();
        if !body.is_empty() {
            request = request.body(body);
        }

        let mut request_headers = HeaderMap::new();
        for (key, value) in headers {
            request_headers.insert(key, value.parse().unwrap());
        }
        request_headers.insert(AUTHORIZATION, self.credentials.parse().unwrap());

        let response = request.headers(request_headers).send().await.unwrap();
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string().to_lowercase(),
                    v.to_str().unwrap().to_string(),
                )
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map(|bytes| String::from_utf8(bytes.to_vec()).unwrap())
            .map_err(|err| err.to_string());
        let xml = match &body {
            Ok(body) if body.starts_with("<?xml") => flatten_xml(body),
            _ => vec![],
        };

        DavResponse {
            headers,
            status,
            body,
            xml,
        }
    }

    pub async fn available_quota(&self, path: &str) -> u64 {
        self.propfind(
            path,
            [DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes)],
        )
        .await
        .properties(path)
        .get(DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes))
        .value()
        .parse()
        .unwrap()
    }

    pub async fn create_hierarchy(
        &self,
        base_path: &str,
        max_depth: usize,
        containers_per_level: usize,
        files_per_container: usize,
    ) -> (String, Vec<(String, String)>) {
        let resource_type = if base_path.starts_with("/dav/card/") {
            DavResourceName::Card
        } else if base_path.starts_with("/dav/cal/") {
            DavResourceName::Cal
        } else {
            DavResourceName::File
        };

        let mut created_resources = Vec::new();

        self.create_hierarchy_recursive(
            resource_type,
            base_path,
            max_depth,
            containers_per_level,
            files_per_container,
            0,
            &mut created_resources,
        )
        .await;

        let root_folder = created_resources.first().unwrap().0.clone();
        created_resources.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        (root_folder, created_resources)
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_hierarchy_recursive(
        &self,
        resource_type: DavResourceName,
        base_path: &str,
        max_depth: usize,
        containers_per_level: usize,
        files_per_container: usize,
        current_depth: usize,
        created_resources: &mut Vec<(String, String)>,
    ) {
        let folder_name = generate_random_name(4);
        let folder_path = format!("{base_path}/Folder_{folder_name}");

        self.mkcol("MKCOL", &folder_path, [], [])
            .await
            .with_status(StatusCode::CREATED);

        created_resources.push((format!("{folder_path}/"), "".to_string()));

        for _ in 0..files_per_container {
            let file_name = generate_random_name(8);
            let file_path = format!(
                "{folder_path}/{file_name}.{}",
                match resource_type {
                    DavResourceName::Card => "vcf",
                    DavResourceName::Cal => "ics",
                    DavResourceName::File => "txt",
                    _ => unreachable!(),
                }
            );
            let content = match resource_type {
                DavResourceName::Card => generate_random_vcard(),
                DavResourceName::Cal => generate_random_ical(),
                DavResourceName::File => generate_random_content(100, 500),
                _ => unreachable!(),
            };

            self.request("PUT", &file_path, &content)
                .await
                .with_status(StatusCode::CREATED);

            created_resources.push((file_path, content));
        }

        if current_depth < max_depth {
            for _ in 0..containers_per_level {
                Box::pin(self.create_hierarchy_recursive(
                    resource_type,
                    &folder_path,
                    max_depth,
                    containers_per_level,
                    files_per_container,
                    current_depth + 1,
                    created_resources,
                ))
                .await;
            }
        }
    }

    pub async fn validate_values(&self, items: &[(String, String)]) {
        for (path, value) in items {
            if !path.ends_with('/') {
                self.request("GET", path, "")
                    .await
                    .with_status(StatusCode::OK)
                    .with_body(value);
            }
        }
    }

    pub async fn delete_default_containers(&self) {
        self.delete_default_containers_by_account(self.name).await;
    }

    pub async fn delete_default_containers_by_account(&self, account: &str) {
        for col in ["card", "cal"] {
            self.request("DELETE", &format!("/dav/{col}/{account}/default"), "")
                .await
                .with_status(StatusCode::NO_CONTENT);
        }
    }
}

impl DavResponse {
    pub fn with_status(self, status: StatusCode) -> Self {
        if self.status != status {
            self.dump_response();
            panic!("Expected {status} but got {}", self.status)
        }
        self
    }

    pub fn with_redirect_to(self, url: &str) -> Self {
        self.with_status(StatusCode::TEMPORARY_REDIRECT)
            .with_header("location", url)
    }

    pub fn with_header(self, header: &str, value: &str) -> Self {
        if self.headers.get(header).is_some_and(|v| v == value) {
            self
        } else {
            self.dump_response();
            panic!("Header {header}:{value} not found.")
        }
    }

    pub fn with_body(self, expect_body: impl AsRef<str>) -> Self {
        let expect_body = expect_body.as_ref();
        if self.body.is_ok() {
            let body = self.body.as_ref().unwrap();
            if body != expect_body {
                self.dump_response();
                assert_eq!(body, &expect_body);
            }
            self
        } else {
            self.dump_response();
            panic!("Expected body {expect_body:?} but no body was returned.")
        }
    }

    pub fn with_empty_body(self) -> Self {
        if self.body.is_ok() {
            let body = self.body.as_ref().unwrap();
            if !body.is_empty() {
                self.dump_response();
                panic!("Expected empty body but got {body:?}");
            }
            self
        } else {
            self.dump_response();
            panic!("Expected empty body but no body was returned.")
        }
    }

    pub fn expect_body(&self) -> &str {
        if self.body.is_ok() {
            self.body.as_ref().unwrap()
        } else {
            self.dump_response();
            panic!("Expected body but no body was returned.")
        }
    }

    pub fn header(&self, header: &str) -> &str {
        if let Some(value) = self.headers.get(header) {
            value
        } else {
            self.dump_response();
            panic!("Header {header} not found.")
        }
    }

    pub fn etag(&self) -> &str {
        self.header("etag")
    }

    pub fn sync_token(&self) -> &str {
        self.find_keys("D:multistatus.D:sync-token")
            .next()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                self.dump_response();
                panic!("Sync token not found.")
            })
    }

    pub fn hrefs(&self) -> Vec<&str> {
        let mut hrefs = self
            .find_keys("D:multistatus.D:response.D:href")
            .collect::<Vec<_>>();
        hrefs.sort_unstable();
        hrefs
    }

    pub fn with_href_count(self, count: usize) -> Self {
        let href_count = self.find_keys("D:multistatus.D:response.D:href").count();
        if href_count != count {
            self.dump_response();
            panic!("Expected {} hrefs but got {}", count, href_count);
        }
        self
    }

    pub fn with_hrefs<'x>(self, hrefs: impl IntoIterator<Item = &'x str>) -> Self {
        let expected_hrefs = hrefs.into_iter().collect::<AHashSet<_>>();
        let hrefs = self
            .find_keys("D:multistatus.D:response.D:href")
            .collect::<AHashSet<_>>();
        if expected_hrefs != hrefs {
            self.dump_response();

            println!("\nMissing: {:?}", expected_hrefs.difference(&hrefs));
            println!("\nExtra: {:?}", hrefs.difference(&expected_hrefs));

            panic!(
                "Hierarchy mismatch: expected {} items, received {} items",
                expected_hrefs.len(),
                hrefs.len()
            );
        }
        self
    }

    fn dump_response(&self) {
        eprintln!("-------------------------------------");
        eprintln!("Status: {}", self.status);
        eprintln!("Headers:");
        for (key, value) in self.headers.iter() {
            eprintln!("  {}: {:?}", key, value);
        }
        if !self.xml.is_empty() {
            eprintln!("XML: {}", xml_pretty_print(self.body.as_ref().unwrap()));

            for (key, value) in self.xml.iter() {
                eprintln!("{} -> {:?}", key, value);
            }
        } else {
            eprintln!("Body: {:?}", self.body);
        }
    }

    fn find_keys(&self, name: &str) -> impl Iterator<Item = &str> {
        self.xml
            .iter()
            .filter(move |(key, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    pub fn value(&self, name: &str) -> &str {
        self.find_keys(name).next().unwrap_or_else(|| {
            self.dump_response();
            panic!("Key {name} not found.")
        })
    }

    // Poor man's XPath
    pub fn with_value(self, query: &str, expect: impl AsRef<str>) -> Self {
        let expect = expect.as_ref();
        if let Some(value) = self.find_keys(query).next() {
            if value != expect {
                self.dump_response();
                panic!("Expected {query} = {expect:?} but got {value:?}");
            }
        } else {
            self.dump_response();
            panic!("Key {query} not found.");
        }
        self
    }

    pub fn with_any_value<'x>(
        self,
        query: &str,
        expect: impl IntoIterator<Item = &'x str>,
    ) -> Self {
        let expect = expect.into_iter().collect::<AHashSet<_>>();
        if let Some(value) = self.find_keys(query).next() {
            if !expect.contains(value) {
                self.dump_response();
                panic!("Expected {query} = {expect:?} but got {value:?}");
            }
        } else {
            self.dump_response();
            panic!("Key {query} not found.");
        }
        self
    }

    pub fn with_values<I, T>(self, query: &str, expect: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let expect_owned: Vec<T> = expect.into_iter().collect();
        let expect = expect_owned.iter().map(|s| s.as_ref()).collect::<Vec<_>>();
        let found = self.find_keys(query).collect::<Vec<_>>();
        if expect != found {
            self.dump_response();
            panic!("Expected {query} = {expect:?} but got {found:?}");
        }
        self
    }

    pub fn with_failed_precondition(self, precondition: &str, value: &str) -> Self {
        let error = format!("D:error.{precondition}");
        if self.find_keys(&error).next().is_none_or(|v| v != value) {
            self.dump_response();
            panic!("Precondition {precondition} did not match.");
        }
        self
    }
}

pub trait DavResourcesTest {
    fn items(&self) -> Vec<DavResource>;
}

impl DavResourcesTest for DavResources {
    fn items(&self) -> Vec<DavResource> {
        self.resources.clone()
    }
}

fn flatten_xml(xml: &str) -> Vec<(String, String)> {
    let mut reader = Reader::from_str(xml);

    let mut path: Vec<String> = Vec::new();
    let mut result: Vec<(String, String)> = Vec::new();
    let mut buf = Vec::new();
    let mut text_content: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf).unwrap() {
            Event::Start(ref e) => {
                let name = str::from_utf8(e.name().as_ref()).unwrap().to_string();
                path.push(name);
                let base_path = path.join(".");
                for attr in e.attributes() {
                    let attr = attr.unwrap();
                    let key = str::from_utf8(attr.key.as_ref()).unwrap().to_string();
                    let value = attr.unescape_value().unwrap();
                    let value_str = value.trim().to_string();

                    result.push((format!("{}.[{}]", base_path, key), value_str));
                }
                text_content = None;
            }
            Event::Empty(ref e) => {
                let name = str::from_utf8(e.name().as_ref()).unwrap().to_string();
                let base_path = format!("{}.{}", path.join("."), name);
                let mut has_attrs = false;

                for attr in e.attributes() {
                    let attr = attr.unwrap();
                    let key = str::from_utf8(attr.key.as_ref()).unwrap().to_string();
                    let value = attr.unescape_value().unwrap();
                    let value_str = value.trim().to_string();
                    has_attrs = true;
                    result.push((format!("{}.[{}]", base_path, key), value_str));
                }

                if !has_attrs {
                    result.push((base_path, "".to_string()));
                }
            }
            Event::Text(e) => {
                let text = e.xml_content().unwrap();
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    if let Some(text_content) = text_content.as_mut() {
                        text_content.push_str(trimmed);
                    } else {
                        text_content = Some(trimmed.to_string());
                    }
                }
            }
            Event::GeneralRef(entity) => {
                let value: Cow<str> = match entity.as_ref() {
                    b"lt" => "<".into(),
                    b"gt" => ">".into(),
                    b"amp" => "&".into(),
                    b"apos" => "'".into(),
                    b"quot" => "\"".into(),
                    _ => {
                        if let Ok(Some(gr)) = entity.resolve_char_ref() {
                            gr.to_string().into()
                        } else {
                            std::str::from_utf8(entity.as_ref())
                                .unwrap_or_default()
                                .into()
                        }
                    }
                };

                if let Some(text_content) = text_content.as_mut() {
                    text_content.push_str(value.as_ref());
                } else {
                    text_content = Some(value.into_owned());
                }
            }
            Event::CData(e) => {
                text_content = Some(std::str::from_utf8(e.as_ref()).unwrap().to_string());
            }
            Event::End(_) => {
                if let Some(text) = text_content.take() {
                    result.push((path.join("."), text));
                }

                if !path.is_empty() {
                    path.pop();
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    result
}

pub const TEST_VCARD_1: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:18F098B5-7383-4FD6-B482-48F2181D73AA
X-TEST:SEQ1
N:Coyote;Wile;E.;;
FN:Wile E. Coyote
ORG:ACME Inc.;
END:VCARD
"#;

pub const TEST_VCARD_2: &str = r#"BEGIN:VCARD
VERSION:4.0
UID:6exhjr32bt783wwlr9u0sr8lfqse5x7zqc8y
X-TEST:SEQ1
FN:Joe Citizen
N:Citizen;Joe;;;
NICKNAME:human_being
EMAIL;TYPE=pref:jcitizen@foo.com
REV:20200411T072429Z
END:VCARD
"#;

pub const TEST_ICAL_1: &str = r#"BEGIN:VCALENDAR
SOURCE;VALUE=URI:http://calendar.example.com/event_with_html.ics
X-TEST:SEQ1
BEGIN:VEVENT
UID: 2371c2d9-a136-43b0-bba3-f6ab249ad46e
SUMMARY:What a nice present: 🎁
DTSTART;TZID=America/New_York:20190221T170000
DTEND;TZID=America/New_York:20190221T180000
LOCATION:Germany
DESCRIPTION:<html><body><h1>Title</h1><p><ul><li><b>first</b> Row </li><li><
 i>second</i> Row</li></ul></p></body></html>
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_ICAL_2: &str = r#"BEGIN:VCALENDAR
X-TEST:SEQ1
BEGIN:VEVENT
UID:0000001
SUMMARY:Treasure Hunting
DTSTART;TZID=America/Los_Angeles:20150706T120000
DTEND;TZID=America/Los_Angeles:20150706T130000
RRULE:FREQ=DAILY;COUNT=10
EXDATE;TZID=America/Los_Angeles:20150708T120000
EXDATE;TZID=America/Los_Angeles:20150710T120000
END:VEVENT
BEGIN:VEVENT
UID:0000001
SUMMARY:More Treasure Hunting
LOCATION:The other island
DTSTART;TZID=America/Los_Angeles:20150709T150000
DTEND;TZID=America/Los_Angeles:20150707T160000
RECURRENCE-ID;TZID=America/Los_Angeles:20150707T120000
END:VEVENT
END:VCALENDAR
"#;

pub const TEST_FILE_1: &str = r#"this is a test file
with some text
and some more text

X-TEST:SEQ1
"#;

pub const TEST_FILE_2: &str = r#"another test file
with amazing content
and some more text

X-TEST:SEQ1
"#;

pub const TEST_VTIMEZONE_1: &str = r#"BEGIN:VCALENDAR
PRODID:-//Example Corp.//CalDAV Client//EN
VERSION:2.0
BEGIN:VTIMEZONE
TZID:US-Eastern
LAST-MODIFIED:19870101T000000Z
BEGIN:STANDARD
DTSTART:19671029T020000
RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
TZNAME:Eastern Standard Time (US Canada)
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19870405T020000
RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
TZNAME:Eastern Daylight Time (US Canada)
END:DAYLIGHT
END:VTIMEZONE
END:VCALENDAR
"#;

pub trait GenerateTestDavResource {
    fn generate(&self) -> String;
}

impl GenerateTestDavResource for DavResourceName {
    fn generate(&self) -> String {
        match self {
            DavResourceName::Card => generate_random_vcard(),
            DavResourceName::Cal => generate_random_ical(),
            DavResourceName::File => generate_random_content(100, 200),
            _ => unreachable!(),
        }
    }
}

fn generate_random_vcard() -> String {
    r#"BEGIN:VCARD
VERSION:4.0
UID:$UID
FN:$NAME
END:VCARD
"#
    .replace("$UID", &generate_random_name(8))
    .replace("$NAME", &generate_random_name(10))
    .replace('\n', "\r\n")
}

fn generate_random_ical() -> String {
    r#"BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:$UID
SUMMARY:$SUMMARY
DESCRIPTION:$DESCRIPTION
END:VEVENT
END:VCALENDAR
"#
    .replace("$UID", &generate_random_name(8))
    .replace("$SUMMARY", &generate_random_name(10))
    .replace("$DESCRIPTION", &generate_random_name(20))
    .replace('\n', "\r\n")
}

fn generate_random_content(min_chars: usize, max_chars: usize) -> String {
    let mut rng = rng();
    let length = rng.random_range(min_chars..=max_chars);

    let words = [
        "lorem",
        "ipsum",
        "dolor",
        "sit",
        "amet",
        "consectetur",
        "adipiscing",
        "elit",
        "sed",
        "do",
        "eiusmod",
        "tempor",
        "incididunt",
        "ut",
        "labore",
        "et",
        "dolore",
        "magna",
        "aliqua",
        "ut",
        "enim",
        "ad",
        "minim",
        "veniam",
        "quis",
        "nostrud",
        "exercitation",
        "ullamco",
        "laboris",
        "nisi",
        "ut",
        "aliquip",
        "ex",
        "ea",
        "commodo",
        "consequat",
    ];

    let mut content = String::with_capacity(length);

    while content.len() < length {
        let word_idx = rng.random_range(0..words.len());
        if !content.is_empty() {
            content.push(' ');
        }
        if rng.random_ratio(1, 10) {
            content.push('.');
            let word = words[word_idx];
            let mut chars = word.chars();
            if let Some(first_char) = chars.next() {
                content.push_str(&first_char.to_uppercase().to_string());
                content.push_str(chars.as_str());
            }
        } else {
            content.push_str(words[word_idx]);
        }
    }

    if !content.ends_with('.') {
        content.push('.');
    }

    content
}

fn generate_random_name(length: usize) -> String {
    let mut rng = rng();
    (0..length)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

impl WebDavTest {
    pub async fn fetch_email(&self, account_id: u32, document_id: u32) -> Vec<u8> {
        let metadata_ = self
            .server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata,
            ))
            .await
            .unwrap()
            .unwrap();
        self.server
            .blob_store()
            .get_blob(
                metadata_
                    .unarchive::<MessageMetadata>()
                    .unwrap()
                    .blob_hash
                    .0
                    .as_slice(),
                0..usize::MAX,
            )
            .await
            .unwrap()
            .unwrap()
    }
}

const SERVER: &str = r#"
[server]
hostname = "webdav.example.org"

[spam-filter]
enable = false

[http]
url = "'https://127.0.0.1:8899'"

[server.listener.webdav]
bind = ["127.0.0.1:8899"]
protocol = "http"
max-connections = 81920
tls.implicit = true

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = "default"

[session.ehlo]
reject-non-fqdn = false

[session.rcpt]
relay = [ { if = "!is_empty(authenticated_as)", then = true }, 
        { else = false } ]

[session.rcpt.errors]
total = 5
wait = "1ms"

[resolver]
type = "system"

[queue.strategy]
route = [ { if = "rcpt_domain == 'example.com'", then = "'local'" }, 
            { else = "'mx'" } ]

[session.data.add-headers]
delivered-to = false

[session.extensions]
future-release = [ { if = "!is_empty(authenticated_as)", then = "99999999d"},
                { else = false } ]

[certificate.default]
cert = "%{file:{CERT}}%"
private-key = "%{file:{PK}}%"

[jmap.protocol]
set.max-objects = 100000

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
authentication = "100/2s"
anonymous = "100/1m"

[calendar.alarms]
minimum-interval = "1s"

[calendar.scheduling.inbound]
auto-add = true

[dav.collection]
assisted-discovery = {ASSISTED_DISCOVERY}

[sharing]
allow-directory-query = true

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

[oauth]
key = "parerga_und_paralipomena"

[oauth.auth]
max-attempts = 1

[oauth.expiry]
user-code = "1s"
token = "1s"
refresh-token = "3s"
refresh-token-renew = "2s"

[tracer.console]
type = "console"
level = "{LEVEL}"
multiline = false
ansi = true
disabled-events = ["network.*"]
 
"#;
