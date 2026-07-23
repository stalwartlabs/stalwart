/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use base64::{Engine, engine::general_purpose::STANDARD};
use dav_proto::{
    Depth,
    schema::property::{CalDavProperty, DavProperty, WebDavProperty},
    xml_pretty_print,
};
use groupware::DavResourceName;
use hyper::{HeaderMap, Method, StatusCode, header::AUTHORIZATION};
use quick_xml::{Reader, XmlVersion, events::Event};
use std::{borrow::Cow, time::Duration};
use store::rand::{Rng, distr::Alphanumeric, rng};

#[allow(dead_code)]
#[derive(Debug)]
pub struct DummyWebDavClient {
    pub account_id: u32,
    pub name: &'static str,
    pub email: &'static str,
    pub credentials: String,
}

#[derive(Debug)]
pub struct DavResponse {
    pub headers: AHashMap<String, String>,
    pub status: StatusCode,
    pub body: Result<String, String>,
    pub xml: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct DavMultiStatus {
    pub response: DavResponse,
    pub hrefs: AHashMap<String, DavProperties>,
}

#[derive(Debug, serde::Serialize)]
pub struct DavItem {
    #[serde(serialize_with = "serialize_status_code")]
    pub status: StatusCode,
    pub values: AHashMap<String, Vec<String>>,
    pub error: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct DavProperties {
    #[serde(skip)]
    status: StatusCode,
    props: Vec<DavItem>,
}

pub struct DavPropertyResult<'x> {
    pub response: &'x DavResponse,
    pub properties: &'x DavProperties,
}

pub struct DavQueryResult<'x> {
    pub response: &'x DavResponse,
    pub prop: &'x DavItem,
    pub values: &'x [String],
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
        self.request_with_headers(method, query, [], body).await
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

    pub async fn lock_create(
        &self,
        path: &str,
        owner: &str,
        is_exclusive: bool,
        depth: &str,
        timeout: &str,
    ) -> DavResponse {
        let lock_request = LOCK_REQUEST
            .replace("$TYPE", if is_exclusive { "exclusive" } else { "shared" })
            .replace("$OWNER", owner);
        self.request_with_headers(
            "LOCK",
            path,
            [("depth", depth), ("timeout", timeout)],
            &lock_request,
        )
        .await
    }

    pub async fn lock_refresh(
        &self,
        path: &str,
        lock_token: &str,
        depth: &str,
        timeout: &str,
    ) -> DavResponse {
        let condition = format!("(<{lock_token}>)");
        self.request_with_headers(
            "LOCK",
            path,
            [
                ("if", condition.as_str()),
                ("depth", depth),
                ("timeout", timeout),
            ],
            "",
        )
        .await
    }

    pub async fn unlock(&self, path: &str, lock_token: &str) -> DavResponse {
        let condition = format!("<{lock_token}>");
        self.request_with_headers("UNLOCK", path, [("lock-token", condition.as_str())], "")
            .await
    }

    pub async fn mkcol(
        &self,
        method: &str,
        path: &str,
        resource_types: impl IntoIterator<Item = &str>,
        properties: impl IntoIterator<Item = (&str, &str)>,
    ) -> DavResponse {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:mkcol xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" xmlns:B=\"urn:ietf:params:xml:ns:carddav\">",
            "<D:set><D:prop>"
        )
        .to_string();

        let mut has_resource_type = false;
        for (idx, resource_type) in resource_types.into_iter().enumerate() {
            if idx == 0 {
                request.push_str("<D:resourcetype>");
            }
            request.push_str(&format!("<{resource_type}/>"));
            has_resource_type = true;
        }

        if has_resource_type {
            request.push_str("</D:resourcetype>");
        }

        for (key, value) in properties {
            request.push_str(&format!("<{key}>{value}</{key}>"));
        }
        request.push_str("</D:prop></D:set></D:mkcol>");

        if method == "MKCALENDAR" {
            request = request.replace("D:mkcol", "A:mkcalendar");
        }

        self.request(method, path, &request).await
    }

    pub async fn patch_and_check<T>(
        &self,
        path: &str,
        properties: impl IntoIterator<Item = (T, &str)>,
    ) where
        T: AsRef<str> + Clone,
    {
        let mut expect_set = Vec::new();
        let mut expect_remove = Vec::new();

        for (key, value) in properties {
            if !value.is_empty() {
                expect_set.push((key, value));
            } else {
                expect_remove.push(key);
            }
        }

        let response = self
            .proppatch(
                path,
                expect_set.iter().cloned(),
                expect_remove.iter().cloned(),
                [],
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None);
        let patch_prop = response.properties(path);
        for (key, _) in &expect_set {
            patch_prop.get(key.as_ref()).with_status(StatusCode::OK);
        }
        for key in &expect_remove {
            patch_prop
                .get(key.as_ref())
                .with_status(StatusCode::NO_CONTENT);
        }

        let response = self
            .propfind(
                path,
                expect_set
                    .iter()
                    .map(|(k, _)| k)
                    .chain(expect_remove.iter()),
            )
            .await;
        let prop = response.properties(path);

        for (key, value) in expect_set {
            prop.get(key.as_ref())
                .with_values([value])
                .with_status(StatusCode::OK);
        }

        for key in expect_remove {
            prop.get(key.as_ref()).with_status(StatusCode::NOT_FOUND);
        }
    }

    pub async fn propfind<I, T>(&self, path: &str, properties: I) -> DavMultiStatus
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        self.propfind_with_headers(path, properties, []).await
    }

    pub async fn propfind_with_headers<I, T>(
        &self,
        path: &str,
        properties: I,
        headers: impl IntoIterator<Item = (&'static str, &str)>,
    ) -> DavMultiStatus
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:propfind xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" ",
            "xmlns:B=\"urn:ietf:params:xml:ns:carddav\" xmlns:C=\"http://calendarserver.org/ns/\">",
            "<D:prop>"
        )
        .to_string();

        for property in properties {
            request.push_str(&format!("<{}/>", property.as_ref()));
        }

        request.push_str("</D:prop></D:propfind>");

        self.request_with_headers("PROPFIND", path, headers, &request)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None)
    }

    pub async fn proppatch<T>(
        &self,
        path: &str,
        set: impl IntoIterator<Item = (T, &str)>,
        clear: impl IntoIterator<Item = T>,
        headers: impl IntoIterator<Item = (&'static str, &str)>,
    ) -> DavResponse
    where
        T: AsRef<str>,
    {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" ",
            "xmlns:B=\"urn:ietf:params:xml:ns:carddav\" xmlns:C=\"http://calendarserver.org/ns/\">",
            "<D:remove><D:prop>"
        )
        .to_string();

        for property in clear {
            request.push_str(&format!("<{}/>", property.as_ref()));
        }

        request.push_str("</D:prop></D:remove><D:set><D:prop>");

        for (key, value) in set {
            let key = key.as_ref();
            request.push_str(&format!("<{key}>{value}</{key}>"));
        }

        request.push_str("</D:prop></D:set></D:propertyupdate>");

        self.request_with_headers("PROPPATCH", path, headers, &request)
            .await
    }

    pub async fn multiget_calendar(&self, path: &str, uris: &[&str]) -> DavMultiStatus {
        let mut paths = String::new();
        for uri in uris {
            paths.push_str(&format!("<D:href>{}</D:href>", uri));
        }

        self.request("REPORT", path, &MULTIGET_CALENDAR.replace("$PATH", &paths))
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None)
    }

    pub async fn multiget_addressbook(&self, path: &str, uris: &[&str]) -> DavMultiStatus {
        let mut paths = String::new();
        for uri in uris {
            paths.push_str(&format!("<D:href>{}</D:href>", uri));
        }

        self.request(
            "REPORT",
            path,
            &MULTIGET_ADDRESSBOOK.replace("$PATH", &paths),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .into_propfind_response(None)
    }

    pub async fn sync_collection(
        &self,
        path: &str,
        sync_token: &str,
        depth: Depth,
        limit: Option<usize>,
        properties: impl IntoIterator<Item = &str>,
    ) -> DavResponse {
        let mut request = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
            "<D:sync-collection xmlns:D=\"DAV:\" xmlns:A=\"urn:ietf:params:xml:ns:caldav\" xmlns:B=\"urn:ietf:params:xml:ns:carddav\">",
            "<D:prop>"
        )
        .to_string();

        for property in properties {
            request.push_str(&format!("<{property}/>"));
        }

        request.push_str("</D:prop><D:sync-token>");
        request.push_str(sync_token);
        request.push_str("</D:sync-token><D:sync-level>");
        request.push_str(match depth {
            Depth::One => "1",
            Depth::Infinity => "infinite",
            _ => "0",
        });
        request.push_str("</D:sync-level>");

        if let Some(limit) = limit {
            request.push_str("<D:limit><D:nresults>");
            request.push_str(&limit.to_string());
            request.push_str("</D:nresults></D:limit>");
        }

        request.push_str("</D:sync-collection>");

        self.request("REPORT", path, &request)
            .await
            .with_status(StatusCode::MULTI_STATUS)
    }

    pub async fn acl<'x>(
        &self,
        query: &str,
        principal_href: &str,
        grant: impl IntoIterator<Item = &'x str>,
    ) -> DavResponse {
        let body = ACL_QUERY.replace("$HREF", principal_href).replace(
            "$GRANT",
            &grant.into_iter().fold(String::new(), |mut output, g| {
                use std::fmt::Write;
                let _ = write!(output, "<D:privilege><D:{g}/></D:privilege>");
                output
            }),
        );
        self.request("ACL", query, &body).await
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
        if let Ok(body) = &self.body {
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
        if let Ok(body) = &self.body {
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
        if let Ok(body) = &self.body {
            body
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

    pub fn lock_token(&self) -> &str {
        self.value("D:prop.D:lockdiscovery.D:activelock.D:locktoken.D:href")
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

    pub fn into_propfind_response(mut self, prop_prefix: Option<&str>) -> DavMultiStatus {
        if let Some(prop_prefix) = prop_prefix {
            for (key, _) in self.xml.iter_mut() {
                if let Some(suffix) = key.strip_prefix(prop_prefix) {
                    *key = format!("D:multistatus.D:response{suffix}");
                }
            }
            self.xml.push((
                "D:multistatus.D:response.D:href".to_string(),
                "".to_string(),
            ));
        }

        let mut result = DavMultiStatus {
            response: self,
            hrefs: AHashMap::new(),
        };
        let mut href = None;
        let mut href_status = StatusCode::OK;
        let mut props = Vec::new();
        let mut prop = DavItem::default();

        for (key, value) in &result.response.xml {
            match key.as_str() {
                "D:multistatus.D:response.D:href" => {
                    if let Some(href) = href.take() {
                        if !prop.is_empty() {
                            props.push(std::mem::take(&mut prop));
                        }
                        result.hrefs.insert(
                            href,
                            DavProperties {
                                status: href_status,
                                props: std::mem::take(&mut props),
                            },
                        );
                        href_status = StatusCode::OK;
                    }
                    href = Some(value.to_string());
                }
                "D:multistatus.D:response.D:status" => {
                    href_status = value
                        .split_ascii_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .parse()
                        .unwrap();
                }
                "D:multistatus.D:response.D:propstat.D:status" => {
                    prop.status = value
                        .split_ascii_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .parse()
                        .unwrap();
                }
                "D:multistatus.D:response.D:propstat.D:responsedescription" => {
                    prop.description = Some(value.to_string());
                }
                _ => {
                    if let Some(prop_name) =
                        key.strip_prefix("D:multistatus.D:response.D:propstat.D:prop.")
                    {
                        if prop.status != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                            props.push(std::mem::take(&mut prop));
                        }

                        let (prop_name, prop_value) =
                            if let Some((prop_name, prop_sub_name)) = prop_name.split_once('.') {
                                if value.is_empty() {
                                    (prop_name, prop_sub_name.to_string())
                                } else {
                                    (prop_name, format!("{}:{}", prop_sub_name, value))
                                }
                            } else {
                                (prop_name, value.to_string())
                            };
                        prop.values
                            .entry(prop_name.to_string())
                            .or_default()
                            .push(prop_value);
                    }
                }
            }
        }

        if let Some(href) = href.take() {
            if !prop.is_empty() {
                props.push(prop);
            }
            result.hrefs.insert(
                href,
                DavProperties {
                    status: href_status,
                    props,
                },
            );
        }

        result
    }
}

impl DavPropertyResult<'_> {
    pub fn get(&self, name: impl AsRef<str>) -> DavQueryResult<'_> {
        let name = name.as_ref();
        self.properties
            .props
            .iter()
            .find_map(|prop| {
                prop.values.get(name).map(|values| DavQueryResult {
                    response: self.response,
                    prop,
                    values,
                })
            })
            .unwrap_or_else(|| {
                self.response.dump_response();
                panic!(
                    "No property found for name: {name} in {}",
                    serde_json::to_string_pretty(&self.properties.props).unwrap()
                )
            })
    }

    pub fn with_status(&self, status: StatusCode) -> &Self {
        if self.properties.status != status {
            self.response.dump_response();
            panic!(
                "Expected status {status}, but got {}",
                self.properties.status
            );
        }
        self
    }

    pub fn is_defined(&self, name: impl AsRef<str>) -> &Self {
        if self
            .properties
            .props
            .iter()
            .any(|prop| prop.values.contains_key(name.as_ref()))
        {
            self
        } else {
            self.response.dump_response();
            panic!("Expected property {} to be defined", name.as_ref());
        }
    }

    pub fn is_undefined(&self, name: impl AsRef<str>) -> &Self {
        if self
            .properties
            .props
            .iter()
            .any(|prop| prop.values.contains_key(name.as_ref()))
        {
            self.response.dump_response();
            panic!("Expected property {} to be undefined", name.as_ref());
        }
        self
    }

    pub fn calendar_data(&self) -> DavQueryResult<'_> {
        self.get(DavProperty::CalDav(CalDavProperty::CalendarData(
            Default::default(),
        )))
    }
}

impl<'x> DavQueryResult<'x> {
    pub fn with_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let expected_values = AHashSet::from_iter(expected_values);
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();

        if values != expected_values {
            self.response.dump_response();
            assert_eq!(values, expected_values,);
        }
        self
    }

    pub fn with_some_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();

        for expected_value in expected_values {
            if !values.contains(expected_value) {
                self.response.dump_response();
                panic!("Expected at least one of {expected_value:?} values, but got {values:?}",);
            }
        }

        self
    }

    pub fn with_any_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();
        let expected_values = AHashSet::from_iter(expected_values);

        if values.is_disjoint(&expected_values) {
            self.response.dump_response();
            panic!("Expected at least one of {expected_values:?} values, but got {values:?}",);
        }

        self
    }

    pub fn without_values(&self, expected_values: impl IntoIterator<Item = &'x str>) -> &Self {
        let expected_values = AHashSet::from_iter(expected_values);
        let values = self
            .values
            .iter()
            .map(|s| s.as_str())
            .collect::<AHashSet<_>>();

        if !expected_values.is_disjoint(&values) {
            self.response.dump_response();
            panic!("Expected no {expected_values:?} values, but got {values:?}",);
        }
        self
    }

    pub fn is_not_empty(&self) -> &Self {
        if self.values.is_empty() || self.values.iter().all(|s| s.is_empty()) {
            self.response.dump_response();
            panic!("Expected non-empty values, but got {:?}", self.values);
        }
        self
    }

    pub fn value(&self) -> &str {
        if let Some(value) = self.values.iter().find(|s| !s.is_empty()) {
            value
        } else {
            self.response.dump_response();
            panic!("Expected a value, but got {:?}", self.values);
        }
    }

    pub fn with_status(&self, status: StatusCode) -> &Self {
        if self.prop.status != status {
            self.response.dump_response();
            panic!("Expected status {status}, but got {}", self.prop.status);
        }
        self
    }

    pub fn with_description(&self, description: &str) -> &Self {
        if self.prop.description.as_deref() != Some(description) {
            self.response.dump_response();
            panic!(
                "Expected description {description}, but got {:?}",
                self.prop.description
            );
        }
        self
    }
    pub fn with_error(&self, error: &str) -> &Self {
        if !self.prop.error.contains(&error.to_string()) {
            self.response.dump_response();
            panic!("Expected error {error}, but got {:?}", self.prop.error);
        }
        self
    }
}

impl DavMultiStatus {
    pub fn properties(&self, href: &str) -> DavPropertyResult<'_> {
        DavPropertyResult {
            response: &self.response,
            properties: self.hrefs.get(href).unwrap_or_else(|| {
                self.response.dump_response();
                panic!(
                    "No properties found for href: {href} in {}",
                    serde_json::to_string_pretty(&self.hrefs).unwrap()
                )
            }),
        }
    }

    pub fn with_hrefs<'x>(&self, expect_hrefs: impl IntoIterator<Item = &'x str>) -> &Self {
        let expect_hrefs: AHashSet<_> = expect_hrefs.into_iter().collect();
        let hrefs: AHashSet<_> = self.hrefs.keys().map(|s| s.as_str()).collect();
        if hrefs != expect_hrefs {
            self.response.dump_response();
            panic!("Expected hrefs {expect_hrefs:?}, but got {hrefs:?}",);
        }
        self
    }
}

impl DavItem {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
            && self.status == StatusCode::PROXY_AUTHENTICATION_REQUIRED
            && self.error.is_empty()
            && self.description.is_none()
    }
}

impl Default for DavItem {
    fn default() -> Self {
        DavItem {
            status: StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            values: AHashMap::new(),
            error: Vec::new(),
            description: None,
        }
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
                    let value = attr.normalized_value(XmlVersion::Implicit1_0).unwrap();
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
                    let value = attr.normalized_value(XmlVersion::Implicit1_0).unwrap();
                    let value_str = value.trim().to_string();
                    has_attrs = true;
                    result.push((format!("{}.[{}]", base_path, key), value_str));
                }

                if !has_attrs {
                    result.push((base_path, "".to_string()));
                }
            }
            Event::Text(e) => {
                let text = e.xml_content(XmlVersion::Implicit1_0).unwrap();
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
                let entity_slice: &[u8] = entity.as_ref();
                let value: Cow<str> = match entity_slice {
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

fn serialize_status_code<S>(status_code: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&status_code.to_string())
}

const MULTIGET_CALENDAR: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop>
       <D:getetag/>
       <C:calendar-data/>
     </D:prop>
     $PATH
   </C:calendar-multiget>
"#;
const MULTIGET_ADDRESSBOOK: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-multiget xmlns:D="DAV:"
                        xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop>
       <D:getetag/>
       <C:address-data/>
     </D:prop>
     $PATH
   </C:addressbook-multiget>
"#;

const ACL_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl xmlns:D="DAV:">
     <D:ace>
       <D:principal>
         <D:href>$HREF</D:href>
       </D:principal>
       <D:grant>
         $GRANT
       </D:grant>
     </D:ace>
   </D:acl>"#;

const LOCK_REQUEST: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
     <D:lockinfo xmlns:D='DAV:'>
       <D:lockscope><D:$TYPE/></D:lockscope>
       <D:locktype><D:write/></D:locktype>
       <D:owner>
         <D:href>$OWNER</D:href>
       </D:owner>
     </D:lockinfo>"#;
