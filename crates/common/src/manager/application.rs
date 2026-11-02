/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Server,
    auth::oauth::client::{AppOriginPolicy, ApplicationClient},
    manager::{
        app_client::{
            APP_CLIENT_DOCUMENT, AppClientId, AppClientTemplate, app_base, normalize_url_prefix,
        },
        fetch_resource,
    },
};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use bytes::Bytes;
use compact_str::{CompactString, format_compact};
use registry::schema::{enums::CompressionAlgo, structs::Application};
use serde::Deserialize;
use std::{
    borrow::Cow,
    io::{self, Cursor, Read, Seek},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use store::{
    registry::{RegistryObject, bootstrap::Bootstrap},
    write::{BatchBuilder, BlobLink, BlobOp, blob::BlobLinkValue, now},
};
use trc::{AddContext, Key};
use types::{blob_hash::BlobHash, id::Id, semver::Semver};
use zip::{ZipArchive, result::ZipError};

const APP_BLOB_PREFIX: &str = "STALWART_APP_";
const MAX_APP_SIZE: usize = 100 * 1024 * 1024;
const INDEX_PAGE: &str = "index.html";
const BASE_HREF: &str = "<base href=\"/\"";
const OAUTH_CLIENT_ID: &str = "<meta name=\"oauth-client-id\" content=\"\"";
const OAUTH_SCOPES: &str = "<meta name=\"oauth-scopes\" content=\"\"";
const APP_MANIFEST: &str = "stalwart-app.json";
const MAX_APP_MANIFEST_SIZE: u64 = 4 * 1024;

#[derive(Deserialize)]
struct AppManifest<'x> {
    id: &'x str,
    version: &'x str,
    #[serde(rename = "minServerVersion")]
    min_server_version: Option<&'x str>,
}

enum IndexEdit<'x> {
    BaseHref(&'x str),
    Meta(&'x str),
}

#[derive(Default, Clone)]
struct IndexMeta {
    client_id: Option<String>,
    scopes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppClientDocument {
    NotShipped,
    Untrusted,
    Document(Vec<u8>),
}

#[allow(clippy::type_complexity)]
pub struct WebApplications {
    applications: ArcSwap<Vec<WebApplicationManager>>,
    routes: ArcSwap<AHashMap<String, Arc<AppRoutes>>>,
    generation: AtomicU64,
}

pub struct AppRoutes {
    resources: AHashMap<String, Resource<PathBuf>>,
    index_pages: AHashMap<String, Bytes>,
    oauth_client: Option<AppClientTemplate>,
    _bundle_dir: TempDir,
}

#[derive(Clone)]
pub struct WebApplicationManager {
    base_path: PathBuf,
    prefixes: Vec<String>,
    description: String,
    url: String,
    expiry: u64,
    blob_key: BlobHash,
    oauth_client_id: Option<String>,
    index_meta: IndexMeta,
}

#[derive(Default, Clone)]
pub struct Resource<T> {
    pub content_type: Cow<'static, str>,
    pub contents: T,
}

impl<T> Resource<T> {
    pub fn new(content_type: impl Into<Cow<'static, str>>, contents: T) -> Self {
        Self {
            content_type: content_type.into(),
            contents,
        }
    }
}

pub struct AppResource {
    pub resource: Resource<Bytes>,
    pub no_cache: bool,
}

impl WebApplications {
    pub fn new() -> Self {
        Self {
            applications: ArcSwap::new(Arc::new(Vec::new())),
            routes: ArcSwap::new(Arc::new(AHashMap::new())),
            generation: AtomicU64::new(0),
        }
    }

    pub fn has_prefix(&self, prefix: &str) -> bool {
        self.routes.load().contains_key(prefix)
    }

    pub fn is_first_party_client(
        &self,
        client_id: &str,
        policy: Option<AppOriginPolicy<'_>>,
    ) -> bool {
        if self
            .applications
            .load()
            .iter()
            .any(|app| app.oauth_client_id.as_deref() == Some(client_id))
        {
            return true;
        }
        let (Some(policy), Some(client_id)) = (policy, AppClientId::parse(client_id)) else {
            return false;
        };
        if !policy.accepts(client_id.is_tls, client_id.authority) {
            return false;
        }
        let routes = self.routes.load();

        #[cfg(feature = "dev_mode")]
        if client_id.prefix.is_empty() {
            return routes.values().any(|app| app.oauth_client.is_some());
        }

        routes
            .get(client_id.prefix)
            .is_some_and(|app| app.oauth_client.is_some())
    }

    pub fn recognize_client(
        &self,
        client_id: &str,
        policy: AppOriginPolicy<'_>,
    ) -> Option<ApplicationClient> {
        self.with_client_template(client_id, policy, |template, client_id| {
            template.client(&client_id.base())
        })
    }

    pub fn post_logout_redirect_uri_matches(
        &self,
        client_id: &str,
        policy: AppOriginPolicy<'_>,
        uri: &str,
    ) -> Option<bool> {
        self.with_client_template(client_id, policy, |template, client_id| {
            template.post_logout_redirect_uri_matches(client_id, uri)
        })
    }

    fn with_client_template<T>(
        &self,
        client_id: &str,
        policy: AppOriginPolicy<'_>,
        f: impl FnOnce(&AppClientTemplate, &AppClientId<'_>) -> T,
    ) -> Option<T> {
        let client_id = AppClientId::parse(client_id)?;
        if !policy.accepts(client_id.is_tls, client_id.authority) {
            return None;
        }
        let routes = self.routes.load();

        #[cfg(feature = "dev_mode")]
        if client_id.prefix.is_empty() {
            return routes
                .iter()
                .filter_map(|(prefix, app)| Some((prefix, app.oauth_client.as_ref()?)))
                .min_by_key(|(prefix, _)| prefix.as_str())
                .map(|(_, template)| f(template, &client_id));
        }

        routes
            .get(client_id.prefix)?
            .oauth_client
            .as_ref()
            .map(|template| f(template, &client_id))
    }

    pub fn client_document(
        &self,
        prefix: &str,
        is_tls: bool,
        authority: &str,
        policy: AppOriginPolicy<'_>,
    ) -> AppClientDocument {
        match self
            .routes
            .load()
            .get(prefix)
            .and_then(|routes| routes.oauth_client.as_ref())
        {
            Some(template) if policy.accepts(is_tls, authority) => {
                AppClientDocument::Document(template.document(&app_base(is_tls, authority, prefix)))
            }
            Some(_) => AppClientDocument::Untrusted,
            None => AppClientDocument::NotShipped,
        }
    }

    pub async fn serve(&self, prefix: &str, path: &str) -> trc::Result<Option<AppResource>> {
        if let Some(routes) = self.routes.load().get(prefix)
            && let Some((is_index, resource)) = routes
                .resources
                .get(path)
                .map(|res| (path == INDEX_PAGE, res))
                .or_else(|| routes.resources.get(INDEX_PAGE).map(|res| (true, res)))
        {
            if is_index && let Some(page) = routes.index_pages.get(prefix) {
                return Ok(Some(AppResource {
                    resource: Resource {
                        content_type: resource.content_type.clone(),
                        contents: page.clone(),
                    },
                    no_cache: true,
                }));
            }

            tokio::fs::read(&resource.contents)
                .await
                .map(|contents| {
                    Some(AppResource {
                        resource: Resource {
                            content_type: resource.content_type.clone(),
                            contents: contents.into(),
                        },
                        no_cache: is_index,
                    })
                })
                .map_err(|err| {
                    trc::ResourceEvent::Error
                        .reason(err)
                        .ctx(trc::Key::Path, CompactString::from(path))
                        .caused_by(trc::location!())
                })
        } else {
            Ok(None)
        }
    }

    pub async fn reload(&self, bp: &mut Bootstrap) {
        let mut apps = Vec::new();
        for app in bp.list_infallible::<Application>().await {
            if app.object.enable {
                apps.push(WebApplicationManager::new(app));
            }
        }
        self.applications.store(Arc::new(apps));
    }

    pub async fn unpack_all(&self, server: &Server, update: bool) {
        let previous = self.routes.load_full();
        let sweep_orphans = previous.is_empty();
        let mut routes = AHashMap::with_capacity(previous.len());

        for app in self.applications.load().as_ref() {
            match app
                .unpack(server, self.next_generation(), update, sweep_orphans)
                .await
            {
                Ok(app_routes) => {
                    let app_routes = Arc::new(app_routes);

                    for prefix in &app.prefixes {
                        routes.insert(prefix.clone(), app_routes.clone());
                    }
                }
                Err(err) => {
                    let mut is_retained = false;
                    for prefix in &app.prefixes {
                        if let Some(app_routes) = previous.get(prefix) {
                            routes.insert(prefix.clone(), app_routes.clone());
                            is_retained = true;
                        }
                    }

                    trc::event!(
                        Resource(trc::ResourceEvent::Error),
                        Reason = err,
                        Url = app.url.clone(),
                        Details = format_compact!(
                            "Failed to unpack application for prefixes: {}, {}",
                            app.prefixes.join(", "),
                            if is_retained {
                                "the previously unpacked bundle remains in service"
                            } else {
                                "no bundle is available to serve"
                            }
                        )
                    );
                }
            }
        }

        self.routes.store(Arc::new(routes));
    }

    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed)
    }
}

impl WebApplicationManager {
    pub fn new(app: RegistryObject<Application>) -> Self {
        let base_path = app
            .object
            .unpack_directory
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(app.id.id().to_string());

        Self {
            base_path,
            blob_key: BlobHash::generate(format!("{}{}", APP_BLOB_PREFIX, app.id.id()).as_bytes()),
            url: app.object.resource_url,
            description: app.object.description,
            expiry: app.object.auto_update_interval.as_secs(),
            index_meta: IndexMeta::new(
                app.object.oauth_client_id.as_deref(),
                scope_list(app.object.oauth_scopes.iter()).as_deref(),
            ),
            oauth_client_id: app.object.oauth_client_id,
            prefixes: app
                .object
                .url_prefix
                .iter()
                .map(|prefix| normalize_url_prefix(prefix).to_string())
                .collect(),
        }
    }

    async fn unpack(
        &self,
        server: &Server,
        generation: u64,
        force_refresh: bool,
        sweep_orphans: bool,
    ) -> trc::Result<AppRoutes> {
        let mut cached = if force_refresh {
            None
        } else {
            match server
                .blob_store()
                .get_blob(self.blob_key.as_slice(), 0..usize::MAX)
                .await
            {
                Ok(cached) => cached,
                Err(err) => {
                    trc::event!(
                        Resource(trc::ResourceEvent::Error),
                        Reason = err,
                        Url = self.url.clone(),
                        Details = "Failed to read cached application bundle, downloading it again"
                    );
                    None
                }
            }
        };
        let staging = TempDir::new(self.base_path.join(format!("{:x}-{generation:x}", now())));
        staging.create().await.map_err(unpack_error)?;

        let max_prefix_len = self
            .prefixes
            .iter()
            .map(String::len)
            .max()
            .unwrap_or_default();
        let (resources, index, oauth_client, bundle, is_cached) = loop {
            let is_cached = cached.is_some();
            let bundle = match cached.take() {
                Some(bundle) => bundle,
                None => self.fetch().await?,
            };
            let url = self.url.clone();
            let bundle_path = staging.path.clone();
            match tokio::task::spawn_blocking(move || -> trc::Result<_> {
                let mut archive = ZipArchive::new(Cursor::new(bundle)).map_err(|err| {
                    trc::ResourceEvent::Error
                        .caused_by(trc::location!())
                        .reason(err)
                        .ctx(Key::Url, url.clone())
                        .details("Failed to decompress application bundle")
                })?;
                verify_manifest(&mut archive, &url)?;
                let mut resources = AHashMap::with_capacity(archive.len());
                let mut index = None;
                let mut client_document = None;
                for i in 0..archive.len() {
                    let mut file = archive.by_index(i).map_err(|err| {
                        trc::ResourceEvent::Error
                            .caused_by(trc::location!())
                            .reason(err)
                            .details("Failed to read file from application bundle")
                    })?;
                    if file.is_dir() {
                        continue;
                    }

                    let mut contents = Vec::new();
                    file.read_to_end(&mut contents).map_err(unpack_error)?;
                    let file_name = file
                        .name()
                        .map_err(|err| {
                            trc::ResourceEvent::Error
                                .caused_by(trc::location!())
                                .reason(err)
                                .details("Failed to read file name from application bundle")
                        })?
                        .into_owned();
                    drop(file);

                    if file_name == APP_CLIENT_DOCUMENT {
                        client_document = Some(contents);
                        continue;
                    }
                    if file_name == APP_MANIFEST {
                        continue;
                    }

                    let path = bundle_path.join(format!("{i:02}"));
                    std::fs::write(&path, &contents).map_err(unpack_error)?;
                    if file_name == INDEX_PAGE {
                        index = Some(contents);
                    }

                    let resource = Resource {
                        content_type: match file_name
                            .rsplit_once('.')
                            .map(|(_, ext)| ext)
                            .unwrap_or_default()
                        {
                            "html" => "text/html",
                            "css" => "text/css",
                            "wasm" => "application/wasm",
                            "js" => "application/javascript",
                            "json" => "application/json",
                            "png" => "image/png",
                            "svg" => "image/svg+xml",
                            "ico" => "image/x-icon",
                            _ => "application/octet-stream",
                        }
                        .into(),
                        contents: path,
                    };

                    resources.insert(file_name, resource);
                }
                let oauth_client = client_document
                    .map(|document| {
                        AppClientTemplate::parse(&document, max_prefix_len, |path| {
                            resources.contains_key(path)
                        })
                        .map_err(|err| {
                            trc::ResourceEvent::Error
                                .caused_by(trc::location!())
                                .ctx(Key::Url, url.clone())
                                .details(err)
                        })
                    })
                    .transpose()?;
                Ok((
                    resources,
                    index,
                    oauth_client,
                    archive.into_inner().into_inner(),
                ))
            })
            .await
            .map_err(|err| {
                trc::ResourceEvent::Error
                    .caused_by(trc::location!())
                    .reason(err)
                    .details("Bundle unpack task panicked")
            })? {
                Ok((resources, index, oauth_client, bundle)) => {
                    break (resources, index, oauth_client, bundle, is_cached);
                }
                Err(err) if is_cached => {
                    trc::event!(
                        Resource(trc::ResourceEvent::Error),
                        Reason = err,
                        Url = self.url.clone(),
                        Details = "Cached application bundle is invalid, downloading it again"
                    );
                }
                Err(err) => return Err(err),
            }
        };

        if !is_cached && let Err(err) = self.cache(server, &bundle).await {
            trc::event!(
                Resource(trc::ResourceEvent::Error),
                Reason = err,
                Url = self.url.clone(),
                Details = "Failed to cache application bundle, it will be downloaded again"
            );
        }

        if sweep_orphans {
            remove_siblings(&self.base_path, &staging.path).await;
        }

        trc::event!(
            Resource(trc::ResourceEvent::ApplicationUnpacked),
            Url = self.url.clone(),
            Path = CompactString::from(staging.path.to_string_lossy()),
        );

        Ok(AppRoutes {
            resources,
            index_pages: index
                .map(|index| index_pages(&index, &self.prefixes, &self.index_meta))
                .unwrap_or_default(),
            oauth_client,
            _bundle_dir: staging,
        })
    }

    async fn fetch(&self) -> trc::Result<Vec<u8>> {
        fetch_resource(
            &self.url,
            None,
            Duration::from_secs(60),
            MAX_APP_SIZE,
            false,
        )
        .await
        .map_err(|err| {
            trc::ResourceEvent::Error
                .caused_by(trc::location!())
                .ctx(Key::Url, self.url.clone())
                .reason(err)
                .details("Failed to fetch application bundle")
        })
    }

    async fn cache(&self, server: &Server, bundle: &[u8]) -> trc::Result<()> {
        server
            .blob_store()
            .put_blob(self.blob_key.as_slice(), bundle, CompressionAlgo::None)
            .await
            .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        batch
            .set(
                BlobOp::Link {
                    hash: self.blob_key.clone(),
                    to: BlobLink::Temporary {
                        until: now() + self.expiry,
                    },
                },
                BlobLinkValue::new(bundle.len()),
            )
            .set(
                BlobOp::Commit {
                    hash: self.blob_key.clone(),
                },
                Vec::new(),
            );
        server
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Resource(trc::ResourceEvent::ApplicationUpdated),
            Url = self.url.clone(),
            Details = self.description.clone(),
        );

        Ok(())
    }

    pub async fn delete_bundle(server: &Server, app_id: Id) -> trc::Result<()> {
        let blob_key = BlobHash::generate(format!("{APP_BLOB_PREFIX}{app_id}").as_bytes());

        server
            .blob_store()
            .delete_blob(blob_key.as_slice())
            .await
            .map(|_| ())
    }
}

impl Resource<Vec<u8>> {
    pub fn is_empty(&self) -> bool {
        self.content_type.is_empty() && self.contents.is_empty()
    }
}

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(path: PathBuf) -> TempDir {
        TempDir { path }
    }

    pub async fn create(&self) -> io::Result<()> {
        if tokio::fs::metadata(&self.path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&self.path).await;
        }
        tokio::fs::create_dir_all(&self.path).await
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let path = std::mem::take(&mut self.path);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || {
                let _ = std::fs::remove_dir_all(path);
            });
        } else {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

async fn remove_siblings(base_path: &Path, keep: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(base_path).await else {
        return;
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path == keep {
            continue;
        }

        if matches!(entry.file_type().await, Ok(file_type) if file_type.is_dir()) {
            let _ = tokio::fs::remove_dir_all(&path).await;
        } else {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
}

fn verify_manifest<R: Read + Seek>(archive: &mut ZipArchive<R>, url: &str) -> trc::Result<()> {
    let manifest_error = || {
        trc::ResourceEvent::Error
            .caused_by(trc::location!())
            .ctx(Key::Url, url.to_string())
    };

    let file = archive.by_name(APP_MANIFEST).map_err(|err| match err {
        ZipError::FileNotFound => {
            manifest_error().details("Application bundle does not contain a manifest")
        }
        err => manifest_error()
            .reason(err)
            .details("Failed to read application manifest"),
    })?;
    if file.size() > MAX_APP_MANIFEST_SIZE {
        return Err(manifest_error().details("Application manifest is too large"));
    }
    let mut contents = Vec::new();
    file.take(MAX_APP_MANIFEST_SIZE + 1)
        .read_to_end(&mut contents)
        .map_err(|err| {
            manifest_error()
                .reason(err)
                .details("Failed to read application manifest")
        })?;
    if contents.len() as u64 > MAX_APP_MANIFEST_SIZE {
        return Err(manifest_error().details("Application manifest is too large"));
    }

    let manifest = serde_json::from_slice::<AppManifest<'_>>(&contents).map_err(|err| {
        manifest_error()
            .reason(err)
            .details("Invalid application manifest")
    })?;
    let manifest_error = || {
        manifest_error()
            .ctx(Key::Id, manifest.id.to_string())
            .ctx(Key::Version, manifest.version.to_string())
    };
    let semver = parse_version(manifest.version)
        .ok_or_else(|| manifest_error().details("Invalid application manifest version"))?;

    if let Some(min_server_version) = manifest.min_server_version {
        let min_server_semver = parse_version(min_server_version).ok_or_else(|| {
            manifest_error().details("Invalid application manifest minimum server version")
        })?;
        let server_semver = Semver::current();
        if min_server_semver > server_semver {
            return Err(manifest_error().details(format_compact!(
                "Incompatible application bundle: {} version {} requires Stalwart {min_server_semver} or later, running {server_semver}",
                manifest.id,
                manifest.version
            )));
        }
    }

    match hashify::map!(manifest.id.as_bytes(), u16, "webui" => 2) {
        Some(&major) if semver.major() != major => Err(manifest_error().details(format_compact!(
            "Incompatible application bundle: {} version {} found, major version {major} is required",
            manifest.id,
            manifest.version
        ))),
        _ => Ok(()),
    }
}

fn parse_version(version: &str) -> Option<Semver> {
    let version = version.trim();
    let version = version
        .split_once(['-', '+'])
        .map_or(version, |(version, _)| version);
    Semver::try_from(version).ok()
}

fn unpack_error(err: std::io::Error) -> trc::Error {
    trc::ResourceEvent::Error
        .reason(err)
        .details("Failed to unpack application bundle")
}

impl Default for WebApplications {
    fn default() -> Self {
        Self::new()
    }
}

fn index_pages(index: &[u8], prefixes: &[String], meta: &IndexMeta) -> AHashMap<String, Bytes> {
    let html = std::str::from_utf8(index).ok();
    prefixes
        .iter()
        .map(|prefix| {
            let page = match html {
                Some(html) => rewrite_index(html, prefix, meta),
                None => index.to_vec(),
            };
            (prefix.clone(), Bytes::from(page))
        })
        .collect()
}

fn rewrite_index(html: &str, prefix: &str, meta: &IndexMeta) -> Vec<u8> {
    let mut edits = [
        html.find(BASE_HREF)
            .map(|at| (at, BASE_HREF.len(), IndexEdit::BaseHref(prefix))),
        meta_edit(html, OAUTH_CLIENT_ID, meta.client_id.as_deref()),
        meta_edit(html, OAUTH_SCOPES, meta.scopes.as_deref()),
    ];

    if edits.iter().all(Option::is_none) {
        return html.as_bytes().to_vec();
    }
    edits.sort_unstable_by_key(|edit| edit.as_ref().map_or(usize::MAX, |(at, _, _)| *at));

    let mut out = String::with_capacity(html.len() + prefix.len() + meta.len());
    let mut pos = 0;

    for (at, len, edit) in edits.into_iter().flatten() {
        out.push_str(&html[pos..at]);
        match edit {
            IndexEdit::BaseHref(prefix) => {
                out.push_str("<base href=\"/");
                out.push_str(prefix);
                out.push_str("/\"");
            }
            IndexEdit::Meta(tag) => out.push_str(tag),
        }
        pos = at + len;
    }
    out.push_str(&html[pos..]);
    out.into_bytes()
}

fn meta_edit<'x>(
    html: &str,
    placeholder: &'static str,
    tag: Option<&'x str>,
) -> Option<(usize, usize, IndexEdit<'x>)> {
    tag.and_then(|tag| {
        html.find(placeholder)
            .map(|at| (at, placeholder.len(), IndexEdit::Meta(tag)))
    })
}

impl IndexMeta {
    fn new(client_id: Option<&str>, scopes: Option<&str>) -> Self {
        Self {
            client_id: client_id.map(|client_id| meta_tag(OAUTH_CLIENT_ID, client_id)),
            scopes: scopes.map(|scopes| meta_tag(OAUTH_SCOPES, scopes)),
        }
    }

    fn len(&self) -> usize {
        self.client_id.as_ref().map_or(0, String::len) + self.scopes.as_ref().map_or(0, String::len)
    }
}

fn meta_tag(placeholder: &str, content: &str) -> String {
    let open = placeholder.strip_suffix('"').unwrap_or(placeholder);
    let mut meta = String::with_capacity(placeholder.len() + content.len());
    meta.push_str(open);
    for ch in content.chars() {
        match ch {
            '&' => meta.push_str("&amp;"),
            '"' => meta.push_str("&quot;"),
            '<' => meta.push_str("&lt;"),
            '>' => meta.push_str("&gt;"),
            _ => meta.push(ch),
        }
    }
    meta.push('"');
    meta
}

fn scope_list<'x>(scopes: impl Iterator<Item = &'x String>) -> Option<String> {
    let mut list = String::new();
    for scope in scopes.filter(|scope| is_scope_token(scope)) {
        if !list.is_empty() {
            list.push(' ');
        }
        list.push_str(scope);
    }
    (!list.is_empty()).then_some(list)
}

fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/manager/application/tests.rs"]
mod tests;
