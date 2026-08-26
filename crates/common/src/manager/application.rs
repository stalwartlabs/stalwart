/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Server, manager::fetch_resource};
use ahash::AHashMap;
use arc_swap::ArcSwap;
use registry::schema::{enums::CompressionAlgo, structs::Application};
use std::{
    borrow::Cow,
    io::{self, Cursor, Read},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use store::{
    registry::{RegistryObject, bootstrap::Bootstrap},
    write::{BatchBuilder, BlobLink, BlobOp, now},
};
use trc::{AddContext, Key};
use types::blob_hash::BlobHash;

const APP_BLOB_PREFIX: &str = "STALWART_APP_";
const MAX_APP_SIZE: usize = 100 * 1024 * 1024;
const BASE_HREF: &str = "<base href=\"/\"";
const OAUTH_CLIENT_ID: &str = "<meta name=\"oauth-client-id\" content=\"\"";

enum IndexEdit<'x> {
    BaseHref(&'x str),
    OAuthClientId(&'x str),
}

#[allow(clippy::type_complexity)]
pub struct WebApplications {
    applications: ArcSwap<Vec<WebApplicationManager>>,
    routes: ArcSwap<AHashMap<String, Arc<AppRoutes>>>,
}

pub struct AppRoutes {
    resources: AHashMap<String, Resource<PathBuf>>,
    oauth_client_id_meta: Option<String>,
}

#[derive(Clone)]
pub struct WebApplicationManager {
    bundle_path: TempDir,
    prefixes: Vec<String>,
    description: String,
    url: String,
    expiry: u64,
    blob_key: BlobHash,
    oauth_client_id: Option<String>,
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
    pub resource: Resource<Vec<u8>>,
    pub no_cache: bool,
}

impl WebApplications {
    pub fn new() -> Self {
        Self {
            applications: ArcSwap::new(Arc::new(Vec::new())),
            routes: ArcSwap::new(Arc::new(AHashMap::new())),
        }
    }

    pub async fn serve(&self, prefix: &str, path: &str) -> trc::Result<Option<AppResource>> {
        if let Some(routes) = self.routes.load().get(prefix)
            && let Some((is_index, resource)) = routes
                .resources
                .get(path)
                .map(|res| (path == "index.html", res))
                .or_else(|| routes.resources.get("index.html").map(|res| (true, res)))
        {
            tokio::fs::read(&resource.contents)
                .await
                .map(|mut contents| {
                    if is_index && let Ok(html) = std::str::from_utf8(&contents) {
                        contents =
                            rewrite_index(html, prefix, routes.oauth_client_id_meta.as_deref());
                    }

                    Some(AppResource {
                        resource: Resource {
                            content_type: resource.content_type.clone(),
                            contents,
                        },
                        no_cache: is_index,
                    })
                })
                .map_err(|err| {
                    trc::ResourceEvent::Error
                        .reason(err)
                        .ctx(trc::Key::Path, path.to_string())
                        .caused_by(trc::location!())
                })
        } else {
            Ok(None)
        }
    }

    pub async fn reload(&self, bp: &mut Bootstrap) {
        let mut apps = Vec::new();
        for app in bp.list_infallible::<Application>().await {
            if app.object.enabled {
                apps.push(WebApplicationManager::new(app));
            }
        }
        self.applications.store(Arc::new(apps));
    }

    pub async fn unpack_all(&self, server: &Server, update: bool) {
        let mut routes = AHashMap::new();
        for app in self.applications.load().as_ref() {
            if update && let Err(err) = app.delete(server).await {
                trc::event!(
                    Resource(trc::ResourceEvent::Error),
                    Reason = err,
                    Url = app.url.clone(),
                    Details = format!(
                        "Failed to delete application bundle for prefixes: {}",
                        app.prefixes.join(", ")
                    )
                );
            }
            match app.unpack(server).await {
                Ok(resources) => {
                    let app_routes = Arc::new(AppRoutes {
                        resources,
                        oauth_client_id_meta: app
                            .oauth_client_id
                            .as_deref()
                            .map(oauth_client_id_meta),
                    });

                    for prefix in &app.prefixes {
                        routes.insert(prefix.clone(), app_routes.clone());
                    }
                }
                Err(err) => {
                    trc::event!(
                        Resource(trc::ResourceEvent::Error),
                        Reason = err,
                        Url = app.url.clone(),
                        Details = format!(
                            "Failed to unpack application for prefixes: {}",
                            app.prefixes.join(", ")
                        )
                    );
                }
            }
        }
        self.routes.store(Arc::new(routes));
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
            bundle_path: TempDir::new(base_path),
            blob_key: BlobHash::generate(format!("{}{}", APP_BLOB_PREFIX, app.id.id()).as_bytes()),
            url: app.object.resource_url,
            description: app.object.description,
            expiry: app.object.auto_update_frequency.as_secs(),
            oauth_client_id: app.object.oauth_client_id,
            prefixes: app
                .object
                .url_prefix
                .iter()
                .map(|prefix| {
                    prefix
                        .trim_end_matches('/')
                        .trim_start_matches('/')
                        .to_string()
                })
                .collect(),
        }
    }

    async fn unpack(&self, server: &Server) -> trc::Result<AHashMap<String, Resource<PathBuf>>> {
        // Delete any existing bundles
        self.bundle_path.clean().await.map_err(unpack_error)?;

        // Obtain application bundle
        let bundle = if let Some(bundle) = server
            .blob_store()
            .get_blob(self.blob_key.as_slice(), 0..usize::MAX)
            .await?
        {
            bundle
        } else {
            // Fetch app bundle
            let resource = fetch_resource(&self.url, None, Duration::from_secs(60), MAX_APP_SIZE)
                .await
                .map_err(|err| {
                    trc::ResourceEvent::Error
                        .caused_by(trc::location!())
                        .ctx(Key::Url, self.url.clone())
                        .reason(err)
                        .details("Failed to fetch application bundle")
                })?;

            // Store in blob store for future use
            server
                .blob_store()
                .put_blob(self.blob_key.as_slice(), &resource, CompressionAlgo::None)
                .await
                .caused_by(trc::location!())?;

            // Schedule expiration
            let mut batch = BatchBuilder::new();
            batch
                .set(
                    BlobOp::Link {
                        hash: self.blob_key.clone(),
                        to: BlobLink::Temporary {
                            until: now() + self.expiry,
                        },
                    },
                    vec![],
                )
                .set(
                    BlobOp::Commit {
                        hash: self.blob_key.clone(),
                    },
                    Vec::new(),
                );
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;

            trc::event!(
                Resource(trc::ResourceEvent::ApplicationUpdated),
                Url = self.url.clone(),
                Details = self.description.clone(),
            );

            resource
        };

        let url = self.url.clone();
        let bundle_path = self.bundle_path.path.clone();
        let routes = tokio::task::spawn_blocking(move || -> trc::Result<_> {
            let mut bundle = zip::ZipArchive::new(Cursor::new(bundle)).map_err(|err| {
                trc::ResourceEvent::Error
                    .caused_by(trc::location!())
                    .reason(err)
                    .ctx(Key::Url, url.clone())
                    .details("Failed to decompress application bundle")
            })?;
            let mut routes = AHashMap::new();
            for i in 0..bundle.len() {
                let mut file = bundle.by_index(i).map_err(|err| {
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
                let file_name = file.name().to_string();
                drop(file);

                let path = bundle_path.join(format!("{i:02}"));
                std::fs::write(&path, contents).map_err(unpack_error)?;

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

                routes.insert(file_name, resource);
            }
            Ok(routes)
        })
        .await
        .map_err(|err| {
            trc::ResourceEvent::Error
                .caused_by(trc::location!())
                .reason(err)
                .details("Bundle unpack task panicked")
        })??;

        trc::event!(
            Resource(trc::ResourceEvent::ApplicationUnpacked),
            Url = self.url.clone(),
            Path = self.bundle_path.path.to_string_lossy().into_owned(),
        );

        Ok(routes)
    }

    async fn delete(&self, server: &Server) -> trc::Result<()> {
        server
            .blob_store()
            .delete_blob(self.blob_key.as_slice())
            .await
            .map(|_| ())
    }
}

impl Resource<Vec<u8>> {
    pub fn is_empty(&self) -> bool {
        self.content_type.is_empty() && self.contents.is_empty()
    }
}

#[derive(Clone)]
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(path: PathBuf) -> TempDir {
        TempDir { path }
    }

    pub async fn clean(&self) -> io::Result<()> {
        if tokio::fs::metadata(&self.path).await.is_ok() {
            let _ = tokio::fs::remove_dir_all(&self.path).await;
        }
        tokio::fs::create_dir(&self.path).await
    }
}

fn unpack_error(err: std::io::Error) -> trc::Error {
    trc::ResourceEvent::Error
        .reason(err)
        .details("Failed to unpack application bundle")
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

impl Default for WebApplications {
    fn default() -> Self {
        Self::new()
    }
}

fn rewrite_index(html: &str, prefix: &str, oauth_client_id_meta: Option<&str>) -> Vec<u8> {
    let mut edits = [
        html.find(BASE_HREF)
            .map(|at| (at, BASE_HREF.len(), IndexEdit::BaseHref(prefix))),
        oauth_client_id_meta.and_then(|meta| {
            html.find(OAUTH_CLIENT_ID)
                .map(|at| (at, OAUTH_CLIENT_ID.len(), IndexEdit::OAuthClientId(meta)))
        }),
    ];

    if edits.iter().all(Option::is_none) {
        return html.as_bytes().to_vec();
    }
    edits.sort_unstable_by_key(|edit| edit.as_ref().map_or(usize::MAX, |(at, _, _)| *at));

    let mut out =
        String::with_capacity(html.len() + prefix.len() + oauth_client_id_meta.map_or(0, str::len));
    let mut pos = 0;

    for (at, len, edit) in edits.into_iter().flatten() {
        out.push_str(&html[pos..at]);
        match edit {
            IndexEdit::BaseHref(prefix) => {
                out.push_str("<base href=\"/");
                out.push_str(prefix);
                out.push_str("/\"");
            }
            IndexEdit::OAuthClientId(meta) => out.push_str(meta),
        }
        pos = at + len;
    }
    out.push_str(&html[pos..]);
    out.into_bytes()
}

fn oauth_client_id_meta(client_id: &str) -> String {
    let mut meta = String::with_capacity(OAUTH_CLIENT_ID.len() + client_id.len());
    meta.push_str("<meta name=\"oauth-client-id\" content=\"");
    for ch in client_id.chars() {
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

#[cfg(test)]
mod tests {
    use super::*;

    const INDEX: &str = concat!(
        "<!doctype html>\n<html lang=\"en\">\n\n<head>\n  <meta charset=\"UTF-8\" />\n",
        "  <base href=\"/\" />\n  <meta name=\"oauth-client-id\" content=\"\" />\n",
        "  <title>Portal</title>\n</head>\n\n<body></body>\n\n</html>\n"
    );

    #[test]
    fn index_is_rewritten_with_the_prefix_and_client_id() {
        let meta = oauth_client_id_meta("stalwart-webui");
        let html = String::from_utf8(rewrite_index(INDEX, "admin", Some(&meta))).unwrap();

        assert!(html.contains("<base href=\"/admin/\" />"), "{html}");
        assert!(
            html.contains("<meta name=\"oauth-client-id\" content=\"stalwart-webui\" />"),
            "{html}"
        );
        assert!(html.contains("<title>Portal</title>"), "{html}");
        assert!(html.starts_with("<!doctype html>"), "{html}");
        assert!(html.ends_with("</html>\n"), "{html}");
    }

    #[test]
    fn index_keeps_the_empty_placeholder_when_no_client_id_is_configured() {
        let html = String::from_utf8(rewrite_index(INDEX, "account", None)).unwrap();

        assert!(html.contains("<base href=\"/account/\" />"), "{html}");
        assert!(
            html.contains("<meta name=\"oauth-client-id\" content=\"\" />"),
            "{html}"
        );
    }

    #[test]
    fn index_without_a_placeholder_is_left_alone() {
        let bundle = "<head>\n  <base href=\"/\" />\n</head>";
        let meta = oauth_client_id_meta("stalwart-webui");
        let html = String::from_utf8(rewrite_index(bundle, "admin", Some(&meta))).unwrap();

        assert_eq!(html, "<head>\n  <base href=\"/admin/\" />\n</head>");
    }

    #[test]
    fn edits_are_applied_in_document_order() {
        let bundle = concat!(
            "<head><meta name=\"oauth-client-id\" content=\"\" />",
            "<base href=\"/\" /></head>"
        );
        let meta = oauth_client_id_meta("app");
        let html = String::from_utf8(rewrite_index(bundle, "admin", Some(&meta))).unwrap();

        assert_eq!(
            html,
            concat!(
                "<head><meta name=\"oauth-client-id\" content=\"app\" />",
                "<base href=\"/admin/\" /></head>"
            )
        );
    }

    #[test]
    fn client_ids_are_escaped_for_the_attribute() {
        let meta = oauth_client_id_meta("a\"b&c<d>");

        assert_eq!(
            meta,
            "<meta name=\"oauth-client-id\" content=\"a&quot;b&amp;c&lt;d&gt;\""
        );
    }

    async fn fixture(name: &str, client_id: Option<&str>) -> (WebApplications, TempDir) {
        let dir = TempDir::new(std::env::temp_dir().join(format!("stalwart-app-{name}")));
        dir.clean().await.unwrap();
        tokio::fs::write(dir.path.join("index.html"), INDEX)
            .await
            .unwrap();
        tokio::fs::write(dir.path.join("app.js"), "export const x = 1;\n")
            .await
            .unwrap();

        let mut resources = AHashMap::new();
        resources.insert(
            "index.html".to_string(),
            Resource::new("text/html", dir.path.join("index.html")),
        );
        resources.insert(
            "app.js".to_string(),
            Resource::new("text/javascript", dir.path.join("app.js")),
        );

        let routes = Arc::new(AppRoutes {
            resources,
            oauth_client_id_meta: client_id.map(oauth_client_id_meta),
        });

        let mut map = AHashMap::new();
        map.insert("admin".to_string(), routes.clone());
        map.insert("account".to_string(), routes);

        let apps = WebApplications::new();
        apps.routes.store(Arc::new(map));

        (apps, dir)
    }

    async fn serve_html(apps: &WebApplications, prefix: &str, path: &str) -> String {
        let served = apps.serve(prefix, path).await.unwrap().unwrap();
        assert!(served.no_cache, "index responses must not be cached");
        assert_eq!(served.resource.content_type.as_ref(), "text/html");
        String::from_utf8(served.resource.contents).unwrap()
    }

    #[tokio::test]
    async fn serving_index_injects_the_prefix_and_client_id() {
        let (apps, _dir) = fixture("serve-configured", Some("pocket-id-client")).await;

        let html = serve_html(&apps, "admin", "index.html").await;
        assert!(html.contains("<base href=\"/admin/\" />"), "{html}");
        assert!(
            html.contains("<meta name=\"oauth-client-id\" content=\"pocket-id-client\" />"),
            "{html}"
        );

        let html = serve_html(&apps, "account", "index.html").await;
        assert!(html.contains("<base href=\"/account/\" />"), "{html}");
        assert!(
            html.contains("<meta name=\"oauth-client-id\" content=\"pocket-id-client\" />"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn unknown_paths_fall_back_to_a_rewritten_index() {
        let (apps, _dir) = fixture("serve-fallback", Some("pocket-id-client")).await;

        let html = serve_html(&apps, "admin", "settings/directory").await;
        assert!(html.contains("<base href=\"/admin/\" />"), "{html}");
        assert!(
            html.contains("<meta name=\"oauth-client-id\" content=\"pocket-id-client\" />"),
            "{html}"
        );
    }

    #[tokio::test]
    async fn assets_and_unknown_prefixes_are_untouched() {
        let (apps, _dir) = fixture("serve-assets", Some("pocket-id-client")).await;

        let served = apps.serve("admin", "app.js").await.unwrap().unwrap();
        assert_eq!(served.resource.contents, b"export const x = 1;\n");
        assert_eq!(served.resource.content_type.as_ref(), "text/javascript");
        assert!(!served.no_cache);

        assert!(apps.serve("unknown", "index.html").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn serving_index_without_a_client_id_keeps_the_placeholder() {
        let (apps, _dir) = fixture("serve-unconfigured", None).await;

        let html = serve_html(&apps, "admin", "index.html").await;
        assert!(html.contains("<base href=\"/admin/\" />"), "{html}");
        assert!(
            html.contains("<meta name=\"oauth-client-id\" content=\"\" />"),
            "{html}"
        );
    }

    #[test]
    fn an_unmodified_document_is_returned_verbatim() {
        let bundle = "<head><title>x</title></head>";

        assert_eq!(rewrite_index(bundle, "admin", None), bundle.as_bytes());
    }
}
