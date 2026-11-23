/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod generate;
pub mod row;

pub use generate::{OAB_REFRESH, RefreshOutcome, refresh, spawn_refresh};
pub use row::{OAB_OWNER, OabRow, OabTenant};

use crate::{autodiscover::Endpoints, mapi::nspi::scan::directory_visible};
use common::{Server, auth::AccessToken};
use dav_proto::{ByteRange, schema::property::Rfc1123DateTime};
use exchange_proto::{
    common::{Braces, Guid, HexCase, guid::push_hex_lower},
    ids::essdn::GAL_DN,
    oab::{GAL_NAME, OabFile, OabManifest, OabRequest, write_manifest},
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::{
    Method, StatusCode,
    header::{ALLOW, HeaderValue, IF_RANGE, RANGE},
};
use row::{OabBlob, OabGeneration};
use std::ops::Range;
use store::write::now;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

const OAB_PATH: &str = "/OAB/";
const ALLOWED_METHODS: &str = "GET, HEAD";
const MANIFEST_CONTENT_TYPE: &str = "text/xml; charset=utf-8";
const FILE_CONTENT_TYPE: &str = "application/octet-stream";
const CACHE_CONTROL: &str = "private";
const GUID_TEXT_LEN: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetch {
    Head,
    Body,
}

pub trait OabHandler: Sync + Send {
    fn handle_oab(
        &self,
        request: HttpRequest,
        access_token: AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl OabHandler for Server {
    async fn handle_oab(
        &self,
        request: HttpRequest,
        access_token: AccessToken,
    ) -> trc::Result<HttpResponse> {
        let fetch = match *request.method() {
            Method::GET => Fetch::Body,
            Method::HEAD => Fetch::Head,
            _ => {
                return Ok(HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED)
                    .with_header(ALLOW, ALLOWED_METHODS));
            }
        };
        let Some(target) =
            OabRequest::parse(request.uri().path()).filter(|_| oab_allowed(self, &access_token))
        else {
            return Ok(not_found());
        };
        let row = OabRow::read(self, OabTenant::of(&access_token)).await?;
        let Some(row) = row else {
            spawn_refresh(self, &access_token);
            return Ok(not_found());
        };
        if row.guid != target.guid {
            return Ok(not_found());
        }
        let (generation, file) = match target.file {
            OabFile::Manifest => {
                refresh_if_stale(self, &access_token, &row);
                return Ok(match row.slots.current() {
                    Some(current) => manifest_response(&row, current, fetch),
                    None => not_found(),
                });
            }
            OabFile::Full { seq } => match row.slots.find(seq) {
                Some(generation) => (generation, &generation.full),
                None => return Ok(not_found()),
            },
            OabFile::Template { seq } => match row.slots.find(seq) {
                Some(generation) => (generation, &generation.template),
                None => return Ok(not_found()),
            },
        };
        file_response(self, &request, generation, file, fetch).await
    }
}

pub fn oab_allowed(server: &Server, access_token: &AccessToken) -> bool {
    let mut types = Bitmap::<DataType>::all();
    access_token.restrict_data_types(&mut types);
    types.contains(DataType::Principal) && directory_visible(server, access_token)
}

pub async fn advertised_url(server: &Server, access_token: &AccessToken) -> Option<String> {
    if !oab_allowed(server, access_token) {
        return None;
    }
    let row = match OabRow::read(server, OabTenant::of(access_token)).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            spawn_refresh(server, access_token);
            return None;
        }
        Err(err) => {
            trc::error!(err.details("Offline address book row unreadable"));
            return None;
        }
    };
    refresh_if_stale(server, access_token, &row);
    row.slots.current().map(|_| url(server, row.guid))
}

fn refresh_if_stale(server: &Server, access_token: &AccessToken, row: &OabRow) {
    let now = now();
    if row.is_stale(now, OAB_REFRESH) && !row.is_leased(now) {
        spawn_refresh(server, access_token);
    }
}

fn url(server: &Server, guid: Guid) -> String {
    let endpoints = Endpoints::new(server);
    let mut url = Vec::with_capacity(endpoints.base.len() + OAB_PATH.len() + GUID_TEXT_LEN + 1);
    url.extend_from_slice(endpoints.base.as_bytes());
    url.extend_from_slice(OAB_PATH.as_bytes());
    guid.write_text(&mut url, HexCase::Lower, Braces::None);
    url.push(b'/');
    String::from_utf8(url).unwrap_or_default()
}

fn manifest_response(row: &OabRow, current: &OabGeneration, fetch: Fetch) -> HttpResponse {
    let mut body = Vec::with_capacity(1024);
    write_manifest(
        &mut body,
        &OabManifest {
            guid: row.guid,
            name: GAL_NAME,
            distinguished_name: GAL_DN,
            full: current.full.manifest(current.seq),
            template: current.template.manifest(current.seq),
        },
    );
    let response = HttpResponse::new(StatusCode::OK)
        .with_content_type(MANIFEST_CONTENT_TYPE)
        .with_etag(format!("\"{}\"", current.seq))
        .with_last_modified(last_modified(current))
        .with_cache_control(CACHE_CONTROL);
    match fetch {
        Fetch::Head => response.with_content_length(body.len()),
        Fetch::Body => response.with_binary_body(body),
    }
}

async fn file_response(
    server: &Server,
    request: &HttpRequest,
    generation: &OabGeneration,
    file: &OabBlob,
    fetch: Fetch,
) -> trc::Result<HttpResponse> {
    let mut etag = Vec::with_capacity(file.sha1.len() * 2 + 2);
    etag.push(b'"');
    push_hex_lower(&file.sha1, &mut etag);
    etag.push(b'"');
    let etag = String::from_utf8(etag).unwrap_or_default();
    let last_modified = last_modified(generation);
    let size = u64::from(file.size);
    let response = HttpResponse::new(StatusCode::OK)
        .with_content_type(FILE_CONTENT_TYPE)
        .with_accept_ranges()
        .with_cache_control(CACHE_CONTROL);
    let range = match fetch {
        Fetch::Head => {
            return Ok(response
                .with_etag(etag)
                .with_last_modified(last_modified)
                .with_content_length(usize::try_from(size).unwrap_or(usize::MAX)));
        }
        Fetch::Body => {
            let headers = request.headers();
            headers
                .get(RANGE)
                .and_then(|value| value.to_str().ok())
                .and_then(ByteRange::parse)
                .filter(|_| if_range_matches(headers.get(IF_RANGE), &etag, &last_modified))
                .map(|range| range.resolve(size).map(to_usize_range))
        }
    };
    let range = match range {
        Some(Some(range)) => Some(range),
        Some(None) => {
            return Ok(HttpResponse::new(StatusCode::RANGE_NOT_SATISFIABLE)
                .with_accept_ranges()
                .with_etag(etag)
                .with_content_range(format!("bytes */{size}")));
        }
        None => None,
    };
    let Some(contents) = server
        .fetch_blob(
            &file.hash,
            range.clone().unwrap_or(0..usize::MAX),
            Some(size),
        )
        .await?
    else {
        return Ok(not_found());
    };
    let response = response.with_etag(etag).with_last_modified(last_modified);
    Ok(match range {
        Some(range) if !contents.is_empty() => response
            .with_status_code(StatusCode::PARTIAL_CONTENT)
            .with_content_range(format!(
                "bytes {}-{}/{size}",
                range.start,
                range.start + contents.len() - 1
            )),
        Some(_) => return Ok(not_found()),
        None => response,
    }
    .with_binary_body(contents))
}

fn if_range_matches(validator: Option<&HeaderValue>, etag: &str, last_modified: &str) -> bool {
    match validator {
        None => true,
        Some(validator) => validator
            .to_str()
            .is_ok_and(|validator| validator == etag || validator == last_modified),
    }
}

fn to_usize_range(range: Range<u64>) -> Range<usize> {
    usize::try_from(range.start).unwrap_or(usize::MAX)
        ..usize::try_from(range.end).unwrap_or(usize::MAX)
}

fn last_modified(generation: &OabGeneration) -> String {
    Rfc1123DateTime::new(i64::try_from(generation.assigned_at).unwrap_or(i64::MAX)).to_string()
}

fn not_found() -> HttpResponse {
    HttpResponse::new(StatusCode::NOT_FOUND)
}
