/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    DavError, DavMethod,
    common::{
        ETag,
        lock::{LockRequestHandler, ResourceState},
        uri::DavUriResource,
    },
    file::DavFileResource,
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use dav_proto::{HttpRange, RangeSpec, RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

pub(crate) trait FileGetRequestHandler: Sync + Send {
    fn handle_file_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> impl Future<Output = crate::Result<HttpResponse>> + Send;
}

impl FileGetRequestHandler for Server {
    async fn handle_file_get_request(
        &self,
        access_token: &AccessToken,
        headers: &RequestHeaders<'_>,
        is_head: bool,
    ) -> crate::Result<HttpResponse> {
        // Validate URI
        let resource_ = self
            .validate_uri(access_token, headers.uri)
            .await?
            .into_owned_uri()?;
        let account_id = resource_.account_id;
        let files = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::FileNode)
            .await
            .caused_by(trc::location!())?;
        let resource = files.map_resource(&resource_)?;

        // Fetch node
        let node_ = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::FileNode,
                resource.resource,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
        let node = node_.unarchive::<FileNode>().caused_by(trc::location!())?;

        // Validate ACL
        if !access_token.is_member(account_id)
            && !node.acls.effective_acl(access_token).contains(Acl::Read)
        {
            return Err(DavError::Code(StatusCode::FORBIDDEN));
        }

        let (hash, size, content_type) = if let Some(file) = node.file.as_ref() {
            (
                file.blob_hash.0.as_ref(),
                u32::from(file.size) as usize,
                file.media_type.as_ref().map(|s| s.as_str()),
            )
        } else {
            return Err(DavError::Code(StatusCode::METHOD_NOT_ALLOWED));
        };

        // Validate headers
        let etag = node_.etag();
        self.validate_headers(
            access_token,
            headers,
            vec![ResourceState {
                account_id,
                collection: resource.collection,
                document_id: resource.resource.into(),
                etag: etag.clone().into(),
                path: resource_.resource.unwrap(),
                ..Default::default()
            }],
            Default::default(),
            DavMethod::GET,
        )
        .await?;

        // Check for range request
        let (status, content_range, range_start, range_end) = if let Some(range) = &headers.range {
            let file_size = size as u64;
            if range.ranges.len() > 1 {
                trc::event!(
                    WebDav(trc::WebDavEvent::Error),
                    Reason = "Multiple ranges not supported",
                );
                return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
            }
            let spec = &range.ranges[0];
            match spec {
                RangeSpec::FromTo { start, end } => {
                    if *start >= file_size || *start > *end {
                        trc::event!(
                            WebDav(trc::WebDavEvent::Error),
                            Reason = format!("Invalid range: start={} end={} file_size={}", start, end, file_size),
                        );
                        return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                    }
                    let actual_end = (*end).min(file_size - 1);
                    (
                        StatusCode::PARTIAL_CONTENT,
                        Some(format!("bytes {}-{}/{}", start, actual_end, file_size)),
                        *start as usize,
                        (actual_end + 1) as usize,
                    )
                }
                RangeSpec::From { start } => {
                    if *start >= file_size {
                        trc::event!(
                            WebDav(trc::WebDavEvent::Error),
                            Reason = format!("Invalid range: start={} >= file_size={}", start, file_size),
                        );
                        return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                    }
                    (
                        StatusCode::PARTIAL_CONTENT,
                        Some(format!("bytes {}-{}/{}", start, file_size - 1, file_size)),
                        *start as usize,
                        size,
                    )
                }
                RangeSpec::Last { suffix } => {
                    if *suffix == 0 {
                        trc::event!(
                            WebDav(trc::WebDavEvent::Error),
                            Reason = "Invalid range: suffix=0",
                        );
                        return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                    }
                    let start = if *suffix >= file_size { 0 } else { file_size - *suffix };
                    (
                        StatusCode::PARTIAL_CONTENT,
                        Some(format!("bytes {}-{}/{}", start, file_size - 1, file_size)),
                        start as usize,
                        size,
                    )
                }
            }
        } else {
            (StatusCode::OK, None, 0, size)
        };

        let mut response = HttpResponse::new(status)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_etag(etag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(node.modified)).to_string());

        if let Some(content_range) = content_range {
            response = response.with_header("Content-Range", content_range);
        }

        if !is_head {
            let body = self.blob_store()
                .get_blob(hash, range_start..range_end)
                .await
                .caused_by(trc::location!())?
                .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;
            Ok(response.with_binary_body(body))
        } else {
            if status == StatusCode::PARTIAL_CONTENT {
                response = response.with_content_length(range_end - range_start);
            } else {
                response = response.with_content_length(size);
            }
            Ok(response)
        }
    }
}
