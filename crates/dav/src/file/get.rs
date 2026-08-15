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
use dav_proto::{RequestHeaders, schema::property::Rfc1123DateTime};
use groupware::{cache::GroupwareCache, file::FileNode};
use http_proto::HttpResponse;
use hyper::StatusCode;
use store::{
    ValueKey,
    write::{AlignedBytes, Archive, now},
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
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
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

        let modified = i64::from(node.modified);
        let last_modified = Rfc1123DateTime::new(modified).to_string();
        let byte_range = if !is_head && size > 0 {
            headers
                .range
                .filter(|_| {
                    headers.eval_if_range(
                        &etag,
                        ((modified as u64) < now()).then_some(last_modified.as_str()),
                    )
                })
                .map(|range| range.resolve(size as u64))
        } else {
            None
        };
        let byte_range = match byte_range {
            Some(Some(range)) => Some(range.start as usize..range.end as usize),
            Some(None) => {
                return Ok(HttpResponse::new(StatusCode::RANGE_NOT_SATISFIABLE)
                    .with_accept_ranges()
                    .with_etag(etag)
                    .with_content_range(format!("bytes */{size}")));
            }
            None => None,
        };

        let response = HttpResponse::new(StatusCode::OK)
            .with_content_type(content_type.unwrap_or("application/octet-stream"))
            .with_etag(etag)
            .with_last_modified(last_modified)
            .with_accept_ranges();

        if is_head {
            return Ok(response.with_content_length(size));
        }

        let contents = self
            .blob_store()
            .get_blob(hash, byte_range.clone().unwrap_or(0..usize::MAX))
            .await
            .caused_by(trc::location!())?
            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?;

        Ok(match byte_range {
            Some(byte_range) if !contents.is_empty() => response
                .with_status_code(StatusCode::PARTIAL_CONTENT)
                .with_content_range(format!(
                    "bytes {}-{}/{}",
                    byte_range.start,
                    byte_range.start + contents.len() - 1,
                    size
                )),
            Some(_) => return Err(DavError::Code(StatusCode::NOT_FOUND)),
            None => response,
        }
        .with_binary_body(contents))
    }
}
