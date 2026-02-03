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
use http_proto::{HttpResponse, HttpResponseBody};
use http_body_util::StreamBody;
use hyper::body::Frame;
use hyper::StatusCode;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use rand;
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
                file.blob_hash.0.as_ref().to_vec(),
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
        let (status, content_type_header, content_range, body_data): (StatusCode, String, Option<String>, Option<HttpResponseBody>) = if let Some(range) = &headers.range {
            let file_size = size as u64;
            let mut parts = Vec::new();
            let mut has_invalid = false;
            // Process each range spec and validate against file size
            for spec in &range.ranges {
                match spec {
                    RangeSpec::FromTo { start, end } => {
                        // Invalid if start > end or start >= file_size
                        if *start > *end || *start >= file_size {
                            has_invalid = true;
                            break;
                        }
                        let actual_end = (*end).min(file_size - 1);
                        let range_start = *start as usize;
                        let range_end = (actual_end + 1) as usize;
                        parts.push((*start, actual_end, range_start, range_end));
                    }
                    RangeSpec::From { start } => {
                        // Invalid if start is beyond file
                        if *start > file_size.saturating_sub(1) {
                            has_invalid = true;
                            break;
                        }
                        let range_start = *start as usize;
                        parts.push((*start, file_size - 1, range_start, size));
                    }
                    RangeSpec::Last { suffix } => {
                        // Invalid if suffix is 0 (would be empty range)
                        if *suffix == 0 {
                            has_invalid = true;
                            break;
                        }
                        let start_pos = if *suffix >= file_size { 0 } else { file_size - *suffix };
                        let range_start = start_pos as usize;
                        parts.push((start_pos, file_size - 1, range_start, size));
                    }
                }
            }
            if has_invalid {
                trc::event!(
                    WebDav(trc::WebDavEvent::Error),
                    Reason = "Invalid range in request",
                );
                return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
            }
            // RFC 9110: Multiple Last ranges are not allowed in multipart requests
            let last_count = range.ranges.iter().filter(|r| matches!(r, RangeSpec::Last { .. })).count();
            if last_count > 1 {
                trc::event!(
                    WebDav(trc::WebDavEvent::Error),
                    Reason = "Multiple Last ranges not allowed",
                );
                return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
            }
            // Check for overlapping ranges - RFC 9110 discourages inefficient overlapping ranges
            let mut sorted_parts = parts.clone();
            sorted_parts.sort_by_key(|(s, _, _, _)| *s);
            for i in 1..sorted_parts.len() {
                let (_, prev_end, _, _) = sorted_parts[i - 1];
                let (curr_start, _, _, _) = sorted_parts[i];
                if prev_end >= curr_start {
                    trc::event!(
                        WebDav(trc::WebDavEvent::Error),
                        Reason = "Overlapping ranges in request",
                    );
                    return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                }
            }
            if parts.is_empty() {
                (
                    StatusCode::OK,
                    content_type.unwrap_or("application/octet-stream").to_string(),
                    None,
                    if !is_head {
                        Some(HttpResponseBody::Binary(self.blob_store()
                            .get_blob(&hash, 0..size)
                            .await
                            .caused_by(trc::location!())?
                            .ok_or(DavError::Code(StatusCode::NOT_FOUND))?))
                    } else {
                        None
                    }
                )
            } else if parts.len() == 1 {
                let (start, actual_end, range_start, range_end) = parts[0];
                let content_range = format!("bytes {}-{}/{}", start, actual_end, file_size);
                let body = if !is_head {
                    Some(HttpResponseBody::Binary(self.blob_store()
                        .get_blob(&hash, range_start..range_end)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?))
                } else {
                    None
                };
                (StatusCode::PARTIAL_CONTENT, content_type.unwrap_or("application/octet-stream").to_string(), Some(content_range), body)
            } else {
                // Multipart
                let boundary = format!("{:x}", rand::random::<u64>());
                let content_type_multipart = format!("multipart/byteranges; boundary={}", boundary);
                let content_type_str = content_type.unwrap_or("application/octet-stream").to_string();
                let file_size_str = file_size.to_string();
                let parts_vec = parts;
                // Clone the blob store Arc to make it owned, as the stream requires 'static lifetime
        // Without cloning, the stream would borrow from self, causing lifetime errors
        let blob_store = self.blob_store().clone();
                let hash_clone = hash.clone();
                let (tx, rx) = mpsc::unbounded_channel();
                let blob_store_clone = blob_store.clone();
                let boundary_clone = boundary.clone();
                let content_type_str_clone = content_type_str.clone();
                let file_size_str_clone = file_size_str.clone();
                tokio::spawn(async move {
                    for (start, actual_end, range_start, range_end) in parts_vec {
                        let data_result = blob_store_clone.get_blob(hash_clone.as_ref(), range_start..range_end).await;
                        let data = match data_result {
                            Ok(Some(d)) => d,
                            Ok(None) => {
                                let _ = tx.send(Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Blob not found")) as Box<dyn std::error::Error + Send + Sync + 'static>));
                                return;
                            }
                            Err(e) => {
                                let _ = tx.send(Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e))) as Box<dyn std::error::Error + Send + Sync + 'static>));
                                return;
                            }
                        };

                        let mut part = Vec::new();
                        part.extend_from_slice(b"--");
                        part.extend_from_slice(boundary_clone.as_bytes());
                        part.extend_from_slice(b"\r\n");
                        part.extend_from_slice(b"Content-Type: ");
                        part.extend_from_slice(content_type_str_clone.as_bytes());
                        part.extend_from_slice(b"\r\n");
                        part.extend_from_slice(b"Content-Range: bytes ");
                        part.extend_from_slice(format!("{}", start).as_bytes());
                        part.extend_from_slice(b"-");
                        part.extend_from_slice(format!("{}", actual_end).as_bytes());
                        part.extend_from_slice(b"/");
                        part.extend_from_slice(file_size_str_clone.as_bytes());
                        part.extend_from_slice(b"\r\n\r\n");
                        part.extend_from_slice(&data);
                        part.extend_from_slice(b"\r\n");

                        if tx.send(Ok(Frame::data(bytes::Bytes::from(part)))).is_err() {
                            return;
                        }
                    }

                    let mut end = Vec::new();
                    end.extend_from_slice(b"--");
                    end.extend_from_slice(boundary_clone.as_bytes());
                    end.extend_from_slice(b"--\r\n");

                    let _ = tx.send(Ok(Frame::data(bytes::Bytes::from(end))));
                });

                let stream = UnboundedReceiverStream::new(rx);
                let boxed_body = http_body_util::combinators::BoxBody::new(StreamBody::new(stream));
                (
                    StatusCode::PARTIAL_CONTENT,
                    content_type_multipart,
                    None,
                    if is_head { None } else { Some(HttpResponseBody::Stream(boxed_body)) }
                )
            }
        } else {
            (
                StatusCode::OK,
                content_type.unwrap_or("application/octet-stream").to_string(),
                None,
                if !is_head {
                    Some(HttpResponseBody::Binary(self.blob_store()
                        .get_blob(&hash, 0..size)
                        .await
                        .caused_by(trc::location!())?
                        .ok_or(DavError::Code(StatusCode::NOT_FOUND))?))
                } else {
                    None
                }
            )
        };

        let mut response = HttpResponse::new(status)
            .with_content_type(content_type_header)
            .with_etag(etag)
            .with_last_modified(Rfc1123DateTime::new(i64::from(node.modified)).to_string());

        if status == StatusCode::OK {
            response = response.with_header("Accept-Ranges", "bytes");
        }

        if let Some(ref content_range) = content_range {
            response = response.with_header("Content-Range", content_range.clone());
        }

        if let Some(body) = body_data {
            match body {
                HttpResponseBody::Binary(b) => Ok(response.with_binary_body(b)),
                HttpResponseBody::Stream(s) => Ok(response.with_stream_body(s)),
                _ => unreachable!(),
            }
        } else {
            // For no range or HEAD, set content_length
            if status == StatusCode::OK {
                response = response.with_content_length(size);
            } else if status == StatusCode::PARTIAL_CONTENT && content_range.is_some() {
                // For single range HEAD, calculate content_length
                if let Some(range) = &headers.range {
                    if range.ranges.len() == 1 {
                        let spec = &range.ranges[0];
                        let file_size = size as u64;
                        match spec {
                            RangeSpec::FromTo { start, end } => {
                                let actual_end = (*end).min(file_size - 1);
                                response = response.with_content_length((actual_end - start + 1) as usize);
                            }
                            RangeSpec::From { start } => {
                                response = response.with_content_length(size - *start as usize);
                            }
                            RangeSpec::Last { suffix } => {
                                let start_pos = if *suffix >= file_size { 0 } else { file_size - *suffix };
                                response = response.with_content_length(size - start_pos as usize);
                            }
                        }
                    }
                }
            } // For multipart, content_length is not set, as it's variable
            Ok(response)
        }
    }
}
