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
use dav_proto::{HttpRange, RangeSpec, RequestHeaders, schema::property::Rfc1123DateTime, MAX_RANGE_PARTS};

use groupware::{cache::GroupwareCache, file::FileNode};
use futures::{stream, StreamExt, TryStreamExt};
use http_proto::{HttpResponse, HttpResponseBody};
use http_body_util::{combinators::UnsyncBoxBody, StreamBody};
use hyper::body::Frame;
use hyper::StatusCode;
use rand::{Rng, distributions::Alphanumeric};
use store::{
    ValueKey,
    write::{AlignedBytes, Archive},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

use bytes::BytesMut;

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
            // Validate number of ranges
            if range.ranges.len() > MAX_RANGE_PARTS {
                trc::event!(
                    WebDav(trc::WebDavEvent::Error),
                    Reason = "Too many range specs in request",
                );
                return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
            }
            let file_size = size as u64;
            let mut parts: Vec<(usize, usize)> = Vec::new();
            // Process each range spec and validate against file size
            for spec in &range.ranges {
                match spec {
                    RangeSpec::Invalid { reason } => {
                        trc::event!(
                            WebDav(trc::WebDavEvent::Error),
                            Reason = format!("Invalid range spec: {}", reason),
                        );
                        return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                    }
                    RangeSpec::FromTo { start, end } => {
                        // Validate start < file_size (parser validated start < end)
                        if *start >= file_size {
                            trc::event!(
                                WebDav(trc::WebDavEvent::Error),
                                Reason = "Range start beyond file size",
                            );
                            return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                        }
                        let range_start = *start as usize;
                        // HTTP range end is inclusive; convert to exclusive Rust range: clamp end to file_size-1, then +1
                        let range_end = ((*end).min(file_size - 1) + 1) as usize;
                        parts.push((range_start, range_end));
                    }
                    RangeSpec::From { start } => {
                        // Validate start < file_size
                        if *start >= file_size {
                            trc::event!(
                                WebDav(trc::WebDavEvent::Error),
                                Reason = "Range start beyond file size",
                            );
                            return Err(DavError::Code(StatusCode::RANGE_NOT_SATISFIABLE));
                        }
                        let range_start = *start as usize;
                        // Exclusive end at file size (covers from start to end of file)
                        let range_end = size;
                        parts.push((range_start, range_end));
                    }
                    RangeSpec::Last { suffix } => {
                        // Parser validated suffix > 0
                        // Calculate start position for the last 'suffix' bytes
                        let start_pos = if *suffix >= file_size { 0 } else { file_size - *suffix };
                        let range_start = start_pos as usize;
                        // Exclusive end at file size
                        let range_end = size;
                        parts.push((range_start, range_end));
                    }
                }
            }
            if parts.len() > MAX_RANGE_PARTS {
                trc::event!(
                    WebDav(trc::WebDavEvent::Error),
                    Reason = "Too many range parts in request",
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
            // Check for overlapping ranges - RFC 9110, Section 14.2: 'A client SHOULD NOT request multiple ranges that are inherently less efficient to process and transfer than a single range that encompasses the same data.'
            // range_end is exclusive; overlap if prev_end > curr_start (not >=, to allow adjacent ranges)
            let mut sorted_parts = parts.clone();
            sorted_parts.sort_by_key(|(s, _)| *s);
            for window in sorted_parts.windows(2) {
                let [(_, prev_end), (curr_start, _)] = window else { unreachable!() };
                if prev_end > curr_start {
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
                let (range_start, range_end) = parts[0];
                let start = range_start as u64;
                // range_end is exclusive; HTTP Content-Range end is inclusive: range_end - 1
                let actual_end = (range_end - 1) as u64;
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
                let boundary: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(30)
                    .map(char::from)
                    .collect();
                let content_type_multipart = format!("multipart/byteranges; boundary={}", boundary);
                let content_type_str = content_type.unwrap_or("application/octet-stream").to_string();
                let file_size_str = file_size.to_string();
                // Clone the blob store Arc to make it owned, as the stream requires 'static lifetime
                // Without cloning, the stream would borrow from self, causing lifetime errors
                let blob_store = self.blob_store().clone();
                let hash_clone = hash.clone();
                let stream = stream::unfold(
                    (parts, boundary, content_type_str, file_size_str, hash_clone),
                    move |(mut remaining_parts, boundary, content_type, file_size, hash)| {
                        let blob_store = blob_store.clone();
                        async move {
                            if let Some((range_start, range_end)) = remaining_parts.pop() {
                                let start = range_start as u64;
                                // range_end is exclusive; HTTP Content-Range end is inclusive: range_end - 1
                                let actual_end = (range_end - 1) as u64;
                                let data_result = blob_store.get_blob(&hash, range_start..range_end).await;
                                let data = match data_result {
                                    Ok(Some(d)) => d,
                                    Ok(None) => return Some((Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Blob not found")), (remaining_parts, boundary, content_type, file_size, hash))),
                                    Err(e) => return Some((Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e))), (remaining_parts, boundary, content_type, file_size, hash))),
                                };

                                let start_str = format!("{}", start);
                                let actual_end_str = format!("{}", actual_end);
                                let file_size_str = format!("{}", file_size);
                                let data_len = data.len();
                                let estimated_capacity = 150 + data_len + boundary.len() + content_type.len() + start_str.len() + actual_end_str.len() + file_size_str.len();
                                let mut part = BytesMut::with_capacity(estimated_capacity);
                                part.extend_from_slice(b"--");
                                part.extend_from_slice(boundary.as_bytes());
                                part.extend_from_slice(b"\r\n");
                                part.extend_from_slice(b"Content-Type: ");
                                part.extend_from_slice(content_type.as_bytes());
                                part.extend_from_slice(b"\r\n");
                                part.extend_from_slice(b"Content-Range: bytes ");
                                part.extend_from_slice(start_str.as_bytes());
                                part.extend_from_slice(b"-");
                                part.extend_from_slice(actual_end_str.as_bytes());
                                part.extend_from_slice(b"/");
                                part.extend_from_slice(file_size_str.as_bytes());
                                part.extend_from_slice(b"\r\n\r\n");
                                part.extend_from_slice(&data);
                                part.extend_from_slice(b"\r\n");

                                Some((Ok(part.freeze()), (remaining_parts, boundary, content_type, file_size, hash)))
                            } else {
                                let mut end = BytesMut::with_capacity(10 + boundary.len());
                                end.extend_from_slice(b"--");
                                end.extend_from_slice(boundary.as_bytes());
                                end.extend_from_slice(b"--\r\n");
                                Some((Ok(end.freeze()), (remaining_parts, boundary, content_type, file_size, hash)))
                            }
                        }
                    }
                );
                let stream = stream.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync + 'static>).map_ok(Frame::data);
                let boxed_body = UnsyncBoxBody::new(StreamBody::new(stream));
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
                            RangeSpec::Invalid { .. } => unreachable!(),
                        }
                    }
                }
            } // For multipart, content_length is not set, as it's variable
            Ok(response)
        }
    }
}
