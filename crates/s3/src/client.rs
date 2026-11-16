/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Credentials, DeleteBatch, Endpoint, Error, Result, RetryPolicy, Scheme, UrlStyle,
    delete::{DeleteFailure, DeleteResponse},
    endpoint::{Location, RequestUrl},
    error::read_capped,
    retry::Attempts,
    signer::{
        AmzDate, CanonicalRequest, EMPTY_PAYLOAD_SHA256, Sha256Hex, Signer, UNSIGNED_PAYLOAD,
    },
};
use bytes::Bytes;
use encodify::base64::STANDARD;
use reqwest::{
    Client, Method, Response, StatusCode,
    header::{AUTHORIZATION, CONTENT_LENGTH, HeaderName, RANGE},
};
use std::{
    fmt,
    ops::Range,
    sync::atomic::{AtomicBool, Ordering},
};

const CONTENT_MD5_NAME: &str = "content-md5";
const HOST_NAME: &str = "host";
const X_AMZ_CHECKSUM_CRC32C_NAME: &str = "x-amz-checksum-crc32c";
const X_AMZ_CONTENT_SHA256_NAME: &str = "x-amz-content-sha256";
const X_AMZ_DATE_NAME: &str = "x-amz-date";
const X_AMZ_SECURITY_TOKEN_NAME: &str = "x-amz-security-token";

const CONTENT_MD5: HeaderName = HeaderName::from_static(CONTENT_MD5_NAME);
const X_AMZ_CHECKSUM_CRC32C: HeaderName = HeaderName::from_static(X_AMZ_CHECKSUM_CRC32C_NAME);
const X_AMZ_CONTENT_SHA256: HeaderName = HeaderName::from_static(X_AMZ_CONTENT_SHA256_NAME);
const X_AMZ_DATE: HeaderName = HeaderName::from_static(X_AMZ_DATE_NAME);
const X_AMZ_SECURITY_TOKEN: HeaderName = HeaderName::from_static(X_AMZ_SECURITY_TOKEN_NAME);

const MAX_DELETE_RESPONSE: usize = 1024 * 1024;
const MAX_SIGNED_HEADERS: usize = 6;

pub struct BucketConfig<'x> {
    pub endpoint: Endpoint,
    pub bucket: &'x str,
    pub region: &'x str,
    pub style: UrlStyle,
    pub credentials: Credentials,
    pub retry: RetryPolicy,
}

pub struct Bucket {
    http: Client,
    location: Location,
    signer: Signer,
    session_token: Option<Box<str>>,
    scheme: Scheme,
    retry: RetryPolicy,
    checksum: AtomicBool,
    multi_delete: AtomicBool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteCheck {
    None,
    Head,
}

struct Request<'x> {
    method: Method,
    url: &'x RequestUrl,
    query: &'x str,
    payload_hash: &'x str,
    body: Option<&'x Bytes>,
    content_md5: Option<&'x str>,
    checksum: Option<&'x str>,
    range: Option<&'x str>,
}

impl Bucket {
    pub fn new(http: Client, config: BucketConfig<'_>) -> Result<Self> {
        let location = config.endpoint.locate(config.bucket, config.style)?;
        Ok(Bucket {
            http,
            location,
            signer: Signer::new(&config.credentials, config.region),
            session_token: config.credentials.session_token().map(Into::into),
            scheme: config.endpoint.scheme(),
            retry: config.retry,
            checksum: AtomicBool::new(true),
            multi_delete: AtomicBool::new(true),
        })
    }

    pub fn sends_checksum(&self) -> bool {
        self.scheme == Scheme::Https && self.checksum.load(Ordering::Relaxed)
    }

    pub fn supports_multi_delete(&self) -> bool {
        self.multi_delete.load(Ordering::Relaxed)
    }

    pub async fn put_object(&self, key: &str, body: Bytes) -> Result<()> {
        self.put(key, body, WriteCheck::None).await
    }

    pub async fn put_object_verified(&self, key: &str, body: Bytes) -> Result<()> {
        self.put(key, body, WriteCheck::Head).await
    }

    async fn put(&self, key: &str, body: Bytes, check: WriteCheck) -> Result<()> {
        let url = self.location.object_url(key)?;
        let payload_hash = match self.scheme {
            Scheme::Https => None,
            Scheme::Http => Some(Sha256Hex::of(&body)),
        };
        let payload_hash = payload_hash
            .as_ref()
            .map_or(UNSIGNED_PAYLOAD, Sha256Hex::as_str);
        let (mut checksum, mut content_md5) = match self.scheme {
            Scheme::Http => (None, None),
            Scheme::Https if self.checksum.load(Ordering::Relaxed) => {
                (Some(crc32c_base64(&body)), None)
            }
            Scheme::Https => (None, Some(md5_base64(&body))),
        };
        let mut attempts = Attempts::new(self.retry);

        loop {
            let response = self
                .execute(
                    &Request {
                        method: Method::PUT,
                        url: &url,
                        query: "",
                        payload_hash,
                        body: Some(&body),
                        content_md5: content_md5.as_deref(),
                        checksum: checksum.as_deref(),
                        range: None,
                    },
                    &mut attempts,
                )
                .await?;
            if !response.status().is_success() {
                let error = Error::from_response(response).await;
                if checksum.is_some() && error.rejects_checksum() {
                    self.checksum.store(false, Ordering::Relaxed);
                    checksum = None;
                    content_md5 = Some(md5_base64(&body));
                    continue;
                }
                return Err(error);
            }
            if check == WriteCheck::None || self.head(&url, &mut attempts).await?.is_some() {
                return Ok(());
            }
            if !attempts.can_retry() {
                return Err(Error::NotVisible);
            }
            attempts.backoff().await;
        }
    }

    pub async fn get_object(&self, key: &str, range: Option<Range<u64>>) -> Result<Option<Bytes>> {
        let range_header = match &range {
            Some(range) if range.start >= range.end => {
                return Ok(self.head_object(key).await?.map(|_| Bytes::new()));
            }
            Some(range) if range.end == u64::MAX => Some(format!("bytes={}-", range.start)),
            Some(range) => Some(format!("bytes={}-{}", range.start, range.end - 1)),
            None => None,
        };
        let url = self.location.object_url(key)?;
        let request = Request {
            method: Method::GET,
            url: &url,
            query: "",
            payload_hash: EMPTY_PAYLOAD_SHA256,
            body: None,
            content_md5: None,
            checksum: None,
            range: range_header.as_deref(),
        };

        let mut attempts = Attempts::new(self.retry);
        loop {
            let response = self.execute(&request, &mut attempts).await?;
            let status = response.status();
            match status {
                StatusCode::OK | StatusCode::PARTIAL_CONTENT => match response.bytes().await {
                    Ok(body) => {
                        return Ok(Some(match &range {
                            Some(range) if status == StatusCode::OK => slice_range(body, range),
                            _ => body,
                        }));
                    }
                    Err(err) if attempts.retries_transport(&err) => attempts.backoff().await,
                    Err(err) => return Err(Error::Transport(err)),
                },
                StatusCode::NOT_FOUND => return Ok(None),
                StatusCode::RANGE_NOT_SATISFIABLE => return Ok(Some(Bytes::new())),
                _ => return Err(Error::from_response(response).await),
            }
        }
    }

    pub async fn head_object(&self, key: &str) -> Result<Option<u64>> {
        let url = self.location.object_url(key)?;
        self.head(&url, &mut Attempts::new(self.retry)).await
    }

    async fn head(&self, url: &RequestUrl, attempts: &mut Attempts) -> Result<Option<u64>> {
        let response = self
            .execute(
                &Request {
                    method: Method::HEAD,
                    url,
                    query: "",
                    payload_hash: EMPTY_PAYLOAD_SHA256,
                    body: None,
                    content_md5: None,
                    checksum: None,
                    range: None,
                },
                attempts,
            )
            .await?;
        match response.status() {
            status if status.is_success() => Ok(Some(
                response
                    .headers()
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_default(),
            )),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(Error::from_response(response).await),
        }
    }

    pub async fn delete_object(&self, key: &str) -> Result<bool> {
        let url = self.location.object_url(key)?;
        let response = self
            .execute(
                &Request {
                    method: Method::DELETE,
                    url: &url,
                    query: "",
                    payload_hash: EMPTY_PAYLOAD_SHA256,
                    body: None,
                    content_md5: None,
                    checksum: None,
                    range: None,
                },
                &mut Attempts::new(self.retry),
            )
            .await?;
        match response.status() {
            status if status.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            _ => Err(Error::from_response(response).await),
        }
    }

    pub async fn delete_objects(&self, batch: DeleteBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let url = self.location.bucket_url("delete");
        let mut body = batch.into_body();
        let mut attempts = Attempts::new(self.retry);

        loop {
            let content_md5 = md5_base64(&body);
            let payload_hash = Sha256Hex::of(&body);
            let response = self
                .execute(
                    &Request {
                        method: Method::POST,
                        url: &url,
                        query: "delete=",
                        payload_hash: payload_hash.as_str(),
                        body: Some(&body),
                        content_md5: Some(&content_md5),
                        checksum: None,
                        range: None,
                    },
                    &mut attempts,
                )
                .await?;
            let status = response.status();
            if !status.is_success() {
                let error = Error::from_response(response).await;
                if error.is_not_implemented() {
                    self.multi_delete.store(false, Ordering::Relaxed);
                }
                return Err(error);
            }

            let content_length = response.content_length();
            let response = read_capped(response, MAX_DELETE_RESPONSE + 1).await?;
            if response.len() > MAX_DELETE_RESPONSE {
                return Err(Error::InvalidResponse(
                    "DeleteObjects response exceeds 1 MiB",
                ));
            }
            match DeleteResponse::parse(&response, content_length) {
                DeleteResponse::Deleted => return Ok(()),
                DeleteResponse::Malformed => {
                    return Err(Error::InvalidResponse(
                        "DeleteObjects response is not a DeleteResult",
                    ));
                }
                DeleteResponse::Rejected { code, message } => {
                    let not_implemented = code.as_deref() == Some("NotImplemented");
                    let retryable = code.as_deref().is_some_and(RetryPolicy::is_retryable_code);
                    if not_implemented {
                        self.multi_delete.store(false, Ordering::Relaxed);
                    }
                    if !retryable || !attempts.can_retry() {
                        return Err(Error::Status {
                            status: if not_implemented {
                                StatusCode::NOT_IMPLEMENTED.as_u16()
                            } else {
                                status.as_u16()
                            },
                            code: code.map(String::into_boxed_str),
                            message: message.map(String::into_boxed_str),
                        });
                    }
                }
                DeleteResponse::Failed(failures) => {
                    body = retry_batch(failures, &attempts)?;
                }
            }

            attempts.backoff().await;
        }
    }

    async fn execute(&self, request: &Request<'_>, attempts: &mut Attempts) -> Result<Response> {
        loop {
            match self.send(request).await {
                Ok(response) if attempts.retries_status(response.status()) => {}
                Ok(response) => return Ok(response),
                Err(err) if attempts.retries_transport(&err) => {}
                Err(err) => return Err(Error::Transport(err)),
            }
            attempts.backoff().await;
        }
    }

    async fn send(&self, request: &Request<'_>) -> reqwest::Result<Response> {
        let date = AmzDate::now();
        let entries = [
            request.content_md5.map(|value| (CONTENT_MD5_NAME, value)),
            Some((HOST_NAME, self.location.host())),
            request
                .checksum
                .map(|value| (X_AMZ_CHECKSUM_CRC32C_NAME, value)),
            Some((X_AMZ_CONTENT_SHA256_NAME, request.payload_hash)),
            Some((X_AMZ_DATE_NAME, date.as_str())),
            self.session_token
                .as_deref()
                .map(|value| (X_AMZ_SECURITY_TOKEN_NAME, value)),
        ];
        let mut headers = [("", ""); MAX_SIGNED_HEADERS];
        let mut len = 0;
        for (slot, entry) in headers.iter_mut().zip(entries.into_iter().flatten()) {
            *slot = entry;
            len += 1;
        }
        let authorization = self.signer.authorization(
            &CanonicalRequest {
                method: request.method.as_str(),
                uri: request.url.canonical_uri(),
                query: request.query,
                headers: headers.get(..len).unwrap_or_default(),
                payload_hash: request.payload_hash,
            },
            &date,
        );

        let mut builder = self
            .http
            .request(request.method.clone(), request.url.as_str())
            .header(AUTHORIZATION, authorization)
            .header(X_AMZ_DATE, date.as_str())
            .header(X_AMZ_CONTENT_SHA256, request.payload_hash);
        if let Some(content_md5) = request.content_md5 {
            builder = builder.header(CONTENT_MD5, content_md5);
        }
        if let Some(checksum) = request.checksum {
            builder = builder.header(X_AMZ_CHECKSUM_CRC32C, checksum);
        }
        if let Some(token) = &self.session_token {
            builder = builder.header(X_AMZ_SECURITY_TOKEN, token.as_ref());
        }
        if let Some(range) = request.range {
            builder = builder.header(RANGE, range);
        }
        if let Some(body) = request.body {
            builder = builder
                .header(CONTENT_LENGTH, body.len())
                .body(body.clone());
        }
        builder.send().await
    }
}

impl fmt::Debug for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bucket")
            .field("location", &self.location)
            .field("signer", &self.signer)
            .field("scheme", &self.scheme)
            .field("retry", &self.retry)
            .field("checksum", &self.checksum)
            .field("multi_delete", &self.multi_delete)
            .finish_non_exhaustive()
    }
}

fn retry_batch(failures: Vec<DeleteFailure>, attempts: &Attempts) -> Result<Bytes> {
    let can_retry = attempts.can_retry();
    let key_len = failures.first().map_or(0, |failure| failure.key.len());
    let mut batch = DeleteBatch::with_capacity(failures.len(), key_len);
    for failure in failures {
        if !can_retry || !RetryPolicy::is_retryable_code(&failure.code) {
            return Err(Error::DeleteFailed {
                key: failure.key.into_boxed_str(),
                code: failure.code.into_boxed_str(),
                message: failure.message.map(String::into_boxed_str),
            });
        }
        batch.push(&failure.key)?;
    }
    Ok(batch.into_body())
}

fn slice_range(body: Bytes, range: &Range<u64>) -> Bytes {
    let len = body.len() as u64;
    let start = range.start.min(len);
    let end = range.end.min(len);
    body.slice(start as usize..end as usize)
}

fn md5_base64(data: &[u8]) -> String {
    STANDARD.encode(md5::compute(data).0)
}

pub fn crc32c_base64(data: &[u8]) -> String {
    STANDARD.encode(crc_fast::crc32_iscsi(data).to_be_bytes())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/s3/src/client/tests.rs"]
mod tests;
