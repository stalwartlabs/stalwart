/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    TransportError,
    conn::{Connection, ReceivedResponse},
    endpoint::{Endpoint, Signal, Target, Transport},
    response::{Verdict, classify},
    retry::{Backoff, write_grpc_timeout},
};
use bytes::Bytes;
use http::{
    HeaderName, HeaderValue, Method, Request,
    header::{CONTENT_TYPE, HOST, TE, USER_AGENT},
};
use http_body_util::Full;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_rustls::TlsConnector;

const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const USER_AGENT_VALUE: &str = concat!("Stalwart/", env!("CARGO_PKG_VERSION"));
const CONTENT_TYPE_PROTOBUF: &str = "application/x-protobuf";
const CONTENT_TYPE_GRPC: &str = "application/grpc";
const GRPC_TIMEOUT: &str = "grpc-timeout";
const GRPC_ACCEPT_ENCODING: &str = "grpc-accept-encoding";

pub type Headers = Arc<[(HeaderName, HeaderValue)]>;

pub fn is_reserved_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with("grpc-")
        || hashify::set!(
            name.as_bytes(),
            "content-type",
            "content-length",
            "te",
            "host",
            "user-agent",
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        )
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered,
    PartialSuccess { rejected: i64, message: String },
    Rejected { reason: String },
    Deferred { reason: String },
}

pub struct Sender {
    endpoint: Endpoint,
    transport: Transport,
    target: Target,
    headers: Headers,
    tls: Option<TlsConnector>,
    conn: Option<Connection>,
    backoff: Backoff,
    next_attempt_at: Option<Instant>,
}

impl Sender {
    pub fn new(
        endpoint: Endpoint,
        transport: Transport,
        signal: Signal,
        headers: Headers,
        tls: Option<TlsConnector>,
        seed: u64,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            target: endpoint.target(transport, signal)?,
            endpoint,
            transport,
            headers,
            tls,
            conn: None,
            backoff: Backoff::new(seed),
            next_attempt_at: None,
        })
    }

    pub fn next_attempt_at(&self) -> Option<Instant> {
        self.next_attempt_at
    }

    pub async fn run(mut self, body: Bytes, deadline: Instant) -> (Self, Outcome) {
        let outcome = self.send(body, deadline).await;
        (self, outcome)
    }

    pub async fn send(&mut self, body: Bytes, deadline: Instant) -> Outcome {
        let mut last_error = None;
        let mut stale_retried = false;
        loop {
            if let Some(at) = self.next_attempt_at {
                if at >= deadline {
                    return Outcome::Deferred {
                        reason: last_error
                            .unwrap_or_else(|| "Retry delayed past the export timeout".to_string()),
                    };
                }
                sleep_until(at).await;
                self.next_attempt_at = None;
            }

            let reused = self.conn.is_some();
            match timeout_at(deadline, self.attempt(&body, deadline)).await {
                Err(_) => {
                    self.conn = None;
                    self.schedule_retry(None);
                    return Outcome::Deferred {
                        reason: last_error.unwrap_or_else(|| "Export timed out".to_string()),
                    };
                }
                Ok(Ok(response)) => match classify(self.transport, &response, SystemTime::now()) {
                    Verdict::Success => {
                        self.backoff.reset();
                        return Outcome::Delivered;
                    }
                    Verdict::PartialSuccess { rejected, message } => {
                        self.backoff.reset();
                        return Outcome::PartialSuccess { rejected, message };
                    }
                    Verdict::Drop { reason } => {
                        self.backoff.reset();
                        return Outcome::Rejected { reason };
                    }
                    Verdict::Retry { delay, reason } => {
                        self.schedule_retry(delay);
                        last_error = Some(reason);
                    }
                },
                Ok(Err(err)) => {
                    self.conn = None;
                    if !err.is_retryable() {
                        return Outcome::Rejected {
                            reason: err.to_string(),
                        };
                    }
                    if reused && !stale_retried && matches!(err, TransportError::Request(_)) {
                        stale_retried = true;
                        continue;
                    }
                    self.schedule_retry(None);
                    last_error = Some(err.to_string());
                }
            }
        }
    }

    fn schedule_retry(&mut self, server_delay: Option<Duration>) {
        let delay = self
            .backoff
            .next_delay()
            .max(server_delay.unwrap_or_default());
        self.next_attempt_at = Some(Instant::now() + delay);
    }

    async fn attempt(
        &mut self,
        body: &Bytes,
        deadline: Instant,
    ) -> Result<ReceivedResponse, TransportError> {
        let conn = match self.conn.take().filter(|conn| !conn.is_closed()) {
            Some(conn) => self.conn.insert(conn),
            None => self.conn.insert(
                Connection::connect(&self.endpoint, self.transport, self.tls.as_ref()).await?,
            ),
        };
        let request = build_request(
            self.transport,
            &self.target,
            &self.headers,
            conn.is_http2(),
            body.clone(),
            deadline,
        )?;
        conn.send(request, MAX_RESPONSE_BYTES).await
    }
}

fn build_request(
    transport: Transport,
    target: &Target,
    headers: &[(HeaderName, HeaderValue)],
    is_http2: bool,
    body: Bytes,
    deadline: Instant,
) -> Result<Request<Full<Bytes>>, TransportError> {
    let mut builder = Request::builder().method(Method::POST);
    if is_http2 {
        builder = builder.uri(target.absolute_form.clone());
    } else {
        builder = builder
            .uri(target.origin_form.clone())
            .header(HOST, target.host.clone());
    }
    builder = builder.header(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    match transport {
        Transport::Http => {
            builder = builder.header(
                CONTENT_TYPE,
                HeaderValue::from_static(CONTENT_TYPE_PROTOBUF),
            );
        }
        Transport::Grpc => {
            let mut timeout = [0u8; 16];
            let timeout = write_grpc_timeout(
                deadline.saturating_duration_since(Instant::now()),
                &mut timeout,
            );
            builder = builder
                .header(CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE_GRPC))
                .header(TE, HeaderValue::from_static("trailers"))
                .header(GRPC_ACCEPT_ENCODING, HeaderValue::from_static("identity"))
                .header(
                    GRPC_TIMEOUT,
                    HeaderValue::from_bytes(timeout)
                        .map_err(|err| TransportError::InvalidHeader(err.to_string().into()))?,
                );
        }
    }
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(body))
        .map_err(|err| TransportError::InvalidHeader(err.to_string().into()))
}
