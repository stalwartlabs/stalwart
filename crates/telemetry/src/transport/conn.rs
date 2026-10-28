/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    TransportError,
    endpoint::{Endpoint, Transport},
};
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP1: &[u8] = b"http/1.1";

pub enum Connection {
    Http1(http1::SendRequest<Full<Bytes>>),
    Http2(http2::SendRequest<Full<Bytes>>),
}

pub struct ReceivedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub trailers: Option<HeaderMap>,
}

pub fn tls_connector(tls: &ClientConfig, transport: Transport) -> TlsConnector {
    let mut tls = tls.clone();
    tls.alpn_protocols = match transport {
        Transport::Http => vec![ALPN_H2.to_vec(), ALPN_HTTP1.to_vec()],
        Transport::Grpc => vec![ALPN_H2.to_vec()],
    };
    TlsConnector::from(Arc::new(tls))
}

impl Connection {
    pub async fn connect(
        endpoint: &Endpoint,
        transport: Transport,
        tls: Option<&TlsConnector>,
    ) -> Result<Self, TransportError> {
        let tcp = TcpStream::connect((endpoint.host(), endpoint.port()))
            .await
            .map_err(TransportError::Connect)?;
        let _ = tcp.set_nodelay(true);

        match (endpoint.is_tls(), tls) {
            (true, Some(tls)) => {
                let server_name = ServerName::try_from(endpoint.host().to_string())
                    .map_err(|_| TransportError::InvalidEndpoint(endpoint.host().into()))?;
                let stream = tls
                    .connect(server_name, tcp)
                    .await
                    .map_err(TransportError::Tls)?;
                let is_h2 = stream.get_ref().1.alpn_protocol() == Some(ALPN_H2);
                if is_h2 || transport == Transport::Grpc {
                    Self::handshake_h2(TokioIo::new(stream)).await
                } else {
                    Self::handshake_h1(TokioIo::new(stream)).await
                }
            }
            (true, None) => Err(TransportError::InvalidEndpoint(
                "TLS endpoint without TLS configuration".into(),
            )),
            (false, _) => match transport {
                Transport::Grpc => Self::handshake_h2(TokioIo::new(tcp)).await,
                Transport::Http => Self::handshake_h1(TokioIo::new(tcp)).await,
            },
        }
    }

    async fn handshake_h1<T>(io: T) -> Result<Self, TransportError>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let (sender, conn) = http1::handshake(io)
            .await
            .map_err(TransportError::Handshake)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Connection::Http1(sender))
    }

    async fn handshake_h2<T>(io: T) -> Result<Self, TransportError>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(TransportError::Handshake)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Connection::Http2(sender))
    }

    pub fn is_http2(&self) -> bool {
        matches!(self, Connection::Http2(_))
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Connection::Http1(sender) => sender.is_closed(),
            Connection::Http2(sender) => sender.is_closed(),
        }
    }

    pub async fn send(
        &mut self,
        request: Request<Full<Bytes>>,
        max_response_bytes: usize,
    ) -> Result<ReceivedResponse, TransportError> {
        let response = match self {
            Connection::Http1(sender) => {
                sender.ready().await.map_err(TransportError::Request)?;
                sender.send_request(request).await
            }
            Connection::Http2(sender) => {
                sender.ready().await.map_err(TransportError::Request)?;
                sender.send_request(request).await
            }
        }
        .map_err(TransportError::Request)?;
        read_response(response, max_response_bytes).await
    }
}

async fn read_response(
    response: Response<Incoming>,
    max_response_bytes: usize,
) -> Result<ReceivedResponse, TransportError> {
    let (parts, mut incoming) = response.into_parts();
    let mut body = Vec::new();
    let mut trailers = None;
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(TransportError::Request)?;
        match frame.into_data() {
            Ok(data) => {
                if body.len() + data.len() > max_response_bytes {
                    return Err(TransportError::ResponseTooLarge);
                }
                body.extend_from_slice(&data);
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }
    Ok(ReceivedResponse {
        status: parts.status,
        headers: parts.headers,
        body,
        trailers,
    })
}
