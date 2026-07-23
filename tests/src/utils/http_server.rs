/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{AssertConfig, utils::server::TestServer};
use ahash::AHashMap;
use common::{config::server::Listeners, network::SessionData};
use http_proto::{HttpResponse, request::fetch_body};
use hyper::{Method, Uri, body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        prelude::{ObjectType, SocketAddr},
        structs::{NetworkListener, SystemSettings},
    },
    types::{id::ObjectId, map::Map},
};
use std::{str::FromStr, sync::Arc};
use store::registry::{RegistryObject, bootstrap::Bootstrap};
use tokio::sync::watch;

#[derive(Clone)]
pub struct HttpSessionManager {
    inner: HttpRequestHandler,
}

pub type HttpRequestHandler = Arc<dyn Fn(HttpMessage) -> HttpResponse + Sync + Send>;

#[derive(Debug)]
pub struct HttpMessage {
    pub method: Method,
    pub headers: AHashMap<String, String>,
    pub uri: Uri,
    pub body: Option<Vec<u8>>,
}

impl HttpMessage {
    pub fn get_url_encoded(&self, key: &str) -> Option<String> {
        form_urlencoded::parse(self.body.as_ref()?.as_slice())
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.into_owned())
    }
}

pub async fn spawn_mock_http_server(
    test: &TestServer,
    handler: HttpRequestHandler,
    port: u16,
) -> (watch::Sender<bool>, watch::Receiver<bool>) {
    // Start mock HTTP server
    let mut bp = Bootstrap::new_uninitialized(test.server.registry().clone());
    let mut servers = Listeners::default();
    servers.parse_server(
        &mut bp,
        RegistryObject {
            id: ObjectId::new(ObjectType::NetworkListener, 0u64.into()),
            object: NetworkListener {
                name: "mock-http".into(),
                bind: Map::new(vec![
                    SocketAddr::from_str(&format!("127.0.0.1:{port}")).unwrap(),
                ]),
                protocol: NetworkListenerProtocol::Http,
                tls_implicit: true,
                use_tls: true,
                socket_reuse_address: true,
                socket_reuse_port: true,
                ..Default::default()
            },
            revision: 0,
        },
        &SystemSettings::default(),
    );
    servers
        .parse_tcp_acceptors(&mut bp, test.server.inner.clone())
        .await;
    servers.bind_and_drop_priv(&mut bp);
    bp.assert_no_errors();
    servers.spawn(|server, acceptor, shutdown_rx| {
        server.spawn(
            HttpSessionManager {
                inner: handler.clone(),
            },
            test.server.inner.clone(),
            acceptor,
            shutdown_rx,
        );
    })
}

impl common::network::SessionManager for HttpSessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: common::network::SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let sender = self.inner;
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(session.stream),
                    service_fn(|mut req: hyper::Request<body::Incoming>| {
                        let sender = sender.clone();

                        async move {
                            let response = sender(HttpMessage {
                                method: req.method().clone(),
                                uri: req.uri().clone(),
                                headers: req
                                    .headers()
                                    .iter()
                                    .map(|(k, v)| {
                                        (k.as_str().to_lowercase(), v.to_str().unwrap().to_string())
                                    })
                                    .collect(),
                                body: fetch_body(&mut req, 1024 * 1024, 0).await,
                            });

                            Ok::<_, hyper::Error>(response.build())
                        }
                    }),
                )
                .await;
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}
