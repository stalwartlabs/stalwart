/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use crate::utils::smtp::SmtpConnection;
use aws_lc_rs::hmac;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::{manager::application::Resource, telemetry::tracers::store::TracingStore};
use http_proto::{ToHttpResponse, request::fetch_body};
use hyper::{body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use jmap::api::ToJmapHttpResponse;
use jmap_proto::error::request::RequestError;
use registry::{
    schema::{
        enums::EventPolicy,
        prelude::ObjectType,
        structs::{SecretKeyOptional, SecretKeyValue, WebHook},
    },
    types::map::Map,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use store::parking_lot::Mutex;
use tokio::{net::TcpListener, sync::watch};
use trc::EventType;

struct MockWebhookEndpoint {
    pub _tx: watch::Sender<bool>,
    pub events: Mutex<Vec<serde_json::Value>>,
    pub reject: AtomicBool,
}

pub async fn test(test: &TestServer) {
    println!("Running Webhooks tests...");

    // Spawn mock webhook endpoint
    let webhook = spawn_mock_webhook_endpoint();

    // Add telemetry webhook
    let admin = test.account("admin@example.org");
    admin
        .registry_create_object(WebHook {
            enable: true,
            url: "http://127.0.0.1:8821/hook".into(),
            signature_key: SecretKeyOptional::Value(SecretKeyValue {
                secret: "ovos-moles".into(),
            }),
            throttle: 100u64.into(),
            allow_invalid_certs: true,
            events: Map::new(
                EventType::variants()
                    .iter()
                    .filter(|ev| {
                        let ev = ev.as_str();
                        ev.starts_with("smtp.connection-")
                            || ev.starts_with("delivery.dsn")
                            || ev.starts_with("message-ingest.")
                    })
                    .copied()
                    .collect(),
            ),
            events_policy: EventPolicy::Include,
            ..Default::default()
        })
        .await;
    admin.reload_settings().await;

    // Send test email
    let john = test
        .create_user_account(
            "admin@example.org",
            "jdoe@example.org",
            "this is a very strong password",
            &["john.doe@example.org"],
            "jdoe@example.org",
        )
        .await;
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.org",
        &["jdoe@example.org"],
        concat!(
            "From: bill@example.org\r\n",
            "To: jdoe@example.org\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    test.wait_for_tasks().await;

    // Enable the webhook
    webhook.assert_is_empty();
    webhook.accept();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check for events
    webhook.assert_contains(&[
        "smtp.connection-start",
        "message-ingest.",
        "delivery.dsn",
        "\"from\": \"bill@example.org\"",
        "\"jdoe@example.org\"",
    ]);

    // Cleanup
    admin.registry_destroy_all(ObjectType::WebHook).await;
    admin.reload_settings().await;
    admin.destroy_account(john).await;
    test.server
        .tracing_store()
        .purge_spans(Duration::from_secs(0), test.server.search_store().into())
        .await
        .unwrap();
    test.cleanup().await;
}

impl MockWebhookEndpoint {
    pub fn assert_contains(&self, expected: &[&str]) {
        let events =
            serde_json::to_string_pretty(&self.events.lock().drain(..).collect::<Vec<_>>())
                .unwrap();

        for string in expected {
            if !events.contains(string) {
                panic!(
                    "Expected events to contain '{}', but it did not. Events: {}",
                    string, events
                );
            }
        }
    }

    pub fn accept(&self) {
        self.reject.store(false, Ordering::Relaxed);
    }

    /*pub fn reject(&self) {
        self.reject.store(true, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.events.lock().clear();
    }*/

    pub fn assert_is_empty(&self) {
        assert!(self.events.lock().is_empty());
    }
}

fn spawn_mock_webhook_endpoint() -> Arc<MockWebhookEndpoint> {
    let (_tx, rx) = watch::channel(true);
    let endpoint_ = Arc::new(MockWebhookEndpoint {
        _tx,
        events: Mutex::new(vec![]),
        reject: true.into(),
    });

    let endpoint = endpoint_.clone();

    tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:8821")
            .await
            .unwrap_or_else(|e| {
                panic!("Failed to bind mock Webhooks server to 127.0.0.1:8821: {e}");
            });
        let mut rx_ = rx.clone();

        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {

                            let _ = http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(
                                TokioIo::new(stream),
                                service_fn(|mut req: hyper::Request<body::Incoming>| {
                                    let endpoint = endpoint.clone();

                                    async move {
                                        // Verify HMAC signature
                                        let key = hmac::Key::new(hmac::HMAC_SHA256, "ovos-moles".as_bytes());
                                        let body = fetch_body(&mut req, usize::MAX, 0).await.unwrap();
                                        let tag = STANDARD.decode(req.headers().get("X-Signature").unwrap().to_str().unwrap()).unwrap();
                                        hmac::verify(&key, &body, &tag).expect("Invalid signature");

                                        // Deserialize JSON
                                        #[derive(serde::Deserialize)]
                                        struct WebhookRequest {
                                            events: Vec<serde_json::Value>,
                                        }
                                        let request = serde_json::from_slice::<WebhookRequest>(&body)
                                        .expect("Failed to parse JSON");

                                        if !endpoint.reject.load(Ordering::Relaxed) {
                                            //let c = print!("received webhook: {}", serde_json::to_string_pretty(&request).unwrap());

                                            // Add events
                                            endpoint.events.lock().extend(request.events);

                                            Ok::<_, hyper::Error>(
                                                Resource::new("application/json", "[]".to_string().into_bytes())
                                                .into_http_response().build(),
                                            )
                                        } else {
                                            //let c = print!("rejected webhook: {}", serde_json::to_string_pretty(&request).unwrap());

                                            Ok::<_, hyper::Error>(
                                                RequestError::not_found().into_http_response().build()
                                            )
                                        }

                                    }
                                }),
                            )
                            .await;
                        }
                        Err(err) => {
                            panic!("Something went wrong: {err}" );
                        }
                    }
                },
                _ = rx_.changed() => {
                    break;
                }
            };
        }
    });

    endpoint_
}
