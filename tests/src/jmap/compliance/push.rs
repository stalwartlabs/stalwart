/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_contains, check_eq};
use crate::{AssertConfig, utils::server::TestServer};
use common::{config::server::Listeners, network::SessionData};
use futures::StreamExt;
use http_proto::{HtmlResponse, ToHttpResponse, request::fetch_body};
use hyper::{body, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        prelude::{ObjectType, SocketAddr},
        structs::{NetworkListener, SystemSettings},
    },
    types::{id::ObjectId, map::Map},
};
use serde_json::{Value, json};
use std::{str::FromStr, time::Duration};
use store::registry::{RegistryObject, bootstrap::Bootstrap};
use tokio::sync::{Mutex, mpsc};

const PUSH_URL: &str = "https://127.0.0.1:19000/push";

struct PushState {
    rx: Mutex<mpsc::Receiver<Value>>,
}

#[derive(Clone)]
struct SessionManager {
    tx: mpsc::Sender<Value>,
}

pub async fn run(test: &TestServer, ctx: &CompCtx<'_>) {
    println!("[compliance] push");

    let (event_tx, event_rx) = mpsc::channel::<Value>(100);

    let mut bp = Bootstrap::new_uninitialized(test.server.registry().clone());
    let mut servers = Listeners::default();
    servers.parse_server(
        &mut bp,
        RegistryObject {
            id: ObjectId::new(ObjectType::NetworkListener, 0u64.into()),
            object: NetworkListener {
                name: "mock-push-compliance".into(),
                bind: Map::new(vec![SocketAddr::from_str("127.0.0.1:19000").unwrap()]),
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
    let _shutdown_tx = servers.spawn(|server, acceptor, shutdown_rx| {
        server.spawn(
            SessionManager {
                tx: event_tx.clone(),
            },
            test.server.inner.clone(),
            acceptor,
            shutdown_rx,
        );
    });

    let state = PushState {
        rx: Mutex::new(event_rx),
    };

    ctx.run(
        "push-subscription/push-subscription-reject-non-https",
        reject_non_https(ctx),
    )
    .await;
    ctx.run(
        "push-subscription/push-subscription-receives-notification",
        receives_notification(ctx, &state),
    )
    .await;
    ctx.run("push-subscription/push-subscription-create", create(ctx))
        .await;
    ctx.run("push-subscription/push-subscription-get", get(ctx))
        .await;
    ctx.run("push-subscription/push-subscription-destroy", destroy(ctx))
        .await;
    ctx.run(
        "push-subscription/push-subscription-types-filter",
        types_filter(ctx),
    )
    .await;
    ctx.run(
        "push-subscription/push-subscription-verification",
        verification(ctx),
    )
    .await;

    ctx.run(
        "push-eventsource/eventsource-connect",
        eventsource_connect(ctx),
    )
    .await;
    ctx.run(
        "push-eventsource/eventsource-receives-state-change",
        eventsource_receives_state_change(ctx),
    )
    .await;
    ctx.run(
        "push-eventsource/eventsource-types-filter",
        eventsource_types_filter(ctx),
    )
    .await;
    ctx.run(
        "push-eventsource/eventsource-closeafter",
        eventsource_closeafter(ctx),
    )
    .await;
}

impl common::network::SessionManager for SessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: common::network::SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let tx = self.tx;
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(session.stream),
                    service_fn(|mut req: hyper::Request<body::Incoming>| {
                        let tx = tx.clone();
                        async move {
                            let body = fetch_body(&mut req, 1024 * 1024, 0).await.unwrap();
                            if let Ok(message) = serde_json::from_slice::<Value>(&body) {
                                let _ = tx.send(message).await;
                            }
                            Ok::<_, hyper::Error>(
                                HtmlResponse::new("ok".to_string())
                                    .into_http_response()
                                    .build(),
                            )
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

async fn expect_push(state: &PushState, predicate: impl Fn(&Value) -> bool) -> Option<Value> {
    let mut rx = state.rx.lock().await;
    let deadline = Duration::from_secs(10);
    loop {
        match tokio::time::timeout(deadline, rx.recv()).await {
            Ok(Some(message)) => {
                if predicate(&message) {
                    return Some(message);
                }
            }
            _ => return None,
        }
    }
}

async fn destroy_subscription(ctx: &CompCtx<'_>, id: &str) {
    ctx.primary
        .jmap_method_call("PushSubscription/set", json!({ "destroy": [id] }))
        .await;
}

async fn reject_non_https(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "bad": {
                        "deviceClientId": "jmap-test-reject-http",
                        "url": "http://example.com/push"
                    }
                }
            }),
        )
        .await;
    check(
        !resp.method_response()["notCreated"]["bad"].is_null(),
        "Server MUST reject PushSubscription with non-https URL",
    )
}

async fn receives_notification(ctx: &CompCtx<'_>, state: &PushState) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "psNotify": {
                        "deviceClientId": "jmap-test-device-notify",
                        "url": PUSH_URL,
                        "types": null
                    }
                }
            }),
        )
        .await;
    let ps_id = create_resp.method_response()["created"]["psNotify"]["id"]
        .as_str()
        .map(|s| s.to_string());
    let ps_id = match ps_id {
        Some(id) => id,
        None => {
            return check(false, "Subscription should be created");
        }
    };

    let verification = expect_push(state, |e| {
        e["@type"] == json!("PushVerification") && e["pushSubscriptionId"] == json!(ps_id)
    })
    .await;
    if let Some(verification) = verification
        && let Some(code) = verification["verificationCode"].as_str()
    {
        let mut update = serde_json::Map::new();
        update.insert(ps_id.clone(), json!({ "verificationCode": code }));
        ctx.primary
            .jmap_method_call("PushSubscription/set", json!({ "update": update }))
            .await;
    }

    let mut mailbox_ids = serde_json::Map::new();
    mailbox_ids.insert(ctx.role("inbox").to_string(), json!(true));
    let email_resp = ctx
        .primary
        .jmap_method_call(
            "Email/set",
            json!({
                "accountId": ctx.account_id(),
                "create": {
                    "pushEmail": {
                        "mailboxIds": mailbox_ids,
                        "from": [{ "name": "Push", "email": "push@example.com" }],
                        "to": [{ "name": "User", "email": "user@example.com" }],
                        "subject": "Push notification test",
                        "bodyStructure": { "type": "text/plain", "partId": "1" },
                        "bodyValues": { "1": { "value": "trigger push" } }
                    }
                }
            }),
        )
        .await;
    let email_id = email_resp.method_response()["created"]["pushEmail"]["id"]
        .as_str()
        .map(|s| s.to_string());

    let notification = expect_push(state, |e| e["@type"] == json!("StateChange")).await;

    let result = match &notification {
        Some(n) => check_eq(&n["@type"], &json!("StateChange"), "@type"),
        None => check(
            false,
            "Server MUST send push notification after state change",
        ),
    };

    destroy_subscription(ctx, &ps_id).await;
    if let Some(email_id) = email_id {
        ctx.primary
            .jmap_method_call(
                "Email/set",
                json!({ "accountId": ctx.account_id(), "destroy": [email_id] }),
            )
            .await;
    }

    result
}

async fn create(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "ps1": {
                        "deviceClientId": "jmap-test-device-001",
                        "url": PUSH_URL,
                        "types": null
                    }
                }
            }),
        )
        .await;
    let created = &resp.method_response()["created"]["ps1"];
    let outcome = check(!created.is_null(), "Subscription should be created")
        .and_then(|_| check(created["id"].is_string(), "Subscription should have an id"));
    if let Some(id) = created["id"].as_str() {
        destroy_subscription(ctx, id).await;
    }
    outcome
}

async fn get(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "psGet": {
                        "deviceClientId": "jmap-test-device-get",
                        "url": PUSH_URL,
                        "types": ["Email"]
                    }
                }
            }),
        )
        .await;
    let ps_id = match resp.method_response()["created"]["psGet"]["id"].as_str() {
        Some(id) => id.to_string(),
        None => return check(false, "Subscription should be created"),
    };

    let get_resp = ctx
        .primary
        .jmap_method_call("PushSubscription/get", json!({ "ids": [ps_id.clone()] }))
        .await;
    let list = get_resp.method_response()["list"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let outcome = (|| {
        check_eq(list.len(), 1, "list length")?;
        check_eq(&list[0]["id"], &json!(ps_id), "id")?;
        check_eq(
            &list[0]["deviceClientId"],
            &json!("jmap-test-device-get"),
            "deviceClientId",
        )?;
        if let Some(url) = list[0]["url"].as_str() {
            check_contains(url, PUSH_URL, "url")?;
        }
        Ok(())
    })();

    destroy_subscription(ctx, &ps_id).await;
    outcome
}

async fn destroy(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "psDel": {
                        "deviceClientId": "jmap-test-device-del",
                        "url": PUSH_URL
                    }
                }
            }),
        )
        .await;
    let ps_id = match create_resp.method_response()["created"]["psDel"]["id"].as_str() {
        Some(id) => id.to_string(),
        None => return check(false, "Subscription should be created"),
    };

    let destroy_resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({ "destroy": [ps_id.clone()] }),
        )
        .await;
    let destroyed = &destroy_resp.method_response()["destroyed"];
    check(
        destroyed.is_array(),
        format!(
            "PushSubscription/set destroyed must be an array, got {}",
            destroyed
        ),
    )?;
    check(
        destroyed
            .as_array()
            .map(|a| a.iter().any(|v| v == &json!(ps_id)))
            .unwrap_or(false),
        "destroyed must include subscription id",
    )?;

    let get_resp = ctx
        .primary
        .jmap_method_call("PushSubscription/get", json!({ "ids": [ps_id.clone()] }))
        .await;
    let not_found = &get_resp.method_response()["notFound"];
    check(
        not_found.is_array(),
        format!(
            "PushSubscription/get notFound MUST be a String[], got {}",
            not_found
        ),
    )?;
    check(
        not_found
            .as_array()
            .map(|a| a.iter().any(|v| v == &json!(ps_id)))
            .unwrap_or(false),
        "notFound must include subscription id",
    )
}

async fn types_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "psTypes": {
                        "deviceClientId": "jmap-test-device-types",
                        "url": PUSH_URL,
                        "types": ["Email", "Mailbox"]
                    }
                }
            }),
        )
        .await;
    let created = &resp.method_response()["created"]["psTypes"];
    let outcome = check(!created.is_null(), "Subscription should be created");
    if let Some(id) = created["id"].as_str() {
        destroy_subscription(ctx, id).await;
    }
    outcome
}

async fn verification(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "PushSubscription/set",
            json!({
                "create": {
                    "psVerify": {
                        "deviceClientId": "jmap-test-device-verify",
                        "url": PUSH_URL
                    }
                }
            }),
        )
        .await;
    let created = &resp.method_response()["created"]["psVerify"];
    if created.is_null() {
        return Ok(());
    }
    let outcome = check(created["id"].is_string(), "Subscription should have an id");
    if let Some(id) = created["id"].as_str() {
        destroy_subscription(ctx, id).await;
    }
    outcome
}

fn event_source_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

async fn eventsource_connect(ctx: &CompCtx<'_>) -> TestOutcome {
    let url = ctx.event_source_url("*", "no", "0");
    let response = event_source_client()
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, ctx.primary.basic_auth())
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|e| super::Fail::Assert(format!("EventSource connection failed: {e}")))?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    drop(response);

    check_eq(status, 200, "status")?;
    check_contains(&content_type, "text/event-stream", "content-type")
}

async fn eventsource_receives_state_change(ctx: &CompCtx<'_>) -> TestOutcome {
    let url = ctx.event_source_url("*", "no", "0");
    let response = event_source_client()
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, ctx.primary.basic_auth())
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|e| super::Fail::Assert(format!("EventSource connection failed: {e}")))?;
    check_eq(response.status().as_u16(), 200, "status")?;

    let mut stream = response.bytes_stream();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut mailbox_ids = serde_json::Map::new();
    mailbox_ids.insert(ctx.role("inbox").to_string(), json!(true));
    let email_resp = ctx
        .primary
        .jmap_method_call(
            "Email/set",
            json!({
                "accountId": ctx.account_id(),
                "create": {
                    "esTest": {
                        "mailboxIds": mailbox_ids,
                        "from": [{ "name": "ES", "email": "es@example.com" }],
                        "to": [{ "name": "User", "email": "user@example.com" }],
                        "subject": "EventSource test",
                        "bodyStructure": { "type": "text/plain", "partId": "1" },
                        "bodyValues": { "1": { "value": "trigger state change" } }
                    }
                }
            }),
        )
        .await;
    let email_id = email_resp.method_response()["created"]["esTest"]["id"]
        .as_str()
        .map(|s| s.to_string());

    let mut buffer = String::new();
    let mut state_change: Option<Value> = None;

    let read_result = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => break,
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(idx) = buffer.find('\n') {
                let line = buffer[..idx].trim().to_string();
                buffer = buffer[idx + 1..].to_string();
                if let Some(data) = line.strip_prefix("data:")
                    && let Ok(value) = serde_json::from_str::<Value>(data.trim())
                    && value["@type"] == json!("StateChange")
                {
                    state_change = Some(value);
                    return;
                }
            }
        }
    })
    .await;

    let _ = read_result;
    drop(stream);

    if let Some(email_id) = email_id {
        ctx.primary
            .jmap_method_call(
                "Email/set",
                json!({ "accountId": ctx.account_id(), "destroy": [email_id] }),
            )
            .await;
    }

    let value = state_change
        .ok_or_else(|| super::Fail::Assert("Did not receive StateChange event".to_string()))?;
    check_eq(&value["@type"], &json!("StateChange"), "@type")?;
    check(
        !value["changed"].is_null(),
        "StateChange must have changed property",
    )
}

async fn eventsource_types_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let url = ctx.event_source_url("Email", "no", "0");
    let response = event_source_client()
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, ctx.primary.basic_auth())
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|e| super::Fail::Assert(format!("EventSource connection failed: {e}")))?;
    let status = response.status().as_u16();
    drop(response);
    check_eq(status, 200, "status")
}

async fn eventsource_closeafter(ctx: &CompCtx<'_>) -> TestOutcome {
    let url = ctx.event_source_url("*", "state", "0");
    let response = event_source_client()
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, ctx.primary.basic_auth())
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .map_err(|e| super::Fail::Assert(format!("EventSource connection failed: {e}")))?;
    let status = response.status().as_u16();
    drop(response);
    check_eq(status, 200, "status")
}
