/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{AssertConfig, add_test_certs, jmap::JMAPTest};
use base64::{Engine, engine::general_purpose};
use common::{Caches, Core, Data, Inner, config::server::Listeners, listener::SessionData};
use ece::EcKeyComponents;
use http_proto::{HtmlResponse, ToHttpResponse, request::fetch_body};
use hyper::{StatusCode, body, header::CONTENT_ENCODING, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use jmap_client::{mailbox::Role, push_subscription::Keys};
use jmap_proto::{response::status::PushObject, types::state::State};
use services::state_manager::ece::ece_encrypt;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use store::ahash::AHashSet;
use tokio::sync::mpsc;
use types::{id::Id, type_state::DataType};
use utils::{config::Config, map::vec_map::VecMap};

const SERVER: &str = r#"
[server]
hostname = "'jmap-push.example.org'"

[http]
url = "'https://127.0.0.1:9000'"

[server.listener.jmap]
bind = ['127.0.0.1:9000']
protocol = 'http'
tls.implicit = true

[server.socket]
reuse-addr = true

[certificate.default]
cert = '%{file:{CERT}}%'
private-key = '%{file:{PK}}%'
default = true
"#;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Push Subscription tests...");

    // Create test account
    let account = params.account("jdoe@example.com");
    let client = account.client();

    // Create channels
    let (event_tx, mut event_rx) = mpsc::channel::<PushMessage>(100);

    // Create subscription keys
    let (keypair, auth_secret) = ece::generate_keypair_and_auth_secret().unwrap();
    let pubkey = keypair.pub_as_raw().unwrap();
    let keys = Keys::new(&pubkey, &auth_secret);

    let push_server = Arc::new(PushServer {
        keypair: keypair.raw_components().unwrap(),
        auth_secret: auth_secret.to_vec(),
        tx: event_tx,
        fail_requests: false.into(),
    });

    // Start mock push server
    let mut settings = Config::new(add_test_certs(SERVER)).unwrap();
    settings.resolve_all_macros().await;
    let mock_inner = Arc::new(Inner {
        shared_core: Core::parse(&mut settings, Default::default(), Default::default())
            .await
            .into_shared(),
        data: Data::parse(&mut settings),
        cache: Caches::parse(&mut settings),
        ..Default::default()
    });
    settings.errors.clear();
    settings.warnings.clear();
    let mut servers = Listeners::parse(&mut settings);
    servers.parse_tcp_acceptors(&mut settings, mock_inner.clone());

    // Start JMAP server
    servers.bind_and_drop_priv(&mut settings);
    settings.assert_no_errors();
    let _shutdown_tx = servers.spawn(|server, acceptor, shutdown_rx| {
        server.spawn(
            SessionManager::from(push_server.clone()),
            mock_inner.clone(),
            acceptor,
            shutdown_rx,
        );
    });

    // Register push notification (no encryption)
    let push_id = client
        .push_subscription_create("123", "https://127.0.0.1:9000/push", None)
        .await
        .unwrap()
        .take_id();

    // Expect push verification
    let verification = expect_push(&mut event_rx).await.unwrap_verification();
    assert_eq!(verification.push_subscription_id, push_id);

    // Update verification code
    client
        .push_subscription_verify(&push_id, verification.verification_code)
        .await
        .unwrap();

    // Create a mailbox and expect a state change
    let mailbox_id = client
        .mailbox_create("PushSubscription Test", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();

    assert_state(&mut event_rx, account.id(), &[DataType::Mailbox]).await;

    // Receive states just for the requested types
    client
        .push_subscription_update_types(&push_id, [jmap_client::DataType::Email].into())
        .await
        .unwrap();
    client
        .mailbox_update_sort_order(&mailbox_id, 123)
        .await
        .unwrap();
    expect_nothing(&mut event_rx).await;

    // Destroy subscription
    client.push_subscription_destroy(&push_id).await.unwrap();

    // Only one verification per minute is allowed
    let push_id = client
        .push_subscription_create("invalid", "https://127.0.0.1:9000/push", None)
        .await
        .unwrap()
        .take_id();
    expect_nothing(&mut event_rx).await;
    client.push_subscription_destroy(&push_id).await.unwrap();

    // Register push notification (with encryption)
    let push_id = client
        .push_subscription_create(
            "123",
            "https://127.0.0.1:9000/push?skip_checks=true", // skip_checks only works in cfg(test)
            keys.into(),
        )
        .await
        .unwrap()
        .take_id();

    // Expect push verification
    let verification = expect_push(&mut event_rx).await.unwrap_verification();
    assert_eq!(verification.push_subscription_id, push_id);

    // Update verification code
    client
        .push_subscription_verify(&push_id, verification.verification_code)
        .await
        .unwrap();

    // Failed deliveries should be re-attempted
    push_server.fail_requests.store(true, Ordering::Relaxed);
    client
        .mailbox_update_sort_order(&mailbox_id, 101)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    push_server.fail_requests.store(false, Ordering::Relaxed);
    assert_state(&mut event_rx, account.id(), &[DataType::Mailbox]).await;

    // Make a mailbox change and expect state change
    client
        .mailbox_rename(&mailbox_id, "My Mailbox")
        .await
        .unwrap();
    assert_state(&mut event_rx, account.id(), &[DataType::Mailbox]).await;
    //expect_nothing(&mut event_rx).await;

    // Multiple change updates should be grouped and pushed in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    assert_state(&mut event_rx, account.id(), &[DataType::Mailbox]).await;
    expect_nothing(&mut event_rx).await;

    // Destroy mailbox
    client.push_subscription_destroy(&push_id).await.unwrap();
    client.mailbox_destroy(&mailbox_id, true).await.unwrap();
    expect_nothing(&mut event_rx).await;

    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}

#[derive(Clone)]
pub struct SessionManager {
    pub inner: Arc<PushServer>,
}

impl From<Arc<PushServer>> for SessionManager {
    fn from(inner: Arc<PushServer>) -> Self {
        SessionManager { inner }
    }
}
pub struct PushServer {
    keypair: EcKeyComponents,
    auth_secret: Vec<u8>,
    tx: mpsc::Sender<PushMessage>,
    fail_requests: AtomicBool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
enum PushMessage {
    PushObject(PushObject),
    Verification(PushVerification),
}

impl PushMessage {
    pub fn unwrap_state_change(self) -> VecMap<Id, VecMap<DataType, State>> {
        match self {
            PushMessage::PushObject(PushObject::StateChange { changed }) => changed,
            _ => panic!("Expected PushObject"),
        }
    }

    pub fn unwrap_verification(self) -> PushVerification {
        match self {
            PushMessage::Verification(verification) => verification,
            _ => panic!("Expected Verification"),
        }
    }
}

#[derive(serde::Deserialize, Debug)]
enum PushVerificationType {
    PushVerification,
}

#[derive(serde::Deserialize, Debug)]
struct PushVerification {
    #[serde(rename = "@type")]
    _type: PushVerificationType,
    #[serde(rename = "pushSubscriptionId")]
    pub push_subscription_id: String,
    #[serde(rename = "verificationCode")]
    pub verification_code: String,
}

impl common::listener::SessionManager for SessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: common::listener::SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            let push = self.inner;
            let _ = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(session.stream),
                    service_fn(|mut req: hyper::Request<body::Incoming>| {
                        let push = push.clone();

                        async move {
                            if push.fail_requests.load(Ordering::Relaxed) {
                                return Ok(HtmlResponse::with_status(
                                    StatusCode::TOO_MANY_REQUESTS,
                                    "too many requests".to_string(),
                                )
                                .into_http_response()
                                .build());
                            }
                            let is_encrypted = req
                                .headers()
                                .get(CONTENT_ENCODING)
                                .is_some_and(|encoding| encoding.to_str().unwrap() == "aes128gcm");
                            let body = fetch_body(&mut req, 1024 * 1024, 0).await.unwrap();
                            let message = serde_json::from_slice::<PushMessage>(&if is_encrypted {
                                ece::decrypt(
                                    &push.keypair,
                                    &push.auth_secret,
                                    &general_purpose::URL_SAFE.decode(body).unwrap(),
                                )
                                .unwrap()
                            } else {
                                body
                            })
                            .unwrap();

                            //println!("Push received ({}): {:?}", is_encrypted, message);

                            push.tx.send(message).await.unwrap();

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

async fn expect_push(event_rx: &mut mpsc::Receiver<PushMessage>) -> PushMessage {
    match tokio::time::timeout(Duration::from_millis(1500), event_rx.recv()).await {
        Ok(Some(push)) => {
            //println!("Push received: {:?}", push);
            push
        }
        result => {
            panic!("Timeout waiting for push: {:?}", result);
        }
    }
}

async fn expect_nothing(event_rx: &mut mpsc::Receiver<PushMessage>) {
    match tokio::time::timeout(Duration::from_millis(1000), event_rx.recv()).await {
        Err(_) => {}
        message => {
            panic!("Received a message when expecting nothing: {:?}", message);
        }
    }
}

async fn assert_state(event_rx: &mut mpsc::Receiver<PushMessage>, id: &Id, state: &[DataType]) {
    assert_eq!(
        expect_push(event_rx)
            .await
            .unwrap_state_change()
            .get(id)
            .unwrap()
            .iter()
            .map(|x| x.0)
            .collect::<AHashSet<&DataType>>(),
        state.iter().collect::<AHashSet<&DataType>>()
    );
}

#[test]
fn ece_roundtrip() {
    for len in [1, 2, 5, 16, 256, 1024, 2048, 4096, 1024 * 1024] {
        let (keypair, auth_secret) = ece::generate_keypair_and_auth_secret().unwrap();

        let bytes: Vec<u8> = (0..len).map(|_| store::rand::random::<u8>()).collect();

        let encrypted_bytes =
            ece_encrypt(&keypair.pub_as_raw().unwrap(), &auth_secret, &bytes).unwrap();

        let decrypted_bytes = ece::decrypt(
            &keypair.raw_components().unwrap(),
            &auth_secret,
            &encrypted_bytes,
        )
        .unwrap();

        assert_eq!(bytes, decrypted_bytes, "len: {}", len);
    }
}
