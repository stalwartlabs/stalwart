/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    AssertConfig,
    utils::{server::TestServer, smtp::SmtpConnection},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{config::server::Listeners, network::SessionData};
use ece::EcKeyComponents;
use email::push::{EmailPush, Urgency};
use http_proto::{HtmlResponse, ToHttpResponse, request::fetch_body};
use hyper::{
    StatusCode, body,
    header::{AUTHORIZATION, CONTENT_ENCODING},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use jmap_client::{mailbox::Role, push_subscription::Keys};
use jmap_proto::{
    method::query::Filter,
    object::{email::EmailFilter, push_subscription::EmailPushProperty},
    request::capability::{Capabilities, Capability},
    types::state::State,
};
use registry::{
    schema::{
        enums::NetworkListenerProtocol,
        prelude::{ObjectType, SocketAddr},
        structs::{NetworkListener, SystemSettings},
    },
    types::{id::ObjectId, map::Map},
};
use serde_json::json;
use services::state_manager::ece::ece_encrypt;
use services::state_manager::email_push::build_email_push_object;
use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use store::{
    ahash::AHashSet,
    registry::{RegistryObject, bootstrap::Bootstrap},
};
use tokio::sync::mpsc;
use types::{id::Id, keyword::Keyword, type_state::DataType};
use utils::map::vec_map::VecMap;

pub async fn test(test: &TestServer) {
    println!("Running Push Subscription tests...");

    // ECE roundtrip test
    ece_roundtrip();

    // Create test account
    let account = test.account("robert@example.com");
    let client = account.jmap_client().await;

    // Create channels
    let (event_tx, mut event_rx) = mpsc::channel::<PushMessage>(100);

    // Create subscription keys
    let (keypair, auth_secret) = ece::generate_keypair_and_auth_secret().unwrap();
    let pubkey = keypair.pub_as_raw().unwrap();
    let keys = Keys::new(&pubkey, &auth_secret);

    // The server must expose a VAPID key and advertise it in the session capabilities
    let vapid_public_key = test
        .server
        .core
        .jmap
        .vapid
        .as_ref()
        .expect("A VAPID key must be configured")
        .public_key()
        .to_string();
    let advertised_key = test
        .server
        .core
        .jmap
        .capabilities
        .session
        .iter()
        .find_map(
            |(capability, capabilities)| match (capability, capabilities) {
                (Capability::WebPushVapid, Capabilities::WebPush(webpush)) => {
                    Some(webpush.application_server_key.as_str())
                }
                _ => None,
            },
        )
        .expect("The webpush-vapid capability must be advertised");
    assert_eq!(
        advertised_key, vapid_public_key,
        "The advertised applicationServerKey must match the signing key"
    );

    let push_server = Arc::new(PushServer {
        keypair: keypair.raw_components().unwrap(),
        auth_secret: auth_secret.to_vec(),
        vapid_public_key,
        endpoint_origin: "https://127.0.0.1:19000".to_string(),
        tx: event_tx,
        fail_requests: false.into(),
    });

    // Start mock push server
    let mut bp = Bootstrap::new_uninitialized(test.server.registry().clone());
    let mut servers = Listeners::default();
    servers.parse_server(
        &mut bp,
        RegistryObject {
            id: ObjectId::new(ObjectType::NetworkListener, 0u64.into()),
            object: NetworkListener {
                name: "mock-push".into(),
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
            SessionManager::from(push_server.clone()),
            test.server.inner.clone(),
            acceptor,
            shutdown_rx,
        );
    });

    // Register push notification (no encryption)
    let push_id = client
        .push_subscription_create("123", "https://127.0.0.1:19000/push", None)
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
        .push_subscription_create("invalid", "https://127.0.0.1:19000/push", None)
        .await
        .unwrap()
        .take_id();
    expect_nothing(&mut event_rx).await;
    client.push_subscription_destroy(&push_id).await.unwrap();

    // Register push notification (with encryption)
    let push_id = client
        .push_subscription_create(
            "123",
            "https://127.0.0.1:19000/push?skip_checks=true", // skip_checks only works in cfg(test)
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

    let account_id_str = account.id_string().to_string();
    let p256dh = URL_SAFE_NO_PAD.encode(&pubkey);
    let auth = URL_SAFE_NO_PAD.encode(auth_secret);
    let create = account
        .jmap_request(
            &[
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:emailpush",
            ],
            json!([[
                "PushSubscription/set",
                {
                    "create": {
                        "i0": {
                            "deviceClientId": "emailpush",
                            "url": "https://127.0.0.1:19000/push?skip_checks=true",
                            "keys": { "p256dh": p256dh, "auth": auth },
                            "types": [],
                            "emailPush": {
                                (account_id_str.clone()): {
                                    "filter": { "subject": "urgent" },
                                    "properties": ["from", "subject", "id"],
                                    "urgency": "high"
                                }
                            }
                        }
                    }
                },
                "0"
            ]]),
        )
        .await;
    let ep_id = create.created_id(0);

    let verification = expect_push(&mut event_rx).await.unwrap_verification();
    assert_eq!(verification.push_subscription_id, ep_id.to_string());
    account
        .jmap_request(
            &["urn:ietf:params:jmap:core"],
            json!([[
                "PushSubscription/set",
                { "update": { (ep_id.to_string()): { "verificationCode": verification.verification_code } } },
                "0"
            ]]),
        )
        .await;

    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "sender@example.com",
        &["robert@example.com"],
        concat!(
            "From: Sender <sender@example.com>\r\n",
            "To: robert@example.com\r\n",
            "Subject: Urgent: action required\r\n",
            "\r\n",
            "Please respond as soon as possible."
        ),
    )
    .await;
    lmtp.quit().await;

    let (push_account, emails, state) = expect_push(&mut event_rx).await.unwrap_email_push();
    assert_eq!(push_account.to_string(), account_id_str);
    assert!(state.is_some(), "EmailPush must carry the Email state");
    assert_eq!(emails.len(), 1, "expected exactly one email in the push");
    let email = emails[0].to_string();
    assert!(
        email.contains("Urgent: action required"),
        "subject missing: {email}"
    );
    assert!(
        email.contains("sender@example.com"),
        "from missing: {email}"
    );

    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "sender@example.com",
        &["robert@example.com"],
        concat!(
            "From: Sender <sender@example.com>\r\n",
            "To: robert@example.com\r\n",
            "Subject: weekly newsletter\r\n",
            "\r\n",
            "Nothing important here."
        ),
    )
    .await;
    lmtp.quit().await;
    expect_nothing(&mut event_rx).await;

    account
        .jmap_request(
            &["urn:ietf:params:jmap:core"],
            json!([[
                "PushSubscription/set",
                { "destroy": [ep_id.to_string()] },
                "0"
            ]]),
        )
        .await;

    // Test the EmailPush object builder (filters and size limits) directly
    test_email_push_object(test).await;

    test.destroy_all_mailboxes(account).await;
    test.assert_is_empty().await;
}

async fn test_email_push_object(test: &TestServer) {
    let account = test.account("robert@example.com");
    let client = account.jmap_client().await;
    let account_id = account.id().document_id();

    let mailbox_id = client
        .mailbox_create("EmailPush Object Test", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    let mailbox_doc_id = Id::from_str(&mailbox_id).unwrap().document_id();

    let email_id = client
        .email_import(
            b"From: Alice <alice@example.com>\r\nTo: robert@example.com\r\nSubject: Urgent meeting tonight\r\n\r\nPlease join the urgent meeting tonight.".to_vec(),
            [&mailbox_id],
            Some(["$notify"]),
            None,
        )
        .await
        .unwrap()
        .take_id();
    let document_id = Id::from_str(&email_id).unwrap().document_id();
    test.wait_for_tasks().await;

    let properties = vec![
        EmailPushProperty::Id,
        EmailPushProperty::From,
        EmailPushProperty::Subject,
    ];
    let config = |filter: Vec<Filter<EmailFilter>>| EmailPush {
        account_id,
        properties: properties.clone(),
        filter,
        urgency: Urgency::Normal,
    };

    // Matching subject (case-insensitive substring), full object is produced
    let value = build_email_push_object(
        &test.server,
        account_id,
        document_id,
        &config(vec![Filter::Property(EmailFilter::Subject(
            "URGENT".into(),
        ))]),
        4096,
    )
    .await
    .unwrap()
    .expect("matching subject filter must produce an object");
    let json = serde_json::to_string(&value).unwrap();
    assert!(
        json.contains("Urgent meeting tonight"),
        "subject missing: {json}"
    );
    assert!(json.contains("alice@example.com"), "from missing: {json}");

    // A collection of filters that should each either match (Some) or not (None)
    for (expected_match, filter) in [
        (
            false,
            vec![Filter::Property(EmailFilter::Subject(
                "does-not-appear".into(),
            ))],
        ),
        (
            true,
            vec![Filter::Property(EmailFilter::InMailbox(Id::from(
                mailbox_doc_id,
            )))],
        ),
        (
            false,
            vec![Filter::Property(EmailFilter::InMailbox(Id::from(
                mailbox_doc_id + 1,
            )))],
        ),
        (
            true,
            vec![Filter::Property(EmailFilter::HasKeyword(Keyword::parse(
                "$notify",
            )))],
        ),
        (
            false,
            vec![Filter::Property(EmailFilter::NotKeyword(Keyword::parse(
                "$notify",
            )))],
        ),
        (true, vec![]),
        (
            true,
            vec![
                Filter::Or,
                Filter::Property(EmailFilter::Subject("urgent".into())),
                Filter::Property(EmailFilter::From("nobody@example.com".into())),
                Filter::Close,
            ],
        ),
        (
            false,
            vec![
                Filter::And,
                Filter::Property(EmailFilter::Subject("urgent".into())),
                Filter::Property(EmailFilter::From("nobody@example.com".into())),
                Filter::Close,
            ],
        ),
    ] {
        let result = build_email_push_object(
            &test.server,
            account_id,
            document_id,
            &config(filter.clone()),
            4096,
        )
        .await
        .unwrap();
        assert_eq!(
            result.is_some(),
            expected_match,
            "filter produced the wrong match result: {filter:?}"
        );
    }

    // Size limit: a generous budget keeps every property, a tiny budget drops some (in order)
    let full =
        build_email_push_object(&test.server, account_id, document_id, &config(vec![]), 4096)
            .await
            .unwrap()
            .expect("object");
    assert_eq!(
        full.as_object().unwrap().as_vec().len(),
        3,
        "all requested properties must fit under a generous budget"
    );
    let truncated =
        build_email_push_object(&test.server, account_id, document_id, &config(vec![]), 50)
            .await
            .unwrap()
            .expect("object");
    assert!(
        truncated.as_object().unwrap().as_vec().len() < 3,
        "a tiny size budget must drop properties: {}",
        serde_json::to_string(&truncated).unwrap()
    );
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
    vapid_public_key: String,
    endpoint_origin: String,
    tx: mpsc::Sender<PushMessage>,
    fail_requests: AtomicBool,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
enum PushMessage {
    PushObject(PushObject),
    Verification(PushVerification),
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
#[serde(tag = "@type")]
enum PushObject {
    StateChange {
        changed: VecMap<Id, VecMap<DataType, State>>,
    },
    EmailPush {
        #[serde(rename = "accountId")]
        account_id: Id,
        #[serde(default)]
        emails: Vec<serde_json::Value>,
        #[serde(default)]
        state: Option<State>,
    },
    CalendarAlert {
        #[serde(rename = "accountId")]
        account_id: Id,
        #[serde(rename = "calendarEventId")]
        calendar_event_id: Id,
        uid: String,
        #[serde(rename = "recurrenceId")]
        recurrence_id: Option<String>,
        #[serde(rename = "alertId")]
        alert_id: String,
    },
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

    pub fn unwrap_email_push(self) -> (Id, Vec<serde_json::Value>, Option<State>) {
        match self {
            PushMessage::PushObject(PushObject::EmailPush {
                account_id,
                emails,
                state,
            }) => (account_id, emails, state),
            other => panic!("Expected EmailPush, got: {other:?}"),
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

impl common::network::SessionManager for SessionManager {
    #[allow(clippy::manual_async_fn)]
    fn handle<T: common::network::SessionStream>(
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

                            // Every push POST must be authenticated with a VAPID token (RFC 9749)
                            let authorization = req
                                .headers()
                                .get(AUTHORIZATION)
                                .map(|value| value.to_str().unwrap().to_string())
                                .expect("Push POST must carry a VAPID Authorization header");
                            assert_vapid_authorization(
                                &authorization,
                                &push.vapid_public_key,
                                &push.endpoint_origin,
                            );

                            let is_encrypted = req
                                .headers()
                                .get(CONTENT_ENCODING)
                                .is_some_and(|encoding| encoding.to_str().unwrap() == "aes128gcm");
                            let body = fetch_body(&mut req, 1024 * 1024, 0).await.unwrap();
                            let message = serde_json::from_slice::<PushMessage>(&if is_encrypted {
                                ece::decrypt(&push.keypair, &push.auth_secret, &body).unwrap()
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

fn assert_vapid_authorization(header: &str, expected_key: &str, expected_origin: &str) {
    let (token, key) = header
        .strip_prefix("vapid ")
        .and_then(|rest| rest.split_once(", "))
        .expect("VAPID header must be 'vapid t=<jwt>, k=<key>'");
    let jwt = token.strip_prefix("t=").expect("Missing t= parameter");
    let key = key.strip_prefix("k=").expect("Missing k= parameter");
    assert_eq!(
        key, expected_key,
        "The k= parameter must match the advertised applicationServerKey"
    );

    let parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "A JWT must have three parts");
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .expect("Each JWT part must be base64url encoded")
    };
    assert_eq!(
        decode(parts[0]),
        br#"{"typ":"JWT","alg":"ES256"}"#,
        "The JWT header must declare typ JWT and alg ES256"
    );

    let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
    assert_eq!(
        claims["aud"], expected_origin,
        "The aud claim must be the push endpoint origin"
    );
    let now = store::write::now();
    let exp = claims["exp"]
        .as_u64()
        .expect("The exp claim must be a number");
    assert!(
        exp > now && exp <= now + 24 * 3600,
        "The exp claim must be no more than 24 hours in the future (exp={exp}, now={now})"
    );
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

async fn assert_state(event_rx: &mut mpsc::Receiver<PushMessage>, id: Id, state: &[DataType]) {
    assert_eq!(
        expect_push(event_rx)
            .await
            .unwrap_state_change()
            .get(&id)
            .unwrap()
            .iter()
            .map(|x| x.0)
            .collect::<AHashSet<&DataType>>(),
        state.iter().collect::<AHashSet<&DataType>>()
    );
}

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
