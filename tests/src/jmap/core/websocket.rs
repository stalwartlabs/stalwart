/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::JMAPTest;
use ahash::AHashSet;
use futures::StreamExt;
use jmap_client::{
    DataType, PushObject,
    client_ws::WebSocketMessage,
    core::{
        response::{Response, TaggedMethodResponse},
        set::SetObject,
    },
};
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn test(params: &mut JMAPTest) {
    println!("Running WebSockets tests...");

    // Authenticate all accounts
    let account = params.account("jdoe@example.com");
    let client = account.client();

    let mut ws_stream = client.connect_ws().await.unwrap();

    let (stream_tx, mut stream_rx) = mpsc::channel::<WebSocketMessage>(100);

    tokio::spawn(async move {
        while let Some(change) = ws_stream.next().await {
            stream_tx.send(change.unwrap()).await.unwrap();
        }
    });

    // Create mailbox
    let mut request = client.build();
    let create_id = request
        .set_mailbox()
        .create()
        .name("WebSocket Test")
        .create_id()
        .unwrap();
    let request_id = request.send_ws().await.unwrap();
    let mut response = expect_response(&mut stream_rx).await;
    assert_eq!(request_id, response.request_id().unwrap());
    let mailbox_id = response
        .pop_method_response()
        .unwrap()
        .unwrap_set_mailbox()
        .unwrap()
        .created(&create_id)
        .unwrap()
        .take_id();

    // Enable push notifications
    client
        .enable_push_ws(None::<Vec<_>>, None::<&str>)
        .await
        .unwrap();

    // Make changes over standard HTTP and expect a push notification via WebSockets
    client
        .mailbox_update_sort_order(&mailbox_id, 1)
        .await
        .unwrap();
    assert_state(&mut stream_rx, account.id_string(), &[DataType::Mailbox]).await;

    // Multiple changes should be grouped and delivered in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_state(&mut stream_rx, account.id_string(), &[DataType::Mailbox]).await;
    expect_nothing(&mut stream_rx).await;

    // Disable push notifications
    client.disable_push_ws().await.unwrap();

    // No more changes should be received
    let mut request = client.build();
    request.set_mailbox().destroy([&mailbox_id]);
    request.send_ws().await.unwrap();
    expect_response(&mut stream_rx)
        .await
        .pop_method_response()
        .unwrap()
        .unwrap_set_mailbox()
        .unwrap()
        .destroyed(&mailbox_id)
        .unwrap();
    expect_nothing(&mut stream_rx).await;

    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}

async fn expect_response(
    stream_rx: &mut mpsc::Receiver<WebSocketMessage>,
) -> Response<TaggedMethodResponse> {
    match tokio::time::timeout(Duration::from_millis(100), stream_rx.recv()).await {
        Ok(Some(message)) => match message {
            WebSocketMessage::Response(response) => response,
            _ => panic!("Expected response, got: {:?}", message),
        },
        result => {
            panic!("Timeout waiting for websocket: {:?}", result);
        }
    }
}

async fn assert_state(
    stream_rx: &mut mpsc::Receiver<WebSocketMessage>,
    id: &str,
    state: &[DataType],
) {
    match tokio::time::timeout(Duration::from_millis(700), stream_rx.recv()).await {
        Ok(Some(message)) => match message {
            WebSocketMessage::PushNotification(PushObject::StateChange { changed }) => {
                assert_eq!(
                    changed
                        .get(id)
                        .unwrap()
                        .keys()
                        .collect::<AHashSet<&DataType>>(),
                    state.iter().collect::<AHashSet<&DataType>>()
                );
            }
            _ => panic!("Expected state change, got: {:?}", message),
        },
        result => {
            panic!("Timeout waiting for websocket: {:?}", result);
        }
    }
}

async fn expect_nothing(stream_rx: &mut mpsc::Receiver<WebSocketMessage>) {
    match tokio::time::timeout(Duration::from_millis(1000), stream_rx.recv()).await {
        Err(_) => {}
        message => {
            panic!("Received a message when expecting nothing: {:?}", message);
        }
    }
}
