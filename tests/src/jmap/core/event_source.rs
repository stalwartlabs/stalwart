/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, mail::delivery::SmtpConnection};
use email::mailbox::INBOX_ID;
use futures::StreamExt;
use jmap_client::{
    DataType,
    event_source::{Changes, PushNotification},
    mailbox::Role,
};
use std::time::Duration;
use store::ahash::AHashSet;
use tokio::sync::mpsc;
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running EventSource tests...");

    // Create test account
    let account = params.account("jdoe@example.com");
    let client = account.client();

    let mut changes = client
        .event_source(None::<Vec<_>>, false, 1.into(), None)
        .await
        .unwrap();

    let (event_tx, mut event_rx) = mpsc::channel::<Changes>(100);

    tokio::spawn(async move {
        while let Some(change) = changes.next().await {
            if let Err(_err) = event_tx
                .send(match change.unwrap() {
                    PushNotification::StateChange(changes) => changes,
                    PushNotification::CalendarAlert(_) => unreachable!(),
                })
                .await
            {
                //println!("Error sending event: {}", _err);
                break;
            }
        }
    });

    assert_ping(&mut event_rx).await;

    // Create mailbox and expect state change
    let mailbox_id = client
        .mailbox_create("EventSource Test", None::<String>, Role::None)
        .await
        .unwrap()
        .take_id();
    assert_state(&mut event_rx, account.id_string(), &[DataType::Mailbox]).await;

    // Multiple changes should be grouped and delivered in intervals
    for num in 0..5 {
        client
            .mailbox_update_sort_order(&mailbox_id, num)
            .await
            .unwrap();
    }
    assert_state(&mut event_rx, account.id_string(), &[DataType::Mailbox]).await;
    assert_ping(&mut event_rx).await; // Pings are only received in cfg(test)

    // Ingest email and expect state change
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "bill@example.com",
        &["jdoe@example.com"],
        concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great."
        ),
    )
    .await;
    lmtp.quit().await;

    assert_state(
        &mut event_rx,
        account.id_string(),
        &[
            DataType::EmailDelivery,
            DataType::Email,
            DataType::Thread,
            DataType::Mailbox,
        ],
    )
    .await;
    assert_ping(&mut event_rx).await;

    // Destroy mailbox
    client.mailbox_destroy(&mailbox_id, true).await.unwrap();
    assert_state(&mut event_rx, account.id_string(), &[DataType::Mailbox]).await;

    // Destroy Inbox
    client
        .mailbox_destroy(&Id::from(INBOX_ID).to_string(), true)
        .await
        .unwrap();
    assert_state(
        &mut event_rx,
        account.id_string(),
        &[DataType::Email, DataType::Thread, DataType::Mailbox],
    )
    .await;
    assert_ping(&mut event_rx).await;
    assert_ping(&mut event_rx).await;

    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}

async fn assert_state(
    event_rx: &mut mpsc::Receiver<Changes>,
    account_id: &str,
    state: &[DataType],
) {
    match tokio::time::timeout(Duration::from_millis(700), event_rx.recv()).await {
        Ok(Some(changes)) => {
            assert_eq!(
                changes
                    .changes(account_id)
                    .unwrap()
                    .map(|x| x.0)
                    .collect::<AHashSet<&DataType>>(),
                state.iter().collect::<AHashSet<&DataType>>()
            );
        }
        result => {
            panic!("Timeout waiting for event {:?}: {:?}", state, result);
        }
    }
}

async fn assert_ping(event_rx: &mut mpsc::Receiver<Changes>) {
    match tokio::time::timeout(Duration::from_millis(1100), event_rx.recv()).await {
        Ok(Some(changes)) => {
            assert!(changes.changes("ping").is_some(),);
        }
        _ => {
            panic!("Did not receive ping.");
        }
    }
}
