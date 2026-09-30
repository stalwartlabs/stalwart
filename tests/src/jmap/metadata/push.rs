/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Access, Ctx, MetaType};
use crate::utils::{account::Account, server::TestServer};
use futures::StreamExt;
use jmap_client::{
    DataType,
    event_source::{Changes, PushNotification},
};
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const SETTLE: Duration = Duration::from_millis(1500);

pub async fn test(test: &TestServer) {
    println!("Running JMAP private metadata push tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let writer = ctx.account("jane.smith@example.com");
    let bystander = ctx.account("bill@example.com");
    let parents = ctx.parents(owner).await;

    let mailbox = ctx
        .create_ok(owner, MetaType::Mailbox, &parents, 0, json!({}))
        .await;
    for sharee in [writer, bystander] {
        ctx.share(
            owner,
            MetaType::Mailbox,
            &mailbox,
            sharee,
            Some(Access::Read),
        )
        .await;
    }
    ctx.test.wait_for_tasks().await;

    let mut owner_events = subscribe(owner).await;
    let mut writer_events = subscribe(writer).await;
    let mut bystander_events = subscribe(bystander).await;
    for events in [&mut owner_events, &mut writer_events, &mut bystander_events] {
        drain(events, owner.id_string(), SETTLE).await;
    }

    ctx.update_ok(
        writer,
        owner,
        MetaType::Mailbox,
        &mailbox,
        json!({"privateMetadata/p.example": {"pushed": true}}),
    )
    .await;

    let writer_types = drain(&mut writer_events, owner.id_string(), SETTLE).await;
    assert!(
        writer_types.contains(&DataType::Mailbox),
        "the writer must be notified of its own private write, got {writer_types:?}"
    );
    for (who, events) in [
        ("owner", &mut owner_events),
        ("bystander", &mut bystander_events),
    ] {
        let types = drain(events, owner.id_string(), SETTLE).await;
        assert!(
            types.is_empty(),
            "the {who} received a push for another user's private write: {types:?}"
        );
    }

    ctx.update_ok(
        owner,
        owner,
        MetaType::Mailbox,
        &mailbox,
        json!({"metadata/x.example": {"shared": true}}),
    )
    .await;
    let owner_types = drain(&mut owner_events, owner.id_string(), SETTLE).await;
    assert!(
        owner_types.contains(&DataType::Mailbox),
        "a shared metadata write must be pushed to the owner, got {owner_types:?}"
    );

    for sharee in [writer, bystander] {
        ctx.share(owner, MetaType::Mailbox, &mailbox, sharee, None)
            .await;
    }
    ctx.cleanup(&[owner, writer, bystander]).await;
}

async fn subscribe(account: &Account) -> mpsc::Receiver<Changes> {
    let client = account.jmap_client().await;
    let mut stream = client
        .event_source(None::<Vec<_>>, false, 1.into(), None)
        .await
        .expect("event source");
    let (event_tx, event_rx) = mpsc::channel::<Changes>(100);
    tokio::spawn(async move {
        let _client = client;
        while let Some(change) = stream.next().await {
            let changes = match change {
                Ok(PushNotification::StateChange(changes)) => changes,
                Ok(PushNotification::CalendarAlert(_)) => continue,
                Err(_) => break,
            };
            if event_tx.send(changes).await.is_err() {
                break;
            }
        }
    });
    event_rx
}

async fn drain(
    events: &mut mpsc::Receiver<Changes>,
    account_id: &str,
    wait: Duration,
) -> Vec<DataType> {
    let deadline = Instant::now() + wait;
    let mut types = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(changes)) => {
                if let Some(changes) = changes.changes(account_id) {
                    types.extend(changes.map(|(data_type, _)| data_type.clone()));
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    types
}
