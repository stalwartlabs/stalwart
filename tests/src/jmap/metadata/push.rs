/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Access, Ctx, MetaType, Parents, Using, changes_list, response_ids};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use futures::StreamExt;
use jmap_client::{
    DataType,
    event_source::{Changes, PushNotification},
};
use serde_json::{Value, json};
use std::{
    slice,
    time::{Duration, Instant},
};
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
    created_with_private_metadata(&ctx, owner, writer, &parents).await;
    created_next_to_a_private_update(&ctx, owner, &parents).await;
    ctx.cleanup(&[owner, writer, bystander]).await;
}

async fn created_next_to_a_private_update(ctx: &Ctx<'_>, owner: &Account, parents: &Parents) {
    let ty = MetaType::Email;
    let existing = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    ctx.test.wait_for_tasks().await;
    let mut events = subscribe(owner).await;
    drain(&mut events, owner.id_string(), SETTLE).await;

    let private = json!({"p.example": {"mixed": true}});
    let payload = ctx.payload(owner, owner, ty, parents, 0, json!({})).await;
    let response = ctx
        .method(
            owner,
            Using::Metadata,
            "Email/set",
            json!({
                "accountId": owner.id_string(),
                "create": {"c": payload},
                "update": {existing.as_str(): {"privateMetadata": private}}
            }),
        )
        .await;
    let created = response
        .pointer("/methodResponses/0/1/created/c/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Email not created: {response:?}"))
        .to_string();
    assert!(
        response
            .pointer(&format!("/methodResponses/0/1/updated/{existing}"))
            .is_some(),
        "the private-only update must be reported as updated: {response:?}"
    );
    let types = drain(&mut events, owner.id_string(), SETTLE).await;
    assert!(
        [DataType::Email, DataType::Mailbox, DataType::Thread]
            .iter()
            .all(|data_type| types.contains(data_type)),
        "a create next to a private-only update must still push its state change, got {types:?}"
    );

    ctx.assert_metadata(owner, owner, ty, &existing, json!({}), private)
        .await;
    ctx.destroy(owner, ty, &[&existing, &created]).await;
}

async fn created_with_private_metadata(
    ctx: &Ctx<'_>,
    owner: &Account,
    writer: &Account,
    parents: &Parents,
) {
    let ty = MetaType::ContactCard;
    let book = parents.address_books[0].as_str();
    ctx.share(owner, ty, book, writer, Some(Access::Write))
        .await;
    ctx.test.wait_for_tasks().await;

    let mut owner_events = subscribe(owner).await;
    let mut writer_events = subscribe(writer).await;
    for events in [&mut owner_events, &mut writer_events] {
        drain(events, owner.id_string(), SETTLE).await;
    }
    let private = json!({"p.example": {"created": true}});
    let create = async |caller: &Account, extra| {
        ctx.create(caller, owner, ty, parents, 0, extra, Using::Metadata)
            .await
            .created(0)
            .id()
            .to_string()
    };

    let owned = create(owner, json!({"privateMetadata": private})).await;
    assert_eq!(
        count_events(&mut owner_events, owner.id_string(), SETTLE).await,
        1,
        "creating an object with private metadata must push one state change"
    );

    let plain = create(writer, json!({})).await;
    let plain_pushes = count_events(&mut writer_events, owner.id_string(), SETTLE).await;
    let since = ctx.state(writer, owner, ty, Using::Metadata).await;
    let id = create(writer, json!({"privateMetadata": private})).await;
    assert_eq!(
        count_events(&mut writer_events, owner.id_string(), SETTLE).await,
        plain_pushes,
        "a sharee's create with private metadata must push what a plain create pushes"
    );
    drain(&mut owner_events, owner.id_string(), SETTLE).await;

    let changes = ctx
        .changes(writer, owner, ty, &since, json!({}), Using::Metadata)
        .await;
    assert_eq!(changes_list(&changes, "created"), slice::from_ref(&id));
    assert!(
        changes_list(&changes, "updated").is_empty(),
        "a created object must not also be reported as updated: {changes:?}"
    );
    assert_ne!(ctx.state(writer, owner, ty, Using::Metadata).await, since);

    ctx.assert_metadata(writer, owner, ty, &id, json!({}), private)
        .await;
    let found = ctx
        .query(
            writer,
            owner,
            ty,
            json!({"privateMetadataExists": "p.example"}),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        response_ids(&found),
        slice::from_ref(&id),
        "the private container of a created object must be counted for its writer"
    );

    ctx.share(owner, ty, book, writer, None).await;
    ctx.destroy(owner, ty, &[&owned, &plain, &id]).await;
}

async fn count_events(
    events: &mut mpsc::Receiver<Changes>,
    account_id: &str,
    wait: Duration,
) -> usize {
    let deadline = Instant::now() + wait;
    let mut count = 0;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Some(changes)) => {
                if changes.changes(account_id).is_some() {
                    count += 1;
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    count
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
