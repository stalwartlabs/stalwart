/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents, Using, changes_list, sorted, updated_properties};
use crate::utils::{account::Account, server::TestServer};
use serde_json::json;

const COUNT_PROPERTIES: [&str; 4] = [
    "totalEmails",
    "totalThreads",
    "unreadEmails",
    "unreadThreads",
];

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata changes tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::ALL {
        if ty.has_changes() {
            metadata_only_changes(&ctx, owner, &parents, ty).await;
            paging(&ctx, owner, &parents, ty).await;
            created_and_destroyed(&ctx, owner, &parents, ty).await;
        } else {
            state_only(&ctx, owner, &parents, ty).await;
        }
    }
    mailbox_union(&ctx, owner, &parents).await;

    ctx.cleanup(&[owner]).await;
}

async fn metadata_only_changes(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let a = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({"metadata": {"x.example": {"v": 1}}}),
        )
        .await;
    let b = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let s0 = ctx.state(owner, owner, ty, Using::Metadata).await;
    let plain_s0 = ctx.state(owner, owner, ty, Using::Plain).await;
    assert_eq!(
        s0,
        plain_s0,
        "{}: states differ without private data",
        ty.name()
    );

    ctx.update_ok(owner, owner, ty, &a, json!({"metadata/x.example/v": 2}))
        .await;
    let response = ctx
        .changes(owner, owner, ty, &s0, json!({}), Using::Metadata)
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&a]),
        "{response:?}"
    );
    assert!(
        changes_list(&response, "created").is_empty(),
        "{response:?}"
    );
    assert!(
        changes_list(&response, "destroyed").is_empty(),
        "{response:?}"
    );
    assert_eq!(
        updated_properties(&response),
        Some(vec!["metadata".to_string()]),
        "{}: a metadata-only page must list metadata: {response:?}",
        ty.name()
    );
    let s1 = response.new_state().to_string();
    assert_ne!(
        s0,
        s1,
        "{}: a metadata write did not advance the state",
        ty.name()
    );

    ctx.update_ok(
        owner,
        owner,
        ty,
        &a,
        json!({"privateMetadata/p.example": {"n": 1}}),
    )
    .await;
    let response = ctx
        .changes(owner, owner, ty, &s1, json!({}), Using::Metadata)
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&a]),
        "{response:?}"
    );
    assert_eq!(
        updated_properties(&response),
        Some(vec!["privateMetadata".to_string()]),
        "{}: {response:?}",
        ty.name()
    );
    let s2 = response.new_state().to_string();
    assert_ne!(s1, s2);
    assert_eq!(ctx.state(owner, owner, ty, Using::Metadata).await, s2);

    let response = ctx
        .changes(owner, owner, ty, &s0, json!({}), Using::Metadata)
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&a]),
        "{response:?}"
    );
    assert_eq!(
        updated_properties(&response),
        Some(vec!["metadata".to_string(), "privateMetadata".to_string()]),
        "{}: {response:?}",
        ty.name()
    );
    assert_eq!(response.new_state(), s2);

    let response = ctx
        .changes(
            owner,
            owner,
            ty,
            &s0,
            json!({"ignoreMetadataOnlyChanges": true}),
            Using::Metadata,
        )
        .await;
    assert!(
        changes_list(&response, "updated").is_empty(),
        "{}: metadata-only ids must be ignored: {response:?}",
        ty.name()
    );
    assert_eq!(updated_properties(&response), None, "{response:?}");
    assert_eq!(
        response.new_state(),
        s2,
        "{}: the state must still advance when ignoring metadata-only changes",
        ty.name()
    );

    let plain_state = ctx.state(owner, owner, ty, Using::Plain).await;
    assert_ne!(
        plain_state,
        plain_s0,
        "{}: shared metadata must advance the state",
        ty.name()
    );
    let response = ctx
        .changes(owner, owner, ty, &plain_s0, json!({}), Using::Plain)
        .await;
    assert!(
        changes_list(&response, "updated").is_empty(),
        "{}: clients without the capability must not see metadata-only changes: {response:?}",
        ty.name()
    );
    assert_eq!(response.new_state(), plain_state);

    ctx.update_ok(owner, owner, ty, &b, ty.rename_patch(&ctx.unique(ty)))
        .await;
    let response = ctx
        .changes(owner, owner, ty, &s0, json!({}), Using::Metadata)
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&a, &b]),
        "{response:?}"
    );
    assert_eq!(
        updated_properties(&response),
        None,
        "{}: a page mixing full and metadata-only updates must not list properties: {response:?}",
        ty.name()
    );
    for (arguments, using) in [
        (json!({"ignoreMetadataOnlyChanges": true}), Using::Metadata),
        (json!({}), Using::Plain),
    ] {
        let since = if using == Using::Plain {
            &plain_s0
        } else {
            &s0
        };
        let response = ctx.changes(owner, owner, ty, since, arguments, using).await;
        assert_eq!(
            changes_list(&response, "updated"),
            sorted(&[&b]),
            "{}: {response:?}",
            ty.name()
        );
        assert_eq!(updated_properties(&response), None, "{response:?}");
    }

    let mut patch = ty.rename_patch(&ctx.unique(ty));
    if let Some(patch) = patch.as_object_mut() {
        patch.insert("metadata/x.example/v".into(), 3.into());
    }
    ctx.update_ok(owner, owner, ty, &a, patch).await;
    let response = ctx
        .changes(
            owner,
            owner,
            ty,
            &s0,
            json!({"ignoreMetadataOnlyChanges": true}),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&a, &b]),
        "{}: ids with other changes must stay: {response:?}",
        ty.name()
    );

    ctx.destroy(owner, ty, &[&a, &b]).await;
}

async fn paging(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let a = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let b = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let since = ctx.state(owner, owner, ty, Using::Metadata).await;

    for n in 0..3 {
        ctx.update_ok(
            owner,
            owner,
            ty,
            &a,
            json!({"metadata/x.example": {"n": n}}),
        )
        .await;
    }
    ctx.update_ok(owner, owner, ty, &b, ty.rename_patch(&ctx.unique(ty)))
        .await;

    let response = ctx
        .changes(
            owner,
            owner,
            ty,
            &since,
            json!({"ignoreMetadataOnlyChanges": true, "maxChanges": 1}),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&b]),
        "{}: paging must run over the filtered changes: {response:?}",
        ty.name()
    );

    ctx.destroy(owner, ty, &[&a, &b]).await;
}

async fn created_and_destroyed(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let since = ctx.state(owner, owner, ty, Using::Metadata).await;
    let id = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata/p.example": {"n": 1}}),
    )
    .await;
    ctx.destroy(owner, ty, &[&id]).await;

    let response = ctx
        .changes(owner, owner, ty, &since, json!({}), Using::Metadata)
        .await;
    for kind in ["created", "updated"] {
        assert!(
            !changes_list(&response, kind).contains(&id),
            "{}: an object created and destroyed since the old state is listed in {kind}: {response:?}",
            ty.name()
        );
    }
}

async fn state_only(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let id = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let s0 = ctx.state(owner, owner, ty, Using::Metadata).await;
    let plain_s0 = ctx.state(owner, owner, ty, Using::Plain).await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/x.example": {"a": 1}}),
    )
    .await;
    let s1 = ctx.state(owner, owner, ty, Using::Metadata).await;
    let plain_s1 = ctx.state(owner, owner, ty, Using::Plain).await;
    assert_ne!(
        s0,
        s1,
        "{}: a metadata write must advance /get state",
        ty.name()
    );
    assert_ne!(
        plain_s0,
        plain_s1,
        "{}: shared metadata advances every state",
        ty.name()
    );

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata/x.example": {"a": 1}}),
    )
    .await;
    let s2 = ctx.state(owner, owner, ty, Using::Metadata).await;
    assert_ne!(
        s1,
        s2,
        "{}: a private write must advance the writer's state",
        ty.name()
    );
    assert_eq!(
        ctx.state(owner, owner, ty, Using::Plain).await,
        plain_s1,
        "{}: private writes are invisible without the capability",
        ty.name()
    );

    ctx.destroy(owner, ty, &[&id]).await;
}

async fn mailbox_union(ctx: &Ctx<'_>, owner: &Account, parents: &Parents) {
    let mailbox = ctx
        .create_ok(owner, MetaType::Mailbox, parents, 0, json!({}))
        .await;
    let other = ctx
        .create_ok(owner, MetaType::Mailbox, parents, 0, json!({}))
        .await;
    let since = ctx
        .state(owner, owner, MetaType::Mailbox, Using::Metadata)
        .await;

    ctx.update_ok(
        owner,
        owner,
        MetaType::Mailbox,
        &other,
        json!({"metadata/x.example": {"color": "red"}}),
    )
    .await;
    ctx.method(
        owner,
        Using::Plain,
        "Email/set",
        json!({
            "accountId": owner.id_string(),
            "create": {"e": {
                "mailboxIds": {mailbox.as_str(): true},
                "subject": "count change",
                "from": [{"email": "metadata@example.com"}],
                "bodyValues": {"1": {"value": "count change"}},
                "textBody": [{"partId": "1", "type": "text/plain"}]
            }}
        }),
    )
    .await;

    let response = ctx
        .changes(
            owner,
            owner,
            MetaType::Mailbox,
            &since,
            json!({}),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&mailbox, &other]),
        "{response:?}"
    );
    let mut expected = COUNT_PROPERTIES
        .iter()
        .map(|property| property.to_string())
        .chain(["metadata".to_string()])
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(
        updated_properties(&response),
        Some(expected),
        "count and metadata changes must be reported as their union: {response:?}"
    );

    let response = ctx
        .changes(
            owner,
            owner,
            MetaType::Mailbox,
            &since,
            json!({"ignoreMetadataOnlyChanges": true}),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&mailbox]),
        "{response:?}"
    );
    let counts = sorted(&COUNT_PROPERTIES);
    assert_eq!(
        updated_properties(&response),
        Some(counts.clone()),
        "a count-only page must keep the count names when metadata-only changes are ignored: {response:?}"
    );

    let since = ctx
        .state(owner, owner, MetaType::Mailbox, Using::Metadata)
        .await;
    ctx.update_ok(
        owner,
        owner,
        MetaType::Mailbox,
        &mailbox,
        json!({"metadata/x.example": {"color": "blue"}}),
    )
    .await;
    ctx.method(
        owner,
        Using::Plain,
        "Email/set",
        json!({
            "accountId": owner.id_string(),
            "create": {"e": {
                "mailboxIds": {mailbox.as_str(): true},
                "subject": "second count change",
                "from": [{"email": "metadata@example.com"}],
                "bodyValues": {"1": {"value": "count change"}},
                "textBody": [{"partId": "1", "type": "text/plain"}]
            }}
        }),
    )
    .await;
    let response = ctx
        .changes(
            owner,
            owner,
            MetaType::Mailbox,
            &since,
            json!({"ignoreMetadataOnlyChanges": true}),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        changes_list(&response, "updated"),
        sorted(&[&mailbox]),
        "a mailbox whose counts also changed must stay: {response:?}"
    );
    assert_eq!(
        updated_properties(&response),
        Some(counts),
        "ignored metadata must not be listed next to the counts: {response:?}"
    );

    ctx.destroy(owner, MetaType::Mailbox, &[&mailbox, &other])
        .await;
}
