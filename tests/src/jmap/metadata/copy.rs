/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Access, Ctx, MetaType, Parents, Using, random_text};
use crate::utils::{account::Account, jmap::JmapResponse, server::TestServer};
use serde_json::{Map, Value, json};

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata copy tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let copier = ctx.account("jane.smith@example.com");
    let owner_parents = ctx.parents(owner).await;
    let copier_parents = ctx.parents(copier).await;

    for ty in MetaType::COPYABLE {
        copy_type(&ctx, owner, copier, &owner_parents, &copier_parents, ty).await;
    }

    ctx.cleanup(&[owner, copier]).await;
}

pub fn destination(ty: MetaType, parents: &Parents) -> Value {
    match ty {
        MetaType::Email => json!({"mailboxIds": {parents.mailboxes[0].as_str(): true}}),
        MetaType::CalendarEvent => json!({"calendarIds": {parents.calendars[0].as_str(): true}}),
        MetaType::ContactCard => {
            json!({"addressBookIds": {parents.address_books[0].as_str(): true}})
        }
        MetaType::FileNode => json!({"parentId": parents.folders[0]}),
        other => panic!("{} has no /copy", other.name()),
    }
}

pub async fn copy(
    ctx: &Ctx<'_>,
    caller: &Account,
    from: &Account,
    to: &Account,
    ty: MetaType,
    source: &str,
    create: Value,
) -> JmapResponse {
    let mut create = match create {
        Value::Object(create) => create,
        _ => Map::new(),
    };
    create.insert("id".into(), source.into());
    ctx.method(
        caller,
        Using::Metadata,
        &format!("{}/copy", ty.name()),
        json!({
            "fromAccountId": from.id_string(),
            "accountId": to.id_string(),
            "create": {"c": Value::Object(create)}
        }),
    )
    .await
}

pub fn copied_id(response: &JmapResponse, ty: MetaType) -> String {
    response
        .pointer("/methodResponses/0/1/created/c/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} copy failed: {response:?}", ty.name()))
        .to_string()
}

async fn copy_type(
    ctx: &Ctx<'_>,
    owner: &Account,
    copier: &Account,
    owner_parents: &Parents,
    copier_parents: &Parents,
    ty: MetaType,
) {
    let shared = json!({"x.example": {"copied": true, "payload": random_text(400)}});
    let annotated = json!({
        "metadata": shared,
        "privateMetadata": {"x.example": {"owner": "stays private"}}
    });
    let source = ctx
        .create_ok(owner, ty, owner_parents, 0, annotated.clone())
        .await;
    let override_source = ctx.create_ok(owner, ty, owner_parents, 0, annotated).await;
    let twin = ctx.create_ok(owner, ty, owner_parents, 0, json!({})).await;
    let target = match ty {
        MetaType::FileNode => owner_parents.folders[0].clone(),
        _ => owner_parents
            .parent(ty, 0)
            .expect("contained type")
            .to_string(),
    };
    ctx.share(owner, ty, &target, copier, Some(Access::Read))
        .await;
    for id in [&source, &override_source] {
        ctx.update_ok(
            copier,
            owner,
            ty,
            id,
            json!({"privateMetadata/x.example": {"copier": "travels"}}),
        )
        .await;
    }

    let destination = destination(ty, copier_parents);

    ctx.test.wait_for_tasks().await;
    let before_twin = ctx.used_quota(copier).await;
    let twin_copy = copied_id(
        &copy(ctx, copier, owner, copier, ty, &twin, destination.clone()).await,
        ty,
    );
    ctx.test.wait_for_tasks().await;
    let plain_delta = ctx.used_quota(copier).await - before_twin;
    ctx.assert_metadata(copier, copier, ty, &twin_copy, json!({}), json!({}))
        .await;

    let before = ctx.used_quota(copier).await;
    let copied = copied_id(
        &copy(ctx, copier, owner, copier, ty, &source, destination.clone()).await,
        ty,
    );
    ctx.test.wait_for_tasks().await;
    let metadata_delta = ctx.used_quota(copier).await - before;
    assert!(
        metadata_delta > plain_delta,
        "{}: copying metadata must charge the destination ({metadata_delta} bytes with metadata, {plain_delta} without)",
        ty.name()
    );
    ctx.assert_metadata(
        copier,
        copier,
        ty,
        &copied,
        shared.clone(),
        json!({"x.example": {"copier": "travels"}}),
    )
    .await;

    let mut overrides = destination;
    if let Some(overrides) = overrides.as_object_mut() {
        overrides.insert("metadata".into(), json!({"z.example": {"override": 1}}));
        overrides.insert("privateMetadata".into(), json!({}));
    }
    let overridden = copied_id(
        &copy(ctx, copier, owner, copier, ty, &override_source, overrides).await,
        ty,
    );
    ctx.assert_metadata(
        copier,
        copier,
        ty,
        &overridden,
        json!({"z.example": {"override": 1}}),
        json!({}),
    )
    .await;

    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &source,
        shared,
        json!({"x.example": {"owner": "stays private"}}),
    )
    .await;

    ctx.share(owner, ty, &target, copier, None).await;
    ctx.destroy(copier, ty, &[&twin_copy, &copied, &overridden])
        .await;
    ctx.destroy(owner, ty, &[&source, &override_source, &twin])
        .await;
}
