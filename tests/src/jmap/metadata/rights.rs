/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    fixture::{Access, Ctx, MetaType, Parents, Using, depth_value},
    private::share_target,
};
use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapUtils},
    server::TestServer,
};
use jmap_proto::error::set::SetErrorType;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata rights tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let sharee = ctx.account("jane.smith@example.com");
    let outsider = ctx.account("bill@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::SHAREABLE {
        shared_object(&ctx, owner, sharee, outsider, &parents, ty).await;
    }
    private_event(&ctx, owner, sharee, &parents).await;
    sharee_mailbox_create(&ctx, owner, sharee, &parents).await;

    ctx.cleanup(&[owner, sharee, outsider]).await;
}

async fn shared_object(
    ctx: &Ctx<'_>,
    owner: &Account,
    sharee: &Account,
    outsider: &Account,
    parents: &Parents,
    ty: MetaType,
) {
    let shared = json!({"x.example": {"owner": "set by the owner"}});
    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({
                "metadata": shared,
                "privateMetadata": {"x.example": {"secret": "owner only"}}
            }),
        )
        .await;
    let target = share_target(ty, parents, &id, 0);

    ctx.share(owner, ty, &target, sharee, Some(Access::Read))
        .await;
    ctx.assert_metadata(sharee, owner, ty, &id, shared.clone(), json!({}))
        .await;

    ctx.update_err(
        sharee,
        owner,
        ty,
        &id,
        json!({"metadata/x.example/sharee": "not allowed"}),
    )
    .await
    .assert_type(SetErrorType::Forbidden);
    ctx.update_err(
        sharee,
        owner,
        ty,
        &id,
        json!({"metadata": {"photography": depth_value(40)}}),
    )
    .await
    .assert_type(SetErrorType::Forbidden);
    for patch in [
        json!({"metadata/bad..namespace": {"a": 1}}),
        json!({"metadata/x.example/missing/leaf": 1}),
        json!({"metadata/x.example/owner/char": 1}),
        json!({"metadata/absent.example/key": 1}),
    ] {
        ctx.update_err(sharee, owner, ty, &id, patch)
            .await
            .assert_type(SetErrorType::Forbidden);
    }
    for patch in [
        json!({"metadata/x.example": {"a": 1}, "metadata/x.example/a": 2}),
        json!({"metadata": {}, "metadata/x.example": {"a": 1}}),
        json!({"metadata/x.example/~2bad": 1}),
    ] {
        ctx.update_err(sharee, owner, ty, &id, patch)
            .await
            .assert_type(SetErrorType::InvalidPatch);
    }
    ctx.update_err(
        sharee,
        owner,
        ty,
        &id,
        json!({"privateMetadata/x.example/missing/leaf": 1}),
    )
    .await
    .assert_type(SetErrorType::InvalidPatch);

    ctx.update_ok(
        sharee,
        owner,
        ty,
        &id,
        json!({"privateMetadata/x.example": {"mine": "sharee note"}}),
    )
    .await;
    ctx.assert_metadata(
        sharee,
        owner,
        ty,
        &id,
        shared.clone(),
        json!({"x.example": {"mine": "sharee note"}}),
    )
    .await;
    ctx.update_err(
        sharee,
        owner,
        ty,
        &id,
        json!({"privateMetadata/photography": {"a": 1}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);

    ctx.share(owner, ty, &target, sharee, Some(Access::Write))
        .await;
    ctx.update_ok(
        sharee,
        owner,
        ty,
        &id,
        json!({"metadata/x.example/sharee": "now allowed"}),
    )
    .await;
    let updated = json!({"x.example": {"owner": "set by the owner", "sharee": "now allowed"}});
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        updated.clone(),
        json!({"x.example": {"secret": "owner only"}}),
    )
    .await;
    ctx.update_err(
        sharee,
        owner,
        ty,
        &id,
        json!({"metadata/photography": {"a": 1}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);

    let plain = inaccessible(ctx, outsider, owner, ty, &id, &["id"]).await;
    let with_metadata = inaccessible(ctx, outsider, owner, ty, &id, &["id", "metadata"]).await;
    assert_eq!(
        plain,
        with_metadata,
        "{}: reading metadata of an inaccessible object must fail like any other property",
        ty.name()
    );
    let response = ctx
        .update(
            outsider,
            owner,
            ty,
            &id,
            json!({"privateMetadata/x.example": {"a": 1}}),
            Using::Metadata,
        )
        .await;
    assert!(
        response
            .pointer(&format!("/methodResponses/0/1/updated/{id}"))
            .is_none(),
        "{}: an outsider wrote private metadata: {response:?}",
        ty.name()
    );

    ctx.share(owner, ty, &target, sharee, None).await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        updated,
        json!({"x.example": {"secret": "owner only"}}),
    )
    .await;
    ctx.destroy(owner, ty, &[&id]).await;
}

async fn inaccessible(
    ctx: &Ctx<'_>,
    caller: &Account,
    owner: &Account,
    ty: MetaType,
    id: &str,
    properties: &[&str],
) -> Value {
    let response: JmapResponse = ctx
        .get(caller, owner, ty, &[id], Some(properties), Using::Metadata)
        .await;
    if response.name_at(0) == "error" {
        json!({"error": response.error_type_at(0)})
    } else {
        let list = response
            .pointer("/methodResponses/0/1/list")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default();
        assert_eq!(
            list,
            0,
            "{}: inaccessible object returned: {response:?}",
            ty.name()
        );
        json!({"notFound": response.pointer("/methodResponses/0/1/notFound")})
    }
}

async fn private_event(ctx: &Ctx<'_>, owner: &Account, sharee: &Account, parents: &Parents) {
    let id = ctx
        .create_ok(
            owner,
            MetaType::CalendarEvent,
            parents,
            0,
            json!({
                "privacy": "private",
                "metadata": {"x.example": {"hidden": "from sharees"}}
            }),
        )
        .await;
    ctx.share(
        owner,
        MetaType::CalendarEvent,
        &parents.calendars[0],
        sharee,
        Some(Access::Read),
    )
    .await;

    let object = ctx
        .get_one(
            sharee,
            owner,
            MetaType::CalendarEvent,
            &id,
            Some(&["id", "metadata"]),
            Using::Metadata,
        )
        .await;
    assert_eq!(
        object.get("metadata"),
        Some(&json!({})),
        "private events must hide metadata from non-owners: {object}"
    );
    ctx.assert_metadata(
        owner,
        owner,
        MetaType::CalendarEvent,
        &id,
        json!({"x.example": {"hidden": "from sharees"}}),
        json!({}),
    )
    .await;

    let response = ctx
        .query(
            sharee,
            owner,
            MetaType::CalendarEvent,
            json!({"metadataExists": "x.example"}),
            Using::Metadata,
        )
        .await;
    assert!(
        !super::fixture::response_ids(&response).contains(&id),
        "metadata conditions must not match private events of other users: {response:?}"
    );

    ctx.share(
        owner,
        MetaType::CalendarEvent,
        &parents.calendars[0],
        sharee,
        None,
    )
    .await;
    ctx.destroy(owner, MetaType::CalendarEvent, &[&id]).await;
}

async fn sharee_mailbox_create(
    ctx: &Ctx<'_>,
    owner: &Account,
    sharee: &Account,
    parents: &Parents,
) {
    let parent = parents.mailboxes[0].as_str();
    let response = ctx
        .method(
            owner,
            Using::Plain,
            "Mailbox/set",
            json!({
                "accountId": owner.id_string(),
                "update": {parent: {
                    format!("shareWith/{}", sharee.id_string()):
                        {"mayReadItems": true, "mayCreateChild": true}
                }}
            }),
        )
        .await;
    assert!(
        response
            .pointer(&format!("/methodResponses/0/1/updated/{parent}"))
            .is_some(),
        "Sharing mailbox {parent} failed: {response:?}"
    );

    for extra in [
        json!({"metadata": {"x.example": {"v": 1}}}),
        json!({"privateMetadata": {"x.example": {"v": 1}}}),
    ] {
        ctx.create(
            sharee,
            owner,
            MetaType::Mailbox,
            parents,
            0,
            extra.clone(),
            Using::Metadata,
        )
        .await
        .not_created(0)
        .to_set_error()
        .assert_type(SetErrorType::Forbidden);
    }
    let created = ctx
        .create(
            sharee,
            owner,
            MetaType::Mailbox,
            parents,
            0,
            json!({}),
            Using::Metadata,
        )
        .await
        .created(0)
        .id()
        .to_string();

    ctx.share(owner, MetaType::Mailbox, parent, sharee, None)
        .await;
    ctx.destroy(owner, MetaType::Mailbox, &[&created]).await;
}
