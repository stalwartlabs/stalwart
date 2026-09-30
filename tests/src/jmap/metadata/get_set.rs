/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents, Using};
use crate::utils::{account::Account, server::TestServer};
use jmap_proto::error::set::SetErrorType;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata get/set tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::ALL {
        create_and_read(&ctx, owner, &parents, ty).await;
        replace_and_patch(&ctx, owner, &parents, ty).await;
        atomic_updates(&ctx, owner, &parents, ty).await;
    }

    ctx.cleanup(&[owner]).await;
}

async fn create_and_read(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let shared = json!({
        "acme.example.com": {
            "color": "blue",
            "priority": "high",
            "project": {"id": "ALPHA-2024", "deadline": "2024-12-31"}
        }
    });
    let private = json!({"acme.example.com": {"workflowState": "pending-review"}});

    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({"metadata": shared, "privateMetadata": private}),
        )
        .await;
    ctx.assert_metadata(owner, owner, ty, &id, shared.clone(), private.clone())
        .await;

    let object = ctx
        .get_one(owner, owner, ty, &id, None, Using::Metadata)
        .await;
    assert_eq!(
        object.get("metadata"),
        Some(&shared),
        "{}: default properties with the capability must include metadata: {object}",
        ty.name()
    );
    assert_eq!(
        object.get("privateMetadata"),
        Some(&private),
        "{}: default properties with the capability must include privateMetadata: {object}",
        ty.name()
    );

    let only_metadata = ctx
        .get_one(owner, owner, ty, &id, Some(&["metadata"]), Using::Metadata)
        .await;
    assert_eq!(only_metadata.get("metadata"), Some(&shared));
    assert!(
        only_metadata.get("privateMetadata").is_none(),
        "{}: privateMetadata returned without being requested: {only_metadata}",
        ty.name()
    );

    let bare = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    ctx.assert_metadata(owner, owner, ty, &bare, json!({}), json!({}))
        .await;

    let explicit = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({"metadata": {}, "privateMetadata": {}}),
        )
        .await;
    ctx.assert_metadata(owner, owner, ty, &explicit, json!({}), json!({}))
        .await;

    let list = ctx
        .get(
            owner,
            owner,
            ty,
            &[id.as_str(), bare.as_str(), explicit.as_str()],
            Some(&["id", "metadata", "privateMetadata"]),
            Using::Metadata,
        )
        .await;
    for object in list.list() {
        for property in ["metadata", "privateMetadata"] {
            assert!(
                object.get(property).is_some_and(Value::is_object),
                "{}: {property} must never be null or absent: {object}",
                ty.name()
            );
        }
    }

    for id in [&id, &bare, &explicit] {
        ctx.destroy(owner, ty, &[id]).await;
    }
}

async fn replace_and_patch(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let private = json!({"x.example": {"note": "mine"}});
    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({
                "metadata": {"x.example": {"a": 1}},
                "privateMetadata": private
            }),
        )
        .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata": {"y.example": {"k": "v"}}}),
    )
    .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({"y.example": {"k": "v"}}),
        private.clone(),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/z.example": {"a": true, "b": "c"}}),
    )
    .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({"y.example": {"k": "v"}, "z.example": {"a": true, "b": "c"}}),
        private.clone(),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/z.example": {"a": false}}),
    )
    .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({"y.example": {"k": "v"}, "z.example": {"a": false}}),
        private.clone(),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({
            "metadata/y.example/k": "w",
            "metadata/y.example/list": [1, "two", {"three": 3}],
            "metadata/y.example/obj": {"inner": 1},
            "metadata/y.example/a~1b~0c": "escaped"
        }),
    )
    .await;
    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({
            "metadata/y.example/obj/inner": 2,
            "metadata/y.example/obj/other": "x"
        }),
    )
    .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({
            "y.example": {
                "k": "w",
                "list": [1, "two", {"three": 3}],
                "obj": {"inner": 2, "other": "x"},
                "a/b~c": "escaped"
            },
            "z.example": {"a": false}
        }),
        private.clone(),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({
            "metadata/y.example/k": null,
            "metadata/y.example/obj/other": null,
            "metadata/z.example": null
        }),
    )
    .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({
            "y.example": {
                "list": [1, "two", {"three": 3}],
                "obj": {"inner": 2},
                "a/b~c": "escaped"
            }
        }),
        private.clone(),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({
            "privateMetadata/x.example/note": "changed",
            "privateMetadata/w.example": {"n": 1}
        }),
    )
    .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({
            "y.example": {
                "list": [1, "two", {"three": 3}],
                "obj": {"inner": 2},
                "a/b~c": "escaped"
            }
        }),
        json!({"x.example": {"note": "changed"}, "w.example": {"n": 1}}),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata": {"v.example": {"only": true}}}),
    )
    .await;
    ctx.update_ok(owner, owner, ty, &id, json!({"metadata": {}}))
        .await;
    ctx.assert_metadata(
        owner,
        owner,
        ty,
        &id,
        json!({}),
        json!({"v.example": {"only": true}}),
    )
    .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata/v.example": null}),
    )
    .await;
    ctx.assert_metadata(owner, owner, ty, &id, json!({}), json!({}))
        .await;

    ctx.destroy(owner, ty, &[&id]).await;
}

async fn atomic_updates(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let shared = json!({"acme.example.com": {"approvalStatus": "draft"}});
    let id = ctx
        .create_ok(owner, ty, parents, 0, json!({"metadata": shared}))
        .await;

    let mut patch = ty.rename_patch(&ctx.unique(ty));
    if let Some(patch) = patch.as_object_mut() {
        patch.insert(
            "metadata/acme.example.com/lastModifiedReason".into(),
            "Rescheduled per manager request".into(),
        );
        patch.insert(
            "metadata/acme.example.com/approvalStatus".into(),
            "pending".into(),
        );
    }
    ctx.update_ok(owner, owner, ty, &id, patch).await;
    let expected = json!({
        "acme.example.com": {
            "approvalStatus": "pending",
            "lastModifiedReason": "Rescheduled per manager request"
        }
    });
    ctx.assert_metadata(owner, owner, ty, &id, expected.clone(), json!({}))
        .await;

    let mut patch = ty.rename_patch(&ctx.unique(ty));
    if let Some(patch) = patch.as_object_mut() {
        patch.insert(
            "metadata/acme.example.com/approvalStatus".into(),
            "approved".into(),
        );
        patch.insert("metadata/acme.example.com/missing/leaf".into(), 1.into());
    }
    ctx.update_err(owner, owner, ty, &id, patch)
        .await
        .assert_type(SetErrorType::InvalidPatch);
    ctx.assert_metadata(owner, owner, ty, &id, expected, json!({}))
        .await;

    ctx.destroy(owner, ty, &[&id]).await;
}
