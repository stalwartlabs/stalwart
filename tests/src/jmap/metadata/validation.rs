/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents, depth_value};
use crate::utils::{account::Account, server::TestServer};
use jmap_proto::error::set::SetErrorType;
use serde_json::{Map, Value, json};

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata validation tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::ALL {
        create_rules(&ctx, owner, &parents, ty).await;
        invalid_patches(&ctx, owner, &parents, ty).await;
        namespaces_and_depth(&ctx, owner, &parents, ty).await;
        server_limits(&ctx, owner, &parents, ty).await;
    }

    ctx.cleanup(&[owner]).await;
}

async fn create_rules(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    for (extra, property) in [
        (json!({"metadata": null}), "metadata"),
        (json!({"privateMetadata": null}), "privateMetadata"),
        (json!({"metadata": "a string"}), "metadata"),
        (json!({"metadata": ["x.example"]}), "metadata"),
        (
            json!({"metadata": {"x.example": "not an object"}}),
            "metadata/x.example",
        ),
        (
            json!({"metadata": {"x.example": null}}),
            "metadata/x.example",
        ),
        (
            json!({"privateMetadata": {"x.example": [1, 2]}}),
            "privateMetadata/x.example",
        ),
    ] {
        ctx.create_err(owner, ty, parents, extra.clone())
            .await
            .assert_type(SetErrorType::InvalidProperties)
            .assert_properties(&[property]);
    }
}

async fn invalid_patches(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let shared = json!({"x.example": {"list": [1, 2, 3], "obj": {"a": 1}, "s": "text"}});
    let id = ctx
        .create_ok(owner, ty, parents, 0, json!({"metadata": shared}))
        .await;

    for patch in [
        json!({"metadata/x.example/list/0": 5}),
        json!({"metadata/x.example/list/-": 4}),
        json!({"metadata/x.example/missing/leaf": 1}),
        json!({"metadata/x.example/s/char": 1}),
        json!({"metadata/absent.example/key": 1}),
        json!({"metadata": {"y.example": {}}, "metadata/x.example": {"b": 1}}),
        json!({"metadata/x.example": {"b": 1}, "metadata/x.example/obj": {"c": 1}}),
        json!({"metadata/x.example/obj": {"c": 1}, "metadata/x.example/obj/a": 2}),
        json!({"privateMetadata": {}, "privateMetadata/x.example": {"a": 1}}),
    ] {
        ctx.update_err(owner, owner, ty, &id, patch.clone())
            .await
            .assert_type(SetErrorType::InvalidPatch);
        ctx.assert_metadata(owner, owner, ty, &id, shared.clone(), json!({}))
            .await;
    }

    let max_depth = ctx
        .test
        .server
        .core
        .metadata
        .max_depth
        .expect("default maxDepth") as usize;
    for (patch, expected) in [
        (
            json!({"metadata/x.example/~2bad": 1}),
            SetErrorType::InvalidPatch,
        ),
        (
            json!({"metadata/x.example/trailing~": 1}),
            SetErrorType::InvalidPatch,
        ),
        (
            json!({"metadata/photography/missing/leaf": 1}),
            SetErrorType::InvalidProperties,
        ),
        (
            json!({"metadata/X.example/missing/leaf": 1}),
            SetErrorType::InvalidProperties,
        ),
        (
            json!({"metadata/x.example/missing/leaf": depth_value(max_depth + 4)}),
            SetErrorType::InvalidPatch,
        ),
        (
            json!({"metadata/x.example/list/0": depth_value(max_depth + 4)}),
            SetErrorType::InvalidPatch,
        ),
        (
            json!({"privateMetadata/x.example/missing/leaf": 1}),
            SetErrorType::InvalidPatch,
        ),
        (
            json!({format!("metadata/x.example{}", "/a".repeat(128)): 1}),
            SetErrorType::InvalidPatch,
        ),
    ] {
        ctx.update_err(owner, owner, ty, &id, patch.clone())
            .await
            .assert_type(expected);
        ctx.assert_metadata(owner, owner, ty, &id, shared.clone(), json!({}))
            .await;
    }

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/x.example/obj": {"c": 1}, "metadata/y.example": {"d": 2}}),
    )
    .await;

    ctx.destroy(owner, ty, &[&id]).await;
}

async fn namespaces_and_depth(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let max_depth = ctx
        .test
        .server
        .core
        .metadata
        .max_depth
        .expect("default maxDepth") as usize;

    for namespace in [
        "photography",
        "registered_name",
        "-leading.example",
        "trailing-.example",
        "double..example",
        ".example",
        "example.",
        "under_score.example",
        "sp ace.example",
        "Mixed-Case.Example.COM",
        "EXAMPLE.COM",
        "x.Example",
    ] {
        let object = json!({ namespace: {"a": 1} });
        ctx.create_err(owner, ty, parents, json!({"metadata": object}))
            .await
            .assert_type(SetErrorType::InvalidProperties)
            .assert_properties(&[&format!("metadata/{namespace}")]);
    }
    ctx.create_err(
        owner,
        ty,
        parents,
        json!({"privateMetadata": {"Upper.example": {"a": 1}}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties)
    .assert_properties(&["privateMetadata/Upper.example"]);

    let long_label = format!("{}.example", "a".repeat(64));
    let long_name = format!("{}example", "abcdefghi.".repeat(26));
    for namespace in [long_label.as_str(), long_name.as_str()] {
        let object = json!({ namespace: {"a": 1} });
        ctx.create_err(owner, ty, parents, json!({"metadata": object}))
            .await
            .assert_type(SetErrorType::InvalidProperties);
    }

    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({
                "metadata": {
                    "deep.example": {"deep": depth_value(max_depth - 1)},
                    "x.example": {"arrays": [[[{"inner": [{"leaf": 1}]}]]]}
                }
            }),
        )
        .await;

    for patch in [
        json!({"metadata/photography": {"a": 1}}),
        json!({"privateMetadata/photography": {"a": 1}}),
        json!({"metadata/Deep.example": {"a": 1}}),
        json!({"metadata/DEEP.EXAMPLE/deep": 1}),
        json!({"metadata/Deep.example": null}),
        json!({"privateMetadata/Upper.example": {"a": 1}}),
        json!({"metadata": {"deep.example": {"a": 1}, "Upper.example": {"a": 1}}}),
        json!({"metadata/y.example": depth_value(max_depth + 1)}),
        json!({"metadata/deep.example/deep": depth_value(max_depth)}),
        json!({"metadata/x.example/arrays": [[{"a": depth_value(max_depth)}]]}),
    ] {
        ctx.update_err(owner, owner, ty, &id, patch)
            .await
            .assert_type(SetErrorType::InvalidProperties);
    }

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/y.example": depth_value(max_depth)}),
    )
    .await;

    for (key, value) in [
        ("bell\u{0007}", json!("ok")),
        ("ok", json!("nul\u{0000}byte")),
        ("ok", json!({"nested": "escape\u{001B}[0m"})),
        ("ok", json!(["delete\u{007F}"])),
        ("ok", json!("vertical\u{000B}tab")),
    ] {
        let mut namespace = Map::new();
        namespace.insert(key.to_string(), value);
        ctx.update_err(
            owner,
            owner,
            ty,
            &id,
            json!({"metadata/z.example": Value::Object(namespace)}),
        )
        .await
        .assert_type(SetErrorType::InvalidProperties);
    }
    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/z.example": {"tab\tkey": "line\nbreak\r\n\ttab"}}),
    )
    .await;

    ctx.destroy(owner, ty, &[&id]).await;
}

async fn server_limits(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let limits = &ctx.test.server.core.metadata;
    let id = ctx.create_ok(owner, ty, parents, 0, json!({})).await;

    let entry = |size: usize| json!({"v": "e".repeat(size)});

    ctx.update_err(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/big.example": entry(limits.max_entry_size + 1)}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);

    let chunk = limits.max_entry_size / 2;
    let namespaces = limits.max_size / chunk + 2;
    let oversized = (0..namespaces)
        .map(|n| (format!("n{n}.example"), entry(chunk)))
        .collect::<Map<_, _>>();
    ctx.update_err(owner, owner, ty, &id, json!({"metadata": oversized}))
        .await
        .assert_type(SetErrorType::InvalidProperties);

    let private_namespaces = limits.max_private_size / chunk + 2;
    let oversized_private = (0..private_namespaces)
        .map(|n| (format!("p{n}.example"), entry(chunk)))
        .collect::<Map<_, _>>();
    ctx.update_err(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata": oversized_private}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);

    let too_many = (0..=limits.max_entries)
        .map(|n| (format!("c{n}.example"), json!({"n": n})))
        .collect::<Map<_, _>>();
    ctx.update_err(owner, owner, ty, &id, json!({"metadata": too_many}))
        .await
        .assert_type(SetErrorType::InvalidProperties);

    let at_limit = (0..limits.max_entries)
        .map(|n| (format!("c{n}.example"), json!({"n": n})))
        .collect::<Map<_, _>>();
    ctx.update_ok(owner, owner, ty, &id, json!({"metadata": at_limit}))
        .await;
    ctx.update_err(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/one-more.example": {"n": 0}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/fits.example": entry(limits.max_entry_size / 2), "metadata/c0.example": null}),
    )
    .await;

    ctx.destroy(owner, ty, &[&id]).await;
}
