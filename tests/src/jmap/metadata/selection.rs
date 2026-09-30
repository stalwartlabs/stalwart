/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents, Using, method_error};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata selection tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::ALL {
        subselectors(&ctx, owner, &parents, ty).await;
        opaque_values(&ctx, owner, &parents, ty).await;
        without_capability(&ctx, owner, &parents, ty).await;
    }

    ctx.cleanup(&[owner]).await;
}

async fn subselectors(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let shared = json!({
        "x.example": {"a": 1},
        "y.example": {"b": 2},
        "z.example": {"c": 3}
    });
    let private = json!({
        "x.example": {"p": 1},
        "w.example": {"q": 2}
    });
    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({"metadata": shared, "privateMetadata": private}),
        )
        .await;

    for (properties, expected_shared, expected_private) in [
        (
            &["id", "metadata/x.example", "metadata/y.example"][..],
            Some(json!({"x.example": {"a": 1}, "y.example": {"b": 2}})),
            None,
        ),
        (
            &["id", "metadata", "metadata/x.example"][..],
            Some(shared.clone()),
            None,
        ),
        (
            &["id", "metadata/x.example", "metadata"][..],
            Some(shared.clone()),
            None,
        ),
        (
            &["id", "privateMetadata/w.example"][..],
            None,
            Some(json!({"w.example": {"q": 2}})),
        ),
        (
            &["id", "metadata/z.example", "privateMetadata/x.example"][..],
            Some(json!({"z.example": {"c": 3}})),
            Some(json!({"x.example": {"p": 1}})),
        ),
        (
            &["id", "metadata/missing.example"][..],
            Some(json!({})),
            None,
        ),
        (
            &["id", "metadata/photography", "metadata/x.example"][..],
            Some(json!({"x.example": {"a": 1}})),
            None,
        ),
        (&["id", "metadata/photography"][..], Some(json!({})), None),
        (&["id", "metadata/X.example"][..], Some(json!({})), None),
        (
            &["id", "metadata/X.EXAMPLE", "metadata/x.example"][..],
            Some(json!({"x.example": {"a": 1}})),
            None,
        ),
        (
            &["id", "privateMetadata/X.example"][..],
            None,
            Some(json!({})),
        ),
    ] {
        let object = ctx
            .get_one(owner, owner, ty, &id, Some(properties), Using::Metadata)
            .await;
        assert_eq!(
            object.get("metadata").cloned(),
            expected_shared,
            "{}: selection {properties:?} returned {object}",
            ty.name()
        );
        assert_eq!(
            object.get("privateMetadata").cloned(),
            expected_private,
            "{}: selection {properties:?} returned {object}",
            ty.name()
        );
    }

    for properties in [
        &["id", "metadata/x.example/a"][..],
        &["id", "privateMetadata/x.example/p/q"][..],
        &["id", "metadata/x.example/"][..],
    ] {
        let response = ctx
            .get(owner, owner, ty, &[&id], Some(properties), Using::Metadata)
            .await;
        assert_eq!(
            method_error(&response),
            Some("invalidArguments"),
            "{}: selection {properties:?} must be rejected: {response:?}",
            ty.name()
        );
    }

    ctx.destroy(owner, ty, &[&id]).await;
}

async fn opaque_values(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let tricky = json!({
        "id": "#i0",
        "blobId": "#i1",
        "parentId": "a-string-that-is-much-longer-than-any-jmap-identifier-0123456789",
        "mailboxIds": {"#i0": true, "Mz": false},
        "keywords": {"$Seen": true},
        "receivedAt": "2024-01-01T00:00:00+00:00",
        "created": "2024-01-01T10:00:00.123+02:00",
        "updated": "2024-06-30T23:59:60Z",
        "start": "2024-01-01T10:00:00",
        "duration": "P1D",
        "size": "12",
        "@type": "Event",
        "name": {"full": "Not a card"},
        "metadata": {"nested": "not a root"},
        "privateMetadata": "not a root either",
        "0": "numeric key",
        "a/b": "slash key",
        "~": "tilde key"
    });
    let shared = json!({"x.example": tricky});
    let private = json!({"x.example": {"ref": "#i0", "date": "2024-02-29T12:00:00-08:00"}});

    let first = ctx.payload(owner, owner, ty, parents, 0, json!({})).await;
    let second = ctx
        .payload(
            owner,
            owner,
            ty,
            parents,
            0,
            json!({"metadata": shared, "privateMetadata": private}),
        )
        .await;
    let response = ctx
        .method(
            owner,
            Using::Metadata,
            &format!("{}/set", ty.name()),
            json!({
                "accountId": owner.id_string(),
                "create": {"i0": first, "i1": second}
            }),
        )
        .await;
    let first_id = response.created(0).id().to_string();
    let second_id = response.created(1).id().to_string();

    ctx.assert_metadata(owner, owner, ty, &second_id, shared, private)
        .await;

    ctx.update_ok(
        owner,
        owner,
        ty,
        &second_id,
        json!({
            "metadata/x.example/receivedAt": "1999-12-31T23:59:59+14:00",
            "metadata/x.example/0": "still a key",
            "metadata/x.example/a~1b": "#i1"
        }),
    )
    .await;
    let (got, _) = ctx.metadata(owner, owner, ty, &second_id).await;
    for (key, value) in [
        ("receivedAt", "1999-12-31T23:59:59+14:00"),
        ("0", "still a key"),
        ("a/b", "#i1"),
        ("id", "#i0"),
    ] {
        assert_eq!(
            got.pointer(&format!(
                "/x.example/{}",
                key.replace('~', "~0").replace('/', "~1")
            ))
            .and_then(Value::as_str),
            Some(value),
            "{}: value of {key} changed: {got}",
            ty.name()
        );
    }

    ctx.destroy(owner, ty, &[&first_id, &second_id]).await;
}

async fn without_capability(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let shared = json!({"x.example": {"a": 1}});
    let private = json!({"x.example": {"b": 2}});
    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            0,
            json!({"metadata": shared, "privateMetadata": private}),
        )
        .await;

    let object = ctx.get_one(owner, owner, ty, &id, None, Using::Plain).await;
    for property in ["metadata", "privateMetadata"] {
        assert!(
            object.get(property).is_none(),
            "{}: {property} returned to a client without the capability: {object}",
            ty.name()
        );
    }

    let object = ctx
        .get_one(
            owner,
            owner,
            ty,
            &id,
            Some(&["id", "metadata", "privateMetadata"]),
            Using::Plain,
        )
        .await;
    assert_eq!(
        object.get("metadata"),
        Some(&shared),
        "{}: explicitly requested metadata must be returned: {object}",
        ty.name()
    );
    assert_eq!(
        object.get("privateMetadata"),
        Some(&private),
        "{}: explicitly requested privateMetadata must be returned: {object}",
        ty.name()
    );

    ctx.destroy(owner, ty, &[&id]).await;
}
