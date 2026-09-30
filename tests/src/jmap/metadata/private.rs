/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{
    Access, Ctx, MetaType, Parents, Using, changes_list, response_ids, sorted, updated_properties,
};
use crate::utils::{account::Account, jmap::JmapUtils, server::TestServer};
use registry::schema::prelude::ObjectType;
use serde_json::{Value, json};

pub async fn test(test: &TestServer) {
    println!("Running JMAP private metadata tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let first = ctx.account("jane.smith@example.com");
    let second = ctx.account("bill@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::SHAREABLE {
        isolation(&ctx, owner, first, second, &parents, ty).await;
    }
    for ty in [MetaType::Email, MetaType::Mailbox] {
        query_changes(&ctx, owner, first, second, &parents, ty).await;
    }
    group_members(&ctx, first, second).await;

    ctx.cleanup(&[owner, first, second]).await;
}

pub fn share_target(ty: MetaType, parents: &Parents, id: &str, slot: usize) -> String {
    match ty {
        MetaType::Email => parents.mailboxes[slot].clone(),
        MetaType::CalendarEvent => parents.calendars[slot].clone(),
        MetaType::ContactCard => parents.address_books[slot].clone(),
        _ => id.to_string(),
    }
}

struct Seen {
    metadata: String,
    plain: String,
}

async fn states(ctx: &Ctx<'_>, caller: &Account, owner: &Account, ty: MetaType) -> Seen {
    Seen {
        metadata: ctx.state(caller, owner, ty, Using::Metadata).await,
        plain: ctx.state(caller, owner, ty, Using::Plain).await,
    }
}

async fn isolation(
    ctx: &Ctx<'_>,
    owner: &Account,
    first: &Account,
    second: &Account,
    parents: &Parents,
    ty: MetaType,
) {
    let shared = json!({"x.example": {"visible": "to everyone"}});
    let id = ctx
        .create_ok(owner, ty, parents, 0, json!({"metadata": shared}))
        .await;
    let target = share_target(ty, parents, &id, 0);
    for sharee in [first, second] {
        ctx.share(owner, ty, &target, sharee, Some(Access::Read))
            .await;
    }

    let owner_before = states(ctx, owner, owner, ty).await;
    let first_before = states(ctx, first, owner, ty).await;
    let second_before = states(ctx, second, owner, ty).await;

    ctx.update_ok(
        first,
        owner,
        ty,
        &id,
        json!({"privateMetadata/p.example": {"who": "first"}}),
    )
    .await;

    let first_after = states(ctx, first, owner, ty).await;
    assert_ne!(
        first_before.metadata,
        first_after.metadata,
        "{}: a private write must advance the writer's state",
        ty.name()
    );
    assert_eq!(
        first_before.plain,
        first_after.plain,
        "{}: private writes must not move the state of clients without the capability",
        ty.name()
    );
    for (who, before, after) in [
        ("owner", &owner_before, states(ctx, owner, owner, ty).await),
        (
            "second sharee",
            &second_before,
            states(ctx, second, owner, ty).await,
        ),
    ] {
        assert_eq!(
            before.metadata,
            after.metadata,
            "{}: another user's private write moved the {who}'s state",
            ty.name()
        );
        assert_eq!(before.plain, after.plain);
    }

    if ty.has_changes() {
        let response = ctx
            .changes(
                first,
                owner,
                ty,
                &first_before.metadata,
                json!({}),
                Using::Metadata,
            )
            .await;
        assert_eq!(
            changes_list(&response, "updated"),
            sorted(&[&id]),
            "{response:?}"
        );
        assert_eq!(
            updated_properties(&response),
            Some(vec!["privateMetadata".to_string()]),
            "{}: {response:?}",
            ty.name()
        );
        assert_eq!(response.new_state(), first_after.metadata);

        for (caller, before) in [(owner, &owner_before), (second, &second_before)] {
            let response = ctx
                .changes(
                    caller,
                    owner,
                    ty,
                    &before.metadata,
                    json!({}),
                    Using::Metadata,
                )
                .await;
            assert!(
                changes_list(&response, "updated").is_empty()
                    && changes_list(&response, "created").is_empty(),
                "{}: {} saw another user's private write: {response:?}",
                ty.name(),
                caller.name()
            );
            assert_eq!(response.new_state(), before.metadata);
        }

        let response = ctx
            .changes(
                first,
                owner,
                ty,
                &first_after.metadata,
                json!({}),
                Using::Metadata,
            )
            .await;
        assert!(
            changes_list(&response, "updated").is_empty(),
            "{response:?}"
        );
    }

    ctx.update_ok(
        second,
        owner,
        ty,
        &id,
        json!({"privateMetadata": {"p.example": {"who": "second"}}}),
    )
    .await;
    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata/p.example": {"who": "owner"}}),
    )
    .await;

    for (caller, who) in [(owner, "owner"), (first, "first"), (second, "second")] {
        ctx.assert_metadata(
            caller,
            owner,
            ty,
            &id,
            shared.clone(),
            json!({"p.example": {"who": who}}),
        )
        .await;
        let object = ctx
            .get_one(caller, owner, ty, &id, None, Using::Metadata)
            .await;
        assert_eq!(
            object.get("privateMetadata"),
            Some(&json!({"p.example": {"who": who}})),
            "{}: default /get of {who}: {object}",
            ty.name()
        );
    }

    let query = ctx
        .query(
            second,
            owner,
            ty,
            json!({"privateMetadataTextEquals": {"path": "p.example/who", "value": "first"}}),
            Using::Metadata,
        )
        .await;
    assert!(
        !response_ids(&query).contains(&id),
        "{}: private conditions matched another user's private metadata: {query:?}",
        ty.name()
    );
    let query = ctx
        .query(
            second,
            owner,
            ty,
            json!({"privateMetadataTextEquals": {"path": "p.example/who", "value": "second"}}),
            Using::Metadata,
        )
        .await;
    assert!(
        response_ids(&query).contains(&id),
        "{}: private conditions must match the caller's own data: {query:?}",
        ty.name()
    );

    ctx.share(owner, ty, &target, first, None).await;
    let response = ctx
        .get(
            first,
            owner,
            ty,
            &[&id],
            Some(&["id", "privateMetadata"]),
            Using::Metadata,
        )
        .await;
    assert!(
        response
            .pointer("/methodResponses/0/1/list/0/privateMetadata")
            .is_none(),
        "{}: private metadata visible after losing access: {response:?}",
        ty.name()
    );
    ctx.share(owner, ty, &target, first, Some(Access::Read))
        .await;
    ctx.assert_metadata(
        first,
        owner,
        ty,
        &id,
        shared,
        json!({"p.example": {"who": "first"}}),
    )
    .await;

    for sharee in [first, second] {
        ctx.share(owner, ty, &target, sharee, None).await;
    }
    ctx.destroy(owner, ty, &[&id]).await;
}

async fn query_changes(
    ctx: &Ctx<'_>,
    owner: &Account,
    first: &Account,
    second: &Account,
    parents: &Parents,
    ty: MetaType,
) {
    let id = ctx
        .create_ok(
            owner,
            ty,
            parents,
            1,
            json!({"metadata": {"x.example": {"tag": "shared"}}}),
        )
        .await;
    let target = share_target(ty, parents, &id, 1);
    for sharee in [first, second] {
        ctx.share(owner, ty, &target, sharee, Some(Access::Read))
            .await;
    }
    let scope = parents.filter(ty, 1).expect("scoped type");
    let filters = [
        json!({"operator": "AND", "conditions": [scope.clone(), {"metadataExists": "x.example"}]}),
        json!({"operator": "AND", "conditions": [scope, {"privateMetadataExists": "p.example"}]}),
    ];

    let mut query_states = Vec::new();
    for caller in [owner, first, second] {
        for filter in &filters {
            let response = ctx
                .query(caller, owner, ty, filter.clone(), Using::Metadata)
                .await;
            let state = response
                .pointer("/methodResponses/0/1/queryState")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("Missing queryState: {response:?}"))
                .to_string();
            query_states.push((caller, filter.clone(), state));
        }
    }

    ctx.update_ok(
        first,
        owner,
        ty,
        &id,
        json!({"privateMetadata/p.example": {"memo": "first only"}}),
    )
    .await;

    for (caller, filter, since) in &query_states {
        let response = ctx
            .method(
                caller,
                Using::Metadata,
                &format!("{}/queryChanges", ty.name()),
                json!({
                    "accountId": owner.id_string(),
                    "filter": filter,
                    "sinceQueryState": since
                }),
            )
            .await;
        let added = response
            .pointer("/methodResponses/0/1/added")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("Missing added: {response:?}"))
            .iter()
            .filter_map(|item| item.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .collect::<Vec<_>>();
        let removed = response
            .pointer("/methodResponses/0/1/removed")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default();
        let is_private_filter = filter.to_string().contains("privateMetadataExists");
        if caller.id() == first.id() && is_private_filter {
            assert_eq!(
                added,
                vec![id.clone()],
                "{}: the writer's private query must see the change: {response:?}",
                ty.name()
            );
        } else if caller.id() != first.id() {
            assert!(
                added.is_empty() && removed == 0,
                "{}: {} saw another user's private change through queryChanges: {response:?}",
                ty.name(),
                caller.name()
            );
            assert_eq!(
                response
                    .pointer("/methodResponses/0/1/newQueryState")
                    .and_then(Value::as_str),
                Some(since.as_str()),
                "{}: {} query state moved on another user's private write",
                ty.name(),
                caller.name()
            );
        }
    }

    for sharee in [first, second] {
        ctx.share(owner, ty, &target, sharee, None).await;
    }
    ctx.destroy(owner, ty, &[&id]).await;
}

async fn group_members(ctx: &Ctx<'_>, first: &Account, second: &Account) {
    let admin = ctx.account("admin");
    let group = ctx.account("sales@example.com");
    for member in [first, second] {
        admin
            .registry_update_object(
                ObjectType::Account,
                member.id(),
                json!({"memberGroupIds": {group.id_string(): true}}),
            )
            .await;
    }

    let parents = ctx.parents_as(first, group).await;
    for ty in [MetaType::Mailbox, MetaType::SieveScript, MetaType::FileNode] {
        let id = ctx
            .create(first, group, ty, &parents, 0, json!({}), Using::Metadata)
            .await
            .created(0)
            .id()
            .to_string();
        for (member, who) in [(first, "first member"), (second, "second member")] {
            ctx.update_ok(
                member,
                group,
                ty,
                &id,
                json!({"privateMetadata/p.example": {"who": who}}),
            )
            .await;
        }
        for (member, who) in [(first, "first member"), (second, "second member")] {
            ctx.assert_metadata(
                member,
                group,
                ty,
                &id,
                json!({}),
                json!({"p.example": {"who": who}}),
            )
            .await;
        }
        ctx.destroy_as(first, group, ty, &[&id]).await;
    }

    ctx.destroy_all_as(first, group).await;
    ctx.purge(&[group]).await;
    for member in [first, second] {
        admin
            .registry_update_object(
                ObjectType::Account,
                member.id(),
                json!({"memberGroupIds": {}}),
            )
            .await;
    }
}
