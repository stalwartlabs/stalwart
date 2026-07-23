/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_eq, check_ne};
use crate::utils::jmap::JmapUtils;
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] mailbox");

    ctx.run("mailbox/get-all", get_all(ctx)).await;
    ctx.run("mailbox/get-by-ids", get_by_ids(ctx)).await;
    ctx.run("mailbox/get-inbox-exists", get_inbox_exists(ctx))
        .await;
    ctx.run("mailbox/get-not-found", get_not_found(ctx)).await;
    ctx.run(
        "mailbox/get-mailbox-properties",
        get_mailbox_properties(ctx),
    )
    .await;
    ctx.run("mailbox/get-parent-id-correct", get_parent_id_correct(ctx))
        .await;
    ctx.run("mailbox/get-properties-filter", get_properties_filter(ctx))
        .await;
    ctx.run("mailbox/get-state-returned", get_state_returned(ctx))
        .await;
    ctx.run(
        "mailbox/get-account-id-returned",
        get_account_id_returned(ctx),
    )
    .await;
    ctx.run(
        "mailbox/get-total-emails-accurate",
        get_total_emails_accurate(ctx),
    )
    .await;

    ctx.run("mailbox/query-all", query_all(ctx)).await;
    ctx.run("mailbox/query-filter-by-name", query_filter_by_name(ctx))
        .await;
    ctx.run(
        "mailbox/query-filter-by-parent-id",
        query_filter_by_parent_id(ctx),
    )
    .await;
    ctx.run(
        "mailbox/query-filter-by-parent-id-null",
        query_filter_by_parent_id_null(ctx),
    )
    .await;
    ctx.run("mailbox/query-filter-by-role", query_filter_by_role(ctx))
        .await;
    ctx.run(
        "mailbox/query-filter-has-any-role",
        query_filter_has_any_role(ctx),
    )
    .await;
    ctx.run(
        "mailbox/query-filter-has-any-role-false",
        query_filter_has_any_role_false(ctx),
    )
    .await;
    ctx.run(
        "mailbox/query-filter-null-accepted",
        query_filter_null_accepted(ctx),
    )
    .await;
    ctx.run("mailbox/query-limit", query_limit(ctx)).await;
    ctx.run("mailbox/query-position", query_position(ctx)).await;
    ctx.run(
        "mailbox/query-response-structure",
        query_response_structure(ctx),
    )
    .await;
    ctx.run("mailbox/query-sort-by-name", query_sort_by_name(ctx))
        .await;
    ctx.run(
        "mailbox/query-sort-by-sort-order",
        query_sort_by_sort_order(ctx),
    )
    .await;

    ctx.run("mailbox/set-create-top-level", set_create_top_level(ctx))
        .await;
    ctx.run("mailbox/set-create-child", set_create_child(ctx))
        .await;
    ctx.run(
        "mailbox/set-create-returns-server-set-props",
        set_create_returns_server_set_props(ctx),
    )
    .await;
    ctx.run("mailbox/set-rename", set_rename(ctx)).await;
    ctx.run("mailbox/set-change-sort-order", set_change_sort_order(ctx))
        .await;
    ctx.run("mailbox/set-move-parent", set_move_parent(ctx))
        .await;
    ctx.run("mailbox/set-destroy-empty", set_destroy_empty(ctx))
        .await;
    ctx.run("mailbox/set-destroy-not-found", set_destroy_not_found(ctx))
        .await;
    ctx.run(
        "mailbox/set-duplicate-name-same-parent",
        set_duplicate_name_same_parent(ctx),
    )
    .await;
    ctx.run(
        "mailbox/set-cannot-destroy-with-children",
        set_cannot_destroy_with_children(ctx),
    )
    .await;
    ctx.run(
        "mailbox/set-on-destroy-remove-emails",
        set_on_destroy_remove_emails(ctx),
    )
    .await;
    ctx.run(
        "mailbox/set-on-destroy-remove-emails-with-children",
        set_on_destroy_remove_emails_with_children(ctx),
    )
    .await;
    ctx.run("mailbox/set-state-changes", set_state_changes(ctx))
        .await;

    ctx.run("mailbox/changes-after-create", changes_after_create(ctx))
        .await;
    ctx.run("mailbox/changes-after-rename", changes_after_rename(ctx))
        .await;
    ctx.run(
        "mailbox/changes-has-more-changes",
        changes_has_more_changes(ctx),
    )
    .await;
    ctx.run("mailbox/changes-no-changes", changes_no_changes(ctx))
        .await;
    ctx.run(
        "mailbox/changes-response-structure",
        changes_response_structure(ctx),
    )
    .await;

    ctx.run(
        "mailbox/query-changes-after-create",
        query_changes_after_create(ctx),
    )
    .await;
    ctx.run(
        "mailbox/query-changes-filter-null-accepted",
        query_changes_filter_null_accepted(ctx),
    )
    .await;
    ctx.run(
        "mailbox/query-changes-no-changes",
        query_changes_no_changes(ctx),
    )
    .await;
    ctx.run(
        "mailbox/query-changes-response-structure",
        query_changes_response_structure(ctx),
    )
    .await;
}

const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";

fn default_using() -> Vec<&'static str> {
    vec![CORE, MAIL]
}

async fn get_all(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    check(!resp.list().is_empty(), "Must have at least one mailbox")
}

async fn get_by_ids(ctx: &CompCtx<'_>) -> TestOutcome {
    let inbox = ctx.role("inbox").to_string();
    let folder_a = ctx.mailbox("folderA").to_string();
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [&inbox, &folder_a])
        .await;
    let list = resp.list();
    check_eq(list.len(), 2, "list length")?;
    let ids = list.iter().map(|m| m.id()).collect::<Vec<_>>();
    check(ids.contains(&inbox.as_str()), "list includes inbox")?;
    check(ids.contains(&folder_a.as_str()), "list includes folderA")
}

async fn get_inbox_exists(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [ctx.role("inbox")])
        .await;
    check_eq(&resp.list()[0]["role"], &json!("inbox"), "role")
}

async fn get_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), ["nonexistent-mailbox-xyz"])
        .await;
    check(
        resp.method_response()["notFound"].is_array(),
        "notFound must be a String[]",
    )?;
    let not_found = resp.not_found().collect::<Vec<_>>();
    check(
        not_found.contains(&"nonexistent-mailbox-xyz"),
        "notFound includes the requested id",
    )
}

async fn get_mailbox_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [ctx.role("inbox")])
        .await;
    let mb = &resp.list()[0];
    check(mb["id"].is_string(), "id must be string")?;
    check(mb["name"].is_string(), "name must be string")?;
    check(
        mb["parentId"].is_null() || mb["parentId"].is_string(),
        "parentId must be null or string",
    )?;
    check(
        mb["role"].is_null() || mb["role"].is_string(),
        "role must be null or string",
    )?;
    check(mb["sortOrder"].is_number(), "sortOrder must be number")?;
    check(mb["totalEmails"].is_number(), "totalEmails must be number")?;
    check(
        mb["unreadEmails"].is_number(),
        "unreadEmails must be number",
    )?;
    check(
        mb["totalThreads"].is_number(),
        "totalThreads must be number",
    )?;
    check(
        mb["unreadThreads"].is_number(),
        "unreadThreads must be number",
    )?;
    check(
        mb["isSubscribed"].is_boolean(),
        "isSubscribed must be boolean",
    )?;
    let rights = &mb["myRights"];
    for prop in [
        "mayReadItems",
        "mayAddItems",
        "mayRemoveItems",
        "maySetSeen",
        "maySetKeywords",
        "mayCreateChild",
        "mayRename",
        "mayDelete",
        "maySubmit",
    ] {
        check(rights[prop].is_boolean(), format!("{prop} must be boolean"))?;
    }
    Ok(())
}

async fn get_parent_id_correct(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [ctx.mailbox("child1")])
        .await;
    check_eq(
        &resp.list()[0]["parentId"],
        &json!(ctx.mailbox("folderA")),
        "parentId",
    )
}

async fn get_properties_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", ["id", "name", "role"], [ctx.role("inbox")])
        .await;
    let list = resp.list();
    check_eq(list.len(), 1, "list length")?;
    let mb = &list[0];
    check(mb["id"].is_string(), "id present")?;
    check(mb["name"].is_string(), "name present")?;
    check(
        mb.get("totalEmails").is_none(),
        "totalEmails must not be returned when not requested",
    )?;
    check(
        mb.get("unreadEmails").is_none(),
        "unreadEmails must not be returned when not requested",
    )?;
    check(
        mb.get("sortOrder").is_none(),
        "sortOrder must not be returned when not requested",
    )
}

async fn get_state_returned(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = &resp.method_response()["state"];
    check(state.is_string(), "state must be string")?;
    check(
        state.as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "state must not be empty",
    )
}

async fn get_account_id_returned(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    check_eq(
        &resp.method_response()["accountId"],
        &json!(ctx.account_id()),
        "accountId",
    )
}

async fn get_total_emails_accurate(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_query(
            "Email",
            [("inMailbox", json!(ctx.role("inbox")))],
            Vec::<String>::new(),
            [("calculateTotal", json!(true))],
        )
        .await;
    let total = query.method_response()["total"].clone();
    let mb = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [ctx.role("inbox")])
        .await;
    check_eq(
        &mb.list()[0]["totalEmails"],
        &total,
        "totalEmails == query total",
    )
}

async fn query_all(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            Vec::<String>::new(),
            [("calculateTotal", json!(true))],
        )
        .await;
    let ids = resp.ids().count();
    let total = resp.method_response()["total"].as_u64().unwrap_or(0) as usize;
    check(ids > 0, "Must have at least one mailbox")?;
    check_eq(ids, total, "ids length == total")
}

async fn query_filter_by_name(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            [("name", json!("Test Folder A"))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().collect::<Vec<_>>();
    check(ids.contains(&ctx.mailbox("folderA")), "includes folderA")
}

async fn query_filter_by_parent_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            [("parentId", json!(ctx.mailbox("folderA")))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().collect::<Vec<_>>();
    check(ids.contains(&ctx.mailbox("child1")), "includes child1")?;
    check(ids.contains(&ctx.mailbox("child2")), "includes child2")?;
    check_eq(ids.len(), 2, "ids length")
}

async fn query_filter_by_parent_id_null(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            [("parentId", Value::Null)],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().collect::<Vec<_>>();
    check(ids.contains(&ctx.role("inbox")), "includes inbox")?;
    check(ids.contains(&ctx.mailbox("folderA")), "includes folderA")?;
    check(ids.contains(&ctx.mailbox("folderB")), "includes folderB")?;
    check(!ids.contains(&ctx.mailbox("child1")), "excludes child1")?;
    check(!ids.contains(&ctx.mailbox("child2")), "excludes child2")
}

async fn query_filter_by_role(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            [("role", json!("inbox"))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().collect::<Vec<_>>();
    check_eq(ids.len(), 1, "ids length")?;
    check_eq(ids[0], ctx.role("inbox"), "id is inbox")
}

async fn query_filter_has_any_role(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            [("hasAnyRole", json!(true))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().map(|s| s.to_string()).collect::<Vec<_>>();
    let get = ctx.primary.jmap_get("Mailbox", ["id", "role"], &ids).await;
    for mb in get.list() {
        check(
            !mb["role"].is_null(),
            format!("Mailbox {} should have a role", mb.id()),
        )?;
    }
    Ok(())
}

async fn query_filter_has_any_role_false(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            [("hasAnyRole", json!(false))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().collect::<Vec<_>>();
    check(ids.contains(&ctx.mailbox("folderA")), "includes folderA")?;
    check(ids.contains(&ctx.mailbox("folderB")), "includes folderB")
}

async fn query_filter_null_accepted(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([[
                "Mailbox/query",
                { "accountId": ctx.account_id(), "filter": null },
                "0"
            ]]),
        )
        .await;
    let ids = &resp.response_at(0)["ids"];
    check(ids.is_array(), "ids must be array")?;
    check(
        ids.as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "Null filter should return mailboxes",
    )
}

async fn query_limit(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            Vec::<String>::new(),
            [("limit", json!(2)), ("calculateTotal", json!(true))],
        )
        .await;
    let ids = resp.ids().count();
    check(ids <= 2, format!("Expected at most 2 results, got {ids}"))
}

async fn query_position(ctx: &CompCtx<'_>) -> TestOutcome {
    let all = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            ["name"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let all_ids = all.ids().map(|s| s.to_string()).collect::<Vec<_>>();
    if all_ids.len() < 2 {
        return Ok(());
    }
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            ["name"],
            [("position", json!(1))],
        )
        .await;
    let ids = resp.ids().collect::<Vec<_>>();
    check_eq(ids[0], all_ids[1].as_str(), "first id at position 1")?;
    check_eq(&resp.method_response()["position"], &json!(1), "position")
}

async fn query_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["queryState"].is_string(), "queryState must be string")?;
    check(
        r["canCalculateChanges"].is_boolean(),
        "canCalculateChanges must be boolean",
    )?;
    check(r["position"].is_number(), "position must be number")?;
    check(r["ids"].is_array(), "ids must be array")
}

async fn query_sort_by_name(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            ["name"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let ids = resp.ids().map(|s| s.to_string()).collect::<Vec<_>>();
    let get = ctx.primary.jmap_get("Mailbox", ["id", "name"], &ids).await;
    let mut name_map = std::collections::HashMap::new();
    for mb in get.list() {
        name_map.insert(mb.id().to_string(), mb.text_field("name").to_string());
    }
    for i in 1..ids.len() {
        let prev = name_map.get(&ids[i - 1]).cloned().unwrap_or_default();
        let curr = name_map.get(&ids[i]).cloned().unwrap_or_default();
        check(
            prev <= curr,
            format!("Expected '{prev}' <= '{curr}' in sort order"),
        )?;
    }
    Ok(())
}

async fn query_sort_by_sort_order(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            ["sortOrder"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    check(resp.ids().count() > 0, "Must have at least one mailbox")
}

async fn set_create_top_level(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Set Test Top Level", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let created = resp.created(0);
    check(created["id"].is_string(), "created must have id")?;
    let id = created.id().to_string();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    Ok(())
}

async fn set_create_child(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Set Test Child", "parentId": ctx.mailbox("folderA") })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [&id])
        .await;
    let parent = get.list()[0]["parentId"].clone();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    check_eq(&parent, &json!(ctx.mailbox("folderA")), "parentId")
}

async fn set_create_returns_server_set_props(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Server Set Props", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let created = resp.created(0);
    check(created["id"].is_string(), "Server must set id")?;
    let id = created.id().to_string();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    Ok(())
}

async fn set_rename(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Before Rename", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    ctx.primary
        .jmap_update(
            "Mailbox",
            [(id.clone(), json!({ "name": "After Rename" }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [&id])
        .await;
    let name = get.list()[0]["name"].clone();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    check_eq(&name, &json!("After Rename"), "name")
}

async fn set_change_sort_order(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Sort Order Test", "parentId": null, "sortOrder": 10 })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    ctx.primary
        .jmap_update(
            "Mailbox",
            [(id.clone(), json!({ "sortOrder": 99 }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [&id])
        .await;
    let sort_order = get.list()[0]["sortOrder"].clone();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    check_eq(&sort_order, &json!(99), "sortOrder")
}

async fn set_move_parent(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Movable Folder", "parentId": ctx.mailbox("folderA") })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    ctx.primary
        .jmap_update(
            "Mailbox",
            [(id.clone(), json!({ "parentId": ctx.mailbox("folderB") }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [&id])
        .await;
    let parent = get.list()[0]["parentId"].clone();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    check_eq(&parent, &json!(ctx.mailbox("folderB")), "parentId")
}

async fn set_destroy_empty(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Destroy Me", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    let destroy = ctx
        .primary
        .jmap_destroy("Mailbox", [&id], Vec::<(String, Value)>::new())
        .await;
    check(
        destroy.method_response()["destroyed"].is_array(),
        "destroyed must be an array",
    )?;
    let destroyed = destroy.destroyed().collect::<Vec<_>>();
    check(
        destroyed.contains(&id.as_str()),
        "destroyed includes the id",
    )
}

async fn set_destroy_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_destroy(
            "Mailbox",
            ["nonexistent-mailbox-xyz"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let not_destroyed = &resp.method_response()["notDestroyed"];
    check(
        !not_destroyed.is_null(),
        "notDestroyed must not be null when destroying a nonexistent id",
    )?;
    check(
        !not_destroyed["nonexistent-mailbox-xyz"].is_null(),
        "notDestroyed must contain error for the id",
    )?;
    check_eq(
        &not_destroyed["nonexistent-mailbox-xyz"]["type"],
        &json!("notFound"),
        "type",
    )
}

async fn set_duplicate_name_same_parent(ctx: &CompCtx<'_>) -> TestOutcome {
    let create1 = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Duplicate Name Test", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id1 = create1.created(0).id().to_string();

    let create2 = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Duplicate Name Test", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let not_created = &create2.method_response()["notCreated"]["i0"];
    let outcome = check(
        !not_created.is_null(),
        "Server MUST reject duplicate mailbox name under same parent",
    )
    .and_then(|_| check_eq(&not_created["type"], &json!("alreadyExists"), "type"));

    if let Some(created) = create2.method_response()["created"]["i0"].as_object()
        && let Some(id) = created.get("id").and_then(|v| v.as_str())
    {
        ctx.primary
            .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
            .await;
    }
    ctx.primary
        .jmap_destroy("Mailbox", [id1], Vec::<(String, Value)>::new())
        .await;
    outcome
}

async fn set_cannot_destroy_with_children(ctx: &CompCtx<'_>) -> TestOutcome {
    let parent = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Parent With Child", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let parent_id = parent.created(0).id().to_string();
    let child = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "The Child", "parentId": parent_id.clone() })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let child_id = child.created(0).id().to_string();

    let destroy = ctx
        .primary
        .jmap_destroy("Mailbox", [&parent_id], Vec::<(String, Value)>::new())
        .await;
    let not_destroyed = &destroy.method_response()["notDestroyed"][&parent_id];
    let outcome = check(
        !not_destroyed.is_null(),
        "Server MUST refuse to destroy mailbox that has child mailboxes",
    )
    .and_then(|_| check_eq(&not_destroyed["type"], &json!("mailboxHasChild"), "type"));

    ctx.primary
        .jmap_destroy("Mailbox", [&child_id], Vec::<(String, Value)>::new())
        .await;
    ctx.primary
        .jmap_destroy("Mailbox", [&parent_id], Vec::<(String, Value)>::new())
        .await;
    outcome
}

async fn set_on_destroy_remove_emails(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_mb = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Temp With Email", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let mb_id = create_mb.created(0).id().to_string();

    ctx.primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { (mb_id.clone()): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Temp email for destroy test",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "Temporary email body" } },
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let destroy = ctx
        .primary
        .jmap_destroy(
            "Mailbox",
            [&mb_id],
            [("onDestroyRemoveEmails", json!(true))],
        )
        .await;
    check(
        destroy.method_response()["destroyed"].is_array(),
        "destroyed must be an array",
    )?;
    let destroyed = destroy.destroyed().collect::<Vec<_>>();
    check(
        destroyed.contains(&mb_id.as_str()),
        "destroyed includes mailbox",
    )
}

async fn set_on_destroy_remove_emails_with_children(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_parent = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Parent For Destroy Child Test", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let parent_id = create_parent.created(0).id().to_string();
    let create_child = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Child Of Destroy Test", "parentId": parent_id.clone() })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let child_id = create_child.created(0).id().to_string();

    let create_email = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { (parent_id.clone()): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Email in parent with child",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "body" } },
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = create_email.created(0).id().to_string();

    let destroy = ctx
        .primary
        .jmap_destroy(
            "Mailbox",
            [&parent_id],
            [("onDestroyRemoveEmails", json!(true))],
        )
        .await;
    let not_destroyed = &destroy.method_response()["notDestroyed"][&parent_id];
    let outcome = check(
        !not_destroyed.is_null(),
        "Server MUST refuse to destroy mailbox with children even with onDestroyRemoveEmails",
    )
    .and_then(|_| check_eq(&not_destroyed["type"], &json!("mailboxHasChild"), "type"));

    let child_get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), [&child_id])
        .await;
    let child_exists = child_get.list().len();
    let email_get = ctx.primary.jmap_get("Email", ["id"], [&email_id]).await;
    let email_exists = email_get.list().len();

    ctx.primary
        .jmap_destroy("Email", [&email_id], Vec::<(String, Value)>::new())
        .await;
    ctx.primary
        .jmap_destroy("Mailbox", [&child_id], Vec::<(String, Value)>::new())
        .await;
    ctx.primary
        .jmap_destroy("Mailbox", [&parent_id], Vec::<(String, Value)>::new())
        .await;

    outcome?;
    check_eq(child_exists, 1, "Child mailbox must still exist")?;
    check_eq(email_exists, 1, "Email in parent must still exist")
}

async fn set_state_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "State Test", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let r = resp.method_response();
    let old_state = r["oldState"].clone();
    let new_state = r["newState"].clone();
    let id = resp.created(0).id().to_string();
    ctx.primary
        .jmap_destroy("Mailbox", [id], Vec::<(String, Value)>::new())
        .await;
    check(!old_state.is_null(), "oldState present")?;
    check(!new_state.is_null(), "newState present")?;
    check_ne(&old_state, &new_state, "oldState != newState")
}

async fn changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get.state().to_string();
    let resp = ctx.primary.jmap_changes("Mailbox", &state).await;
    let r = resp.method_response();
    check_eq(&r["oldState"], &json!(state), "oldState")?;
    check(!r["newState"].is_null(), "newState present")?;
    check_eq(
        r["created"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "created empty",
    )?;
    check_eq(
        r["updated"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "updated empty",
    )?;
    check_eq(
        r["destroyed"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "destroyed empty",
    )?;
    check_eq(&r["hasMoreChanges"], &json!(false), "hasMoreChanges")
}

async fn changes_after_create(ctx: &CompCtx<'_>) -> TestOutcome {
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let old_state = get.state().to_string();
    let set = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Temp Changes Test", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let temp_id = set.created(0).id().to_string();

    let changes = ctx.primary.jmap_changes("Mailbox", &old_state).await;
    let created = changes.method_response()["created"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let outcome = check(
        created.contains(&temp_id.as_str()),
        "created includes temp mailbox",
    );

    ctx.primary
        .jmap_destroy("Mailbox", [temp_id], Vec::<(String, Value)>::new())
        .await;
    outcome
}

async fn changes_after_rename(ctx: &CompCtx<'_>) -> TestOutcome {
    let set = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "Before Rename", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let mb_id = set.created(0).id().to_string();
    let mid_state = set.method_response()["newState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Mailbox",
            [(mb_id.clone(), json!({ "name": "After Rename" }))],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let changes = ctx.primary.jmap_changes("Mailbox", &mid_state).await;
    let updated = changes.method_response()["updated"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let outcome = check(
        updated.contains(&mb_id.as_str()),
        "updated includes mailbox",
    );

    ctx.primary
        .jmap_destroy("Mailbox", [mb_id], Vec::<(String, Value)>::new())
        .await;
    outcome
}

async fn changes_has_more_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get.state().to_string();
    let resp = ctx.primary.jmap_changes("Mailbox", &state).await;
    check(
        resp.method_response()["hasMoreChanges"].is_boolean(),
        "hasMoreChanges must be boolean",
    )
}

async fn changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let get = ctx
        .primary
        .jmap_get("Mailbox", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get.state().to_string();
    let resp = ctx.primary.jmap_changes("Mailbox", &state).await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["oldState"].is_string(), "oldState must be string")?;
    check(r["newState"].is_string(), "newState must be string")?;
    check(
        r["hasMoreChanges"].is_boolean(),
        "hasMoreChanges must be boolean",
    )?;
    check(r["created"].is_array(), "created must be array")?;
    check(r["updated"].is_array(), "updated must be array")?;
    check(r["destroyed"].is_array(), "destroyed must be array")
}

fn mailbox_query_changes(
    ctx: &CompCtx<'_>,
    filter: Value,
    sort: Option<Value>,
    since_query_state: &str,
) -> Value {
    let mut args = json!({
        "accountId": ctx.account_id(),
        "filter": filter,
        "sinceQueryState": since_query_state,
    });
    if let Some(sort) = sort {
        args.as_object_mut().unwrap().insert("sort".into(), sort);
    }
    json!([["Mailbox/queryChanges", args, "0"]])
}

async fn query_changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let sort = json!([{ "property": "name", "isAscending": true }]);
    let query = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            ["name"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let query_state = query.method_response()["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let calls = mailbox_query_changes(ctx, json!({}), Some(sort), &query_state);
    let resp = ctx.primary.jmap_request(&default_using(), calls).await;
    let r = resp.response_at(0);
    check_eq(&r["oldQueryState"], &json!(query_state), "oldQueryState")?;
    check_eq(
        r["removed"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "removed empty",
    )?;
    check_eq(
        r["added"].as_array().map(|a| a.len()).unwrap_or(usize::MAX),
        0,
        "added empty",
    )
}

async fn query_changes_after_create(ctx: &CompCtx<'_>) -> TestOutcome {
    let sort = json!([{ "property": "name", "isAscending": true }]);
    let query = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            ["name"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let old_query_state = query.method_response()["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let set = ctx
        .primary
        .jmap_create(
            "Mailbox",
            [json!({ "name": "QC Test Mailbox", "parentId": null })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let new_id = set.created(0).id().to_string();

    let calls = mailbox_query_changes(ctx, json!({}), Some(sort), &old_query_state);
    let resp = ctx.primary.jmap_request(&default_using(), calls).await;
    let added_ids = resp.response_at(0)["added"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["id"].as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let outcome = check(
        added_ids.contains(&new_id),
        "added includes the new mailbox",
    );

    ctx.primary
        .jmap_destroy("Mailbox", [new_id], Vec::<(String, Value)>::new())
        .await;
    outcome
}

async fn query_changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_query(
            "Mailbox",
            Vec::<(String, Value)>::new(),
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let query_state = query.method_response()["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let calls = mailbox_query_changes(ctx, json!({}), None, &query_state);
    let resp = ctx.primary.jmap_request(&default_using(), calls).await;
    let r = resp.response_at(0);
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(
        r["oldQueryState"].is_string(),
        "oldQueryState must be string",
    )?;
    check(
        r["newQueryState"].is_string(),
        "newQueryState must be string",
    )?;
    check(r["removed"].is_array(), "removed must be array")?;
    check(r["added"].is_array(), "added must be array")
}

async fn query_changes_filter_null_accepted(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([[
                "Mailbox/query",
                { "accountId": ctx.account_id(), "filter": null },
                "0"
            ]]),
        )
        .await;
    let query_state = query.response_at(0)["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let calls = mailbox_query_changes(ctx, Value::Null, None, &query_state);
    let resp = ctx.primary.jmap_request(&default_using(), calls).await;
    let r = resp.response_at(0);
    check(
        r["oldQueryState"].is_string(),
        "oldQueryState must be string",
    )?;
    check(
        r["newQueryState"].is_string(),
        "newQueryState must be string",
    )?;
    check(r["removed"].is_array(), "removed must be array")?;
    check(r["added"].is_array(), "added must be array")
}
