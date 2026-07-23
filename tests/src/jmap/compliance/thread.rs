/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_eq};
use crate::utils::jmap::JmapUtils;
use serde_json::json;

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] thread");

    ctx.run("thread/get-thread-by-id", get_thread_by_id(ctx))
        .await;
    ctx.run(
        "thread/get-single-email-thread",
        get_single_email_thread(ctx),
    )
    .await;
    ctx.run(
        "thread/get-thread-email-ids-order",
        get_thread_email_ids_order(ctx),
    )
    .await;
    ctx.run(
        "thread/get-thread-response-structure",
        get_thread_response_structure(ctx),
    )
    .await;
    ctx.run("thread/get-thread-not-found", get_thread_not_found(ctx))
        .await;

    ctx.run(
        "thread/changes-after-new-email",
        changes_after_new_email(ctx),
    )
    .await;
    ctx.run(
        "thread/changes-after-email-destroy",
        changes_after_email_destroy(ctx),
    )
    .await;
    ctx.run("thread/changes-no-changes", changes_no_changes(ctx))
        .await;
    ctx.run(
        "thread/changes-response-structure",
        changes_response_structure(ctx),
    )
    .await;
}

async fn thread_id_of(ctx: &CompCtx<'_>, email_key: &str) -> String {
    let resp = ctx
        .primary
        .jmap_get("Email", ["threadId"], [ctx.email(email_key)])
        .await;
    resp.list()[0].text_field("threadId").to_string()
}

async fn get_thread_by_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let thread_id = thread_id_of(ctx, "thread-starter").await;
    let resp = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), [thread_id.as_str()])
        .await;
    let list = resp.list();
    check_eq(list.len(), 1, "list length")?;
    check_eq(list[0].text_field("id"), thread_id.as_str(), "thread id")?;
    let email_ids = list[0]["emailIds"].as_array();
    check(email_ids.is_some(), "emailIds must be array")?;
    check(
        email_ids.map(|a| a.len()).unwrap_or(0) >= 3,
        "Thread should have at least 3 emails",
    )
}

async fn get_single_email_thread(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let thread_id = thread_id_of(ctx, "plain-simple").await;
    let resp = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), [thread_id.as_str()])
        .await;
    let list = resp.list();
    let email_ids = list[0]["emailIds"].as_array().map(|a| a.len()).unwrap_or(0);
    check_eq(email_ids, 1, "single email thread length")?;
    check_eq(
        list[0]["emailIds"][0].as_str().unwrap_or(""),
        email_id,
        "emailIds[0]",
    )
}

async fn get_thread_email_ids_order(ctx: &CompCtx<'_>) -> TestOutcome {
    let thread_id = thread_id_of(ctx, "thread-starter").await;
    let resp = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), [thread_id.as_str()])
        .await;
    let email_ids = resp.list()[0]["emailIds"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();

    let get_result = ctx
        .primary
        .jmap_get("Email", ["receivedAt"], email_ids.iter())
        .await;
    let mut id_to_date = std::collections::HashMap::new();
    for email in get_result.list() {
        let id = email.text_field("id").to_string();
        let received = email["receivedAt"].as_str().unwrap_or("").to_string();
        id_to_date.insert(id, received);
    }

    for i in 1..email_ids.len() {
        let prev = id_to_date.get(&email_ids[i - 1]);
        let curr = id_to_date.get(&email_ids[i]);
        if let (Some(prev), Some(curr)) = (prev, curr) {
            check(prev <= curr, "emailIds should be ordered by receivedAt")?;
        }
    }
    Ok(())
}

async fn get_thread_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["state"].is_string(), "state must be string")?;
    check(r["list"].is_array(), "list must be array")?;
    check(r["notFound"].is_array(), "notFound must be array")
}

async fn get_thread_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), ["nonexistent-thread-xyz"])
        .await;
    let r = resp.method_response();
    check(
        r["notFound"].is_array(),
        format!(
            "Thread/get notFound MUST be a String[] (RFC 8620 5.1), got {}",
            r["notFound"]
        ),
    )?;
    let not_found = resp.not_found().collect::<Vec<_>>();
    check(
        not_found.contains(&"nonexistent-thread-xyz"),
        "notFound should include nonexistent-thread-xyz",
    )
}

async fn changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get_result.state().to_string();

    let resp = ctx.primary.jmap_changes("Thread", &state).await;
    let r = resp.method_response();
    check_eq(
        r["oldState"].as_str().unwrap_or(""),
        state.as_str(),
        "oldState",
    )?;
    check_eq(
        r["created"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "created length",
    )?;
    check_eq(
        r["updated"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "updated length",
    )?;
    check_eq(
        r["destroyed"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "destroyed length",
    )
}

fn email_create_item(ctx: &CompCtx<'_>, subject: &str) -> serde_json::Value {
    json!({
        "mailboxIds": { (ctx.role("inbox")): true },
        "from": [{ "name": "Test", "email": "test@example.com" }],
        "to": [{ "name": "User", "email": "user@example.com" }],
        "subject": subject,
        "bodyStructure": { "type": "text/plain", "partId": "1" },
        "bodyValues": { "1": { "value": "body" } },
    })
}

async fn changes_after_new_email(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let old_state = get_result.state().to_string();

    let create_result = ctx
        .primary
        .jmap_create(
            "Email",
            [email_create_item(ctx, "New thread for changes test")],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;
    let email_id = create_result.created(0).text_field("id").to_string();

    let changes = ctx.primary.jmap_changes("Thread", &old_state).await;
    let created_len = changes.method_response()["created"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);

    let outcome = check(created_len > 0, "Should have at least one new thread");

    ctx.primary
        .jmap_destroy(
            "Email",
            [email_id.as_str()],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    outcome
}

async fn changes_after_email_destroy(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_result = ctx
        .primary
        .jmap_create(
            "Email",
            [email_create_item(ctx, "Thread to destroy")],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;
    let email_id = create_result.created(0).text_field("id").to_string();

    let email_get = ctx
        .primary
        .jmap_get("Email", ["threadId"], [email_id.as_str()])
        .await;
    let thread_id = email_get.list()[0].text_field("threadId").to_string();

    let thread_get = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let mid_state = thread_get.state().to_string();

    ctx.primary
        .jmap_destroy(
            "Email",
            [email_id.as_str()],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    let changes = ctx.primary.jmap_changes("Thread", &mid_state).await;
    let destroyed = changes.method_response()["destroyed"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();

    check(
        destroyed.contains(&thread_id),
        format!("destroyed should include {thread_id}"),
    )
}

async fn changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get("Thread", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get_result.state().to_string();

    let resp = ctx.primary.jmap_changes("Thread", &state).await;
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
