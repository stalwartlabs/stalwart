/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_contains, check_eq};
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] search-snippet");

    ctx.run("search-snippet/snippet-body-match", snippet_body_match(ctx))
        .await;
    ctx.run(
        "search-snippet/snippet-subject-match",
        snippet_subject_match(ctx),
    )
    .await;
    ctx.run("search-snippet/snippet-mark-tags", snippet_mark_tags(ctx))
        .await;
    ctx.run("search-snippet/snippet-not-found", snippet_not_found(ctx))
        .await;
    ctx.run(
        "search-snippet/snippet-null-when-no-match",
        snippet_null_when_no_match(ctx),
    )
    .await;
    ctx.run(
        "search-snippet/snippet-response-structure",
        snippet_response_structure(ctx),
    )
    .await;
}

async fn snippet_body_match(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_query(
            "Email",
            [("text", json!("xylophone"))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_ids = query.ids().map(|s| s.to_string()).collect::<Vec<_>>();
    check(
        !email_ids.is_empty(),
        "expected at least one matching email",
    )?;

    let resp = ctx
        .primary
        .jmap_method_call(
            "SearchSnippet/get",
            json!({
                "accountId": ctx.account_id(),
                "emailIds": email_ids,
                "filter": { "text": "xylophone" }
            }),
        )
        .await;
    let list = resp.method_response()["list"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    check(!list.is_empty(), "expected at least one snippet")?;

    let snippet = list
        .iter()
        .find(|s| s["emailId"].as_str() == Some(ctx.email("thread-reply-2")));
    check(snippet.is_some(), "Should have snippet for matching email")?;

    let snippet = snippet.unwrap();
    if let Some(preview) = snippet["preview"].as_str() {
        check(
            preview.to_lowercase().contains("xylophone") || preview.contains("<mark>"),
            "Preview should highlight the match",
        )?;
    }
    Ok(())
}

async fn snippet_subject_match(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_query(
            "Email",
            [("text", json!("Financial Report"))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_ids = query.ids().map(|s| s.to_string()).collect::<Vec<_>>();

    if email_ids.is_empty() {
        return Ok(());
    }

    let resp = ctx
        .primary
        .jmap_method_call(
            "SearchSnippet/get",
            json!({
                "accountId": ctx.account_id(),
                "emailIds": email_ids,
                "filter": { "text": "Financial Report" }
            }),
        )
        .await;
    let list = resp.method_response()["list"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let snippet = list
        .iter()
        .find(|s| s["emailId"].as_str() == Some(ctx.email("html-attachment")));
    if let Some(snippet) = snippet
        && let Some(subject) = snippet["subject"].as_str()
    {
        check(
            subject.contains("Financial") || subject.contains("<mark>"),
            "Subject snippet should highlight match",
        )?;
    }
    Ok(())
}

async fn snippet_null_when_no_match(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "SearchSnippet/get",
            json!({
                "accountId": ctx.account_id(),
                "emailIds": [ctx.email("plain-simple")],
                "filter": { "text": "xylophone" }
            }),
        )
        .await;
    let list = resp.method_response()["list"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !list.is_empty() {
        let snippet = list[0].as_object();
        check_eq(
            snippet.and_then(|o| o.get("subject")),
            Some(&json!(null)),
            "subject must be present and null",
        )?;
        check_eq(
            snippet.and_then(|o| o.get("preview")),
            Some(&json!(null)),
            "preview must be present and null",
        )?;
    }
    Ok(())
}

async fn snippet_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "SearchSnippet/get",
            json!({
                "accountId": ctx.account_id(),
                "emailIds": [ctx.email("plain-simple")],
                "filter": { "text": "meeting" }
            }),
        )
        .await;
    let obj = resp.method_response().as_object();
    check(
        obj.and_then(|o| o.get("accountId"))
            .map(|v| v.is_string())
            .unwrap_or(false),
        "accountId must be a string",
    )?;
    check(
        obj.and_then(|o| o.get("list"))
            .map(|v| v.is_array())
            .unwrap_or(false),
        "list must be array",
    )?;
    let not_found = obj.and_then(|o| o.get("notFound"));
    check(
        matches!(not_found, Some(Value::Null))
            || not_found
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false),
        "notFound must be present and null or a non-empty array",
    )
}

async fn snippet_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "SearchSnippet/get",
            json!({
                "accountId": ctx.account_id(),
                "emailIds": ["nonexistent-email-xyz"],
                "filter": { "text": "test" }
            }),
        )
        .await;
    let r = resp.method_response();
    check(
        r["notFound"].is_array(),
        "Expected notFound to contain 'nonexistent-email-xyz', but got null (server claims all email ids were found)",
    )?;
    let not_found = r["notFound"].as_array().cloned().unwrap_or_default();
    check(
        not_found
            .iter()
            .any(|v| v.as_str() == Some("nonexistent-email-xyz")),
        "notFound must include nonexistent-email-xyz",
    )
}

async fn snippet_mark_tags(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_query(
            "Email",
            [("text", json!("conference"))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_ids = query.ids().map(|s| s.to_string()).collect::<Vec<_>>();
    if email_ids.is_empty() {
        return Ok(());
    }

    let resp = ctx
        .primary
        .jmap_method_call(
            "SearchSnippet/get",
            json!({
                "accountId": ctx.account_id(),
                "emailIds": email_ids,
                "filter": { "text": "conference" }
            }),
        )
        .await;
    let list = resp.method_response()["list"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let snippet = list.iter().find(|s| !s["preview"].is_null());
    if let Some(snippet) = snippet
        && let Some(preview) = snippet["preview"].as_str()
    {
        check_contains(preview, "<mark>", "preview should contain <mark>")?;
        check_contains(preview, "</mark>", "preview should contain </mark>")?;
    }
    Ok(())
}
