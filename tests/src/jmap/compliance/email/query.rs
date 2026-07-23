/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::compliance::{CompCtx, TestOutcome, check, check_eq};
use crate::utils::jmap::JmapResponse;
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    ctx.run("email/filter-in-mailbox", filter_in_mailbox(ctx))
        .await;
    ctx.run(
        "email/filter-in-mailbox-other-than",
        filter_in_mailbox_other_than(ctx),
    )
    .await;
    ctx.run("email/filter-before", filter_before(ctx)).await;
    ctx.run("email/filter-after", filter_after(ctx)).await;
    ctx.run("email/filter-min-size", filter_min_size(ctx)).await;
    ctx.run("email/filter-max-size", filter_max_size(ctx)).await;
    ctx.run("email/filter-has-keyword", filter_has_keyword(ctx))
        .await;
    ctx.run("email/filter-not-keyword", filter_not_keyword(ctx))
        .await;
    ctx.run(
        "email/filter-has-attachment-true",
        filter_has_attachment_true(ctx),
    )
    .await;
    ctx.run(
        "email/filter-has-attachment-false",
        filter_has_attachment_false(ctx),
    )
    .await;
    ctx.run(
        "email/filter-text-search-headers",
        filter_text_search_headers(ctx),
    )
    .await;
    ctx.run(
        "email/filter-text-search-body",
        filter_text_search_body(ctx),
    )
    .await;
    ctx.run("email/filter-from", filter_from(ctx)).await;
    ctx.run("email/filter-to", filter_to(ctx)).await;
    ctx.run("email/filter-cc", filter_cc(ctx)).await;
    ctx.run("email/filter-subject", filter_subject(ctx)).await;
    ctx.run("email/filter-body", filter_body(ctx)).await;
    ctx.run(
        "email/filter-header-name-only",
        filter_header_name_only(ctx),
    )
    .await;
    ctx.run(
        "email/filter-header-name-value",
        filter_header_name_value(ctx),
    )
    .await;
    ctx.run(
        "email/filter-some-in-thread-have-keyword",
        filter_some_in_thread_have_keyword(ctx),
    )
    .await;
    ctx.run(
        "email/filter-none-in-thread-have-keyword",
        filter_none_in_thread_have_keyword(ctx),
    )
    .await;
    ctx.run("email/filter-operator-and", filter_operator_and(ctx))
        .await;
    ctx.run("email/filter-operator-or", filter_operator_or(ctx))
        .await;
    ctx.run("email/filter-operator-not", filter_operator_not(ctx))
        .await;
    ctx.run(
        "email/filter-nested-operators",
        filter_nested_operators(ctx),
    )
    .await;
    ctx.run(
        "email/filter-empty-matches-all",
        filter_empty_matches_all(ctx),
    )
    .await;
    ctx.run(
        "email/filter-multiple-conditions-on-one-filter",
        filter_multiple_conditions_on_one_filter(ctx),
    )
    .await;
    ctx.run("email/filter-custom-keyword", filter_custom_keyword(ctx))
        .await;
    ctx.run(
        "email/filter-in-child-mailbox",
        filter_in_child_mailbox(ctx),
    )
    .await;
    ctx.run(
        "email/filter-before-and-after",
        filter_before_and_after(ctx),
    )
    .await;
    ctx.run("email/filter-null-accepted", filter_null_accepted(ctx))
        .await;
    ctx.run(
        "email/filter-from-display-name",
        filter_from_display_name(ctx),
    )
    .await;

    ctx.run("email/sort-received-at-desc", sort_received_at_desc(ctx))
        .await;
    ctx.run("email/sort-received-at-asc", sort_received_at_asc(ctx))
        .await;
    ctx.run("email/sort-size", sort_size(ctx)).await;
    ctx.run("email/sort-from", sort_from(ctx)).await;
    ctx.run("email/sort-to", sort_to(ctx)).await;
    ctx.run("email/sort-subject", sort_subject(ctx)).await;
    ctx.run("email/sort-sent-at", sort_sent_at(ctx)).await;
    ctx.run("email/sort-has-keyword", sort_has_keyword(ctx))
        .await;
    ctx.run("email/sort-multi-property", sort_multi_property(ctx))
        .await;
    ctx.run("email/sort-default-no-sort", sort_default_no_sort(ctx))
        .await;

    ctx.run("email/paging-position-zero", paging_position_zero(ctx))
        .await;
    ctx.run(
        "email/paging-positive-position",
        paging_positive_position(ctx),
    )
    .await;
    ctx.run(
        "email/paging-negative-position",
        paging_negative_position(ctx),
    )
    .await;
    ctx.run("email/paging-limit", paging_limit(ctx)).await;
    ctx.run("email/paging-anchor", paging_anchor(ctx)).await;
    ctx.run("email/paging-anchor-offset", paging_anchor_offset(ctx))
        .await;
    ctx.run("email/paging-calculate-total", paging_calculate_total(ctx))
        .await;
    ctx.run(
        "email/paging-anchor-not-found",
        paging_anchor_not_found(ctx),
    )
    .await;
    ctx.run(
        "email/paging-position-beyond-total",
        paging_position_beyond_total(ctx),
    )
    .await;
    ctx.run(
        "email/paging-response-position",
        paging_response_position(ctx),
    )
    .await;

    ctx.run("email/collapse-threads-basic", collapse_threads_basic(ctx))
        .await;
    ctx.run(
        "email/collapse-threads-one-per-thread",
        collapse_threads_one_per_thread(ctx),
    )
    .await;
    ctx.run(
        "email/collapse-threads-with-filter",
        collapse_threads_with_filter(ctx),
    )
    .await;
    ctx.run(
        "email/collapse-threads-sort-determines-representative",
        collapse_threads_sort_determines_representative(ctx),
    )
    .await;
    ctx.run(
        "email/collapse-threads-calculate-total",
        collapse_threads_calculate_total(ctx),
    )
    .await;
}

async fn email_query(ctx: &CompCtx<'_>, body: Value) -> JmapResponse {
    let mut obj = body;
    if let Value::Object(map) = &mut obj {
        map.insert("accountId".to_string(), json!(ctx.account_id()));
    }
    ctx.primary.jmap_method_call("Email/query", obj).await
}

fn query_ids(resp: &JmapResponse) -> Vec<String> {
    resp.method_response()["ids"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn has_id(ids: &[String], id: &str) -> bool {
    ids.iter().any(|i| i == id)
}

async fn get_emails(ctx: &CompCtx<'_>, ids: &[String], properties: Value) -> Vec<Value> {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({
                "accountId": ctx.account_id(),
                "ids": ids,
                "properties": properties,
            }),
        )
        .await;
    resp.method_response()["list"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn find_email<'a>(list: &'a [Value], id: &str) -> Option<&'a Value> {
    list.iter().find(|e| e["id"].as_str() == Some(id))
}

fn display_value(email: &Value, field: &str) -> String {
    let addr = &email[field][0];
    if let Some(name) = addr["name"].as_str()
        && !name.is_empty()
    {
        return name.to_string();
    }
    addr["email"].as_str().unwrap_or("").to_string()
}

async fn filter_in_mailbox(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": { "inMailbox": ctx.role("inbox") }, "calculateTotal": true }),
    )
    .await;
    let ids = query_ids(&resp);
    check(!ids.is_empty(), "expected at least one email")?;
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should be in inbox",
    )?;
    check(
        !has_id(&ids, ctx.email("very-old")),
        "very-old should not be in inbox",
    )
}

async fn filter_in_mailbox_other_than(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": { "inMailboxOtherThan": [ctx.role("inbox")] } }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("very-old")),
        "very-old should appear",
    )
}

async fn filter_before(ctx: &CompCtx<'_>) -> TestOutcome {
    let five_days_ago = (Utc::now() - ChronoDuration::days(5)).to_rfc3339();
    let resp = email_query(ctx, json!({ "filter": { "before": five_days_ago } })).await;
    let ids = query_ids(&resp);
    check(has_id(&ids, ctx.email("very-old")), "very-old should match")?;
    check(
        !has_id(&ids, ctx.email("custom-keywords")),
        "custom-keywords should not match",
    )
}

async fn filter_after(ctx: &CompCtx<'_>) -> TestOutcome {
    let five_days_ago = (Utc::now() - ChronoDuration::days(5)).to_rfc3339();
    let resp = email_query(ctx, json!({ "filter": { "after": five_days_ago } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("custom-keywords")),
        "custom-keywords should match",
    )?;
    check(
        !has_id(&ids, ctx.email("very-old")),
        "very-old should not match",
    )
}

async fn filter_min_size(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "minSize": 10000 } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("large-email")),
        "large-email should match",
    )?;
    check(
        !has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should not match",
    )
}

async fn filter_max_size(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "maxSize": 1000 } })).await;
    let ids = query_ids(&resp);
    check(
        !has_id(&ids, ctx.email("large-email")),
        "large-email should not match",
    )
}

async fn filter_has_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "hasKeyword": "$flagged" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment should match",
    )?;
    check(
        !has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should not match",
    )
}

async fn filter_not_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "notKeyword": "$seen" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("thread-reply-1")),
        "thread-reply-1 should match",
    )?;
    check(
        !has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should not match",
    )
}

async fn filter_has_attachment_true(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "hasAttachment": true } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment (has PDF attachment) should be in hasAttachment=true results",
    )?;
    let list = get_emails(ctx, &ids, json!(["subject", "from", "hasAttachment"])).await;
    for email in &list {
        check(
            email["hasAttachment"].as_bool().unwrap_or(false),
            format!(
                "hasAttachment=true query returned email without attachment: {}",
                email["subject"].as_str().unwrap_or("")
            ),
        )?;
    }
    Ok(())
}

async fn filter_has_attachment_false(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "hasAttachment": false } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple (no attachment) should be in hasAttachment=false results",
    )?;
    let list = get_emails(ctx, &ids, json!(["subject", "from", "hasAttachment"])).await;
    for email in &list {
        check(
            !email["hasAttachment"].as_bool().unwrap_or(false),
            format!(
                "hasAttachment=false query returned email WITH attachment: {}",
                email["subject"].as_str().unwrap_or("")
            ),
        )?;
    }
    Ok(())
}

async fn filter_text_search_headers(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "text": "Project Alpha" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("thread-reply-2")),
        "thread-reply-2 should match",
    )
}

async fn filter_text_search_body(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "text": "xylophone" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("thread-reply-2")),
        "thread-reply-2 should match",
    )
}

async fn filter_from(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "from": "alice@example.com" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should match",
    )?;
    check(
        has_id(&ids, ctx.email("thread-reply-1")),
        "thread-reply-1 should match",
    )
}

async fn filter_to(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "to": "alice@example.com" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("thread-starter")),
        "thread-starter should match",
    )
}

async fn filter_cc(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "cc": "charlie@example.net" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment should match",
    )
}

async fn filter_subject(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "subject": "Financial Report" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment should match",
    )
}

async fn filter_body(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "body": "conference room" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should match",
    )
}

async fn filter_header_name_only(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "header": ["X-Custom-Header"] } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("special-headers")),
        "special-headers should match",
    )?;
    check(
        !has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should not match",
    )
}

async fn filter_header_name_value(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": { "header": ["X-Custom-Header", "custom-value-12345"] } }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("special-headers")),
        "special-headers should match",
    )
}

async fn filter_some_in_thread_have_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": { "someInThreadHaveKeyword": "$answered" } }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("thread-starter")),
        "thread-starter should match",
    )?;
    check(
        has_id(&ids, ctx.email("thread-reply-1")),
        "thread-reply-1 should match",
    )?;
    check(
        has_id(&ids, ctx.email("thread-reply-2")),
        "thread-reply-2 should match",
    )
}

async fn filter_none_in_thread_have_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": { "noneInThreadHaveKeyword": "$answered" } }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        !has_id(&ids, ctx.email("thread-starter")),
        "thread-starter should be excluded",
    )?;
    check(
        !has_id(&ids, ctx.email("thread-reply-1")),
        "thread-reply-1 should be excluded",
    )?;
    check(
        !has_id(&ids, ctx.email("thread-reply-2")),
        "thread-reply-2 should be excluded",
    )?;
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should be included",
    )
}

async fn filter_operator_and(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {
                "operator": "AND",
                "conditions": [
                    { "hasKeyword": "$seen" },
                    { "inMailbox": ctx.role("inbox") }
                ]
            }
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should match",
    )?;
    check(
        !has_id(&ids, ctx.email("thread-reply-1")),
        "thread-reply-1 should not match",
    )
}

async fn filter_operator_or(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {
                "operator": "OR",
                "conditions": [
                    { "hasKeyword": "$flagged" },
                    { "hasKeyword": "$answered" }
                ]
            }
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment should match",
    )?;
    check(
        has_id(&ids, ctx.email("thread-reply-2")),
        "thread-reply-2 should match",
    )
}

async fn filter_operator_not(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {
                "operator": "NOT",
                "conditions": [{ "hasKeyword": "$seen" }]
            }
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("thread-reply-1")),
        "thread-reply-1 should match",
    )?;
    check(
        !has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should not match",
    )
}

async fn filter_nested_operators(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {
                "operator": "OR",
                "conditions": [
                    {
                        "operator": "AND",
                        "conditions": [
                            { "inMailbox": ctx.role("inbox") },
                            { "hasKeyword": "$seen" }
                        ]
                    },
                    { "hasKeyword": "$flagged" }
                ]
            }
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should match",
    )?;
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment should match",
    )
}

async fn filter_empty_matches_all(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": {}, "calculateTotal": true })).await;
    let total = resp.method_response()["total"].as_u64().unwrap_or(0);
    check(
        total >= ctx.email_ids.len() as u64,
        "Null filter should return all emails",
    )
}

async fn filter_multiple_conditions_on_one_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {
                "inMailbox": ctx.role("inbox"),
                "hasKeyword": "$flagged"
            }
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("html-attachment")),
        "html-attachment should match",
    )
}

async fn filter_custom_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "hasKeyword": "custom_label" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("custom-keywords")),
        "custom-keywords should match",
    )?;
    check_eq(ids.len(), 1, "exactly one match")
}

async fn filter_in_child_mailbox(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": { "inMailbox": ctx.mailbox("child1") } }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("child-mailbox-email")),
        "child-mailbox-email should match",
    )
}

async fn filter_before_and_after(ctx: &CompCtx<'_>) -> TestOutcome {
    let eight_days_ago = (Utc::now() - ChronoDuration::days(8)).to_rfc3339();
    let two_days_ago = (Utc::now() - ChronoDuration::days(2)).to_rfc3339();
    let resp = email_query(
        ctx,
        json!({ "filter": { "after": eight_days_ago, "before": two_days_ago } }),
    )
    .await;
    let ids = query_ids(&resp);
    check(
        !has_id(&ids, ctx.email("very-old")),
        "very-old should be excluded",
    )?;
    check(
        !has_id(&ids, ctx.email("custom-keywords")),
        "custom-keywords should be excluded",
    )
}

async fn filter_null_accepted(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": null, "calculateTotal": true })).await;
    check(
        resp.method_response()["ids"].is_array(),
        "ids must be array",
    )?;
    let total = resp.method_response()["total"].as_u64().unwrap_or(0);
    check(
        total >= ctx.email_ids.len() as u64,
        "Null filter should return all emails",
    )
}

async fn filter_from_display_name(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "from": "Alice Sender" } })).await;
    let ids = query_ids(&resp);
    check(
        has_id(&ids, ctx.email("plain-simple")),
        "plain-simple should match",
    )
}

async fn sort_received_at_desc(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.role("inbox") },
            "sort": [{ "property": "receivedAt", "isAscending": false }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let head = ids.iter().take(5).cloned().collect::<Vec<_>>();
    let list = get_emails(ctx, &head, json!(["receivedAt"])).await;
    let dates = ordered_text(&head, &list, "receivedAt");
    for i in 1..head.len() {
        check(dates[i - 1] >= dates[i], "receivedAt should be descending")?;
    }
    Ok(())
}

async fn sort_received_at_asc(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.mailbox("folderB") },
            "sort": [{ "property": "receivedAt", "isAscending": true }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["receivedAt"])).await;
    let dates = ordered_text(&ids, &list, "receivedAt");
    for i in 1..ids.len() {
        check(dates[i - 1] <= dates[i], "receivedAt should be ascending")?;
    }
    Ok(())
}

async fn sort_size(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.mailbox("folderB") },
            "sort": [{ "property": "size", "isAscending": true }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["size"])).await;
    let sizes = ordered_num(&ids, &list, "size");
    for i in 1..ids.len() {
        check(
            sizes[i - 1] <= sizes[i],
            format!("Expected size {} <= {}", sizes[i - 1], sizes[i]),
        )?;
    }
    Ok(())
}

async fn sort_from(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.mailbox("folderB") },
            "sort": [{ "property": "from", "isAscending": true }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["from"])).await;
    let displays = ordered_display(&ids, &list, "from");
    for i in 1..ids.len() {
        check(
            displays[i - 1] <= displays[i],
            format!(
                "Expected from '{}' <= '{}' in ascending from sort",
                displays[i - 1],
                displays[i]
            ),
        )?;
    }
    Ok(())
}

async fn sort_to(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "to", "isAscending": true }],
            "limit": 10
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["to"])).await;
    let displays = ordered_display(&ids, &list, "to");
    for i in 1..ids.len() {
        check(
            displays[i - 1] <= displays[i],
            format!(
                "Expected to '{}' <= '{}' in ascending to sort",
                displays[i - 1],
                displays[i]
            ),
        )?;
    }
    Ok(())
}

async fn sort_subject(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.mailbox("folderB") },
            "sort": [{ "property": "subject", "isAscending": true }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    let list = get_emails(ctx, &ids, json!(["subject"])).await;
    let subjects = ordered_text(&ids, &list, "subject");
    for i in 1..ids.len() {
        check(
            subjects[i - 1] <= subjects[i],
            format!(
                "Expected '{}' <= '{}' in subject sort",
                subjects[i - 1],
                subjects[i]
            ),
        )?;
    }
    Ok(())
}

async fn sort_sent_at(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.mailbox("folderB") },
            "sort": [{ "property": "sentAt", "isAscending": true }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["sentAt"])).await;
    let dates = ordered_text(&ids, &list, "sentAt");
    for i in 1..ids.len() {
        check(dates[i - 1] <= dates[i], "sentAt should be ascending")?;
    }
    Ok(())
}

async fn sort_has_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.mailbox("folderB") },
            "sort": [{ "property": "hasKeyword", "keyword": "$flagged", "isAscending": false }]
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["keywords"])).await;
    let mut seen_non_flagged = false;
    for id in &ids {
        let flagged = find_email(&list, id)
            .map(|e| e["keywords"]["$flagged"].as_bool().unwrap_or(false))
            .unwrap_or(false);
        if !flagged {
            seen_non_flagged = true;
        } else {
            check(
                !seen_non_flagged,
                "Flagged email appeared after non-flagged email in descending hasKeyword sort",
            )?;
        }
    }
    check_eq(
        ids.first().map(|s| s.as_str()).unwrap_or(""),
        ctx.email("sort-test-2"),
        "sort-test-2 ($flagged) should be first in descending hasKeyword sort",
    )
}

async fn sort_multi_property(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [
                { "property": "receivedAt", "isAscending": false },
                { "property": "subject", "isAscending": true }
            ],
            "limit": 10
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check(ids.len() > 1, "expected more than one email")?;
    let list = get_emails(ctx, &ids, json!(["receivedAt", "subject"])).await;
    let dates = ordered_text(&ids, &list, "receivedAt");
    for i in 1..ids.len() {
        check(
            dates[i - 1] >= dates[i],
            "Primary sort receivedAt should be descending",
        )?;
    }
    Ok(())
}

async fn sort_default_no_sort(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": { "inMailbox": ctx.role("inbox") } })).await;
    let ids = query_ids(&resp);
    check(!ids.is_empty(), "Should return emails with no sort")
}

async fn paging_position_zero(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "position": 0,
            "limit": 5,
            "calculateTotal": true
        }),
    )
    .await;
    check_eq(&resp.method_response()["position"], &json!(0), "position")?;
    let ids = query_ids(&resp);
    check(!ids.is_empty(), "expected at least one email")?;
    check(ids.len() <= 5, "Should respect limit")
}

async fn paging_positive_position(ctx: &CompCtx<'_>) -> TestOutcome {
    let all = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }]
        }),
    )
    .await;
    let all_ids = query_ids(&all);
    if all_ids.len() < 3 {
        return Ok(());
    }
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "position": 2,
            "limit": 3
        }),
    )
    .await;
    check_eq(&resp.method_response()["position"], &json!(2), "position")?;
    let ids = query_ids(&resp);
    check_eq(
        ids.first().map(|s| s.as_str()).unwrap_or(""),
        all_ids[2].as_str(),
        "first id",
    )
}

async fn paging_negative_position(ctx: &CompCtx<'_>) -> TestOutcome {
    let all = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "calculateTotal": true
        }),
    )
    .await;
    let all_ids = query_ids(&all);
    let total = all.method_response()["total"].as_u64().unwrap_or(0) as usize;
    if total < 3 {
        return Ok(());
    }
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "position": -3,
            "calculateTotal": true
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check_eq(
        ids.first().map(|s| s.as_str()).unwrap_or(""),
        all_ids[total - 3].as_str(),
        "first id",
    )
}

async fn paging_limit(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": {}, "limit": 3, "calculateTotal": true }),
    )
    .await;
    let ids = query_ids(&resp);
    let total = resp.method_response()["total"].as_u64().unwrap_or(0);
    check(
        ids.len() <= 3,
        format!("Expected at most 3, got {}", ids.len()),
    )?;
    if total > 3 {
        check_eq(ids.len(), 3, "should be exactly 3")?;
    }
    Ok(())
}

async fn paging_anchor(ctx: &CompCtx<'_>) -> TestOutcome {
    let all = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }]
        }),
    )
    .await;
    let all_ids = query_ids(&all);
    if all_ids.len() < 3 {
        return Ok(());
    }
    let anchor = all_ids[2].clone();
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "anchor": anchor,
            "limit": 3
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check_eq(
        ids.first().map(|s| s.as_str()).unwrap_or(""),
        anchor.as_str(),
        "first id should be anchor",
    )?;
    check_eq(&resp.method_response()["position"], &json!(2), "position")
}

async fn paging_anchor_offset(ctx: &CompCtx<'_>) -> TestOutcome {
    let all = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }]
        }),
    )
    .await;
    let all_ids = query_ids(&all);
    if all_ids.len() < 5 {
        return Ok(());
    }
    let anchor = all_ids[3].clone();
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "anchor": anchor,
            "anchorOffset": -1,
            "limit": 3
        }),
    )
    .await;
    let ids = query_ids(&resp);
    check_eq(
        ids.first().map(|s| s.as_str()).unwrap_or(""),
        all_ids[2].as_str(),
        "first id",
    )
}

async fn paging_calculate_total(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": {}, "limit": 1, "calculateTotal": true }),
    )
    .await;
    check(
        resp.method_response()["total"].is_number(),
        "total must be a number",
    )?;
    let total = resp.method_response()["total"].as_u64().unwrap_or(0);
    check(
        total >= ctx.email_ids.len() as u64,
        "total should be at least the seeded count",
    )
}

async fn paging_anchor_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "anchor": "nonexistent-email-xyz" })).await;
    check_eq(
        resp.name_at(0),
        "error",
        "Server MUST return error for invalid anchor",
    )?;
    check_eq(
        resp.error_type_at(0).unwrap_or(""),
        "anchorNotFound",
        "type",
    )
}

async fn paging_position_beyond_total(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": {}, "position": 99999 })).await;
    let ids = query_ids(&resp);
    check_eq(ids.len(), 0, "expected empty result")
}

async fn paging_response_position(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(ctx, json!({ "filter": {}, "position": 0, "limit": 3 })).await;
    check_eq(&resp.method_response()["position"], &json!(0), "position")
}

async fn collapse_threads_basic(ctx: &CompCtx<'_>) -> TestOutcome {
    let expanded = email_query(
        ctx,
        json!({
            "filter": { "subject": "Project Alpha Discussion" },
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "collapseThreads": false,
            "calculateTotal": true
        }),
    )
    .await;
    let expanded_total = expanded.method_response()["total"].as_u64().unwrap_or(0);

    let collapsed = email_query(
        ctx,
        json!({
            "filter": { "subject": "Project Alpha Discussion" },
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "collapseThreads": true,
            "calculateTotal": true
        }),
    )
    .await;
    let collapsed_total = collapsed.method_response()["total"].as_u64().unwrap_or(0);

    check(
        collapsed_total < expanded_total,
        "Collapsed total should be less than expanded",
    )
}

async fn collapse_threads_one_per_thread(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "collapseThreads": true
        }),
    )
    .await;
    let ids = query_ids(&resp);
    let list = get_emails(ctx, &ids, json!(["threadId"])).await;
    let thread_ids = list
        .iter()
        .map(|e| e["threadId"].as_str().unwrap_or("").to_string())
        .collect::<Vec<_>>();
    let unique = thread_ids.iter().collect::<std::collections::HashSet<_>>();
    check_eq(
        thread_ids.len(),
        unique.len(),
        "Each thread should appear only once",
    )
}

async fn collapse_threads_with_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": { "inMailbox": ctx.role("inbox") },
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "collapseThreads": true
        }),
    )
    .await;
    let ids = query_ids(&resp);
    let thread_email_ids = [ctx.email("thread-reply-1"), ctx.email("thread-reply-2")];
    let matching = ids
        .iter()
        .filter(|id| thread_email_ids.contains(&id.as_str()))
        .count();
    check(
        matching <= 1,
        "At most one email from the thread should appear",
    )
}

async fn collapse_threads_sort_determines_representative(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({
            "filter": {},
            "sort": [{ "property": "receivedAt", "isAscending": false }],
            "collapseThreads": true
        }),
    )
    .await;
    let ids = query_ids(&resp);
    if has_id(&ids, ctx.email("thread-reply-2")) {
        check(
            !has_id(&ids, ctx.email("thread-reply-1")),
            "thread-reply-1 should not appear",
        )?;
        check(
            !has_id(&ids, ctx.email("thread-starter")),
            "thread-starter should not appear",
        )?;
    }
    Ok(())
}

async fn collapse_threads_calculate_total(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_query(
        ctx,
        json!({ "filter": {}, "collapseThreads": true, "calculateTotal": true }),
    )
    .await;
    let total = resp.method_response()["total"].as_u64().unwrap_or(0) as usize;
    let ids = query_ids(&resp);
    check_eq(total, ids.len(), "total should equal ids length")
}

fn ordered_text(ids: &[String], list: &[Value], field: &str) -> Vec<String> {
    ids.iter()
        .map(|id| {
            find_email(list, id)
                .and_then(|e| e[field].as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

fn ordered_num(ids: &[String], list: &[Value], field: &str) -> Vec<i64> {
    ids.iter()
        .map(|id| {
            find_email(list, id)
                .and_then(|e| e[field].as_i64())
                .unwrap_or(0)
        })
        .collect()
}

fn ordered_display(ids: &[String], list: &[Value], field: &str) -> Vec<String> {
    ids.iter()
        .map(|id| {
            find_email(list, id)
                .map(|e| display_value(e, field))
                .unwrap_or_default()
        })
        .collect()
}
