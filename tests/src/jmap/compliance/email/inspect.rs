/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::compliance::{CompCtx, TestOutcome, check, check_contains, check_eq};
use crate::utils::jmap::JmapResponse;
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    ctx.run("email/get-by-id", get_by_id(ctx)).await;
    ctx.run(
        "email/get-metadata-properties",
        get_metadata_properties(ctx),
    )
    .await;
    ctx.run("email/get-mailbox-ids", get_mailbox_ids(ctx)).await;
    ctx.run("email/get-keywords", get_keywords(ctx)).await;
    ctx.run(
        "email/get-has-attachment-true",
        get_has_attachment_true(ctx),
    )
    .await;
    ctx.run(
        "email/get-has-attachment-false",
        get_has_attachment_false(ctx),
    )
    .await;
    ctx.run(
        "email/get-thread-id-consistent",
        get_thread_id_consistent(ctx),
    )
    .await;
    ctx.run("email/get-not-found", get_not_found(ctx)).await;
    ctx.run("email/get-properties-filter", get_properties_filter(ctx))
        .await;
    ctx.run("email/get-preview-is-text", get_preview_is_text(ctx))
        .await;
    ctx.run(
        "email/get-received-at-is-utc-date",
        get_received_at_is_utc_date(ctx),
    )
    .await;
    ctx.run("email/get-multiple-emails", get_multiple_emails(ctx))
        .await;
    ctx.run("email/get-state-returned", get_state_returned(ctx))
        .await;

    ctx.run("email/body-structure", body_structure(ctx)).await;
    ctx.run("email/body-text-body", body_text_body(ctx)).await;
    ctx.run("email/body-html-body", body_html_body(ctx)).await;
    ctx.run("email/body-attachments", body_attachments(ctx))
        .await;
    ctx.run("email/body-values-text", body_values_text(ctx))
        .await;
    ctx.run("email/body-values-html", body_values_html(ctx))
        .await;
    ctx.run("email/body-values-all", body_values_all(ctx)).await;
    ctx.run(
        "email/body-max-body-value-bytes",
        body_max_body_value_bytes(ctx),
    )
    .await;
    ctx.run("email/body-properties-filter", body_properties_filter(ctx))
        .await;
    ctx.run(
        "email/body-multipart-alternative-text-and-html",
        body_multipart_alternative_text_and_html(ctx),
    )
    .await;
    ctx.run(
        "email/body-inline-attachment-cid",
        body_inline_attachment_cid(ctx),
    )
    .await;
    ctx.run(
        "email/body-attachment-blob-id",
        body_attachment_blob_id(ctx),
    )
    .await;
    ctx.run("email/body-non-utf8-charset", body_non_utf8_charset(ctx))
        .await;
    ctx.run(
        "email/body-invalid-ascii-handling",
        body_invalid_ascii_handling(ctx),
    )
    .await;

    ctx.run("email/header-from", header_from(ctx)).await;
    ctx.run("email/header-to", header_to(ctx)).await;
    ctx.run("email/header-cc", header_cc(ctx)).await;
    ctx.run("email/header-subject", header_subject(ctx)).await;
    ctx.run("email/header-subject-empty", header_subject_empty(ctx))
        .await;
    ctx.run("email/header-sent-at", header_sent_at(ctx)).await;
    ctx.run("email/header-message-id", header_message_id(ctx))
        .await;
    ctx.run("email/header-in-reply-to", header_in_reply_to(ctx))
        .await;
    ctx.run("email/header-references", header_references(ctx))
        .await;
    ctx.run("email/header-raw-access", header_raw_access(ctx))
        .await;
    ctx.run("email/header-as-addresses", header_as_addresses(ctx))
        .await;
    ctx.run("email/header-as-message-ids", header_as_message_ids(ctx))
        .await;
    ctx.run("email/header-as-date", header_as_date(ctx)).await;
    ctx.run("email/header-as-urls", header_as_urls(ctx)).await;
    ctx.run("email/header-custom-header", header_custom_header(ctx))
        .await;
    ctx.run(
        "email/header-intl-from-decoded",
        header_intl_from_decoded(ctx),
    )
    .await;
    ctx.run(
        "email/header-as-grouped-addresses",
        header_as_grouped_addresses(ctx),
    )
    .await;
    ctx.run("email/header-raw-form", header_raw_form(ctx)).await;
    ctx.run(
        "email/header-case-insensitive",
        header_case_insensitive(ctx),
    )
    .await;
    ctx.run("email/header-bcc", header_bcc(ctx)).await;

    ctx.run("email/parse-valid-message", parse_valid_message(ctx))
        .await;
    ctx.run("email/parse-null-metadata", parse_null_metadata(ctx))
        .await;
    ctx.run("email/parse-not-found", parse_not_found(ctx)).await;
    ctx.run("email/parse-not-parsable", parse_not_parsable(ctx))
        .await;
    ctx.run("email/parse-body-values", parse_body_values(ctx))
        .await;
    ctx.run(
        "email/parse-response-structure",
        parse_response_structure(ctx),
    )
    .await;
}

async fn email_get(ctx: &CompCtx<'_>, mut args: Value) -> JmapResponse {
    if let Value::Object(map) = &mut args {
        map.insert("accountId".to_string(), json!(ctx.account_id()));
    }
    ctx.primary.jmap_method_call("Email/get", args).await
}

async fn email_parse(ctx: &CompCtx<'_>, mut args: Value) -> JmapResponse {
    if let Value::Object(map) = &mut args {
        map.insert("accountId".to_string(), json!(ctx.account_id()));
    }
    ctx.primary.jmap_method_call("Email/parse", args).await
}

async fn upload_message(ctx: &CompCtx<'_>, content_type: &str, data: &str) -> String {
    let upload = ctx
        .upload(ctx.primary, content_type, data.as_bytes().to_vec())
        .await;
    upload["blobId"]
        .as_str()
        .unwrap_or_else(|| panic!("upload missing blobId: {upload}"))
        .to_string()
}

fn first_email(resp: &JmapResponse) -> &Value {
    resp.list()
        .first()
        .unwrap_or_else(|| panic!("Email/get returned empty list: {resp:?}"))
}

fn count(v: &Value) -> usize {
    v.as_array().map(|a| a.len()).unwrap_or(0)
}

fn date_is_valid(s: &str) -> bool {
    s.len() >= 10 && s.as_bytes()[4] == b'-'
}

fn find_part<'a>(part: &'a Value, type_: &str) -> Option<&'a Value> {
    if part["type"]
        .as_str()
        .map(|t| t.contains(type_))
        .unwrap_or(false)
    {
        return Some(part);
    }
    if let Some(sub_parts) = part["subParts"].as_array() {
        for sub in sub_parts {
            if let Some(found) = find_part(sub, type_) {
                return Some(found);
            }
        }
    }
    None
}

async fn get_by_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(ctx, json!({ "ids": [email_id] })).await;
    let list = resp.list();
    check_eq(list.len(), 1, "list length")?;
    check_eq(list[0]["id"].as_str().unwrap_or(""), email_id, "id")
}

async fn get_metadata_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": [
                "id", "blobId", "threadId", "mailboxIds", "keywords",
                "size", "receivedAt", "hasAttachment", "preview"
            ]
        }),
    )
    .await;
    let email = first_email(&resp);
    check(email["id"].is_string(), "id must be string")?;
    check(email["blobId"].is_string(), "blobId must be string")?;
    check(email["threadId"].is_string(), "threadId must be string")?;
    check(email["mailboxIds"].is_object(), "mailboxIds must be object")?;
    check(email["keywords"].is_object(), "keywords must be object")?;
    check(email["size"].is_number(), "size must be number")?;
    check(
        email["size"].as_i64().unwrap_or(0) > 0,
        "size must be greater than 0",
    )?;
    check(email["receivedAt"].is_string(), "receivedAt must be string")?;
    check(
        email["hasAttachment"].is_boolean(),
        "hasAttachment must be boolean",
    )?;
    check(email["preview"].is_string(), "preview must be string")
}

async fn get_mailbox_ids(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("multi-mailbox");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["mailboxIds"] }),
    )
    .await;
    let email = first_email(&resp);
    let mailbox_ids = &email["mailboxIds"];
    check_eq(&mailbox_ids[ctx.role("inbox")], &json!(true), "inbox")?;
    check_eq(
        &mailbox_ids[ctx.mailbox("folderA")],
        &json!(true),
        "folderA",
    )
}

async fn get_keywords(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("custom-keywords");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["keywords"] }),
    )
    .await;
    let email = first_email(&resp);
    let keywords = &email["keywords"];
    check_eq(&keywords["$seen"], &json!(true), "$seen")?;
    check_eq(&keywords["$forwarded"], &json!(true), "$forwarded")?;
    check_eq(&keywords["custom_label"], &json!(true), "custom_label")
}

async fn get_has_attachment_true(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-attachment");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["hasAttachment"] }),
    )
    .await;
    let email = first_email(&resp);
    check_eq(&email["hasAttachment"], &json!(true), "hasAttachment")
}

async fn get_has_attachment_false(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["hasAttachment"] }),
    )
    .await;
    let email = first_email(&resp);
    check_eq(&email["hasAttachment"], &json!(false), "hasAttachment")
}

async fn get_thread_id_consistent(ctx: &CompCtx<'_>) -> TestOutcome {
    let ids = [
        ctx.email("thread-starter"),
        ctx.email("thread-reply-1"),
        ctx.email("thread-reply-2"),
    ];
    let resp = email_get(ctx, json!({ "ids": ids, "properties": ["threadId"] })).await;
    let list = resp.list();
    check_eq(list.len(), 3, "list length")?;
    check_eq(&list[0]["threadId"], &list[1]["threadId"], "thread 0 == 1")?;
    check_eq(&list[1]["threadId"], &list[2]["threadId"], "thread 1 == 2")
}

async fn get_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_get(ctx, json!({ "ids": ["nonexistent-email-xyz"] })).await;
    let not_found = &resp.method_response()["notFound"];
    check(
        not_found.is_array(),
        format!("notFound must be an array, got {not_found}"),
    )?;
    check(
        not_found
            .as_array()
            .map(|a| {
                a.iter()
                    .any(|v| v.as_str() == Some("nonexistent-email-xyz"))
            })
            .unwrap_or(false),
        "notFound must include nonexistent-email-xyz",
    )
}

async fn get_properties_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["id", "subject"] }),
    )
    .await;
    let email = first_email(&resp);
    check(!email["id"].is_null(), "id must be present")?;
    check(email.get("subject").is_some(), "subject must be defined")
}

async fn get_preview_is_text(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["preview"] })).await;
    let email = first_email(&resp);
    let preview = email["preview"].as_str().unwrap_or("");
    check(email["preview"].is_string(), "preview must be string")?;
    check(!preview.is_empty(), "preview length must be greater than 0")?;
    check(!preview.contains("<html>"), "Preview should be plain text")
}

async fn get_received_at_is_utc_date(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["receivedAt"] }),
    )
    .await;
    let email = first_email(&resp);
    let received = email["receivedAt"].as_str().unwrap_or("");
    check(date_is_valid(received), "receivedAt must be a valid date")
}

async fn get_multiple_emails(ctx: &CompCtx<'_>) -> TestOutcome {
    let ids = [
        ctx.email("plain-simple"),
        ctx.email("html-attachment"),
        ctx.email("thread-starter"),
    ];
    let resp = email_get(ctx, json!({ "ids": ids, "properties": ["id"] })).await;
    check_eq(resp.list().len(), 3, "list length")
}

async fn get_state_returned(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_get(ctx, json!({ "ids": [] })).await;
    check(
        resp.method_response()["state"].is_string(),
        "state must be string",
    )
}

async fn body_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-attachment");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["bodyStructure"],
            "bodyProperties": ["partId", "type", "name", "disposition", "size", "subParts"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let bs = &email["bodyStructure"];
    check(bs.is_object(), "bodyStructure must be present")?;
    check(bs["type"].is_string(), "type must be string")
}

async fn body_text_body(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["textBody"],
            "bodyProperties": ["partId", "type"],
            "fetchTextBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    let text_body = &email["textBody"];
    check(text_body.is_array(), "textBody must be array")?;
    check(
        count(text_body) > 0,
        "textBody length must be greater than 0",
    )?;
    check_contains(
        text_body[0]["type"].as_str().unwrap_or(""),
        "text/plain",
        "type",
    )
}

async fn body_html_body(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-only");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["htmlBody"],
            "bodyProperties": ["partId", "type"],
            "fetchHTMLBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    let html_body = &email["htmlBody"];
    check(html_body.is_array(), "htmlBody must be array")?;
    check(
        count(html_body) > 0,
        "htmlBody length must be greater than 0",
    )?;
    check_contains(
        html_body[0]["type"].as_str().unwrap_or(""),
        "text/html",
        "type",
    )
}

async fn body_attachments(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-attachment");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["attachments"],
            "bodyProperties": ["partId", "type", "name", "disposition", "size"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let attachments = &email["attachments"];
    check(attachments.is_array(), "attachments must be array")?;
    check(
        count(attachments) > 0,
        "attachments length must be greater than 0",
    )?;
    check_eq(&attachments[0]["name"], &json!("report.pdf"), "name")
}

async fn body_values_text(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["textBody", "bodyValues"],
            "bodyProperties": ["partId"],
            "fetchTextBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    let body_values = &email["bodyValues"];
    check(body_values.is_object(), "bodyValues must be present")?;
    let map = body_values.as_object().unwrap();
    check(!map.is_empty(), "Must have at least one body value")?;
    let first = map.values().next().unwrap();
    check(first["value"].is_string(), "value must be string")?;
    check_contains(
        first["value"].as_str().unwrap_or(""),
        "conference room",
        "value",
    )?;
    check(
        first["isEncodingProblem"].is_boolean(),
        "isEncodingProblem must be boolean",
    )?;
    check(
        first["isTruncated"].is_boolean(),
        "isTruncated must be boolean",
    )?;
    check_eq(&first["isTruncated"], &json!(false), "isTruncated")
}

async fn body_values_html(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-only");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["htmlBody", "bodyValues"],
            "bodyProperties": ["partId"],
            "fetchHTMLBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    let map = email["bodyValues"]
        .as_object()
        .unwrap_or_else(|| panic!("bodyValues missing: {email}"));
    check(!map.is_empty(), "Must have at least one body value")?;
    let first = map.values().next().unwrap();
    check_contains(
        first["value"].as_str().unwrap_or(""),
        "Weekly Digest",
        "value",
    )
}

async fn body_values_all(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-only");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["textBody", "htmlBody", "bodyValues"],
            "bodyProperties": ["partId", "type"],
            "fetchAllBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    let len = email["bodyValues"]
        .as_object()
        .map(|m| m.len())
        .unwrap_or(0);
    check(len >= 2, "Must have values for both text and HTML parts")
}

async fn body_max_body_value_bytes(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("large-email");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["textBody", "bodyValues"],
            "bodyProperties": ["partId"],
            "fetchTextBodyValues": true,
            "maxBodyValueBytes": 100
        }),
    )
    .await;
    let email = first_email(&resp);
    let map = email["bodyValues"]
        .as_object()
        .unwrap_or_else(|| panic!("bodyValues missing: {email}"));
    check(!map.is_empty(), "bodyValues must have keys")?;
    let bv = map.values().next().unwrap();
    check(
        bv["value"].as_str().map(|s| s.len()).unwrap_or(0) <= 200,
        "Body should be truncated near maxBodyValueBytes",
    )?;
    check_eq(&bv["isTruncated"], &json!(true), "isTruncated")
}

async fn body_properties_filter(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-attachment");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["bodyStructure"],
            "bodyProperties": ["partId", "type"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let bs = &email["bodyStructure"];
    check(bs.is_object(), "bodyStructure must be present")?;
    if !bs["type"].is_null() {
        check(bs["type"].is_string(), "type must be string")?;
    }
    Ok(())
}

async fn body_multipart_alternative_text_and_html(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-only");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["textBody", "htmlBody"],
            "bodyProperties": ["partId", "type"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let text_body = &email["textBody"];
    let html_body = &email["htmlBody"];
    check(
        count(text_body) > 0,
        "textBody length must be greater than 0",
    )?;
    check(
        count(html_body) > 0,
        "htmlBody length must be greater than 0",
    )?;
    check_contains(
        text_body[0]["type"].as_str().unwrap_or(""),
        "text/plain",
        "textBody type",
    )?;
    check_contains(
        html_body[0]["type"].as_str().unwrap_or(""),
        "text/html",
        "htmlBody type",
    )
}

async fn body_inline_attachment_cid(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("multipart-related");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["bodyStructure"],
            "bodyProperties": ["partId", "type", "cid", "disposition", "subParts"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let bs = &email["bodyStructure"];
    check(bs.is_object(), "bodyStructure must be present")?;
    if let Some(image_part) = find_part(bs, "image/jpeg") {
        check(!image_part["cid"].is_null(), "Inline image should have cid")?;
    }
    Ok(())
}

async fn body_attachment_blob_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-attachment");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["attachments"],
            "bodyProperties": ["partId", "blobId", "type", "name", "size"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let attachments = &email["attachments"];
    check(
        count(attachments) > 0,
        "attachments length must be greater than 0",
    )?;
    check(
        !attachments[0]["blobId"].is_null(),
        "Attachment must have blobId",
    )
}

async fn body_non_utf8_charset(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("korean-euckr");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["textBody", "bodyValues", "from", "subject"],
            "bodyProperties": ["partId", "charset"],
            "fetchTextBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    if let Some(map) = email["bodyValues"].as_object()
        && let Some(first) = map.values().next()
    {
        check(
            first["isEncodingProblem"].is_boolean(),
            "isEncodingProblem must be boolean",
        )?;
    }
    Ok(())
}

async fn body_invalid_ascii_handling(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("invalid-ascii");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["subject", "textBody", "bodyValues"],
            "bodyProperties": ["partId"],
            "fetchTextBodyValues": true
        }),
    )
    .await;
    let email = first_email(&resp);
    check_eq(&email["subject"], &json!("Malformed email test"), "subject")
}

async fn header_from(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["from"] })).await;
    let email = first_email(&resp);
    let from = &email["from"];
    check(from.is_array(), "from must be an array")?;
    check(count(from) > 0, "from length must be greater than 0")?;
    check_eq(&from[0]["email"], &json!("alice@example.com"), "email")?;
    check_eq(&from[0]["name"], &json!("Alice Sender"), "name")
}

async fn header_to(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["to"] })).await;
    let email = first_email(&resp);
    let to = &email["to"];
    check(to.is_array(), "to must be an array")?;
    check(count(to) > 0, "to length must be greater than 0")?;
    check_eq(&to[0]["email"], &json!("testuser@example.com"), "email")
}

async fn header_cc(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("html-attachment");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["cc"] })).await;
    let email = first_email(&resp);
    let cc = &email["cc"];
    check(cc.is_array(), "cc must be an array")?;
    check(count(cc) > 0, "cc length must be greater than 0")?;
    check_eq(&cc[0]["email"], &json!("charlie@example.net"), "email")
}

async fn header_subject(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["subject"] })).await;
    let email = first_email(&resp);
    check_eq(
        &email["subject"],
        &json!("Meeting tomorrow morning"),
        "subject",
    )
}

async fn header_subject_empty(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("no-subject");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["subject"] })).await;
    let email = first_email(&resp);
    let subject = &email["subject"];
    check(
        subject == &json!("") || subject.is_null(),
        format!("Expected empty/null subject, got {subject}"),
    )
}

async fn header_sent_at(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["sentAt"] })).await;
    let email = first_email(&resp);
    check(email["sentAt"].is_string(), "sentAt must be string")?;
    check(
        date_is_valid(email["sentAt"].as_str().unwrap_or("")),
        "sentAt must be a valid date",
    )
}

async fn header_message_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("thread-starter");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["messageId"] }),
    )
    .await;
    let email = first_email(&resp);
    let msg_id = &email["messageId"];
    check(msg_id.is_array(), "messageId must be an array")?;
    check(count(msg_id) > 0, "messageId length must be greater than 0")?;
    check_contains(
        msg_id[0].as_str().unwrap_or(""),
        "thread-alpha-001@test",
        "messageId",
    )
}

async fn header_in_reply_to(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("thread-reply-1");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["inReplyTo"] }),
    )
    .await;
    let email = first_email(&resp);
    let in_reply_to = &email["inReplyTo"];
    check(in_reply_to.is_array(), "inReplyTo must be an array")?;
    check_contains(
        in_reply_to[0].as_str().unwrap_or(""),
        "thread-alpha-001@test",
        "inReplyTo",
    )
}

async fn header_references(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("thread-reply-2");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["references"] }),
    )
    .await;
    let email = first_email(&resp);
    let refs = &email["references"];
    check(refs.is_array(), "references must be an array")?;
    check(count(refs) >= 2, "references length must be at least 2")
}

async fn header_raw_access(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:Subject:asText"] }),
    )
    .await;
    let email = first_email(&resp);
    let header_value = &email["header:Subject:asText"];
    check(header_value.is_string(), "header value must be string")?;
    check_contains(
        header_value.as_str().unwrap_or(""),
        "Meeting tomorrow morning",
        "header value",
    )
}

async fn header_as_addresses(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:From:asAddresses"] }),
    )
    .await;
    let email = first_email(&resp);
    let addrs = &email["header:From:asAddresses"];
    check(addrs.is_array(), "asAddresses must return array")?;
    check_eq(&addrs[0]["email"], &json!("alice@example.com"), "email")
}

async fn header_as_message_ids(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("thread-starter");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:Message-ID:asMessageIds"] }),
    )
    .await;
    let email = first_email(&resp);
    let ids = &email["header:Message-ID:asMessageIds"];
    check(ids.is_array(), "asMessageIds must return array")?;
    check_contains(
        ids[0].as_str().unwrap_or(""),
        "thread-alpha-001@test",
        "messageId",
    )
}

async fn header_as_date(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:Date:asDate"] }),
    )
    .await;
    let email = first_email(&resp);
    let date_str = &email["header:Date:asDate"];
    check(date_str.is_string(), "asDate must be string")?;
    check(
        date_is_valid(date_str.as_str().unwrap_or("")),
        "asDate must return valid date",
    )
}

async fn header_as_urls(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("special-headers");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:List-Unsubscribe:asURLs"] }),
    )
    .await;
    let email = first_email(&resp);
    let urls = &email["header:List-Unsubscribe:asURLs"];
    check(urls.is_array(), "asURLs must return array")?;
    check(count(urls) > 0, "asURLs length must be greater than 0")?;
    check_contains(urls[0].as_str().unwrap_or(""), "example.com/unsub", "url")
}

async fn header_custom_header(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("special-headers");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:X-Custom-Header:asText"] }),
    )
    .await;
    let email = first_email(&resp);
    let value = &email["header:X-Custom-Header:asText"];
    check(value.is_string(), "value must be string")?;
    check_contains(value.as_str().unwrap_or(""), "custom-value-12345", "value")
}

async fn header_intl_from_decoded(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("intl-sender");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["from"] })).await;
    let email = first_email(&resp);
    let from = &email["from"];
    check(count(from) > 0, "from length must be greater than 0")?;
    check_eq(&from[0]["email"], &json!("kaneshiro@example.com"), "email")?;
    if let Some(name) = from[0]["name"].as_str() {
        check(!name.is_empty(), "Decoded name should not be empty")?;
    }
    Ok(())
}

async fn header_as_grouped_addresses(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:From:asGroupedAddresses"] }),
    )
    .await;
    let email = first_email(&resp);
    let groups = &email["header:From:asGroupedAddresses"];
    check(groups.is_array(), "asGroupedAddresses must return array")?;
    check(count(groups) > 0, "groups length must be greater than 0")?;
    check(
        groups[0]["addresses"].is_array(),
        "Each group must have addresses array",
    )
}

async fn header_raw_form(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({ "ids": [email_id], "properties": ["header:Subject"] }),
    )
    .await;
    let email = first_email(&resp);
    let raw = &email["header:Subject"];
    check(raw.is_string(), "raw must be string")?;
    check_contains(
        raw.as_str().unwrap_or(""),
        "Meeting tomorrow morning",
        "raw",
    )
}

async fn header_case_insensitive(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = email_get(
        ctx,
        json!({
            "ids": [email_id],
            "properties": ["header:subject:asText", "header:SUBJECT:asText"]
        }),
    )
    .await;
    let email = first_email(&resp);
    let lower = email["header:subject:asText"].as_str().unwrap_or("");
    let upper = email["header:SUBJECT:asText"].as_str().unwrap_or("");
    check(
        !lower.is_empty() || !upper.is_empty(),
        "At least one form should return a value",
    )
}

async fn header_bcc(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("bcc-email");
    let resp = email_get(ctx, json!({ "ids": [email_id], "properties": ["bcc"] })).await;
    let email = first_email(&resp);
    if let Some(arr) = email["bcc"].as_array()
        && !arr.is_empty()
    {
        check_eq(&arr[0]["email"], &json!("secret@example.com"), "email")?;
    }
    Ok(())
}

async fn parse_valid_message(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = [
        "From: Parser Test <parse@example.com>",
        "To: testuser@example.com",
        "Subject: Parse test message",
        "Date: Mon, 01 Jan 2026 12:00:00 +0000",
        "Message-ID: <parse-001@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8",
        "",
        "This is a message to be parsed.",
    ]
    .join("\r\n");
    let blob_id = upload_message(ctx, "message/rfc5322", &message).await;
    let resp = email_parse(
        ctx,
        json!({
            "blobIds": [blob_id],
            "properties": ["subject", "from", "to", "textBody", "bodyValues"],
            "fetchTextBodyValues": true
        }),
    )
    .await;
    let email = &resp.method_response()["parsed"][&blob_id];
    check(!email.is_null(), "parsed entry must be present")?;
    check_eq(&email["subject"], &json!("Parse test message"), "subject")?;
    check_eq(
        &email["from"][0]["email"],
        &json!("parse@example.com"),
        "from email",
    )
}

async fn parse_null_metadata(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = [
        "From: meta@example.com",
        "To: testuser@example.com",
        "Subject: Metadata parse test",
        "Message-ID: <parse-meta@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "body",
    ]
    .join("\r\n");
    let blob_id = upload_message(ctx, "message/rfc5322", &message).await;
    let resp = email_parse(
        ctx,
        json!({
            "blobIds": [blob_id],
            "properties": [
                "id", "blobId", "threadId", "mailboxIds", "keywords",
                "receivedAt", "subject"
            ]
        }),
    )
    .await;
    let email = &resp.method_response()["parsed"][&blob_id];
    check(email["id"].is_null(), "id must be null")?;
    check(email["threadId"].is_null(), "threadId must be null")?;
    check(email["mailboxIds"].is_null(), "mailboxIds must be null")?;
    check(email["keywords"].is_null(), "keywords must be null")?;
    check(email["receivedAt"].is_null(), "receivedAt must be null")?;
    check_eq(&email["subject"], &json!("Metadata parse test"), "subject")
}

async fn parse_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = email_parse(ctx, json!({ "blobIds": ["nonexistent-blob-xyz"] })).await;
    let not_found = &resp.method_response()["notFound"];
    check(
        not_found.is_array(),
        "Expected notFound to contain nonexistent-blob-xyz, but got null",
    )?;
    check(
        not_found
            .as_array()
            .map(|a| a.iter().any(|v| v.as_str() == Some("nonexistent-blob-xyz")))
            .unwrap_or(false),
        "notFound must include nonexistent-blob-xyz",
    )
}

async fn parse_not_parsable(ctx: &CompCtx<'_>) -> TestOutcome {
    let blob_id = upload_message(
        ctx,
        "application/octet-stream",
        "this is not an email at all, just random text",
    )
    .await;
    let resp = email_parse(ctx, json!({ "blobIds": [blob_id] })).await;
    let not_parsable = &resp.method_response()["notParsable"];
    check(
        count(not_parsable) > 0,
        "Server MUST return notParsable for non-email blob",
    )?;
    check(
        not_parsable
            .as_array()
            .map(|a| a.iter().any(|v| v.as_str() == Some(blob_id.as_str())))
            .unwrap_or(false),
        "notParsable must include blob id",
    )
}

async fn parse_body_values(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = [
        "From: bv@example.com",
        "To: testuser@example.com",
        "Subject: Body values parse",
        "Message-ID: <parse-bv@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "The body content for parsing.",
    ]
    .join("\r\n");
    let blob_id = upload_message(ctx, "message/rfc5322", &message).await;
    let resp = email_parse(
        ctx,
        json!({
            "blobIds": [blob_id],
            "properties": ["textBody", "bodyValues"],
            "bodyProperties": ["partId"],
            "fetchTextBodyValues": true
        }),
    )
    .await;
    let email = &resp.method_response()["parsed"][&blob_id];
    let map = email["bodyValues"]
        .as_object()
        .unwrap_or_else(|| panic!("bodyValues missing: {email}"));
    check(!map.is_empty(), "bodyValues must have keys")?;
    let first = map.values().next().unwrap();
    check_contains(
        first["value"].as_str().unwrap_or(""),
        "body content for parsing",
        "value",
    )
}

async fn parse_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let blob_id = upload_message(
        ctx,
        "message/rfc5322",
        "From: x@example.com\r\nTo: y@example.com\r\nSubject: test\r\n\r\nbody",
    )
    .await;
    let resp = email_parse(ctx, json!({ "blobIds": [blob_id] })).await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(
        !r["parsed"].is_null() || !r["notParsable"].is_null(),
        "Must have parsed or notParsable",
    )
}
