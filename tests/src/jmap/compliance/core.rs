/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_contains, check_eq};
use serde_json::json;

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] core");

    // --- echo ---
    ctx.run("core/echo-basic", echo_basic(ctx)).await;
    ctx.run("core/echo-empty", echo_empty(ctx)).await;
    ctx.run("core/echo-nested", echo_nested(ctx)).await;

    // --- session ---
    ctx.run(
        "core/session-has-capabilities",
        session_has_capabilities(ctx),
    )
    .await;
    ctx.run(
        "core/session-has-core-capability",
        session_has_core_capability(ctx),
    )
    .await;
    ctx.run(
        "core/session-has-mail-capability",
        session_has_mail_capability(ctx),
    )
    .await;
    ctx.run(
        "core/session-core-capability-properties",
        session_core_capability_properties(ctx),
    )
    .await;
    ctx.run(
        "core/session-accounts-present",
        session_accounts_present(ctx),
    )
    .await;
    ctx.run(
        "core/session-account-properties",
        session_account_properties(ctx),
    )
    .await;
    ctx.run(
        "core/session-primary-accounts",
        session_primary_accounts(ctx),
    )
    .await;
    ctx.run("core/session-username", session_username(ctx))
        .await;
    ctx.run("core/session-api-url", session_api_url(ctx)).await;
    ctx.run(
        "core/session-download-url-template",
        session_download_url_template(ctx),
    )
    .await;
    ctx.run("core/session-upload-url", session_upload_url(ctx))
        .await;
    ctx.run(
        "core/session-event-source-url",
        session_event_source_url(ctx),
    )
    .await;
    ctx.run("core/session-state", session_state(ctx)).await;
    ctx.run(
        "core/session-account-capabilities-mail",
        session_account_capabilities_mail(ctx),
    )
    .await;
    ctx.run(
        "core/session-mail-capability-properties",
        session_mail_capability_properties(ctx),
    )
    .await;

    // --- request errors ---
    ctx.run("core/error-not-json", error_not_json(ctx)).await;
    ctx.run("core/error-not-request", error_not_request(ctx))
        .await;
    ctx.run(
        "core/error-unknown-capability",
        error_unknown_capability(ctx),
    )
    .await;
    ctx.run("core/error-empty-using", error_empty_using(ctx))
        .await;
    ctx.run(
        "core/error-wrong-content-type",
        error_wrong_content_type(ctx),
    )
    .await;
    ctx.run(
        "core/error-method-calls-not-array",
        error_method_calls_not_array(ctx),
    )
    .await;

    // --- method errors ---
    ctx.run("core/error-unknown-method", error_unknown_method(ctx))
        .await;
    ctx.run(
        "core/error-invalid-arguments-missing-account",
        error_invalid_arguments_missing_account(ctx),
    )
    .await;
    ctx.run("core/error-account-not-found", error_account_not_found(ctx))
        .await;
    ctx.run(
        "core/error-invalid-arguments-bad-type",
        error_invalid_arguments_bad_type(ctx),
    )
    .await;
    ctx.run(
        "core/error-method-level-has-type",
        error_method_level_has_type(ctx),
    )
    .await;
    ctx.run("core/error-state-mismatch", error_state_mismatch(ctx))
        .await;
    ctx.run(
        "core/error-multiple-method-responses",
        error_multiple_method_responses(ctx),
    )
    .await;
    ctx.run(
        "core/error-response-has-session-state",
        error_response_has_session_state(ctx),
    )
    .await;

    // --- result references ---
    ctx.run("core/result-ref-simple", result_ref_simple(ctx))
        .await;
    ctx.run("core/result-ref-chained", result_ref_chained(ctx))
        .await;
    ctx.run(
        "core/result-ref-invalid-result-of",
        result_ref_invalid_result_of(ctx),
    )
    .await;
    ctx.run(
        "core/result-ref-wrong-method-name",
        result_ref_wrong_method_name(ctx),
    )
    .await;
    ctx.run(
        "core/result-ref-path-single-value",
        result_ref_path_single_value(ctx),
    )
    .await;
    ctx.run(
        "core/result-ref-call-id-preserved",
        result_ref_call_id_preserved(ctx),
    )
    .await;
}

const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";

fn default_using() -> Vec<&'static str> {
    vec![CORE, MAIL]
}

// --- echo ---

async fn echo_basic(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call("Core/echo", json!({ "hello": "world", "number": 42 }))
        .await;
    let r = resp.method_response();
    check_eq(&r["hello"], &json!("world"), "hello")?;
    check_eq(&r["number"], &json!(42), "number")
}

async fn echo_empty(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx.primary.jmap_method_call("Core/echo", json!({})).await;
    check_eq(resp.method_response(), &json!({}), "echo empty")
}

async fn echo_nested(ctx: &CompCtx<'_>) -> TestOutcome {
    let args = json!({
        "string": "test",
        "number": 42,
        "bool": true,
        "null": null,
        "array": [1, "two", false],
        "object": { "nested": { "deep": "value" } },
    });
    let resp = ctx
        .primary
        .jmap_method_call("Core/echo", args.clone())
        .await;
    check_eq(resp.method_response(), &args, "echo nested")
}

// --- session ---

async fn session_has_capabilities(ctx: &CompCtx<'_>) -> TestOutcome {
    let caps = &ctx.session["capabilities"];
    check(caps.is_object(), "capabilities must be object")?;
    check(
        caps.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        "capabilities must not be empty",
    )
}

async fn session_has_core_capability(ctx: &CompCtx<'_>) -> TestOutcome {
    check(
        !ctx.session["capabilities"][CORE].is_null(),
        "Must have core capability",
    )
}

async fn session_has_mail_capability(ctx: &CompCtx<'_>) -> TestOutcome {
    check(
        !ctx.session["capabilities"][MAIL].is_null(),
        "Must have mail capability",
    )
}

async fn session_core_capability_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let core = &ctx.session["capabilities"][CORE];
    for prop in [
        "maxSizeUpload",
        "maxConcurrentUpload",
        "maxSizeRequest",
        "maxConcurrentRequests",
        "maxCallsInRequest",
        "maxObjectsInGet",
        "maxObjectsInSet",
    ] {
        check(core[prop].is_number(), format!("{prop} must be a number"))?;
    }
    check(
        core["collationAlgorithms"].is_array(),
        "collationAlgorithms must be an array",
    )
}

async fn session_accounts_present(ctx: &CompCtx<'_>) -> TestOutcome {
    let accounts = &ctx.session["accounts"];
    check(accounts.is_object(), "accounts must be object")?;
    check(
        accounts.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        "Must have at least one account",
    )
}

async fn session_account_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let account = &ctx.session["accounts"][ctx.account_id()];
    check(account.is_object(), "Primary account must exist")?;
    check(account["name"].is_string(), "name must be string")?;
    check(
        account["isPersonal"].is_boolean(),
        "isPersonal must be bool",
    )?;
    check(
        account["isReadOnly"].is_boolean(),
        "isReadOnly must be bool",
    )?;
    check(
        account["accountCapabilities"].is_object(),
        "accountCapabilities must be object",
    )
}

async fn session_primary_accounts(ctx: &CompCtx<'_>) -> TestOutcome {
    let pa = &ctx.session["primaryAccounts"];
    check(pa.is_object(), "primaryAccounts must be object")?;
    let mail_acct = &pa[MAIL];
    check(mail_acct.is_string(), "Must have primary mail account")?;
    check_eq(
        mail_acct.as_str().unwrap_or(""),
        ctx.account_id(),
        "primary mail account",
    )
}

async fn session_username(ctx: &CompCtx<'_>) -> TestOutcome {
    let u = &ctx.session["username"];
    check(u.is_string(), "username must be string")?;
    check(
        u.as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "username must not be empty",
    )
}

async fn session_api_url(ctx: &CompCtx<'_>) -> TestOutcome {
    let u = &ctx.session["apiUrl"];
    check(u.is_string(), "apiUrl must be string")?;
    check(
        u.as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "apiUrl must not be empty",
    )
}

async fn session_download_url_template(ctx: &CompCtx<'_>) -> TestOutcome {
    let u = ctx.session["downloadUrl"].as_str().unwrap_or("");
    check(!u.is_empty(), "downloadUrl must be string")?;
    for v in ["{accountId}", "{blobId}", "{name}", "{type}"] {
        check_contains(u, v, "downloadUrl template")?;
    }
    Ok(())
}

async fn session_upload_url(ctx: &CompCtx<'_>) -> TestOutcome {
    let u = ctx.session["uploadUrl"].as_str().unwrap_or("");
    check(!u.is_empty(), "uploadUrl must be string")?;
    check_contains(u, "{accountId}", "uploadUrl template")
}

async fn session_event_source_url(ctx: &CompCtx<'_>) -> TestOutcome {
    let u = &ctx.session["eventSourceUrl"];
    check(u.is_string(), "eventSourceUrl must be string")?;
    check(
        u.as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "eventSourceUrl must not be empty",
    )
}

async fn session_state(ctx: &CompCtx<'_>) -> TestOutcome {
    let u = &ctx.session["state"];
    check(u.is_string(), "state must be string")?;
    check(
        u.as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "state must not be empty",
    )
}

async fn session_account_capabilities_mail(ctx: &CompCtx<'_>) -> TestOutcome {
    let account = &ctx.session["accounts"][ctx.account_id()];
    check(
        !account["accountCapabilities"][MAIL].is_null(),
        "Account must have mail capability",
    )
}

async fn session_mail_capability_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let account = &ctx.session["accounts"][ctx.account_id()];
    let mail = &account["accountCapabilities"][MAIL];
    check(mail.is_object(), "Account must have mail capability object")?;
    check(
        mail["maxMailboxesPerEmail"].is_null() || mail["maxMailboxesPerEmail"].is_number(),
        "maxMailboxesPerEmail must be null or number",
    )?;
    check(
        mail["maxMailboxDepth"].is_null() || mail["maxMailboxDepth"].is_number(),
        "maxMailboxDepth must be null or number",
    )?;
    check(mail["maxSizeMailboxName"].is_number(), "maxSizeMailboxName")?;
    check(
        mail["maxSizeAttachmentsPerEmail"].is_number(),
        "maxSizeAttachmentsPerEmail",
    )?;
    check(
        mail["emailQuerySortOptions"].is_array(),
        "emailQuerySortOptions must be an array",
    )?;
    check(
        mail["mayCreateTopLevelMailbox"].is_boolean(),
        "mayCreateTopLevelMailbox",
    )
}

// --- request errors ---

async fn error_not_json(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_raw_post("this is not json", "application/json")
        .await;
    check(
        resp.is_client_error(),
        format!("Expected 4xx client error, got {}", resp.status),
    )
}

async fn error_not_request(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_raw_post(json!({ "foo": "bar" }).to_string(), "application/json")
        .await;
    check(
        resp.is_client_error(),
        format!("Expected 4xx client error, got {}", resp.status),
    )
}

async fn error_unknown_capability(ctx: &CompCtx<'_>) -> TestOutcome {
    let body = json!({
        "using": [CORE, "urn:fake:nonexistent"],
        "methodCalls": [["Core/echo", {}, "c0"]]
    });
    let resp = ctx
        .primary
        .jmap_raw_post(body.to_string(), "application/json")
        .await;
    check(
        resp.is_client_error(),
        format!(
            "Expected HTTP 4xx for unknown capability, got {}",
            resp.status
        ),
    )
}

async fn error_empty_using(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(&[], json!([["Core/echo", {}, "c0"]]))
        .await;
    check_eq(
        resp.name_at(0),
        "error",
        "With empty using, method call must return error",
    )?;
    check_eq(
        resp.error_type_at(0).unwrap_or(""),
        "unknownMethod",
        "Error type must be unknownMethod when no capabilities in using",
    )
}

async fn error_wrong_content_type(ctx: &CompCtx<'_>) -> TestOutcome {
    let body = json!({
        "using": [CORE],
        "methodCalls": [["Core/echo", {}, "c0"]]
    });
    let resp = ctx
        .primary
        .jmap_raw_post(body.to_string(), "text/plain")
        .await;
    check(
        resp.is_client_error(),
        format!("Expected 4xx for wrong content type, got {}", resp.status),
    )
}

async fn error_method_calls_not_array(ctx: &CompCtx<'_>) -> TestOutcome {
    let body = json!({
        "using": [CORE],
        "methodCalls": "not-an-array"
    });
    let resp = ctx
        .primary
        .jmap_raw_post(body.to_string(), "application/json")
        .await;
    check(
        resp.is_client_error(),
        format!("Expected 4xx client error, got {}", resp.status),
    )
}

// --- method errors ---

async fn error_unknown_method(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(&[CORE], json!([["Fake/nonexistent", {}, "c0"]]))
        .await;
    check_eq(resp.name_at(0), "error", "name")?;
    check_eq(resp.error_type_at(0).unwrap_or(""), "unknownMethod", "type")
}

async fn error_invalid_arguments_missing_account(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(&default_using(), json!([["Mailbox/get", {}, "c0"]]))
        .await;
    check_eq(resp.name_at(0), "error", "name")?;
    check_eq(
        resp.error_type_at(0).unwrap_or(""),
        "invalidArguments",
        "Missing accountId must return invalidArguments",
    )
}

async fn error_account_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([["Mailbox/get", { "accountId": "nonexistent-account-id-xyz" }, "c0"]]),
        )
        .await;
    check_eq(resp.name_at(0), "error", "name")?;
    check_eq(
        resp.error_type_at(0).unwrap_or(""),
        "accountNotFound",
        "type",
    )
}

async fn error_invalid_arguments_bad_type(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([["Mailbox/get", { "accountId": ctx.account_id(), "ids": "not-an-array" }, "c0"]]),
        )
        .await;
    check_eq(resp.name_at(0), "error", "name")?;
    check_eq(
        resp.error_type_at(0).unwrap_or(""),
        "invalidArguments",
        "type",
    )
}

async fn error_method_level_has_type(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(&[CORE], json!([["Fake/method", {}, "c0"]]))
        .await;
    check_eq(resp.name_at(0), "error", "name")?;
    check(
        !resp.response_at(0)["type"].is_null(),
        "Method-level error must include 'type'",
    )
}

async fn error_state_mismatch(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([[
                "Mailbox/set",
                { "accountId": ctx.account_id(), "ifInState": "invalid-state-that-does-not-exist", "update": {} },
                "c0"
            ]]),
        )
        .await;
    match resp
        .0
        .pointer("/methodResponses/0/0")
        .and_then(|v| v.as_str())
    {
        Some("error") => check_eq(resp.error_type_at(0).unwrap_or(""), "stateMismatch", "type"),
        _ => Ok(()),
    }
}

async fn error_multiple_method_responses(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([
                ["Mailbox/get", { "accountId": ctx.account_id(), "ids": [] }, "call1"],
                ["Core/echo", { "test": true }, "call2"],
                ["Fake/nonexistent", {}, "call3"],
            ]),
        )
        .await;
    check_eq(resp.num_responses(), 3, "must have 3 responses")?;
    check_eq(resp.call_id_at(0), "call1", "call1")?;
    check_eq(resp.call_id_at(1), "call2", "call2")?;
    check_eq(resp.call_id_at(2), "call3", "call3")?;
    check_eq(resp.name_at(2), "error", "third must be error")
}

async fn error_response_has_session_state(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(&[CORE], json!([["Core/echo", {}, "c0"]]))
        .await;
    check(
        resp.session_state().map(|s| !s.is_empty()).unwrap_or(false),
        "Response must include non-empty sessionState",
    )
}

// --- result references ---

async fn result_ref_simple(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([
                ["Mailbox/get", { "accountId": ctx.account_id(), "ids": null }, "getMailboxes"],
                [
                    "Mailbox/get",
                    {
                        "accountId": ctx.account_id(),
                        "#ids": { "resultOf": "getMailboxes", "name": "Mailbox/get", "path": "/list/*/id" }
                    },
                    "getById"
                ]
            ]),
        )
        .await;
    check_eq(resp.num_responses(), 2, "responses")?;
    check_eq(resp.name_at(0), "Mailbox/get", "name1")?;
    check_eq(resp.name_at(1), "Mailbox/get", "name2")?;
    let list2 = resp.response_at(1)["list"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    check(list2 > 0, "Should have resolved mailbox ids")
}

async fn result_ref_chained(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([
                [
                    "Email/query",
                    { "accountId": ctx.account_id(), "filter": { "inMailbox": ctx.role("inbox") }, "limit": 3 },
                    "query"
                ],
                [
                    "Email/get",
                    {
                        "accountId": ctx.account_id(),
                        "#ids": { "resultOf": "query", "name": "Email/query", "path": "/ids" },
                        "properties": ["id", "subject"]
                    },
                    "getEmails"
                ]
            ]),
        )
        .await;
    check_eq(resp.num_responses(), 2, "responses")?;
    check_eq(resp.name_at(0), "Email/query", "name1")?;
    check_eq(resp.name_at(1), "Email/get", "name2")?;
    let query_ids = resp.response_at(0)["ids"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    let get_list = resp.response_at(1)["list"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    check_eq(get_list, query_ids, "get list length == query ids length")
}

async fn result_ref_invalid_result_of(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([[
                "Email/get",
                {
                    "accountId": ctx.account_id(),
                    "#ids": { "resultOf": "nonexistent", "name": "Email/query", "path": "/ids" }
                },
                "c0"
            ]]),
        )
        .await;
    check_eq(resp.name_at(0), "error", "name")?;
    check_eq(
        resp.error_type_at(0).unwrap_or(""),
        "invalidResultReference",
        "type",
    )
}

async fn result_ref_wrong_method_name(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([
                [
                    "Email/query",
                    { "accountId": ctx.account_id(), "filter": { "inMailbox": ctx.role("inbox") }, "limit": 1 },
                    "query"
                ],
                [
                    "Email/get",
                    {
                        "accountId": ctx.account_id(),
                        "#ids": { "resultOf": "query", "name": "Mailbox/get", "path": "/ids" }
                    },
                    "get"
                ]
            ]),
        )
        .await;
    check_eq(resp.name_at(1), "error", "name")?;
    check_eq(
        resp.error_type_at(1).unwrap_or(""),
        "invalidResultReference",
        "type",
    )
}

async fn result_ref_path_single_value(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([
                ["Mailbox/get", { "accountId": ctx.account_id(), "ids": [] }, "getState"],
                [
                    "Mailbox/changes",
                    {
                        "accountId": ctx.account_id(),
                        "#sinceState": { "resultOf": "getState", "name": "Mailbox/get", "path": "/state" }
                    },
                    "changes"
                ]
            ]),
        )
        .await;
    check_eq(resp.num_responses(), 2, "responses")?;
    check_eq(resp.name_at(1), "Mailbox/changes", "name2")?;
    let r = resp.response_at(1);
    check(!r["oldState"].is_null(), "Should have oldState")?;
    check(!r["newState"].is_null(), "Should have newState")
}

async fn result_ref_call_id_preserved(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &default_using(),
            json!([
                ["Core/echo", { "value": 1 }, "first"],
                ["Core/echo", { "value": 2 }, "second"],
                ["Core/echo", { "value": 3 }, "third"],
            ]),
        )
        .await;
    check_eq(resp.num_responses(), 3, "responses")?;
    check_eq(resp.call_id_at(0), "first", "first")?;
    check_eq(resp.call_id_at(1), "second", "second")?;
    check_eq(resp.call_id_at(2), "third", "third")
}
