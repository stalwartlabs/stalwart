/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_contains, check_eq, skip};
use serde_json::json;

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] identity");

    ctx.run("identity/get-all-identities", get_all_identities(ctx))
        .await;
    ctx.run("identity/get-identity-by-id", get_identity_by_id(ctx))
        .await;
    ctx.run(
        "identity/get-identity-email-matches",
        get_identity_email_matches(ctx),
    )
    .await;
    ctx.run(
        "identity/get-identity-not-found",
        get_identity_not_found(ctx),
    )
    .await;
    ctx.run(
        "identity/get-identity-properties",
        get_identity_properties(ctx),
    )
    .await;

    ctx.run("identity/changes-after-update", changes_after_update(ctx))
        .await;
    ctx.run("identity/changes-no-changes", changes_no_changes(ctx))
        .await;
    ctx.run(
        "identity/changes-response-structure",
        changes_response_structure(ctx),
    )
    .await;

    ctx.run("identity/set-not-found", set_not_found(ctx)).await;
    ctx.run(
        "identity/set-update-html-signature",
        set_update_html_signature(ctx),
    )
    .await;
    ctx.run("identity/set-update-name", set_update_name(ctx))
        .await;
    ctx.run("identity/set-update-reply-to", set_update_reply_to(ctx))
        .await;
    ctx.run(
        "identity/set-update-text-signature",
        set_update_text_signature(ctx),
    )
    .await;
}

async fn get_all_identities(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let len = resp.method_response()["list"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    check(len > 0, "Must have at least one identity")
}

async fn get_identity_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let identity = &resp.method_response()["list"][0];
    check(identity["id"].is_string(), "id must be string")?;
    check(identity["name"].is_string(), "name must be string")?;
    check(identity["email"].is_string(), "email must be string")?;
    check(
        identity["textSignature"].is_string(),
        "textSignature must be string",
    )?;
    check(
        identity["htmlSignature"].is_string(),
        "htmlSignature must be string",
    )?;
    check(
        identity["mayDelete"].is_boolean(),
        "mayDelete must be boolean",
    )?;
    check(
        identity["replyTo"].is_null() || identity["replyTo"].is_array(),
        "replyTo must be null or array",
    )?;
    check(
        identity["bcc"].is_null() || identity["bcc"].is_array(),
        "bcc must be null or array",
    )
}

async fn get_identity_by_id(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let id = &ctx.identity_ids[0];
    let resp = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [id])
        .await;
    let list = resp.list();
    check_eq(list.len(), 1, "list length")?;
    check_eq(list[0]["id"].as_str().unwrap_or(""), id.as_str(), "id")
}

async fn get_identity_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get(
            "Identity",
            Vec::<String>::new(),
            ["nonexistent-identity-xyz"],
        )
        .await;
    let not_found = &resp.method_response()["notFound"];
    check(
        not_found.is_array(),
        format!("Identity/get notFound MUST be a String[], got {not_found}"),
    )?;
    let found = resp.not_found().any(|id| id == "nonexistent-identity-xyz");
    check(found, "notFound must include nonexistent-identity-xyz")
}

async fn get_identity_email_matches(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let id = &ctx.identity_ids[0];
    let resp = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [id])
        .await;
    let email = resp.method_response()["list"][0]["email"]
        .as_str()
        .unwrap_or("");
    check_contains(email, "@", "email must contain @")
}

async fn changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get_result.state().to_string();
    let resp = ctx.primary.jmap_changes("Identity", &state).await;
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

async fn changes_after_update(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let get_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let old_state = get_result.state().to_string();

    let identity_id = ctx.identity_ids[0].clone();
    let identity_get = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let old_name = identity_get.method_response()["list"][0]["name"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "name": "Updated Name For Test" }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    let changes = ctx.primary.jmap_changes("Identity", &old_state).await;
    let updated_contains = changes.method_response()["updated"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some(identity_id.as_str())))
        .unwrap_or(false);

    ctx.primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "name": old_name }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    check(updated_contains, "updated must include the identity id")
}

async fn changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), Vec::<String>::new())
        .await;
    let state = get_result.state().to_string();
    let resp = ctx.primary.jmap_changes("Identity", &state).await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["oldState"].is_string(), "oldState must be string")?;
    check(r["newState"].is_string(), "newState must be string")?;
    check(
        r["hasMoreChanges"].is_boolean(),
        "hasMoreChanges must be boolean",
    )
}

async fn set_update_name(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let identity_id = ctx.identity_ids[0].clone();

    let get_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let original_name = get_result.method_response()["list"][0]["name"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let set_result = ctx
        .primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "name": "Test Updated Name" }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;
    let updated_truthy = set_result.method_response()["updated"]
        .as_object()
        .map(|o| !o.is_empty())
        .unwrap_or(false);

    let verify_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let new_name = verify_result.method_response()["list"][0]["name"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "name": original_name }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    check(updated_truthy, "updated must be present")?;
    check_eq(new_name.as_str(), "Test Updated Name", "name")
}

async fn set_update_text_signature(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let identity_id = ctx.identity_ids[0].clone();

    let get_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let original_sig = get_result.method_response()["list"][0]["textSignature"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Identity",
            [(
                &identity_id,
                json!({ "textSignature": "-- \nTest Signature" }),
            )],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let sig = verify.method_response()["list"][0]["textSignature"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "textSignature": original_sig }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    check_contains(&sig, "Test Signature", "textSignature")
}

async fn set_update_html_signature(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let identity_id = ctx.identity_ids[0].clone();

    let get_result = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let original_sig = get_result.method_response()["list"][0]["htmlSignature"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Identity",
            [(
                &identity_id,
                json!({ "htmlSignature": "<p><b>Test</b> HTML Signature</p>" }),
            )],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let sig = verify.method_response()["list"][0]["htmlSignature"]
        .as_str()
        .unwrap_or("")
        .to_string();

    ctx.primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "htmlSignature": original_sig }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    check_contains(&sig, "HTML Signature", "htmlSignature")
}

async fn set_update_reply_to(ctx: &CompCtx<'_>) -> TestOutcome {
    if ctx.identity_ids.is_empty() {
        return skip("No identities available");
    }
    let identity_id = ctx.identity_ids[0].clone();

    ctx.primary
        .jmap_update(
            "Identity",
            [(
                &identity_id,
                json!({ "replyTo": [{ "name": "Reply Test", "email": "reply@example.com" }] }),
            )],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get("Identity", Vec::<String>::new(), [&identity_id])
        .await;
    let reply_to = verify.method_response()["list"][0]["replyTo"].clone();

    ctx.primary
        .jmap_update(
            "Identity",
            [(&identity_id, json!({ "replyTo": null }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;

    check(
        reply_to.is_array() && !reply_to.as_array().unwrap().is_empty(),
        "replyTo must be a non-empty array",
    )?;
    check_eq(
        reply_to[0]["email"].as_str().unwrap_or(""),
        "reply@example.com",
        "replyTo email",
    )
}

async fn set_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_update(
            "Identity",
            [("nonexistent-identity-xyz", json!({ "name": "test" }))],
            Vec::<(String, serde_json::Value)>::new(),
        )
        .await;
    let not_updated = &resp.method_response()["notUpdated"];
    check(
        not_updated.is_object(),
        "notUpdated must not be null when updating a nonexistent id",
    )?;
    check(
        !not_updated["nonexistent-identity-xyz"].is_null(),
        "Expected notUpdated to contain error for 'nonexistent-identity-xyz'",
    )
}
