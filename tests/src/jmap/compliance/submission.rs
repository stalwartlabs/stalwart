/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_eq, skip};
use crate::utils::jmap::JmapUtils;
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] submission");

    ctx.run("submission/get-empty", get_empty(ctx)).await;
    ctx.run("submission/get-not-found", get_not_found(ctx))
        .await;
    ctx.run(
        "submission/get-response-structure",
        get_response_structure(ctx),
    )
    .await;

    ctx.run(
        "submission/set-create-submission",
        set_create_submission(ctx),
    )
    .await;
    ctx.run(
        "submission/set-create-with-envelope",
        set_create_with_envelope(ctx),
    )
    .await;
    ctx.run(
        "submission/set-no-recipients-error",
        set_no_recipients_error(ctx),
    )
    .await;
    ctx.run(
        "submission/set-on-success-update-email",
        set_on_success_update_email(ctx),
    )
    .await;
    ctx.run(
        "submission/set-submission-properties",
        set_submission_properties(ctx),
    )
    .await;

    ctx.run("submission/query-all", query_all(ctx)).await;
    ctx.run(
        "submission/query-filter-undo-status",
        query_filter_undo_status(ctx),
    )
    .await;
    ctx.run(
        "submission/query-filter-null-accepted",
        query_filter_null_accepted(ctx),
    )
    .await;
    ctx.run(
        "submission/query-response-structure",
        query_response_structure(ctx),
    )
    .await;

    ctx.run("submission/changes-no-changes", changes_no_changes(ctx))
        .await;
    ctx.run(
        "submission/changes-response-structure",
        changes_response_structure(ctx),
    )
    .await;
}

fn drafts_or_inbox(ctx: &CompCtx<'_>) -> String {
    ctx.role_opt("drafts")
        .unwrap_or_else(|| ctx.role("inbox"))
        .to_string()
}

async fn create_draft(ctx: &CompCtx<'_>, mailbox: &str, subject: &str, with_to: bool) -> String {
    let mut email = json!({
        "mailboxIds": { (mailbox): true },
        "from": [{ "name": "Test", "email": ctx.identity_email }],
        "subject": subject,
        "keywords": { "$seen": true, "$draft": true },
        "bodyStructure": { "type": "text/plain", "partId": "1" },
        "bodyValues": { "1": { "value": "Test email body" } },
    });
    if with_to {
        email["to"] = json!([{ "name": "Secondary", "email": ctx.secondary_email }]);
    }
    let resp = ctx
        .primary
        .jmap_create("Email", [email], Vec::<(String, Value)>::new())
        .await;
    resp.created(0).id().to_string()
}

async fn destroy_email(ctx: &CompCtx<'_>, email_id: &str) {
    ctx.primary
        .jmap_destroy("Email", [email_id], Vec::<(String, Value)>::new())
        .await;
}

async fn destroy_submission(ctx: &CompCtx<'_>, sub_id: &str) {
    ctx.primary
        .jmap_destroy("EmailSubmission", [sub_id], Vec::<(String, Value)>::new())
        .await;
}

async fn get_empty(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get(
            "EmailSubmission",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["state"].is_string(), "state must be string")?;
    check(r["list"].is_array(), "list must be array")
}

async fn get_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get(
            "EmailSubmission",
            Vec::<String>::new(),
            ["nonexistent-submission-xyz"],
        )
        .await;
    let r = resp.method_response();
    check(
        r["notFound"].is_array(),
        format!("notFound must be a String[], got {}", r["notFound"]),
    )?;
    let found = r["notFound"]
        .as_array()
        .map(|a| {
            a.iter()
                .any(|v| v.as_str() == Some("nonexistent-submission-xyz"))
        })
        .unwrap_or(false);
    check(found, "notFound must include nonexistent-submission-xyz")
}

async fn get_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "EmailSubmission/get",
            json!({ "accountId": ctx.account_id(), "ids": [] }),
        )
        .await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["state"].is_string(), "state must be string")?;
    check(r["list"].is_array(), "list must be array")?;
    check(r["notFound"].is_array(), "notFound must be array")
}

async fn set_create_submission(ctx: &CompCtx<'_>) -> TestOutcome {
    let identity = match ctx.identity_ids.first() {
        Some(id) => id,
        None => return skip("No identities available"),
    };
    let mailbox = drafts_or_inbox(ctx);
    let email_id = create_draft(ctx, &mailbox, "Submission test", true).await;

    let resp = ctx
        .primary
        .jmap_create(
            "EmailSubmission",
            [json!({ "identityId": identity, "emailId": email_id })],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let created = resp.pointer("/methodResponses/0/1/created/i0").cloned();
    let outcome = match &created {
        Some(sub) => {
            let mut res = check(sub["id"].is_string(), "id is set by server and required");
            if res.is_ok() {
                res = check(
                    sub["sendAt"].is_string(),
                    "sendAt is set by server and required",
                );
            }
            if res.is_ok() {
                let undo = sub["undoStatus"].as_str().unwrap_or("");
                res = check(
                    undo == "pending" || undo == "final",
                    "undoStatus must be pending or final",
                );
            }
            res
        }
        None => check(false, "Submission should be created"),
    };

    if let Some(sub) = &created
        && let Some(id) = sub["id"].as_str()
    {
        destroy_submission(ctx, id).await;
    }
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_create_with_envelope(ctx: &CompCtx<'_>) -> TestOutcome {
    let identity = match ctx.identity_ids.first() {
        Some(id) => id,
        None => return skip("No identities available"),
    };
    let mailbox = drafts_or_inbox(ctx);
    let email_id = create_draft(ctx, &mailbox, "Envelope test", true).await;

    let resp = ctx
        .primary
        .jmap_create(
            "EmailSubmission",
            [json!({
                "identityId": identity,
                "emailId": email_id,
                "envelope": {
                    "mailFrom": { "email": ctx.identity_email, "parameters": null },
                    "rcptTo": [{ "email": ctx.secondary_email, "parameters": null }],
                },
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let created = resp.pointer("/methodResponses/0/1/created/i0").cloned();
    let outcome = check(created.is_some(), "Submission should be created");

    if let Some(sub) = &created
        && let Some(id) = sub["id"].as_str()
    {
        destroy_submission(ctx, id).await;
    }
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_no_recipients_error(ctx: &CompCtx<'_>) -> TestOutcome {
    let identity = match ctx.identity_ids.first() {
        Some(id) => id,
        None => return skip("No identities available"),
    };
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { (ctx.role("inbox")): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "subject": "No recipients",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "body" } },
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = resp.created(0).id().to_string();

    let resp = ctx
        .primary
        .jmap_create(
            "EmailSubmission",
            [json!({ "identityId": identity, "emailId": email_id })],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let not_created = resp.pointer("/methodResponses/0/1/notCreated/i0").cloned();
    let outcome = match &not_created {
        Some(err) => check(
            err["type"].is_string(),
            "Server MUST reject submission of email with no recipients",
        ),
        None => check(
            false,
            "Server MUST reject submission of email with no recipients",
        ),
    };

    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_on_success_update_email(ctx: &CompCtx<'_>) -> TestOutcome {
    let identity = match ctx.identity_ids.first() {
        Some(id) => id,
        None => return skip("No identities available"),
    };
    let sent_mailbox = match ctx.role_opt("sent") {
        Some(id) => id.to_string(),
        None => return skip("No sent mailbox found"),
    };
    let drafts = drafts_or_inbox(ctx);
    let email_id = create_draft(ctx, &drafts, "onSuccess test", true).await;

    let resp = ctx
        .primary
        .jmap_method_calls(json!([[
            "EmailSubmission/set",
            {
                "accountId": ctx.account_id(),
                "create": {
                    "osuSub": { "identityId": identity, "emailId": email_id }
                },
                "onSuccessUpdateEmail": {
                    "#osuSub": {
                        (format!("mailboxIds/{sent_mailbox}")): true,
                        (format!("mailboxIds/{drafts}")): null,
                        "keywords/$draft": null
                    }
                }
            },
            "submit"
        ]]))
        .await;

    let mut outcome = check(
        resp.num_responses() >= 2,
        "Response must include both EmailSubmission/set and implicit Email/set",
    );
    if outcome.is_ok() {
        outcome = check_eq(
            resp.name_at(0),
            "EmailSubmission/set",
            "first response name",
        );
    }
    if outcome.is_ok() {
        let has_email_set = (0..resp.num_responses()).any(|n| resp.name_at(n) == "Email/set");
        outcome = check(
            has_email_set,
            "Implicit Email/set from onSuccessUpdateEmail must appear in methodResponses",
        );
    }

    if outcome.is_ok() {
        let get_result = ctx
            .primary
            .jmap_method_call(
                "Email/get",
                json!({
                    "accountId": ctx.account_id(),
                    "ids": [email_id],
                    "properties": ["mailboxIds", "keywords"]
                }),
            )
            .await;
        let list = get_result.method_response()["list"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(email) = list.first() {
            let in_sent = email["mailboxIds"][sent_mailbox.as_str()]
                .as_bool()
                .unwrap_or(false);
            if in_sent {
                outcome = check_eq(
                    email["mailboxIds"][sent_mailbox.as_str()]
                        .as_bool()
                        .unwrap_or(false),
                    true,
                    "email in sent",
                );
            }
            if outcome.is_ok() {
                outcome = check(
                    !email["keywords"]["$draft"].as_bool().unwrap_or(false),
                    "$draft should be removed",
                );
            }
        }
    }

    let sub_id = resp
        .pointer("/methodResponses/0/1/created/osuSub/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let Some(id) = sub_id {
        destroy_submission(ctx, &id).await;
    }
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_submission_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let identity = match ctx.identity_ids.first() {
        Some(id) => id,
        None => return skip("No identities available"),
    };
    let email_id = create_draft(ctx, ctx.role("inbox"), "Properties test", true).await;

    let resp = ctx
        .primary
        .jmap_create(
            "EmailSubmission",
            [json!({ "identityId": identity, "emailId": email_id })],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let created = resp.pointer("/methodResponses/0/1/created/i0").cloned();
    let mut outcome = Ok(());
    let mut sub_id_for_cleanup = None;

    if let Some(sub) = &created {
        outcome = check(sub["id"].is_string(), "submission id must be string");
        if outcome.is_ok() {
            let sub_id = sub["id"].as_str().unwrap_or("").to_string();
            sub_id_for_cleanup = Some(sub_id.clone());
            let get_result = ctx
                .primary
                .jmap_get("EmailSubmission", Vec::<String>::new(), [sub_id.clone()])
                .await;
            let fetched = get_result.method_response()["list"]
                .as_array()
                .and_then(|a| a.first())
                .cloned();
            match fetched {
                Some(f) => {
                    outcome = check(f["identityId"].is_string(), "identityId");
                    if outcome.is_ok() {
                        outcome = check(f["emailId"].is_string(), "emailId");
                    }
                    if outcome.is_ok() {
                        outcome = check(!f["sendAt"].is_null(), "sendAt");
                    }
                    if outcome.is_ok() {
                        outcome = check(!f["undoStatus"].is_null(), "undoStatus");
                    }
                }
                None => {
                    let not_found = get_result.method_response()["notFound"].clone();
                    outcome = check_eq(
                        &not_found,
                        &json!([sub_id]),
                        "Item not returned and missing from notFound",
                    );
                }
            }
        }
    }

    if let Some(id) = sub_id_for_cleanup {
        destroy_submission(ctx, &id).await;
    }
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn query_all(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "EmailSubmission",
            Vec::<(String, Value)>::new(),
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let r = resp.method_response();
    check(r["queryState"].is_string(), "queryState must be string")?;
    check(r["ids"].is_array(), "ids must be array")
}

async fn query_filter_undo_status(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "EmailSubmission",
            [("undoStatus", json!("final"))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let r = resp.method_response();
    check(r["ids"].is_array(), "ids must be array")
}

async fn query_filter_null_accepted(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "EmailSubmission/query",
            json!({ "accountId": ctx.account_id(), "filter": null }),
        )
        .await;
    let r = resp.method_response();
    check(r["queryState"].is_string(), "queryState must be string")?;
    check(r["ids"].is_array(), "ids must be array")
}

async fn query_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_query(
            "EmailSubmission",
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

async fn changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get(
            "EmailSubmission",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let state = get_result.state().to_string();

    let resp = ctx.primary.jmap_changes("EmailSubmission", &state).await;
    let r = resp.method_response();
    check_eq(
        r["oldState"].as_str().unwrap_or(""),
        state.as_str(),
        "oldState",
    )?;
    let count = |k: &str| r[k].as_array().map(|a| a.len()).unwrap_or(usize::MAX);
    check_eq(count("created"), 0, "created length")?;
    check_eq(count("updated"), 0, "updated length")?;
    check_eq(count("destroyed"), 0, "destroyed length")
}

async fn changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get(
            "EmailSubmission",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let state = get_result.state().to_string();

    let resp = ctx.primary.jmap_changes("EmailSubmission", &state).await;
    let r = resp.method_response();
    check(r["accountId"].is_string(), "accountId must be string")?;
    check(r["oldState"].is_string(), "oldState must be string")?;
    check(r["newState"].is_string(), "newState must be string")?;
    check(
        r["hasMoreChanges"].is_boolean(),
        "hasMoreChanges must be boolean",
    )
}
