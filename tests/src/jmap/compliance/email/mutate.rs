/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::compliance::{CompCtx, TestOutcome, check, check_eq, check_ne, skip};
use crate::utils::jmap::{ChangeType, JmapResponse, JmapUtils};
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    ctx.run("email/set-create-plain-text", set_create_plain_text(ctx))
        .await;
    ctx.run("email/set-create-html", set_create_html(ctx)).await;
    ctx.run(
        "email/set-create-multipart-alternative",
        set_create_multipart_alternative(ctx),
    )
    .await;
    ctx.run(
        "email/set-create-with-keywords",
        set_create_with_keywords(ctx),
    )
    .await;
    ctx.run(
        "email/set-create-server-set-properties",
        set_create_server_set_properties(ctx),
    )
    .await;
    ctx.run(
        "email/set-create-with-attachment",
        set_create_with_attachment(ctx),
    )
    .await;
    ctx.run(
        "email/set-create-state-changes",
        set_create_state_changes(ctx),
    )
    .await;
    ctx.run(
        "email/set-create-creation-id-reference",
        set_create_creation_id_reference(ctx),
    )
    .await;

    ctx.run("email/set-update-add-keyword", set_update_add_keyword(ctx))
        .await;
    ctx.run(
        "email/set-update-remove-keyword",
        set_update_remove_keyword(ctx),
    )
    .await;
    ctx.run(
        "email/set-update-replace-keywords",
        set_update_replace_keywords(ctx),
    )
    .await;
    ctx.run(
        "email/set-update-move-mailbox",
        set_update_move_mailbox(ctx),
    )
    .await;
    ctx.run("email/set-update-add-mailbox", set_update_add_mailbox(ctx))
        .await;
    ctx.run(
        "email/set-update-remove-mailbox",
        set_update_remove_mailbox(ctx),
    )
    .await;
    ctx.run("email/set-update-if-in-state", set_update_if_in_state(ctx))
        .await;
    ctx.run("email/set-update-not-found", set_update_not_found(ctx))
        .await;

    ctx.run("email/set-destroy-single", set_destroy_single(ctx))
        .await;
    ctx.run("email/set-destroy-multiple", set_destroy_multiple(ctx))
        .await;
    ctx.run("email/set-destroy-not-found", set_destroy_not_found(ctx))
        .await;
    ctx.run(
        "email/set-destroy-removes-from-all-mailboxes",
        set_destroy_removes_from_all_mailboxes(ctx),
    )
    .await;

    ctx.run("email/import-valid-message", import_valid_message(ctx))
        .await;
    ctx.run("email/import-sets-mailbox", import_sets_mailbox(ctx))
        .await;
    ctx.run("email/import-sets-keywords", import_sets_keywords(ctx))
        .await;
    ctx.run(
        "email/import-sets-received-at",
        import_sets_received_at(ctx),
    )
    .await;
    ctx.run("email/import-invalid-blob", import_invalid_blob(ctx))
        .await;
    ctx.run("email/import-not-found-blob", import_not_found_blob(ctx))
        .await;
    ctx.run("email/import-multiple", import_multiple(ctx)).await;
    ctx.run("email/import-state-changes", import_state_changes(ctx))
        .await;

    ctx.run(
        "email/copy-same-account-error",
        copy_same_account_error(ctx),
    )
    .await;
    ctx.run("email/copy-cross-account", copy_cross_account(ctx))
        .await;
    ctx.run("email/copy-not-found", copy_not_found(ctx)).await;

    ctx.run("email/changes-no-changes", changes_no_changes(ctx))
        .await;
    ctx.run(
        "email/changes-after-keyword-change",
        changes_after_keyword_change(ctx),
    )
    .await;
    ctx.run(
        "email/changes-response-structure",
        changes_response_structure(ctx),
    )
    .await;
    ctx.run(
        "email/changes-after-create-and-destroy",
        changes_after_create_and_destroy(ctx),
    )
    .await;

    ctx.run(
        "email/query-changes-no-changes",
        query_changes_no_changes(ctx),
    )
    .await;
    ctx.run(
        "email/query-changes-after-add",
        query_changes_after_add(ctx),
    )
    .await;
    ctx.run(
        "email/query-changes-after-remove",
        query_changes_after_remove(ctx),
    )
    .await;
    ctx.run(
        "email/query-changes-filter-null-accepted",
        query_changes_filter_null_accepted(ctx),
    )
    .await;
    ctx.run(
        "email/query-changes-response-structure",
        query_changes_response_structure(ctx),
    )
    .await;
}

async fn destroy_email(ctx: &CompCtx<'_>, id: &str) {
    ctx.primary
        .jmap_method_call(
            "Email/set",
            json!({ "accountId": ctx.account_id(), "destroy": [id] }),
        )
        .await;
}

async fn email_get_property(ctx: &CompCtx<'_>, id: &str, property: &str) -> Value {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({
                "accountId": ctx.account_id(),
                "ids": [id],
                "properties": [property]
            }),
        )
        .await;
    resp.list()[0][property].clone()
}

fn plain_create(ctx: &CompCtx<'_>, subject: &str) -> Value {
    json!({
        "mailboxIds": { ctx.role("inbox"): true },
        "from": [{ "name": "Test", "email": "test@example.com" }],
        "to": [{ "name": "User", "email": "user@example.com" }],
        "subject": subject,
        "bodyStructure": { "type": "text/plain", "partId": "1" },
        "bodyValues": { "1": { "value": "body" } }
    })
}

async fn set_create_plain_text(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "Test User", "email": "test@example.com" }],
                "to": [{ "name": "Recipient", "email": "recipient@example.com" }],
                "subject": "Plain text creation test",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "This is a plain text body created via Email/set." } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let created = resp.created(0);
    let outcome = check(!created["id"].is_null(), "id must be set")
        .and(check(!created["blobId"].is_null(), "blobId must be set"))
        .and(check(
            !created["threadId"].is_null(),
            "threadId must be set",
        ))
        .and(check(created["size"].is_number(), "size must be a number"));
    let id = created.id().to_string();
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_html(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "Recipient", "email": "recipient@example.com" }],
                "subject": "HTML creation test",
                "bodyStructure": { "type": "text/html", "partId": "1" },
                "bodyValues": { "1": { "value": "<html><body><h1>Hello</h1><p>HTML body.</p></body></html>" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    let outcome = check(!id.is_empty(), "htmlDraft must be created");
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_multipart_alternative(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "Recipient", "email": "recipient@example.com" }],
                "subject": "Multipart alternative test",
                "bodyStructure": {
                    "type": "multipart/alternative",
                    "subParts": [
                        { "type": "text/plain", "partId": "text" },
                        { "type": "text/html", "partId": "html" }
                    ]
                },
                "bodyValues": {
                    "text": { "value": "Plain text version" },
                    "html": { "value": "<html><body><p>HTML version</p></body></html>" }
                }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();

    let get_resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({
                "accountId": ctx.account_id(),
                "ids": [id],
                "properties": ["textBody", "htmlBody"],
                "bodyProperties": ["type"]
            }),
        )
        .await;
    let email = &get_resp.list()[0];
    let text_len = email["textBody"].as_array().map(|a| a.len()).unwrap_or(0);
    let html_len = email["htmlBody"].as_array().map(|a| a.len()).unwrap_or(0);
    let outcome = check(text_len > 0, "textBody must have parts")
        .and(check(html_len > 0, "htmlBody must have parts"));
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_with_keywords(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Keywords test",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "body" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();
    let keywords = email_get_property(ctx, &id, "keywords").await;
    let outcome = check_eq(&keywords["$draft"], &json!(true), "$draft").and(check_eq(
        &keywords["$seen"],
        &json!(true),
        "$seen",
    ));
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_server_set_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Server-set props",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "body" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let created = resp.created(0);
    let outcome = check(!created["id"].is_null(), "id must be server-set")
        .and(check(
            !created["blobId"].is_null(),
            "blobId must be server-set",
        ))
        .and(check(
            !created["threadId"].is_null(),
            "threadId must be server-set",
        ))
        .and(check(created["size"].is_number(), "size must be a number"));
    let id = created.id().to_string();
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_with_attachment(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "With attachment",
                "bodyStructure": {
                    "type": "multipart/mixed",
                    "subParts": [
                        { "type": "text/plain", "partId": "text" },
                        {
                            "type": "application/pdf",
                            "blobId": ctx.blob("pdf"),
                            "name": "test.pdf",
                            "disposition": "attachment"
                        }
                    ]
                },
                "bodyValues": { "text": { "value": "See attached PDF." } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id = resp.created(0).id().to_string();

    let get_resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({
                "accountId": ctx.account_id(),
                "ids": [id],
                "properties": ["hasAttachment", "attachments"],
                "bodyProperties": ["type", "name"]
            }),
        )
        .await;
    let email = &get_resp.list()[0];
    let outcome = check_eq(&email["hasAttachment"], &json!(true), "hasAttachment");
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_state_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "Email",
            [plain_create(ctx, "State change test")],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let r = resp.method_response();
    let old_state = r["oldState"].clone();
    let new_state = r["newState"].clone();
    let outcome = check(!old_state.is_null(), "oldState must be set")
        .and(check(!new_state.is_null(), "newState must be set"))
        .and(check_ne(old_state, new_state, "oldState != newState"));
    let id = resp.created(0).id().to_string();
    destroy_email(ctx, &id).await;
    outcome
}

async fn set_create_creation_id_reference(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_calls(json!([
            [
                "Mailbox/set",
                {
                    "accountId": ctx.account_id(),
                    "create": { "newMb": { "name": "Creation Ref Test", "parentId": null } }
                },
                "mb"
            ],
            [
                "Email/set",
                {
                    "accountId": ctx.account_id(),
                    "create": {
                        "refEmail": {
                            "mailboxIds": { "#newMb": true },
                            "from": [{ "name": "Test", "email": "test@example.com" }],
                            "to": [{ "name": "User", "email": "user@example.com" }],
                            "subject": "Creation ref test",
                            "bodyStructure": { "type": "text/plain", "partId": "1" },
                            "bodyValues": { "1": { "value": "body" } }
                        }
                    }
                },
                "em"
            ]
        ]))
        .await;

    let mb_id = resp
        .response_at(0)
        .pointer("/created/newMb/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let em_id = resp
        .response_at(1)
        .pointer("/created/refEmail/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let outcome = check(mb_id.is_some(), "Mailbox should be created")
        .and(check(em_id.is_some(), "Email should be created"));

    if let Some(id) = &em_id {
        destroy_email(ctx, id).await;
    }
    if let Some(id) = &mb_id {
        ctx.primary
            .jmap_method_call(
                "Mailbox/set",
                json!({ "accountId": ctx.account_id(), "destroy": [id] }),
            )
            .await;
    }
    outcome
}

async fn set_update_add_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$flagged": true }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let keywords = email_get_property(ctx, email_id, "keywords").await;
    let outcome = check_eq(&keywords["$flagged"], &json!(true), "$flagged");
    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$flagged": null }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    outcome
}

async fn set_update_remove_keyword(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("custom-keywords");
    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$forwarded": null }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let keywords = email_get_property(ctx, email_id, "keywords").await;
    let outcome = check(
        keywords["$forwarded"].is_null() || keywords["$forwarded"] == json!(false),
        "$forwarded must be removed",
    );
    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$forwarded": true }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    outcome
}

async fn set_update_replace_keywords(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    ctx.primary
        .jmap_update(
            "Email",
            [(
                email_id,
                json!({ "keywords": { "$seen": true, "$flagged": true } }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let keywords = email_get_property(ctx, email_id, "keywords").await;
    let outcome = check_eq(&keywords["$seen"], &json!(true), "$seen").and(check_eq(
        &keywords["$flagged"],
        &json!(true),
        "$flagged",
    ));
    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords": { "$seen": true } }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    outcome
}

async fn set_update_move_mailbox(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [plain_create(ctx, "Move test")],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = create_resp.created(0).id().to_string();

    ctx.primary
        .jmap_update(
            "Email",
            [(
                email_id.as_str(),
                json!({ "mailboxIds": { ctx.mailbox("folderA"): true } }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let mailbox_ids = email_get_property(ctx, &email_id, "mailboxIds").await;
    let outcome = check_eq(
        &mailbox_ids[ctx.mailbox("folderA")],
        &json!(true),
        "must be in folderA",
    )
    .and(check(
        mailbox_ids[ctx.role("inbox")].is_null(),
        "must not be in inbox",
    ));
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_update_add_mailbox(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [plain_create(ctx, "Add mailbox test")],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = create_resp.created(0).id().to_string();

    ctx.primary
        .jmap_update(
            "Email",
            [(
                email_id.as_str(),
                json!({ format!("mailboxIds/{}", ctx.mailbox("folderB")): true }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let mailbox_ids = email_get_property(ctx, &email_id, "mailboxIds").await;
    let outcome = check_eq(
        &mailbox_ids[ctx.role("inbox")],
        &json!(true),
        "must be in inbox",
    )
    .and(check_eq(
        &mailbox_ids[ctx.mailbox("folderB")],
        &json!(true),
        "must be in folderB",
    ));
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_update_remove_mailbox(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true, ctx.mailbox("folderA"): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Remove mailbox test",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "body" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = create_resp.created(0).id().to_string();

    ctx.primary
        .jmap_update(
            "Email",
            [(
                email_id.as_str(),
                json!({ format!("mailboxIds/{}", ctx.mailbox("folderA")): null }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let mailbox_ids = email_get_property(ctx, &email_id, "mailboxIds").await;
    let outcome = check_eq(
        &mailbox_ids[ctx.role("inbox")],
        &json!(true),
        "must be in inbox",
    )
    .and(check(
        mailbox_ids[ctx.mailbox("folderA")].is_null(),
        "must not be in folderA",
    ));
    destroy_email(ctx, &email_id).await;
    outcome
}

async fn set_update_if_in_state(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({ "accountId": ctx.account_id(), "ids": [] }),
        )
        .await;
    let state = get_resp.state().to_string();

    let email_id = ctx.email("plain-simple");
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/set",
            json!({
                "accountId": ctx.account_id(),
                "ifInState": state,
                "update": { email_id: { "keywords/$flagged": true } }
            }),
        )
        .await;
    let outcome = check(
        !resp.method_response()["newState"].is_null(),
        "newState must be set",
    );
    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$flagged": null }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    outcome
}

async fn set_update_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_update(
            "Email",
            [("nonexistent-email-xyz", json!({ "keywords/$seen": true }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let not_updated = resp.not_updated("nonexistent-email-xyz");
    check_eq(&not_updated["type"], &json!("notFound"), "type")
}

async fn set_destroy_single(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [plain_create(ctx, "Destroy me")],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = create_resp.created(0).id().to_string();

    let destroy_resp = ctx
        .primary
        .jmap_method_call(
            "Email/set",
            json!({ "accountId": ctx.account_id(), "destroy": [email_id] }),
        )
        .await;
    check(
        destroy_resp.method_response()["destroyed"].is_array(),
        "destroyed must be an array",
    )?;
    let destroyed: Vec<&str> = destroy_resp.destroyed().collect();
    check(
        destroyed.contains(&email_id.as_str()),
        "destroyed must include the email",
    )?;

    let get_resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({ "accountId": ctx.account_id(), "ids": [email_id] }),
        )
        .await;
    check(
        get_resp.method_response()["notFound"].is_array(),
        "notFound must be an array",
    )?;
    let not_found: Vec<&str> = get_resp.not_found().collect();
    check(
        not_found.contains(&email_id.as_str()),
        "notFound must include the email",
    )
}

async fn set_destroy_multiple(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [
                plain_create(ctx, "Destroy batch 1"),
                plain_create(ctx, "Destroy batch 2"),
            ],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let id1 = create_resp.created(0).id().to_string();
    let id2 = create_resp.created(1).id().to_string();

    let destroy_resp = ctx
        .primary
        .jmap_method_call(
            "Email/set",
            json!({ "accountId": ctx.account_id(), "destroy": [id1, id2] }),
        )
        .await;
    check(
        destroy_resp.method_response()["destroyed"].is_array(),
        "destroyed must be an array",
    )?;
    let count = destroy_resp.method_response()["destroyed"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    check_eq(count, 2, "destroyed length")
}

async fn set_destroy_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/set",
            json!({ "accountId": ctx.account_id(), "destroy": ["nonexistent-email-xyz"] }),
        )
        .await;
    let not_destroyed = resp.not_destroyed("nonexistent-email-xyz");
    check_eq(&not_destroyed["type"], &json!("notFound"), "type")
}

async fn set_destroy_removes_from_all_mailboxes(ctx: &CompCtx<'_>) -> TestOutcome {
    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true, ctx.mailbox("folderA"): true },
                "from": [{ "name": "Test", "email": "test@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Multi-mailbox destroy",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "body" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let email_id = create_resp.created(0).id().to_string();

    destroy_email(ctx, &email_id).await;

    let q1 = ctx
        .primary
        .jmap_query(
            "Email",
            [("inMailbox", json!(ctx.role("inbox")))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let q1_ids: Vec<&str> = q1.ids().collect();
    check(
        !q1_ids.contains(&email_id.as_str()),
        "must not be in inbox query",
    )?;

    let q2 = ctx
        .primary
        .jmap_query(
            "Email",
            [("inMailbox", json!(ctx.mailbox("folderA")))],
            Vec::<String>::new(),
            Vec::<(String, Value)>::new(),
        )
        .await;
    let q2_ids: Vec<&str> = q2.ids().collect();
    check(
        !q2_ids.contains(&email_id.as_str()),
        "must not be in folderA query",
    )
}

fn rfc5322(lines: &[&str]) -> Vec<u8> {
    lines.join("\r\n").into_bytes()
}

async fn import_one(ctx: &CompCtx<'_>, creation_id: &str, email: Value) -> JmapResponse {
    ctx.primary
        .jmap_method_call(
            "Email/import",
            json!({
                "accountId": ctx.account_id(),
                "emails": { creation_id: email }
            }),
        )
        .await
}

async fn import_valid_message(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = rfc5322(&[
        "From: import-test@example.com",
        "To: testuser@example.com",
        "Subject: Import test message",
        "Date: Thu, 01 Jan 2026 12:00:00 +0000",
        "Message-ID: <import-test-001@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8",
        "",
        "This is an imported message.",
    ]);
    let upload = ctx.upload(ctx.primary, "message/rfc5322", message).await;

    let resp = import_one(
        ctx,
        "imp1",
        json!({
            "blobId": upload.blob_id(),
            "mailboxIds": { ctx.role("inbox"): true },
            "keywords": { "$seen": true },
            "receivedAt": "2026-01-01T12:00:00Z"
        }),
    )
    .await;
    let created = resp
        .method_response()
        .pointer("/created/imp1")
        .cloned()
        .unwrap_or(Value::Null);
    let mut outcome = check(!created.is_null(), "imp1 must be created")
        .and(check(!created["id"].is_null(), "id must be set"))
        .and(check(!created["blobId"].is_null(), "blobId must be set"))
        .and(check(created["size"].is_number(), "size must be a number"));
    let id = created.id().to_string();

    let subject = email_get_property(ctx, &id, "subject").await;
    outcome = outcome.and(check_eq(&subject, &json!("Import test message"), "subject"));
    destroy_email(ctx, &id).await;
    outcome
}

async fn import_sets_mailbox(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = rfc5322(&[
        "From: import-mb@example.com",
        "To: testuser@example.com",
        "Subject: Import mailbox test",
        "Date: Thu, 01 Jan 2026 12:00:00 +0000",
        "Message-ID: <import-mb-001@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "Imported to specific mailbox.",
    ]);
    let upload = ctx.upload(ctx.primary, "message/rfc5322", message).await;

    let resp = import_one(
        ctx,
        "mbImp",
        json!({
            "blobId": upload.blob_id(),
            "mailboxIds": { ctx.mailbox("folderB"): true }
        }),
    )
    .await;
    let created = resp
        .method_response()
        .pointer("/created/mbImp")
        .cloned()
        .unwrap_or(Value::Null);
    let mut outcome = check(!created.is_null(), "mbImp must be created");
    let id = created.id().to_string();

    let mailbox_ids = email_get_property(ctx, &id, "mailboxIds").await;
    outcome = outcome.and(check_eq(
        &mailbox_ids[ctx.mailbox("folderB")],
        &json!(true),
        "must be in folderB",
    ));
    destroy_email(ctx, &id).await;
    outcome
}

async fn import_sets_keywords(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = rfc5322(&[
        "From: import-kw@example.com",
        "To: testuser@example.com",
        "Subject: Import keywords test",
        "Date: Thu, 01 Jan 2026 12:00:00 +0000",
        "Message-ID: <import-kw-001@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "Keywords test.",
    ]);
    let upload = ctx.upload(ctx.primary, "message/rfc5322", message).await;

    let resp = import_one(
        ctx,
        "kwImp",
        json!({
            "blobId": upload.blob_id(),
            "mailboxIds": { ctx.role("inbox"): true },
            "keywords": { "$seen": true, "$flagged": true }
        }),
    )
    .await;
    let id = resp
        .method_response()
        .pointer("/created/kwImp/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let keywords = email_get_property(ctx, &id, "keywords").await;
    let outcome = check_eq(&keywords["$seen"], &json!(true), "$seen").and(check_eq(
        &keywords["$flagged"],
        &json!(true),
        "$flagged",
    ));
    destroy_email(ctx, &id).await;
    outcome
}

async fn import_sets_received_at(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = rfc5322(&[
        "From: import-date@example.com",
        "To: testuser@example.com",
        "Subject: Import date test",
        "Date: Wed, 15 Jan 2025 10:30:00 +0000",
        "Message-ID: <import-date-001@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "Date test.",
    ]);
    let upload = ctx.upload(ctx.primary, "message/rfc5322", message).await;

    let received_at = "2025-06-15T10:30:00Z";
    let resp = import_one(
        ctx,
        "dateImp",
        json!({
            "blobId": upload.blob_id(),
            "mailboxIds": { ctx.role("inbox"): true },
            "receivedAt": received_at
        }),
    )
    .await;
    let id = resp
        .method_response()
        .pointer("/created/dateImp/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let actual = email_get_property(ctx, &id, "receivedAt").await;
    let outcome = check_eq(&actual, &json!("2025-06-15T10:30:00Z"), "receivedAt");
    destroy_email(ctx, &id).await;
    outcome
}

async fn import_invalid_blob(ctx: &CompCtx<'_>) -> TestOutcome {
    let upload = ctx
        .upload(
            ctx.primary,
            "application/octet-stream",
            b"this is not an email".to_vec(),
        )
        .await;

    let resp = import_one(
        ctx,
        "badImp",
        json!({
            "blobId": upload.blob_id(),
            "mailboxIds": { ctx.role("inbox"): true }
        }),
    )
    .await;
    let not_created = resp
        .method_response()
        .pointer("/notCreated/badImp")
        .cloned()
        .unwrap_or(Value::Null);
    let outcome = check(!not_created.is_null(), "badImp must be in notCreated").and(check(
        !not_created["type"].is_null(),
        "error must have a type",
    ));

    if let Some(id) = resp
        .method_response()
        .pointer("/created/badImp/id")
        .and_then(|v| v.as_str())
    {
        destroy_email(ctx, id).await;
    }
    outcome
}

async fn import_not_found_blob(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = import_one(
        ctx,
        "notFound",
        json!({
            "blobId": "nonexistent-blob-xyz",
            "mailboxIds": { ctx.role("inbox"): true }
        }),
    )
    .await;
    let not_created = resp
        .method_response()
        .pointer("/notCreated/notFound")
        .cloned()
        .unwrap_or(Value::Null);
    check(!not_created.is_null(), "notFound must be in notCreated")?;
    check_eq(&not_created["type"], &json!("invalidProperties"), "type")
}

async fn import_multiple(ctx: &CompCtx<'_>) -> TestOutcome {
    let msg1 = rfc5322(&[
        "From: batch1@example.com",
        "To: testuser@example.com",
        "Subject: Batch import 1",
        "Message-ID: <batch1@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "Batch 1",
    ]);
    let msg2 = rfc5322(&[
        "From: batch2@example.com",
        "To: testuser@example.com",
        "Subject: Batch import 2",
        "Message-ID: <batch2@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "Batch 2",
    ]);
    let up1 = ctx.upload(ctx.primary, "message/rfc5322", msg1).await;
    let up2 = ctx.upload(ctx.primary, "message/rfc5322", msg2).await;

    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/import",
            json!({
                "accountId": ctx.account_id(),
                "emails": {
                    "b1": { "blobId": up1.blob_id(), "mailboxIds": { ctx.role("inbox"): true } },
                    "b2": { "blobId": up2.blob_id(), "mailboxIds": { ctx.role("inbox"): true } }
                }
            }),
        )
        .await;
    let b1 = resp
        .method_response()
        .pointer("/created/b1")
        .cloned()
        .unwrap_or(Value::Null);
    let b2 = resp
        .method_response()
        .pointer("/created/b2")
        .cloned()
        .unwrap_or(Value::Null);
    let outcome =
        check(!b1.is_null(), "b1 must be created").and(check(!b2.is_null(), "b2 must be created"));

    let mut destroy = Vec::new();
    if let Some(id) = b1["id"].as_str() {
        destroy.push(id.to_string());
    }
    if let Some(id) = b2["id"].as_str() {
        destroy.push(id.to_string());
    }
    if !destroy.is_empty() {
        ctx.primary
            .jmap_method_call(
                "Email/set",
                json!({ "accountId": ctx.account_id(), "destroy": destroy }),
            )
            .await;
    }
    outcome
}

async fn import_state_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let message = rfc5322(&[
        "From: state@example.com",
        "To: testuser@example.com",
        "Subject: State test",
        "Message-ID: <state-imp@test>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain",
        "",
        "body",
    ]);
    let upload = ctx.upload(ctx.primary, "message/rfc5322", message).await;

    let resp = import_one(
        ctx,
        "st",
        json!({
            "blobId": upload.blob_id(),
            "mailboxIds": { ctx.role("inbox"): true }
        }),
    )
    .await;
    let outcome = check(
        !resp.method_response()["newState"].is_null(),
        "newState must be set",
    );

    if let Some(id) = resp
        .method_response()
        .pointer("/created/st/id")
        .and_then(|v| v.as_str())
    {
        destroy_email(ctx, id).await;
    }
    outcome
}

async fn copy_same_account_error(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/copy",
            json!({
                "fromAccountId": ctx.account_id(),
                "accountId": ctx.account_id(),
                "create": {
                    "x": {
                        "id": "placeholder",
                        "mailboxIds": { ctx.role("inbox"): true }
                    }
                }
            }),
        )
        .await;
    if resp.is_error_at(0) {
        check_eq(
            resp.error_type_at(0).unwrap_or(""),
            "invalidArguments",
            "Same-account copy must return invalidArguments",
        )
    } else {
        Ok(())
    }
}

async fn cross_inbox(ctx: &CompCtx<'_>, cross: &str) -> Option<String> {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Mailbox/get",
            json!({ "accountId": cross, "ids": null, "properties": ["id", "role"] }),
        )
        .await;
    resp.0
        .pointer("/methodResponses/0/1/list")
        .and_then(|v| v.as_array())
        .and_then(|list| list.iter().find(|m| m["role"] == "inbox"))
        .map(|m| m.id().to_string())
}

async fn copy_cross_account(ctx: &CompCtx<'_>) -> TestOutcome {
    let Some(cross) = ctx.cross_account_id.as_deref() else {
        return skip("No cross-account access available");
    };
    let src_id = ctx.email("plain-simple");
    let Some(crossbox) = cross_inbox(ctx, cross).await else {
        return check(false, "Cross account must have an inbox");
    };
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/copy",
            json!({
                "fromAccountId": ctx.account_id(),
                "accountId": cross,
                "create": {
                    "copied": {
                        "id": src_id,
                        "mailboxIds": { crossbox: true },
                        "keywords": { "$seen": true }
                    }
                }
            }),
        )
        .await;
    let r = resp.method_response();
    let result = check(
        !r["created"]["copied"].is_null(),
        "copied email must be in created map",
    )
    .and(check(
        !r["created"]["copied"]["id"].is_null(),
        "copied email must have an id",
    ));
    if let Some(cid) = r["created"]["copied"]["id"].as_str() {
        ctx.primary
            .jmap_method_call("Email/set", json!({ "accountId": cross, "destroy": [cid] }))
            .await;
    }
    result
}

async fn copy_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let Some(cross) = ctx.cross_account_id.as_deref() else {
        return skip("No cross-account access available");
    };
    let Some(crossbox) = cross_inbox(ctx, cross).await else {
        return check(false, "Cross account must have an inbox");
    };
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/copy",
            json!({
                "fromAccountId": ctx.account_id(),
                "accountId": cross,
                "create": {
                    "bad": {
                        "id": "nonexistent-email-xyz",
                        "mailboxIds": { crossbox: true }
                    }
                }
            }),
        )
        .await;
    check(
        !resp.method_response()["notCreated"]["bad"].is_null(),
        "notCreated must contain the bad entry",
    )
}

async fn email_state(ctx: &CompCtx<'_>) -> String {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/get",
            json!({ "accountId": ctx.account_id(), "ids": [] }),
        )
        .await;
    resp.state().to_string()
}

async fn changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let state = email_state(ctx).await;
    let resp = ctx.primary.jmap_changes("Email", &state).await;
    let r = resp.method_response();
    check_eq(&r["oldState"], &json!(state), "oldState")?;
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

async fn changes_after_keyword_change(ctx: &CompCtx<'_>) -> TestOutcome {
    let old_state = email_state(ctx).await;
    let email_id = ctx.email("plain-simple");

    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$flagged": true }))],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let changes = ctx.primary.jmap_changes("Email", &old_state).await;
    let updated: Vec<&str> = changes
        .changes()
        .filter_map(|c| match c {
            ChangeType::Updated(id) => Some(id),
            _ => None,
        })
        .collect();
    let outcome = check(
        updated.contains(&email_id),
        "updated must include the email",
    );

    ctx.primary
        .jmap_update(
            "Email",
            [(email_id, json!({ "keywords/$flagged": null }))],
            Vec::<(String, Value)>::new(),
        )
        .await;
    outcome
}

async fn changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let state = email_state(ctx).await;
    let resp = ctx.primary.jmap_changes("Email", &state).await;
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

async fn changes_after_create_and_destroy(ctx: &CompCtx<'_>) -> TestOutcome {
    let old_state = email_state(ctx).await;

    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [plain_create(ctx, "Changes test email")],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let temp_id = create_resp.created(0).id().to_string();
    let mid_state = create_resp.method_response()["newState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let changes1 = ctx.primary.jmap_changes("Email", &old_state).await;
    let created1: Vec<&str> = changes1
        .changes()
        .filter_map(|c| match c {
            ChangeType::Created(id) => Some(id),
            _ => None,
        })
        .collect();
    let r1 = check(
        created1.contains(&temp_id.as_str()),
        "created must include the temp email",
    );

    destroy_email(ctx, &temp_id).await;

    let changes2 = ctx.primary.jmap_changes("Email", &mid_state).await;
    let destroyed2: Vec<&str> = changes2
        .changes()
        .filter_map(|c| match c {
            ChangeType::Destroyed(id) => Some(id),
            _ => None,
        })
        .collect();
    let r2 = check(
        destroyed2.contains(&temp_id.as_str()),
        "destroyed must include the temp email",
    );
    r1.and(r2)
}

async fn email_query_state(ctx: &CompCtx<'_>, filter: Value) -> String {
    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/query",
            json!({
                "accountId": ctx.account_id(),
                "filter": filter,
                "sort": [{ "property": "receivedAt", "isAscending": false }]
            }),
        )
        .await;
    resp.method_response()["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

async fn query_changes_no_changes(ctx: &CompCtx<'_>) -> TestOutcome {
    let filter = json!({ "inMailbox": ctx.role("inbox") });
    let query_state = email_query_state(ctx, filter.clone()).await;

    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/queryChanges",
            json!({
                "accountId": ctx.account_id(),
                "filter": filter,
                "sort": [{ "property": "receivedAt", "isAscending": false }],
                "sinceQueryState": query_state
            }),
        )
        .await;
    let r = resp.method_response();
    check_eq(&r["oldQueryState"], &json!(query_state), "oldQueryState")?;
    check_eq(
        r["removed"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "removed length",
    )?;
    check_eq(
        r["added"].as_array().map(|a| a.len()).unwrap_or(usize::MAX),
        0,
        "added length",
    )
}

async fn query_changes_after_add(ctx: &CompCtx<'_>) -> TestOutcome {
    let filter = json!({ "inMailbox": ctx.role("inbox") });
    let old_query_state = email_query_state(ctx, filter.clone()).await;

    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "QC Test", "email": "qc@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "QueryChanges test",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "test" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let new_id = create_resp.created(0).id().to_string();

    let changes = ctx
        .primary
        .jmap_method_call(
            "Email/queryChanges",
            json!({
                "accountId": ctx.account_id(),
                "filter": filter,
                "sort": [{ "property": "receivedAt", "isAscending": false }],
                "sinceQueryState": old_query_state
            }),
        )
        .await;
    let added_ids: Vec<&str> = changes.method_response()["added"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x["id"].as_str()).collect())
        .unwrap_or_default();
    let outcome = check(
        added_ids.contains(&new_id.as_str()),
        "added must include the new email",
    );

    destroy_email(ctx, &new_id).await;
    outcome
}

async fn query_changes_after_remove(ctx: &CompCtx<'_>) -> TestOutcome {
    let filter = json!({ "inMailbox": ctx.role("inbox") });

    let create_resp = ctx
        .primary
        .jmap_create(
            "Email",
            [json!({
                "mailboxIds": { ctx.role("inbox"): true },
                "from": [{ "name": "RM Test", "email": "rm@example.com" }],
                "to": [{ "name": "User", "email": "user@example.com" }],
                "subject": "Will be removed",
                "bodyStructure": { "type": "text/plain", "partId": "1" },
                "bodyValues": { "1": { "value": "test" } }
            })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let rm_id = create_resp.created(0).id().to_string();

    let old_query_state = email_query_state(ctx, filter.clone()).await;

    destroy_email(ctx, &rm_id).await;

    let changes = ctx
        .primary
        .jmap_method_call(
            "Email/queryChanges",
            json!({
                "accountId": ctx.account_id(),
                "filter": filter,
                "sort": [{ "property": "receivedAt", "isAscending": false }],
                "sinceQueryState": old_query_state
            }),
        )
        .await;
    let removed: Vec<&str> = changes.method_response()["removed"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    check(
        removed.contains(&rm_id.as_str()),
        "removed must include the removed email",
    )
}

async fn query_changes_filter_null_accepted(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_method_call(
            "Email/query",
            json!({ "accountId": ctx.account_id(), "filter": null }),
        )
        .await;
    let query_state = query.method_response()["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/queryChanges",
            json!({
                "accountId": ctx.account_id(),
                "filter": null,
                "sinceQueryState": query_state
            }),
        )
        .await;
    let r = resp.method_response();
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

async fn query_changes_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let query = ctx
        .primary
        .jmap_method_call(
            "Email/query",
            json!({ "accountId": ctx.account_id(), "filter": {} }),
        )
        .await;
    let query_state = query.method_response()["queryState"]
        .as_str()
        .unwrap_or("")
        .to_string();

    let resp = ctx
        .primary
        .jmap_method_call(
            "Email/queryChanges",
            json!({
                "accountId": ctx.account_id(),
                "filter": {},
                "sinceQueryState": query_state
            }),
        )
        .await;
    let r = resp.method_response();
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
