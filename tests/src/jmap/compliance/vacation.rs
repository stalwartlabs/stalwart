/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_contains, check_eq};
use crate::utils::jmap::JmapUtils;
use serde_json::{Value, json};

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] vacation");

    ctx.run("vacation/get-singleton", get_singleton(ctx)).await;
    ctx.run(
        "vacation/get-singleton-null-ids",
        get_singleton_null_ids(ctx),
    )
    .await;
    ctx.run(
        "vacation/get-singleton-properties",
        get_singleton_properties(ctx),
    )
    .await;
    ctx.run(
        "vacation/get-not-found-invalid-id",
        get_not_found_invalid_id(ctx),
    )
    .await;
    ctx.run("vacation/set-enable-vacation", set_enable_vacation(ctx))
        .await;
    ctx.run("vacation/set-disable-vacation", set_disable_vacation(ctx))
        .await;
    ctx.run("vacation/set-dates", set_dates(ctx)).await;
    ctx.run("vacation/set-html-body", set_html_body(ctx)).await;
    ctx.run("vacation/set-cannot-create", set_cannot_create(ctx))
        .await;
    ctx.run("vacation/set-cannot-destroy", set_cannot_destroy(ctx))
        .await;
}

async fn get_singleton(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("VacationResponse", Vec::<String>::new(), ["singleton"])
        .await;
    let list = resp.list();
    check_eq(list.len(), 1, "list length")?;
    check_eq(list[0].id(), "singleton", "id")
}

async fn get_singleton_null_ids(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let list = resp.list();
    check_eq(list.len(), 1, "list length")?;
    check_eq(list[0].id(), "singleton", "id")
}

async fn get_singleton_properties(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let vr = &resp.list()[0];
    check_eq(vr.id(), "singleton", "id")?;
    check(vr["isEnabled"].is_boolean(), "isEnabled must be boolean")?;
    check(
        vr["fromDate"].is_null() || vr["fromDate"].is_string(),
        "fromDate must be null or string",
    )?;
    check(
        vr["toDate"].is_null() || vr["toDate"].is_string(),
        "toDate must be null or string",
    )?;
    check(
        vr["subject"].is_null() || vr["subject"].is_string(),
        "subject must be null or string",
    )?;
    check(
        vr["textBody"].is_null() || vr["textBody"].is_string(),
        "textBody must be null or string",
    )?;
    check(
        vr["htmlBody"].is_null() || vr["htmlBody"].is_string(),
        "htmlBody must be null or string",
    )
}

async fn get_not_found_invalid_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_get("VacationResponse", Vec::<String>::new(), ["not-singleton"])
        .await;
    let not_found = &resp.method_response()["notFound"];
    check(
        not_found.is_array(),
        format!(
            "VacationResponse/get notFound MUST be a String[], got {}",
            not_found
        ),
    )?;
    let contains = not_found
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str() == Some("not-singleton")))
        .unwrap_or(false);
    check(contains, "notFound must include not-singleton")
}

async fn set_enable_vacation(ctx: &CompCtx<'_>) -> TestOutcome {
    let get_result = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let original = get_result.list()[0].clone();

    ctx.primary
        .jmap_update(
            "VacationResponse",
            [(
                "singleton",
                json!({
                    "isEnabled": true,
                    "subject": "Out of Office - Test",
                    "textBody": "I am currently out of the office for testing.",
                }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let vr = &verify.list()[0];
    let outcome = check_eq(&vr["isEnabled"], &json!(true), "isEnabled")
        .and_then(|_| check_eq(&vr["subject"], &json!("Out of Office - Test"), "subject"));

    ctx.primary
        .jmap_update(
            "VacationResponse",
            [(
                "singleton",
                json!({
                    "isEnabled": original["isEnabled"],
                    "subject": original["subject"],
                    "textBody": original["textBody"],
                }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    outcome
}

async fn set_disable_vacation(ctx: &CompCtx<'_>) -> TestOutcome {
    ctx.primary
        .jmap_update(
            "VacationResponse",
            [("singleton", json!({ "isEnabled": false }))],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let vr = &verify.list()[0];
    check_eq(&vr["isEnabled"], &json!(false), "isEnabled")
}

async fn set_dates(ctx: &CompCtx<'_>) -> TestOutcome {
    let from_date = "2026-03-01T00:00:00Z";
    let to_date = "2026-03-15T00:00:00Z";

    ctx.primary
        .jmap_update(
            "VacationResponse",
            [(
                "singleton",
                json!({ "fromDate": from_date, "toDate": to_date }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let vr = &verify.list()[0];
    let outcome = check_eq(&vr["fromDate"], &json!(from_date), "fromDate")
        .and_then(|_| check_eq(&vr["toDate"], &json!(to_date), "toDate"));

    ctx.primary
        .jmap_update(
            "VacationResponse",
            [("singleton", json!({ "fromDate": null, "toDate": null }))],
            Vec::<(String, Value)>::new(),
        )
        .await;

    outcome
}

async fn set_html_body(ctx: &CompCtx<'_>) -> TestOutcome {
    ctx.primary
        .jmap_update(
            "VacationResponse",
            [(
                "singleton",
                json!({ "htmlBody": "<p>I am out of office.</p>" }),
            )],
            Vec::<(String, Value)>::new(),
        )
        .await;

    let verify = ctx
        .primary
        .jmap_get(
            "VacationResponse",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await;
    let vr = &verify.list()[0];
    let outcome = check_contains(
        vr["htmlBody"].as_str().unwrap_or(""),
        "out of office",
        "htmlBody",
    );

    ctx.primary
        .jmap_update(
            "VacationResponse",
            [("singleton", json!({ "htmlBody": null }))],
            Vec::<(String, Value)>::new(),
        )
        .await;

    outcome
}

async fn set_cannot_create(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_create(
            "VacationResponse",
            [json!({ "isEnabled": false })],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let not_created = resp.not_created(0);
    check(
        !not_created.is_null(),
        "Should not allow creating new VacationResponse",
    )?;
    check_eq(not_created.typ(), "singleton", "type")
}

async fn set_cannot_destroy(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_destroy(
            "VacationResponse",
            ["singleton"],
            Vec::<(String, Value)>::new(),
        )
        .await;
    let not_destroyed = resp.not_destroyed("singleton");
    check(
        !not_destroyed.is_null(),
        "Should not allow destroying VacationResponse singleton",
    )?;
    check_eq(not_destroyed.typ(), "singleton", "type")
}
