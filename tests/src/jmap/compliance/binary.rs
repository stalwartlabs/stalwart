/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CompCtx, TestOutcome, check, check_contains, check_eq, skip};
use crate::utils::jmap::JmapUtils;
use serde_json::json;

pub async fn run(ctx: &CompCtx<'_>) {
    println!("[compliance] binary");

    ctx.run("binary/upload-basic", upload_basic(ctx)).await;
    ctx.run("binary/upload-binary-content", upload_binary_content(ctx))
        .await;
    ctx.run("binary/upload-large-data", upload_large_data(ctx))
        .await;
    ctx.run(
        "binary/upload-preserves-content-type",
        upload_preserves_content_type(ctx),
    )
    .await;
    ctx.run(
        "binary/upload-returns-valid-blob-id",
        upload_returns_valid_blob_id(ctx),
    )
    .await;

    ctx.run("binary/download-uploaded-blob", download_uploaded_blob(ctx))
        .await;
    ctx.run("binary/download-email-blob", download_email_blob(ctx))
        .await;
    ctx.run(
        "binary/download-nonexistent-blob",
        download_nonexistent_blob(ctx),
    )
    .await;
    ctx.run(
        "binary/download-respects-type-param",
        download_respects_type_param(ctx),
    )
    .await;

    ctx.run(
        "binary/blob-copy-same-account-error",
        blob_copy_same_account_error(ctx),
    )
    .await;
    ctx.run(
        "binary/blob-copy-cross-account",
        blob_copy_cross_account(ctx),
    )
    .await;
    ctx.run("binary/blob-copy-not-found", blob_copy_not_found(ctx))
        .await;
    ctx.run(
        "binary/blob-copy-response-structure",
        blob_copy_response_structure(ctx),
    )
    .await;
}

const CORE: &str = "urn:ietf:params:jmap:core";
const BLOB: &str = "urn:ietf:params:jmap:blob";

async fn upload_basic(ctx: &CompCtx<'_>) -> TestOutcome {
    let data = b"Hello, JMAP upload test!".to_vec();
    let len = data.len() as i64;
    let result = ctx.upload(ctx.primary, "text/plain", data).await;
    check(!result.blob_id().is_empty(), "Must return blobId")?;
    let typ = result.typ();
    check(
        typ == "text/plain" || typ.starts_with("text/plain;"),
        format!("Expected type to be text/plain (possibly with params), got \"{typ}\""),
    )?;
    check_eq(result.integer_field("size"), len, "size")?;
    check_eq(
        result.text_field("accountId"),
        ctx.account_id(),
        "accountId",
    )
}

async fn upload_binary_content(ctx: &CompCtx<'_>) -> TestOutcome {
    let data = vec![0x00u8, 0x01, 0x02, 0xff, 0xfe, 0xfd];
    let result = ctx
        .upload(ctx.primary, "application/octet-stream", data)
        .await;
    check(!result.blob_id().is_empty(), "Must return blobId")?;
    check_eq(result.integer_field("size"), 6, "size")
}

async fn upload_large_data(ctx: &CompCtx<'_>) -> TestOutcome {
    let len = 100 * 1024;
    let data: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
    let result = ctx
        .upload(ctx.primary, "application/octet-stream", data)
        .await;
    check(!result.blob_id().is_empty(), "Must return blobId")?;
    check_eq(result.integer_field("size"), len as i64, "size")
}

async fn upload_preserves_content_type(ctx: &CompCtx<'_>) -> TestOutcome {
    let data = b"<html><body>test</body></html>".to_vec();
    let result = ctx.upload(ctx.primary, "text/html", data).await;
    let typ = result.typ();
    check(
        typ == "text/html" || typ.starts_with("text/html;"),
        format!("Expected type to be text/html (possibly with params), got \"{typ}\""),
    )
}

async fn upload_returns_valid_blob_id(ctx: &CompCtx<'_>) -> TestOutcome {
    let data = b"test".to_vec();
    let result = ctx.upload(ctx.primary, "text/plain", data).await;
    let blob_id = result.blob_id();
    check(!blob_id.is_empty(), "blobId must not be empty")?;
    check(blob_id.len() <= 255, "blobId must be <= 255 chars")
}

async fn download_uploaded_blob(ctx: &CompCtx<'_>) -> TestOutcome {
    let original = b"Download test content 12345".to_vec();
    let upload = ctx
        .upload(ctx.primary, "text/plain", original.clone())
        .await;
    let url = ctx.download_url(ctx.account_id(), upload.blob_id(), "text/plain", "test.txt");
    let result = ctx.primary.http_get_raw(&url, None).await;
    check_eq(result.status, 200, "status")?;
    check_eq(result.body.len(), original.len(), "downloaded length")?;
    check(
        result.body == original,
        "downloaded bytes must match original",
    )
}

async fn download_email_blob(ctx: &CompCtx<'_>) -> TestOutcome {
    let email_id = ctx.email("plain-simple");
    let resp = ctx.primary.jmap_get("Email", ["blobId"], [email_id]).await;
    let email = &resp.list()[0];
    let blob_id = email.blob_id();
    check(!blob_id.is_empty(), "Must return blobId")?;
    let url = ctx.download_url(ctx.account_id(), blob_id, "message/rfc5322", "email.eml");
    let download = ctx.primary.http_get_raw(&url, None).await;
    check_eq(download.status, 200, "status")?;
    check(!download.body.is_empty(), "body must not be empty")
}

async fn download_nonexistent_blob(ctx: &CompCtx<'_>) -> TestOutcome {
    let url = ctx.download_url(
        ctx.account_id(),
        "nonexistent-blob-id-xyz",
        "application/octet-stream",
        "missing.bin",
    );
    let result = ctx.primary.http_get_raw(&url, None).await;
    check_eq(result.status, 404, "status")
}

async fn download_respects_type_param(ctx: &CompCtx<'_>) -> TestOutcome {
    let data = b"type test".to_vec();
    let upload = ctx.upload(ctx.primary, "text/plain", data).await;
    let url = ctx.download_url(
        ctx.account_id(),
        upload.blob_id(),
        "application/octet-stream",
        "test.bin",
    );
    let result = ctx.primary.http_get_raw(&url, None).await;
    check_eq(result.status, 200, "status")?;
    let ct = result.content_type().unwrap_or("");
    check_contains(ct, "application/octet-stream", "content-type")
}

async fn blob_copy_same_account_error(ctx: &CompCtx<'_>) -> TestOutcome {
    let resp = ctx
        .primary
        .jmap_request(
            &[CORE, BLOB],
            json!([[
                "Blob/copy",
                {
                    "fromAccountId": ctx.account_id(),
                    "accountId": ctx.account_id(),
                    "blobIds": ["placeholder"]
                },
                "c0"
            ]]),
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

async fn blob_copy(
    ctx: &CompCtx<'_>,
    cross: &str,
    blob_ids: &[&str],
) -> crate::utils::jmap::JmapResponse {
    ctx.primary
        .jmap_request(
            &[CORE, BLOB],
            json!([[
                "Blob/copy",
                {
                    "fromAccountId": ctx.account_id(),
                    "accountId": cross,
                    "blobIds": blob_ids
                },
                "c0"
            ]]),
        )
        .await
}

async fn blob_copy_cross_account(ctx: &CompCtx<'_>) -> TestOutcome {
    let Some(cross) = ctx.cross_account_id.as_deref() else {
        return skip("No cross-account access available");
    };
    let upload = ctx
        .upload(
            ctx.primary,
            "text/plain",
            b"blob cross-account copy test".to_vec(),
        )
        .await;
    let blob_id = upload.blob_id();
    let resp = blob_copy(ctx, cross, &[blob_id]).await;
    let r = resp.response_at(0);
    check(!r["copied"].is_null(), "copied must not be null")?;
    check(
        !r["copied"][blob_id].is_null(),
        "Blob should be in copied map",
    )
}

async fn blob_copy_not_found(ctx: &CompCtx<'_>) -> TestOutcome {
    let Some(cross) = ctx.cross_account_id.as_deref() else {
        return skip("No cross-account access available");
    };
    let resp = blob_copy(ctx, cross, &["nonexistent-blob-xyz"]).await;
    let r = resp.response_at(0);
    check(!r["notCopied"].is_null(), "notCopied must be present")?;
    let nc = &r["notCopied"]["nonexistent-blob-xyz"];
    check(!nc.is_null(), "Invalid blob should be in notCopied")?;
    check_eq(
        nc["type"].as_str().unwrap_or(""),
        "blobNotFound",
        "notCopied type",
    )
}

async fn blob_copy_response_structure(ctx: &CompCtx<'_>) -> TestOutcome {
    let Some(cross) = ctx.cross_account_id.as_deref() else {
        return skip("No cross-account access available");
    };
    let upload = ctx
        .upload(ctx.primary, "text/plain", b"structure test".to_vec())
        .await;
    let resp = blob_copy(ctx, cross, &[upload.blob_id()]).await;
    let r = resp.response_at(0);
    check_eq(
        r["fromAccountId"].as_str().unwrap_or(""),
        ctx.account_id(),
        "fromAccountId",
    )?;
    check_eq(r["accountId"].as_str().unwrap_or(""), cross, "accountId")
}
