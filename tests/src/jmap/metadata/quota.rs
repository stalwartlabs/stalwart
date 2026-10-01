/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    copy::{copied_id, copy, destination},
    fixture::{Access, Ctx, MetaType, Parents, random_text},
};
use crate::utils::{account::Account, server::TestServer};
use jmap_proto::error::set::SetErrorType;
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
    },
    types::EnumImpl,
};
use serde_json::{Value, json};

pub const ENTRY_SIZE: usize = 900;
const FILLERS: usize = 4;

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata quota tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let admin = ctx.account("admin");

    let user = create_account(
        &ctx,
        "meta-quota@example.com",
        "meta quota secret with extra safety",
    )
    .await;
    let parents = ctx.parents(&user).await;
    let owner_parents = ctx.parents(owner).await;
    ctx.test.wait_for_tasks().await;

    let baseline = ctx.used_quota(&user).await;
    let mut fillers = Vec::with_capacity(FILLERS);
    for _ in 0..FILLERS {
        fillers.push(
            ctx.create_ok(
                &user,
                MetaType::Mailbox,
                &parents,
                0,
                json!({"metadata": entry()}),
            )
            .await,
        );
    }
    let used = ctx.used_quota(&user).await;
    assert!(
        used - baseline >= (ENTRY_SIZE * FILLERS) as i64,
        "metadata was not charged to the account: {baseline} before, {used} after"
    );
    let per_filler = (used - baseline) / FILLERS as i64;
    admin
        .registry_update_object(
            ObjectType::Account,
            user.id(),
            json!({
                Property::Quotas: {
                    StorageQuota::MaxDiskQuota.as_str(): used + per_filler / 2
                }
            }),
        )
        .await;

    for ty in [MetaType::Mailbox, MetaType::FileNode, MetaType::ContactCard] {
        ctx.create_err(&user, ty, &parents, json!({"metadata": entry()}))
            .await
            .assert_type(SetErrorType::OverQuota);
    }
    let spare = ctx
        .create_ok(&user, MetaType::Mailbox, &parents, 0, json!({}))
        .await;
    ctx.update_err(
        &user,
        &user,
        MetaType::Mailbox,
        &spare,
        json!({"metadata": entry()}),
    )
    .await
    .assert_type(SetErrorType::OverQuota);
    ctx.update_err(
        &user,
        &user,
        MetaType::Mailbox,
        &spare,
        json!({"privateMetadata": entry()}),
    )
    .await
    .assert_type(SetErrorType::OverQuota);
    ctx.update_err(
        &user,
        &user,
        MetaType::Mailbox,
        &spare,
        json!({"metadata/photography": {"v": random_text(ENTRY_SIZE)}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);
    ctx.update_err(
        &user,
        &user,
        MetaType::Mailbox,
        &spare,
        json!({"metadata/x.example": {"v": random_text(ctx.test.server.core.metadata.max_entry_size + 1)}}),
    )
    .await
    .assert_type(SetErrorType::InvalidProperties);
    ctx.update_ok(
        &user,
        &user,
        MetaType::Mailbox,
        &fillers[0],
        json!({"metadata/x.example/v": "shrunk"}),
    )
    .await;
    let shrunk = ctx.used_quota(&user).await;
    assert!(
        used - shrunk >= (ENTRY_SIZE - 100) as i64,
        "shrinking a container must return its bytes: {used} before, {shrunk} after"
    );
    ctx.update_ok(
        &user,
        &user,
        MetaType::Mailbox,
        &fillers[0],
        json!({"metadata": entry()}),
    )
    .await;

    let before = ctx.used_quota(&user).await;
    ctx.destroy(&user, MetaType::Mailbox, &[&fillers[1]]).await;
    ctx.test.wait_for_tasks().await;
    let after = ctx.used_quota(&user).await;
    assert!(
        before - after >= ENTRY_SIZE as i64,
        "destroying an object must return its container bytes: {before} before, {after} after"
    );
    ctx.update_ok(
        &user,
        &user,
        MetaType::Mailbox,
        &spare,
        json!({"metadata": entry()}),
    )
    .await;
    ctx.destroy(&user, MetaType::Mailbox, &[&spare]).await;
    ctx.test.wait_for_tasks().await;

    private_charged_to_writer(&ctx, owner, &user, &owner_parents).await;
    copy_charged_to_destination(&ctx, owner, &user, &owner_parents, &parents).await;

    ctx.destroy_all(&user).await;
    ctx.purge(&[&user, owner]).await;
    admin.destroy_account(user).await;
    ctx.cleanup(&[owner]).await;
}

pub fn entry() -> Value {
    json!({"x.example": {"v": random_text(ENTRY_SIZE)}})
}

pub async fn create_account(ctx: &Ctx<'_>, name: &'static str, secret: &'static str) -> Account {
    ctx.account("admin")
        .create_user_account(
            name,
            secret,
            "Metadata test account",
            &[],
            vec![Permission::UnlimitedRequests, Permission::UnlimitedUploads],
        )
        .await
}

async fn private_charged_to_writer(
    ctx: &Ctx<'_>,
    owner: &Account,
    writer: &Account,
    owner_parents: &Parents,
) {
    let first = ctx
        .create_ok(owner, MetaType::Mailbox, owner_parents, 0, json!({}))
        .await;
    let second = ctx
        .create_ok(owner, MetaType::Mailbox, owner_parents, 0, json!({}))
        .await;
    for mailbox in [&first, &second] {
        ctx.share(
            owner,
            MetaType::Mailbox,
            mailbox,
            writer,
            Some(Access::Read),
        )
        .await;
    }

    let owner_before = ctx.used_quota(owner).await;
    let writer_before = ctx.used_quota(writer).await;
    ctx.update_ok(
        writer,
        owner,
        MetaType::Mailbox,
        &first,
        json!({"privateMetadata": entry()}),
    )
    .await;
    let writer_after = ctx.used_quota(writer).await;
    assert!(
        writer_after - writer_before >= ENTRY_SIZE as i64,
        "private metadata must be charged to the writer: {writer_before} before, {writer_after} after"
    );
    assert_eq!(
        ctx.used_quota(owner).await,
        owner_before,
        "private metadata of a sharee must not be charged to the owner"
    );

    ctx.update_err(
        writer,
        owner,
        MetaType::Mailbox,
        &second,
        json!({"privateMetadata": entry()}),
    )
    .await
    .assert_type(SetErrorType::OverQuota);

    ctx.update_ok(
        writer,
        owner,
        MetaType::Mailbox,
        &first,
        json!({"privateMetadata": {}}),
    )
    .await;
    assert!(
        ctx.used_quota(writer).await <= writer_before,
        "clearing private metadata must return the bytes to the writer"
    );

    for mailbox in [&first, &second] {
        ctx.share(owner, MetaType::Mailbox, mailbox, writer, None)
            .await;
    }
    ctx.destroy(owner, MetaType::Mailbox, &[&first, &second])
        .await;
}

async fn copy_charged_to_destination(
    ctx: &Ctx<'_>,
    owner: &Account,
    user: &Account,
    owner_parents: &Parents,
    user_parents: &Parents,
) {
    let big = ctx
        .create_ok(
            owner,
            MetaType::FileNode,
            owner_parents,
            0,
            json!({"metadata": {"x.example": {"v": random_text(ENTRY_SIZE * 4)}}}),
        )
        .await;
    let small = ctx
        .create_ok(
            owner,
            MetaType::FileNode,
            owner_parents,
            0,
            json!({"metadata": {"x.example": {"v": "small"}}}),
        )
        .await;
    ctx.share(
        owner,
        MetaType::FileNode,
        &owner_parents.folders[0],
        user,
        Some(Access::Read),
    )
    .await;

    let destination = destination(MetaType::FileNode, user_parents);
    let response = copy(
        ctx,
        user,
        owner,
        user,
        MetaType::FileNode,
        &big,
        destination.clone(),
    )
    .await;
    assert_eq!(
        response
            .pointer("/methodResponses/0/1/notCreated/c/type")
            .and_then(Value::as_str),
        Some("overQuota"),
        "copying metadata beyond the destination quota must fail: {response:?}"
    );

    let owner_before = ctx.used_quota(owner).await;
    let before = ctx.used_quota(user).await;
    let copied = copied_id(
        &copy(
            ctx,
            user,
            owner,
            user,
            MetaType::FileNode,
            &small,
            destination,
        )
        .await,
        MetaType::FileNode,
    );
    assert!(
        ctx.used_quota(user).await > before,
        "the copy's metadata must be charged to the destination account"
    );
    assert_eq!(ctx.used_quota(owner).await, owner_before);

    ctx.destroy(user, MetaType::FileNode, &[&copied]).await;
    ctx.share(
        owner,
        MetaType::FileNode,
        &owner_parents.folders[0],
        user,
        None,
    )
    .await;
    ctx.destroy(owner, MetaType::FileNode, &[&big, &small])
        .await;
}
