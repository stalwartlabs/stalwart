/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    fixture::{Access, Ctx, MetaType, random_text},
    private::share_target,
    quota::{ENTRY_SIZE, create_account},
};
use crate::utils::{account::Account, server::TestServer};
use serde_json::json;
use std::str::FromStr;
use store::{
    ValueKey,
    write::{
        ValueClass,
        metadata::{MetadataBuf, MetadataClass},
    },
};
use types::{collection::Collection, id::Id};

pub async fn test(test: &TestServer) {
    println!("Running JMAP private metadata cleanup tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let first = ctx.account("jane.smith@example.com");
    let second = ctx.account("bill@example.com");

    sharee_account_deletion(&ctx, owner).await;
    purge_frees_private_data(&ctx, owner, first, second).await;

    ctx.cleanup(&[owner, first, second]).await;
}

fn collection(ty: MetaType) -> Collection {
    match ty {
        MetaType::Email => Collection::Email,
        MetaType::Mailbox => Collection::Mailbox,
        MetaType::SieveScript => Collection::SieveScript,
        MetaType::Calendar => Collection::Calendar,
        MetaType::CalendarEvent => Collection::CalendarEvent,
        MetaType::AddressBook => Collection::AddressBook,
        MetaType::ContactCard => Collection::ContactCard,
        MetaType::FileNode => Collection::FileNode,
    }
}

async fn private_container(
    ctx: &Ctx<'_>,
    owner: &Account,
    viewer: &Account,
    ty: MetaType,
    id: &str,
) -> Option<MetadataBuf> {
    let document_id = Id::from_str(id).expect("valid id").document_id();
    ctx.test
        .server
        .store()
        .get_value::<MetadataBuf>(ValueKey {
            account_id: owner.id().document_id(),
            collection: collection(ty).into(),
            document_id,
            class: ValueClass::Metadata(MetadataClass::Private {
                viewer: viewer.id().document_id(),
            }),
        })
        .await
        .expect("store read")
}

async fn sharee_account_deletion(ctx: &Ctx<'_>, owner: &Account) {
    let admin = ctx.account("admin");
    let parents = ctx.parents(owner).await;
    let viewer = create_account(
        ctx,
        "meta-viewer@example.com",
        "meta viewer secret with extra safety",
    )
    .await;

    let mut objects = Vec::new();
    for ty in [
        MetaType::Email,
        MetaType::Mailbox,
        MetaType::CalendarEvent,
        MetaType::ContactCard,
        MetaType::FileNode,
    ] {
        let id = ctx
            .create_ok(
                owner,
                ty,
                &parents,
                0,
                json!({"metadata": {"x.example": {"kept": true}}}),
            )
            .await;
        ctx.share(
            owner,
            ty,
            &share_target(ty, &parents, &id, 0),
            &viewer,
            Some(Access::Read),
        )
        .await;
        ctx.update_ok(
            &viewer,
            owner,
            ty,
            &id,
            json!({"privateMetadata": {"p.example": {"who": "deleted viewer"}}}),
        )
        .await;
        assert!(
            private_container(ctx, owner, &viewer, ty, &id)
                .await
                .is_some(),
            "{}: private container not written",
            ty.name()
        );
        objects.push((ty, id));
    }

    let viewer_id = viewer.id();
    admin.destroy_account(viewer).await;
    ctx.test.wait_for_tasks().await;

    let deleted = Account::new(
        "meta-viewer@example.com",
        "meta viewer secret with extra safety",
        &[],
        "Deleted viewer",
        viewer_id,
    );
    for (ty, id) in &objects {
        assert!(
            private_container(ctx, owner, &deleted, *ty, id)
                .await
                .is_none(),
            "{}: private metadata of a deleted account survived in the owner's account",
            ty.name()
        );
        ctx.assert_metadata(
            owner,
            owner,
            *ty,
            id,
            json!({"x.example": {"kept": true}}),
            json!({}),
        )
        .await;
    }
}

async fn purge_frees_private_data(
    ctx: &Ctx<'_>,
    owner: &Account,
    first: &Account,
    second: &Account,
) {
    let parents = ctx.parents(owner).await;
    let mut objects = Vec::new();
    for ty in [MetaType::Mailbox, MetaType::FileNode, MetaType::Calendar] {
        let id = ctx.create_ok(owner, ty, &parents, 0, json!({})).await;
        let target = share_target(ty, &parents, &id, 0);
        for viewer in [first, second] {
            ctx.share(owner, ty, &target, viewer, Some(Access::Read))
                .await;
        }
        objects.push((ty, id));
    }
    ctx.test.wait_for_tasks().await;

    let first_before = ctx.used_quota(first).await;
    let second_before = ctx.used_quota(second).await;
    for (ty, id) in &objects {
        for viewer in [first, second] {
            ctx.update_ok(
                viewer,
                owner,
                *ty,
                id,
                json!({"privateMetadata": {"p.example": {"v": random_text(ENTRY_SIZE)}}}),
            )
            .await;
        }
    }
    let charged = (ENTRY_SIZE * objects.len()) as i64;
    for (viewer, before) in [(first, first_before), (second, second_before)] {
        let used = ctx.used_quota(viewer).await;
        assert!(
            used - before >= charged,
            "private metadata not charged to {}: {before} before, {used} after",
            viewer.name()
        );
    }

    for (ty, id) in &objects {
        ctx.destroy(owner, *ty, &[id]).await;
    }
    ctx.test.wait_for_tasks().await;
    ctx.purge(&[owner]).await;

    for (viewer, before) in [(first, first_before), (second, second_before)] {
        assert_eq!(
            ctx.used_quota(viewer).await,
            before,
            "the account purge must return the private bytes of destroyed objects to {}",
            viewer.name()
        );
        for (ty, id) in &objects {
            assert!(
                private_container(ctx, owner, viewer, *ty, id)
                    .await
                    .is_none(),
                "{}: private container of a destroyed object survived the purge",
                ty.name()
            );
        }
    }
}
