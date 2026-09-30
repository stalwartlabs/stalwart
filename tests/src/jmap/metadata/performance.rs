/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents, Using};
use crate::utils::{account::Account, server::TestServer};
use serde_json::{Value, json};
use std::str::FromStr;
use store::{
    ValueKey,
    dispatch::StoreOps,
    write::{Archive, ArchiveBytes},
};
use types::{
    collection::Collection,
    field::{CalendarEventField, ContactField},
    id::Id,
};

const OBJECTS: usize = 6;
const RUNS: usize = 4;

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata performance guards...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let parents = ctx.parents(owner).await;

    for ty in MetaType::ALL {
        reads(&ctx, owner, &parents, ty).await;
    }
    for ty in MetaType::ALL {
        deletions(&ctx, owner, &parents, ty).await;
    }
    for ty in [MetaType::CalendarEvent, MetaType::ContactCard] {
        metadata_only_writes(&ctx, owner, &parents, ty).await;
    }

    ctx.cleanup(&[owner]).await;
}

pub async fn min_ops(test: &TestServer, measure: impl AsyncFn()) -> usize {
    test.wait_for_tasks().await;
    let mut lowest = usize::MAX;
    for _ in 0..RUNS {
        StoreOps::take();
        measure().await;
        lowest = lowest.min(StoreOps::take().total());
    }
    lowest
}

fn clear_cache(test: &TestServer, ty: MetaType) {
    let cache = &test.server.inner.cache;
    match ty {
        MetaType::Email | MetaType::Mailbox => cache.messages.clear(),
        MetaType::Calendar | MetaType::CalendarEvent => cache.events.clear(),
        MetaType::AddressBook | MetaType::ContactCard => cache.contacts.clear(),
        MetaType::FileNode => cache.files.clear(),
        MetaType::SieveScript => (),
    }
}

fn scope(ty: MetaType, parents: &Parents) -> Value {
    parents.filter(ty, 0).unwrap_or_else(|| json!({}))
}

struct Measures {
    cold: usize,
    plain: usize,
    selected: usize,
    query: usize,
    aware_ids: usize,
    plain_ids: usize,
}

async fn measure(
    ctx: &Ctx<'_>,
    owner: &Account,
    parents: &Parents,
    ty: MetaType,
    ids: &[&str],
) -> Measures {
    let test = ctx.test;
    Measures {
        cold: min_ops(test, async || {
            clear_cache(test, ty);
            ctx.get(owner, owner, ty, ids, Some(&["id"]), Using::Plain)
                .await;
        })
        .await,
        plain: min_ops(test, async || {
            ctx.get(owner, owner, ty, ids, None, Using::Plain).await;
        })
        .await,
        selected: min_ops(test, async || {
            ctx.get(
                owner,
                owner,
                ty,
                ids,
                Some(&["id", "metadata", "privateMetadata"]),
                Using::Metadata,
            )
            .await;
        })
        .await,
        query: min_ops(test, async || {
            ctx.query(owner, owner, ty, scope(ty, parents), Using::Plain)
                .await;
        })
        .await,
        aware_ids: min_ops(test, async || {
            ctx.get(owner, owner, ty, ids, Some(&["id"]), Using::Metadata)
                .await;
        })
        .await,
        plain_ids: min_ops(test, async || {
            ctx.get(owner, owner, ty, ids, Some(&["id"]), Using::Plain)
                .await;
        })
        .await,
    }
}

async fn reads(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let mut ids = Vec::with_capacity(OBJECTS);
    for _ in 0..OBJECTS {
        ids.push(ctx.create_ok(owner, ty, parents, 0, json!({})).await);
    }
    let ids = ids.iter().map(String::as_str).collect::<Vec<_>>();
    let name = ty.name();

    let before = measure(ctx, owner, parents, ty, &ids).await;
    assert_eq!(
        before.aware_ids, before.plain_ids,
        "{name}: a metadata-aware request from a user without private data must read nothing extra"
    );

    for id in &ids[..2] {
        ctx.update_ok(
            owner,
            owner,
            ty,
            id,
            json!({"metadata/x.example": {"flag": true}}),
        )
        .await;
    }
    let partial = measure(ctx, owner, parents, ty, &ids).await;

    for id in &ids[2..] {
        ctx.update_ok(
            owner,
            owner,
            ty,
            id,
            json!({"metadata/x.example": {"flag": true}}),
        )
        .await;
    }
    let after = measure(ctx, owner, parents, ty, &ids).await;

    for (label, flagged) in [("some", &partial), ("all", &after)] {
        assert!(
            flagged.cold <= before.cold,
            "{name}: a cache build read metadata keys when {label} objects carry metadata ({} reads, {} without metadata)",
            flagged.cold,
            before.cold
        );
        assert!(
            flagged.plain <= before.plain,
            "{name}: /get without the capability read containers when {label} objects carry metadata ({} reads, {} without)",
            flagged.plain,
            before.plain
        );
        assert!(
            flagged.query <= before.query,
            "{name}: a query without metadata conditions read containers when {label} objects carry metadata ({} reads, {} without)",
            flagged.query,
            before.query
        );
        assert!(
            flagged.selected > before.selected && flagged.selected <= before.selected + 1,
            "{name}: /get of metadata must read the containers of flagged objects in one bulk call when {label} objects carry metadata ({} reads, {} without)",
            flagged.selected,
            before.selected
        );
        assert_eq!(
            flagged.aware_ids, flagged.plain_ids,
            "{name}: metadata-aware requests that select no metadata must read nothing extra"
        );
    }

    for id in &ids[..2] {
        ctx.update_ok(
            owner,
            owner,
            ty,
            id,
            json!({"privateMetadata/p.example": {"mine": true}}),
        )
        .await;
    }
    let private = measure(ctx, owner, parents, ty, &ids).await;
    assert!(
        private.selected <= after.selected + 1,
        "{name}: private containers must be read in one bulk call ({} reads, {} before)",
        private.selected,
        after.selected
    );
    assert!(
        private.plain <= before.plain && private.cold <= before.cold,
        "{name}: private metadata must cost nothing to clients without the capability"
    );
    assert_eq!(
        private.aware_ids, private.plain_ids,
        "{name}: the private state must come from memory, not from a per-request read"
    );

    ctx.destroy(owner, ty, &ids).await;
}

async fn deletions(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let mut unflagged = Vec::new();
    let mut flagged = Vec::new();
    for _ in 0..3 {
        unflagged.push(ctx.create_ok(owner, ty, parents, 0, json!({})).await);
        flagged.push(
            ctx.create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"metadata": {"x.example": {"flag": true}}}),
            )
            .await,
        );
    }

    let mut unflagged_ops = usize::MAX;
    let mut flagged_ops = usize::MAX;
    for (ids, lowest) in [
        (&unflagged, &mut unflagged_ops),
        (&flagged, &mut flagged_ops),
    ] {
        for id in ids {
            ctx.test.wait_for_tasks().await;
            StoreOps::take();
            ctx.destroy(owner, ty, &[id]).await;
            *lowest = (*lowest).min(StoreOps::take().total());
        }
    }
    assert!(
        unflagged_ops < flagged_ops,
        "{}: deleting objects without metadata must not read metadata keys ({unflagged_ops} reads without metadata, {flagged_ops} with)",
        ty.name()
    );
}

pub async fn stored(
    test: &TestServer,
    owner: &Account,
    ty: MetaType,
    id: &str,
) -> (Option<ArchiveBytes>, Option<ArchiveBytes>) {
    let account_id = owner.id().document_id();
    let document_id = Id::from_str(id).expect("valid id").document_id();
    let (collection, content) = match ty {
        MetaType::CalendarEvent => (
            Collection::CalendarEvent,
            CalendarEventField::Content.field(),
        ),
        MetaType::ContactCard => (Collection::ContactCard, ContactField::Content.field()),
        other => panic!("{} has no content archive", other.name()),
    };
    let store = test.server.store();
    let main = store
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(account_id, collection, document_id))
        .await
        .expect("store read")
        .map(|archive| archive.inner);
    let content = store
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            collection,
            document_id,
            content,
        ))
        .await
        .expect("store read")
        .map(|archive| archive.inner);
    (main, content)
}

async fn metadata_only_writes(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let name = ty.name();
    let id = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let (main_0, content_0) = stored(ctx.test, owner, ty, &id).await;
    assert!(
        main_0.is_some() && content_0.is_some(),
        "{name}: archives missing"
    );

    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"metadata/x.example": {"v": 1}}),
    )
    .await;
    let (main_1, content_1) = stored(ctx.test, owner, ty, &id).await;
    assert_eq!(
        content_0, content_1,
        "{name}: a metadata write rewrote the content archive"
    );

    for patch in [
        json!({"metadata/x.example/v": 2}),
        json!({"metadata/y.example": {"w": true}}),
        json!({"privateMetadata/p.example": {"v": 1}}),
        json!({"privateMetadata/p.example/v": 2}),
    ] {
        ctx.update_ok(owner, owner, ty, &id, patch.clone()).await;
        let (main, content) = stored(ctx.test, owner, ty, &id).await;
        assert_eq!(
            content, content_0,
            "{name}: {patch} rewrote the content archive"
        );
        assert_eq!(
            main, main_1,
            "{name}: {patch} rewrote the main archive although presence did not change"
        );
    }

    ctx.update_ok(owner, owner, ty, &id, json!({"metadata": {}}))
        .await;
    let (_, content) = stored(ctx.test, owner, ty, &id).await;
    assert_eq!(
        content, content_0,
        "{name}: clearing metadata rewrote the content archive"
    );

    ctx.destroy(owner, ty, &[&id]).await;
}
