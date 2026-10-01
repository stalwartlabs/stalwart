/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    copy::destination,
    fixture::{Access, Ctx, MetaType, Parents, Using, response_ids},
    quota::create_account,
};
use crate::utils::{account::Account, server::TestServer};
use serde_json::{Map, Value, json};
use std::{cell::RefCell, str::FromStr, time::Duration};
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
const GROUP: usize = 3;

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
    for ty in MetaType::ALL {
        if ty.has_changes() {
            changes_reads(&ctx, owner, &parents, ty).await;
        }
    }
    for ty in MetaType::ALL {
        writes_and_queries(&ctx, owner, &parents, ty).await;
    }
    let copier = ctx.account("jane.smith@example.com");
    let copier_parents = ctx.parents(copier).await;
    for ty in MetaType::COPYABLE {
        copies(&ctx, owner, copier, &parents, &copier_parents, ty).await;
    }
    for ty in MetaType::ALL {
        creates_and_destroys(&ctx, owner, &parents, ty).await;
    }

    runtime_paths(&ctx, owner, &parents).await;

    ctx.cleanup(&[owner, copier]).await;
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

#[derive(Debug, Clone, Copy)]
struct Reads {
    gets: usize,
    metadata: usize,
    metadata_min: usize,
}

impl Reads {
    const NONE: Reads = Reads {
        gets: usize::MAX,
        metadata: 0,
        metadata_min: usize::MAX,
    };

    fn take() -> Self {
        let ops = StoreOps::take();
        Reads {
            gets: ops.get_value - ops.metadata_get,
            metadata: ops.metadata,
            metadata_min: ops.metadata,
        }
    }

    fn add(&mut self, sample: Reads) {
        self.gets = self.gets.min(sample.gets);
        self.metadata = self.metadata.max(sample.metadata);
        self.metadata_min = self.metadata_min.min(sample.metadata);
    }
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

    let name = ty.name();
    let mut unflagged_reads = Reads::NONE;
    let mut flagged_reads = Reads::NONE;
    for (ids, reads) in [
        (&unflagged, &mut unflagged_reads),
        (&flagged, &mut flagged_reads),
    ] {
        for id in ids {
            settle(ctx, owner, ty).await;
            ctx.destroy(owner, ty, &[id]).await;
            reads.add(Reads::take());
        }
    }
    assert_eq!(
        unflagged_reads.metadata, 0,
        "{name}: deleting objects without metadata must not read metadata keys ({unflagged_reads:?})"
    );
    assert!(
        flagged_reads.metadata_min == 1 && flagged_reads.metadata == 1,
        "{name}: deleting an object with metadata must read its container once ({flagged_reads:?})"
    );
    assert_eq!(
        flagged_reads.gets, unflagged_reads.gets,
        "{name}: deleting an object with metadata must read nothing but its container ({flagged_reads:?}, {unflagged_reads:?} without metadata)"
    );
}

async fn changes_reads(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let name = ty.name();
    let test = ctx.test;
    let a = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let b = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    let plain_since = ctx.state(owner, owner, ty, Using::Plain).await;
    let aware_since = ctx.state(owner, owner, ty, Using::Metadata).await;
    let changes = async |since: &str, using: Using| {
        min_ops(test, async || {
            ctx.changes(owner, owner, ty, since, json!({}), using).await;
        })
        .await
    };

    ctx.update_ok(owner, owner, ty, &a, ty.rename_patch(&ctx.unique(ty)))
        .await;
    let plain = changes(&plain_since, Using::Plain).await;
    let aware = changes(&aware_since, Using::Metadata).await;
    assert_eq!(
        aware, plain,
        "{name}: /changes with the capability and no private data must read nothing extra ({aware} reads, {plain} without the capability)"
    );

    ctx.update_ok(
        owner,
        owner,
        ty,
        &b,
        json!({"metadata/x.example": {"v": 1}}),
    )
    .await;
    let plain_shared = changes(&plain_since, Using::Plain).await;
    assert!(
        plain_shared <= plain,
        "{name}: shared metadata rows cost /changes without the capability a read ({plain_shared} reads, {plain} before)"
    );

    let shared_only = ctx.state(owner, owner, ty, Using::Metadata).await;
    ctx.update_ok(
        owner,
        owner,
        ty,
        &b,
        json!({"privateMetadata/p.example": {"v": 1}}),
    )
    .await;
    let plain_private = changes(&plain_since, Using::Plain).await;
    let aware_private = changes(&aware_since, Using::Metadata).await;
    let private_only = changes(&shared_only, Using::Metadata).await;
    assert!(
        plain_private <= plain,
        "{name}: private rows cost /changes without the capability a read ({plain_private} reads, {plain} before)"
    );
    assert_eq!(
        aware_private,
        plain + 1,
        "{name}: private rows must cost the viewer exactly one private log read ({aware_private} reads, {plain} without)"
    );
    assert_eq!(
        private_only, plain,
        "{name}: a sinceState at the shared state must read only the private log ({private_only} reads, {plain} without)"
    );

    ctx.destroy(owner, ty, &[&a, &b]).await;
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

async fn set_ops(
    ctx: &Ctx<'_>,
    owner: &Account,
    ty: MetaType,
    ids: &[String],
    using: Using,
    patch: impl Fn() -> Value,
) -> Reads {
    let mut lowest = Reads::NONE;
    for _ in 0..RUNS {
        ctx.test.wait_for_tasks().await;
        ctx.get(owner, owner, ty, &[], Some(&["id"]), Using::Plain)
            .await;
        let update = ids
            .iter()
            .map(|id| (id.clone(), patch()))
            .collect::<Map<String, Value>>();
        StoreOps::take();
        let response = ctx
            .method(
                owner,
                using,
                &format!("{}/set", ty.name()),
                json!({"accountId": owner.id_string(), "update": update}),
            )
            .await;
        lowest.add(Reads::take());
        let updated = response
            .pointer("/methodResponses/0/1/updated")
            .and_then(Value::as_object)
            .map_or(0, Map::len);
        assert_eq!(
            updated,
            ids.len(),
            "{} update failed: {response:?}",
            ty.name()
        );
    }
    lowest
}

async fn query_ops(
    ctx: &Ctx<'_>,
    owner: &Account,
    ty: MetaType,
    filter: &Value,
    using: Using,
) -> (usize, Vec<String>) {
    let found = RefCell::new(Vec::new());
    let ops = min_ops(ctx.test, async || {
        let response = ctx.query(owner, owner, ty, filter.clone(), using).await;
        *found.borrow_mut() = response_ids(&response);
    })
    .await;
    (ops, found.into_inner())
}

async fn writes_and_queries(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let name = ty.name();
    let mut unflagged = Vec::with_capacity(GROUP);
    let mut flagged = Vec::with_capacity(GROUP);
    for _ in 0..GROUP {
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

    let rename = || ty.rename_patch(&ctx.unique(ty));
    let plain_unflagged = set_ops(ctx, owner, ty, &unflagged, Using::Plain, rename).await;
    let plain_flagged = set_ops(ctx, owner, ty, &flagged, Using::Plain, rename).await;
    let aware_flagged = set_ops(ctx, owner, ty, &flagged, Using::Metadata, rename).await;
    assert!(
        plain_flagged.metadata_min == 0 && plain_flagged.gets <= plain_unflagged.gets,
        "{name}: a /set without metadata keys read containers of flagged objects ({plain_flagged:?}, {plain_unflagged:?} for unflagged objects)"
    );
    assert!(
        aware_flagged.metadata_min == 0 && aware_flagged.gets == plain_flagged.gets,
        "{name}: a metadata-aware /set without metadata keys must read nothing extra ({aware_flagged:?}, {plain_flagged:?} without the capability)"
    );

    let removal = || json!({"metadata/zz.example": null});
    let patch_unflagged = set_ops(ctx, owner, ty, &unflagged, Using::Metadata, removal).await;
    let patch_flagged = set_ops(ctx, owner, ty, &flagged, Using::Metadata, removal).await;
    assert!(
        patch_flagged.metadata_min <= patch_unflagged.metadata_min + 1
            && patch_flagged.gets <= patch_unflagged.gets,
        "{name}: metadata patches must read the containers of all flagged objects in one bulk call ({patch_flagged:?}, {patch_unflagged:?} for unflagged objects)"
    );

    let scope = scope(ty, parents);
    let (plain_query, _) = query_ops(ctx, owner, ty, &scope, Using::Plain).await;
    for (condition, is_shared) in [
        (json!({"metadataExists": "x.example/flag"}), true),
        (
            json!({"metadataTextEquals": {"path": "x.example/flag", "value": "x"}}),
            false,
        ),
        (json!({"privateMetadataExists": "x.example"}), false),
    ] {
        let mut filter = scope.clone();
        if let (Some(filter), Value::Object(condition)) = (filter.as_object_mut(), condition) {
            filter.extend(condition);
        }
        let (ops, found) = query_ops(ctx, owner, ty, &filter, Using::Metadata).await;
        assert!(
            ops <= plain_query + 1,
            "{name}: {filter} must read the flagged containers in one bulk call ({ops} reads, {plain_query} without the condition)"
        );
        assert!(
            flagged.iter().all(|id| found.contains(id) == is_shared)
                && unflagged.iter().all(|id| !found.contains(id)),
            "{name}: {filter} returned {found:?}"
        );
    }

    let mut ids = unflagged;
    ids.extend(flagged);
    ctx.destroy(
        owner,
        ty,
        &ids.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .await;
}

async fn copies(
    ctx: &Ctx<'_>,
    owner: &Account,
    copier: &Account,
    owner_parents: &Parents,
    copier_parents: &Parents,
    ty: MetaType,
) {
    let name = ty.name();
    let unflagged = ctx.create_ok(owner, ty, owner_parents, 0, json!({})).await;
    let flagged = ctx
        .create_ok(
            owner,
            ty,
            owner_parents,
            0,
            json!({"metadata": {"x.example": {"flag": true}}}),
        )
        .await;
    let target = match ty {
        MetaType::FileNode => owner_parents.folders[0].clone(),
        _ => owner_parents
            .parent(ty, 0)
            .expect("contained type")
            .to_string(),
    };
    ctx.share(owner, ty, &target, copier, Some(Access::Read))
        .await;

    let copy_ops = async |source: &str, using: Using| {
        let mut lowest = Reads::NONE;
        for _ in 0..RUNS {
            ctx.test.wait_for_tasks().await;
            for account in [owner, copier] {
                ctx.get(copier, account, ty, &[], Some(&["id"]), Using::Plain)
                    .await;
            }
            let mut create = destination(ty, copier_parents);
            if let Some(create) = create.as_object_mut() {
                create.insert("id".into(), source.into());
            }
            StoreOps::take();
            let response = ctx
                .method(
                    copier,
                    using,
                    &format!("{name}/copy"),
                    json!({
                        "fromAccountId": owner.id_string(),
                        "accountId": copier.id_string(),
                        "create": {"c": create}
                    }),
                )
                .await;
            lowest.add(Reads::take());
            let id = response
                .pointer("/methodResponses/0/1/created/c/id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{name} copy failed: {response:?}"))
                .to_string();
            ctx.destroy(copier, ty, &[&id]).await;
        }
        lowest
    };
    let plain_unflagged = copy_ops(&unflagged, Using::Plain).await;
    let aware_unflagged = copy_ops(&unflagged, Using::Metadata).await;
    let aware_flagged = copy_ops(&flagged, Using::Metadata).await;
    assert!(
        aware_unflagged.metadata_min == 0
            && plain_unflagged.metadata_min == 0
            && aware_unflagged.gets == plain_unflagged.gets,
        "{name}: a metadata-aware /copy of an object without metadata must read nothing extra ({aware_unflagged:?}, {plain_unflagged:?} without the capability)"
    );
    assert!(
        aware_flagged.metadata_min == 1 && aware_flagged.gets == aware_unflagged.gets,
        "{name}: /copy must read the source containers in one bulk call ({aware_flagged:?}, {aware_unflagged:?} without metadata)"
    );

    ctx.share(owner, ty, &target, copier, None).await;
    ctx.destroy(owner, ty, &[&unflagged, &flagged]).await;
}

async fn settle(ctx: &Ctx<'_>, owner: &Account, ty: MetaType) {
    tokio::time::sleep(SETTLE_DELAY).await;
    ctx.test.wait_for_tasks().await;
    ctx.get(owner, owner, ty, &[], Some(&["id"]), Using::Metadata)
        .await;
    StoreOps::take();
}

const SETTLE_DELAY: Duration = Duration::from_millis(50);

const WRITE_RUNS: usize = 8;

async fn creates_and_destroys(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let name = ty.name();
    let mut created = Vec::with_capacity(2 * WRITE_RUNS);
    let mut create_ops = [Reads::NONE; 2];
    for _ in 0..WRITE_RUNS {
        for (lowest, using) in create_ops.iter_mut().zip([Using::Plain, Using::Metadata]) {
            let payload = ctx.payload(owner, owner, ty, parents, 0, json!({})).await;
            settle(ctx, owner, ty).await;
            let response = ctx
                .method(
                    owner,
                    using,
                    &format!("{name}/set"),
                    json!({"accountId": owner.id_string(), "create": {"i0": payload}}),
                )
                .await;
            lowest.add(Reads::take());
            let id = response
                .pointer("/methodResponses/0/1/created/i0/id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{name} not created: {response:?}"));
            created.push(id.to_string());
        }
    }
    let [plain_create, aware_create] = create_ops;
    assert!(
        aware_create.metadata_min == 0
            && plain_create.metadata_min == 0
            && aware_create.gets == plain_create.gets,
        "{name}: a metadata-aware create without metadata must read exactly what a plain one reads ({aware_create:?}, {plain_create:?} without the capability)"
    );

    let mut destroy_ops = [Reads::NONE; 2];
    for (id, using) in created
        .iter()
        .zip([Using::Plain, Using::Metadata].into_iter().cycle())
    {
        let mut arguments = ty.destroy_arguments();
        if let Some(arguments) = arguments.as_object_mut() {
            arguments.insert("accountId".into(), owner.id_string().into());
            arguments.insert("destroy".into(), json!([id]));
        }
        settle(ctx, owner, ty).await;
        let response = ctx
            .method(owner, using, &format!("{name}/set"), arguments)
            .await;
        let reads = Reads::take();
        assert!(
            response
                .pointer("/methodResponses/0/1/destroyed/0")
                .is_some(),
            "{name} {id} not destroyed: {response:?}"
        );
        if let Some(lowest) = destroy_ops.get_mut(usize::from(using == Using::Metadata)) {
            lowest.add(reads);
        }
    }
    let [plain_destroy, aware_destroy] = destroy_ops;
    assert!(
        aware_destroy.metadata_min == 0
            && plain_destroy.metadata_min == 0
            && aware_destroy.gets == plain_destroy.gets,
        "{name}: a metadata-aware destroy of an object without metadata must read exactly what a plain one reads ({aware_destroy:?}, {plain_destroy:?} without the capability)"
    );
}

async fn runtime_paths(ctx: &Ctx<'_>, owner: &Account, parents: &Parents) {
    let test = ctx.test;
    let server = &test.server;
    let ty = MetaType::Mailbox;

    let account = create_account(
        ctx,
        "meta-guard@example.com",
        "meta guard secret with extra safety",
    )
    .await;
    let account_parents = ctx.parents(&account).await;
    let (warm, cold) = viewer_loads(ctx, &account, &account_parents).await;
    assert_eq!(
        cold,
        warm + 1,
        "a viewer without private data must cost one empty range read on a cold cache and mark nothing stale ({cold} reads, {warm} when warm)"
    );

    let account_id = account.id().document_id();
    for (path, expected, ops) in [
        (
            "purge_private_metadata",
            1,
            min_ops(test, async || {
                server
                    .purge_private_metadata(account_id, Some(10))
                    .await
                    .expect("purge");
            })
            .await,
        ),
        (
            "metadata_used_quota",
            2,
            min_ops(test, async || {
                assert_eq!(
                    server.metadata_used_quota(account_id).await.expect("quota"),
                    0
                );
            })
            .await,
        ),
        (
            "destroy_viewer_metadata",
            1,
            min_ops(test, async || {
                server
                    .destroy_viewer_metadata(account_id)
                    .await
                    .expect("destroy");
            })
            .await,
        ),
        (
            "destroy_owner_metadata",
            1,
            min_ops(test, async || {
                server
                    .destroy_owner_metadata(account_id)
                    .await
                    .expect("destroy");
            })
            .await,
        ),
    ] {
        assert_eq!(
            ops, expected,
            "{path} on an account that never had metadata must read one empty range per key class"
        );
    }
    ctx.destroy_all(&account).await;
    test.account("admin").destroy_account(account).await;
    test.wait_for_tasks().await;

    let id = ctx.create_ok(owner, ty, parents, 0, json!({})).await;
    ctx.update_ok(
        owner,
        owner,
        ty,
        &id,
        json!({"privateMetadata/p.example": {"v": 1}}),
    )
    .await;
    let since = ctx.state(owner, owner, ty, Using::Plain).await;
    let scope = scope(ty, parents);
    let aware_get = async || {
        ctx.get(owner, owner, ty, &[&id], Some(&["id"]), Using::Metadata)
            .await;
    };
    let warm = min_ops(test, aware_get).await;
    let cold = min_ops(test, async || {
        server.inner.cache.metadata_viewers.clear();
        aware_get().await;
    })
    .await;
    assert_eq!(
        cold,
        warm + 2,
        "a cold viewer load with private data must read the Owner keys and revalidate the owner's shared cache ({cold} reads, {warm} when warm)"
    );
    let after_unaware = min_ops(test, async || {
        server.inner.cache.metadata_viewers.clear();
        ctx.update(
            owner,
            owner,
            ty,
            &id,
            ty.rename_patch(&ctx.unique(ty)),
            Using::Plain,
        )
        .await;
        ctx.query(owner, owner, ty, scope.clone(), Using::Plain)
            .await;
        ctx.changes(owner, owner, ty, &since, json!({}), Using::Plain)
            .await;
        StoreOps::take();
        aware_get().await;
    })
    .await;
    assert_eq!(
        after_unaware, cold,
        "/set, /query and /changes without the capability must leave the viewer cache cold ({after_unaware} reads for the next aware /get, {cold} on a cold cache)"
    );
    ctx.destroy(owner, ty, &[&id]).await;
}

async fn viewer_loads(ctx: &Ctx<'_>, account: &Account, parents: &Parents) -> (usize, usize) {
    let test = ctx.test;
    let ty = MetaType::Mailbox;
    let id = ctx.create_ok(account, ty, parents, 0, json!({})).await;
    let aware_get = async || {
        ctx.get(account, account, ty, &[&id], Some(&["id"]), Using::Metadata)
            .await;
    };
    let warm = min_ops(test, aware_get).await;
    let cold = min_ops(test, async || {
        test.server.inner.cache.metadata_viewers.clear();
        aware_get().await;
    })
    .await;
    ctx.destroy(account, ty, &[&id]).await;
    (warm, cold)
}
