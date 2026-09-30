/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::fixture::{Ctx, MetaType, Parents, Using, method_error, response_ids, sorted};
use crate::utils::{account::Account, server::TestServer};
use registry::schema::{prelude::Property, structs::Metadata};
use serde_json::{Value, json};

struct Objects {
    ty: MetaType,
    a: String,
    b: String,
    c: String,
    d: String,
    e: String,
}

pub async fn test(test: &TestServer) {
    println!("Running JMAP metadata query tests...");
    let ctx = Ctx::new(test);
    let owner = ctx.account("jdoe@example.com");
    let parents = ctx.parents(owner).await;

    let mut all = Vec::with_capacity(MetaType::ALL.len());
    for ty in MetaType::ALL {
        let objects = create_objects(&ctx, owner, &parents, ty).await;
        conditions(&ctx, owner, &parents, &objects).await;
        all.push(objects);
        collation(&ctx, owner, &parents, ty).await;
    }
    for ty in [MetaType::Calendar, MetaType::AddressBook] {
        let response = ctx
            .query(
                owner,
                owner,
                ty,
                json!({"unknownCondition": true}),
                Using::Metadata,
            )
            .await;
        assert_eq!(
            method_error(&response),
            Some("unsupportedFilter"),
            "{}: unknown conditions must be rejected: {response:?}",
            ty.name()
        );
    }

    scan_bound(&ctx, owner, &all).await;

    ctx.cleanup(&[owner]).await;
}

async fn create_objects(
    ctx: &Ctx<'_>,
    owner: &Account,
    parents: &Parents,
    ty: MetaType,
) -> Objects {
    Objects {
        ty,
        a: ctx
            .create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"metadata": {"x.example": {"tag": "Alpha Beta", "n": 1}}}),
            )
            .await,
        b: ctx
            .create_ok(
                owner,
                ty,
                parents,
                1,
                json!({"metadata": {"x.example": {"tag": "gamma"}}}),
            )
            .await,
        c: ctx
            .create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"metadata": {"y.example": {"other": "x"}}}),
            )
            .await,
        d: ctx
            .create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"privateMetadata": {"x.example": {"memo": "please follow up"}}}),
            )
            .await,
        e: ctx
            .create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"metadata": {"z.example": {}}}),
            )
            .await,
    }
}

impl Objects {
    fn ids(&self) -> [&str; 5] {
        [&self.a, &self.b, &self.c, &self.d, &self.e]
    }

    fn only_mine(&self, ids: Vec<String>) -> Vec<String> {
        let mine = self.ids();
        ids.into_iter()
            .filter(|id| mine.contains(&id.as_str()))
            .collect()
    }
}

async fn run(ctx: &Ctx<'_>, owner: &Account, objects: &Objects, filter: Value) -> Vec<String> {
    let response = ctx
        .query(owner, owner, objects.ty, filter.clone(), Using::Metadata)
        .await;
    if let Some(error) = method_error(&response) {
        panic!(
            "{}: filter {filter} failed with {error}: {response:?}",
            objects.ty.name()
        );
    }
    objects.only_mine(response_ids(&response))
}

async fn conditions(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, objects: &Objects) {
    let ty = objects.ty;
    let (a, b, c, d, e) = (
        objects.a.as_str(),
        objects.b.as_str(),
        objects.c.as_str(),
        objects.d.as_str(),
        objects.e.as_str(),
    );

    for (filter, expected) in [
        (json!({"metadataExists": "x.example"}), vec![a, b]),
        (json!({"metadataExists": "x.example/tag"}), vec![a, b]),
        (json!({"metadataExists": "x.example/n"}), vec![a]),
        (json!({"metadataExists": "y.example"}), vec![c]),
        (json!({"metadataExists": "z.example"}), vec![]),
        (json!({"metadataExists": "y.example/missing"}), vec![]),
        (json!({"metadataExists": "photography"}), vec![]),
        (json!({"metadataExists": "photography/tag"}), vec![]),
        (json!({"metadataExists": "X.example"}), vec![]),
        (json!({"metadataExists": "X.EXAMPLE/tag"}), vec![]),
        (json!({"privateMetadataExists": "X.example/memo"}), vec![]),
        (
            json!({"metadataTextEquals": {"path": "X.example/tag", "value": "gamma"}}),
            vec![],
        ),
        (
            json!({"metadataTextContains": {"path": "x.Example/tag", "value": "beta"}}),
            vec![],
        ),
        (
            json!({"metadataTextContains": {"path": "x.example/tag", "value": "BETA"}}),
            vec![a],
        ),
        (
            json!({"metadataTextContains": {"path": "x.example/tag", "value": "a"}}),
            vec![a, b],
        ),
        (
            json!({"metadataTextContains": {"path": "x.example", "value": "gamma"}}),
            vec![],
        ),
        (
            json!({"metadataTextEquals": {"path": "x.example/tag", "value": "gamma"}}),
            vec![b],
        ),
        (
            json!({"metadataTextEquals": {"path": "x.example/tag", "value": "Gamma"}}),
            vec![],
        ),
        (
            json!({"metadataTextEquals": {"path": "x.example/n", "value": "1"}}),
            vec![],
        ),
        (
            json!({"metadataTextEquals": {"path": "photography/tag", "value": "gamma"}}),
            vec![],
        ),
        (json!({"privateMetadataExists": "x.example"}), vec![d]),
        (json!({"privateMetadataExists": "x.example/memo"}), vec![d]),
        (
            json!({"privateMetadataTextContains": {"path": "x.example/memo", "value": "FOLLOW UP"}}),
            vec![d],
        ),
        (
            json!({"privateMetadataTextEquals": {"path": "x.example/memo", "value": "please follow up"}}),
            vec![d],
        ),
        (
            json!({"operator": "AND", "conditions": [
                {"metadataExists": "x.example"},
                {"metadataTextContains": {"path": "x.example/tag", "value": "alpha"}}
            ]}),
            vec![a],
        ),
        (
            json!({"operator": "OR", "conditions": [
                {"metadataTextEquals": {"path": "x.example/tag", "value": "gamma"}},
                {"metadataExists": "x.example/n"}
            ]}),
            vec![a, b],
        ),
        (
            json!({"operator": "OR", "conditions": [
                {"privateMetadataExists": "x.example"},
                {"metadataExists": "y.example"}
            ]}),
            vec![c, d],
        ),
        (
            json!({"operator": "AND", "conditions": [
                {"metadataExists": "x.example"},
                {"operator": "NOT", "conditions": [{"metadataExists": "x.example/n"}]}
            ]}),
            vec![b],
        ),
    ] {
        assert_eq!(
            run(ctx, owner, objects, filter.clone()).await,
            sorted(&expected),
            "{}: {filter}",
            ty.name()
        );
    }

    let negated = run(
        ctx,
        owner,
        objects,
        json!({"operator": "NOT", "conditions": [{"metadataExists": "x.example"}]}),
    )
    .await;
    assert_eq!(negated, sorted(&[c, d, e]), "{}: NOT", ty.name());

    if let (Some(scope_0), Some(scope_1)) = (parents.filter(ty, 0), parents.filter(ty, 1)) {
        for (filter, expected) in [
            (
                json!({"operator": "AND", "conditions": [scope_0.clone(), {"metadataExists": "x.example"}]}),
                vec![a],
            ),
            (
                json!({"operator": "AND", "conditions": [scope_1.clone(), {"metadataExists": "x.example"}]}),
                vec![b],
            ),
            (
                json!({"operator": "AND", "conditions": [
                    scope_0.clone(),
                    {"operator": "NOT", "conditions": [{"metadataExists": "x.example"}]}
                ]}),
                vec![c, d, e],
            ),
            (
                json!({"operator": "OR", "conditions": [
                    scope_1.clone(),
                    {"privateMetadataExists": "x.example/memo"}
                ]}),
                vec![b, d],
            ),
        ] {
            assert_eq!(
                run(ctx, owner, objects, filter.clone()).await,
                sorted(&expected),
                "{}: {filter}",
                ty.name()
            );
        }
    }

    for filter in [
        json!({"metadataExists": "x.example/tag/deeper"}),
        json!({"privateMetadataExists": "x.example/a/b"}),
        json!({"metadataTextContains": {"path": "x.example/a/b", "value": "x"}}),
        json!({"metadataTextEquals": {"value": "x"}}),
        json!({"metadataExists": "x.example/bad~2escape"}),
    ] {
        let response = ctx
            .query(owner, owner, ty, filter.clone(), Using::Metadata)
            .await;
        assert_eq!(
            method_error(&response),
            Some("invalidArguments"),
            "{}: {filter} must be rejected: {response:?}",
            ty.name()
        );
    }
}

async fn scan_bound(ctx: &Ctx<'_>, owner: &Account, all: &[Objects]) {
    let admin = ctx.account("admin");
    admin
        .registry_update_setting(
            Metadata {
                query_max_scan: 1,
                ..Default::default()
            },
            &[Property::QueryMaxScan],
        )
        .await;
    admin.reload_settings().await;

    for objects in all {
        let ty = objects.ty;
        for filter in [
            json!({"metadataTextContains": {"path": "x.example/tag", "value": "beta"}}),
            json!({"metadataTextEquals": {"path": "x.example/tag", "value": "gamma"}}),
        ] {
            let response = ctx
                .query(owner, owner, ty, filter.clone(), Using::Metadata)
                .await;
            assert_eq!(
                method_error(&response),
                Some("unsupportedFilter"),
                "{}: text conditions above queryMaxScan must be rejected: {response:?}",
                ty.name()
            );
        }
        assert_eq!(
            run(ctx, owner, objects, json!({"metadataExists": "x.example"})).await,
            sorted(&[&objects.a, &objects.b]),
            "{}: metadataExists must be evaluated regardless of queryMaxScan",
            ty.name()
        );
    }

    admin
        .registry_update_setting(Metadata::default(), &[Property::QueryMaxScan])
        .await;
    admin.reload_settings().await;

    for objects in all {
        ctx.destroy(owner, objects.ty, &objects.ids()).await;
    }
}

const COLLATION_VALUES: [&str; 8] = [
    "\u{c9}COLE Normale",
    "e\u{301}cole du soir",
    "stra\u{df}e",
    "\u{39f}\u{394}\u{38c}\u{3a3}",
    "Kelvin \u{212a}",
    "\u{ff21}\u{ff22}\u{ff23} wide",
    "pro\u{fb01}le",
    "STRASSE",
];

async fn collation(ctx: &Ctx<'_>, owner: &Account, parents: &Parents, ty: MetaType) {
    let mut ids = Vec::with_capacity(COLLATION_VALUES.len());
    for value in COLLATION_VALUES {
        ids.push(
            ctx.create_ok(
                owner,
                ty,
                parents,
                0,
                json!({"metadata": {"u.example": {"text": value}}}),
            )
            .await,
        );
    }
    let [
        ecole_upper,
        ecole_decomposed,
        strasse_sharp,
        greek,
        kelvin,
        fullwidth,
        ligature,
        strasse_ascii,
    ] = ids.as_slice()
    else {
        unreachable!()
    };
    let mine = |found: Vec<String>| {
        found
            .into_iter()
            .filter(|id| ids.contains(id))
            .collect::<Vec<_>>()
    };

    for (value, expected) in [
        ("\u{e9}cole", vec![ecole_upper, ecole_decomposed]),
        ("E\u{301}COLE", vec![ecole_upper, ecole_decomposed]),
        ("\u{c9}cole normale", vec![ecole_upper]),
        ("stra\u{df}e", vec![strasse_sharp]),
        ("STRA\u{df}E", vec![strasse_sharp]),
        ("strasse", vec![strasse_ascii]),
        ("STRA\u{1e9e}E", vec![]),
        ("\u{3bf}\u{3b4}\u{3cc}\u{3c2}", vec![greek]),
        ("kelvin k", vec![kelvin]),
        ("abc wide", vec![fullwidth]),
        ("profile", vec![]),
        ("PRO\u{fb01}LE", vec![ligature]),
    ] {
        let response = ctx
            .query(
                owner,
                owner,
                ty,
                json!({"metadataTextContains": {"path": "u.example/text", "value": value}}),
                Using::Metadata,
            )
            .await;
        if let Some(error) = method_error(&response) {
            panic!(
                "{}: contains {value:?} failed with {error}: {response:?}",
                ty.name()
            );
        }
        let mut expected = expected
            .into_iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(
            mine(response_ids(&response)),
            expected,
            "{}: i;unicode-casemap substring {value:?}",
            ty.name()
        );
    }

    for (value, expected) in [
        ("\u{c9}COLE Normale", vec![ecole_upper]),
        ("\u{e9}cole normale", vec![]),
        ("\u{e9}cole du soir", vec![]),
        ("e\u{301}cole du soir", vec![ecole_decomposed]),
    ] {
        let response = ctx
            .query(
                owner,
                owner,
                ty,
                json!({"metadataTextEquals": {"path": "u.example/text", "value": value}}),
                Using::Metadata,
            )
            .await;
        let mut expected = expected
            .into_iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(
            mine(response_ids(&response)),
            expected,
            "{}: metadataTextEquals {value:?} must compare bytes",
            ty.name()
        );
    }

    let ids = ids.iter().map(String::as_str).collect::<Vec<_>>();
    ctx.destroy(owner, ty, &ids).await;
}
