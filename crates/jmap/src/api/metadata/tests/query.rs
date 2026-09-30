/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{container, support};
use crate::api::metadata::{MetadataQuery, MetadataSupport};
use jmap_proto::object::metadata::{MetadataCondition, MetadataFilter, MetadataPath, MetadataRoot};
use store::roaring::RoaringBitmap;

fn filter(root: MetadataRoot, path: &str, condition: MetadataCondition) -> MetadataFilter {
    let (namespace, key) = match path.split_once('/') {
        Some((namespace, key)) => (namespace, Some(key.into())),
        None => (path, None),
    };
    MetadataFilter::Condition {
        root,
        path: MetadataPath {
            namespace: namespace.into(),
            key,
        },
        condition,
    }
}

fn exists(path: &str) -> MetadataFilter {
    filter(MetadataRoot::Shared, path, MetadataCondition::Exists)
}

fn contains(path: &str, text: &str) -> MetadataFilter {
    filter(
        MetadataRoot::Shared,
        path,
        MetadataCondition::TextContains(text.into()),
    )
}

fn equals(path: &str, text: &str) -> MetadataFilter {
    filter(
        MetadataRoot::Shared,
        path,
        MetadataCondition::TextEquals(text.into()),
    )
}

fn evaluate(
    query: &MetadataQuery,
    shared: &[(u32, &str)],
    private: &[(u32, &str)],
) -> Vec<Vec<u32>> {
    let mut results = vec![RoaringBitmap::new(); query.len()];
    let mut scratch = String::new();
    for (root, containers) in [
        (MetadataRoot::Shared, shared),
        (MetadataRoot::Private, private),
    ] {
        for (document_id, json) in containers {
            let stored = container(json);
            query.evaluate_container(
                root,
                *document_id,
                &stored.view(),
                &mut results,
                &mut scratch,
            );
        }
    }
    results
        .into_iter()
        .map(|result| result.into_iter().collect())
        .collect()
}

const CONTAINERS: &[(u32, &str)] = &[
    (
        1,
        r#"{"acme.example": {"memo": "Please FOLLOW UP soon", "color": "blue", "n": 1}, "empty.example": {}}"#,
    ),
    (
        2,
        r#"{"acme.example": {"memo": "nothing", "color": "Blue"}}"#,
    ),
    (3, r#"{"other.example": {"x": null}}"#),
    (4, r#"{"acme.example": {"memo": "Ünïcödé Straße"}}"#),
];

#[test]
fn filter_evaluation() {
    let filters = [
        exists("acme.example"),
        exists("acme.example/color"),
        exists("empty.example"),
        exists("other.example/x"),
        contains("acme.example/memo", "follow up"),
        contains("acme.example/memo", "ÜNÏ"),
        equals("acme.example/color", "blue"),
        contains("acme.example/n", "1"),
        equals("acme.example", "x"),
        exists("bad name"),
        exists("unregistered"),
        filter(
            MetadataRoot::Private,
            "acme.example",
            MetadataCondition::Exists,
        ),
        contains("acme.example/memo", ""),
        exists("acme.example/missing"),
    ];
    let query = MetadataQuery::new(Some(&support()), &filters).expect("supported filters");
    assert!(query.has_shared() && query.has_private());

    let expected: [&[u32]; 14] = [
        &[1, 2, 4],
        &[1, 2],
        &[],
        &[3],
        &[1],
        &[4],
        &[1],
        &[],
        &[],
        &[],
        &[],
        &[2],
        &[1, 2, 4],
        &[],
    ];
    let results = evaluate(
        &query,
        CONTAINERS,
        &[(2, r#"{"acme.example": {"note": "mine"}}"#)],
    );
    for ((result, expected), filter) in results.iter().zip(expected).zip(&filters) {
        assert_eq!(result.as_slice(), expected, "{filter:?}");
    }
}

#[test]
fn unsupported_namespaces_match_nothing() {
    let no_vendor = MetadataSupport {
        vendor_namespaces: false,
        ..support()
    };
    let filters = [exists("acme.example"), contains("acme.example/memo", "")];
    let query = MetadataQuery::new(Some(&no_vendor), &filters).expect("valid filters");
    assert!(!query.has_shared());
    assert_eq!(
        evaluate(&query, CONTAINERS, &[]),
        vec![Vec::<u32>::new(); 2]
    );
}

#[test]
fn unsupported_filters() {
    let private = [filter(
        MetadataRoot::Private,
        "a.example",
        MetadataCondition::Exists,
    )];
    let no_private = MetadataSupport {
        private: false,
        ..support()
    };
    assert!(MetadataQuery::new(Some(&no_private), &private).is_err());
    assert!(MetadataQuery::new(Some(&support()), &private).is_ok());
    assert!(MetadataQuery::new(None, &private).is_err());
    assert!(
        MetadataQuery::new(None, &[])
            .expect("no filters")
            .is_empty()
    );
}

#[test]
fn invalid_conditions() {
    let invalid = |root| {
        [MetadataFilter::Invalid {
            root,
            name: "metadataExists",
            reason: "metadata path must have at most two segments",
        }]
    };
    let fails_with = |result: trc::Result<MetadataQuery>, event: trc::JmapEvent| {
        result.is_err_and(|err| err.matches(trc::EventType::Jmap(event)))
    };
    let no_private = MetadataSupport {
        private: false,
        ..support()
    };

    assert!(fails_with(
        MetadataQuery::new(Some(&support()), &invalid(MetadataRoot::Shared)),
        trc::JmapEvent::InvalidArguments
    ));
    assert!(fails_with(
        MetadataQuery::new(Some(&support()), &invalid(MetadataRoot::Private)),
        trc::JmapEvent::InvalidArguments
    ));
    assert!(fails_with(
        MetadataQuery::new(None, &invalid(MetadataRoot::Shared)),
        trc::JmapEvent::UnsupportedFilter
    ));
    assert!(fails_with(
        MetadataQuery::new(Some(&no_private), &invalid(MetadataRoot::Private)),
        trc::JmapEvent::UnsupportedFilter
    ));
}

#[test]
fn scan_limit_applies_to_text_conditions_only() {
    let limited = MetadataSupport {
        query_max_scan: 2,
        ..support()
    };
    let text = [exists("a.example"), equals("a.example/k", "v")];
    let query = MetadataQuery::new(Some(&limited), &text).expect("valid filters");
    assert!(query.check_scan_limit(MetadataRoot::Shared, 2).is_ok());
    assert!(query.check_scan_limit(MetadataRoot::Shared, 3).is_err());
    assert!(query.check_scan_limit(MetadataRoot::Private, 3).is_ok());

    let presence = [exists("a.example"), exists("a.example/k")];
    let query = MetadataQuery::new(Some(&limited), &presence).expect("valid filters");
    assert!(query.check_scan_limit(MetadataRoot::Shared, 1_000).is_ok());

    let unsupported = [contains("bad name/k", "v")];
    let query = MetadataQuery::new(Some(&limited), &unsupported).expect("valid filters");
    assert!(query.check_scan_limit(MetadataRoot::Shared, 1_000).is_ok());

    let private = [filter(
        MetadataRoot::Private,
        "a.example/k",
        MetadataCondition::TextContains("v".into()),
    )];
    let query = MetadataQuery::new(Some(&limited), &private).expect("valid filters");
    assert!(query.check_scan_limit(MetadataRoot::Private, 3).is_err());
    assert!(query.check_scan_limit(MetadataRoot::Shared, 3).is_ok());
}

#[test]
fn uppercase_vendor_namespaces_match_nothing() {
    let filters = [exists("Acme.example"), contains("ACME.EXAMPLE/memo", "")];
    let query = MetadataQuery::new(Some(&support()), &filters).expect("valid filters");
    assert!(!query.has_shared());
    assert_eq!(
        evaluate(&query, &[(1, r#"{"acme.example": {"memo": "x"}}"#)], &[]),
        vec![Vec::<u32>::new(); 2]
    );
}

#[test]
fn casemap_examples() {
    let matches = |haystack: &str, needle: &str| {
        let stored = container(&format!(
            r#"{{"a.example": {{"k": {}}}}}"#,
            serde_json::to_string(haystack).expect("serializable")
        ));
        let query = MetadataQuery::new(
            Some(&support()),
            &[
                contains("a.example/k", needle),
                equals("a.example/k", needle),
            ],
        )
        .expect("valid filters");
        let mut results = vec![RoaringBitmap::new(); 2];
        let mut scratch = String::new();
        query.evaluate_container(
            MetadataRoot::Shared,
            1,
            &stored.view(),
            &mut results,
            &mut scratch,
        );
        results
            .iter()
            .map(|result| result.contains(1))
            .collect::<Vec<_>>()
    };

    for (haystack, needle, contains, equals) in [
        ("straße", "STRASSE", false, false),
        ("STRASSE", "straße", false, false),
        ("straße", "STRAẞE", false, false),
        ("STRASSE", "STRAẞE", false, false),
        ("strasse", "STRAẞE", false, false),
        ("proﬁle", "profile", false, false),
        ("proﬁle", "PROﬁLE", true, false),
        ("k", "\u{212a}", true, false),
        ("\u{212a}", "k", true, false),
        ("abc", "ＡＢＣ", true, false),
        ("ＡＢＣ", "abc", true, false),
        ("ΟΔΌΣ", "οδός", true, false),
        ("οδός", "ΟΔΌΣ", true, false),
        ("Blue", "blue", true, false),
        ("Blue", "Blue", true, true),
        ("xBluex", "Blue", true, false),
    ] {
        assert_eq!(
            matches(haystack, needle),
            [contains, equals],
            "{needle:?} in {haystack:?}"
        );
    }
}
