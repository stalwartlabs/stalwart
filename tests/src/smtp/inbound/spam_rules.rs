/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::{TestServer, TestServerBuilder};
use registry::{
    schema::{
        enums::TaskSpamFilterMaintenanceType,
        prelude::{Object, ObjectType},
        structs::{
            HttpLookup, MemoryLookupKey, MemoryLookupKeyValue, SpamDnsblServer, SpamFileExtension,
            SpamRule, SpamSettings, SpamTag, SpamTagScore, Task, TaskSpamFilterMaintenance,
            TaskStatus,
        },
    },
    types::{ObjectImpl, float::Float},
};
use serde_json::{Value, json};
use std::fs;
use store::registry::RegistryObject;

#[tokio::test(flavor = "multi_thread")]
async fn spam_rules_update() {
    let test = TestServerBuilder::new("spam_rules_update_test")
        .await
        .with_http_listener(19057)
        .await
        .build()
        .await;
    let admin = test.account("admin");
    let rules_path = test.temp_dir.path.join("spam-filter-rules.json");
    admin
        .registry_create_object(SpamSettings {
            spam_filter_rules_url: format!("file://{}", rules_path.display()).into(),
            ..Default::default()
        })
        .await;
    admin
        .registry_create_object(MemoryLookupKeyValue {
            namespace: "test-keys".into(),
            key: "conflict.org".into(),
            value: "local".into(),
            is_glob_pattern: false,
        })
        .await;
    admin.reload_settings().await;

    update_rules(&test, &release_1()).await;

    for name in ["STWT_TEST_RULE", "STWT_TEST_DISABLED"] {
        assert!(
            stored::<SpamRule>(&test, "name", name)
                .await
                .unwrap()
                .object
                .enable()
        );
    }
    assert!(
        stored::<SpamDnsblServer>(&test, "name", "STWT_TEST_DNSBL")
            .await
            .unwrap()
            .object
            .enable()
    );
    assert!(
        stored::<MemoryLookupKey>(&test, "key", "conflict.org")
            .await
            .is_none()
    );

    let disabled_rule = stored::<SpamRule>(&test, "name", "STWT_TEST_DISABLED")
        .await
        .unwrap();
    admin
        .registry_update_object(
            ObjectType::SpamRule,
            disabled_rule.id.id(),
            json!({"enable": false}),
        )
        .await;
    let local_tag = stored::<SpamTag>(&test, "tag", "TEST_TAG_LOCAL")
        .await
        .unwrap();
    admin
        .registry_update_object(
            ObjectType::SpamTag,
            local_tag.id.id(),
            json!({"score": 2.0}),
        )
        .await;
    let feed = stored::<HttpLookup>(&test, "namespace", "stwt_test_feed")
        .await
        .unwrap();
    admin
        .registry_update_object(
            ObjectType::HttpLookup,
            feed.id.id(),
            json!({"enable": false}),
        )
        .await;

    let release_2 = release_2();
    for _ in 0..2 {
        update_rules(&test, &release_2).await;

        let rule = stored::<SpamRule>(&test, "name", "STWT_TEST_RULE")
            .await
            .unwrap()
            .object;
        assert!(rule.enable());
        assert_eq!(object_json(&rule)["priority"], 400);

        let rule = stored::<SpamRule>(&test, "name", "STWT_TEST_DISABLED")
            .await
            .unwrap()
            .object;
        assert!(!rule.enable());
        assert_eq!(object_json(&rule)["priority"], 450);

        assert!(
            stored::<SpamRule>(&test, "name", "STWT_TEST_NEW")
                .await
                .is_some()
        );

        for upstream in release_2["SpamRule"].as_array().unwrap() {
            let mut upstream: SpamRule = serde_json::from_value(upstream.clone()).unwrap();
            let local = stored::<SpamRule>(
                &test,
                "name",
                object_json(&upstream)["name"].as_str().unwrap(),
            )
            .await
            .unwrap()
            .object;
            upstream.set_enable(local.enable());
            assert_eq!(local, upstream);
        }
        for upstream in release_2["SpamDnsblServer"].as_array().unwrap() {
            let upstream: SpamDnsblServer = serde_json::from_value(upstream.clone()).unwrap();
            let local = stored::<SpamDnsblServer>(
                &test,
                "name",
                object_json(&upstream)["name"].as_str().unwrap(),
            )
            .await
            .unwrap()
            .object;
            assert_eq!(local, upstream);
        }

        for (tag, score) in [("TEST_TAG", 6.5), ("TEST_TAG_LOCAL", 2.0)] {
            assert_eq!(
                stored::<SpamTag>(&test, "tag", tag).await.unwrap().object,
                SpamTag::Score(SpamTagScore {
                    tag: tag.into(),
                    score: Float::new(score),
                })
            );
        }

        let feed = stored::<HttpLookup>(&test, "namespace", "stwt_test_feed")
            .await
            .unwrap()
            .object;
        assert!(!feed.enable);
        assert_eq!(feed.max_entries, 2000);

        assert!(
            stored::<MemoryLookupKey>(&test, "key", "example.org")
                .await
                .unwrap()
                .object
                .is_glob_pattern
        );
        assert!(
            stored::<MemoryLookupKey>(&test, "key", "conflict.org")
                .await
                .is_none()
        );
        assert_eq!(
            stored::<MemoryLookupKeyValue>(&test, "key", "conflict.org")
                .await
                .unwrap()
                .object
                .value,
            "local"
        );

        assert!(
            stored::<SpamFileExtension>(&test, "extension", "tst")
                .await
                .unwrap()
                .object
                .is_bad
        );
    }
}

async fn update_rules(test: &TestServer, rules: &Value) {
    fs::write(
        test.temp_dir.path.join("spam-filter-rules.json"),
        rules.to_string(),
    )
    .unwrap();
    test.account("admin")
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::UpdateRules,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
}

async fn stored<T: ObjectImpl + From<Object>>(
    test: &TestServer,
    property: &str,
    value: &str,
) -> Option<RegistryObject<T>> {
    test.server
        .registry()
        .list::<T>()
        .await
        .unwrap()
        .into_iter()
        .find(|item| object_json(&item.object)[property] == value)
}

fn object_json<T: ObjectImpl>(object: &T) -> Value {
    serde_json::to_value(object).unwrap()
}

fn release_1() -> Value {
    json!({
        "SpamRule": [
            {
                "@type": "Any",
                "name": "STWT_TEST_RULE",
                "enable": true,
                "priority": 500,
                "condition": {"else": "false", "match": {"0": {"if": "$MISSING_ESSENTIAL_HEADERS && $SINGLE_SHORT_PART", "then": "'SHORT_PART_BAD_HEADERS'"}}}
            },
            {
                "@type": "Any",
                "name": "STWT_TEST_DISABLED",
                "enable": true,
                "priority": 500,
                "condition": {"else": "false", "match": {"0": {"if": "$MISSING_ESSENTIAL_HEADERS && $SINGLE_SHORT_PART", "then": "'SHORT_PART_BAD_HEADERS'"}}}
            }
        ],
        "SpamDnsblServer": [
            {
                "@type": "Domain",
                "name": "STWT_TEST_DNSBL",
                "enable": true,
                "tag": {"else": "false", "match": {
                    "0": {"if": "octets[3] == 1", "then": "'URIBL_BLOCKED'"},
                    "1": {"if": "octets[3] == 2", "then": "'URIBL_BLACK'"},
                    "2": {"if": "octets[3] == 4", "then": "'URIBL_GREY'"},
                    "3": {"if": "octets[3] == 8", "then": "'URIBL_RED'"}
                }},
                "zone": {"else": "value + '.multi.uribl.com'", "match": {}}
            }
        ],
        "SpamTag": [
            {"@type": "Score", "tag": "TEST_TAG", "score": 6.5},
            {"@type": "Score", "tag": "TEST_TAG_LOCAL", "score": 1.0}
        ],
        "HttpLookup": [
            {
                "namespace": "stwt_test_feed",
                "url": "http://127.0.0.1:1/feed.txt",
                "format": {"@type": "List"},
                "enable": true,
                "isGzipped": false,
                "maxSize": 1048576,
                "maxEntries": 1000,
                "maxEntrySize": 512,
                "refresh": 43200000,
                "retry": 3600000,
                "timeout": 30000
            }
        ],
        "MemoryLookupKey": [
            {"namespace": "test-keys", "key": "example.org", "isGlobPattern": false},
            {"namespace": "test-keys", "key": "conflict.org", "isGlobPattern": false}
        ],
        "SpamFileExtension": [
            {"extension": "tst", "contentTypes": {}, "isArchive": false, "isBad": false, "isNz": false}
        ]
    })
}

fn release_2() -> Value {
    json!({
        "SpamRule": [
            {
                "@type": "Any",
                "name": "STWT_TEST_RULE",
                "enable": true,
                "priority": 400,
                "condition": {"else": "false", "match": {"0": {"if": "$MISSING_ESSENTIAL_HEADERS && $SINGLE_SHORT_PART", "then": "'SHORT_PART_BAD_HEADERS'"}}}
            },
            {
                "@type": "Any",
                "name": "STWT_TEST_DISABLED",
                "enable": true,
                "priority": 450,
                "condition": {"else": "false", "match": {"0": {"if": "$MISSING_ESSENTIAL_HEADERS && $SINGLE_SHORT_PART", "then": "'SHORT_PART_BAD_HEADERS'"}}}
            },
            {
                "@type": "Any",
                "name": "STWT_TEST_NEW",
                "enable": true,
                "priority": 500,
                "condition": {"else": "false", "match": {"0": {"if": "$MISSING_ESSENTIAL_HEADERS && $SINGLE_SHORT_PART", "then": "'SHORT_PART_BAD_HEADERS'"}}}
            }
        ],
        "SpamDnsblServer": [
            {
                "@type": "Domain",
                "name": "STWT_TEST_DNSBL",
                "enable": true,
                "tag": {"else": "false", "match": {
                    "0": {"if": "octets[0] != 127", "then": "false"},
                    "1": {"if": "octets[3] == 1", "then": "'URIBL_BLOCKED'"},
                    "2": {"if": "bit_and(octets[3], 2) != 0", "then": "'URIBL_BLACK'"},
                    "3": {"if": "bit_and(octets[3], 4) != 0", "then": "'URIBL_GREY'"},
                    "4": {"if": "bit_and(octets[3], 8) != 0", "then": "'URIBL_RED'"}
                }},
                "zone": {"else": "value + '.multi.uribl.com'", "match": {}}
            }
        ],
        "SpamTag": [
            {"@type": "Score", "tag": "TEST_TAG", "score": 4.5},
            {"@type": "Score", "tag": "TEST_TAG_LOCAL", "score": 1.0}
        ],
        "HttpLookup": [
            {
                "namespace": "stwt_test_feed",
                "url": "http://127.0.0.1:1/feed.txt",
                "format": {"@type": "List"},
                "enable": true,
                "isGzipped": false,
                "maxSize": 1048576,
                "maxEntries": 2000,
                "maxEntrySize": 512,
                "refresh": 43200000,
                "retry": 3600000,
                "timeout": 30000
            }
        ],
        "MemoryLookupKey": [
            {"namespace": "test-keys", "key": "example.org", "isGlobPattern": true},
            {"namespace": "test-keys", "key": "conflict.org", "isGlobPattern": false}
        ],
        "SpamFileExtension": [
            {"extension": "tst", "contentTypes": {}, "isArchive": false, "isBad": true, "isNz": false}
        ]
    })
}
