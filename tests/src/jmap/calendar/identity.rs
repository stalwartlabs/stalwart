/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    jmap::{ChangeType, JmapUtils},
    server::TestServer,
};
use jmap_proto::{
    object::participant_identity::ParticipantIdentityProperty, request::method::MethodObject,
};
use serde_json::json;
use store::write::BatchBuilder;
use types::{collection::Collection, field::PrincipalField};

pub async fn test(test: &TestServer) {
    println!("Running Participant Identity tests...");
    let account = test.account("jdoe@example.com");

    // Obtain all identities
    let response = account
        .jmap_get(
            MethodObject::ParticipantIdentity,
            [
                ParticipantIdentityProperty::Id,
                ParticipantIdentityProperty::Name,
                ParticipantIdentityProperty::CalendarAddress,
                ParticipantIdentityProperty::IsDefault,
            ],
            Vec::<&str>::new(),
        )
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "id": "a",
        "name": "John Doe",
        "calendarAddress": "mailto:jdoe@example.com",
        "isDefault": true
      },
      {
        "id": "b",
        "name": "John Doe",
        "calendarAddress": "mailto:john.doe@example.com",
        "isDefault": false
      }
    ]));

    let initial_state = response.state().to_string();

    // Destroy identity b
    let response = account
        .jmap_destroy(
            MethodObject::ParticipantIdentity,
            ["b"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.destroyed().next(), Some("b"));

    let destroyed_state = response.new_state().to_string();
    assert_ne!(destroyed_state, initial_state);
    let changes = account
        .jmap_changes(MethodObject::ParticipantIdentity, &initial_state)
        .await;
    assert_eq!(changes.new_state(), destroyed_state);
    assert_eq!(
        changes.changes().collect::<Vec<_>>(),
        [ChangeType::Destroyed("b")]
    );

    // A stale state is rejected
    let stale = account
        .jmap_method_call(
            "ParticipantIdentity/set",
            json!({
                "accountId": account.id_string(),
                "ifInState": &initial_state,
                "destroy": ["a"]
            }),
        )
        .await;
    assert_eq!(
        stale.method_response()["type"],
        json!("stateMismatch"),
        "{stale:?}"
    );

    let response = account
        .jmap_get(
            MethodObject::ParticipantIdentity,
            [
                ParticipantIdentityProperty::Id,
                ParticipantIdentityProperty::Name,
                ParticipantIdentityProperty::CalendarAddress,
                ParticipantIdentityProperty::IsDefault,
            ],
            Vec::<&str>::new(),
        )
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "id": "a",
        "name": "John Doe",
        "calendarAddress": "mailto:jdoe@example.com",
        "isDefault": true
      }
    ]));

    // Creating a new identity with an unauthorized calendar address should fail
    let response = account
        .jmap_create(
            MethodObject::ParticipantIdentity,
            [
                json!({
                    "name": "Work",
                    "calendarAddress": "mailto:work@example.com"
                }),
                json!({
                    "name": "Work",
                    "calendarAddress": "work@example.com"
                }),
            ],
            [("onSuccessSetIsDefault", "#i0")],
        )
        .await;
    for idx in 0..2 {
        assert_eq!(response.not_created(idx).typ(), "forbidden");
        assert_eq!(
            response.not_created(idx).description(),
            "Calendar address not configured for this account."
        );
    }

    // Create a new identity and set it as default
    let response = account
        .jmap_create(
            MethodObject::ParticipantIdentity,
            [json!({
                "name": "Johnny B Goode",
                "calendarAddress": "mailto:john.doe@example.com"
            })],
            [("onSuccessSetIsDefault", "#i0")],
        )
        .await;
    response.created(0);
    let mut changes = account
        .jmap_changes(MethodObject::ParticipantIdentity, &destroyed_state)
        .await
        .changes()
        .map(|change| format!("{change:?}"))
        .collect::<Vec<_>>();
    changes.sort();
    assert_eq!(changes, ["Created(\"b\")", "Updated(\"a\")"]);
    let response = account
        .jmap_get(
            MethodObject::ParticipantIdentity,
            [
                ParticipantIdentityProperty::Id,
                ParticipantIdentityProperty::Name,
                ParticipantIdentityProperty::CalendarAddress,
                ParticipantIdentityProperty::IsDefault,
            ],
            Vec::<&str>::new(),
        )
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "id": "a",
        "name": "John Doe",
        "calendarAddress": "mailto:jdoe@example.com",
        "isDefault": false
      },
      {
        "id": "b",
        "name": "Johnny B Goode",
        "calendarAddress": "mailto:john.doe@example.com",
        "isDefault": true
      }
    ]));
    let changes_since = async |since: &str, max_changes: Option<u64>| {
        account
            .jmap_method_call(
                "ParticipantIdentity/changes",
                json!({
                    "accountId": account.id_string(),
                    "sinceState": since,
                    "maxChanges": max_changes
                }),
            )
            .await
            .method_response()
            .clone()
    };
    let rename = async |id: &str, name: &str| {
        account
            .jmap_update(
                MethodObject::ParticipantIdentity,
                [(id, json!({"name": name}))],
                Vec::<(&str, &str)>::new(),
            )
            .await
            .new_state()
            .to_string()
    };
    let initial_state = response.state().to_string();

    // maxChanges must be positive and never exceeded
    assert_eq!(
        changes_since(&initial_state, Some(0)).await["type"],
        json!("invalidArguments")
    );
    rename("a", "John A").await;
    let renamed_state = rename("b", "John B").await;
    let changes = changes_since(&initial_state, Some(1)).await;
    assert_eq!(changes["updated"], json!(["a"]), "{changes}");
    assert_eq!(changes["hasMoreChanges"], json!(true), "{changes}");
    let changes = changes_since(changes["newState"].as_str().unwrap(), Some(1)).await;
    assert_eq!(changes["updated"], json!(["b"]), "{changes}");
    assert_eq!(changes["hasMoreChanges"], json!(false), "{changes}");
    assert_eq!(changes["newState"], json!(&renamed_state), "{changes}");

    // A single change that cannot fit into maxChanges cannot be calculated
    account
        .jmap_destroy(
            MethodObject::ParticipantIdentity,
            ["a", "b"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(
        changes_since(&renamed_state, Some(1)).await["type"],
        json!("cannotCalculateChanges")
    );
    let changes = changes_since(&renamed_state, None).await;
    let mut destroyed = changes["destroyed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|id| id.as_str())
        .collect::<Vec<_>>();
    destroyed.sort_unstable();
    assert_eq!(destroyed, ["a", "b"], "{changes}");

    // States older than the retained changes cannot be calculated
    let response = account
        .jmap_create(
            MethodObject::ParticipantIdentity,
            [json!({"calendarAddress": "mailto:jdoe@example.com"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let identity_id = response.created(0).id().to_string();
    let trimmed_state = response.new_state().to_string();
    for idx in 0..=16 {
        rename(&identity_id, &format!("Name {idx}")).await;
    }
    assert_eq!(
        changes_since(&trimmed_state, None).await["type"],
        json!("cannotCalculateChanges")
    );

    // Cleanup
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account.id().document_id())
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear(PrincipalField::ParticipantIdentities);
    test.server.commit_batch(batch).await.unwrap();
    test.assert_is_empty().await;
}
