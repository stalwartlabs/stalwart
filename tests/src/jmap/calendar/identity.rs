/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, JmapUtils};
use jmap_proto::{
    object::participant_identity::ParticipantIdentityProperty, request::method::MethodObject,
};
use serde_json::json;
use store::write::BatchBuilder;
use types::{collection::Collection, field::PrincipalField};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Participant Identity tests...");
    let account = params.account("jdoe@example.com");

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

    // Destroy identity b
    let response = account
        .jmap_destroy(
            MethodObject::ParticipantIdentity,
            ["b"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.destroyed().next(), Some("b"));
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
    assert_eq!(
        response.not_created(0).description(),
        "Calendar address not configured for this account."
    );
    assert_eq!(
        response.not_created(1).description(),
        "Calendar address not configured for this account."
    );

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

    // Cleanup
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(account.id().document_id())
        .with_collection(Collection::Principal)
        .with_document(0)
        .clear(PrincipalField::ParticipantIdentities);
    params.server.commit_batch(batch).await.unwrap();
    params.assert_is_empty().await;
}
