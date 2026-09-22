/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::calendar::event::*,
    utils::{
        account::Account,
        jmap::{IntoJmapSet, JmapUtils},
        server::TestServer,
    },
};
use calcard::jscalendar::JSCalendarProperty;
use groupware::cache::GroupwareCache;
use hyper::StatusCode;
use jmap_proto::request::method::MethodObject;
use registry::{
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::{
            self, Calendar, CertificateManagement, Credential, DkimManagement, DnsManagement,
            Domain, Jmap, PasswordCredential, Permissions, PermissionsList, Rate, Tenant,
            UserAccount,
        },
    },
    types::{duration::Duration, list::List, map::Map},
};
use serde_json::{Value, json};
use std::str::FromStr;
use types::{collection::SyncCollection, id::Id};

pub async fn test(test: &TestServer) {
    println!("Running Principal Availability tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let admin = test.account("admin@example.com");
    let john_id = john.id_string().to_string();
    let jane_id = jane.id_string().to_string();

    // Create test calendars
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Test Calendar",
                "includeInAvailability": "all"
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar1_id = response.created(0).id().to_string();

    // Create test events
    let event_1 = test_jscalendar_1().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str()].into_jmap_set(),
    );
    let event_2 = test_jscalendar_2().with_property(
        JSCalendarProperty::<Id>::CalendarIds,
        [calendar1_id.as_str()].into_jmap_set(),
    );
    let event_3 = test_jscalendar_3()
        .with_property(
            JSCalendarProperty::<Id>::CalendarIds,
            [calendar1_id.as_str()].into_jmap_set(),
        )
        .with_property(
            JSCalendarProperty::<Id>::Participants,
            json!({
              "3f5bc8c0-c722-5345-b7d9-5a899db08a30": {
                "calendarAddress": "mailto:jdoe@example.com",
                "@type": "Participant",
                "roles": {
                  "attendee": true,
                  "chair": true
                },
                "participationStatus": "accepted"
              }
            }),
        );
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [event_1, event_2, event_3],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let _event_1_id = response.created(0).id().to_string();
    let _event_2_id = response.created(1).id().to_string();
    let event_3_id = response.created(2).id().to_string();

    // Jane should not have access to John's availability
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([]));

    // Grant Jane free/busy access
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar1_id,
            json!({
                "shareWith": {
                   &jane_id : {
                     "mayReadFreeBusy": true,
                   }
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar1_id);

    // Jane should see John's availability now
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "utcStart": "2006-01-02T15:00:00Z",
        "utcEnd": "2006-01-02T16:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2006-01-02T17:00:00Z",
        "utcEnd": "2006-01-02T18:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2006-01-03T17:00:00Z",
        "utcEnd": "2006-01-03T18:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2006-01-04T15:00:00Z",
        "utcEnd": "2006-01-04T16:00:00Z",
        "busyStatus": "tentative",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2006-01-04T19:00:00Z",
        "utcEnd": "2006-01-04T20:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2006-01-05T17:00:00Z",
        "utcEnd": "2006-01-05T18:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2006-01-06T19:00:00Z",
        "utcEnd": "2006-01-06T20:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      }
    ]));

    // Update availability to none
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar1_id,
            json!({
                "includeInAvailability": "none"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar1_id);

    // Jane should not see any events now
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([]));

    // Update availability to attending
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar1_id,
            json!({
                "includeInAvailability": "attending"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar1_id);

    // Jane should only see events where John is attending
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([
      {
        "utcStart": "2006-01-04T15:00:00Z",
        "utcEnd": "2006-01-04T16:00:00Z",
        "busyStatus": "tentative",
        "event": null,
        "accountId": null
      }
    ]));

    // Update attending event to not attending
    john.jmap_update(
        MethodObject::CalendarEvent,
        [(
            &event_3_id,
            json!({
                "participants/3f5bc8c0-c722-5345-b7d9-5a899db08a30/participationStatus": "declined"
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&event_3_id);

    // Jane should not see any events now
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            },
            "0"
        ]]))
        .await;
    response.list_array().assert_is_equal(json!([]));

    // Overlapping periods are split and merged by precedence, while secret, free
    // and cancelled events are not relevant
    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [json!({
                "name": "Busy calendar",
                "shareWith": {&jane_id: {"mayReadFreeBusy": true}}
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar2_id = response.created(0).id().to_string();
    let busy_event = |title: &str, start: &str, duration: &str| {
        json!({
            "calendarIds": {&calendar2_id: true},
            "title": title,
            "start": start,
            "duration": duration,
            "timeZone": "Etc/UTC"
        })
    };
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                busy_event("Confirmed", "2007-01-01T10:00:00", "PT2H"),
                busy_event("Tentative", "2007-01-01T11:00:00", "PT2H")
                    .with_property("status", "tentative"),
                busy_event("Unanswered", "2007-01-01T12:30:00", "PT1H30M")
                    .with_property("organizerCalendarAddress", "mailto:boss@example.org")
                    .with_property(
                        "participants",
                        json!({
                            "boss": {
                                "@type": "Participant",
                                "calendarAddress": "mailto:boss@example.org",
                                "roles": {"owner": true}
                            },
                            "john": {
                                "@type": "Participant",
                                "calendarAddress": "mailto:jdoe@example.com",
                                "roles": {"attendee": true},
                                "participationStatus": "needs-action"
                            }
                        }),
                    ),
                busy_event("Private", "2007-01-02T10:00:00", "PT1H")
                    .with_property("privacy", "private"),
                busy_event("Secret", "2007-01-02T12:00:00", "PT1H")
                    .with_property("privacy", "secret"),
                busy_event("Free", "2007-01-02T13:00:00", "PT1H")
                    .with_property("freeBusyStatus", "free"),
                busy_event("Cancelled", "2007-01-02T14:00:00", "PT1H")
                    .with_property("status", "cancelled"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..7 {
        response.created(idx);
    }
    let merged_periods = json!([
      {
        "utcStart": "2007-01-01T10:00:00Z",
        "utcEnd": "2007-01-01T12:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2007-01-01T12:00:00Z",
        "utcEnd": "2007-01-01T12:30:00Z",
        "busyStatus": "tentative",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2007-01-01T12:30:00Z",
        "utcEnd": "2007-01-01T14:00:00Z",
        "busyStatus": "unavailable",
        "event": null,
        "accountId": null
      },
      {
        "utcStart": "2007-01-02T10:00:00Z",
        "utcEnd": "2007-01-02T11:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      }
    ]);
    let availability = |show_details: bool, event_properties: Value| {
        json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2007-01-01T00:00:00Z",
                "utcEnd": "2007-01-03T00:00:00Z",
                "showDetails": show_details,
                "eventProperties": event_properties
            },
            "0"
        ]])
    };
    jane.jmap_method_calls(availability(false, Value::Null))
        .await
        .list_array()
        .assert_is_equal(merged_periods.clone());

    // Without mayReadItems no details are returned
    jane.jmap_method_calls(availability(true, Value::Null))
        .await
        .list_array()
        .assert_is_equal(merged_periods.clone());

    // With mayReadItems details are returned, except for private events
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar2_id,
            json!({
                "shareWith": {
                   &jane_id : {
                     "mayReadFreeBusy": true,
                     "mayReadItems": true,
                   }
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar2_id);
    let detailed_periods = json!([
      {
        "utcStart": "2007-01-01T10:00:00Z",
        "utcEnd": "2007-01-01T12:00:00Z",
        "busyStatus": "confirmed",
        "event": {"title": "Confirmed"},
        "accountId": &john_id
      },
      {
        "utcStart": "2007-01-01T11:00:00Z",
        "utcEnd": "2007-01-01T13:00:00Z",
        "busyStatus": "tentative",
        "event": {"title": "Tentative"},
        "accountId": &john_id
      },
      {
        "utcStart": "2007-01-01T12:30:00Z",
        "utcEnd": "2007-01-01T14:00:00Z",
        "busyStatus": "unavailable",
        "event": {"title": "Unanswered"},
        "accountId": &john_id
      },
      {
        "utcStart": "2007-01-02T10:00:00Z",
        "utcEnd": "2007-01-02T11:00:00Z",
        "busyStatus": "confirmed",
        "event": null,
        "accountId": null
      }
    ]);
    jane.jmap_method_calls(availability(true, json!(["title"])))
        .await
        .list_array()
        .assert_is_equal(detailed_periods.clone());
    let response = jane
        .jmap_method_calls(availability(true, Value::Null))
        .await;
    let first = &response.list_array()[0];
    assert_eq!(first["event"]["title"], json!("Confirmed"));
    assert!(first["event"]["id"].is_string(), "{first:?}");

    // Details are fetched in batches of maxObjectsInGet
    admin
        .registry_update_setting(
            Jmap {
                get_max_results: 2,
                ..Default::default()
            },
            &[Property::GetMaxResults],
        )
        .await;
    admin.reload_settings().await;
    let response = jane
        .jmap_method_calls(availability(true, json!(["title"])))
        .await;
    admin
        .registry_update_setting(
            Jmap {
                get_max_results: 100_000,
                ..Default::default()
            },
            &[Property::GetMaxResults],
        )
        .await;
    admin.reload_settings().await;
    response.list_array().assert_is_equal(detailed_periods);

    // Details require the CalendarEvent/get permission
    let restricted = admin
        .create_user_account(
            "restricted@example.com",
            "restricted + extra safety",
            "Restricted User",
            &[],
            vec![Permission::UnlimitedRequests],
        )
        .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            restricted.id(),
            json!({
                Property::Permissions: Permissions::Merge(PermissionsList {
                    disabled_permissions: Map::new(vec![Permission::JmapCalendarEventGet]),
                    enabled_permissions: Map::new(vec![Permission::UnlimitedRequests]),
                })
            }),
        )
        .await;
    john.jmap_update(
        MethodObject::Calendar,
        [(
            &calendar2_id,
            json!({
                format!("shareWith/{}", restricted.id_string()): {
                    "mayReadFreeBusy": true,
                    "mayReadItems": true
                }
            }),
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&calendar2_id);
    assert_eq!(
        restricted
            .jmap_method_calls(json!([[
                "CalendarEvent/get",
                {"accountId": &john_id, "ids": null},
                "0"
            ]]))
            .await
            .method_response()["type"],
        json!("forbidden")
    );
    restricted
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": restricted.id_string(),
                "id": &john_id,
                "utcStart": "2007-01-01T00:00:00Z",
                "utcEnd": "2007-01-03T00:00:00Z",
                "showDetails": true,
                "eventProperties": ["title"]
            },
            "0"
        ]]))
        .await
        .list_array()
        .assert_is_equal(merged_periods.clone());
    admin
        .registry_destroy(ObjectType::Account, [restricted.id()])
        .await;

    // Principals outside the tenant or unknown ids are rejected
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": "zzzzzzz",
                "utcStart": "2007-01-01T00:00:00Z",
                "utcEnd": "2007-01-03T00:00:00Z"
            },
            "0"
        ]]))
        .await;
    assert_eq!(response.method_response()["type"], json!("notFound"));
    let tenant_id = admin
        .registry_create_object(Tenant {
            name: "Availability tenant".to_string(),
            ..Default::default()
        })
        .await;
    let domain_id = admin
        .registry_create_object(Domain {
            name: "availability-tenant.org".to_string(),
            is_enabled: true,
            member_tenant_id: tenant_id.into(),
            certificate_management: CertificateManagement::Manual,
            dns_management: DnsManagement::Manual,
            dkim_management: DkimManagement::Manual,
            ..Default::default()
        })
        .await;
    let tenant_user = Account::new(
        "tenant-user@availability-tenant.org",
        "tenant user + extra safety",
        &[],
        "Tenant User",
        admin
            .registry_create_object(structs::Account::User(UserAccount {
                name: "tenant-user".to_string(),
                domain_id,
                member_tenant_id: tenant_id.into(),
                credentials: List::from_iter([Credential::Password(PasswordCredential {
                    secret: "tenant user + extra safety".to_string(),
                    ..Default::default()
                })]),
                ..Default::default()
            }))
            .await,
    );
    let response = tenant_user
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": tenant_user.id_string(),
                "id": &john_id,
                "utcStart": "2007-01-01T00:00:00Z",
                "utcEnd": "2007-01-03T00:00:00Z"
            },
            "0"
        ]]))
        .await;
    assert_eq!(response.method_response()["type"], json!("notFound"));
    let response = tenant_user
        .jmap_get(
            MethodObject::Principal,
            ["id"],
            [&john_id, tenant_user.id_string()],
        )
        .await;
    assert_eq!(response.list().len(), 1, "{response:?}");
    assert_eq!(response.list()[0]["id"], json!(tenant_user.id_string()));
    assert_eq!(response.not_found().collect::<Vec<_>>(), [john_id.as_str()]);
    admin
        .registry_destroy(ObjectType::Account, [tenant_user.id()])
        .await;
    admin
        .registry_destroy(ObjectType::Domain, [domain_id])
        .await;
    admin
        .registry_destroy(ObjectType::Tenant, [tenant_id])
        .await;

    // The accountId must be an account the caller can access
    for (account_id, error) in [
        (Some(john_id.as_str()), None),
        (Some(admin.id_string()), Some("accountNotFound")),
        (Some("zzzzzzz"), Some("accountNotFound")),
        (None, Some("invalidArguments")),
    ] {
        let mut arguments = json!({
            "id": &john_id,
            "utcStart": "2007-01-01T00:00:00Z",
            "utcEnd": "2007-01-03T00:00:00Z"
        });
        if let Some(account_id) = account_id {
            arguments = arguments.with_property("accountId", account_id);
        }
        let response = jane
            .jmap_method_calls(json!([["Principal/getAvailability", arguments, "0"]]))
            .await;
        assert_eq!(
            response
                .method_response()
                .get("type")
                .and_then(Value::as_str),
            error,
            "{account_id:?}"
        );
    }

    // Time spans above maxAvailabilityDuration are rejected
    let response = jane
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": &jane_id,
                "id": &john_id,
                "utcStart": "2007-01-01T00:00:00Z",
                "utcEnd": "2009-01-01T00:00:00Z"
            },
            "0"
        ]]))
        .await;
    assert_eq!(response.method_response()["type"], json!("tooLarge"));

    // Missing, invalid or empty time ranges are invalid arguments
    for arguments in [
        json!({"accountId": &jane_id, "id": &john_id, "utcEnd": "2007-01-03T00:00:00Z"}),
        json!({"accountId": &jane_id, "id": &john_id, "utcStart": "2007-01-01T00:00:00Z"}),
        json!({
            "accountId": &jane_id,
            "id": &john_id,
            "utcStart": "2007-13-45T99:99:99Z",
            "utcEnd": "2007-01-03T00:00:00Z"
        }),
        json!({
            "accountId": &jane_id,
            "id": &john_id,
            "utcStart": "2007-01-01T00:00:00Z",
            "utcEnd": "2007-01-01T00:00:00Z"
        }),
        json!({
            "accountId": &jane_id,
            "id": &john_id,
            "utcStart": "2007-01-03T00:00:00Z",
            "utcEnd": "2007-01-01T00:00:00Z"
        }),
    ] {
        let response = jane
            .jmap_method_calls(json!([["Principal/getAvailability", &arguments, "0"]]))
            .await;
        assert_eq!(
            response.method_response()["type"],
            json!("invalidArguments"),
            "{arguments}"
        );
    }

    // Exceeding the expansion limit is reported as tooLarge
    admin
        .registry_update_setting(
            Calendar {
                max_recurrence_expansions: 2,
                ..Default::default()
            },
            &[Property::MaxRecurrenceExpansions],
        )
        .await;
    admin.reload_settings().await;
    let response = jane
        .jmap_method_calls(availability(false, Value::Null))
        .await;
    admin
        .registry_update_setting(Calendar::default(), &[Property::MaxRecurrenceExpansions])
        .await;
    admin.reload_settings().await;
    assert_eq!(response.method_response()["type"], json!("tooLarge"));

    // Principal/getAvailability is part of the principals:availability capability
    let request = availability(false, Value::Null);
    jane.jmap_request(
        &[
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:principals:availability",
        ],
        request.clone(),
    )
    .await
    .list_array()
    .assert_is_equal(merged_periods);
    assert_eq!(
        jane.jmap_request(
            &[
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:principals"
            ],
            request,
        )
        .await
        .method_response()["type"],
        json!("unknownMethod")
    );

    // Availability requests are rate limited, unless the caller has UnlimitedRequests
    admin
        .registry_update_setting(
            Calendar {
                availability_rate_limit: Some(Rate {
                    count: 2,
                    period: Duration::from_millis(86_400_000),
                }),
                ..Default::default()
            },
            &[Property::AvailabilityRateLimit],
        )
        .await;
    admin.reload_settings().await;
    let limited = admin
        .create_user_account(
            "limited@example.com",
            "limited + extra safety",
            "Limited User",
            &[],
            vec![],
        )
        .await;
    let availability_request = json!([[
        "Principal/getAvailability",
        {
            "accountId": limited.id_string(),
            "id": &john_id,
            "utcStart": "2007-01-01T00:00:00Z",
            "utcEnd": "2007-01-03T00:00:00Z"
        },
        "0"
    ]]);
    for _ in 0..2 {
        assert_eq!(
            limited
                .jmap_method_calls(availability_request.clone())
                .await
                .method_response()
                .get("type"),
            None
        );
    }
    let mut is_rate_limited = false;
    for _ in 0..3 {
        if limited
            .jmap_method_calls(availability_request.clone())
            .await
            .method_response()["type"]
            == json!("rateLimit")
        {
            is_rate_limited = true;
            break;
        }
    }
    assert!(
        is_rate_limited,
        "availability requests were not rate limited"
    );
    for _ in 0..3 {
        assert_eq!(
            jane.jmap_method_calls(availability(false, Value::Null))
                .await
                .method_response()
                .get("type"),
            None
        );
    }
    admin
        .registry_update_setting(Calendar::default(), &[Property::AvailabilityRateLimit])
        .await;
    admin.reload_settings().await;
    admin
        .registry_destroy(ObjectType::Account, [limited.id()])
        .await;

    relevance(test).await;
    floating_time(test).await;
    multiple_calendars(test).await;
    group_calendars(test).await;
    sharee_preferences(test).await;

    // Cleanup
    john.destroy_all_calendars().await;
    test.assert_is_empty().await;
}

async fn relevance(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string();
    let jane_id = jane.id_string();

    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Relevance",
                    "shareWith": {jane_id: {"mayReadFreeBusy": true, "mayReadItems": true}}
                }),
                json!({
                    "name": "Unsubscribed",
                    "isSubscribed": false,
                    "shareWith": {jane_id: {"mayReadFreeBusy": true}}
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let calendar_id = response.created(0).id().to_string();
    let unsubscribed_id = response.created(1).id().to_string();
    let daily = json!({"@type": "RecurrenceRule", "frequency": "daily", "count": 3});
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                utc_event(&calendar_id, "Free series", "2008-02-04T09:00:00", "PT1H")
                    .with_property("recurrenceRule", daily.clone())
                    .with_property("freeBusyStatus", "free")
                    .with_property(
                        "recurrenceOverrides",
                        json!({"2008-02-05T09:00:00": {"freeBusyStatus": "busy"}}),
                    ),
                utc_event(
                    &calendar_id,
                    "Cancelled series",
                    "2008-02-04T12:00:00",
                    "PT1H",
                )
                .with_property("recurrenceRule", daily)
                .with_property("status", "cancelled")
                .with_property(
                    "recurrenceOverrides",
                    json!({"2008-02-06T12:00:00": {"status": "confirmed"}}),
                ),
                utc_event(&calendar_id, "Long", "2008-02-06T15:00:00", "PT3H"),
                utc_event(
                    &unsubscribed_id,
                    "Unsubscribed",
                    "2008-02-05T15:00:00",
                    "PT1H",
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..4 {
        response.created(idx);
    }

    let calendar_path = calendar_dav_path(test, john, &calendar_id).await;
    for (name, components) in [
        (
            "task",
            concat!(
                "BEGIN:VTODO\r\n",
                "UID:availability-task\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "DTSTART:20080204T150000Z\r\n",
                "DUE:20080205T150000Z\r\n",
                "SUMMARY:Task\r\n",
                "END:VTODO\r\n",
            ),
        ),
        (
            "reversed",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:availability-reversed\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "DTSTART:20080206T170000Z\r\n",
                "DTEND:20080206T160000Z\r\n",
                "SUMMARY:Reversed\r\n",
                "END:VEVENT\r\n",
            ),
        ),
        (
            "mixed-secret",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:availability-mixed-secret\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "DTSTART:20080207T090000Z\r\n",
                "DURATION:PT1H\r\n",
                "RRULE:FREQ=DAILY;COUNT=2\r\n",
                "CLASS:PUBLIC\r\n",
                "SUMMARY:Mixed secret\r\n",
                "END:VEVENT\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:availability-mixed-secret\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "RECURRENCE-ID:20080208T090000Z\r\n",
                "DTSTART:20080208T100000Z\r\n",
                "DURATION:PT1H\r\n",
                "CLASS:CONFIDENTIAL\r\n",
                "SUMMARY:Mixed secret\r\n",
                "END:VEVENT\r\n",
            ),
        ),
        (
            "mixed-private",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:availability-mixed-private\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "DTSTART:20080211T090000Z\r\n",
                "DURATION:PT1H\r\n",
                "RRULE:FREQ=DAILY;COUNT=2\r\n",
                "CLASS:PUBLIC\r\n",
                "SUMMARY:Mixed private\r\n",
                "END:VEVENT\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:availability-mixed-private\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "RECURRENCE-ID:20080212T090000Z\r\n",
                "DTSTART:20080212T090000Z\r\n",
                "DURATION:PT1H\r\n",
                "CLASS:PRIVATE\r\n",
                "SUMMARY:Mixed private\r\n",
                "END:VEVENT\r\n",
            ),
        ),
        (
            "pre-1900",
            concat!(
                "BEGIN:VEVENT\r\n",
                "UID:availability-pre-1900\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "DTSTART:18991231T100000Z\r\n",
                "DURATION:PT1H\r\n",
                "RRULE:FREQ=DAILY;COUNT=2\r\n",
                "SUMMARY:Old series\r\n",
                "END:VEVENT\r\n",
                "BEGIN:VEVENT\r\n",
                "UID:availability-pre-1900\r\n",
                "DTSTAMP:20080101T000000Z\r\n",
                "RECURRENCE-ID:18991231T100000Z\r\n",
                "DTSTART:20100301T100000Z\r\n",
                "DURATION:PT1H\r\n",
                "SUMMARY:Moved\r\n",
                "END:VEVENT\r\n",
            ),
        ),
    ] {
        john.webdav_client()
            .request(
                "PUT",
                &format!("{calendar_path}{name}.ics"),
                format!(
                    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Stalwart//Test//EN\r\n{components}END:VCALENDAR\r\n"
                ),
            )
            .await
            .with_status(StatusCode::CREATED);
    }

    // Busy overrides of free or cancelled series count, while tasks, secret
    // occurrences, unsubscribed calendars and reversed intervals do not
    busy_periods(
        jane,
        john_id,
        "2008-02-04T00:00:00Z",
        "2008-02-10T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([
        busy("2008-02-05T09:00:00Z", "2008-02-05T10:00:00Z", "confirmed"),
        busy("2008-02-06T12:00:00Z", "2008-02-06T13:00:00Z", "confirmed"),
        busy("2008-02-06T15:00:00Z", "2008-02-06T18:00:00Z", "confirmed"),
    ]));

    // Details of recurring events are returned for the occurrence
    jane.jmap_method_calls(json!([[
        "Principal/getAvailability",
        {
            "accountId": jane_id,
            "id": john_id,
            "utcStart": "2008-02-05T00:00:00Z",
            "utcEnd": "2008-02-05T12:00:00Z",
            "showDetails": true,
            "eventProperties": ["title", "recurrenceId"]
        },
        "0"
    ]]))
    .await
    .list_array()
    .assert_is_equal(json!([{
        "utcStart": "2008-02-05T09:00:00Z",
        "utcEnd": "2008-02-05T10:00:00Z",
        "busyStatus": "confirmed",
        "event": {"title": "Free series", "recurrenceId": "2008-02-05T09:00:00"},
        "accountId": john_id
    }]));

    // Events with a private occurrence return no details for any occurrence
    jane.jmap_method_calls(json!([[
        "Principal/getAvailability",
        {
            "accountId": jane_id,
            "id": john_id,
            "utcStart": "2008-02-11T00:00:00Z",
            "utcEnd": "2008-02-13T00:00:00Z",
            "showDetails": true,
            "eventProperties": ["title"]
        },
        "0"
    ]]))
    .await
    .list_array()
    .assert_is_equal(json!([
        busy("2008-02-11T09:00:00Z", "2008-02-11T10:00:00Z", "confirmed"),
        busy("2008-02-12T09:00:00Z", "2008-02-12T10:00:00Z", "confirmed"),
    ]));

    // Occurrences whose recurrence id predates 1900 still count
    jane.jmap_method_calls(json!([[
        "Principal/getAvailability",
        {
            "accountId": jane_id,
            "id": john_id,
            "utcStart": "2010-03-01T00:00:00Z",
            "utcEnd": "2010-03-02T00:00:00Z",
            "showDetails": true,
            "eventProperties": ["title"]
        },
        "0"
    ]]))
    .await
    .list_array()
    .assert_is_equal(json!([busy(
        "2010-03-01T10:00:00Z",
        "2010-03-01T11:00:00Z",
        "confirmed"
    )]));
}

async fn floating_time(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string();
    let jane_id = jane.id_string();

    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Pacific",
                    "timeZone": "America/Los_Angeles",
                    "shareWith": {jane_id: {"mayReadFreeBusy": true}}
                }),
                json!({
                    "name": "Tokyo",
                    "timeZone": "Asia/Tokyo",
                    "shareWith": {jane_id: {"mayReadFreeBusy": true}}
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let pacific_id = response.created(0).id().to_string();
    let tokyo_id = response.created(1).id().to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                json!({
                    "calendarIds": {&pacific_id: true},
                    "title": "All day",
                    "start": "2026-03-10T00:00:00",
                    "duration": "P1D",
                    "showWithoutTime": true
                }),
                json!({
                    "calendarIds": {&pacific_id: true},
                    "title": "Floating west",
                    "start": "2026-03-12T20:00:00",
                    "duration": "PT1H"
                }),
                json!({
                    "calendarIds": {&tokyo_id: true},
                    "title": "Floating east",
                    "start": "2026-03-16T08:00:00",
                    "duration": "PT1H"
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..3 {
        response.created(idx);
    }

    // Events without a time zone are resolved in the calendar time zone
    busy_periods(
        jane,
        john_id,
        "2026-03-11T01:00:00Z",
        "2026-03-11T06:00:00Z",
    )
    .await
    .assert_is_equal(json!([busy(
        "2026-03-10T07:00:00Z",
        "2026-03-11T07:00:00Z",
        "confirmed"
    )]));
    busy_periods(
        jane,
        john_id,
        "2026-03-13T01:00:00Z",
        "2026-03-13T06:00:00Z",
    )
    .await
    .assert_is_equal(json!([busy(
        "2026-03-13T03:00:00Z",
        "2026-03-13T04:00:00Z",
        "confirmed"
    )]));
    busy_periods(
        jane,
        john_id,
        "2026-03-15T22:00:00Z",
        "2026-03-16T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([busy(
        "2026-03-15T23:00:00Z",
        "2026-03-16T00:00:00Z",
        "confirmed"
    )]));
}

async fn multiple_calendars(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let john_id = john.id_string();
    let jane_id = jane.id_string();

    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Included",
                    "shareWith": {jane_id: {"mayReadFreeBusy": true}}
                }),
                json!({
                    "name": "Excluded",
                    "includeInAvailability": "none",
                    "shareWith": {jane_id: {"mayReadFreeBusy": true}}
                }),
                json!({"name": "Not shared"}),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let included_id = response.created(0).id().to_string();
    let excluded_id = response.created(1).id().to_string();
    let not_shared_id = response.created(2).id().to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                utc_event(&included_id, "Included", "2011-05-02T09:00:00", "PT1H").with_property(
                    "calendarIds",
                    json!({&included_id: true, &excluded_id: true}),
                ),
                utc_event(&excluded_id, "Excluded", "2011-05-02T11:00:00", "PT1H").with_property(
                    "calendarIds",
                    json!({&excluded_id: true, &not_shared_id: true}),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    for idx in 0..2 {
        response.created(idx);
    }

    // An event counts when any single calendar meets every condition
    busy_periods(
        jane,
        john_id,
        "2011-05-02T00:00:00Z",
        "2011-05-03T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([busy(
        "2011-05-02T09:00:00Z",
        "2011-05-02T10:00:00Z",
        "confirmed"
    )]));
}

async fn group_calendars(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let admin = test.account("admin@example.com");
    let sales = test.account("sales@example.com");
    let john_id = john.id_string();
    let jane_id = jane.id_string();
    let sales_id = sales.id_string();

    admin
        .registry_update_object(
            ObjectType::Account,
            john.id(),
            json!({"memberGroupIds": {sales.id(): true}}),
        )
        .await;
    let calendar_id = john
        .jmap_create_account(
            sales,
            MethodObject::Calendar,
            [json!({
                "name": "Sales",
                "shareWith": {jane_id: {"mayReadFreeBusy": true}}
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .created(0)
        .id()
        .to_string();
    john.jmap_create_account(
        sales,
        MethodObject::CalendarEvent,
        [utc_event(
            &calendar_id,
            "Sales meeting",
            "2012-06-04T09:00:00",
            "PT1H",
        )],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(0);

    // Calendars in group accounts default to includeInAvailability all for members
    busy_periods(
        jane,
        john_id,
        "2012-06-04T00:00:00Z",
        "2012-06-05T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([busy(
        "2012-06-04T09:00:00Z",
        "2012-06-04T10:00:00Z",
        "confirmed"
    )]));

    john.jmap_method_calls(json!([
        [
            "Calendar/get",
            {"accountId": sales_id, "ids": null, "properties": ["id"]},
            "R1"
        ],
        [
            "Calendar/set",
            {
                "accountId": sales_id,
                "#destroy": {"resultOf": "R1", "name": "Calendar/get", "path": "/list/*/id"},
                "onDestroyRemoveEvents": true
            },
            "R2"
        ]
    ]))
    .await;
    admin
        .registry_update_object(
            ObjectType::Account,
            john.id(),
            json!({"memberGroupIds": {sales.id(): false}}),
        )
        .await;
}

async fn sharee_preferences(test: &TestServer) {
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let jane_id = jane.id_string();
    let bill_id = bill.id_string();

    let response = john
        .jmap_create(
            MethodObject::Calendar,
            [
                json!({
                    "name": "Team",
                    "shareWith": {
                        bill_id: {"mayReadItems": true, "mayUpdatePrivate": true},
                        jane_id: {"mayReadFreeBusy": true}
                    }
                }),
                json!({
                    "name": "Side",
                    "shareWith": {
                        bill_id: {"mayReadItems": true},
                        jane_id: {"mayReadFreeBusy": true}
                    }
                }),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let team_id = response.created(0).id().to_string();
    let side_id = response.created(1).id().to_string();
    let response = john
        .jmap_create(
            MethodObject::CalendarEvent,
            [
                utc_event(&team_id, "Offsite", "2009-03-02T10:00:00", "PT1H"),
                utc_event(&team_id, "Owner free", "2009-03-02T12:00:00", "PT1H")
                    .with_property("freeBusyStatus", "free"),
                utc_event(&team_id, "Standup", "2009-03-03T09:00:00", "PT30M").with_property(
                    "recurrenceRule",
                    json!({"@type": "RecurrenceRule", "frequency": "daily", "count": 3}),
                ),
                utc_event(&side_id, "Side", "2009-03-02T15:00:00", "PT1H"),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let offsite_id = response.created(0).id().to_string();
    response.created(1);
    let standup_id = response.created(2).id().to_string();
    response.created(3);
    let response = bill
        .jmap_update_account(
            john,
            MethodObject::Calendar,
            [&team_id, &side_id].map(|calendar_id| {
                (
                    calendar_id,
                    json!({"isSubscribed": true, "includeInAvailability": "all"}),
                )
            }),
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.updated(&team_id);
    response.updated(&side_id);

    // Sharees are busy by default, whatever the owner's freeBusyStatus is
    busy_periods(
        jane,
        bill_id,
        "2009-03-02T00:00:00Z",
        "2009-03-06T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([
        busy("2009-03-02T10:00:00Z", "2009-03-02T11:00:00Z", "confirmed"),
        busy("2009-03-02T12:00:00Z", "2009-03-02T13:00:00Z", "confirmed"),
        busy("2009-03-02T15:00:00Z", "2009-03-02T16:00:00Z", "confirmed"),
        busy("2009-03-03T09:00:00Z", "2009-03-03T09:30:00Z", "confirmed"),
        busy("2009-03-04T09:00:00Z", "2009-03-04T09:30:00Z", "confirmed"),
        busy("2009-03-05T09:00:00Z", "2009-03-05T09:30:00Z", "confirmed"),
    ]));

    // Per-user freeBusyStatus of the sharee applies to the event and its occurrences
    let response = bill
        .jmap_update_account(
            john,
            MethodObject::CalendarEvent,
            [
                (&offsite_id, json!({"freeBusyStatus": "free"})),
                (
                    &standup_id,
                    json!({
                        "freeBusyStatus": "free",
                        "recurrenceOverrides": {
                            "2009-03-04T09:00:00": {"freeBusyStatus": "busy"}
                        }
                    }),
                ),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.updated(&offsite_id);
    response.updated(&standup_id);
    busy_periods(
        jane,
        bill_id,
        "2009-03-02T00:00:00Z",
        "2009-03-06T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([
        busy("2009-03-02T12:00:00Z", "2009-03-02T13:00:00Z", "confirmed"),
        busy("2009-03-02T15:00:00Z", "2009-03-02T16:00:00Z", "confirmed"),
        busy("2009-03-04T09:00:00Z", "2009-03-04T09:30:00Z", "confirmed"),
    ]));

    // Revoked calendars stop counting even if the sharee preferences remain
    john.jmap_update(
        MethodObject::Calendar,
        [(&side_id, json!({format!("shareWith/{bill_id}"): null}))],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .updated(&side_id);
    busy_periods(
        jane,
        bill_id,
        "2009-03-02T00:00:00Z",
        "2009-03-06T00:00:00Z",
    )
    .await
    .assert_is_equal(json!([
        busy("2009-03-02T12:00:00Z", "2009-03-02T13:00:00Z", "confirmed"),
        busy("2009-03-04T09:00:00Z", "2009-03-04T09:30:00Z", "confirmed"),
    ]));

    bill.destroy_all_calendars().await;
}

fn utc_event(calendar_id: &str, title: &str, start: &str, duration: &str) -> Value {
    json!({
        "calendarIds": {calendar_id: true},
        "title": title,
        "start": start,
        "duration": duration,
        "timeZone": "Etc/UTC"
    })
}

fn busy(utc_start: &str, utc_end: &str, busy_status: &str) -> Value {
    json!({
        "utcStart": utc_start,
        "utcEnd": utc_end,
        "busyStatus": busy_status,
        "event": null,
        "accountId": null
    })
}

async fn busy_periods(
    caller: &Account,
    principal_id: &str,
    utc_start: &str,
    utc_end: &str,
) -> Value {
    caller
        .jmap_method_calls(json!([[
            "Principal/getAvailability",
            {
                "accountId": caller.id_string(),
                "id": principal_id,
                "utcStart": utc_start,
                "utcEnd": utc_end
            },
            "0"
        ]]))
        .await
        .list_array()
        .clone()
}

async fn calendar_dav_path(test: &TestServer, account: &Account, calendar_id: &str) -> String {
    let account_id = account.id().document_id();
    let resources = test
        .server
        .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
        .await
        .unwrap();
    let path = resources
        .container_resource_path_by_id(Id::from_str(calendar_id).unwrap().document_id())
        .unwrap();
    format!("{}{}/", resources.base_path, path.path())
}
