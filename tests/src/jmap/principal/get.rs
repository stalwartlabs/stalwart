/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{object::principal::PrincipalProperty, request::method::MethodObject};
use registry::schema::{
    prelude::{ObjectType, Property},
    structs::Sharing,
};
use serde_json::json;

use crate::utils::{jmap::JmapUtils, server::TestServer};

pub async fn test(test: &TestServer) {
    println!("Running Principal get/query tests...");
    let john = test.account("jdoe@example.com");
    let jane = test.account("jane.smith@example.com");
    let bill = test.account("bill@example.com");
    let sales = test.account("sales@example.com");

    let john_id = john.id_string();
    let jane_id = jane.id_string();
    let bill_id = bill.id_string();
    let sales_id = sales.id_string();

    // Validate session object capabilities
    let response = john.jmap_session_object().await.into_inner();
    let session_accounts = response["accounts"].clone();
    let principal_accounts = |id: &str| {
        session_accounts
            .get(id)
            .map_or(serde_json::Value::Null, |account| json!({ id: account }))
    };
    let application_server_key =
        response["capabilities"]["urn:ietf:params:jmap:webpush-vapid"]["applicationServerKey"]
            .clone();
    let metadata_info = json!({
        "namespaces": [],
        "supportsVendorNamespaces": true,
        "supportsPrivate": true,
        "maxDepth": 8
    });
    response.assert_is_equal(json!({
      "capabilities": {
        "urn:ietf:params:jmap:core": {
          "maxSizeUpload": 50000000,
          "maxConcurrentUpload": 4,
          "maxSizeRequest": 10000000,
          "maxConcurrentRequests": 4,
          "maxCallsInRequest": 16,
          "maxObjectsInGet": 100000,
          "maxObjectsInSet": 100000,
          "collationAlgorithms": [
            "i;ascii-numeric",
            "i;ascii-casemap",
            "i;unicode-casemap"
          ]
        },
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:calendars": {},
        "urn:ietf:params:jmap:calendars:parse": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:contacts:parse": {},
        "urn:ietf:params:jmap:emailpush": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {},
        "urn:ietf:params:jmap:principals:availability": {},
        "urn:ietf:params:jmap:submission": {},
        "urn:ietf:params:jmap:vacationresponse": {},
        "urn:ietf:params:jmap:sieve": {
          "implementation": "Stalwart v1.0.0"
        },
        "urn:ietf:params:jmap:blob": {},
        "urn:ietf:params:jmap:quota": {},
        "urn:ietf:params:jmap:metadata": {},
        "urn:ietf:params:jmap:webpush-vapid": {
          "applicationServerKey": application_server_key
        },
        "urn:ietf:params:jmap:websocket": {
          "url": "wss://127.0.0.1:8899/jmap/ws",
          "supportsPush": true
        }
      },
      "accounts": {
        john_id: {
          "name": "jdoe@example.com",
          "isPersonal": true,
          "isReadOnly": false,
          "accountCapabilities": {
            "urn:ietf:params:jmap:mail": {
              "maxMailboxesPerEmail": 100,
              "maxMailboxDepth": 10,
              "maxSizeMailboxName": 255,
              "maxSizeAttachmentsPerEmail": 50000000,
              "emailQuerySortOptions": [
                "receivedAt",
                "size",
                "from",
                "to",
                "subject",
                "sentAt",
                "hasKeyword",
                "allInThreadHaveKeyword",
                "someInThreadHaveKeyword"
              ],
              "mayCreateTopLevelMailbox": true
            },
            "urn:ietf:params:jmap:submission": {
              "maxDelayedSend": 2592000,
              "submissionExtensions": {
                "FUTURERELEASE": [],
                "SIZE": [],
                "DSN": [],
                "DELIVERYBY": [],
                "MT-PRIORITY": [
                  "MIXER"
                ],
                "REQUIRETLS": []
              }
            },
            "urn:ietf:params:jmap:vacationresponse": {},
            "urn:ietf:params:jmap:contacts": {
              "maxAddressBooksPerCard": 10,
              "mayCreateAddressBook": true
            },
            "urn:ietf:params:jmap:contacts:parse": {},
            "urn:ietf:params:jmap:emailpush": {},
            "urn:ietf:params:jmap:calendars": {
              "maxCalendarsPerEvent": 10,
              "minDateTime": "0001-01-01T00:00:00Z",
              "maxDateTime": "9999-12-31T23:59:59Z",
              "maxExpandedQueryDuration": "P52W1D",
              "maxParticipantsPerEvent": 20,
              "mayCreateCalendar": true
            },
            "urn:ietf:params:jmap:calendars:parse": {},
            "urn:ietf:params:jmap:websocket": {},
            "urn:ietf:params:jmap:sieve": {
              "maxSizeScriptName": 512,
              "maxSizeScript": 102400,
              "maxNumberScripts": 100,
              "maxNumberRedirects": 1,
              "sieveExtensions": [
                "body",
                "comparator-elbonia",
                "comparator-i;ascii-casemap",
                "comparator-i;ascii-numeric",
                "comparator-i;octet",
                "convert",
                "copy",
                "date",
                "duplicate",
                "editheader",
                "enclose",
                "encoded-character",
                "enotify",
                "envelope",
                "envelope-deliverby",
                "envelope-dsn",
                "environment",
                "ereject",
                "extlists",
                "extracttext",
                "fcc",
                "fileinto",
                "foreverypart",
                "ihave",
                "imap4flags",
                "imapsieve",
                "include",
                "index",
                "mailbox",
                "mailboxid",
                "mboxmetadata",
                "mime",
                "redirect-deliverby",
                "redirect-dsn",
                "regex",
                "reject",
                "relational",
                "replace",
                "servermetadata",
                "spamtest",
                "spamtestplus",
                "special-use",
                "subaddress",
                "vacation",
                "vacation-seconds",
                "variables",
                "virustest"
              ],
              "notificationMethods": [
                "mailto"
              ],
              "externalLists": null
            },
            "urn:ietf:params:jmap:blob": {
              "maxSizeBlobSet": 7499488,
              "maxDataSources": 16,
              "supportedTypeNames": [
                "Email",
                "Thread",
                "SieveScript",
                "CalendarEvent",
                "ContactCard"
              ],
              "supportedDigestAlgorithms": [
                "sha",
                "sha-256",
                "sha-512"
              ]
            },
            "urn:ietf:params:jmap:quota": {},
            "urn:ietf:params:jmap:principals": {
              "currentUserPrincipalId": john_id
            },
            "urn:ietf:params:jmap:principals:owner": {
              "accountIdForPrincipal": john_id,
              "principalId": john_id
            },
            "urn:ietf:params:jmap:principals:availability": {
              "maxAvailabilityDuration": "P52W1D",
            },
            "urn:ietf:params:jmap:filenode": {
              "maxSizeFileNodeName": 255,
              "forbiddenNameChars": "/<>:\"\\|?*",
              "forbiddenNodeNames": [
                ".",
                "..",
                "CON",
                "PRN",
                "AUX",
                "NUL",
                "COM0",
                "COM1",
                "COM2",
                "COM3",
                "COM4",
                "COM5",
                "COM6",
                "COM7",
                "COM8",
                "COM9",
                "LPT0",
                "LPT1",
                "LPT2",
                "LPT3",
                "LPT4",
                "LPT5",
                "LPT6",
                "LPT7",
                "LPT8",
                "LPT9"
              ],
              "fileNodeQuerySortOptions": [
                "name",
                "size",
                "created",
                "modified",
                "type",
                "nodeType",
                "tree"
              ],
              "maxFileNodeDepth": 64,
              "mayCreateTopLevelFileNode": true,
              "caseInsensitiveNames": false,
              "webTrashUrl": null,
              "webUrlTemplate": null,
              "webWriteUrlTemplate": null
            },
            "urn:ietf:params:jmap:mail:share": {},
            "urn:stalwart:jmap": {},
            "urn:ietf:params:jmap:metadata": {
              "dataTypes": {
                "Email": metadata_info,
                "Mailbox": metadata_info,
                "SieveScript": metadata_info,
                "Calendar": metadata_info,
                "CalendarEvent": metadata_info,
                "AddressBook": metadata_info,
                "ContactCard": metadata_info,
                "FileNode": metadata_info
              }
            }
          }
        }
      },
      "primaryAccounts": {
        "urn:ietf:params:jmap:mail": john_id,
        "urn:ietf:params:jmap:submission": john_id,
        "urn:ietf:params:jmap:vacationresponse": john_id,
        "urn:ietf:params:jmap:contacts": john_id,
        "urn:ietf:params:jmap:contacts:parse": john_id,
        "urn:ietf:params:jmap:emailpush": john_id,
        "urn:ietf:params:jmap:calendars": john_id,
        "urn:ietf:params:jmap:calendars:parse": john_id,
        "urn:ietf:params:jmap:websocket": john_id,
        "urn:ietf:params:jmap:sieve": john_id,
        "urn:ietf:params:jmap:blob": john_id,
        "urn:ietf:params:jmap:quota": john_id,
        "urn:ietf:params:jmap:principals": john_id,
        "urn:ietf:params:jmap:principals:availability": john_id,
        "urn:ietf:params:jmap:filenode": john_id,
        "urn:ietf:params:jmap:mail:share": john_id,
        "urn:stalwart:jmap": john_id,
        "urn:ietf:params:jmap:metadata": john_id
      },
      "username": "jdoe@example.com",
      "apiUrl": "https://127.0.0.1:8899/jmap/",
      "downloadUrl":
      "https://127.0.0.1:8899/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
      "uploadUrl":
      "https://127.0.0.1:8899/jmap/upload/{accountId}/",
      "eventSourceUrl":
      "https://127.0.0.1:8899/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
      "state": response.text_field("state")
    }));

    // Obtain principal ids for Jane, Bill and the sales group
    let response = john
        .jmap_query(
            MethodObject::Principal,
            [("email", "john.doe@example.com")],
            ["name"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.ids().collect::<Vec<_>>(), [john_id]);
    let response = john
        .jmap_query(
            MethodObject::Principal,
            [("name", "bill@example.com")],
            ["name"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.ids().collect::<Vec<_>>(), [bill_id]);
    let response = john
        .jmap_query(
            MethodObject::Principal,
            [("accountIds", [jane_id])],
            ["name"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.ids().collect::<Vec<_>>(), [jane_id]);
    let response = john
        .jmap_query(
            MethodObject::Principal,
            [("text", "sales group")],
            ["name"],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.ids().collect::<Vec<_>>(), [sales_id]);
    for address in ["mailto:Jane@example.com", "mailto:jane%40example.com"] {
        let response = john
            .jmap_query(
                MethodObject::Principal,
                [("calendarAddress", address)],
                ["name"],
                Vec::<(&str, &str)>::new(),
            )
            .await;
        assert_eq!(response.ids().collect::<Vec<_>>(), [jane_id], "{address}");
    }

    // The calendarAddress filter requires the principals:availability capability
    let response = john
        .jmap_request(
            &[
                "urn:ietf:params:jmap:core",
                "urn:ietf:params:jmap:principals",
            ],
            json!([[
                "Principal/query",
                {
                    "accountId": john_id,
                    "filter": {"calendarAddress": "mailto:jane@example.com"}
                },
                "0"
            ]]),
        )
        .await;
    assert_eq!(
        response.method_response()["type"],
        json!("unsupportedFilter")
    );

    // Validate principal contents
    let response = john
        .jmap_get(
            MethodObject::Principal,
            [
                PrincipalProperty::Id,
                PrincipalProperty::Type,
                PrincipalProperty::Email,
                PrincipalProperty::Description,
                PrincipalProperty::Name,
                PrincipalProperty::Timezone,
                PrincipalProperty::Capabilities,
                PrincipalProperty::Accounts,
            ],
            [john_id, jane_id, bill_id, sales_id],
        )
        .await;
    let list = response.list();
    assert_eq!(list.len(), 4);
    assert_eq!(list[0]["accounts"][john_id]["isPersonal"], json!(true));
    assert!(list[1]["accounts"].is_null(), "{list:?}");

    list[0].assert_is_equal(json!({
      "id": john_id,
      "type": "individual",
      "email": "jdoe@example.com",
      "description": "John Doe",
      "name": "jdoe@example.com",
      "timeZone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {},
        "urn:ietf:params:jmap:calendars": {
          "accountId": john_id,
          "mayGetAvailability": true,
          "mayShareWith": false,
          "calendarAddress": "mailto:jdoe@example.com"
        }
      },
      "accounts": principal_accounts(john_id)
    }));
    list[1].assert_is_equal(json!({
      "id": jane_id,
      "type": "individual",
      "email": "jane.smith@example.com",
      "description": "Jane Smith",
      "name": "jane.smith@example.com",
      "timeZone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {},
        "urn:ietf:params:jmap:calendars": {
          "accountId": null,
          "mayGetAvailability": true,
          "mayShareWith": true,
          "calendarAddress": "mailto:jane.smith@example.com"
        }
      },
      "accounts": null
    }));
    list[2].assert_is_equal(json!({
      "id": bill_id,
      "type": "individual",
      "email": "bill@example.com",
      "description": "Bill Foobar",
      "name": "bill@example.com",
      "timeZone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {},
        "urn:ietf:params:jmap:calendars": {
          "accountId": null,
          "mayGetAvailability": true,
          "mayShareWith": true,
          "calendarAddress": "mailto:bill@example.com"
        }
      },
      "accounts": null
    }));
    list[3].assert_is_equal(json!({
      "id": sales_id,
      "type": "group",
      "email": "sales@example.com",
      "description": "Sales Group",
      "name": "sales@example.com",
      "timeZone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {},
        "urn:ietf:params:jmap:calendars": {
          "accountId": null,
          "mayGetAvailability": true,
          "mayShareWith": true,
          "calendarAddress": "mailto:sales@example.com"
        }
      },
      "accounts": null
    }));

    // Unknown principals are reported as not found
    let response = john
        .jmap_get(
            MethodObject::Principal,
            [PrincipalProperty::Id],
            [jane_id, "zzzzzzz"],
        )
        .await;
    assert_eq!(response.list().len(), 1, "{response:?}");
    assert_eq!(response.not_found().collect::<Vec<_>>(), ["zzzzzzz"]);

    // All properties are returned when properties is null
    let response = john
        .jmap_get(MethodObject::Principal, Vec::<&str>::new(), [jane_id])
        .await;
    response.list()[0].assert_is_equal(json!({
      "id": jane_id,
      "type": "individual",
      "email": "jane.smith@example.com",
      "description": "Jane Smith",
      "name": "jane.smith@example.com",
      "timeZone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {},
        "urn:ietf:params:jmap:calendars": {
          "accountId": null,
          "mayGetAvailability": true,
          "mayShareWith": true,
          "calendarAddress": "mailto:jane.smith@example.com"
        }
      },
      "accounts": null
    }));

    // Shared and group accounts are owned by their principal and report the caller
    // as the current user principal
    let admin = test.account("admin@example.com");
    admin
        .registry_update_object(
            ObjectType::Account,
            john.id(),
            json!({"memberGroupIds": {sales.id(): true}}),
        )
        .await;
    jane.jmap_create(
        MethodObject::Calendar,
        [json!({
            "name": "Shared with John",
            "shareWith": {john_id: {"mayReadItems": true}}
        })],
        Vec::<(&str, &str)>::new(),
    )
    .await
    .created(0);
    let session = john.jmap_session_object().await.into_inner();
    for (account_id, name, may_create) in [
        (jane_id, "jane.smith@example.com", false),
        (sales_id, "sales@example.com", true),
    ] {
        let account = &session["accounts"][account_id];
        assert_eq!(account["name"], json!(name), "{session}");
        assert_eq!(account["isPersonal"], json!(false), "{session}");
        let capabilities = &account["accountCapabilities"];
        assert_eq!(
            capabilities["urn:ietf:params:jmap:principals"],
            json!({"currentUserPrincipalId": john_id}),
            "{session}"
        );
        assert_eq!(
            capabilities["urn:ietf:params:jmap:principals:owner"],
            json!({"accountIdForPrincipal": john_id, "principalId": account_id}),
            "{session}"
        );
        assert_eq!(
            capabilities["urn:ietf:params:jmap:calendars"]["mayCreateCalendar"],
            json!(may_create),
            "{session}"
        );
    }
    let response = john
        .jmap_get(
            MethodObject::Principal,
            [PrincipalProperty::Capabilities, PrincipalProperty::Accounts],
            [jane_id, sales_id],
        )
        .await;
    for (principal, account_id) in response.list().iter().zip([jane_id, sales_id]) {
        assert_eq!(
            principal["capabilities"]["urn:ietf:params:jmap:calendars"]["accountId"],
            json!(account_id),
            "{principal}"
        );
        assert_eq!(
            principal["accounts"],
            json!({account_id: &session["accounts"][account_id]}),
            "{principal}"
        );
    }

    // Disabling directory queries restricts Principal/get to accessible principals
    admin
        .registry_update_setting(
            Sharing {
                allow_directory_queries: false,
                ..Default::default()
            },
            &[Property::AllowDirectoryQueries],
        )
        .await;
    admin.reload_settings().await;
    let response = john
        .jmap_get(
            MethodObject::Principal,
            [PrincipalProperty::Id, PrincipalProperty::Capabilities],
            [john_id, jane_id, sales_id, bill_id],
        )
        .await;
    let mut visible = response
        .list()
        .iter()
        .map(|principal| principal.text_field("id"))
        .collect::<Vec<_>>();
    visible.sort_unstable();
    let mut expected = vec![john_id, jane_id, sales_id];
    expected.sort_unstable();
    assert_eq!(visible, expected, "{response:?}");
    assert_eq!(response.not_found().collect::<Vec<_>>(), [bill_id]);
    assert_eq!(
        response.list()[0]["capabilities"]["urn:ietf:params:jmap:calendars"]["mayGetAvailability"],
        json!(false),
        "{response:?}"
    );
    let response = john
        .jmap_get(
            MethodObject::Principal,
            [PrincipalProperty::Id],
            Vec::<&str>::new(),
        )
        .await;
    let visible = response
        .list()
        .iter()
        .map(|principal| principal.text_field("id"))
        .collect::<Vec<_>>();
    assert!(visible.contains(&john_id), "{response:?}");
    assert!(!visible.contains(&bill_id), "{response:?}");
    assert_eq!(
        john.jmap_method_call(
            "Principal/query",
            json!({"accountId": john_id, "filter": {"email": "bill@example.com"}}),
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );
    assert_eq!(
        john.jmap_method_call(
            "Principal/getAvailability",
            json!({
                "accountId": john_id,
                "id": john_id,
                "utcStart": "2006-01-01T00:00:00Z",
                "utcEnd": "2006-01-08T00:00:00Z",
            }),
        )
        .await
        .method_response()
        .typ(),
        "forbidden"
    );
    admin
        .registry_update_setting(
            Sharing {
                allow_directory_queries: true,
                ..Default::default()
            },
            &[Property::AllowDirectoryQueries],
        )
        .await;
    admin.reload_settings().await;

    jane.destroy_all_calendars().await;
    admin
        .registry_update_object(
            ObjectType::Account,
            john.id(),
            json!({"memberGroupIds": {sales.id(): false}}),
        )
        .await;
}
