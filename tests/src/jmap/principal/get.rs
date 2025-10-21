/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::jmap::{JMAPTest, JmapUtils};
use jmap_proto::{object::principal::PrincipalProperty, request::method::MethodObject};
use serde_json::json;

pub async fn test(params: &mut JMAPTest) {
    println!("Running Principal get/query tests...");
    let john = params.account("jdoe@example.com");
    let jane = params.account("jane.smith@example.com");
    let bill = params.account("bill@example.com");
    let sales = params.account("sales@example.com");

    let john_id = john.id_string();
    let jane_id = jane.id_string();
    let bill_id = bill.id_string();
    let sales_id = sales.id_string();

    // Validate session object capabilities
    let response = john.jmap_session_object().await.into_inner();
    response.assert_is_equal(json!({
      "capabilities": {
        "urn:ietf:params:jmap:core": {
          "maxSizeUpload": 5000000,
          "maxConcurrentUpload": 4,
          "maxSizeRequest": 10000000,
          "maxConcurrentRequests": 8,
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
              "maxMailboxesPerEmail": null,
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
              "maxAddressBooksPerCard": null,
              "mayCreateAddressBook": true
            },
            "urn:ietf:params:jmap:contacts:parse": {},
            "urn:ietf:params:jmap:calendars": {
              "maxCalendarsPerEvent": null,
              "minDateTime": "0001-01-01T00:00:00Z",
              "maxDateTime": "65534-12-31T23:59:59Z",
              "maxExpandedQueryDuration": "P52W1D",
              "maxParticipantsPerEvent": 20,
              "mayCreateCalendar": true
            },
            "urn:ietf:params:jmap:calendars:parse": {},
            "urn:ietf:params:jmap:websocket": {},
            "urn:ietf:params:jmap:sieve": {
              "maxSizeScriptName": 512,
              "maxSizeScript": 1048576,
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
                "SieveScript"
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
            "urn:ietf:params:jmap:principals:availability": {
              "maxAvailabilityDuration": "P52W1D",
            },
            "urn:ietf:params:jmap:filenode": {
              "maxFileNodeDepth": null,
              "maxSizeFileNodeName": 255,
              "fileNodeQuerySortOptions": [],
              "mayCreateTopLevelFileNode": true
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
        "urn:ietf:params:jmap:calendars": john_id,
        "urn:ietf:params:jmap:calendars:parse": john_id,
        "urn:ietf:params:jmap:websocket": john_id,
        "urn:ietf:params:jmap:sieve": john_id,
        "urn:ietf:params:jmap:blob": john_id,
        "urn:ietf:params:jmap:quota": john_id,
        "urn:ietf:params:jmap:principals": john_id,
        "urn:ietf:params:jmap:principals:availability": john_id,
        "urn:ietf:params:jmap:filenode": john_id
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

    list[0].assert_is_equal(json!({
      "id": john_id,
      "type": "individual",
      "email": "jdoe@example.com",
      "description": "John Doe",
      "name": "jdoe@example.com",
      "timezone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:calendars": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {}
      },
      "accounts": {
        john_id: {
          "urn:ietf:params:jmap:mail": {},
          "urn:ietf:params:jmap:contacts": {},
          "urn:ietf:params:jmap:calendars": {
            "accountId": john_id,
            "mayGetAvailability": true,
            "mayShareWith": true,
            "calendarAddress": "mailto:jdoe@example.com"
          },
          "urn:ietf:params:jmap:filenode": {},
          "urn:ietf:params:jmap:principals": {},
          "urn:ietf:params:jmap:principals:owner": {
            "accountIdForPrincipal": john_id,
            "principalId": john_id
          }
        }
      }
    }));
    list[1].assert_is_equal(json!({
      "id": jane_id,
      "type": "individual",
      "email": "jane.smith@example.com",
      "description": "Jane Smith",
      "name": "jane.smith@example.com",
      "timezone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:calendars": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {}
      },
      "accounts": {
        jane_id: {
          "urn:ietf:params:jmap:mail": {},
          "urn:ietf:params:jmap:contacts": {},
          "urn:ietf:params:jmap:calendars": {
            "accountId": jane_id,
            "mayGetAvailability": true,
            "mayShareWith": true,
            "calendarAddress": "mailto:jane.smith@example.com"
          },
          "urn:ietf:params:jmap:filenode": {},
          "urn:ietf:params:jmap:principals": {},
          "urn:ietf:params:jmap:principals:owner": {
            "accountIdForPrincipal": jane_id,
            "principalId": jane_id
          }
        }
      }
    }));
    list[2].assert_is_equal(json!({
      "id": bill_id,
      "type": "individual",
      "email": "bill@example.com",
      "description": "Bill Foobar",
      "name": "bill@example.com",
      "timezone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:calendars": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {}
      },
      "accounts": {
        bill_id: {
          "urn:ietf:params:jmap:mail": {},
          "urn:ietf:params:jmap:contacts": {},
          "urn:ietf:params:jmap:calendars": {
            "accountId": bill_id,
            "mayGetAvailability": true,
            "mayShareWith": true,
            "calendarAddress": "mailto:bill@example.com"
          },
          "urn:ietf:params:jmap:filenode": {},
          "urn:ietf:params:jmap:principals": {},
          "urn:ietf:params:jmap:principals:owner": {
            "accountIdForPrincipal": bill_id,
            "principalId": bill_id
          }
        }
      }
    }));
    list[3].assert_is_equal(json!({
      "id": sales_id,
      "type": "group",
      "email": "sales@example.com",
      "description": "Sales Group",
      "name": "sales@example.com",
      "timezone": null,
      "capabilities": {
        "urn:ietf:params:jmap:mail": {},
        "urn:ietf:params:jmap:contacts": {},
        "urn:ietf:params:jmap:calendars": {},
        "urn:ietf:params:jmap:filenode": {},
        "urn:ietf:params:jmap:principals": {}
      },
      "accounts": {
        sales_id: {
          "urn:ietf:params:jmap:mail": {},
          "urn:ietf:params:jmap:contacts": {},
          "urn:ietf:params:jmap:calendars": {
            "accountId": sales_id,
            "mayGetAvailability": true,
            "mayShareWith": true,
            "calendarAddress": "mailto:sales@example.com"
          },
          "urn:ietf:params:jmap:filenode": {},
          "urn:ietf:params:jmap:principals": {},
          "urn:ietf:params:jmap:principals:owner": {
            "accountIdForPrincipal": sales_id,
            "principalId": sales_id
          }
        }
      }
    }));
}
