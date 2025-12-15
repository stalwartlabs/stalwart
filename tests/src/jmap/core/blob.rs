/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{jmap::JMAPTest, store::cleanup::store_blob_expire_all};
use email::mailbox::INBOX_ID;
use serde_json::{Value, json};
use types::id::Id;

pub async fn test(params: &mut JMAPTest) {
    println!("Running blob tests...");
    let server = params.server.clone();
    let account = params.account("jdoe@example.com");
    store_blob_expire_all(&server.core.storage.data).await;

    // Blob/set simple test
    let response = account.jmap_method_call("Blob/upload", json!({
             "create": {
              "abc": {
               "data" : [
               {
                "data:asBase64": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQMAAAAl21bKAAAAA1BMVEX/AAAZ4gk3AAAAAXRSTlN/gFy0ywAAAApJREFUeJxjYgAAAAYAAzY3fKgAAAAASUVORK5CYII="
               }
              ],
              "type": "image/png"
              }
             }
            })).await;

    assert_eq!(
        response
            .pointer("/methodResponses/0/1/created/abc/type")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "image/png",
        "Response: {:?}",
        response
    );
    assert_eq!(
        response
            .pointer("/methodResponses/0/1/created/abc/size")
            .and_then(|v| v.as_i64())
            .unwrap_or_default(),
        95,
        "Response: {:?}",
        response
    );

    // Blob/get simple test
    let blob_id = account
        .jmap_method_call(
            "Blob/upload",
            json!({
             "create": {
              "abc": {
               "data" : [
               {
                "data:asText": "The quick brown fox jumped over the lazy dog."
               }
              ]
              }
             }
            }),
        )
        .await
        .pointer("/methodResponses/0/1/created/abc/id")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    let response = account
        .jmap_method_calls(json!([[
            "Blob/get",
            {
              "ids" : [
                blob_id
              ],
              "properties" : [
                "data:asText",
                "digest:sha",
                "size"
              ]
            },
            "R1"
          ],
          [
            "Blob/get",
            {
              "ids" : [
                blob_id
              ],
              "properties" : [
                "data:asText",
                "digest:sha",
                "digest:sha-256",
                "size"
              ],
              "offset" : 4,
              "length" : 9
            },
            "R2"
          ]
        ]))
        .await;

    for (pointer, expected) in [
        (
            "/methodResponses/0/1/list/0/data:asText",
            "The quick brown fox jumped over the lazy dog.",
        ),
        (
            "/methodResponses/0/1/list/0/digest:sha",
            "wIVPufsDxBzOOALLDSIFKebu+U4=",
        ),
        ("/methodResponses/0/1/list/0/size", "45"),
        ("/methodResponses/1/1/list/0/data:asText", "quick bro"),
        (
            "/methodResponses/1/1/list/0/digest:sha",
            "QiRAPtfyX8K6tm1iOAtZ87Xj3Ww=",
        ),
        (
            "/methodResponses/1/1/list/0/digest:sha-256",
            "gdg9INW7lwHK6OQ9u0dwDz2ZY/gubi0En0xlFpKt0OA=",
        ),
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_default(),
            expected,
            "Pointer {pointer:?} Response: {response:?}",
        );
    }

    store_blob_expire_all(&server.core.storage.data).await;

    // Blob/upload Complex Example
    let response = account
        .jmap_method_calls(json!([
         [
          "Blob/upload",
          {
           "create": {
            "b4": {
             "data": [
              {
               "data:asText": "The quick brown fox jumped over the lazy dog."
              }
            ]
           }
          }
         },
         "S4"
        ],
        [
          "Blob/upload",
          {
           "create": {
             "cat": {
               "data": [
                 {
                   "data:asText": "How"
                 },
                 {
                   "blobId": "#b4",
                   "length": 7,
                   "offset": 3
                 },
                 {
                   "data:asText": "was t"
                 },
                 {
                   "blobId": "#b4",
                   "length": 1,
                   "offset": 1
                 },
                 {
                   "data:asBase64": "YXQ/"
                 }
               ]
             }
           }
          },
          "CAT"
        ],
        [
          "Blob/get",
          {
           "properties": [
             "data:asText",
             "size"
           ],
           "ids": [
             "#cat"
           ]
          },
          "G4"
         ]
        ]))
        .await;

    for (pointer, expected) in [
        (
            "/methodResponses/2/1/list/0/data:asText",
            "How quick was that?",
        ),
        ("/methodResponses/2/1/list/0/size", "19"),
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_default(),
            expected,
            "Pointer {pointer:?} Response: {response:?}",
        );
    }
    store_blob_expire_all(&server.core.storage.data).await;

    // Blob/get Example with Range and Encoding Errors
    let response = account.jmap_method_calls(json!([
            [
              "Blob/upload",
              {
                "create": {
                  "b1": {
                    "data": [
                      {
                        "data:asBase64": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUggYEgZG9nLg=="
                      }
                    ]
                  },
                  "b2": {
                    "data": [
                      {
                        "data:asText": "hello world"
                      }
                    ],
                    "type" : "text/plain"
                  }
                }
              },
              "S1"
            ],
            [
              "Blob/get",
              {
                "ids": [
                  "#b1",
                  "#b2"
                ]
              },
              "G1"
            ],
            [
              "Blob/get",
              {
                "ids": [
                  "#b1",
                  "#b2"
                ],
                "properties": [
                  "data:asText",
                  "size"
                ]
              },
              "G2"
            ],
            [
              "Blob/get",
              {
                "ids": [
                  "#b1",
                  "#b2"
                ],
                "properties": [
                  "data:asBase64",
                  "size"
                ]
              },
              "G3"
            ],
            [
              "Blob/get",
              {
                "offset": 0,
                "length": 5,
                "ids": [
                  "#b1",
                  "#b2"
                ]
              },
              "G4"
            ],
            [
              "Blob/get",
              {
                "offset": 20,
                "length": 100,
                "ids": [
                  "#b1",
                  "#b2"
                ]
              },
              "G5"
            ]
          ])).await;

    for (pointer, expected) in [
        (
            "/methodResponses/1/1/list/0/data:asBase64",
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUggYEgZG9nLg==",
        ),
        ("/methodResponses/1/1/list/1/data:asText", "hello world"),
        ("/methodResponses/2/1/list/0/isEncodingProblem", "true"),
        ("/methodResponses/2/1/list/1/data:asText", "hello world"),
        (
            "/methodResponses/3/1/list/0/data:asBase64",
            "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUggYEgZG9nLg==",
        ),
        (
            "/methodResponses/3/1/list/1/data:asBase64",
            "aGVsbG8gd29ybGQ=",
        ),
        ("/methodResponses/4/1/list/0/data:asText", "The q"),
        ("/methodResponses/4/1/list/1/data:asText", "hello"),
        ("/methodResponses/5/1/list/0/isEncodingProblem", "true"),
        ("/methodResponses/5/1/list/0/isTruncated", "true"),
        ("/methodResponses/5/1/list/1/isTruncated", "true"),
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| match v {
                    Value::String(s) => Some(s.to_string()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
                .unwrap_or_default(),
            expected,
            "Pointer {pointer:?} Response: {response:?}",
        );
    }
    store_blob_expire_all(&server.core.storage.data).await;

    // Blob/lookup
    let client = account.client();
    let blob_id = client
        .email_import(
            concat!(
                "From: bill@example.com\r\n",
                "To: jdoe@example.com\r\n",
                "Subject: TPS Report\r\n",
                "\r\n",
                "I'm going to need those TPS reports ASAP. ",
                "So, if you could do that, that'd be great."
            )
            .as_bytes()
            .to_vec(),
            [&Id::from(INBOX_ID).to_string()],
            None::<Vec<&str>>,
            None,
        )
        .await
        .unwrap()
        .take_blob_id();

    let response = account
        .jmap_method_call(
            "Blob/lookup",
            json!({
              "typeNames": [
                "Mailbox",
                "Thread",
                "Email"
              ],
              "ids": [
                blob_id,
                "not-a-blob"
              ]
            }),
        )
        .await;

    for pointer in [
        "/methodResponses/0/1/list/0/matchedIds/Email",
        "/methodResponses/0/1/list/0/matchedIds/Mailbox",
        "/methodResponses/0/1/list/0/matchedIds/Thread",
    ] {
        assert_eq!(
            response
                .pointer(pointer)
                .and_then(|v| v.as_array())
                .map(|arr| arr.len())
                .unwrap_or_default(),
            1,
            "Pointer {pointer:?} Response: {response:#?}",
        );
    }

    // Remove test data
    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}
