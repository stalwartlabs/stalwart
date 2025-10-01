/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::format_compact;
use std::collections::HashMap;
use utils::map::vec_map::VecMap;

pub mod eval;
pub mod jsptr;
pub mod resolve;

pub(crate) enum Graph<'x> {
    Some {
        child_id: &'x str,
        graph: &'x mut HashMap<String, Vec<String>>,
    },
    None,
}

fn topological_sort<T>(
    create: &mut VecMap<String, T>,
    graph: HashMap<String, Vec<String>>,
) -> trc::Result<VecMap<String, T>> {
    // Make sure all references exist
    for (from_id, to_ids) in graph.iter() {
        for to_id in to_ids {
            if !create.contains_key(to_id) {
                return Err(trc::JmapEvent::InvalidResultReference.into_err().details(
                    format_compact!(
                        "Invalid reference to non-existing object {to_id:?} from {from_id:?}"
                    ),
                ));
            }
        }
    }

    let mut sorted_create = VecMap::with_capacity(create.len());
    let mut it_stack = Vec::new();
    let keys = graph.keys().cloned().collect::<Vec<_>>();
    let mut it = keys.iter();

    'main: loop {
        while let Some(from_id) = it.next() {
            if let Some(to_ids) = graph.get(from_id) {
                it_stack.push((it, from_id));
                if it_stack.len() > 1000 {
                    return Err(trc::JmapEvent::InvalidArguments
                        .into_err()
                        .details("Cyclical references are not allowed."));
                }
                it = to_ids.iter();
                continue;
            } else if let Some((id, value)) = create.remove_entry(from_id) {
                sorted_create.append(id, value);
                if create.is_empty() {
                    break 'main;
                }
            }
        }

        if let Some((prev_it, from_id)) = it_stack.pop() {
            it = prev_it;
            if let Some((id, value)) = create.remove_entry(from_id) {
                sorted_create.append(id, value);
                if create.is_empty() {
                    break 'main;
                }
            }
        } else {
            break;
        }
    }

    // Add remaining items
    if !create.is_empty() {
        for (id, value) in std::mem::take(create) {
            sorted_create.append(id, value);
        }
    }
    Ok(sorted_create)
}

#[cfg(test)]
mod tests {
    use crate::{
        method::{changes::ChangesResponse, get::GetResponse, query::QueryResponse},
        object::{
            email::{EmailProperty, EmailValue},
            mailbox::{MailboxProperty, MailboxValue},
            thread::{ThreadProperty, ThreadValue},
        },
        request::{
            Call, GetRequestMethod, Request, RequestMethod, SetRequestMethod,
            reference::{MaybeIdReference, MaybeResultReference},
        },
        response::{ChangesResponseMethod, GetResponseMethod, Response, ResponseMethod},
    };
    use jmap_tools::{Key, Map, Value};
    use std::collections::HashMap;
    use types::id::Id;

    #[test]
    fn eval_value_references() {
        let request = Request::parse(
            br##"{
                    "using":["urn:ietf:params:jmap:mail"],
                    "methodCalls": [[ "Email/query", {
                            "accountId": "a",
                            "filter": { "inMailbox": "a" },
                            "sort": [{ "property": "receivedAt", "isAscending": false }],
                            "collapseThreads": true,
                            "position": 0,
                            "limit": 10,
                            "calculateTotal": true
                        }, "t0" ],
                        [ "Email/get", {
                            "accountId": "a",
                            "#ids": {
                            "resultOf": "t0",
                            "name": "Email/query",
                            "path": "/ids"
                            },
                            "properties": [ "threadId" ]
                        }, "t1" ],
                        [ "Thread/get", {
                            "accountId": "a",
                            "#ids": {
                            "resultOf": "t1",
                            "name": "Email/get",
                            "path": "/list/*/threadId"
                            }
                        }, "t2" ],
                        [ "Email/get", {
                            "accountId": "a",
                            "#ids": {
                            "resultOf": "t2",
                            "name": "Thread/get",
                            "path": "/list/*/emailIds"
                            },
                            "properties": [ "from", "receivedAt", "subject" ]
                        }, "t3" ]]
                    }"##,
            100,
            1024 * 1024,
        )
        .unwrap();

        let mut response = Response::new(
            1234,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        assert_eq!(request.method_calls.len(), 4);

        for (test_num, mut call) in request.method_calls.into_iter().enumerate() {
            match test_num {
                0 => {
                    response.method_responses.push(Call {
                        id: call.id,
                        name: call.name,
                        method: ResponseMethod::Query(QueryResponse {
                            account_id: Id::new(1),
                            query_state: Default::default(),
                            can_calculate_changes: Default::default(),
                            position: Default::default(),
                            ids: vec![Id::new(4), Id::new(5)],
                            total: Default::default(),
                            limit: Default::default(),
                        }),
                    });
                }
                1 => {
                    response.resolve_references(&mut call.method).unwrap();
                    match call.method {
                        RequestMethod::Get(GetRequestMethod::Email(req)) => {
                            assert_eq!(
                                req.ids,
                                Some(MaybeResultReference::Value(vec![
                                    MaybeIdReference::Id(Id::new(4)),
                                    MaybeIdReference::Id(Id::new(5))
                                ]))
                            );
                        }
                        _ => panic!("Expected Email Get Request"),
                    }
                    response.method_responses.push(Call {
                        id: call.id,
                        name: call.name,
                        method: ResponseMethod::Get(GetResponseMethod::Email(GetResponse {
                            account_id: Id::new(1).into(),
                            state: Default::default(),
                            list: vec![
                                Value::Object(Map::from(vec![(
                                    Key::Property(EmailProperty::ThreadId),
                                    Value::Element(EmailValue::Id(Id::new(9))),
                                )])),
                                Value::Object(Map::from(vec![(
                                    Key::Property(EmailProperty::ThreadId),
                                    Value::Element(EmailValue::Id(Id::new(10))),
                                )])),
                            ],
                            not_found: Default::default(),
                        })),
                    });
                }
                2 => {
                    response.resolve_references(&mut call.method).unwrap();
                    match call.method {
                        RequestMethod::Get(GetRequestMethod::Thread(req)) => {
                            assert_eq!(
                                req.ids,
                                Some(MaybeResultReference::Value(vec![
                                    MaybeIdReference::Id(Id::new(9)),
                                    MaybeIdReference::Id(Id::new(10))
                                ]))
                            );
                        }
                        _ => panic!("Expected Thread Get Request"),
                    }
                    response.method_responses.push(Call {
                        id: call.id,
                        name: call.name,
                        method: ResponseMethod::Get(GetResponseMethod::Thread(GetResponse {
                            account_id: Id::new(1).into(),
                            state: Default::default(),
                            list: vec![
                                Value::Object(Map::from(vec![(
                                    Key::Property(ThreadProperty::EmailIds),
                                    Value::Array(vec![
                                        Value::Element(ThreadValue::Id(Id::new(100))),
                                        Value::Element(ThreadValue::Id(Id::new(101))),
                                    ]),
                                )])),
                                Value::Object(Map::from(vec![(
                                    Key::Property(ThreadProperty::EmailIds),
                                    Value::Array(vec![
                                        Value::Element(ThreadValue::Id(Id::new(102))),
                                        Value::Element(ThreadValue::Id(Id::new(103))),
                                    ]),
                                )])),
                            ],
                            not_found: Default::default(),
                        })),
                    });
                }
                3 => {
                    response.resolve_references(&mut call.method).unwrap();
                    match call.method {
                        RequestMethod::Get(GetRequestMethod::Email(req)) => {
                            assert_eq!(
                                req.ids,
                                Some(MaybeResultReference::Value(vec![
                                    MaybeIdReference::Id(Id::new(100)),
                                    MaybeIdReference::Id(Id::new(101)),
                                    MaybeIdReference::Id(Id::new(102)),
                                    MaybeIdReference::Id(Id::new(103)),
                                ]))
                            );
                        }
                        _ => panic!("Expected Mailbox Get Request"),
                    }
                }
                _ => panic!("Unexpected invocation {}", test_num),
            }
        }
    }

    #[test]
    fn eval_property_references() {
        let request = Request::parse(
            br##"{
                    "using":["urn:ietf:params:jmap:mail"],
                    "methodCalls": [
                    ["Mailbox/changes",{
                    "accountId":"s",
                    "sinceState":"srxqk071myhgkyay"
                    },"0"],
                    ["Mailbox/get",{
                    "accountId":"s",
                    "#ids":{"name":"Mailbox/changes","path":"/created","resultOf":"0"}
                    },"1"],
                    ["Mailbox/get",{
                    "accountId":"s",
                    "#ids":{"name":"Mailbox/changes","path":"/updated","resultOf":"0"},
                    "#properties":{"name":"Mailbox/changes","path":"/updatedProperties","resultOf":"0"}
                    },"2"]
                    ]
                    }"##,
            100,
            1024 * 1024,
        )
        .unwrap();

        let mut response = Response::new(
            1234,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        assert_eq!(request.method_calls.len(), 3);

        for (test_num, mut call) in request.method_calls.into_iter().enumerate() {
            match test_num {
                0 => {
                    response.method_responses.push(Call {
                        id: call.id,
                        name: call.name,
                        method: ResponseMethod::Changes(ChangesResponseMethod::Mailbox(
                            ChangesResponse {
                                account_id: Id::new(1),
                                old_state: Default::default(),
                                new_state: Default::default(),
                                has_more_changes: Default::default(),
                                created: Default::default(),
                                updated: vec![Id::new(2), Id::new(3)],
                                destroyed: Default::default(),
                                updated_properties: Some(vec![
                                    MailboxProperty::Name.into(),
                                    MailboxProperty::ParentId.into(),
                                ]),
                            },
                        )),
                    });
                }
                1 => {
                    response.resolve_references(&mut call.method).unwrap();
                    match call.method {
                        RequestMethod::Get(GetRequestMethod::Mailbox(req)) => {
                            assert_eq!(req.ids, Some(MaybeResultReference::Value(vec![])));
                        }
                        _ => panic!("Expected Mailbox Get Request"),
                    }
                }
                2 => {
                    response.resolve_references(&mut call.method).unwrap();
                    match call.method {
                        RequestMethod::Get(GetRequestMethod::Mailbox(req)) => {
                            assert_eq!(
                                req.ids,
                                Some(MaybeResultReference::Value(vec![
                                    MaybeIdReference::Id(Id::new(2)),
                                    MaybeIdReference::Id(Id::new(3))
                                ]))
                            );
                        }
                        _ => panic!("Expected Mailbox Get Request"),
                    }
                }
                _ => panic!("Unexpected invocation {}", test_num),
            }
        }
    }

    #[test]
    fn eval_create_references() {
        let request = Request::parse(
            br##"{
                    "using": [
                        "urn:ietf:params:jmap:core",
                        "urn:ietf:params:jmap:mail"
                    ],
                    "methodCalls": [
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "a": {
                                        "name": "Folder a",
                                        "parentId": "#b"
                                    },
                                    "b": {
                                        "name": "Folder b",
                                        "parentId": "#c"
                                    },
                                    "c": {
                                        "name": "Folder c",
                                        "parentId": "#d"
                                    },
                                    "d": {
                                        "name": "Folder d",
                                        "parentId": "#e"
                                    },
                                    "e": {
                                        "name": "Folder e",
                                        "parentId": "#f"
                                    },
                                    "f": {
                                        "name": "Folder f",
                                        "parentId": "#g"
                                    },
                                    "g": {
                                        "name": "Folder g",
                                        "parentId": null
                                    }
                                }
                            },
                            "fulltree"
                        ],
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "a1": {
                                        "name": "Folder a1",
                                        "parentId": null
                                    },
                                    "b2": {
                                        "name": "Folder b2",
                                        "parentId": "#a1"
                                    },
                                    "c3": {
                                        "name": "Folder c3",
                                        "parentId": "#a1"
                                    },
                                    "d4": {
                                        "name": "Folder d4",
                                        "parentId": "#b2"
                                    },
                                    "e5": {
                                        "name": "Folder e5",
                                        "parentId": "#b2"
                                    },
                                    "f6": {
                                        "name": "Folder f6",
                                        "parentId": "#d4"
                                    },
                                    "g7": {
                                        "name": "Folder g7",
                                        "parentId": "#e5"
                                    }
                                }
                            },
                            "fulltree2"
                        ],
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "z": {
                                        "name": "Folder Z",
                                        "parentId": "#x"
                                    },
                                    "y": {
                                        "name": null
                                    },
                                    "x": {
                                        "name": "Folder X"
                                    }
                                }
                            },
                            "xyz"
                        ],
                        [
                            "Mailbox/set",
                            {
                                "accountId": "b",
                                "create": {
                                    "a": {
                                        "name": "Folder a",
                                        "parentId": "#b"
                                    },
                                    "b": {
                                        "name": "Folder b",
                                        "parentId": "#c"
                                    },
                                    "c": {
                                        "name": "Folder c",
                                        "parentId": "#d"
                                    },
                                    "d": {
                                        "name": "Folder d",
                                        "parentId": "#a"
                                    }
                                }
                            },
                            "circular"
                        ]
                    ]
                }"##,
            100,
            1024 * 1024,
        )
        .unwrap();

        let response = Response::new(
            1234,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        for (test_num, mut call) in request.method_calls.into_iter().enumerate() {
            match response.resolve_references(&mut call.method) {
                Ok(_) => assert!(
                    (0..3).contains(&test_num),
                    "Unexpected invocation {}",
                    test_num
                ),
                Err(err) => {
                    assert_eq!(test_num, 3);
                    assert!(
                        err.matches(trc::EventType::Jmap(trc::JmapEvent::InvalidArguments)),
                        "{:?}",
                        err
                    );
                    continue;
                }
            }

            if let RequestMethod::Set(SetRequestMethod::Mailbox(request)) = call.method {
                if test_num == 0 {
                    assert_eq!(
                        request
                            .create
                            .unwrap()
                            .into_iter()
                            .map(|b| b.0)
                            .collect::<Vec<_>>(),
                        ["g", "f", "e", "d", "c", "b", "a"]
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                    );
                } else if test_num == 1 {
                    let mut pending_ids = vec!["a1", "b2", "d4", "e5", "f6", "c3", "g7"];

                    for (id, _) in request.create.as_ref().unwrap() {
                        match id.as_str() {
                            "a1" => (),
                            "b2" | "c3" => assert!(!pending_ids.contains(&"a1")),
                            "d4" | "e5" => assert!(!pending_ids.contains(&"b2")),
                            "f6" => assert!(!pending_ids.contains(&"d4")),
                            "g7" => assert!(!pending_ids.contains(&"e5")),
                            _ => panic!("Unexpected ID"),
                        }
                        pending_ids.retain(|i| i != id);
                    }

                    if !pending_ids.is_empty() {
                        panic!(
                            "Unexpected order: {:?}",
                            request
                                .create
                                .as_ref()
                                .unwrap()
                                .iter()
                                .map(|b| b.0.to_string())
                                .collect::<Vec<_>>()
                        );
                    }
                } else if test_num == 2 {
                    assert_eq!(
                        request
                            .create
                            .unwrap()
                            .into_iter()
                            .map(|b| b.0)
                            .collect::<Vec<_>>(),
                        ["x", "z", "y"]
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                    );
                }
            } else {
                panic!("Expected Set Mailbox Request");
            }
        }

        let request = Request::parse(
            br##"{
                "using": [
                    "urn:ietf:params:jmap:core",
                    "urn:ietf:params:jmap:mail"
                ],
                "methodCalls": [
                    [
                        "Mailbox/set",
                        {
                            "accountId": "b",
                            "create": {
                                "a": {
                                    "name": "a",
                                    "parentId": "#x"
                                },
                                "b": {
                                    "name": "b",
                                    "parentId": "#y"
                                },
                                "c": {
                                    "name": "c",
                                    "parentId": "#z"
                                }
                            }
                        },
                        "ref1"
                    ],
                    [
                        "Mailbox/set",
                        {
                            "accountId": "b",
                            "create": {
                                "a1": {
                                    "name": "a1",
                                    "parentId": "#a"
                                },
                                "b2": {
                                    "name": "b2",
                                    "parentId": "#b"
                                },
                                "c3": {
                                    "name": "c3",
                                    "parentId": "#c"
                                }
                            }
                        },
                        "red2"
                    ]
                ],
                "createdIds": {
                    "x": "b",
                    "y": "c",
                    "z": "d"
                }
            }"##,
            1024,
            1024 * 1024,
        )
        .unwrap();

        let mut response = Response::new(
            1234,
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );

        let mut invocations = request.method_calls.into_iter();
        let mut call = invocations.next().unwrap();
        response.resolve_references(&mut call.method).unwrap();

        if let RequestMethod::Set(SetRequestMethod::Mailbox(request)) = call.method {
            let create = request
                .create
                .as_ref()
                .unwrap()
                .iter()
                .map(|(p, v)| {
                    (
                        p.as_str(),
                        v.as_object()
                            .unwrap()
                            .get(&Key::Property(MailboxProperty::ParentId))
                            .unwrap(),
                    )
                })
                .collect::<HashMap<_, _>>();
            assert_eq!(
                *create.get("a").unwrap(),
                &Value::Element(MailboxValue::Id(Id::new(1)))
            );
            assert_eq!(
                *create.get("b").unwrap(),
                &Value::Element(MailboxValue::Id(Id::new(2)))
            );
            assert_eq!(
                *create.get("c").unwrap(),
                &Value::Element(MailboxValue::Id(Id::new(3)))
            );
        } else {
            panic!("Expected Mailbox Set Request");
        }

        response
            .created_ids
            .insert("a".to_string(), Id::new(5).into());
        response
            .created_ids
            .insert("b".to_string(), Id::new(6).into());
        response
            .created_ids
            .insert("c".to_string(), Id::new(7).into());

        let mut call = invocations.next().unwrap();
        response.resolve_references(&mut call.method).unwrap();

        if let RequestMethod::Set(SetRequestMethod::Mailbox(request)) = call.method {
            let create = request
                .create
                .as_ref()
                .unwrap()
                .iter()
                .map(|(p, v)| {
                    (
                        p.as_str(),
                        v.as_object()
                            .unwrap()
                            .get(&Key::Property(MailboxProperty::ParentId))
                            .unwrap(),
                    )
                })
                .collect::<HashMap<_, _>>();
            assert_eq!(
                *create.get("a1").unwrap(),
                &Value::Element(MailboxValue::Id(Id::new(5)))
            );
            assert_eq!(
                *create.get("b2").unwrap(),
                &Value::Element(MailboxValue::Id(Id::new(6)))
            );
            assert_eq!(
                *create.get("c3").unwrap(),
                &Value::Element(MailboxValue::Id(Id::new(7)))
            );
        } else {
            panic!("Expected Mailbox Set Request");
        }
    }
}
